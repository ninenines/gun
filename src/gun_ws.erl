%% Copyright (c) 2015-2019, Loïc Hoguin <essen@ninenines.eu>
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

-module(gun_ws).

-export([check_options/1]).
-export([name/0]).
-export([init/9]).
-export([handle/4]).
-export([update_flow/4]).
-export([close/4]).
-export([send/4]).
-export([down/1]).

-record(payload, {
	type = undefined :: cow_ws:frame_type(),
	rsv = undefined :: cow_ws:rsv(),
	len = undefined :: non_neg_integer(),
	mask_key = undefined :: cow_ws:mask_key(),
	close_code = undefined :: undefined | cow_ws:close_code(),
	unmasked = <<>> :: binary(),
	unmasked_len = 0 :: non_neg_integer()
}).

-record(ws_state, {
	owner :: pid(),
	stream_ref :: reference(),
	socket :: inet:socket() | ssl:sslsocket(),
	transport :: module(),
	buffer = <<>> :: binary(),
	in = head :: head | #payload{} | close,
	frag_state = undefined :: cow_ws:frag_state(),
	utf8_state = 0 :: cow_ws:utf8_state(),
	extensions = #{} :: cow_ws:extensions(),
	flow :: integer() | infinity,
	handler :: module(),
	handler_state :: any()
}).

check_options(Opts) ->
	do_check_options(maps:to_list(Opts)).

do_check_options([]) ->
	ok;
do_check_options([{compress, B}|Opts]) when B =:= true; B =:= false ->
	do_check_options(Opts);
do_check_options([{default_protocol, M}|Opts]) when is_atom(M) ->
	do_check_options(Opts);
do_check_options([{flow, InitialFlow}|Opts]) when is_integer(InitialFlow), InitialFlow > 0 ->
	do_check_options(Opts);
do_check_options([Opt={protocols, L}|Opts]) when is_list(L) ->
	case lists:usort(lists:flatten([[is_binary(B), is_atom(M)] || {B, M} <- L])) of
		[true] -> do_check_options(Opts);
		_ -> {error, {options, {ws, Opt}}}
	end;
do_check_options([{user_opts, _}|Opts]) ->
	do_check_options(Opts);
do_check_options([Opt|_]) ->
	{error, {options, {ws, Opt}}}.

name() -> ws.

init(Owner, Socket, Transport, StreamRef, Headers, Extensions, InitialFlow, Handler, Opts) ->
	Owner ! {gun_upgrade, self(), StreamRef, [<<"websocket">>], Headers},
	{ok, HandlerState} = Handler:init(Owner, StreamRef, Headers, Opts),
	{switch_protocol, ?MODULE, #ws_state{owner=Owner, stream_ref=StreamRef,
		socket=Socket, transport=Transport, extensions=Extensions,
		flow=InitialFlow, handler=Handler, handler_state=HandlerState}}.

%% Do not handle anything if we received a close frame.
handle(_, State=#ws_state{in=close}, _, EvHandlerState) ->
	{{state, State}, EvHandlerState};
%% Shortcut for common case when Data is empty after processing a frame.
handle(<<>>, State=#ws_state{in=head}, _, EvHandlerState) ->
	maybe_active(State, EvHandlerState);
handle(Data, State=#ws_state{owner=ReplyTo, stream_ref=StreamRef, buffer=Buffer,
		in=head, frag_state=FragState, extensions=Extensions},
		EvHandler, EvHandlerState0) ->
	%% Send the event only if there was no data in the buffer.
	%% If there is data in the buffer then we already sent the event.
	EvHandlerState1 = case Buffer of
		<<>> ->
			EvHandler:ws_recv_frame_start(#{
				stream_ref => StreamRef,
				reply_to => ReplyTo,
				frag_state => FragState,
				extensions => Extensions
			}, EvHandlerState0);
		_ ->
			EvHandlerState0
	end,
	Data2 = << Buffer/binary, Data/binary >>,
	case cow_ws:parse_header(Data2, Extensions, FragState) of
		{Type, FragState2, Rsv, Len, MaskKey, Rest} ->
			EvHandlerState = EvHandler:ws_recv_frame_header(#{
				stream_ref => StreamRef,
				reply_to => ReplyTo,
				frag_state => FragState2,
				extensions => Extensions,
				type => Type,
				rsv => Rsv,
				len => Len,
				mask_key => MaskKey
			}, EvHandlerState1),
			handle(Rest, State#ws_state{buffer= <<>>,
				in=#payload{type=Type, rsv=Rsv, len=Len, mask_key=MaskKey},
				frag_state=FragState2}, EvHandler, EvHandlerState);
		more ->
			maybe_active(State#ws_state{buffer=Data2}, EvHandlerState1);
		error ->
			close({error, badframe}, State, EvHandler, EvHandlerState1)
	end;
handle(Data, State=#ws_state{in=In=#payload{type=Type, rsv=Rsv, len=Len, mask_key=MaskKey,
		close_code=CloseCode, unmasked=Unmasked, unmasked_len=UnmaskedLen}, frag_state=FragState,
		utf8_state=Utf8State, extensions=Extensions}, EvHandler, EvHandlerState) ->
	case cow_ws:parse_payload(Data, MaskKey, Utf8State, UnmaskedLen, Type, Len, FragState, Extensions, Rsv) of
		{ok, CloseCode2, Payload, Utf8State2, Rest} ->
			dispatch(Rest, State#ws_state{in=head, utf8_state=Utf8State2}, Type,
				<<Unmasked/binary, Payload/binary>>, CloseCode2,
				EvHandler, EvHandlerState);
		{ok, Payload, Utf8State2, Rest} ->
			dispatch(Rest, State#ws_state{in=head, utf8_state=Utf8State2}, Type,
				<<Unmasked/binary, Payload/binary>>, CloseCode,
				EvHandler, EvHandlerState);
		{more, CloseCode2, Payload, Utf8State2} ->
			maybe_active(State#ws_state{in=In#payload{close_code=CloseCode2,
				unmasked= <<Unmasked/binary, Payload/binary>>,
				len=Len - byte_size(Data), unmasked_len=2 + byte_size(Data)}, utf8_state=Utf8State2},
				EvHandlerState);
		{more, Payload, Utf8State2} ->
			maybe_active(State#ws_state{in=In#payload{unmasked= <<Unmasked/binary, Payload/binary>>,
				len=Len - byte_size(Data), unmasked_len=UnmaskedLen + byte_size(Data)}, utf8_state=Utf8State2},
				EvHandlerState);
		Error = {error, _Reason} ->
			close(Error, State, EvHandler, EvHandlerState)
	end.

maybe_active(State=#ws_state{flow=Flow}, EvHandlerState) ->
	{[
		{state, State},
		{active, Flow > 0}
	], EvHandlerState}.

dispatch(Rest, State0=#ws_state{owner=ReplyTo, stream_ref=StreamRef,
		frag_state=FragState, extensions=Extensions, flow=Flow0,
		handler=Handler, handler_state=HandlerState0},
		Type, Payload, CloseCode, EvHandler, EvHandlerState0) ->
	EvHandlerState1 = EvHandler:ws_recv_frame_end(#{
		stream_ref => StreamRef,
		reply_to => ReplyTo,
		extensions => Extensions,
		close_code => CloseCode,
		payload => Payload
	}, EvHandlerState0),
	case cow_ws:make_frame(Type, Payload, CloseCode, FragState) of
		ping ->
			{{state, State}, EvHandlerState} = send(pong, State0, EvHandler, EvHandlerState1),
			handle(Rest, State, EvHandler, EvHandlerState);
		{ping, Payload} ->
			{{state, State}, EvHandlerState} = send({pong, Payload}, State0, EvHandler, EvHandlerState1),
			handle(Rest, State, EvHandler, EvHandlerState);
		pong ->
			handle(Rest, State0, EvHandler, EvHandlerState1);
		{pong, _} ->
			handle(Rest, State0, EvHandler, EvHandlerState1);
		Frame ->
			{ok, Dec, HandlerState} = Handler:handle(Frame, HandlerState0),
			Flow = case Flow0 of
				infinity -> infinity;
				_ -> Flow0 - Dec
			end,
			State1 = State0#ws_state{flow=Flow, handler_state=HandlerState},
			State = case Frame of
				close -> State1#ws_state{in=close};
				{close, _, _} -> State1#ws_state{in=close};
				{fragment, fin, _, _} -> State1#ws_state{frag_state=undefined};
				_ -> State1
			end,
			handle(Rest, State, EvHandler, EvHandlerState1)
	end.

update_flow(State=#ws_state{flow=Flow0}, _ReplyTo, _StreamRef, Inc) ->
	Flow = case Flow0 of
		infinity -> infinity;
		_ -> Flow0 + Inc
	end,
	[
		{state, State#ws_state{flow=Flow}},
		{active, Flow > 0}
	].

close(Reason, State, EvHandler, EvHandlerState) ->
	case Reason of
		normal ->
			send({close, 1000, <<>>}, State, EvHandler, EvHandlerState);
		owner_down ->
			send({close, 1001, <<>>}, State, EvHandler, EvHandlerState);
		{error, badframe} ->
			send({close, 1002, <<>>}, State, EvHandler, EvHandlerState);
		{error, badencoding} ->
			send({close, 1007, <<>>}, State, EvHandler, EvHandlerState);
		%% Socket errors; do nothing.
		closed ->
			{ok, EvHandlerState};
		{error, _} ->
			{ok, EvHandlerState}
	end.

send(Frame, State=#ws_state{owner=ReplyTo, stream_ref=StreamRef,
		socket=Socket, transport=Transport, extensions=Extensions},
		EvHandler, EvHandlerState0) ->
	WsSendFrameEvent = #{
		stream_ref => StreamRef,
		reply_to => ReplyTo,
		extensions => Extensions,
		frame => Frame
	},
	EvHandlerState1 = EvHandler:ws_send_frame_start(WsSendFrameEvent, EvHandlerState0),
	Transport:send(Socket, cow_ws:masked_frame(Frame, Extensions)),
	EvHandlerState = EvHandler:ws_send_frame_end(WsSendFrameEvent, EvHandlerState1),
	case Frame of
		close -> {close, EvHandlerState};
		{close, _, _} -> {close, EvHandlerState};
		_ -> {{state, State}, EvHandlerState}
	end.

%% Websocket has no concept of streams.
down(_) ->
	{[], []}.
