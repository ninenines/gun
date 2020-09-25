%% Copyright (c) 2014-2019, Loïc Hoguin <essen@ninenines.eu>
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

-module(gun_http).

-export([check_options/1]).
-export([name/0]).
-export([opts_name/0]).
-export([has_keepalive/0]).
-export([default_keepalive/0]).
-export([init/4]).
-export([switch_transport/3]).
-export([handle/4]).
-export([update_flow/4]).
-export([closing/4]).
-export([close/4]).
-export([keepalive/3]).
-export([headers/11]).
-export([request/12]).
-export([data/7]).
-export([connect/7]).
-export([cancel/5]).
-export([stream_info/2]).
-export([down/1]).
-export([ws_upgrade/10]).

%% Functions shared with gun_http2.
-export([host_header/3]).

-type io() :: head | {body, non_neg_integer()} | body_close | body_chunked | body_trailer.

%% @todo Make that a record.
-type connect_info() :: {connect, gun:stream_ref(), gun:connect_destination()}.

-record(websocket, {
	ref :: gun:stream_ref(),
	reply_to :: pid(),
	key :: binary(),
	extensions :: [binary()],
	opts :: gun:ws_opts()
}).

-record(stream, {
	ref :: gun:stream_ref() | connect_info() | #websocket{},
	reply_to :: pid(),
	flow :: integer() | infinity,
	method :: binary(),

	%% Request target URI.
	authority :: iodata(),
	path :: iodata(),

	is_alive :: boolean(),
	handler_state :: undefined | gun_content_handler:state()
}).

-record(http_state, {
	socket :: inet:socket() | ssl:sslsocket(),
	transport :: module(),
	opts = #{} :: gun:http_opts(),
	version = 'HTTP/1.1' :: cow_http:version(),
	connection = keepalive :: keepalive | close,
	buffer = <<>> :: binary(),

	%% Base stream ref, defined when the protocol runs
	%% inside an HTTP/2 CONNECT stream.
	base_stream_ref = undefined :: undefined | gun:stream_ref(),

	streams = [] :: [#stream{}],
	in = head :: io(),
	in_state = {0, 0} :: {non_neg_integer(), non_neg_integer()},
	out = head :: io(),

	%% We must queue commands when parsing the incoming data.
	commands_queue = [] :: [{set_cookie, iodata(), iodata(), cow_http:status(), cow_http:headers()}]
}).

check_options(Opts) ->
	do_check_options(maps:to_list(Opts)).

do_check_options([]) ->
	ok;
do_check_options([{closing_timeout, infinity}|Opts]) ->
	do_check_options(Opts);
do_check_options([{closing_timeout, T}|Opts]) when is_integer(T), T > 0 ->
	do_check_options(Opts);
do_check_options([Opt={content_handlers, Handlers}|Opts]) ->
	case gun_content_handler:check_option(Handlers) of
		ok -> do_check_options(Opts);
		error -> {error, {options, {http, Opt}}}
	end;
do_check_options([{flow, InitialFlow}|Opts]) when is_integer(InitialFlow), InitialFlow > 0 ->
	do_check_options(Opts);
do_check_options([{keepalive, infinity}|Opts]) ->
	do_check_options(Opts);
do_check_options([{keepalive, K}|Opts]) when is_integer(K), K > 0 ->
	do_check_options(Opts);
do_check_options([{transform_header_name, F}|Opts]) when is_function(F) ->
	do_check_options(Opts);
do_check_options([{version, V}|Opts]) when V =:= 'HTTP/1.1'; V =:= 'HTTP/1.0' ->
	do_check_options(Opts);
do_check_options([Opt|_]) ->
	{error, {options, {http, Opt}}}.

name() -> http.
opts_name() -> http_opts.
has_keepalive() -> true.
default_keepalive() -> infinity.

init(_ReplyTo, Socket, Transport, Opts) ->
	BaseStreamRef = maps:get(stream_ref, Opts, undefined),
	Version = maps:get(version, Opts, 'HTTP/1.1'),
	{connected, #http_state{socket=Socket, transport=Transport,
		opts=Opts, version=Version, base_stream_ref=BaseStreamRef}}.

switch_transport(Transport, Socket, State) ->
	State#http_state{socket=Socket, transport=Transport}.

%% This function is called before returning from handle/4.
handle_ret(CommandOrCommands, #http_state{commands_queue=[]}) ->
	empty_commands_queue(CommandOrCommands);
handle_ret(Commands, #http_state{commands_queue=Queue}) when is_list(Commands) ->
	lists:reverse(Queue, empty_commands_queue(Commands));
handle_ret(Command, #http_state{commands_queue=Queue}) ->
	lists:reverse([empty_commands_queue(Command)|Queue]).

empty_commands_queue([{state, State}|Tail]) -> [{state, State#http_state{commands_queue=[]}}|Tail];
empty_commands_queue([Command|Tail]) -> [Command|empty_commands_queue(Tail)];
empty_commands_queue([]) -> [];
empty_commands_queue({state, State}) -> {state, State#http_state{commands_queue=[]}};
empty_commands_queue(Command) -> Command.

%% Stop looping when we got no more data.
handle(<<>>, State, _, EvHandlerState) ->
	{handle_ret({state, State}, State), EvHandlerState};
%% Close when server responds and we don't have any open streams.
handle(_, State=#http_state{streams=[]}, _, EvHandlerState) ->
	{handle_ret(close, State), EvHandlerState};
%% Wait for the full response headers before trying to parse them.
handle(Data, State=#http_state{in=head, buffer=Buffer,
		streams=[#stream{ref=StreamRef, reply_to=ReplyTo}|_]}, EvHandler, EvHandlerState0) ->
	%% Send the event only if there was no data in the buffer.
	%% If there is data in the buffer then we already sent the event.
	EvHandlerState = case Buffer of
		<<>> ->
			EvHandler:response_start(#{
				stream_ref => stream_ref(State, StreamRef),
				reply_to => ReplyTo
			}, EvHandlerState0);
		_ ->
			EvHandlerState0
	end,
	Data2 = << Buffer/binary, Data/binary >>,
	case binary:match(Data2, <<"\r\n\r\n">>) of
		nomatch -> {handle_ret({state, State#http_state{buffer=Data2}}, State), EvHandlerState};
		{_, _} -> handle_head(Data2, State#http_state{buffer= <<>>}, EvHandler, EvHandlerState)
	end;
%% Everything sent to the socket until it closes is part of the response body.
handle(Data, State=#http_state{in=body_close}, _, EvHandlerState) ->
	{handle_ret(send_data(Data, State, nofin), State), EvHandlerState};
%% Chunked transfer-encoding may contain both data and trailers.
handle(Data, State=#http_state{in=body_chunked, in_state=InState,
		buffer=Buffer, streams=[#stream{ref=StreamRef, reply_to=ReplyTo}|_],
		connection=Conn}, EvHandler, EvHandlerState0) ->
	Buffer2 = << Buffer/binary, Data/binary >>,
	case cow_http_te:stream_chunked(Buffer2, InState) of
		more ->
			{handle_ret({state, State#http_state{buffer=Buffer2}}, State), EvHandlerState0};
		{more, Data2, InState2} ->
			{handle_ret(send_data(Data2, State#http_state{buffer= <<>>, in_state=InState2}, nofin), State),
				EvHandlerState0};
		{more, Data2, Length, InState2} when is_integer(Length) ->
			%% @todo See if we can recv faster than one message at a time.
			{handle_ret(send_data(Data2, State#http_state{buffer= <<>>, in_state=InState2}, nofin), State),
				EvHandlerState0};
		{more, Data2, Rest, InState2} ->
			%% @todo See if we can recv faster than one message at a time.
			{handle_ret(send_data(Data2, State#http_state{buffer=Rest, in_state=InState2}, nofin), State),
				EvHandlerState0};
		{done, HasTrailers, Rest} ->
			%% @todo response_end should be called AFTER send_data
			{IsFin, EvHandlerState} = case HasTrailers of
				trailers ->
					{nofin, EvHandlerState0};
				no_trailers ->
					EvHandlerState1 = EvHandler:response_end(#{
						stream_ref => StreamRef,
						reply_to => ReplyTo
					}, EvHandlerState0),
					{fin, EvHandlerState1}
			end,
			%% I suppose it doesn't hurt to append an empty binary.
			%% We ignore the active command because the stream ended.
			[{state, State1}|_] = send_data(<<>>, State, IsFin),
			case {HasTrailers, Conn} of
				{trailers, _} ->
					handle(Rest, State1#http_state{buffer = <<>>, in=body_trailer}, EvHandler, EvHandlerState);
				{no_trailers, keepalive} ->
					handle(Rest, end_stream(State1#http_state{buffer= <<>>}), EvHandler, EvHandlerState);
				{no_trailers, close} ->
					{handle_ret([{state, end_stream(State1)}, close], State1), EvHandlerState}
			end;
		{done, Data2, HasTrailers, Rest} ->
			%% @todo response_end should be called AFTER send_data
			{IsFin, EvHandlerState} = case HasTrailers of
				trailers ->
					{nofin, EvHandlerState0};
				no_trailers ->
					EvHandlerState1 = EvHandler:response_end(#{
						stream_ref => StreamRef,
						reply_to => ReplyTo
					}, EvHandlerState0),
					{fin, EvHandlerState1}
			end,
			%% We ignore the active command because the stream ended.
			[{state, State1}|_] = send_data(Data2, State, IsFin),
			case {HasTrailers, Conn} of
				{trailers, _} ->
					handle(Rest, State1#http_state{buffer = <<>>, in=body_trailer}, EvHandler, EvHandlerState);
				{no_trailers, keepalive} ->
					handle(Rest, end_stream(State1#http_state{buffer= <<>>}), EvHandler, EvHandlerState);
				{no_trailers, close} ->
					{handle_ret([{state, end_stream(State1)}, close], State1), EvHandlerState}
			end
	end;
handle(Data, State=#http_state{in=body_trailer, buffer=Buffer, connection=Conn,
		streams=[#stream{ref=StreamRef, reply_to=ReplyTo}|_]}, EvHandler, EvHandlerState0) ->
	Data2 = << Buffer/binary, Data/binary >>,
	case binary:match(Data2, <<"\r\n\r\n">>) of
		nomatch ->
			{handle_ret({state, State#http_state{buffer=Data2}}, State), EvHandlerState0};
		{_, _} ->
			{Trailers, Rest} = cow_http:parse_headers(Data2),
			%% @todo We probably want to pass this to gun_content_handler?
			ReplyTo ! {gun_trailers, self(), stream_ref(State, StreamRef), Trailers},
			ResponseEvent = #{
				stream_ref => StreamRef,
				reply_to => ReplyTo
			},
			EvHandlerState1 = EvHandler:response_trailers(ResponseEvent#{headers => Trailers}, EvHandlerState0),
			EvHandlerState = EvHandler:response_end(ResponseEvent, EvHandlerState1),
			case Conn of
				keepalive ->
					handle(Rest, end_stream(State#http_state{buffer= <<>>}), EvHandler, EvHandlerState);
				close ->
					{handle_ret([{state, end_stream(State)}, close], State), EvHandlerState}
			end
	end;
%% We know the length of the rest of the body.
handle(Data, State=#http_state{in={body, Length}, connection=Conn,
		streams=[#stream{ref=StreamRef, reply_to=ReplyTo}|_]},
		EvHandler, EvHandlerState0) ->
	DataSize = byte_size(Data),
	if
		%% More data coming.
		DataSize < Length ->
			{handle_ret(send_data(Data, State#http_state{in={body, Length - DataSize}}, nofin), State),
				EvHandlerState0};
		%% Stream finished, no rest.
		DataSize =:= Length ->
			%% We ignore the active command because the stream ended.
			[{state, State1}|_] = send_data(Data, State, fin),
			EvHandlerState = EvHandler:response_end(#{
				stream_ref => StreamRef,
				reply_to => ReplyTo
			}, EvHandlerState0),
			case Conn of
				keepalive ->
					{handle_ret([{state, end_stream(State1)}, {active, true}], State1), EvHandlerState};
				close ->
					{handle_ret([{state, end_stream(State1)}, close], State1), EvHandlerState}
			end;
		%% Stream finished, rest.
		true ->
			<< Body:Length/binary, Rest/bits >> = Data,
			%% We ignore the active command because the stream ended.
			[{state, State1}|_] = send_data(Body, State, fin),
			EvHandlerState = EvHandler:response_end(#{
				stream_ref => StreamRef,
				reply_to => ReplyTo
			}, EvHandlerState0),
			case Conn of
				keepalive -> handle(Rest, end_stream(State1), EvHandler, EvHandlerState);
				close -> {handle_ret([{state, end_stream(State1)}, close], State1), EvHandlerState}
			end
	end.

handle_head(Data, State0=#http_state{streams=[#stream{ref=StreamRef, authority=Authority, path=Path}|_],
		commands_queue=Commands}, EvHandler, EvHandlerState) ->
	{Version, Status, _, Rest0} = cow_http:parse_status_line(Data),
	{Headers, Rest} = cow_http:parse_headers(Rest0),
	State = State0#http_state{commands_queue=[{set_cookie, Authority, Path, Status, Headers}|Commands]},
	case StreamRef of
		{connect, _, _} when Status >= 200, Status < 300 ->
			handle_connect(Rest, State, EvHandler, EvHandlerState, Version, Status, Headers);
		_ when Status >= 100, Status =< 199 ->
			handle_inform(Rest, State, EvHandler, EvHandlerState, Version, Status, Headers);
		_ ->
			handle_response(Rest, State, EvHandler, EvHandlerState, Version, Status, Headers)
	end.

handle_connect(Rest, State=#http_state{
		streams=[Stream=#stream{ref={_, StreamRef, Destination}, reply_to=ReplyTo}|Tail]},
		EvHandler, EvHandlerState0, 'HTTP/1.1', Status, Headers) ->
	RealStreamRef = stream_ref(State, StreamRef),
	%% @todo If the stream is cancelled we probably shouldn't finish the CONNECT setup.
	_ = case Stream of
		#stream{is_alive=false} -> ok;
		_ -> ReplyTo ! {gun_response, self(), RealStreamRef, fin, Status, Headers}
	end,
	%% @todo Figure out whether the event should trigger if the stream was cancelled.
	EvHandlerState1 = EvHandler:response_headers(#{
		stream_ref => RealStreamRef,
		reply_to => ReplyTo,
		status => Status,
		headers => Headers
	}, EvHandlerState0),
	%% We expect there to be no additional data after the CONNECT response.
	%% @todo That's probably wrong.
	<<>> = Rest,
	_ = end_stream(State#http_state{streams=[Stream|Tail]}),
	NewHost = maps:get(host, Destination),
	NewPort = maps:get(port, Destination),
	case Destination of
		#{transport := tls} ->
			HandshakeEvent = #{
				stream_ref => RealStreamRef,
				reply_to => ReplyTo,
				tls_opts => maps:get(tls_opts, Destination, []),
				timeout => maps:get(tls_handshake_timeout, Destination, infinity)
			},
			Protocols = maps:get(protocols, Destination, [http2, http]),
			{handle_ret([
				{origin, <<"https">>, NewHost, NewPort, connect},
				{tls_handshake, HandshakeEvent, Protocols, ReplyTo}
			], State), EvHandlerState1};
		_ ->
			[NewProtocol0] = maps:get(protocols, Destination, [http]),
			NewProtocol = gun_protocols:add_stream_ref(NewProtocol0, RealStreamRef),
			Protocol = gun_protocols:handler(NewProtocol),
			ReplyTo ! {gun_tunnel_up, self(), RealStreamRef, Protocol:name()},
			{handle_ret([
				{origin, <<"http">>, NewHost, NewPort, connect},
				{switch_protocol, NewProtocol, ReplyTo}
			], State), EvHandlerState1}
	end.

%% @todo We probably shouldn't send info messages if the stream is not alive.
handle_inform(Rest, State=#http_state{
		streams=[#stream{ref=StreamRef, reply_to=ReplyTo}|_]},
		EvHandler, EvHandlerState0, Version, Status, Headers) ->
	EvHandlerState = EvHandler:response_inform(#{
		stream_ref => stream_ref(State, StreamRef),
		reply_to => ReplyTo,
		status => Status,
		headers => Headers
	}, EvHandlerState0),
	%% @todo We might want to switch to the HTTP/2 protocol or to the TLS transport as well.
	case {Version, Status, StreamRef} of
		{'HTTP/1.1', 101, #websocket{}} ->
			{handle_ret(ws_handshake(Rest, State, StreamRef, Headers), State), EvHandlerState};
		%% Any other 101 response results in us switching to the raw protocol.
		%% @todo We should check that we asked for an upgrade before accepting it.
		{'HTTP/1.1', 101, _} when is_reference(StreamRef) ->
			try
				%% @todo We shouldn't ignore Rest.
				{_, Upgrade0} = lists:keyfind(<<"upgrade">>, 1, Headers),
				Upgrade = cow_http_hd:parse_upgrade(Upgrade0),
				ReplyTo ! {gun_upgrade, self(), stream_ref(State, StreamRef), Upgrade, Headers},
				%% @todo We probably need to add_stream_ref?
				{handle_ret({switch_protocol, raw, ReplyTo}, State), EvHandlerState0}
			catch _:_ ->
				%% When the Upgrade header is missing or invalid we treat
				%% the response as any other informational response.
				ReplyTo ! {gun_inform, self(), stream_ref(State, StreamRef), Status, Headers},
				handle(Rest, State, EvHandler, EvHandlerState)
			end;
		_ ->
			ReplyTo ! {gun_inform, self(), stream_ref(State, StreamRef), Status, Headers},
			handle(Rest, State, EvHandler, EvHandlerState)
	end.

handle_response(Rest, State=#http_state{version=ClientVersion, opts=Opts, connection=Conn,
		streams=[Stream=#stream{ref=StreamRef, reply_to=ReplyTo, method=Method, is_alive=IsAlive}|Tail]},
		EvHandler, EvHandlerState0, Version, Status, Headers) ->
	In = response_io_from_headers(Method, Version, Status, Headers),
	IsFin = case In of head -> fin; _ -> nofin end,
	%% @todo Figure out whether the event should trigger if the stream was cancelled.
	{Handlers, EvHandlerState2} = case IsAlive of
		false ->
			{undefined, EvHandlerState0};
		true ->
			ReplyTo ! {gun_response, self(), stream_ref(State, StreamRef),
				IsFin, Status, Headers},
			EvHandlerState1 = EvHandler:response_headers(#{
				stream_ref => StreamRef,
				reply_to => ReplyTo,
				status => Status,
				headers => Headers
			}, EvHandlerState0),
			case IsFin of
				fin -> {undefined, EvHandlerState1};
				nofin ->
					Handlers0 = maps:get(content_handlers, Opts, [gun_data_h]),
					{gun_content_handler:init(ReplyTo, stream_ref(State, StreamRef),
						Status, Headers, Handlers0), EvHandlerState1}
			end
	end,
	EvHandlerState = case IsFin of
		nofin ->
			EvHandlerState2;
		fin ->
			EvHandler:response_end(#{
				stream_ref => StreamRef,
				reply_to => ReplyTo
			}, EvHandlerState2)
	end,
	Conn2 = if
		Conn =:= close -> close;
		Version =:= 'HTTP/1.0' -> close;
		ClientVersion =:= 'HTTP/1.0' -> close;
		true -> conn_from_headers(Version, Headers)
	end,
	%% We always reset in_state even if not chunked.
	if
		IsFin =:= fin, Conn2 =:= close ->
			{handle_ret(close, State), EvHandlerState};
		IsFin =:= fin ->
			handle(Rest, end_stream(State#http_state{in=In,
				in_state={0, 0}, connection=Conn2,
				streams=[Stream#stream{handler_state=Handlers}|Tail]}),
				EvHandler, EvHandlerState);
		true ->
			handle(Rest, State#http_state{in=In,
				in_state={0, 0}, connection=Conn2,
				streams=[Stream#stream{handler_state=Handlers}|Tail]},
				EvHandler, EvHandlerState)
	end.

%% The state must be first in order to retrieve it when the stream ended.
send_data(<<>>, State, nofin) ->
	[{state, State}, {active, true}];
%% @todo What if we receive data when the HEAD method was used?
send_data(Data, State=#http_state{streams=[Stream=#stream{
		flow=Flow0, is_alive=true, handler_state=Handlers0}|Tail]}, IsFin) ->
	{ok, Dec, Handlers} = gun_content_handler:handle(IsFin, Data, Handlers0),
	Flow = case Flow0 of
		infinity -> infinity;
		_ -> Flow0 - Dec
	end,
	[
		{state, State#http_state{streams=[Stream#stream{flow=Flow, handler_state=Handlers}|Tail]}},
		{active, Flow > 0}
	];
send_data(_, State, _) ->
	[{state, State}, {active, true}].

%% We only update the active state when the current stream is being updated.
update_flow(State=#http_state{streams=[Stream=#stream{ref=StreamRef, flow=Flow0}|Tail]},
		_ReplyTo, StreamRef, Inc) ->
	Flow = case Flow0 of
		infinity -> infinity;
		_ -> Flow0 + Inc
	end,
	[
		{state, State#http_state{streams=[Stream#stream{flow=Flow}|Tail]}},
		{active, Flow > 0}
	];
update_flow(State=#http_state{streams=Streams0}, _ReplyTo, StreamRef, Inc) ->
	Streams = [case Ref of
		StreamRef when Flow =/= infinity ->
			Tuple#stream{flow=Flow + Inc};
		_ ->
			Tuple
	end || Tuple = #stream{ref=Ref, flow=Flow} <- Streams0],
	{state, State#http_state{streams=Streams}}.

%% We can immediately close the connection when there's no streams.
closing(_, #http_state{streams=[]}, _, EvHandlerState) ->
	{close, EvHandlerState};
%% Otherwise we set connection: close (even if the header was not sent)
%% and close any pipelined streams, only keeping the active stream.
closing(Reason, State=#http_state{streams=[LastStream|Tail]}, _, EvHandlerState) ->
	close_streams(State, Tail, {closing, Reason}),
	{[
		{state, State#http_state{connection=close, streams=[LastStream]}},
		closing(State)
	], EvHandlerState}.

closing(#http_state{opts=Opts}) ->
	Timeout = maps:get(closing_timeout, Opts, 15000),
	{closing, Timeout}.

close(Reason, State=#http_state{in=body_close,
		streams=[#stream{ref=StreamRef, reply_to=ReplyTo}|Tail]},
		EvHandler, EvHandlerState) ->
	%% We may have more than one stream in case we somehow close abruptly.
	close_streams(State, Tail, close_reason(Reason)),
	_ = send_data(<<>>, State, fin),
	EvHandler:response_end(#{
		stream_ref => StreamRef,
		reply_to => ReplyTo
	}, EvHandlerState);
close(Reason, State=#http_state{streams=Streams}, _, EvHandlerState) ->
	close_streams(State, Streams, close_reason(Reason)),
	EvHandlerState.

close_reason(closed) -> closed;
close_reason(Reason) -> {closed, Reason}.

%% @todo Do we want an event for this?
%%
%% @todo Need to propagate stream closing to tunneled streams.
close_streams(_, [], _) ->
	ok;
close_streams(State, [#stream{is_alive=false}|Tail], Reason) ->
	close_streams(State, Tail, Reason);
close_streams(State, [#stream{ref=StreamRef, reply_to=ReplyTo}|Tail], Reason) ->
	ReplyTo ! {gun_error, self(), stream_ref(State, StreamRef), Reason},
	close_streams(State, Tail, Reason).

%% We don't send a keep-alive when a CONNECT request was initiated.
keepalive(State=#http_state{streams=[#stream{ref={connect, _, _}}]}, _, EvHandlerState) ->
	{State, EvHandlerState};
%% We can only keep-alive by sending an empty line in-between streams.
keepalive(State=#http_state{socket=Socket, transport=Transport, out=head}, _, EvHandlerState) ->
	Transport:send(Socket, <<"\r\n">>),
	{State, EvHandlerState};
keepalive(State, _, EvHandlerState) ->
	{State, EvHandlerState}.

headers(State, StreamRef, ReplyTo, Method, Host, Port,
		Path, Headers, InitialFlow, EvHandler, EvHandlerState)
		when is_list(StreamRef) ->
	%% Because we switch protocol we may receive a StreamRef as a list.
	%% But we are always the final StreamRef as HTTP/1.1.
	headers(State, lists:last(StreamRef), ReplyTo, Method, Host, Port,
		Path, Headers, InitialFlow, EvHandler, EvHandlerState);
headers(State=#http_state{opts=Opts, out=head},
		StreamRef, ReplyTo, Method, Host, Port, Path, Headers,
		InitialFlow0, EvHandler, EvHandlerState0) ->
	{Authority, Conn, Out, EvHandlerState} = send_request(State, StreamRef, ReplyTo,
		Method, Host, Port, Path, Headers, undefined,
		EvHandler, EvHandlerState0, ?FUNCTION_NAME),
	InitialFlow = initial_flow(InitialFlow0, Opts),
	{new_stream(State#http_state{connection=Conn, out=Out}, StreamRef, ReplyTo,
		Method, Authority, Path, InitialFlow), EvHandlerState}.

%% @todo I don't think this clause is hit anymore. Same in other related callbacks.
request(State, StreamRef, ReplyTo, Method, Host, Port,
		Path, Headers, Body, InitialFlow, EvHandler, EvHandlerState)
		when is_list(StreamRef) ->
	%% Because we switch protocol we may receive a StreamRef as a list.
	%% But we are always the final StreamRef as HTTP/1.1.
	request(State, lists:last(StreamRef), ReplyTo, Method, Host, Port,
		Path, Headers, Body, InitialFlow, EvHandler, EvHandlerState);
request(State=#http_state{opts=Opts, out=head}, StreamRef, ReplyTo,
		Method, Host, Port, Path, Headers, Body,
		InitialFlow0, EvHandler, EvHandlerState0) ->
	{Authority, Conn, Out, EvHandlerState} = send_request(State, StreamRef, ReplyTo,
		Method, Host, Port, Path, Headers, Body,
		EvHandler, EvHandlerState0, ?FUNCTION_NAME),
	InitialFlow = initial_flow(InitialFlow0, Opts),
	{new_stream(State#http_state{connection=Conn, out=Out}, StreamRef, ReplyTo,
		Method, Authority, Path, InitialFlow), EvHandlerState}.

initial_flow(infinity, #{flow := InitialFlow}) -> InitialFlow;
initial_flow(InitialFlow, _) -> InitialFlow.

send_request(State=#http_state{socket=Socket, transport=Transport, version=Version},
		StreamRef, ReplyTo, Method, Host, Port, Path, Headers0, Body,
		EvHandler, EvHandlerState0, Function) ->
	Headers1 = lists:keydelete(<<"transfer-encoding">>, 1, Headers0),
	Headers2 = case Body of
		undefined -> Headers1;
		_ -> lists:keydelete(<<"content-length">>, 1, Headers1)
	end,
	%% We use Headers2 because this is the smallest list.
	Conn = conn_from_headers(Version, Headers2),
	Out = case Body of
		undefined when Function =:= ws_upgrade -> head;
		undefined -> request_io_from_headers(Headers2);
		_ -> head
	end,
	%% @todo Move this inside the case clause.
	Authority0 = host_header(Transport, Host, Port),
	{Authority, Headers3} = case lists:keyfind(<<"host">>, 1, Headers2) of
		false -> {Authority0, [{<<"host">>, Authority0}|Headers2]};
		{_, Authority1} -> {Authority1, Headers2}
	end,
	Headers4 = transform_header_names(State, Headers3),
	Headers = case {Body, Out} of
		{undefined, body_chunked} when Version =:= 'HTTP/1.0' -> Headers4;
		{undefined, body_chunked} -> [{<<"transfer-encoding">>, <<"chunked">>}|Headers4];
		{undefined, _} -> Headers4;
		_ -> [{<<"content-length">>, integer_to_binary(iolist_size(Body))}|Headers4]
	end,
	RequestEvent = #{
		stream_ref => StreamRef,
		reply_to => ReplyTo,
		function => Function,
		method => Method,
		authority => Authority,
		path => Path,
		headers => Headers
	},
	EvHandlerState1 = EvHandler:request_start(RequestEvent, EvHandlerState0),
	Transport:send(Socket, [
		cow_http:request(Method, Path, Version, Headers),
		[Body || Body =/= undefined]]),
	EvHandlerState2 = EvHandler:request_headers(RequestEvent, EvHandlerState1),
	EvHandlerState = case Out of
		head ->
			RequestEndEvent = #{
				stream_ref => StreamRef,
				reply_to => ReplyTo
			},
			EvHandler:request_end(RequestEndEvent, EvHandlerState2);
		_ ->
			EvHandlerState2
	end,
	{Authority, Conn, Out, EvHandlerState}.

host_header(Transport, Host0, Port) ->
	Host = case Host0 of
		{local, _SocketPath} -> <<>>;
		Tuple when tuple_size(Tuple) =:= 8 -> [$[, inet:ntoa(Tuple), $]]; %% IPv6.
		Tuple when tuple_size(Tuple) =:= 4 -> inet:ntoa(Tuple); %% IPv4.
		Atom when is_atom(Atom) -> atom_to_list(Atom);
		_ -> Host0
	end,
	case {Transport:name(), Port} of
		{tcp, 80} -> Host;
		{tls, 443} -> Host;
		_ -> [Host, $:, integer_to_binary(Port)]
	end.

transform_header_names(#http_state{opts=Opts}, Headers) ->
	case maps:get(transform_header_name, Opts, undefined) of
		undefined -> Headers;
		Fun -> lists:keymap(Fun, 1, Headers)
	end.

data(State, StreamRef, ReplyTo, IsFin, Data, EvHandler, EvHandlerState)
		when is_list(StreamRef) ->
	%% Because we switch protocol we may receive a StreamRef as a list.
	%% But we are always the final StreamRef as HTTP/1.1.
	data(State, lists:last(StreamRef), ReplyTo, IsFin, Data, EvHandler, EvHandlerState);
%% We are expecting a new stream.
data(State=#http_state{out=head}, StreamRef, ReplyTo, _, _, _, EvHandlerState) ->
	{error_stream_closed(State, StreamRef, ReplyTo), EvHandlerState};
%% There are no active streams.
data(State=#http_state{streams=[]}, StreamRef, ReplyTo, _, _, _, EvHandlerState) ->
	{error_stream_not_found(State, StreamRef, ReplyTo), EvHandlerState};
%% We can only send data on the last created stream.
data(State=#http_state{socket=Socket, transport=Transport, version=Version,
		out=Out, streams=Streams}, StreamRef, ReplyTo, IsFin, Data,
		EvHandler, EvHandlerState0) ->
	case lists:last(Streams) of
		#stream{ref=StreamRef, is_alive=true} ->
			DataLength = iolist_size(Data),
			case Out of
				body_chunked when Version =:= 'HTTP/1.1', IsFin =:= fin ->
					case Data of
						<<>> ->
							Transport:send(Socket, cow_http_te:last_chunk());
						_ ->
							Transport:send(Socket, [
								cow_http_te:chunk(Data),
								cow_http_te:last_chunk()
							])
					end,
					RequestEndEvent = #{
						stream_ref => StreamRef,
						reply_to => ReplyTo
					},
					EvHandlerState = EvHandler:request_end(RequestEndEvent, EvHandlerState0),
					{State#http_state{out=head}, EvHandlerState};
				body_chunked when Version =:= 'HTTP/1.1' ->
					Transport:send(Socket, cow_http_te:chunk(Data)),
					{State, EvHandlerState0};
				{body, Length} when DataLength =< Length ->
					Transport:send(Socket, Data),
					Length2 = Length - DataLength,
					if
						Length2 =:= 0, IsFin =:= fin ->
							RequestEndEvent = #{
								stream_ref => StreamRef,
								reply_to => ReplyTo
							},
							EvHandlerState = EvHandler:request_end(RequestEndEvent, EvHandlerState0),
							{State#http_state{out=head}, EvHandlerState};
						Length2 > 0, IsFin =:= nofin ->
							{State#http_state{out={body, Length2}}, EvHandlerState0}
					end;
				body_chunked -> %% HTTP/1.0
					Transport:send(Socket, Data),
					{State, EvHandlerState0}
			end;
		_ ->
			{error_stream_not_found(State, StreamRef, ReplyTo), EvHandlerState0}
	end.

connect(State, StreamRef, ReplyTo, Destination, TunnelInfo, Headers, InitialFlow)
		when is_list(StreamRef) ->
	%% Because we switch protocol we may receive a StreamRef as a list.
	%% But we are always the final StreamRef as HTTP/1.1.
	connect(State, lists:last(StreamRef), ReplyTo, Destination, TunnelInfo, Headers, InitialFlow);
connect(State=#http_state{streams=Streams}, StreamRef, ReplyTo, _, _, _, _) when Streams =/= [] ->
	ReplyTo ! {gun_error, self(), stream_ref(State, StreamRef), {badstate,
		"CONNECT can only be used with HTTP/1.1 when no other streams are active."}},
	State;
connect(State=#http_state{socket=Socket, transport=Transport, opts=Opts, version=Version},
		StreamRef, ReplyTo, Destination=#{host := Host0}, _TunnelInfo, Headers0, InitialFlow0) ->
	Host = case Host0 of
		Tuple when is_tuple(Tuple) -> inet:ntoa(Tuple);
		_ -> Host0
	end,
	Port = maps:get(port, Destination, 1080),
	Authority = [Host, $:, integer_to_binary(Port)],
	Headers1 = lists:keydelete(<<"content-length">>, 1,
		lists:keydelete(<<"transfer-encoding">>, 1, Headers0)),
	Headers2 = case lists:keymember(<<"host">>, 1, Headers1) of
		false -> [{<<"host">>, Authority}|Headers1];
		true -> Headers1
	end,
	HasProxyAuthorization = lists:keymember(<<"proxy-authorization">>, 1, Headers2),
	Headers3 = case {HasProxyAuthorization, Destination} of
		{false, #{username := UserID, password := Password}} ->
			[{<<"proxy-authorization">>, [
					<<"Basic ">>,
					base64:encode(iolist_to_binary([UserID, $:, Password]))]}
				|Headers2];
		_ ->
			Headers2
	end,
	Headers = transform_header_names(State, Headers3),
	Transport:send(Socket, [
		cow_http:request(<<"CONNECT">>, Authority, Version, Headers)
	]),
	InitialFlow = initial_flow(InitialFlow0, Opts),
	new_stream(State, {connect, StreamRef, Destination}, ReplyTo,
		<<"CONNECT">>, Authority, <<>>, InitialFlow).

cancel(State, StreamRef, ReplyTo, EvHandler, EvHandlerState)
		when is_list(StreamRef) ->
	%% Because we switch protocol we may receive a StreamRef as a list.
	%% But we are always the final StreamRef as HTTP/1.1.
	cancel(State, lists:last(StreamRef), ReplyTo, EvHandler, EvHandlerState);
%% We can't cancel anything, we can just stop forwarding messages to the owner.
cancel(State0, StreamRef, ReplyTo, EvHandler, EvHandlerState0) ->
	case is_stream(State0, StreamRef) of
		true ->
			State = cancel_stream(State0, StreamRef),
			EvHandlerState = EvHandler:cancel(#{
				stream_ref => StreamRef,
				reply_to => ReplyTo,
				endpoint => local,
				reason => cancel
			}, EvHandlerState0),
			{State, EvHandlerState};
		false ->
			{error_stream_not_found(State0, StreamRef, ReplyTo), EvHandlerState0}
	end.

stream_info(State, StreamRef)
		when is_list(StreamRef) ->
	%% Because we switch protocol we may receive a StreamRef as a list.
	%% But we are always the final StreamRef as HTTP/1.1.
	stream_info(State, lists:last(StreamRef));
stream_info(#http_state{streams=Streams}, StreamRef) ->
	case lists:keyfind(StreamRef, #stream.ref, Streams) of
		#stream{reply_to=ReplyTo, is_alive=IsAlive} ->
			{ok, #{
				ref => StreamRef, %% @todo Wrong stream_ref? base_stream_ref it?
				reply_to => ReplyTo,
				state => case IsAlive of
					true -> running;
					false -> stopping
				end
			}};
		false ->
			{ok, undefined}
	end.

down(#http_state{streams=Streams}) ->
	[case Ref of
		{connect, Ref2, _} -> Ref2;
		#websocket{ref=Ref2} -> Ref2;
		_ -> Ref
	end || #stream{ref=Ref} <- Streams].

error_stream_closed(State, StreamRef, ReplyTo) ->
	ReplyTo ! {gun_error, self(), stream_ref(State, StreamRef), {badstate,
		"The stream has already been closed."}},
	State.

error_stream_not_found(State, StreamRef, ReplyTo) ->
	ReplyTo ! {gun_error, self(), stream_ref(State, StreamRef), {badstate,
		"The stream cannot be found."}},
	State.

%% Headers information retrieval.

conn_from_headers(Version, Headers) ->
	case lists:keyfind(<<"connection">>, 1, Headers) of
		false when Version =:= 'HTTP/1.0' ->
			close;
		false ->
			keepalive;
		{_, ConnHd} ->
			conn_from_header(cow_http_hd:parse_connection(ConnHd))
	end.

conn_from_header([]) -> close;
conn_from_header([<<"keep-alive">>|_]) -> keepalive;
conn_from_header([<<"upgrade">>|_]) -> keepalive;
conn_from_header([_|Tail]) -> conn_from_header(Tail).

request_io_from_headers(Headers) ->
	case lists:keyfind(<<"content-length">>, 1, Headers) of
		{_, Length} ->
			{body, cow_http_hd:parse_content_length(Length)};
		_ ->
			body_chunked
	end.

response_io_from_headers(<<"HEAD">>, _, _, _) ->
	head;
response_io_from_headers(_, _, Status, _) when (Status =:= 204) or (Status =:= 304) ->
	head;
response_io_from_headers(_, Version, _Status, Headers) ->
	case lists:keyfind(<<"transfer-encoding">>, 1, Headers) of
		{_, TE} when Version =:= 'HTTP/1.1' ->
			case cow_http_hd:parse_transfer_encoding(TE) of
				[<<"chunked">>] -> body_chunked;
				[<<"identity">>] -> body_close
			end;
		_ ->
			case lists:keyfind(<<"content-length">>, 1, Headers) of
				{_, <<"0">>} ->
					head;
				{_, Length} ->
					{body, cow_http_hd:parse_content_length(Length)};
				_ ->
					body_close
			end
	end.

%% Streams.

stream_ref(#http_state{base_stream_ref=undefined}, StreamRef) ->
	stream_ref(StreamRef);
stream_ref(#http_state{base_stream_ref=BaseStreamRef}, StreamRef)
		when is_reference(BaseStreamRef) ->
	[BaseStreamRef, stream_ref(StreamRef)];
stream_ref(#http_state{base_stream_ref=BaseStreamRef}, StreamRef) ->
	BaseStreamRef ++ [stream_ref(StreamRef)].

stream_ref({connect, StreamRef, _}) -> StreamRef;
stream_ref(#websocket{ref=StreamRef}) -> StreamRef;
stream_ref(StreamRef) -> StreamRef.

new_stream(State=#http_state{streams=Streams}, StreamRef, ReplyTo,
		Method, Authority, Path, InitialFlow) ->
	State#http_state{streams=Streams
		++ [#stream{ref=StreamRef, reply_to=ReplyTo, flow=InitialFlow,
			method=iolist_to_binary(Method), authority=Authority,
			path=iolist_to_binary(Path), is_alive=true}]}.

is_stream(#http_state{streams=Streams}, StreamRef) ->
	lists:keymember(StreamRef, #stream.ref, Streams).

cancel_stream(State=#http_state{streams=Streams}, StreamRef) ->
	Streams2 = [case Ref of
		StreamRef ->
			Tuple#stream{is_alive=false};
		_ ->
			Tuple
	end || Tuple = #stream{ref=Ref} <- Streams],
	State#http_state{streams=Streams2}.

end_stream(State=#http_state{streams=[_|Tail]}) ->
	State#http_state{in=head, streams=Tail}.

%% Websocket upgrade.

ws_upgrade(State=#http_state{version='HTTP/1.0'},
		StreamRef, ReplyTo, _, _, _, _, _, _, EvHandlerState) ->
	ReplyTo ! {gun_error, self(), stream_ref(State, StreamRef), {badstate,
		"Websocket cannot be used over an HTTP/1.0 connection."}},
	{[], EvHandlerState};
ws_upgrade(State=#http_state{out=head}, StreamRef, ReplyTo,
		Host, Port, Path, Headers0, WsOpts, EvHandler, EvHandlerState0) ->
	{Headers1, GunExtensions} = case maps:get(compress, WsOpts, false) of
		true -> {[{<<"sec-websocket-extensions">>,
				<<"permessage-deflate; client_max_window_bits; server_max_window_bits=15">>}
			|Headers0],
			[<<"permessage-deflate">>]};
		false -> {Headers0, []}
	end,
	Headers2 = case maps:get(protocols, WsOpts, []) of
		[] -> Headers1;
		ProtoOpt ->
			<< _, _, Proto/bits >> = iolist_to_binary([[<<", ">>, P] || {P, _} <- ProtoOpt]),
			[{<<"sec-websocket-protocol">>, Proto}|Headers1]
	end,
	Key = cow_ws:key(),
	Headers = [
		{<<"connection">>, <<"upgrade">>},
		{<<"upgrade">>, <<"websocket">>},
		{<<"sec-websocket-version">>, <<"13">>},
		{<<"sec-websocket-key">>, Key}
		|Headers2
	],
	{Authority, Conn, Out, EvHandlerState} = send_request(State, StreamRef, ReplyTo,
		<<"GET">>, Host, Port, Path, Headers, undefined,
		EvHandler, EvHandlerState0, ?FUNCTION_NAME),
	InitialFlow = maps:get(flow, WsOpts, infinity),
	{new_stream(State#http_state{connection=Conn, out=Out},
		#websocket{ref=StreamRef, reply_to=ReplyTo, key=Key, extensions=GunExtensions, opts=WsOpts},
		ReplyTo, <<"GET">>, Authority, Path, InitialFlow), EvHandlerState}.

ws_handshake(Buffer, State, Ws=#websocket{key=Key}, Headers) ->
	%% @todo check upgrade, connection
	case lists:keyfind(<<"sec-websocket-accept">>, 1, Headers) of
		false ->
			close;
		{_, Accept} ->
			case cow_ws:encode_key(Key) of
				Accept ->
					ws_handshake_extensions(Buffer, State, Ws, Headers);
				_ ->
					close
			end
	end.

ws_handshake_extensions(Buffer, State, Ws=#websocket{extensions=Extensions0, opts=Opts}, Headers) ->
	case lists:keyfind(<<"sec-websocket-extensions">>, 1, Headers) of
		false ->
			ws_handshake_protocols(Buffer, State, Ws, Headers, #{});
		{_, ExtHd} ->
			ParsedExtHd = cow_http_hd:parse_sec_websocket_extensions(ExtHd),
			case ws_validate_extensions(ParsedExtHd, Extensions0, #{}, Opts) of
				close ->
					close;
				Extensions ->
					ws_handshake_protocols(Buffer, State, Ws, Headers, Extensions)
			end
	end.

ws_validate_extensions([], _, Acc, _) ->
	Acc;
ws_validate_extensions([{Name = <<"permessage-deflate">>, Params}|Tail], GunExts, Acc, Opts) ->
	case lists:member(Name, GunExts) of
		true ->
			case cow_ws:validate_permessage_deflate(Params, Acc, Opts) of
				{ok, Acc2} -> ws_validate_extensions(Tail, GunExts, Acc2, Opts);
				error -> close
			end;
		%% Fail the connection if extension was not requested.
		false ->
			close
	end;
%% Fail the connection on unknown extension.
ws_validate_extensions(_, _, _, _) ->
	close.

%% @todo Validate protocols.
ws_handshake_protocols(Buffer, State, Ws=#websocket{opts=Opts}, Headers, Extensions) ->
	case lists:keyfind(<<"sec-websocket-protocol">>, 1, Headers) of
		false ->
			ws_handshake_end(Buffer, State, Ws, Headers, Extensions,
				maps:get(default_protocol, Opts, gun_ws_h));
		{_, Proto} ->
			ProtoOpt = maps:get(protocols, Opts, []),
			case lists:keyfind(Proto, 1, ProtoOpt) of
				{_, Handler} ->
					ws_handshake_end(Buffer, State, Ws, Headers, Extensions, Handler);
				false ->
					close
			end
	end.

%% We know that the most recent stream is the Websocket one.
ws_handshake_end(Buffer,
		State=#http_state{socket=Socket, transport=Transport, streams=[#stream{flow=InitialFlow}|_]},
		#websocket{ref=StreamRef, reply_to=ReplyTo, opts=Opts}, Headers, Extensions, Handler) ->
	%% Send ourselves the remaining buffer, if any.
	_ = case Buffer of
		<<>> ->
			ok;
		_ ->
			{OK, _, _} = Transport:messages(),
			self() ! {OK, Socket, Buffer}
	end,
	%% Inform the user that the upgrade was successful and switch the protocol.
	ReplyTo ! {gun_upgrade, self(), stream_ref(State, StreamRef), [<<"websocket">>], Headers},
	{switch_protocol, {ws, #{
		stream_ref => StreamRef,
		headers => Headers,
		extensions => Extensions,
		flow => InitialFlow,
		handler => Handler,
		opts => Opts
	}}, ReplyTo}.
