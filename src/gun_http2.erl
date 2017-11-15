%% Copyright (c) 2016, Loïc Hoguin <essen@ninenines.eu>
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

-module(gun_http2).

-export([check_options/1]).
-export([name/0]).
-export([init/4]).
-export([handle/2]).
-export([close/1]).
-export([keepalive/1]).
-export([request/8]).
-export([request/9]).
-export([data/5]).
-export([cancel/3]).
-export([down/1]).

-record(stream, {
	id :: non_neg_integer(),
	ref :: reference(),
	reply_to :: pid(),
	%% Whether we finished sending data.
	local = nofin :: cowboy_stream:fin(),
	%% Local flow control window (how much we can send).
	local_window :: integer(),
	%% Whether we finished receiving data.
	remote = nofin :: cowboy_stream:fin(),
	%% Remote flow control window (how much we accept to receive).
	remote_window :: integer(),
	%% Content handlers state.
	handler_state :: undefined | gun_content_handler:state()
}).

-record(http2_state, {
	owner :: pid(),
	socket :: inet:socket() | ssl:sslsocket(),
	transport :: module(),
	content_handlers :: gun_content_handler:opt(),
	buffer = <<>> :: binary(),

	local_settings = #{
		initial_window_size => 65535,
		max_frame_size => 16384
	} :: map(),
	remote_settings = #{
		initial_window_size => 65535
	} :: map(),

	%% Connection-wide flow control window.
	local_window = 65535 :: integer(), %% How much we can send.
	remote_window = 65535 :: integer(), %% How much we accept to receive.

	streams = [] :: [#stream{}],
	stream_id = 1 :: non_neg_integer(),

	%% HPACK decoding and encoding state.
	decode_state = cow_hpack:init() :: cow_hpack:state(),
	encode_state = cow_hpack:init() :: cow_hpack:state()
}).

check_options(Opts) ->
	do_check_options(maps:to_list(Opts)).

do_check_options([]) ->
	ok;
do_check_options([{keepalive, infinity}|Opts]) ->
	do_check_options(Opts);
do_check_options([{keepalive, K}|Opts]) when is_integer(K), K > 0 ->
	do_check_options(Opts);
do_check_options([Opt={content_handlers, Handlers}|Opts]) ->
	case gun_content_handler:check_option(Handlers) of
		ok -> do_check_options(Opts);
		error -> {error, {options, {http, Opt}}}
	end;
do_check_options([Opt|_]) ->
	{error, {options, {http2, Opt}}}.

name() -> http2.

init(Owner, Socket, Transport, Opts) ->
	Handlers = maps:get(content_handlers, Opts, [gun_data]),
	State = #http2_state{owner=Owner, socket=Socket,
		transport=Transport, content_handlers=Handlers},
	#http2_state{local_settings=Settings} = State,
	%% Send the HTTP/2 preface.
	Transport:send(Socket, [
		<< "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>,
		cow_http2:settings(Settings)
	]),
	State.

handle(Data, State=#http2_state{buffer=Buffer}) ->
	parse(<< Buffer/binary, Data/binary >>, State#http2_state{buffer= <<>>}).

parse(Data0, State0=#http2_state{buffer=Buffer}) ->
	%% @todo Parse states: Preface. Continuation.
	Data = << Buffer/binary, Data0/binary >>,
	case cow_http2:parse(Data) of
		{ok, Frame, Rest} ->
			case frame(Frame, State0) of
				close -> close;
				State1 -> parse(Rest, State1)
			end;
		{stream_error, StreamID, Reason, Human, Rest} ->
			parse(Rest, stream_reset(State0, StreamID, {stream_error, Reason, Human}));
		Error = {connection_error, _, _} ->
			terminate(State0, Error);
		more ->
			State0#http2_state{buffer=Data}
	end.

%% DATA frame.
frame({data, StreamID, IsFin, Data}, State0=#http2_state{remote_window=ConnWindow}) ->
	case get_stream_by_id(StreamID, State0) of
		Stream0 = #stream{remote=nofin, remote_window=StreamWindow, handler_state=Handlers0} ->
			Handlers = gun_content_handler:handle(IsFin, Data, Handlers0),
			{Stream, State} = send_window_update(
				Stream0#stream{remote_window=StreamWindow - byte_size(Data),
					handler_state=Handlers},
				State0#http2_state{remote_window=ConnWindow - byte_size(Data)}),
			remote_fin(Stream, State, IsFin);
		_ ->
			%% @todo protocol_error if not existing
			stream_reset(State0, StreamID, {stream_error, stream_closed,
				'DATA frame received for a closed or non-existent stream. (RFC7540 6.1)'})
	end;
%% Single HEADERS frame headers block.
frame({headers, StreamID, IsFin, head_fin, HeaderBlock},
		State=#http2_state{decode_state=DecodeState0, content_handlers=Handlers0}) ->
	case get_stream_by_id(StreamID, State) of
		Stream = #stream{ref=StreamRef, reply_to=ReplyTo, remote=nofin} ->
			try cow_hpack:decode(HeaderBlock, DecodeState0) of
				{Headers0, DecodeState} ->
					case lists:keytake(<<":status">>, 1, Headers0) of
						{value, {_, Status}, Headers} ->
							IntStatus = parse_status(Status),
							if
								IntStatus >= 100, IntStatus =< 199 ->
									ReplyTo ! {gun_inform, self(), StreamRef, IntStatus, Headers},
									State#http2_state{decode_state=DecodeState};
								true ->
									ReplyTo ! {gun_response, self(), StreamRef, IsFin, parse_status(Status), Headers},
									Handlers = case IsFin of
										fin -> undefined;
										nofin ->
											gun_content_handler:init(ReplyTo, StreamRef,
												Status, Headers, Handlers0)
									end,
									remote_fin(Stream#stream{handler_state=Handlers},
										State#http2_state{decode_state=DecodeState}, IsFin)
							end;
						%% @todo For now we assume that it's a trailer if there's no :status.
						%% A better state machine is needed to distinguish between that and errors.
						false ->
							%% @todo We probably want to pass this to gun_content_handler?
							ReplyTo ! {gun_trailers, self(), StreamRef, Headers0},
							remote_fin(Stream, State#http2_state{decode_state=DecodeState}, fin)
%%						false ->
%%							stream_reset(State, StreamID, {stream_error, protocol_error,
%%								'Malformed response; missing :status in HEADERS frame. (RFC7540 8.1.2.4)'})
					end
			catch _:_ ->
				terminate(State, StreamID, {connection_error, compression_error,
					'Error while trying to decode HPACK-encoded header block. (RFC7540 4.3)'})
			end;
		_ ->
			stream_reset(State, StreamID, {stream_error, stream_closed,
				'DATA frame received for a closed or non-existent stream. (RFC7540 6.1)'})
	end;
%% @todo HEADERS frame starting a headers block. Enter continuation mode.
%frame(State, {headers, StreamID, IsFin, head_nofin, HeaderBlockFragment}) ->
%	State#http2_state{parse_state={continuation, StreamID, IsFin, HeaderBlockFragment}};
%% @todo Single HEADERS frame headers block with priority.
%frame(State, {headers, StreamID, IsFin, head_fin,
%		_IsExclusive, _DepStreamID, _Weight, HeaderBlock}) ->
%	%% @todo Handle priority.
%	stream_init(State, StreamID, IsFin, HeaderBlock);
%% @todo HEADERS frame starting a headers block. Enter continuation mode.
%frame(State, {headers, StreamID, IsFin, head_nofin,
%		_IsExclusive, _DepStreamID, _Weight, HeaderBlockFragment}) ->
%	%% @todo Handle priority.
%	State#http2_state{parse_state={continuation, StreamID, IsFin, HeaderBlockFragment}};
%% @todo PRIORITY frame.
%frame(State, {priority, _StreamID, _IsExclusive, _DepStreamID, _Weight}) ->
%	%% @todo Validate StreamID?
%	%% @todo Handle priority.
%	State;
%% @todo RST_STREAM frame.
frame({rst_stream, StreamID, Reason}, State) ->
	stream_reset(State, StreamID, {stream_error, Reason, 'Stream reset by server.'});
%% SETTINGS frame.
frame({settings, Settings}, State=#http2_state{socket=Socket, transport=Transport,
		remote_settings=Settings0}) ->
	Transport:send(Socket, cow_http2:settings_ack()),
	State#http2_state{remote_settings=maps:merge(Settings0, Settings)};
%% Ack for a previously sent SETTINGS frame.
frame(settings_ack, State) -> %% @todo =#http2_state{next_settings=_NextSettings}) ->
	%% @todo Apply SETTINGS that require synchronization.
	State;
%% PUSH_PROMISE frame.
%% @todo Continuation.
frame({push_promise, StreamID, head_fin, PromisedStreamID, HeaderBlock},
		State=#http2_state{decode_state=DecodeState0}) ->
	case get_stream_by_id(PromisedStreamID, State) of
		false ->
			case get_stream_by_id(StreamID, State) of
				#stream{ref=StreamRef, reply_to=ReplyTo} ->
					try cow_hpack:decode(HeaderBlock, DecodeState0) of
						{Headers0, DecodeState} ->
							{Method, Scheme, Authority, Path, Headers} = try
								{value, {_, Method0}, Headers1} = lists:keytake(<<":method">>, 1, Headers0),
								{value, {_, Scheme0}, Headers2} = lists:keytake(<<":scheme">>, 1, Headers1),
								{value, {_, Authority0}, Headers3} = lists:keytake(<<":authority">>, 1, Headers2),
								{value, {_, Path0}, Headers4} = lists:keytake(<<":path">>, 1, Headers3),
								{Method0, Scheme0, Authority0, Path0, Headers4}
							catch error:badmatch ->
								stream_reset(State, StreamID, {stream_error, protocol_error,
									'Malformed push promise; missing pseudo-header field. (RFC7540 8.1.2.3)'})
							end,
							NewStreamRef = make_ref(),
							ReplyTo ! {gun_push, self(), StreamRef, NewStreamRef, Method,
								iolist_to_binary([Scheme, <<"://">>, Authority, Path]), Headers},
							new_stream(PromisedStreamID, NewStreamRef, ReplyTo, nofin, fin,
								State#http2_state{decode_state=DecodeState})
					catch _:_ ->
						terminate(State, {connection_error, compression_error,
							'Error while trying to decode HPACK-encoded header block. (RFC7540 4.3)'})
					end;
				_ ->
					stream_reset(State, StreamID, {stream_error, stream_closed,
						'DATA frame received for a closed or non-existent stream. (RFC7540 6.1)'})
			end;
		_ ->
			stream_reset(State, StreamID, {stream_error, todo, ''})
	end;
%% PING frame.
frame({ping, Opaque}, State=#http2_state{socket=Socket, transport=Transport}) ->
	Transport:send(Socket, cow_http2:ping_ack(Opaque)),
	State;
%% Ack for a previously sent PING frame.
%%
%% @todo Might want to check contents but probably a waste of time.
frame({ping_ack, _Opaque}, State) ->
	State;
%% GOAWAY frame.
frame(Frame={goaway, StreamID, _, _}, State) ->
	terminate(State, StreamID, {stop, Frame, 'Client is going away.'});
%% Connection-wide WINDOW_UPDATE frame.
frame({window_update, Increment}, State=#http2_state{local_window=ConnWindow}) ->
	send_data(State#http2_state{local_window=ConnWindow + Increment});
%% Stream-specific WINDOW_UPDATE frame.
frame({window_update, StreamID, Increment}, State0=#http2_state{streams=Streams0}) ->
	case lists:keyfind(StreamID, #stream.id, Streams0) of
		Stream0 = #stream{local_window=StreamWindow} ->
			{State, Stream} = send_data(State0,
				Stream0#stream{local_window=StreamWindow + Increment}),
			Streams = lists:keystore(StreamID, #stream.id, Streams0, Stream),
			State#http2_state{streams=Streams};
		false ->
			%% @todo Receiving this frame on a stream in the idle state is an error.
			%% WINDOW_UPDATE frames may be received for a short period of time
			%% after a stream is closed. They must be ignored.
			State0
	end;
%% Unexpected CONTINUATION frame.
frame({continuation, StreamID, _, _}, State) ->
	terminate(State, StreamID, {connection_error, protocol_error,
		'CONTINUATION frames MUST be preceded by a HEADERS frame. (RFC7540 6.10)'}).

send_window_update(Stream=#stream{id=StreamID, remote_window=StreamWindow0},
		State=#http2_state{socket=Socket, transport=Transport, remote_window=ConnWindow0}) ->
	%% @todo We should make the windows configurable.
	MinConnWindow = 8000000,
	MinStreamWindow = 1000000,
	ConnWindow = if
		ConnWindow0 =< MinConnWindow ->
			Transport:send(Socket, cow_http2:window_update(MinConnWindow)),
			ConnWindow0 + MinConnWindow;
		true ->
			ConnWindow0
	end,
	StreamWindow = if
		StreamWindow0 =< MinStreamWindow ->
			Transport:send(Socket, cow_http2:window_update(StreamID, MinStreamWindow)),
			StreamWindow0 + MinStreamWindow;
		true ->
			StreamWindow0
	end,
	{Stream#stream{remote_window=StreamWindow},
		State#http2_state{remote_window=ConnWindow}}.

parse_status(Status) ->
	<< Code:3/binary, _/bits >> = Status,
	list_to_integer(binary_to_list(Code)).

close(#http2_state{streams=Streams}) ->
	close_streams(Streams).

close_streams([]) ->
	ok;
close_streams([#stream{ref=StreamRef, reply_to=ReplyTo}|Tail]) ->
	ReplyTo ! {gun_error, self(), StreamRef, {closed,
		"The connection was lost."}},
	close_streams(Tail).

keepalive(State=#http2_state{socket=Socket, transport=Transport}) ->
	Transport:send(Socket, cow_http2:ping(0)),
	State.

request(State=#http2_state{socket=Socket, transport=Transport, encode_state=EncodeState0,
		stream_id=StreamID}, StreamRef, ReplyTo, Method, Host, Port, Path, Headers) ->
	{HeaderBlock, EncodeState} = prepare_headers(EncodeState0, Transport, Method, Host, Port, Path, Headers),
	IsFin = case (false =/= lists:keyfind(<<"content-type">>, 1, Headers))
			orelse (false =/= lists:keyfind(<<"content-length">>, 1, Headers)) of
		true -> nofin;
		false -> fin
	end,
	Transport:send(Socket, cow_http2:headers(StreamID, IsFin, HeaderBlock)),
	new_stream(StreamID, StreamRef, ReplyTo, nofin, IsFin,
		State#http2_state{stream_id=StreamID + 2, encode_state=EncodeState}).

%% @todo Handle Body > 16MB. (split it out into many frames)
request(State=#http2_state{socket=Socket, transport=Transport, encode_state=EncodeState0,
		stream_id=StreamID}, StreamRef, ReplyTo, Method, Host, Port, Path, Headers0, Body) ->
	Headers = lists:keystore(<<"content-length">>, 1, Headers0,
		{<<"content-length">>, integer_to_binary(iolist_size(Body))}),
	{HeaderBlock, EncodeState} = prepare_headers(EncodeState0, Transport, Method, Host, Port, Path, Headers),
	Transport:send(Socket, cow_http2:headers(StreamID, nofin, HeaderBlock)),
	%% @todo 16384 is the default SETTINGS_MAX_FRAME_SIZE.
	%% Use the length set by the server instead, if any.
	%% @todo Would be better if we didn't have to convert to binary.
	send_data(Socket, Transport, StreamID, fin, iolist_to_binary(Body), 16384),
	new_stream(StreamID, StreamRef, ReplyTo, nofin, fin,
		State#http2_state{stream_id=StreamID + 2, encode_state=EncodeState}).

prepare_headers(EncodeState, Transport, Method, Host0, Port, Path, Headers0) ->
	Authority = case lists:keyfind(<<"host">>, 1, Headers0) of
		{_, Host} -> Host;
		_ -> [Host0, $:, integer_to_binary(Port)]
	end,
	%% @todo We also must remove any header found in the connection header.
	Headers1 =
		lists:keydelete(<<"host">>, 1,
		lists:keydelete(<<"connection">>, 1,
		lists:keydelete(<<"keep-alive">>, 1,
		lists:keydelete(<<"proxy-connection">>, 1,
		lists:keydelete(<<"transfer-encoding">>, 1,
		lists:keydelete(<<"upgrade">>, 1, Headers0)))))),
	Headers = [
		{<<":method">>, Method},
		{<<":scheme">>, case Transport:secure() of
			true -> <<"https">>;
			false -> <<"http">>
		end},
		{<<":authority">>, Authority},
		{<<":path">>, Path}
	|Headers1],
	cow_hpack:encode(Headers, EncodeState).

data(State=#http2_state{socket=Socket, transport=Transport},
		StreamRef, ReplyTo, IsFin, Data) ->
	case get_stream_by_ref(StreamRef, State) of
		#stream{local=fin} ->
			error_stream_closed(State, StreamRef, ReplyTo);
		S = #stream{} ->
			%% @todo 16384 is the default SETTINGS_MAX_FRAME_SIZE.
			%% Use the length set by the server instead, if any.
			%% @todo Would be better if we didn't have to convert to binary.
			send_data(Socket, Transport, S#stream.id, IsFin, iolist_to_binary(Data), 16384),
			local_fin(S, State, IsFin);
		false ->
			error_stream_not_found(State, StreamRef, ReplyTo)
	end.

send_data(State) -> State.
send_data(State, Stream) -> {State, Stream}.

%% This same function is found in cowboy_http2.
send_data(Socket, Transport, StreamID, IsFin, Data, Length) ->
	if
		Length < byte_size(Data) ->
			<< Payload:Length/binary, Rest/bits >> = Data,
			Transport:send(Socket, cow_http2:data(StreamID, nofin, Payload)),
			send_data(Socket, Transport, StreamID, IsFin, Rest, Length);
		true ->
			Transport:send(Socket, cow_http2:data(StreamID, IsFin, Data))
	end.

cancel(State=#http2_state{socket=Socket, transport=Transport},
		StreamRef, ReplyTo) ->
	case get_stream_by_ref(StreamRef, State) of
		#stream{id=StreamID} ->
			Transport:send(Socket, cow_http2:rst_stream(StreamID, cancel)),
			delete_stream(StreamID, State);
		false ->
			error_stream_not_found(State, StreamRef, ReplyTo)
	end.

%% @todo Add unprocessed streams when GOAWAY handling is done.
down(#http2_state{streams=Streams}) ->
	KilledStreams = [Ref || #stream{ref=Ref} <- Streams],
	{KilledStreams, []}.

terminate(#http2_state{streams=Streams}, Reason) ->
	%% Because a particular stream is unknown,
	%% we're sending the error message to all streams.
	_ = [ReplyTo ! {gun_error, self(), Reason} || #stream{reply_to=ReplyTo} <- Streams],
	%% @todo Send GOAWAY frame.
	%% @todo LastGoodStreamID
	close.

terminate(State, StreamID, Reason) ->
	case get_stream_by_id(StreamID, State) of
		#stream{reply_to=ReplyTo} ->
			ReplyTo ! {gun_error, self(), Reason},
			%% @todo Send GOAWAY frame.
			%% @todo LastGoodStreamID
			close;
		_ ->
			terminate(State, Reason)
	end.

stream_reset(State=#http2_state{socket=Socket, transport=Transport,
		streams=Streams0}, StreamID, StreamError={stream_error, Reason, _}) ->
	Transport:send(Socket, cow_http2:rst_stream(StreamID, Reason)),
	case lists:keytake(StreamID, #stream.id, Streams0) of
		{value, #stream{ref=StreamRef, reply_to=ReplyTo}, Streams} ->
			ReplyTo ! {gun_error, self(), StreamRef, StreamError},
			State#http2_state{streams=Streams};
		false ->
			%% @todo Unknown stream. Not sure what to do here. Check again once all
			%% terminate calls have been written.
			State
	end.

error_stream_closed(State, StreamRef, ReplyTo) ->
	ReplyTo ! {gun_error, self(), StreamRef, {badstate,
		"The stream has already been closed."}},
	State.

error_stream_not_found(State, StreamRef, ReplyTo) ->
	ReplyTo ! {gun_error, self(), StreamRef, {badstate,
		"The stream cannot be found."}},
	State.

%% Streams.
%% @todo probably change order of args and have state first?

new_stream(StreamID, StreamRef, ReplyTo, Remote, Local,
		State=#http2_state{streams=Streams,
			local_settings=#{initial_window_size := RemoteWindow},
			remote_settings=#{initial_window_size := LocalWindow}}) ->
	New = #stream{id=StreamID, ref=StreamRef, reply_to=ReplyTo,
		remote=Remote, remote_window=RemoteWindow,
		local=Local, local_window=LocalWindow},
	State#http2_state{streams=[New|Streams]}.

get_stream_by_id(StreamID, #http2_state{streams=Streams}) ->
	lists:keyfind(StreamID, #stream.id, Streams).

get_stream_by_ref(StreamRef, #http2_state{streams=Streams}) ->
	lists:keyfind(StreamRef, #stream.ref, Streams).

delete_stream(StreamID, State=#http2_state{streams=Streams}) ->
	Streams2 = lists:keydelete(StreamID, #stream.id, Streams),
	State#http2_state{streams=Streams2}.

remote_fin(S=#stream{local=fin}, State, fin) ->
	delete_stream(S#stream.id, State);
%% We always replace the stream in the state because
%% the content handler state has changed.
remote_fin(S, State=#http2_state{streams=Streams}, IsFin) ->
	Streams2 = lists:keyreplace(S#stream.id, #stream.id, Streams,
		S#stream{remote=IsFin}),
	State#http2_state{streams=Streams2}.

local_fin(_, State, nofin) ->
	State;
local_fin(S=#stream{remote=fin}, State, fin) ->
	delete_stream(S#stream.id, State);
local_fin(S, State=#http2_state{streams=Streams}, IsFin) ->
	Streams2 = lists:keyreplace(S#stream.id, #stream.id, Streams,
		S#stream{local=IsFin}),
	State#http2_state{streams=Streams2}.
