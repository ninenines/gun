%% Copyright (c) 2016-2020, Loïc Hoguin <essen@ninenines.eu>
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
-export([opts_name/0]).
-export([has_keepalive/0]).
-export([default_keepalive/0]).
-export([init/4]).
-export([switch_transport/3]).
-export([handle/5]).
-export([handle_continue/6]).
-export([update_flow/4]).
-export([closing/4]).
-export([close/4]).
-export([keepalive/3]).
-export([headers/12]).
-export([request/13]).
-export([data/7]).
-export([connect/9]).
-export([cancel/5]).
-export([timeout/3]).
-export([stream_info/2]).
-export([down/1]).
-export([ws_upgrade/11]).
-export([ws_send/6]).

-record(websocket_info, {
	extensions :: [binary()],
	opts :: gun:ws_opts()
}).

-record(tunnel, {
	state = requested :: requested | established,

	%% Destination information.
	destination = undefined :: undefined | gun:connect_destination(),

	%% Tunnel information.
	info = undefined :: gun:tunnel_info() | #websocket_info{},

	%% Protocol module and state of the outer layer. Only initialized
	%% after the TLS handshake has completed when TLS is involved.
	protocol = undefined :: module(),
	protocol_state = undefined :: any()
}).

-record(stream, {
	id = undefined :: cow_http2:streamid(),

	%% Reference used by the user of Gun to refer to this stream.
	%% This may be only a part of a stream_ref() for tunneled streams.
	ref :: reference(),

	%% Process to send messages to.
	reply_to :: pid(),

	%% Flow control.
	flow :: integer() | infinity,

	%% Request target URI.
	authority :: iodata(),
	path :: iodata(),

	%% Content handlers state.
	handler_state :: undefined | gun_content_handler:state(),

	%% CONNECT tunnel.
	tunnel :: undefined | #tunnel{}
}).

-record(http2_state, {
	reply_to :: pid(),
	socket :: inet:socket() | ssl:sslsocket(),
	transport :: module(),
	opts = #{} :: gun:http2_opts(),
	content_handlers :: gun_content_handler:opt(),
	buffer = <<>> :: binary(),

	%% Base stream ref, defined when the protocol runs
	%% inside an HTTP/2 CONNECT stream.
	base_stream_ref = undefined :: undefined | gun:stream_ref(),

	%% Real transport for the HTTP/2 layer, defined when we are
	%% in a non-HTTP/2 tunnel.
	tunnel_transport = undefined :: undefined | tcp | tls,

	%% Current status of the connection. We use this to ensure we are
	%% not sending the GOAWAY frame more than once, and to validate
	%% the server connection preface.
	status = preface :: preface | connected | goaway | closing,

	%% HTTP/2 state machine.
	http2_machine :: cow_http2_machine:http2_machine(),

	%% Currently active HTTP/2 streams. Streams may be initiated either
	%% by the client or by the server through PUSH_PROMISE frames.
	%%
	%% Streams can be found by ID or by Ref. The most common should be
	%% the idea, that's why the main map has the ID as key. Then we also
	%% have a Ref->ID index for faster lookup when we only have the Ref.
	streams = #{} :: #{cow_http2:streamid() => #stream{}},
	stream_refs = #{} :: #{reference() => cow_http2:streamid()}
}).

check_options(Opts) ->
	do_check_options(maps:to_list(Opts)).

%% @todo Accept http_opts, http2_opts, and so on.
do_check_options([]) ->
	ok;
do_check_options([{closing_timeout, infinity}|Opts]) ->
	do_check_options(Opts);
do_check_options([{closing_timeout, T}|Opts]) when is_integer(T), T > 0 ->
	do_check_options(Opts);
do_check_options([Opt={content_handlers, Handlers}|Opts]) ->
	case gun_content_handler:check_option(Handlers) of
		ok -> do_check_options(Opts);
		error -> {error, {options, {http2, Opt}}}
	end;
do_check_options([{cookie_ignore_informational, B}|Opts]) when is_boolean(B) ->
	do_check_options(Opts);
do_check_options([{flow, InitialFlow}|Opts]) when is_integer(InitialFlow), InitialFlow > 0 ->
	do_check_options(Opts);
do_check_options([{keepalive, infinity}|Opts]) ->
	do_check_options(Opts);
do_check_options([{keepalive, K}|Opts]) when is_integer(K), K > 0 ->
	do_check_options(Opts);
do_check_options([{notify_settings_changed, B}|Opts]) when is_boolean(B) ->
	do_check_options(Opts);
do_check_options([Opt={Name, _}|Opts]) ->
	%% We blindly accept all cow_http2_machine options.
	HTTP2MachineOpts = [
		connection_window_margin_size,
		connection_window_update_threshold,
		enable_connect_protocol,
		initial_connection_window_size,
		initial_stream_window_size,
		max_connection_window_size,
		max_concurrent_streams,
		max_decode_table_size,
		max_encode_table_size,
		max_frame_size_received,
		max_frame_size_sent,
		max_stream_window_size,
		preface_timeout,
		settings_timeout,
		stream_window_margin_size,
		stream_window_update_threshold
	],
	case lists:member(Name, HTTP2MachineOpts) of
		true -> do_check_options(Opts);
		false -> {error, {options, {http2, Opt}}}
	end.

name() -> http2.
opts_name() -> http2_opts.
has_keepalive() -> true.
default_keepalive() -> infinity.

init(ReplyTo, Socket, Transport, Opts0) ->
	%% We have different defaults than the protocol in order
	%% to optimize for performance when receiving responses.
	Opts = Opts0#{
		initial_connection_window_size => maps:get(initial_connection_window_size, Opts0, 8000000),
		initial_stream_window_size => maps:get(initial_stream_window_size, Opts0, 8000000)
	},
	Handlers = maps:get(content_handlers, Opts, [gun_data_h]),
	BaseStreamRef = maps:get(stream_ref, Opts, undefined),
	TunnelTransport = maps:get(tunnel_transport, Opts, undefined),
	{ok, Preface, HTTP2Machine} = cow_http2_machine:init(client, Opts#{message_tag => BaseStreamRef}),
	State = #http2_state{reply_to=ReplyTo, socket=Socket, transport=Transport,
		opts=Opts, base_stream_ref=BaseStreamRef, tunnel_transport=TunnelTransport,
		content_handlers=Handlers, http2_machine=HTTP2Machine},
	Transport:send(Socket, Preface),
	{connected, State}.

switch_transport(Transport, Socket, State) ->
	State#http2_state{socket=Socket, transport=Transport}.

handle(Data, State=#http2_state{buffer=Buffer}, CookieStore, EvHandler, EvHandlerState) ->
	parse(<< Buffer/binary, Data/binary >>, State#http2_state{buffer= <<>>},
		CookieStore, EvHandler, EvHandlerState).

parse(Data, State0=#http2_state{status=preface, http2_machine=HTTP2Machine},
		CookieStore0, EvHandler, EvHandlerState0) ->
	MaxFrameSize = cow_http2_machine:get_local_setting(max_frame_size, HTTP2Machine),
	case cow_http2:parse(Data, MaxFrameSize) of
		{ok, Frame, Rest} when element(1, Frame) =:= settings ->
			case frame(State0#http2_state{status=connected}, Frame, CookieStore0, EvHandler, EvHandlerState0) of
				{Error={error, _}, CookieStore, EvHandlerState} ->
					{Error, CookieStore, EvHandlerState};
				{State, CookieStore, EvHandlerState} ->
					parse(Rest, State, CookieStore, EvHandler, EvHandlerState)
			end;
		more ->
			{{state, State0#http2_state{buffer=Data}}, CookieStore0, EvHandlerState0};
		%% Any error in the preface is converted to this specific error
		%% to make debugging the problem easier (it's the server's fault).
		_ ->
			Reason = case Data of
				<<"HTTP/1",_/bits>> ->
					'Invalid connection preface received. Appears to be an HTTP/1 response? (RFC7540 3.5)';
				_ ->
					'Invalid connection preface received. (RFC7540 3.5)'
			end,
			{connection_error(State0, {connection_error, protocol_error, Reason}),
				CookieStore0, EvHandlerState0}
	end;
parse(Data, State0=#http2_state{status=Status, http2_machine=HTTP2Machine, streams=Streams},
		CookieStore0, EvHandler, EvHandlerState0) ->
	MaxFrameSize = cow_http2_machine:get_local_setting(max_frame_size, HTTP2Machine),
	case cow_http2:parse(Data, MaxFrameSize) of
		{ok, Frame, Rest} ->
			case frame(State0, Frame, CookieStore0, EvHandler, EvHandlerState0) of
				{Error={error, _}, CookieStore, EvHandlerState} ->
					{Error, CookieStore, EvHandlerState};
				{State, CookieStore, EvHandlerState} ->
					parse(Rest, State, CookieStore, EvHandler, EvHandlerState)
			end;
		{ignore, Rest} ->
			case ignored_frame(State0) of
				Error = {error, _} ->
					{Error, CookieStore0, EvHandlerState0};
				State ->
					parse(Rest, State, CookieStore0, EvHandler, EvHandlerState0)
			end;
		{stream_error, StreamID, Reason, Human, Rest} ->
			parse(Rest, reset_stream(State0, StreamID, {stream_error, Reason, Human}),
				CookieStore0, EvHandler, EvHandlerState0);
		Error = {connection_error, _, _} ->
			{connection_error(State0, Error), CookieStore0, EvHandlerState0};
		%% If we both received and sent a GOAWAY frame and there are no streams
		%% currently running, we can close the connection immediately.
		more when Status =/= connected, Streams =:= #{} ->
			{[{state, State0#http2_state{buffer=Data, status=closing}}, close],
				CookieStore0, EvHandlerState0};
		%% Otherwise we enter the closing state.
		more when Status =:= goaway ->
			{[{state, State0#http2_state{buffer=Data, status=closing}}, closing(State0)],
				CookieStore0, EvHandlerState0};
		more ->
			{{state, State0#http2_state{buffer=Data}},
				CookieStore0, EvHandlerState0}
	end.

%% Frames received.

frame(State=#http2_state{http2_machine=HTTP2Machine0}, Frame, CookieStore, EvHandler, EvHandlerState0) ->
	EvHandlerState = if
		element(1, Frame) =:= headers; element(1, Frame) =:= push_promise ->
			EvStreamID = element(2, Frame),
			case cow_http2_machine:get_stream_remote_state(EvStreamID, HTTP2Machine0) of
				{ok, idle} ->
					#stream{ref=StreamRef, reply_to=ReplyTo} = get_stream_by_id(State, EvStreamID),
					EvCallback = case element(1, Frame) of
						headers -> response_start;
						push_promise -> push_promise_start
					end,
					EvHandler:EvCallback(#{
						stream_ref => stream_ref(State, StreamRef),
						reply_to => ReplyTo
					}, EvHandlerState0);
				%% Trailers or invalid header frame.
				_ ->
					EvHandlerState0
			end;
		true ->
			EvHandlerState0
	end,
	case cow_http2_machine:frame(Frame, HTTP2Machine0) of
		%% We only update the connection's window when receiving a lingering data frame.
		{ok, HTTP2Machine} when element(1, Frame) =:= data ->
			{update_window(State#http2_state{http2_machine=HTTP2Machine}),
				CookieStore, EvHandlerState};
		{ok, HTTP2Machine} ->
			{maybe_ack_or_notify(State#http2_state{http2_machine=HTTP2Machine}, Frame),
				CookieStore, EvHandlerState};
		{ok, {data, StreamID, IsFin, Data}, HTTP2Machine} ->
			data_frame(State#http2_state{http2_machine=HTTP2Machine}, StreamID, IsFin, Data,
				CookieStore, EvHandler, EvHandlerState);
		{ok, {headers, StreamID, IsFin, Headers, PseudoHeaders, BodyLen}, HTTP2Machine} ->
			headers_frame(State#http2_state{http2_machine=HTTP2Machine},
				StreamID, IsFin, Headers, PseudoHeaders, BodyLen,
				CookieStore, EvHandler, EvHandlerState);
		{ok, {trailers, StreamID, Trailers}, HTTP2Machine} ->
			{StateRet, EvHandlerStateRet} = trailers_frame(
				State#http2_state{http2_machine=HTTP2Machine},
				StreamID, Trailers, EvHandler, EvHandlerState),
			{StateRet, CookieStore, EvHandlerStateRet};
		{ok, {rst_stream, StreamID, Reason}, HTTP2Machine} ->
			{StateRet, EvHandlerStateRet} = rst_stream_frame(
				State#http2_state{http2_machine=HTTP2Machine},
				StreamID, Reason, EvHandler, EvHandlerState),
			{StateRet, CookieStore, EvHandlerStateRet};
		{ok, {push_promise, StreamID, PromisedStreamID, Headers, PseudoHeaders}, HTTP2Machine} ->
			{StateRet, EvHandlerStateRet} = push_promise_frame(
				State#http2_state{http2_machine=HTTP2Machine},
				StreamID, PromisedStreamID, Headers, PseudoHeaders,
				EvHandler, EvHandlerState),
			{StateRet, CookieStore, EvHandlerStateRet};
		{ok, GoAway={goaway, _, _, _}, HTTP2Machine} ->
			{goaway(State#http2_state{http2_machine=HTTP2Machine}, GoAway),
				CookieStore, EvHandlerState};
		{send, SendData, HTTP2Machine} ->
			{StateRet, EvHandlerStateRet} = send_data(
				maybe_ack_or_notify(State#http2_state{http2_machine=HTTP2Machine}, Frame),
				SendData, EvHandler, EvHandlerState),
			{StateRet, CookieStore, EvHandlerStateRet};
		{error, {stream_error, StreamID, Reason, Human}, HTTP2Machine} ->
			{reset_stream(State#http2_state{http2_machine=HTTP2Machine},
				StreamID, {stream_error, Reason, Human}),
				CookieStore, EvHandlerState};
		{error, Error={connection_error, _, _}, HTTP2Machine} ->
			{connection_error(State#http2_state{http2_machine=HTTP2Machine}, Error),
				CookieStore, EvHandlerState}
	end.

maybe_ack_or_notify(State=#http2_state{reply_to=ReplyTo, socket=Socket,
		transport=Transport, opts=Opts, http2_machine=HTTP2Machine}, Frame) ->
	case Frame of
		{settings, _} ->
			%% We notify remote settings changes only if the user requested it.
			_ = case Opts of
				#{notify_settings_changed := true} ->
					ReplyTo ! {gun_notify, self(), settings_changed,
						cow_http2_machine:get_remote_settings(HTTP2Machine)};
				_ ->
					ok
			end,
			Transport:send(Socket, cow_http2:settings_ack());
		{ping, Opaque} ->
			Transport:send(Socket, cow_http2:ping_ack(Opaque));
		_ ->
			ok
	end,
	State.

data_frame(State0, StreamID, IsFin, Data, CookieStore0, EvHandler, EvHandlerState0) ->
	case get_stream_by_id(State0, StreamID) of
		Stream=#stream{tunnel=undefined} ->
			{State, EvHandlerState} = data_frame1(State0,
				StreamID, IsFin, Data, EvHandler, EvHandlerState0, Stream),
			{State, CookieStore0, EvHandlerState};
		Stream=#stream{tunnel=#tunnel{protocol=Proto, protocol_state=ProtoState0}} ->
%			%% @todo What about IsFin?
			{Commands, CookieStore, EvHandlerState1} = Proto:handle(Data,
				ProtoState0, CookieStore0, EvHandler, EvHandlerState0),
			{State, EvHandlerState} = tunnel_commands(Commands, Stream, State0, EvHandler, EvHandlerState1),
			{State, CookieStore, EvHandlerState}
	end.

tunnel_commands(Command, Stream, State, EvHandler, EvHandlerState)
		when not is_list(Command) ->
	tunnel_commands([Command], Stream, State, EvHandler, EvHandlerState);
tunnel_commands([], Stream, State, _EvHandler, EvHandlerState) ->
	{store_stream(State, Stream), EvHandlerState};
tunnel_commands([{send, IsFin, Data}|Tail], Stream=#stream{id=StreamID},
		State0, EvHandler, EvHandlerState0) ->
	{State, EvHandlerState} = maybe_send_data(State0, StreamID,
		IsFin, Data, EvHandler, EvHandlerState0),
	tunnel_commands(Tail, Stream, State, EvHandler, EvHandlerState);
tunnel_commands([{state, ProtoState}|Tail], Stream=#stream{tunnel=Tunnel},
		State, EvHandler, EvHandlerState) ->
	tunnel_commands(Tail, Stream#stream{tunnel=Tunnel#tunnel{protocol_state=ProtoState}},
		State, EvHandler, EvHandlerState);
tunnel_commands([{error, _Reason}|_], #stream{id=StreamID},
		State, _EvHandler, EvHandlerState) ->
	{delete_stream(State, StreamID), EvHandlerState};
%% @todo Set a timeout for closing the Websocket stream.
tunnel_commands([{closing, _}|Tail], Stream, State, EvHandler, EvHandlerState) ->
	tunnel_commands(Tail, Stream, State, EvHandler, EvHandlerState);
%% @todo Maybe we should stop increasing the window when not in active mode. (HTTP/2 Websocket only.)
tunnel_commands([{active, _}|Tail], Stream, State, EvHandler, EvHandlerState) ->
	tunnel_commands(Tail, Stream, State, EvHandler, EvHandlerState).

continue_stream_ref(#http2_state{socket=#{handle_continue_stream_ref := ContinueStreamRef}}, StreamRef) ->
	case ContinueStreamRef of
		[_|_] -> ContinueStreamRef ++ [StreamRef];
		_ -> [ContinueStreamRef, StreamRef]
	end;
continue_stream_ref(State, StreamRef) ->
	stream_ref(State, StreamRef).

data_frame1(State0, StreamID, IsFin, Data, EvHandler, EvHandlerState0,
		Stream=#stream{ref=StreamRef, reply_to=ReplyTo, flow=Flow0, handler_state=Handlers0}) ->
	{ok, Dec, Handlers} = gun_content_handler:handle(IsFin, Data, Handlers0),
	Flow = case Flow0 of
		infinity -> infinity;
		_ -> Flow0 - Dec
	end,
	State1 = store_stream(State0, Stream#stream{flow=Flow, handler_state=Handlers}),
	{State, EvHandlerState} = case byte_size(Data) of
		%% We do not send a WINDOW_UPDATE if the DATA frame was of size 0.
		0 when IsFin =:= fin ->
			EvHandlerState1 = EvHandler:response_end(#{
				stream_ref => stream_ref(State1, StreamRef),
				reply_to => ReplyTo
			}, EvHandlerState0),
			{State1, EvHandlerState1};
		0 ->
			{State1, EvHandlerState0};
		_ ->
			%% We do not send a stream WINDOW_UPDATE when the flow control kicks in
			%% (it'll be sent when the flow recovers) or for the last DATA frame.
			case IsFin of
				nofin when Flow =< 0 ->
					{update_window(State1), EvHandlerState0};
				nofin ->
					{update_window(State1, StreamID), EvHandlerState0};
				fin ->
					EvHandlerState1 = EvHandler:response_end(#{
						stream_ref => stream_ref(State1, StreamRef),
						reply_to => ReplyTo
					}, EvHandlerState0),
					{update_window(State1), EvHandlerState1}
			end
	end,
	{maybe_delete_stream(State, StreamID, remote, IsFin), EvHandlerState}.

headers_frame(State0=#http2_state{opts=Opts},
		StreamID, IsFin, Headers, #{status := Status}, _BodyLen,
		CookieStore0, EvHandler, EvHandlerState0) ->
	Stream = get_stream_by_id(State0, StreamID),
	#stream{
		authority=Authority,
		path=Path,
		tunnel=Tunnel
	} = Stream,
	CookieStore = gun_cookies:set_cookie_header(scheme(State0),
		Authority, Path, Status, Headers, CookieStore0, Opts),
	{State, EvHandlerState} = if
		Status >= 100, Status =< 199 ->
			headers_frame_inform(State0, Stream, Status, Headers, EvHandler, EvHandlerState0);
		Status >= 200, Status =< 299, element(#tunnel.state, Tunnel) =:= requested, IsFin =:= nofin ->
			headers_frame_connect(State0, Stream, Status, Headers, EvHandler, EvHandlerState0);
		true ->
			headers_frame_response(State0, Stream, IsFin, Status, Headers, EvHandler, EvHandlerState0)
	end,
	{State, CookieStore, EvHandlerState}.

headers_frame_inform(State, #stream{ref=StreamRef, reply_to=ReplyTo},
		Status, Headers, EvHandler, EvHandlerState0) ->
	RealStreamRef = stream_ref(State, StreamRef),
	ReplyTo ! {gun_inform, self(), RealStreamRef, Status, Headers},
	EvHandlerState = EvHandler:response_inform(#{
		stream_ref => RealStreamRef,
		reply_to => ReplyTo,
		status => Status,
		headers => Headers
	}, EvHandlerState0),
	{State, EvHandlerState}.

headers_frame_connect(State0=#http2_state{http2_machine=HTTP2Machine0},
		Stream=#stream{id=StreamID, ref=StreamRef, reply_to=ReplyTo, tunnel=#tunnel{
			info=#websocket_info{extensions=Extensions0, opts=WsOpts}}},
		Status, Headers, EvHandler, EvHandlerState0) ->
	RealStreamRef = stream_ref(State0, StreamRef),
	EvHandlerState1 = EvHandler:response_headers(#{
		stream_ref => RealStreamRef,
		reply_to => ReplyTo,
		status => Status,
		headers => Headers
	}, EvHandlerState0),
	%% Websocket CONNECT response headers terminate the response but not the stream.
	EvHandlerState = EvHandler:response_end(#{
		stream_ref => RealStreamRef,
		reply_to => ReplyTo
	}, EvHandlerState1),
	case gun_ws:select_extensions(Headers, Extensions0, WsOpts) of
		close ->
			{ok, HTTP2Machine} = cow_http2_machine:reset_stream(StreamID, HTTP2Machine0),
			State1 = State0#http2_state{http2_machine=HTTP2Machine},
			State = reset_stream(State1, StreamID, {stream_error, cancel,
				'The sec-websocket-extensions header is invalid. (RFC6455 9.1, RFC7692 7)'}),
			{State, EvHandlerState};
		Extensions ->
			case gun_ws:select_protocol(Headers, WsOpts) of
				close ->
					{ok, HTTP2Machine} = cow_http2_machine:reset_stream(StreamID, HTTP2Machine0),
					State1 = State0#http2_state{http2_machine=HTTP2Machine},
					State = reset_stream(State1, StreamID, {stream_error, cancel,
						'The sec-websocket-protocol header is invalid. (RFC6455 4.1)'}),
					{State, EvHandlerState};
				Handler ->
					headers_frame_connect_websocket(State0, Stream, Headers,
						EvHandler, EvHandlerState, Extensions, Handler)
			end
	end;
headers_frame_connect(State=#http2_state{transport=Transport, opts=Opts, tunnel_transport=TunnelTransport},
		Stream=#stream{ref=StreamRef, reply_to=ReplyTo, tunnel=Tunnel=#tunnel{
		destination=Destination=#{host := DestHost, port := DestPort}, info=TunnelInfo0}},
		Status, Headers, EvHandler, EvHandlerState0) ->
	RealStreamRef = stream_ref(State, StreamRef),
	TunnelInfo = TunnelInfo0#{
		origin_host => DestHost,
		origin_port => DestPort
	},
	ReplyTo ! {gun_response, self(), RealStreamRef, fin, Status, Headers},
	EvHandlerState1 = EvHandler:response_headers(#{
		stream_ref => RealStreamRef,
		reply_to => ReplyTo,
		status => Status,
		headers => Headers
	}, EvHandlerState0),
	EvHandlerState2 = EvHandler:response_end(#{
		stream_ref => RealStreamRef,
		reply_to => ReplyTo
	}, EvHandlerState1),
	EvHandlerState3 = EvHandler:origin_changed(#{
		stream_ref => RealStreamRef,
		type => connect,
		origin_scheme => case Destination of
			#{transport := tls} -> <<"https">>;
			_ -> <<"http">>
		end,
		origin_host => DestHost,
		origin_port => DestPort
	}, EvHandlerState2),
	ContinueStreamRef = continue_stream_ref(State, StreamRef),
	OriginSocket = #{
		gun_pid => self(),
		reply_to => ReplyTo,
		stream_ref => RealStreamRef,
		handle_continue_stream_ref => ContinueStreamRef
	},
	Proto = gun_tunnel,
	ProtoOpts = case Destination of
		#{transport := tls} ->
			Protocols = maps:get(protocols, Destination, [http2, http]),
			TLSOpts = gun:ensure_alpn_sni(Protocols, maps:get(tls_opts, Destination, []), DestHost),
			HandshakeEvent = #{
				stream_ref => RealStreamRef,
				reply_to => ReplyTo,
				tls_opts => TLSOpts,
				timeout => maps:get(tls_handshake_timeout, Destination, infinity)
			},
			Opts#{
				stream_ref => RealStreamRef,
				tunnel => #{
					type => connect,
					transport_name => case TunnelTransport of
						undefined -> Transport:name();
						_ -> TunnelTransport
					end,
					protocol_name => http2,
					info => TunnelInfo,
					handshake_event => HandshakeEvent,
					protocols => Protocols
				}
			};
		_ ->
			[NewProtocol] = maps:get(protocols, Destination, [http]),
			Opts#{
				stream_ref => RealStreamRef,
				tunnel => #{
					type => connect,
					transport_name => case TunnelTransport of
						undefined -> Transport:name();
						_ -> TunnelTransport
					end,
					protocol_name => http2,
					info => TunnelInfo,
					new_protocol => NewProtocol
				}
			}
	end,
	{tunnel, ProtoState, EvHandlerState} = Proto:init(
		ReplyTo, OriginSocket, gun_tcp_proxy, ProtoOpts, EvHandler, EvHandlerState3),
	{store_stream(State, Stream#stream{tunnel=Tunnel#tunnel{state=established,
		info=TunnelInfo, protocol=Proto, protocol_state=ProtoState}}),
		EvHandlerState}.

headers_frame_connect_websocket(State, Stream=#stream{ref=StreamRef, reply_to=ReplyTo,
		tunnel=Tunnel=#tunnel{info=#websocket_info{opts=WsOpts}}},
		Headers, EvHandler, EvHandlerState0, Extensions, Handler) ->
	RealStreamRef = stream_ref(State, StreamRef),
	ContinueStreamRef = continue_stream_ref(State, StreamRef),
	OriginSocket = #{
		gun_pid => self(),
		reply_to => ReplyTo,
		stream_ref => RealStreamRef,
		handle_continue_stream_ref => ContinueStreamRef
	},
	ReplyTo ! {gun_upgrade, self(), RealStreamRef, [<<"websocket">>], Headers},
	Proto = gun_ws,
	EvHandlerState = EvHandler:protocol_changed(#{
		stream_ref => RealStreamRef,
		protocol => Proto:name()
	}, EvHandlerState0),
	ProtoOpts = #{
		stream_ref => RealStreamRef,
		headers => Headers,
		extensions => Extensions,
		flow => maps:get(flow, WsOpts, infinity),
		handler => Handler,
		opts => WsOpts
	},
	{connected_ws_only, ProtoState} = Proto:init(
		ReplyTo, OriginSocket, gun_tcp_proxy, ProtoOpts),
	{store_stream(State, Stream#stream{tunnel=Tunnel#tunnel{state=established,
		protocol=Proto, protocol_state=ProtoState}}),
		EvHandlerState}.

headers_frame_response(State=#http2_state{content_handlers=Handlers0},
		Stream=#stream{id=StreamID, ref=StreamRef, reply_to=ReplyTo},
		IsFin, Status, Headers, EvHandler, EvHandlerState0) ->
	RealStreamRef = stream_ref(State, StreamRef),
	ReplyTo ! {gun_response, self(), RealStreamRef, IsFin, Status, Headers},
	EvHandlerState1 = EvHandler:response_headers(#{
		stream_ref => RealStreamRef,
		reply_to => ReplyTo,
		status => Status,
		headers => Headers
	}, EvHandlerState0),
	{Handlers, EvHandlerState} = case IsFin of
		fin ->
			EvHandlerState2 = EvHandler:response_end(#{
				stream_ref => RealStreamRef,
				reply_to => ReplyTo
			}, EvHandlerState1),
			{undefined, EvHandlerState2};
		nofin ->
			{gun_content_handler:init(ReplyTo, RealStreamRef,
				Status, Headers, Handlers0), EvHandlerState1}
	end,
	%% We disable the tunnel, if any, when receiving any non 2xx response.
	{maybe_delete_stream(store_stream(State,
		Stream#stream{handler_state=Handlers, tunnel=undefined}),
		StreamID, remote, IsFin), EvHandlerState}.

trailers_frame(State, StreamID, Trailers, EvHandler, EvHandlerState0) ->
	#stream{ref=StreamRef, reply_to=ReplyTo} = get_stream_by_id(State, StreamID),
	%% @todo We probably want to pass this to gun_content_handler?
	RealStreamRef = stream_ref(State, StreamRef),
	ReplyTo ! {gun_trailers, self(), RealStreamRef, Trailers},
	ResponseEvent = #{
		stream_ref => RealStreamRef,
		reply_to => ReplyTo
	},
	EvHandlerState1 = EvHandler:response_trailers(ResponseEvent#{headers => Trailers}, EvHandlerState0),
	EvHandlerState = EvHandler:response_end(ResponseEvent, EvHandlerState1),
	{maybe_delete_stream(State, StreamID, remote, fin), EvHandlerState}.

rst_stream_frame(State0, StreamID, Reason, EvHandler, EvHandlerState0) ->
	case take_stream(State0, StreamID) of
		{#stream{ref=StreamRef, reply_to=ReplyTo}, State} ->
			ReplyTo ! {gun_error, self(), stream_ref(State0, StreamRef),
				{stream_error, Reason, 'Stream reset by server.'}},
			EvHandlerState = EvHandler:cancel(#{
				stream_ref => stream_ref(State, StreamRef),
				reply_to => ReplyTo,
				endpoint => remote,
				reason => Reason
			}, EvHandlerState0),
			{State, EvHandlerState};
		error ->
			{State0, EvHandlerState0}
	end.

%% Pushed streams receive the same initial flow value as the parent stream.
push_promise_frame(State=#http2_state{socket=Socket, transport=Transport,
		status=Status, http2_machine=HTTP2Machine0},
		StreamID, PromisedStreamID, Headers, #{
			method := Method, scheme := Scheme,
			authority := Authority, path := Path},
		EvHandler, EvHandlerState0) ->
	#stream{ref=StreamRef, reply_to=ReplyTo, flow=InitialFlow} = get_stream_by_id(State, StreamID),
	PromisedStreamRef = make_ref(),
	RealPromisedStreamRef = stream_ref(State, PromisedStreamRef),
	URI = iolist_to_binary([Scheme, <<"://">>, Authority, Path]),
	PushPromiseEvent0 = #{
		stream_ref => stream_ref(State, StreamRef),
		reply_to => ReplyTo,
		method => Method,
		uri => URI,
		headers => Headers
	},
	PushPromiseEvent = case Status of
		connected ->
			ReplyTo ! {gun_push, self(), stream_ref(State, StreamRef),
				RealPromisedStreamRef, Method, URI, Headers},
			PushPromiseEvent0#{promised_stream_ref => RealPromisedStreamRef};
		_ ->
			PushPromiseEvent0
	end,
	EvHandlerState = EvHandler:push_promise_end(PushPromiseEvent, EvHandlerState0),
	case Status of
		connected ->
			NewStream = #stream{id=PromisedStreamID, ref=PromisedStreamRef,
				reply_to=ReplyTo, flow=InitialFlow, authority=Authority, path=Path},
			{create_stream(State, NewStream), EvHandlerState};
		%% We cancel the push_promise immediately when we are shutting down.
		_ ->
			{ok, HTTP2Machine} = cow_http2_machine:reset_stream(PromisedStreamID, HTTP2Machine0),
			Transport:send(Socket, cow_http2:rst_stream(PromisedStreamID, cancel)),
			{State#http2_state{http2_machine=HTTP2Machine}, EvHandlerState}
	end.

ignored_frame(State=#http2_state{http2_machine=HTTP2Machine0}) ->
	case cow_http2_machine:ignored_frame(HTTP2Machine0) of
		{ok, HTTP2Machine} ->
			State#http2_state{http2_machine=HTTP2Machine};
		{error, Error={connection_error, _, _}, HTTP2Machine} ->
			connection_error(State#http2_state{http2_machine=HTTP2Machine}, Error)
	end.

%% We always pass handle_continue messages to the tunnel.
handle_continue(ContinueStreamRef, Msg, State0, CookieStore0, EvHandler, EvHandlerState0) ->
	StreamRef = case ContinueStreamRef of
		[SR|_] -> SR;
		_ -> ContinueStreamRef
	end,
	case get_stream_by_ref(State0, StreamRef) of
		Stream=#stream{tunnel=#tunnel{protocol=Proto, protocol_state=ProtoState0}} ->
			{Commands, CookieStore, EvHandlerState1} = Proto:handle_continue(ContinueStreamRef,
				Msg, ProtoState0, CookieStore0, EvHandler, EvHandlerState0),
			{State, EvHandlerState} = tunnel_commands(Commands, Stream, State0, EvHandler, EvHandlerState1),
			{{state, State}, CookieStore, EvHandlerState}
		%% The stream may have ended while TLS was being decoded. @todo What should we do?
%		error ->
%                       error_stream_not_found(State, StreamRef, ReplyTo),
%			{[], EvHandlerState0}
	end.

update_flow(State, _ReplyTo, StreamRef, Inc) ->
	case get_stream_by_ref(State, StreamRef) of
		Stream=#stream{id=StreamID, flow=Flow0} ->
			Flow = case Flow0 of
				infinity -> infinity;
				_ -> Flow0 + Inc
			end,
			if
				%% Flow is active again, update the stream's window.
				Flow0 =< 0, Flow > 0 ->
					{state, update_window(store_stream(State,
						Stream#stream{flow=Flow}), StreamID)};
				true ->
					{state, store_stream(State, Stream#stream{flow=Flow})}
			end;
		error ->
			[]
	end.

%% Only update the connection's window.
update_window(State=#http2_state{socket=Socket, transport=Transport,
		opts=#{initial_connection_window_size := ConnWindow}, http2_machine=HTTP2Machine0}) ->
	case cow_http2_machine:ensure_window(ConnWindow, HTTP2Machine0) of
		ok ->
			State;
		{ok, Increment, HTTP2Machine} ->
			Transport:send(Socket, cow_http2:window_update(Increment)),
			State#http2_state{http2_machine=HTTP2Machine}
	end.

%% Update both the connection and the stream's window.
update_window(State=#http2_state{socket=Socket, transport=Transport,
		opts=#{initial_connection_window_size := ConnWindow, initial_stream_window_size := StreamWindow},
		http2_machine=HTTP2Machine0}, StreamID) ->
	{Data1, HTTP2Machine2} = case cow_http2_machine:ensure_window(ConnWindow, HTTP2Machine0) of
		ok -> {<<>>, HTTP2Machine0};
		{ok, Increment1, HTTP2Machine1} -> {cow_http2:window_update(Increment1), HTTP2Machine1}
	end,
	{Data2, HTTP2Machine} = case cow_http2_machine:ensure_window(StreamID, StreamWindow, HTTP2Machine2) of
		ok -> {<<>>, HTTP2Machine2};
		{ok, Increment2, HTTP2Machine3} -> {cow_http2:window_update(StreamID, Increment2), HTTP2Machine3}
	end,
	case {Data1, Data2} of
		{<<>>, <<>>} -> ok;
		_ -> Transport:send(Socket, [Data1, Data2])
	end,
	State#http2_state{http2_machine=HTTP2Machine}.

%% We may have to cancel streams even if we receive multiple
%% GOAWAY frames as the LastStreamID value may be lower than
%% the one previously received.
goaway(State0=#http2_state{socket=Socket, transport=Transport, http2_machine=HTTP2Machine,
		status=Status, streams=Streams0, stream_refs=Refs}, {goaway, LastStreamID, Reason, _}) ->
	{Streams, RemovedRefs} = goaway_streams(State0, maps:to_list(Streams0), LastStreamID,
		{goaway, Reason, 'The connection is going away.'}, [], []),
	State = State0#http2_state{
		streams=maps:from_list(Streams),
		stream_refs=maps:without(RemovedRefs, Refs)
	},
	case Status of
		connected ->
			Transport:send(Socket, cow_http2:goaway(
				cow_http2_machine:get_last_streamid(HTTP2Machine),
				no_error, <<>>)),
			State#http2_state{status=goaway};
		_ ->
			State
	end.

%% Cancel server-initiated streams that are above LastStreamID.
goaway_streams(_, [], _, _, Acc, RefsAcc) ->
	{Acc, RefsAcc};
goaway_streams(State, [{StreamID, Stream=#stream{ref=StreamRef}}|Tail], LastStreamID, Reason, Acc, RefsAcc)
		when StreamID > LastStreamID, (StreamID rem 2) =:= 1 ->
	close_stream(State, Stream, Reason),
	goaway_streams(State, Tail, LastStreamID, Reason, Acc, [StreamRef|RefsAcc]);
goaway_streams(State, [StreamWithID|Tail], LastStreamID, Reason, Acc, RefsAcc) ->
	goaway_streams(State, Tail, LastStreamID, Reason, [StreamWithID|Acc], RefsAcc).

%% We are already closing, do nothing.
closing(_, #http2_state{status=closing}, _, EvHandlerState) ->
	{[], EvHandlerState};
closing(Reason0, State=#http2_state{socket=Socket, transport=Transport,
		http2_machine=HTTP2Machine}, _, EvHandlerState) ->
	Reason = case Reason0 of
		normal -> no_error;
		owner_down -> no_error;
		_ -> internal_error
	end,
	Transport:send(Socket, cow_http2:goaway(
		cow_http2_machine:get_last_streamid(HTTP2Machine),
		Reason, <<>>)),
	{[
		{state, State#http2_state{status=closing}},
		closing(State)
	], EvHandlerState}.

closing(#http2_state{opts=Opts}) ->
	Timeout = maps:get(closing_timeout, Opts, 15000),
	{closing, Timeout}.

close(Reason0, State=#http2_state{streams=Streams}, _, EvHandlerState) ->
	Reason = close_reason(Reason0),
	_ = maps:fold(fun(_, Stream, _) ->
		close_stream(State, Stream, Reason)
	end, [], Streams),
	EvHandlerState.

close_reason(closed) -> closed;
close_reason(Reason) -> {closed, Reason}.

%% @todo Do we want an event for this?
close_stream(State, #stream{ref=StreamRef, reply_to=ReplyTo}, Reason) ->
	ReplyTo ! {gun_error, self(), stream_ref(State, StreamRef), Reason},
	ok.

keepalive(#http2_state{socket=Socket, transport=Transport}, _, EvHandlerState) ->
	Transport:send(Socket, cow_http2:ping(0)),
	{[], EvHandlerState}.

headers(State=#http2_state{socket=Socket, transport=Transport, opts=Opts,
		http2_machine=HTTP2Machine0}, StreamRef, ReplyTo, Method, Host, Port,
		Path, Headers0, InitialFlow0, CookieStore0, EvHandler, EvHandlerState0)
		when is_reference(StreamRef) ->
	{ok, StreamID, HTTP2Machine1} = cow_http2_machine:init_stream(
		iolist_to_binary(Method), HTTP2Machine0),
	{ok, PseudoHeaders, Headers, CookieStore} = prepare_headers(
		State, Method, Host, Port, Path, Headers0, CookieStore0),
	Authority = maps:get(authority, PseudoHeaders),
	RequestEvent = #{
		stream_ref => stream_ref(State, StreamRef),
		reply_to => ReplyTo,
		function => ?FUNCTION_NAME,
		method => Method,
		authority => Authority,
		path => Path,
		headers => Headers
	},
	EvHandlerState1 = EvHandler:request_start(RequestEvent, EvHandlerState0),
	{ok, IsFin, HeaderBlock, HTTP2Machine} = cow_http2_machine:prepare_headers(
		StreamID, HTTP2Machine1, nofin, PseudoHeaders, Headers),
	Transport:send(Socket, cow_http2:headers(StreamID, IsFin, HeaderBlock)),
	EvHandlerState = EvHandler:request_headers(RequestEvent, EvHandlerState1),
	InitialFlow = initial_flow(InitialFlow0, Opts),
	Stream = #stream{id=StreamID, ref=StreamRef, reply_to=ReplyTo, flow=InitialFlow,
		authority=Authority, path=Path},
	{{state, create_stream(State#http2_state{http2_machine=HTTP2Machine}, Stream)},
		CookieStore, EvHandlerState};
%% Tunneled request.
headers(State, RealStreamRef=[StreamRef|_], ReplyTo, Method, _Host, _Port,
		Path, Headers, InitialFlow, CookieStore0, EvHandler, EvHandlerState0) ->
	case get_stream_by_ref(State, StreamRef) of
		%% @todo We should send an error to the user if the stream isn't ready.
		Stream=#stream{tunnel=#tunnel{protocol=Proto, protocol_state=ProtoState0, info=#{
				origin_host := OriginHost, origin_port := OriginPort}}} ->
			{Commands, CookieStore, EvHandlerState1} = Proto:headers(ProtoState0, RealStreamRef,
				ReplyTo, Method, OriginHost, OriginPort, Path, Headers,
				InitialFlow, CookieStore0, EvHandler, EvHandlerState0),
			{State1, EvHandlerState} = tunnel_commands(Commands, Stream,
				State, EvHandler, EvHandlerState1),
			{{state, State1}, CookieStore, EvHandlerState};
		#stream{tunnel=undefined} ->
			ReplyTo ! {gun_error, self(), stream_ref(State, StreamRef), {badstate,
				"The stream is not a tunnel."}},
			{[], CookieStore0, EvHandlerState0};
		error ->
			error_stream_not_found(State, StreamRef, ReplyTo),
			{[], CookieStore0, EvHandlerState0}
	end.

request(State0=#http2_state{socket=Socket, transport=Transport, opts=Opts,
		http2_machine=HTTP2Machine0}, StreamRef, ReplyTo, Method, Host, Port,
		Path, Headers0, Body, InitialFlow0, CookieStore0, EvHandler, EvHandlerState0)
		when is_reference(StreamRef) ->
	Headers1 = lists:keystore(<<"content-length">>, 1, Headers0,
		{<<"content-length">>, integer_to_binary(iolist_size(Body))}),
	{ok, StreamID, HTTP2Machine1} = cow_http2_machine:init_stream(
		iolist_to_binary(Method), HTTP2Machine0),
	{ok, PseudoHeaders, Headers, CookieStore} = prepare_headers(
		State0, Method, Host, Port, Path, Headers1, CookieStore0),
	Authority = maps:get(authority, PseudoHeaders),
	RealStreamRef = stream_ref(State0, StreamRef),
	RequestEvent = #{
		stream_ref => RealStreamRef,
		reply_to => ReplyTo,
		function => ?FUNCTION_NAME,
		method => Method,
		authority => Authority,
		path => Path,
		headers => Headers
	},
	EvHandlerState1 = EvHandler:request_start(RequestEvent, EvHandlerState0),
	IsFin0 = case iolist_size(Body) of
		0 -> fin;
		_ -> nofin
	end,
	{ok, IsFin, HeaderBlock, HTTP2Machine} = cow_http2_machine:prepare_headers(
		StreamID, HTTP2Machine1, IsFin0, PseudoHeaders, Headers),
	Transport:send(Socket, cow_http2:headers(StreamID, IsFin, HeaderBlock)),
	EvHandlerState = EvHandler:request_headers(RequestEvent, EvHandlerState1),
	InitialFlow = initial_flow(InitialFlow0, Opts),
	Stream = #stream{id=StreamID, ref=StreamRef, reply_to=ReplyTo, flow=InitialFlow,
		authority=Authority, path=Path},
	State = create_stream(State0#http2_state{http2_machine=HTTP2Machine}, Stream),
	case IsFin of
		fin ->
			RequestEndEvent = #{
				stream_ref => RealStreamRef,
				reply_to => ReplyTo
			},
			{{state, State}, CookieStore, EvHandler:request_end(RequestEndEvent, EvHandlerState)};
		nofin ->
			{StateRet, EvHandlerStateRet} = maybe_send_data(
				State, StreamID, fin, Body, EvHandler, EvHandlerState),
			{{state, StateRet}, CookieStore, EvHandlerStateRet}
	end;
%% Tunneled request.
request(State, RealStreamRef=[StreamRef|_], ReplyTo, Method, _Host, _Port,
		Path, Headers, Body, InitialFlow, CookieStore0, EvHandler, EvHandlerState0) ->
	case get_stream_by_ref(State, StreamRef) of
		%% @todo We should send an error to the user if the stream isn't ready.
		Stream=#stream{tunnel=#tunnel{protocol=Proto, protocol_state=ProtoState0, info=#{
				origin_host := OriginHost, origin_port := OriginPort}}} ->
			{Commands, CookieStore, EvHandlerState1} = Proto:request(ProtoState0, RealStreamRef,
				ReplyTo, Method, OriginHost, OriginPort, Path, Headers, Body,
				InitialFlow, CookieStore0, EvHandler, EvHandlerState0),
			{State1, EvHandlerState} = tunnel_commands(Commands,
				Stream, State, EvHandler, EvHandlerState1),
			{{state, State1}, CookieStore, EvHandlerState};
		#stream{tunnel=undefined} ->
			ReplyTo ! {gun_error, self(), stream_ref(State, StreamRef), {badstate,
				"The stream is not a tunnel."}},
			{[], CookieStore0, EvHandlerState0};
		error ->
			error_stream_not_found(State, StreamRef, ReplyTo),
			{[], CookieStore0, EvHandlerState0}
	end.

initial_flow(infinity, #{flow := InitialFlow}) -> InitialFlow;
initial_flow(InitialFlow, _) -> InitialFlow.

prepare_headers(State=#http2_state{transport=Transport},
		Method, Host0, Port, Path, Headers0, CookieStore0) ->
	Scheme = scheme(State),
	Authority = case lists:keyfind(<<"host">>, 1, Headers0) of
		{_, Host} -> Host;
		_ -> gun_http:host_header(Transport:name(), Host0, Port)
	end,
	%% @todo We also must remove any header found in the connection header.
	%% @todo Much of this is duplicated in cow_http2_machine; sort things out.
	Headers1 =
		lists:keydelete(<<"host">>, 1,
		lists:keydelete(<<"connection">>, 1,
		lists:keydelete(<<"keep-alive">>, 1,
		lists:keydelete(<<"proxy-connection">>, 1,
		lists:keydelete(<<"transfer-encoding">>, 1,
		lists:keydelete(<<"upgrade">>, 1, Headers0)))))),
	{Headers, CookieStore} = gun_cookies:add_cookie_header(
		Scheme, Authority, Path, Headers1, CookieStore0),
	PseudoHeaders = #{
		method => Method,
		scheme => Scheme,
		authority => Authority,
		path => Path
	},
	{ok, PseudoHeaders, Headers, CookieStore}.

scheme(#http2_state{transport=Transport}) ->
	case Transport of
		gun_tls -> <<"https">>;
		gun_tls_proxy -> <<"https">>;
		gun_tcp -> <<"http">>;
		gun_tcp_proxy -> <<"http">>;
		gun_tls_proxy_http2_connect -> <<"http">>
	end.

%% @todo Make all calls go through this clause.
data(State=#http2_state{http2_machine=HTTP2Machine}, StreamRef, ReplyTo, IsFin, Data,
		EvHandler, EvHandlerState) when is_reference(StreamRef) ->
	case get_stream_by_ref(State, StreamRef) of
		Stream=#stream{id=StreamID, tunnel=Tunnel} ->
			case cow_http2_machine:get_stream_local_state(StreamID, HTTP2Machine) of
				{ok, fin, _} ->
					error_stream_closed(State, StreamRef, ReplyTo),
					{[], EvHandlerState};
				{ok, _, fin} ->
					error_stream_closed(State, StreamRef, ReplyTo),
					{[], EvHandlerState};
				{ok, _, _} when Tunnel =:= undefined ->
					{State1, EvHandlerStateRet} = maybe_send_data(State,
						StreamID, IsFin, Data, EvHandler, EvHandlerState),
					{{state, State1}, EvHandlerStateRet};
				{ok, _, _} ->
					#tunnel{protocol=Proto, protocol_state=ProtoState0} = Tunnel,
					{Commands, EvHandlerState1} = Proto:data(ProtoState0, StreamRef,
						ReplyTo, IsFin, Data, EvHandler, EvHandlerState),
					{State1, EvHandlerStateRet} = tunnel_commands(Commands,
						Stream, State, EvHandler, EvHandlerState1),
					{{state, State1}, EvHandlerStateRet}
			end;
		error ->
			error_stream_not_found(State, StreamRef, ReplyTo),
			{[], EvHandlerState}
	end;
%% Tunneled data.
data(State, RealStreamRef=[StreamRef|_], ReplyTo, IsFin, Data, EvHandler, EvHandlerState0) ->
	case get_stream_by_ref(State, StreamRef) of
		Stream=#stream{tunnel=#tunnel{protocol=Proto, protocol_state=ProtoState0}} ->
			{Commands, EvHandlerState1} = Proto:data(ProtoState0, RealStreamRef,
				ReplyTo, IsFin, Data, EvHandler, EvHandlerState0),
			{State1, EvHandlerState} = tunnel_commands(Commands,
				Stream, State, EvHandler, EvHandlerState1),
			{{state, State1}, EvHandlerState};
		#stream{tunnel=undefined} ->
			ReplyTo ! {gun_error, self(), stream_ref(State, StreamRef), {badstate,
				"The stream is not a tunnel."}},
			{[], EvHandlerState0};
		error ->
			error_stream_not_found(State, StreamRef, ReplyTo),
			{[], EvHandlerState0}
	end.

maybe_send_data(State=#http2_state{http2_machine=HTTP2Machine0}, StreamID, IsFin, Data0,
		EvHandler, EvHandlerState) ->
	Data = case is_tuple(Data0) of
		false -> {data, Data0};
		true -> Data0
	end,
	case cow_http2_machine:send_or_queue_data(StreamID, HTTP2Machine0, IsFin, Data) of
		{ok, HTTP2Machine} ->
			{State#http2_state{http2_machine=HTTP2Machine}, EvHandlerState};
		{send, SendData, HTTP2Machine} ->
			send_data(State#http2_state{http2_machine=HTTP2Machine}, SendData,
				EvHandler, EvHandlerState)
	end.

send_data(State, [], _, EvHandlerState) ->
	{State, EvHandlerState};
send_data(State0, [{StreamID, IsFin, SendData}|Tail], EvHandler, EvHandlerState0) ->
	{State, EvHandlerState} = send_data(State0, StreamID, IsFin, SendData, EvHandler, EvHandlerState0),
	send_data(State, Tail, EvHandler, EvHandlerState).

send_data(State0, StreamID, IsFin, [Data], EvHandler, EvHandlerState0) ->
	State = send_data_frame(State0, StreamID, IsFin, Data),
	EvHandlerState = case IsFin of
		nofin ->
			EvHandlerState0;
		fin ->
			#stream{ref=StreamRef, reply_to=ReplyTo} = get_stream_by_id(State, StreamID),
			RequestEndEvent = #{
				stream_ref => stream_ref(State, StreamRef),
				reply_to => ReplyTo
			},
			EvHandler:request_end(RequestEndEvent, EvHandlerState0)
	end,
	{maybe_delete_stream(State, StreamID, local, IsFin), EvHandlerState};
send_data(State0, StreamID, IsFin, [Data|Tail], EvHandler, EvHandlerState) ->
	State = send_data_frame(State0, StreamID, nofin, Data),
	send_data(State, StreamID, IsFin, Tail, EvHandler, EvHandlerState).

send_data_frame(State=#http2_state{socket=Socket, transport=Transport},
		StreamID, IsFin, {data, Data}) ->
	Transport:send(Socket, cow_http2:data(StreamID, IsFin, Data)),
	State;
%% @todo Uncomment this once sendfile is supported.
%send_data_frame(State=#http2_state{socket=Socket, transport=Transport},
%		StreamID, IsFin, {sendfile, Offset, Bytes, Path}) ->
%	Transport:send(Socket, cow_http2:data_header(StreamID, IsFin, Bytes)),
%	Transport:sendfile(Socket, Path, Offset, Bytes),
%	State;
%% The stream is terminated in cow_http2_machine:prepare_trailers.
send_data_frame(State=#http2_state{socket=Socket, transport=Transport,
		http2_machine=HTTP2Machine0}, StreamID, nofin, {trailers, Trailers}) ->
	{ok, HeaderBlock, HTTP2Machine}
		= cow_http2_machine:prepare_trailers(StreamID, HTTP2Machine0, Trailers),
	Transport:send(Socket, cow_http2:headers(StreamID, fin, HeaderBlock)),
	State#http2_state{http2_machine=HTTP2Machine}.

reset_stream(State0=#http2_state{socket=Socket, transport=Transport},
		StreamID, StreamError={stream_error, Reason, _}) ->
	Transport:send(Socket, cow_http2:rst_stream(StreamID, Reason)),
	case take_stream(State0, StreamID) of
		{#stream{ref=StreamRef, reply_to=ReplyTo}, State} ->
			ReplyTo ! {gun_error, self(), stream_ref(State, StreamRef), StreamError},
			State;
		error ->
			State0
	end.

connect(State=#http2_state{socket=Socket, transport=Transport, opts=Opts,
		http2_machine=HTTP2Machine0}, StreamRef, ReplyTo,
		Destination=#{host := Host0}, TunnelInfo, Headers0, InitialFlow0,
		EvHandler, EvHandlerState0)
		when is_reference(StreamRef) ->
	Host = case Host0 of
		Tuple when is_tuple(Tuple) -> inet:ntoa(Tuple);
		_ -> Host0
	end,
	Port = maps:get(port, Destination, 1080),
	Authority = [Host, $:, integer_to_binary(Port)],
	PseudoHeaders = #{
		method => <<"CONNECT">>,
		authority => iolist_to_binary(Authority)
	},
	Headers1 =
		lists:keydelete(<<"host">>, 1,
		lists:keydelete(<<"content-length">>, 1, Headers0)),
	HasProxyAuthorization = lists:keymember(<<"proxy-authorization">>, 1, Headers1),
	Headers = case {HasProxyAuthorization, Destination} of
		{false, #{username := UserID, password := Password}} ->
			[{<<"proxy-authorization">>, [
					<<"Basic ">>,
					base64:encode(iolist_to_binary([UserID, $:, Password]))]}
				|Headers1];
		_ ->
			Headers1
	end,
	{ok, StreamID, HTTP2Machine1} = cow_http2_machine:init_stream(<<"CONNECT">>, HTTP2Machine0),
	RealStreamRef = stream_ref(State, StreamRef),
	RequestEvent = #{
		stream_ref => RealStreamRef,
		reply_to => ReplyTo,
		function => connect,
		method => <<"CONNECT">>,
		authority => Authority,
		headers => Headers
	},
	EvHandlerState1 = EvHandler:request_start(RequestEvent, EvHandlerState0),
	{ok, nofin, HeaderBlock, HTTP2Machine} = cow_http2_machine:prepare_headers(
		StreamID, HTTP2Machine1, nofin, PseudoHeaders, Headers),
	Transport:send(Socket, cow_http2:headers(StreamID, nofin, HeaderBlock)),
	EvHandlerState2 = EvHandler:request_headers(RequestEvent, EvHandlerState1),
	RequestEndEvent = #{
		stream_ref => RealStreamRef,
		reply_to => ReplyTo
	},
	EvHandlerState = EvHandler:request_end(RequestEndEvent, EvHandlerState2),
	InitialFlow = initial_flow(InitialFlow0, Opts),
	Stream = #stream{id=StreamID, ref=StreamRef, reply_to=ReplyTo, flow=InitialFlow,
		authority=Authority, path= <<>>, tunnel=#tunnel{destination=Destination, info=TunnelInfo}},
	{{state, create_stream(State#http2_state{http2_machine=HTTP2Machine}, Stream)},
		EvHandlerState};
%% Tunneled request.
connect(State, RealStreamRef=[StreamRef|_], ReplyTo, Destination, TunnelInfo, Headers0, InitialFlow,
		EvHandler, EvHandlerState0) ->
	case get_stream_by_ref(State, StreamRef) of
		%% @todo Should we send an error to the user if the stream isn't ready.
		Stream=#stream{tunnel=#tunnel{protocol=Proto, protocol_state=ProtoState0}} ->
			{Commands, EvHandlerState1} = Proto:connect(ProtoState0, RealStreamRef,
				ReplyTo, Destination, TunnelInfo, Headers0, InitialFlow,
				EvHandler, EvHandlerState0),
			{State1, EvHandlerState} = tunnel_commands(Commands,
				Stream, State, EvHandler, EvHandlerState1),
			{{state, State1}, EvHandlerState};
		#stream{tunnel=undefined} ->
			ReplyTo ! {gun_error, self(), stream_ref(State, StreamRef), {badstate,
				"The stream is not a tunnel."}},
			{[], EvHandlerState0};
		error ->
			error_stream_not_found(State, StreamRef, ReplyTo),
			{[], EvHandlerState0}
	end.

cancel(State=#http2_state{socket=Socket, transport=Transport, http2_machine=HTTP2Machine0},
		StreamRef, ReplyTo, EvHandler, EvHandlerState0)
		when is_reference(StreamRef) ->
	case get_stream_by_ref(State, StreamRef) of
		#stream{id=StreamID} ->
			{ok, HTTP2Machine} = cow_http2_machine:reset_stream(StreamID, HTTP2Machine0),
			Transport:send(Socket, cow_http2:rst_stream(StreamID, cancel)),
			EvHandlerState = EvHandler:cancel(#{
				stream_ref => stream_ref(State, StreamRef),
				reply_to => ReplyTo,
				endpoint => local,
				reason => cancel
			}, EvHandlerState0),
			{{state, delete_stream(State#http2_state{http2_machine=HTTP2Machine}, StreamID)},
				EvHandlerState};
		error ->
			error_stream_not_found(State, StreamRef, ReplyTo),
			{[], EvHandlerState0}
	end;
%% Tunneled request.
cancel(State, RealStreamRef=[StreamRef|_], ReplyTo, EvHandler, EvHandlerState0) ->
	case get_stream_by_ref(State, StreamRef) of
		Stream=#stream{tunnel=#tunnel{protocol=Proto, protocol_state=ProtoState0}} ->
			{Commands, EvHandlerState1} = Proto:cancel(ProtoState0,
				RealStreamRef, ReplyTo, EvHandler, EvHandlerState0),
			{State1, EvHandlerState} = tunnel_commands(Commands,
				Stream, State, EvHandler, EvHandlerState1),
			{{state, State1}, EvHandlerState};
		#stream{tunnel=undefined} ->
			ReplyTo ! {gun_error, self(), stream_ref(State, StreamRef), {badstate,
				"The stream is not a tunnel."}},
			{[], EvHandlerState0};
		error ->
			error_stream_not_found(State, StreamRef, ReplyTo),
			{[], EvHandlerState0}
	end.

timeout(State=#http2_state{http2_machine=HTTP2Machine0}, {cow_http2_machine, undefined, Name}, TRef) ->
	case cow_http2_machine:timeout(Name, TRef, HTTP2Machine0) of
		{ok, HTTP2Machine} ->
			{state, State#http2_state{http2_machine=HTTP2Machine}};
		{error, Error={connection_error, _, _}, _HTTP2Machine} ->
			connection_error(State, Error)
	end;
%% Timeouts occurring in tunnels.
timeout(State, {cow_http2_machine, RealStreamRef, Name}, TRef) ->
	{StreamRef, SubStreamRef} = if
		is_reference(RealStreamRef) -> {RealStreamRef, undefined};
		true -> {hd(RealStreamRef), tl(RealStreamRef)}
	end,
	case get_stream_by_ref(State, StreamRef) of
		Stream=#stream{id=StreamID, tunnel=Tunnel=#tunnel{protocol=Proto, protocol_state=ProtoState0}} ->
			case Proto:timeout(ProtoState0, {cow_http2_machine, SubStreamRef, Name}, TRef) of
				{state, ProtoState} ->
					{state, store_stream(State, Stream#stream{
						tunnel=Tunnel#tunnel{protocol_state=ProtoState}})};
				{error, {connection_error, Reason, Human}} ->
					{state, reset_stream(State, StreamID, {stream_error, Reason, Human})}
			end;
		%% We ignore timeout events for streams that no longer exist.
		error ->
			{state, State}
	end.

stream_info(State, StreamRef) when is_reference(StreamRef) ->
	case get_stream_by_ref(State, StreamRef) of
		#stream{reply_to=ReplyTo, tunnel=#tunnel{destination=Destination,
				info=#{origin_host := OriginHost, origin_port := OriginPort},
				protocol=Proto, protocol_state=ProtoState}} ->
			Transport = maps:get(transport, Destination, tcp),
			Protocol = Proto:tunneled_name(ProtoState, true),
			{ok, #{
				ref => StreamRef,
				reply_to => ReplyTo,
				state => running,
				tunnel => #{
					transport => Transport,
					protocol => Protocol,
					origin_scheme => case {Transport, Protocol} of
						{_, raw} -> undefined;
						{tcp, _} -> <<"http">>;
						{tls, _} -> <<"https">>
					end,
					origin_host => OriginHost,
					origin_port => OriginPort
				}
			}};
		#stream{reply_to=ReplyTo} ->
			{ok, #{
				ref => StreamRef,
				reply_to => ReplyTo,
				state => running
			}};
		error ->
			{ok, undefined}
	end;
%% Tunneled streams.
stream_info(State, RealStreamRef=[StreamRef|_]) ->
	case get_stream_by_ref(State, StreamRef) of
		#stream{tunnel=#tunnel{protocol=Proto, protocol_state=ProtoState}} ->
			%% We must return the real stream_ref as seen by the user.
			%% We therefore set it on return, with the outer layer "winning".
			case Proto:stream_info(ProtoState, RealStreamRef) of
				{ok, undefined} ->
					{ok, undefined};
				{ok, Info} ->
					{ok, Info#{ref => RealStreamRef}}
			end;
		error ->
			{ok, undefined}
	end.

%% @todo Tunnels.
down(#http2_state{stream_refs=Refs}) ->
	maps:keys(Refs).

ws_upgrade(State=#http2_state{socket=Socket, transport=Transport,
		http2_machine=HTTP2Machine0}, StreamRef, ReplyTo,
		Host, Port, Path, Headers0, WsOpts,
		CookieStore0, EvHandler, EvHandlerState0)
		when is_reference(StreamRef) ->
	{ok, StreamID, HTTP2Machine1} = cow_http2_machine:init_stream(
		<<"CONNECT">>, HTTP2Machine0),
	{ok, PseudoHeaders, Headers1, CookieStore} = prepare_headers(State,
		<<"CONNECT">>, Host, Port, Path, Headers0, CookieStore0),
	{Headers2, GunExtensions} = case maps:get(compress, WsOpts, false) of
		true ->
			{[{<<"sec-websocket-extensions">>,
				<<"permessage-deflate; client_max_window_bits; server_max_window_bits=15">>}
			|Headers1], [<<"permessage-deflate">>]};
		false ->
			{Headers1, []}
	end,
	Headers3 = case maps:get(protocols, WsOpts, []) of
		[] ->
			Headers2;
		ProtoOpt ->
			<< _, _, Proto/bits >> = iolist_to_binary([[<<", ">>, P] || {P, _} <- ProtoOpt]),
			[{<<"sec-websocket-protocol">>, Proto}|Headers2]
	end,
	Headers = [{<<"sec-websocket-version">>, <<"13">>}|Headers3],
	Authority = maps:get(authority, PseudoHeaders),
	RealStreamRef = stream_ref(State, StreamRef),
	RequestEvent = #{
		stream_ref => RealStreamRef,
		reply_to => ReplyTo,
		function => ?FUNCTION_NAME,
		method => <<"CONNECT">>,
		authority => Authority,
		path => Path,
		headers => Headers
	},
	EvHandlerState1 = EvHandler:request_start(RequestEvent, EvHandlerState0),
	{ok, IsFin, HeaderBlock, HTTP2Machine} = cow_http2_machine:prepare_headers(
		StreamID, HTTP2Machine1, nofin, PseudoHeaders#{protocol => <<"websocket">>}, Headers),
	Transport:send(Socket, cow_http2:headers(StreamID, IsFin, HeaderBlock)),
	EvHandlerState2 = EvHandler:request_headers(RequestEvent, EvHandlerState1),
	RequestEndEvent = #{
		stream_ref => RealStreamRef,
		reply_to => ReplyTo
	},
	EvHandlerState = EvHandler:request_end(RequestEndEvent, EvHandlerState2),
	InitialFlow = maps:get(flow, WsOpts, infinity),
	Stream = #stream{id=StreamID, ref=StreamRef, reply_to=ReplyTo, flow=InitialFlow,
		authority=Authority, path=Path, tunnel=#tunnel{info=#websocket_info{
			extensions=GunExtensions, opts=WsOpts}}},
	{{state, create_stream(State#http2_state{http2_machine=HTTP2Machine}, Stream)},
		CookieStore, EvHandlerState};
ws_upgrade(State, RealStreamRef=[StreamRef|_], ReplyTo,
		Host, Port, Path, Headers, WsOpts, CookieStore0, EvHandler, EvHandlerState0) ->
	case get_stream_by_ref(State, StreamRef) of
		Stream=#stream{tunnel=#tunnel{protocol=Proto, protocol_state=ProtoState0}} ->
			{Commands, CookieStore, EvHandlerState1} = Proto:ws_upgrade(
				ProtoState0, RealStreamRef, ReplyTo,
				Host, Port, Path, Headers, WsOpts,
				CookieStore0, EvHandler, EvHandlerState0),
			{State1, EvHandlerState} = tunnel_commands(Commands,
				Stream, State, EvHandler, EvHandlerState1),
			{{state, State1}, CookieStore, EvHandlerState}
		%% @todo Error conditions?
	end.

ws_send(Frames, State0, RealStreamRef, ReplyTo, EvHandler, EvHandlerState0) ->
	StreamRef = case RealStreamRef of
		[SR|_] -> SR;
		_ -> RealStreamRef
	end,
	case get_stream_by_ref(State0, StreamRef) of
		Stream=#stream{tunnel=#tunnel{protocol=Proto, protocol_state=ProtoState}} ->
			{Commands, EvHandlerState1} = Proto:ws_send(Frames, ProtoState,
				RealStreamRef, ReplyTo, EvHandler, EvHandlerState0),
			{State, EvHandlerState} = tunnel_commands(Commands, Stream, State0, EvHandler, EvHandlerState1),
			{{state, State}, EvHandlerState}
		%% @todo Error conditions?
	end.

connection_error(#http2_state{socket=Socket, transport=Transport,
		http2_machine=HTTP2Machine, streams=Streams},
		Error={connection_error, Reason, HumanReadable}) ->
	Pids = lists:usort(maps:fold(
		fun(_, #stream{reply_to=ReplyTo}, Acc) -> [ReplyTo|Acc] end,
		[], Streams)),
	_ = [Pid ! {gun_error, self(), {Reason, HumanReadable}} || Pid <- Pids],
	Transport:send(Socket, cow_http2:goaway(
		cow_http2_machine:get_last_streamid(HTTP2Machine),
		Reason, <<>>)),
	{error, Error}.

%% Stream functions.

error_stream_closed(State, StreamRef, ReplyTo) ->
	ReplyTo ! {gun_error, self(), stream_ref(State, StreamRef), {badstate,
		"The stream has already been closed."}},
	ok.

error_stream_not_found(State, StreamRef, ReplyTo) ->
	ReplyTo ! {gun_error, self(), stream_ref(State, StreamRef), {badstate,
		"The stream cannot be found."}},
	ok.

%% Streams.

stream_ref(#http2_state{base_stream_ref=undefined}, StreamRef) ->
	StreamRef;
stream_ref(#http2_state{base_stream_ref=BaseStreamRef}, StreamRef)
		when is_reference(BaseStreamRef) ->
	[BaseStreamRef, StreamRef];
stream_ref(#http2_state{base_stream_ref=BaseStreamRef}, StreamRef) ->
	BaseStreamRef ++ [StreamRef].

get_stream_by_id(#http2_state{streams=Streams}, StreamID) ->
	maps:get(StreamID, Streams).

get_stream_by_ref(#http2_state{streams=Streams, stream_refs=Refs}, StreamRef) ->
	case maps:get(StreamRef, Refs, error) of
		error -> error;
		StreamID -> maps:get(StreamID, Streams)
	end.

create_stream(State=#http2_state{streams=Streams, stream_refs=Refs},
		Stream=#stream{id=StreamID, ref=StreamRef}) ->
	State#http2_state{
		streams=Streams#{StreamID => Stream},
		stream_refs=Refs#{StreamRef => StreamID}
	}.

store_stream(State=#http2_state{streams=Streams}, Stream=#stream{id=StreamID}) ->
	State#http2_state{streams=Streams#{StreamID => Stream}}.

take_stream(State=#http2_state{streams=Streams0, stream_refs=Refs}, StreamID) ->
	case maps:take(StreamID, Streams0) of
		{Stream=#stream{ref=StreamRef}, Streams} ->
			{Stream, State#http2_state{
				streams=Streams,
				stream_refs=maps:remove(StreamRef, Refs)
			}};
		error ->
			error
	end.

maybe_delete_stream(State=#http2_state{http2_machine=HTTP2Machine}, StreamID, local, fin) ->
	case cow_http2_machine:get_stream_remote_state(StreamID, HTTP2Machine) of
		{ok, fin} -> delete_stream(State, StreamID);
		{error, closed} -> delete_stream(State, StreamID);
		_ -> State
	end;
maybe_delete_stream(State=#http2_state{http2_machine=HTTP2Machine}, StreamID, remote, fin) ->
	case cow_http2_machine:get_stream_local_state(StreamID, HTTP2Machine) of
		{ok, fin, _} -> delete_stream(State, StreamID);
		{error, closed} -> delete_stream(State, StreamID);
		_ -> State
	end;
maybe_delete_stream(State, _, _, _) ->
	State.

delete_stream(State=#http2_state{streams=Streams, stream_refs=Refs}, StreamID) ->
	#{StreamID := #stream{ref=StreamRef}} = Streams,
	State#http2_state{
		streams=maps:remove(StreamID, Streams),
		stream_refs=maps:remove(StreamRef, Refs)
	}.
