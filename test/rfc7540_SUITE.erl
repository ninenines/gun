%% Copyright (c) 2018-2020, Loïc Hoguin <essen@ninenines.eu>
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

-module(rfc7540_SUITE).
-compile(export_all).
-compile(nowarn_export_all).

-import(ct_helper, [doc/1]).
-import(gun_test, [init_origin/2]).
-import(gun_test, [init_origin/3]).
-import(gun_test, [receive_from/1]).

all() ->
	ct_helper:all(?MODULE).

%% Proxy helpers.

-record(proxy_stream, {
	id,
	status,
	resp_headers = [],
	delay = 0,
	origin_socket
}).

-record(proxy, {
	parent,
	socket,
	transport,
	streams = [],
	decode_state = cow_hpack:init(),
	encode_state = cow_hpack:init()
}).

do_proxy_start(Transport) ->
	do_proxy_start(Transport, [#proxy_stream{id=1, status=200, resp_headers=[], delay=0}]).

do_proxy_start(Transport0, Streams) ->
	Transport = case Transport0 of
		tcp -> gun_tcp;
		tls -> gun_tls
	end,
	Proxy = #proxy{parent=self(), transport=Transport, streams=Streams},
	Pid = spawn_link(fun() -> do_proxy_init(Proxy) end),
	Port = receive_from(Pid),
	{ok, Pid, Port}.

do_proxy_init(Proxy=#proxy{parent=Parent, transport=Transport}) ->
	{ok, ListenSocket} = case Transport of
		gun_tcp ->
			gen_tcp:listen(0, [binary, {active, false}]);
		gun_tls ->
			Opts = ct_helper:get_certs_from_ets(),
			ssl:listen(0, [binary, {active, false}, {alpn_preferred_protocols, [<<"h2">>]}|Opts])
	end,
	{ok, {_, Port}} = Transport:sockname(ListenSocket),
	Parent ! {self(), Port},
	{ok, Socket} = case Transport of
		gun_tcp ->
			gen_tcp:accept(ListenSocket, infinity);
		gun_tls ->
			{ok, Socket0} = ssl:transport_accept(ListenSocket, infinity),
			ssl:handshake(Socket0, infinity),
			{ok, <<"h2">>} = ssl:negotiated_protocol(Socket0),
			{ok, Socket0}
	end,
	gun_test:http2_handshake(Socket, case Transport of
		gun_tcp -> gen_tcp;
		gun_tls -> ssl
	end),
	Parent ! {self(), handshake_completed},
	Transport:setopts(Socket, [{active, true}]),
	do_proxy_receive(<<>>, Proxy#proxy{socket=Socket}).

do_proxy_receive(Buffer, Proxy=#proxy{socket=Socket, transport=Transport}) ->
	{OK, _, _} = Transport:messages(),
	receive
		{OK, Socket, Data0} ->
			do_proxy_parse(<<Buffer/binary, Data0/bits>>, Proxy);
		{tcp, OriginSocket, OriginData} ->
			do_proxy_forward(Buffer, Proxy, OriginSocket, OriginData);
		%% Wait forever when a connection gets closed. We will exit with the test process.
		{tcp_closed, _} ->
			timer:sleep(infinity);
		{ssl_closed, _} ->
			timer:sleep(infinity);
		Msg ->
			error(Msg)
	end.

%% We only expect to receive data on a CONNECT stream.
do_proxy_parse(<<Len:24, 0:8, _:8, StreamID:32, Payload:Len/binary, Rest/bits>>,
		Proxy=#proxy{streams=Streams}) ->
	#proxy_stream{origin_socket=OriginSocket}
		= lists:keyfind(StreamID, #proxy_stream.id, Streams),
	case gen_tcp:send(OriginSocket, Payload) of
		ok ->
			do_proxy_parse(Rest, Proxy);
		{error, _} ->
			ok
	end;
do_proxy_parse(<<Len:24, 1:8, _:8, StreamID:32, ReqHeadersBlock:Len/binary, Rest/bits>>,
		Proxy=#proxy{parent=Parent, socket=Socket, transport=Transport,
			streams=Streams0, decode_state=DecodeState0, encode_state=EncodeState0}) ->
	#proxy_stream{status=Status, resp_headers=RespHeaders, delay=Delay}
		= Stream = lists:keyfind(StreamID, #proxy_stream.id, Streams0),
	{ReqHeaders0, DecodeState} = cow_hpack:decode(ReqHeadersBlock, DecodeState0),
	ReqHeaders = maps:from_list(ReqHeaders0),
	timer:sleep(Delay),
	Parent ! {self(), {request, ReqHeaders}},
	{IsFin, OriginSocket} = case ReqHeaders of
		#{<<":method">> := <<"CONNECT">>, <<":authority">> := Authority}
				when Status >= 200, Status < 300 ->
			{OriginHost, OriginPort} = cow_http_hd:parse_host(Authority),
			{ok, OriginSocket0} = gen_tcp:connect(
				binary_to_list(OriginHost), OriginPort,
				[binary, {active, true}]),
			{nofin, OriginSocket0};
		#{} ->
			{fin, undefined}
	end,
	{RespHeadersBlock, EncodeState} = cow_hpack:encode([
		{<<":status">>, integer_to_binary(Status)}
	|RespHeaders], EncodeState0),
	ok = Transport:send(Socket, [
		cow_http2:headers(StreamID, IsFin, RespHeadersBlock)
	]),
	Streams = lists:keystore(StreamID, #proxy_stream.id, Streams0,
		Stream#proxy_stream{origin_socket=OriginSocket}),
	do_proxy_parse(Rest, Proxy#proxy{streams=Streams,
		decode_state=DecodeState, encode_state=EncodeState});
%% An RST_STREAM was received. Stop the proxy.
do_proxy_parse(<<_:24, 3:8, _/bits>>, _) ->
	ok;
do_proxy_parse(<<Len:24, Header:6/binary, Payload:Len/binary, Rest/bits>>, Proxy) ->
	ct:pal("Ignoring packet header ~0p~npayload ~p", [Header, Payload]),
	do_proxy_parse(Rest, Proxy);
do_proxy_parse(Rest, Proxy) ->
	do_proxy_receive(Rest, Proxy).

do_proxy_forward(Buffer, Proxy=#proxy{socket=Socket, transport=Transport, streams=Streams},
		OriginSocket, OriginData) ->
	#proxy_stream{id=StreamID} = lists:keyfind(OriginSocket, #proxy_stream.origin_socket, Streams),
	Len = byte_size(OriginData),
	Data = [<<Len:24, 0:8, 0:8, StreamID:32>>, OriginData],
	case Transport:send(Socket, Data) of
		ok ->
			do_proxy_receive(Buffer, Proxy);
		{error, _} ->
			ok
	end.

%% Tests.

authority_default_port_http(_) ->
	doc("The default port for http should not be sent in "
		"the :authority pseudo-header. (RFC7540 3, RFC7230 2.7.1)"),
	do_authority_port(tcp, 80, <<>>).

authority_default_port_https(_) ->
	doc("The default port for https should not be sent in "
		"the :authority pseudo-header. (RFC7540 3, RFC7230 2.7.2)"),
	do_authority_port(tls, 443, <<>>).

authority_ipv6(_) ->
	doc("When connecting to a server using an IPv6 address the :authority "
		"pseudo-header must wrap the address with brackets. (RFC7540 8.1.2.3, RFC3986 3.2.2)"),
	{ok, OriginPid, OriginPort} = init_origin(tcp6, http2, fun(Parent, Socket, Transport) ->
		%% Receive the HEADERS frame and send the headers decoded.
		{ok, <<Len:24, 1:8, _:8, 1:32>>} = Transport:recv(Socket, 9, 1000),
		{ok, ReqHeadersBlock} = Transport:recv(Socket, Len, 1000),
		{ReqHeaders, _} = cow_hpack:decode(ReqHeadersBlock),
		Parent ! {self(), ReqHeaders}
	end),
	{ok, ConnPid} = gun:open({0,0,0,0,0,0,0,1}, OriginPort, #{
		transport => tcp,
		protocols => [http2]
	}),
	{ok, http2} = gun:await_up(ConnPid),
	handshake_completed = receive_from(OriginPid),
	_ = gun:get(ConnPid, "/"),
	ReqHeaders = receive_from(OriginPid),
	{_, <<"[::1]", _/bits>>} = lists:keyfind(<<":authority">>, 1, ReqHeaders),
	gun:close(ConnPid).

authority_other_port_http(_) ->
	doc("Non-default ports for http must be sent in "
		"the :authority pseudo-header. (RFC7540 3, RFC7230 2.7.1)"),
	do_authority_port(tcp, 443, <<":443">>).

authority_other_port_https(_) ->
	doc("Non-default ports for https must be sent in "
		"the :authority pseudo-header. (RFC7540 3, RFC7230 2.7.2)"),
	do_authority_port(tls, 80, <<":80">>).

do_authority_port(Transport0, DefaultPort, AuthorityHeaderPort) ->
	{ok, OriginPid, OriginPort} = init_origin(Transport0, http2, fun(Parent, Socket, Transport) ->
		%% Receive the HEADERS frame and send the headers decoded.
		{ok, <<Len:24, 1:8, _:8, 1:32>>} = Transport:recv(Socket, 9, 1000),
		{ok, ReqHeadersBlock} = Transport:recv(Socket, Len, 1000),
		{ReqHeaders, _} = cow_hpack:decode(ReqHeadersBlock),
		Parent ! {self(), ReqHeaders}
	end),
	{ok, ConnPid} = gun:open("localhost", OriginPort, #{
		transport => Transport0,
		protocols => [http2]
	}),
	{ok, http2} = gun:await_up(ConnPid),
	handshake_completed = receive_from(OriginPid),
	%% Change the origin's port in the state to trigger the default port behavior.
	_ = sys:replace_state(ConnPid, fun({StateName, StateData}) ->
		{StateName, setelement(8, StateData, DefaultPort)}
	end, 5000),
	%% Confirm the default port is not sent in the request.
	_ = gun:get(ConnPid, "/"),
	ReqHeaders = receive_from(OriginPid),
	{_, <<"localhost", Rest/bits>>} = lists:keyfind(<<":authority">>, 1, ReqHeaders),
	AuthorityHeaderPort = Rest,
	gun:close(ConnPid).

prior_knowledge_preface_garbage(_) ->
	doc("A PROTOCOL_ERROR connection error must result from the server sending "
		"an invalid preface in the form of garbage when connecting "
		"using the prior knowledge method. (RFC7540 3.4, RFC7540 3.5)"),
	%% We use 'http' here because we are going to do the handshake manually.
	{ok, OriginPid, Port} = init_origin(tcp, http, fun(_, Socket, Transport) ->
		ok = Transport:send(Socket, <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15>>),
		timer:sleep(100)
	end),
	{ok, ConnPid} = gun:open("localhost", Port, #{protocols => [http2]}),
	{ok, http2} = gun:await_up(ConnPid),
	handshake_completed = receive_from(OriginPid),
	receive
		{gun_down, ConnPid, http2, {error, {connection_error, protocol_error,
				'Invalid connection preface received. (RFC7540 3.5)'}}, []} ->
			gun:close(ConnPid);
		Msg ->
			error({unexpected_msg, Msg})
	after 1000 ->
		error(timeout)
	end.

prior_knowledge_preface_http1(_) ->
	doc("A PROTOCOL_ERROR connection error must result from the server sending "
		"an invalid preface in the form of an HTTP/1.1 response when connecting "
		"using the prior knowledge method. (RFC7540 3.4, RFC7540 3.5)"),
	%% We use 'http' here because we are going to do the handshake manually.
	{ok, OriginPid, Port} = init_origin(tcp, http, fun(_, Socket, Transport) ->
		ok = Transport:send(Socket, <<
			"HTTP/1.1 400 Bad Request\r\n"
			"Connection: close\r\n"
			"Content-Length: 0\r\n"
			"Date: Thu, 27 Feb 2020 09:32:17 GMT\r\n"
			"\r\n">>),
		timer:sleep(100)
	end),
	{ok, ConnPid} = gun:open("localhost", Port, #{protocols => [http2]}),
	{ok, http2} = gun:await_up(ConnPid),
	handshake_completed = receive_from(OriginPid),
	receive
		{gun_down, ConnPid, http2, {error, {connection_error, protocol_error,
				'Invalid connection preface received. Appears to be an HTTP/1 response? (RFC7540 3.5)'}}, []} ->
			gun:close(ConnPid);
		Msg ->
			error({unexpected_msg, Msg})
	after 1000 ->
		error(timeout)
	end.

prior_knowledge_preface_http1_await(_) ->
	doc("A PROTOCOL_ERROR connection error must result from the server sending "
		"an invalid preface in the form of an HTTP/1.1 response when connecting "
		"using the prior knowledge method. (RFC7540 3.4, RFC7540 3.5)"),
	%% We use 'http' here because we are going to do the handshake manually.
	{ok, OriginPid, Port} = init_origin(tcp, http, fun(_, Socket, Transport) ->
		timer:sleep(100),
		ok = Transport:send(Socket, <<
			"HTTP/1.1 400 Bad Request\r\n"
			"Connection: close\r\n"
			"Content-Length: 0\r\n"
			"Date: Thu, 27 Feb 2020 09:32:17 GMT\r\n"
			"\r\n">>),
		timer:sleep(100)
	end),
	{ok, ConnPid} = gun:open("localhost", Port, #{protocols => [http2], retry => 0}),
	{ok, http2} = gun:await_up(ConnPid),
	handshake_completed = receive_from(OriginPid),
	{error, {down, {shutdown, {error, {connection_error, protocol_error,
		'Invalid connection preface received. Appears to be an HTTP/1 response? (RFC7540 3.5)'}}}}}
		= gun:await(ConnPid, make_ref()),
	gun:close(ConnPid).

prior_knowledge_preface_other_frame(_) ->
	doc("A PROTOCOL_ERROR connection error must result from the server sending "
		"an invalid preface in the form of a non-SETTINGS frame when connecting "
		"using the prior knowledge method. (RFC7540 3.4, RFC7540 3.5)"),
	%% We use 'http' here because we are going to do the handshake manually.
	{ok, OriginPid, Port} = init_origin(tcp, http, fun(_, Socket, Transport) ->
		ok = Transport:send(Socket, cow_http2:window_update(1)),
		timer:sleep(100)
	end),
	{ok, ConnPid} = gun:open("localhost", Port, #{protocols => [http2]}),
	{ok, http2} = gun:await_up(ConnPid),
	handshake_completed = receive_from(OriginPid),
	receive
		{gun_down, ConnPid, http2, {error, {connection_error, protocol_error,
				'Invalid connection preface received. (RFC7540 3.5)'}}, []} ->
			gun:close(ConnPid);
		Msg ->
			error({unexpected_msg, Msg})
	after 1000 ->
		error(timeout)
	end.

lingering_data_counts_toward_connection_window(_) ->
	doc("DATA frames received after sending RST_STREAM must be counted "
		"toward the connection flow-control window. (RFC7540 5.1)"),
	{ok, OriginPid, Port} = init_origin(tcp, http2, fun(_, Socket, Transport) ->
		%% Step 2.
		%% Receive a HEADERS frame.
		{ok, <<SkipLen:24, 1:8, _:8, 1:32>>} = Transport:recv(Socket, 9, 1000),
		%% Skip the header.
		{ok, _} = gen_tcp:recv(Socket, SkipLen, 1000),
		%% Step 3.
		%% Send a HEADERS frame.
		{HeadersBlock, _} = cow_hpack:encode([
			{<<":status">>, <<"200">>}
		]),
		ok = Transport:send(Socket, [
			cow_http2:headers(1, nofin, HeadersBlock)
		]),
		%% Step 5.
		%% Make sure Gun sends the RST_STREAM.
		timer:sleep(100),
		%% Step 7.
		ok = Transport:send(Socket, [
			cow_http2:data(1, nofin, <<0:0/unit:8>>),
			cow_http2:data(1, nofin, <<0:1000/unit:8>>)
		]),
		%% Skip RST_STREAM.
		{ok, << 4:24, 3:8, 1:40, _:32 >>} = gen_tcp:recv(Socket, 13, 1000),
		%% Received a WINDOW_UPDATE frame after we got RST_STREAM.
		{ok, << 4:24, 8:8, 0:40, Increment:32 >>} = gen_tcp:recv(Socket, 13, 1000),
		true = Increment > 0
	end),
	{ok, ConnPid} = gun:open("localhost", Port, #{
		protocols => [http2],
		http2_opts => #{
			%% We don't set 65535 because we still want to have an initial WINDOW_UPDATE.
			initial_connection_window_size => 65536,
			initial_stream_window_size => 65535
		}
	}),
	{ok, http2} = gun:await_up(ConnPid),
	handshake_completed = receive_from(OriginPid),
	%% Step 1.
	StreamRef = gun:get(ConnPid, "/"),
	%% Step 4.
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
	%% Step 6.
	gun:cancel(ConnPid, StreamRef),
	%% Make sure Gun sends the WINDOW_UPDATE and the server test passes.
	timer:sleep(300),
	gun:close(ConnPid).

headers_priority_flag(_) ->
	doc("HEADERS frames may include a PRIORITY flag indicating "
		"that stream dependency information is attached. (RFC7540 6.2)"),
	{ok, OriginPid, Port} = init_origin(tcp, http2, fun(_, Socket, Transport) ->
		%% Receive a HEADERS frame.
		{ok, <<_:24, 1:8, _:8, 1:32>>} = Transport:recv(Socket, 9, 1000),
		%% Send a HEADERS frame with PRIORITY back.
		{HeadersBlock, _} = cow_hpack:encode([
			{<<":status">>, <<"200">>}
		]),
		Len = iolist_size(HeadersBlock) + 5,
		ok = Transport:send(Socket, [
			<<Len:24, 1:8,
				0:2, %% Undefined.
				1:1, %% PRIORITY.
				0:1, %% Undefined.
				0:1, %% PADDED.
				1:1, %% END_HEADERS.
				0:1, %% Undefined.
				1:1, %% END_STREAM.
				0:1, 1:31,
				1:1, %% Exclusive?
				3:31, %% Stream dependency.
				42:8 >>, %% Weight.
			HeadersBlock
		]),
		timer:sleep(1000)
	end),
	{ok, ConnPid} = gun:open("localhost", Port, #{protocols => [http2]}),
	{ok, http2} = gun:await_up(ConnPid),
	handshake_completed = receive_from(OriginPid),
	StreamRef = gun:get(ConnPid, "/"),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef),
	gun:close(ConnPid).

settings_ack_timeout(_) ->
	doc("Failure to acknowledge the client's SETTINGS frame "
		"results in a SETTINGS_TIMEOUT connection error. (RFC7540 6.5.3)"),
	%% We use 'http' here because we are going to do the handshake manually.
	{ok, _, Port} = init_origin(tcp, http, fun(_, Socket, Transport) ->
		%% Send a valid preface.
		ok = Transport:send(Socket, cow_http2:settings(#{})),
		%% Receive the fixed sequence from the preface.
		Preface = <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>,
		{ok, Preface} = Transport:recv(Socket, byte_size(Preface), 5000),
		%% Receive the SETTINGS from the preface.
		{ok, <<Len:24>>} = Transport:recv(Socket, 3, 5000),
		{ok, <<4:8, 0:40, _:Len/binary>>} = Transport:recv(Socket, 6 + Len, 5000),
		%% Receive the WINDOW_UPDATE sent with the preface.
		{ok, <<4:24, 8:8, 0:40, _:32>>} = Transport:recv(Socket, 13, 5000),
		%% Receive the SETTINGS ack.
		{ok, <<0:24, 4:8, 1:8, 0:32>>} = Transport:recv(Socket, 9, 5000),
		%% Do not ack the client preface. Expect a GOAWAY with reason SETTINGS_TIMEOUT.
		{ok, << _:24, 7:8, _:72, 4:32 >>} = Transport:recv(Socket, 17, 6000)
	end),
	{ok, ConnPid} = gun:open("localhost", Port, #{protocols => [http2]}),
	{ok, http2} = gun:await_up(ConnPid),
	timer:sleep(6000),
	gun:close(ConnPid).

connect_http_via_h2c(_) ->
	doc("CONNECT can be used to establish a TCP connection "
		"to an HTTP/1.1 server via a TCP HTTP/2 proxy. (RFC7540 8.3)"),
	do_connect_http(<<"http">>, tcp, http, <<"http">>, tcp).

connect_https_via_h2c(_) ->
	doc("CONNECT can be used to establish a TLS connection "
		"to an HTTP/1.1 server via a TCP HTTP/2 proxy. (RFC7540 8.3)"),
	do_connect_http(<<"https">>, tls, http, <<"http">>, tcp).

connect_http_via_h2(_) ->
	doc("CONNECT can be used to establish a TCP connection "
		"to an HTTP/1.1 server via a TLS HTTP/2 proxy. (RFC7540 8.3)"),
	do_connect_http(<<"http">>, tcp, http, <<"https">>, tls).

connect_https_via_h2(_) ->
	doc("CONNECT can be used to establish a TLS connection "
		"to an HTTP/1.1 server via a TLS HTTP/2 proxy. (RFC7540 8.3)"),
	do_connect_http(<<"https">>, tls, http, <<"https">>, tls).

connect_h2c_via_h2c(_) ->
	doc("CONNECT can be used to establish a TCP connection "
		"to an HTTP/2 server via a TCP HTTP/2 proxy. (RFC7540 8.3)"),
	do_connect_http(<<"http">>, tcp, http2, <<"http">>, tcp).

connect_h2_via_h2c(_) ->
	doc("CONNECT can be used to establish a TLS connection "
		"to an HTTP/2 server via a TCP HTTP/2 proxy. (RFC7540 8.3)"),
	do_connect_http(<<"https">>, tls, http2, <<"http">>, tcp).

connect_h2c_via_h2(_) ->
	doc("CONNECT can be used to establish a TCP connection "
		"to an HTTP/2 server via a TLS HTTP/2 proxy. (RFC7540 8.3)"),
	do_connect_http(<<"http">>, tcp, http2, <<"https">>, tls).

connect_h2_via_h2(_) ->
	doc("CONNECT can be used to establish a TLS connection "
		"to an HTTP/2 server via a TLS HTTP/2 proxy. (RFC7540 8.3)"),
	do_connect_http(<<"https">>, tls, http2, <<"https">>, tls).

do_origin_fun(http) ->
	fun(Parent, Socket, Transport) ->
		%% Receive the request-line and headers, parse and send them.
		{ok, Data} = Transport:recv(Socket, 0, 5000),
		{Method, Target, 'HTTP/1.1', Rest} = cow_http:parse_request_line(Data),
		{Headers0, _} = cow_http:parse_headers(Rest),
		Headers = maps:from_list(Headers0),
		%% We roughly transform the HTTP/1.1 headers into HTTP/2 format.
		Parent ! {self(), Headers#{
			<<":authority">> => maps:get(<<"host">>, Headers, <<>>),
			<<":method">> => Method,
			<<":path">> => Target
		}},
		gun_test:loop_origin(Parent, Socket, Transport)
	end;
do_origin_fun(http2) ->
	fun(Parent, Socket, Transport) ->
		%% Receive the HEADERS frame and send the headers decoded.
		{ok, <<Len:24, 1:8, _:8, 1:32>>} = Transport:recv(Socket, 9, 1000),
		{ok, ReqHeadersBlock} = Transport:recv(Socket, Len, 1000),
		{ReqHeaders, _} = cow_hpack:decode(ReqHeadersBlock),
		Parent ! {self(), maps:from_list(ReqHeaders)},
		gun_test:loop_origin(Parent, Socket, Transport)
	end.

do_connect_http(OriginScheme, OriginTransport, OriginProtocol, ProxyScheme, ProxyTransport) ->
	{ok, OriginPid, OriginPort} = init_origin(OriginTransport, OriginProtocol, do_origin_fun(OriginProtocol)),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(ProxyTransport, [
		#proxy_stream{id=1, status=200}
	]),
	Authority = iolist_to_binary(["localhost:", integer_to_binary(OriginPort)]),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		transport => ProxyTransport,
		protocols => [http2]
	}),
	{ok, http2} = gun:await_up(ConnPid),
	handshake_completed = receive_from(ProxyPid),
	StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		transport => OriginTransport,
		protocols => [OriginProtocol]
	}),
	{request, #{
		<<":method">> := <<"CONNECT">>,
		<<":authority">> := Authority
	}} = receive_from(ProxyPid),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef),
	handshake_completed = receive_from(OriginPid),
	{up, OriginProtocol} = gun:await(ConnPid, StreamRef),
	ProxiedStreamRef = gun:get(ConnPid, "/proxied", #{}, #{tunnel => StreamRef}),
	#{<<":authority">> := Authority} = receive_from(OriginPid),
	#{
		transport := ProxyTransport,
		protocol := http2,
		origin_scheme := ProxyScheme,
		origin_host := "localhost",
		origin_port := ProxyPort,
		intermediaries := [] %% Intermediaries are specific to the CONNECT stream.
	} = gun:info(ConnPid),
	{ok, #{
		ref := StreamRef,
		reply_to := Self,
		state := running,
		tunnel := #{
			transport := OriginTransport,
			protocol := OriginProtocol,
			origin_scheme := OriginScheme,
			origin_host := "localhost",
			origin_port := OriginPort
		}
	}} = gun:stream_info(ConnPid, StreamRef),
	{ok, #{
		ref := ProxiedStreamRef,
		reply_to := Self,
		state := running,
		intermediaries := [#{
			type := connect,
			host := "localhost",
			port := ProxyPort,
			transport := ProxyTransport,
			protocol := http2
		}]
	}} = gun:stream_info(ConnPid, ProxiedStreamRef),
	gun:close(ConnPid).

connect_cowboy_http_via_h2c(_) ->
	doc("CONNECT can be used to establish a TCP connection "
		"to an HTTP/1.1 server via a TCP HTTP/2 proxy. (RFC7540 8.3)"),
	do_connect_cowboy(<<"http">>, tcp, http, <<"http">>, tcp).

connect_cowboy_https_via_h2c(_) ->
	doc("CONNECT can be used to establish a TLS connection "
		"to an HTTP/1.1 server via a TCP HTTP/2 proxy. (RFC7540 8.3)"),
	do_connect_cowboy(<<"https">>, tls, http, <<"http">>, tcp).

connect_cowboy_http_via_h2(_) ->
	doc("CONNECT can be used to establish a TCP connection "
		"to an HTTP/1.1 server via a TLS HTTP/2 proxy. (RFC7540 8.3)"),
	do_connect_cowboy(<<"http">>, tcp, http, <<"https">>, tls).

connect_cowboy_https_via_h2(_) ->
	doc("CONNECT can be used to establish a TLS connection "
		"to an HTTP/1.1 server via a TLS HTTP/2 proxy. (RFC7540 8.3)"),
	do_connect_cowboy(<<"https">>, tls, http, <<"https">>, tls).

connect_cowboy_h2c_via_h2c(_) ->
	doc("CONNECT can be used to establish a TCP connection "
		"to an HTTP/2 server via a TCP HTTP/2 proxy. (RFC7540 8.3)"),
	do_connect_cowboy(<<"http">>, tcp, http2, <<"http">>, tcp).

connect_cowboy_h2_via_h2c(_) ->
	doc("CONNECT can be used to establish a TLS connection "
		"to an HTTP/2 server via a TCP HTTP/2 proxy. (RFC7540 8.3)"),
	do_connect_cowboy(<<"https">>, tls, http2, <<"http">>, tcp).

connect_cowboy_h2c_via_h2(_) ->
	doc("CONNECT can be used to establish a TCP connection "
		"to an HTTP/2 server via a TLS HTTP/2 proxy. (RFC7540 8.3)"),
	do_connect_cowboy(<<"http">>, tcp, http2, <<"https">>, tls).

connect_cowboy_h2_via_h2(_) ->
	doc("CONNECT can be used to establish a TLS connection "
		"to an HTTP/2 server via a TLS HTTP/2 proxy. (RFC7540 8.3)"),
	do_connect_cowboy(<<"https">>, tls, http2, <<"https">>, tls).

do_connect_cowboy(_OriginScheme, OriginTransport, OriginProtocol, _ProxyScheme, ProxyTransport) ->
	{ok, Ref, OriginPort} = do_cowboy_origin(OriginTransport, OriginProtocol),
	try
		{ok, ProxyPid, ProxyPort} = do_proxy_start(ProxyTransport, [
			#proxy_stream{id=1, status=200},
			#proxy_stream{id=3, status=299}
		]),
		Authority = iolist_to_binary(["localhost:", integer_to_binary(OriginPort)]),
		{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
			transport => ProxyTransport,
			protocols => [http2]
		}),
		{ok, http2} = gun:await_up(ConnPid),
		handshake_completed = receive_from(ProxyPid),
		StreamRef = gun:connect(ConnPid, #{
			host => "localhost",
			port => OriginPort,
			transport => OriginTransport,
			protocols => [OriginProtocol]
		}),
		{request, #{
			<<":method">> := <<"CONNECT">>,
			<<":authority">> := Authority
		}} = receive_from(ProxyPid),
		{response, fin, 200, _} = gun:await(ConnPid, StreamRef),
		{up, OriginProtocol} = gun:await(ConnPid, StreamRef),
		ProxiedStreamRef = gun:get(ConnPid, "/proxied", #{}, #{tunnel => StreamRef}),
		timer:sleep(1000), %% @todo Why?
		{response, nofin, 200, _} = gun:await(ConnPid, ProxiedStreamRef),
		%% We can create more requests on the proxy as well.
		ProxyStreamRef = gun:get(ConnPid, "/"),
		{response, fin, 299, _} = gun:await(ConnPid, ProxyStreamRef),
		gun:close(ConnPid)
	after
		cowboy:stop_listener(Ref)
	end.

do_cowboy_origin(OriginTransport, OriginProtocol) ->
	Ref = make_ref(),
	ProtoOpts0 = case OriginTransport of
		tcp -> #{protocols => [OriginProtocol]};
		tls -> #{}
	end,
	ProtoOpts = ProtoOpts0#{
		env => #{dispatch => cowboy_router:compile([{'_', [
			{"/proxied/[...]", proxied_h, []}
		]}])}
	},
	[{ref, _}, {port, Port}] = case OriginTransport of
		tcp -> gun_test:init_cowboy_tcp(Ref, ProtoOpts, []);
		tls -> gun_test:init_cowboy_tls(Ref, ProtoOpts, [])
	end,
	{ok, Ref, Port}.

connect_handshake_timeout(_) ->
	doc("HTTP/2 timeouts are properly routed to the appropriate "
		"tunnel layer. (RFC7540 3.5, RFC7540 8.3)"),
	{ok, _, OriginPort} = init_origin(tcp, raw, fun(_, _, _) ->
		timer:sleep(5000)
	end),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(tcp, [
		#proxy_stream{id=1, status=200}
	]),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		protocols => [http2]
	}),
	{ok, http2} = gun:await_up(ConnPid),
	handshake_completed = receive_from(ProxyPid),
	StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		protocols => [{http2, #{preface_timeout => 500}}]
	}),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef),
	{up, http2} = gun:await(ConnPid, StreamRef),
	%% @todo The error should be normalized.
	%% @todo Do we want to indicate that a connection_error occurred within the tunnel stream?
	{error, {stream_error, {stream_error, protocol_error,
		'The preface was not received in a reasonable amount of time.'}}}
		= gun:await(ConnPid, StreamRef),
	gun:close(ConnPid).

connect_http_via_http_via_h2c(_) ->
	doc("CONNECT can be used to establish a TCP connection "
		"to an HTTP/1.1 server via a tunnel going through both "
		"a TCP HTTP/2 and a TCP HTTP/1.1 proxy. (RFC7540 8.3)"),
	do_connect_via_multiple_proxies(tcp, http, tcp, http, tcp).

connect_https_via_https_via_h2(_) ->
	doc("CONNECT can be used to establish a TLS connection "
		"to an HTTP/1.1 server via a tunnel going through both "
		"a TLS HTTP/2 and a TLS HTTP/1.1 proxy. (RFC7540 8.3)"),
	do_connect_via_multiple_proxies(tls, http, tls, http, tls).

do_connect_via_multiple_proxies(OriginTransport, OriginProtocol,
		Proxy2Transport, Proxy2Protocol, Proxy1Transport) ->
	{ok, Ref, OriginPort} = do_cowboy_origin(OriginTransport, OriginProtocol),
	try
		{ok, Proxy1Pid, Proxy1Port} = do_proxy_start(Proxy1Transport, [
			#proxy_stream{id=1, status=200}
		]),
		{ok, Proxy2Pid, Proxy2Port} = rfc7231_SUITE:do_proxy_start(Proxy2Transport),
		%% First proxy.
		{ok, ConnPid} = gun:open("localhost", Proxy1Port, #{
			transport => Proxy1Transport,
			protocols => [http2]
		}),
		{ok, http2} = gun:await_up(ConnPid),
		handshake_completed = receive_from(Proxy1Pid),
		%% Second proxy.
		StreamRef1 = gun:connect(ConnPid, #{
			host => "localhost",
			port => Proxy2Port,
			transport => Proxy2Transport,
			protocols => [Proxy2Protocol]
		}, []),
		Authority1 = iolist_to_binary(["localhost:", integer_to_binary(Proxy2Port)]),
		{request, #{
			<<":method">> := <<"CONNECT">>,
			<<":authority">> := Authority1
		}} = receive_from(Proxy1Pid),
		{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
		{up, Proxy2Protocol} = gun:await(ConnPid, StreamRef1),
		%% Origin.
		StreamRef2 = gun:connect(ConnPid, #{
			host => "localhost",
			port => OriginPort,
			transport => OriginTransport,
			protocols => [OriginProtocol]
		}, [], #{tunnel => StreamRef1}),
		Authority2 = iolist_to_binary(["localhost:", integer_to_binary(OriginPort)]),
		{request, <<"CONNECT">>, Authority2, 'HTTP/1.1', _} = receive_from(Proxy2Pid),
		{response, fin, 200, _} = gun:await(ConnPid, StreamRef2),
		{up, OriginProtocol} = gun:await(ConnPid, StreamRef2),
		%% Tunneled request to the origin.
		ProxiedStreamRef = gun:get(ConnPid, "/proxied", [], #{tunnel => StreamRef2}),
		{response, nofin, 200, _} = gun:await(ConnPid, ProxiedStreamRef),
		gun:close(ConnPid)
		%% @todo Also test stream_info.
	after
		cowboy:stop_listener(Ref)
	end.
