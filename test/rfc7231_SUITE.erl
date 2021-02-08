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

-module(rfc7231_SUITE).
-compile(export_all).
-compile(nowarn_export_all).

-import(ct_helper, [doc/1]).
-import(gun_test, [init_origin/1]).
-import(gun_test, [init_origin/2]).
-import(gun_test, [receive_from/1]).
-import(gun_test, [receive_from/2]).

all() ->
	ct_helper:all(?MODULE).

%% Proxy helpers.

do_proxy_start(Transport) ->
	do_proxy_start(Transport, 200, []).

do_proxy_start(Transport, Status) ->
	do_proxy_start(Transport, Status, []).

do_proxy_start(Transport, Status, ConnectRespHeaders) ->
	do_proxy_start(Transport, Status, ConnectRespHeaders, 0).

do_proxy_start(Transport0, Status, ConnectRespHeaders, Delay) ->
	Transport = case Transport0 of
		tcp -> gun_tcp;
		tls -> gun_tls
	end,
	Self = self(),
	Pid = spawn_link(fun() -> do_proxy_init(Self, Transport, Status, ConnectRespHeaders, Delay) end),
	Port = receive_from(Pid),
	{ok, Pid, Port}.

do_proxy_init(Parent, Transport, Status, ConnectRespHeaders, Delay) ->
	{ok, ListenSocket} = case Transport of
		gun_tcp ->
			gen_tcp:listen(0, [binary, {active, false}]);
		gun_tls ->
			Opts = ct_helper:get_certs_from_ets(),
			ssl:listen(0, [binary, {active, false}|Opts])
	end,
	{ok, {_, Port}} = Transport:sockname(ListenSocket),
	Parent ! {self(), Port},
	{ok, ClientSocket} = case Transport of
		gun_tcp ->
			gen_tcp:accept(ListenSocket, infinity);
		gun_tls ->
			{ok, ClientSocket0} = ssl:transport_accept(ListenSocket, infinity),
			{ok, ClientSocket1} = ssl:handshake(ClientSocket0, infinity),
			{ok, ClientSocket1}
	end,
	{ok, Data} = case Transport of
		gun_tcp ->
			gen_tcp:recv(ClientSocket, 0, infinity);
		gun_tls ->
			ssl:recv(ClientSocket, 0, infinity)
	end,
	{Method= <<"CONNECT">>, Authority, Version, Rest} = cow_http:parse_request_line(Data),
	{Headers, <<>>} = cow_http:parse_headers(Rest),
	timer:sleep(Delay),
	Parent ! {self(), {request, Method, Authority, Version, Headers}},
	{OriginHost, OriginPort} = cow_http_hd:parse_host(Authority),
	ok = Transport:send(ClientSocket, [
		<<"HTTP/1.1 ">>,
		integer_to_binary(Status),
		<<" Reason phrase\r\n">>,
		cow_http:headers(ConnectRespHeaders),
		<<"\r\n">>
	]),
	if
		Status >= 200, Status < 300 ->
			{ok, OriginSocket} = gen_tcp:connect(
				binary_to_list(OriginHost), OriginPort,
				[binary, {active, false}]),
			Transport:setopts(ClientSocket, [{active, true}]),
			inet:setopts(OriginSocket, [{active, true}]),
			do_proxy_loop(Transport, ClientSocket, OriginSocket);
		true ->
			timer:sleep(infinity)
	end.

do_proxy_loop(Transport, ClientSocket, OriginSocket) ->
	{OK, _, _} = Transport:messages(),
	receive
		{OK, ClientSocket, Data} ->
			case gen_tcp:send(OriginSocket, Data) of
				ok ->
					do_proxy_loop(Transport, ClientSocket, OriginSocket);
				{error, _} ->
					ok
			end;
		{tcp, OriginSocket, Data} ->
			case Transport:send(ClientSocket, Data) of
				ok ->
					do_proxy_loop(Transport, ClientSocket, OriginSocket);
				{error, _} ->
					ok
			end;
		%% Wait forever when a connection gets closed. We will exit with the test process.
		{tcp_closed, _} ->
			timer:sleep(infinity);
		{ssl_closed, _} ->
			timer:sleep(infinity);
		Msg ->
			error(Msg)
	end.

%% Tests.

connect_http(_) ->
	doc("CONNECT can be used to establish a TCP connection "
		"to an HTTP/1.1 server via an HTTP proxy. (RFC7231 4.3.6)"),
	do_connect_http(<<"http">>, tcp, tcp).

connect_https(_) ->
	doc("CONNECT can be used to establish a TLS connection "
		"to an HTTP/1.1 server via an HTTP proxy. (RFC7231 4.3.6)"),
	do_connect_http(<<"https">>, tls, tcp).

connect_http_over_https_proxy(_) ->
	doc("CONNECT can be used to establish a TCP connection "
		"to an HTTP/1.1 server via an HTTPS proxy. (RFC7231 4.3.6)"),
	do_connect_http(<<"http">>, tcp, tls).

connect_https_over_https_proxy(_) ->
	doc("CONNECT can be used to establish a TLS connection "
		"to an HTTP/1.1 server via an HTTPS proxy. (RFC7231 4.3.6)"),
	do_connect_http(<<"https">>, tls, tls).

do_connect_http(OriginScheme, OriginTransport, ProxyTransport) ->
	{ok, OriginPid, OriginPort} = init_origin(OriginTransport, http),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(ProxyTransport),
	Authority = iolist_to_binary(["localhost:", integer_to_binary(OriginPort)]),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{transport => ProxyTransport}),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		transport => OriginTransport
	}),
	{request, <<"CONNECT">>, Authority, 'HTTP/1.1', _} = receive_from(ProxyPid),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef),
	%% @todo Do we still need these handshake_completed messages?
	handshake_completed = receive_from(OriginPid),
	{up, http} = gun:await(ConnPid, StreamRef),
	_ = gun:get(ConnPid, "/proxied", [], #{tunnel => StreamRef}),
	Data = receive_from(OriginPid),
	Lines = binary:split(Data, <<"\r\n">>, [global]),
	[<<"host: ", Authority/bits>>] = [L || <<"host: ", _/bits>> = L <- Lines],
	#{
		transport := OriginTransport,
		protocol := http,
		origin_scheme := OriginScheme,
		origin_host := "localhost",
		origin_port := OriginPort,
		intermediaries := [#{
			type := connect,
			host := "localhost",
			port := ProxyPort,
			transport := ProxyTransport,
			protocol := http
	}]} = gun:info(ConnPid),
	gun:close(ConnPid).

connect_h2c(_) ->
	doc("CONNECT can be used to establish a TCP connection "
		"to an HTTP/2 server via an HTTP proxy. (RFC7231 4.3.6)"),
	do_connect_h2(<<"http">>, tcp, tcp).

connect_h2(_) ->
	doc("CONNECT can be used to establish a TLS connection "
		"to an HTTP/2 server via an HTTP proxy. (RFC7231 4.3.6)"),
	do_connect_h2(<<"https">>, tls, tcp).

connect_h2c_over_https_proxy(_) ->
	doc("CONNECT can be used to establish a TCP connection "
		"to an HTTP/2 server via an HTTPS proxy. (RFC7231 4.3.6)"),
	do_connect_h2(<<"http">>, tcp, tls).

connect_h2_over_https_proxy(_) ->
	doc("CONNECT can be used to establish a TLS connection "
		"to an HTTP/2 server via an HTTPS proxy. (RFC7231 4.3.6)"),
	do_connect_h2(<<"https">>, tls, tls).

do_connect_h2(OriginScheme, OriginTransport, ProxyTransport) ->
	{ok, OriginPid, OriginPort} = init_origin(OriginTransport, http2),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(ProxyTransport),
	Authority = iolist_to_binary(["localhost:", integer_to_binary(OriginPort)]),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{transport => ProxyTransport}),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		transport => OriginTransport,
		protocols => [http2]
	}),
	{request, <<"CONNECT">>, Authority, 'HTTP/1.1', _} = receive_from(ProxyPid),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef),
	handshake_completed = receive_from(OriginPid),
	{up, http2} = gun:await(ConnPid, StreamRef),
	_ = gun:get(ConnPid, "/proxied", [], #{tunnel => StreamRef}),
	<<_:24, 1:8, _/bits>> = receive_from(OriginPid),
	#{
		transport := OriginTransport,
		protocol := http2,
		origin_scheme := OriginScheme,
		origin_host := "localhost",
		origin_port := OriginPort,
		intermediaries := [#{
			type := connect,
			host := "localhost",
			port := ProxyPort,
			transport := ProxyTransport,
			protocol := http
	}]} = gun:info(ConnPid),
	gun:close(ConnPid).

connect_tcp_through_multiple_tcp_proxies(_) ->
	doc("CONNECT can be used to establish a TCP connection "
		"to an HTTP/1.1 server via a tunnel going through "
		"two separate HTTP proxies. (RFC7231 4.3.6)"),
	do_connect_through_multiple_proxies(<<"http">>, tcp, tcp).

connect_tls_through_multiple_tls_proxies(_) ->
	doc("CONNECT can be used to establish a TLS connection "
		"to an HTTP/1.1 server via a tunnel going through "
		"two separate HTTPS proxies. (RFC7231 4.3.6)"),
	do_connect_through_multiple_proxies(<<"https">>, tls, tls).

do_connect_through_multiple_proxies(OriginScheme, OriginTransport, ProxiesTransport) ->
	{ok, OriginPid, OriginPort} = init_origin(OriginTransport),
	{ok, Proxy1Pid, Proxy1Port} = do_proxy_start(ProxiesTransport),
	{ok, Proxy2Pid, Proxy2Port} = do_proxy_start(ProxiesTransport),
	{ok, ConnPid} = gun:open("localhost", Proxy1Port, #{
		transport => ProxiesTransport
	}),
	{ok, http} = gun:await_up(ConnPid),
	Authority1 = iolist_to_binary(["localhost:", integer_to_binary(Proxy2Port)]),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => Proxy2Port,
		transport => ProxiesTransport
	}),
	{request, <<"CONNECT">>, Authority1, 'HTTP/1.1', _} = receive_from(Proxy1Pid),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{up, http} = gun:await(ConnPid, StreamRef1),
	Authority2 = iolist_to_binary(["localhost:", integer_to_binary(OriginPort)]),
	StreamRef2 = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		transport => OriginTransport
	}, [], #{tunnel => StreamRef1}),
	{request, <<"CONNECT">>, Authority2, 'HTTP/1.1', _} = receive_from(Proxy2Pid),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef2),
	handshake_completed = receive_from(OriginPid),
	{up, http} = gun:await(ConnPid, StreamRef2),
	_ = gun:get(ConnPid, "/proxied", [], #{tunnel => StreamRef2}),
	Data = receive_from(OriginPid),
	Lines = binary:split(Data, <<"\r\n">>, [global]),
	[<<"host: ", Authority2/bits>>] = [L || <<"host: ", _/bits>> = L <- Lines],
	#{
		transport := OriginTransport,
		protocol := http,
		origin_scheme := OriginScheme,
		origin_host := "localhost",
		origin_port := OriginPort,
		intermediaries := [#{
			type := connect,
			host := "localhost",
			port := Proxy1Port,
			transport := ProxiesTransport,
			protocol := http
		}, #{
			type := connect,
			host := "localhost",
			port := Proxy2Port,
			transport := ProxiesTransport,
			protocol := http
	}]} = gun:info(ConnPid),
	gun:close(ConnPid).

connect_delay(_) ->
	doc("The CONNECT response may not be immediate."),
	{ok, OriginPid, OriginPort} = init_origin(tcp),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(tcp, 201, [], 2000),
	Authority = iolist_to_binary(["localhost:", integer_to_binary(OriginPort)]),
	{ok, ConnPid} = gun:open("localhost", ProxyPort,
		#{http_opts => #{keepalive => 1000}}),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort
	}),
	{request, <<"CONNECT">>, Authority, 'HTTP/1.1', _} = receive_from(ProxyPid, 3000),
	{response, fin, 201, _} = gun:await(ConnPid, StreamRef),
	handshake_completed = receive_from(OriginPid),
	{up, http} = gun:await(ConnPid, StreamRef),
	_ = gun:get(ConnPid, "/proxied", [], #{tunnel => StreamRef}),
	Data = receive_from(OriginPid),
	Lines = binary:split(Data, <<"\r\n">>, [global]),
	[<<"host: ", Authority/bits>>] = [L || <<"host: ", _/bits>> = L <- Lines],
	#{
		transport := tcp,
		protocol := http,
		origin_scheme := <<"http">>,
		origin_host := "localhost",
		origin_port := OriginPort,
		intermediaries := [#{
			type := connect,
			host := "localhost",
			port := ProxyPort,
			transport := tcp,
			protocol := http
	}]} = gun:info(ConnPid),
	gun:close(ConnPid).

connect_response_201(_) ->
	doc("2xx responses to CONNECT requests indicate "
		"the tunnel was set up successfully. (RFC7231 4.3.6)"),
	{ok, OriginPid, OriginPort} = init_origin(tcp),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(tcp, 201),
	Authority = iolist_to_binary(["localhost:", integer_to_binary(OriginPort)]),
	{ok, ConnPid} = gun:open("localhost", ProxyPort),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort
	}),
	{request, <<"CONNECT">>, Authority, 'HTTP/1.1', _} = receive_from(ProxyPid),
	{response, fin, 201, _} = gun:await(ConnPid, StreamRef),
	handshake_completed = receive_from(OriginPid),
	{up, http} = gun:await(ConnPid, StreamRef),
	_ = gun:get(ConnPid, "/proxied", [], #{tunnel => StreamRef}),
	Data = receive_from(OriginPid),
	Lines = binary:split(Data, <<"\r\n">>, [global]),
	[<<"host: ", Authority/bits>>] = [L || <<"host: ", _/bits>> = L <- Lines],
	#{
		transport := tcp,
		protocol := http,
		origin_scheme := <<"http">>,
		origin_host := "localhost",
		origin_port := OriginPort,
		intermediaries := [#{
			type := connect,
			host := "localhost",
			port := ProxyPort,
			transport := tcp,
			protocol := http
	}]} = gun:info(ConnPid),
	gun:close(ConnPid).

connect_response_302(_) ->
	doc("3xx responses to CONNECT requests indicate "
		"the tunnel was not set up. (RFC7231 4.3.6)"),
	do_connect_failure(302).

connect_response_403(_) ->
	doc("4xx responses to CONNECT requests indicate "
		"the tunnel was not set up. (RFC7231 4.3.6)"),
	do_connect_failure(403).

connect_response_500(_) ->
	doc("5xx responses to CONNECT requests indicate "
		"the tunnel was not set up. (RFC7231 4.3.6)"),
	do_connect_failure(500).

do_connect_failure(Status) ->
	OriginPort = 33333, %% Doesn't matter because we won't try to connect.
	Headers = [{<<"content-length">>, <<"0">>}],
	{ok, ProxyPid, ProxyPort} = do_proxy_start(tcp, Status, Headers),
	Authority = iolist_to_binary(["localhost:", integer_to_binary(OriginPort)]),
	{ok, ConnPid} = gun:open("localhost", ProxyPort),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort
	}),
	{request, <<"CONNECT">>, Authority, 'HTTP/1.1', _} = receive_from(ProxyPid),
	{response, fin, Status, Headers} = gun:await(ConnPid, StreamRef),
	%% We cannot do a request because the StreamRef is not a tunnel.
	FailedStreamRef = gun:get(ConnPid, "/proxied", [], #{tunnel => StreamRef}),
	{error, {stream_error, {badstate, _}}} = gun:await(ConnPid, FailedStreamRef),
	#{
		transport := tcp,
		protocol := http,
		origin_scheme := <<"http">>,
		origin_host := "localhost",
		origin_port := ProxyPort,
		intermediaries := []
	} = gun:info(ConnPid),
	gun:close(ConnPid).

connect_authority_form(_) ->
	doc("CONNECT requests must use the authority-form. (RFC7231 4.3.6)"),
	{ok, _OriginPid, OriginPort} = init_origin(tcp),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(tcp),
	Authority = iolist_to_binary(["localhost:", integer_to_binary(OriginPort)]),
	{ok, ConnPid} = gun:open("localhost", ProxyPort),
	{ok, http} = gun:await_up(ConnPid),
	_StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort
	}),
	{request, <<"CONNECT">>, Authority, 'HTTP/1.1', _} = receive_from(ProxyPid),
	{<<"localhost">>, OriginPort} = cow_http_hd:parse_host(Authority),
	gun:close(ConnPid).

connect_proxy_authorization(_) ->
	doc("CONNECT requests may include a proxy-authorization header. (RFC7231 4.3.6)"),
	{ok, _OriginPid, OriginPort} = init_origin(tcp),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(tcp),
	Authority = iolist_to_binary(["localhost:", integer_to_binary(OriginPort)]),
	{ok, ConnPid} = gun:open("localhost", ProxyPort),
	{ok, http} = gun:await_up(ConnPid),
	_StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		username => "essen",
		password => "myrealpasswordis"
	}),
	{request, <<"CONNECT">>, Authority, 'HTTP/1.1', Headers} = receive_from(ProxyPid),
	{_, ProxyAuthorization} = lists:keyfind(<<"proxy-authorization">>, 1, Headers),
	{basic, <<"essen">>, <<"myrealpasswordis">>}
		= cow_http_hd:parse_proxy_authorization(ProxyAuthorization),
	gun:close(ConnPid).

connect_request_no_transfer_encoding(_) ->
	doc("The payload for CONNECT requests has no defined semantics. "
		"The transfer-encoding header should not be sent. (RFC7231 4.3.6)"),
	{ok, _OriginPid, OriginPort} = init_origin(tcp),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(tcp),
	Authority = iolist_to_binary(["localhost:", integer_to_binary(OriginPort)]),
	{ok, ConnPid} = gun:open("localhost", ProxyPort),
	{ok, http} = gun:await_up(ConnPid),
	_StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort
	}),
	{request, <<"CONNECT">>, Authority, 'HTTP/1.1', Headers} = receive_from(ProxyPid),
	false = lists:keyfind(<<"transfer-encoding">>, 1, Headers),
	gun:close(ConnPid).

connect_request_no_content_length(_) ->
	doc("The payload for CONNECT requests has no defined semantics. "
		"The content-length header should not be sent. (RFC7231 4.3.6)"),
	{ok, _OriginPid, OriginPort} = init_origin(tcp),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(tcp),
	Authority = iolist_to_binary(["localhost:", integer_to_binary(OriginPort)]),
	{ok, ConnPid} = gun:open("localhost", ProxyPort),
	{ok, http} = gun:await_up(ConnPid),
	_StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort
	}),
	{request, <<"CONNECT">>, Authority, 'HTTP/1.1', Headers} = receive_from(ProxyPid),
	false = lists:keyfind(<<"content-length">>, 1, Headers),
	gun:close(ConnPid).

connect_response_ignore_transfer_encoding(_) ->
	doc("Clients must ignore transfer-encoding headers in responses "
		"to CONNECT requests. (RFC7231 4.3.6)"),
	{ok, OriginPid, OriginPort} = init_origin(tcp),
	Headers = [{<<"transfer-encoding">>, <<"chunked">>}],
	{ok, ProxyPid, ProxyPort} = do_proxy_start(tcp, 200, Headers),
	Authority = iolist_to_binary(["localhost:", integer_to_binary(OriginPort)]),
	{ok, ConnPid} = gun:open("localhost", ProxyPort),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort
	}),
	{request, <<"CONNECT">>, Authority, 'HTTP/1.1', _} = receive_from(ProxyPid),
	{response, fin, 200, Headers} = gun:await(ConnPid, StreamRef),
	handshake_completed = receive_from(OriginPid),
	{up, http} = gun:await(ConnPid, StreamRef),
	_ = gun:get(ConnPid, "/proxied", [], #{tunnel => StreamRef}),
	Data = receive_from(OriginPid),
	Lines = binary:split(Data, <<"\r\n">>, [global]),
	[<<"host: ", Authority/bits>>] = [L || <<"host: ", _/bits>> = L <- Lines],
	gun:close(ConnPid).

connect_response_ignore_content_length(_) ->
	doc("Clients must ignore content-length headers in responses "
		"to CONNECT requests. (RFC7231 4.3.6)"),
	{ok, OriginPid, OriginPort} = init_origin(tcp),
	Headers = [{<<"content-length">>, <<"1000">>}],
	{ok, ProxyPid, ProxyPort} = do_proxy_start(tcp, 200, Headers),
	Authority = iolist_to_binary(["localhost:", integer_to_binary(OriginPort)]),
	{ok, ConnPid} = gun:open("localhost", ProxyPort),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort
	}),
	{request, <<"CONNECT">>, Authority, 'HTTP/1.1', _} = receive_from(ProxyPid),
	{response, fin, 200, Headers} = gun:await(ConnPid, StreamRef),
	handshake_completed = receive_from(OriginPid),
	{up, http} = gun:await(ConnPid, StreamRef),
	_ = gun:get(ConnPid, "/proxied", [], #{tunnel => StreamRef}),
	Data = receive_from(OriginPid),
	Lines = binary:split(Data, <<"\r\n">>, [global]),
	[<<"host: ", Authority/bits>>] = [L || <<"host: ", _/bits>> = L <- Lines],
	gun:close(ConnPid).
