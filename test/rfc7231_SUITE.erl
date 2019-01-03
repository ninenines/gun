%% Copyright (c) 2018, Loïc Hoguin <essen@ninenines.eu>
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

do_proxy_start() ->
	do_proxy_start(200, []).

do_proxy_start(Status) ->
	do_proxy_start(Status, []).

do_proxy_start(Status, ConnectRespHeaders) ->
	do_proxy_start(Status, ConnectRespHeaders, 0).

do_proxy_start(Status, ConnectRespHeaders, Delay) ->
	Self = self(),
	Pid = spawn_link(fun() -> do_proxy_init(Self, Status, ConnectRespHeaders, Delay) end),
	Port = receive_from(Pid),
	{ok, Pid, Port}.

do_proxy_init(Parent, Status, ConnectRespHeaders, Delay) ->
	{ok, ListenSocket} = gen_tcp:listen(0, [binary, {active, false}]),
	{ok, {_, Port}} = inet:sockname(ListenSocket),
	Parent ! {self(), Port},
	{ok, ClientSocket} = gen_tcp:accept(ListenSocket, 1000),
	{ok, Data} = gen_tcp:recv(ClientSocket, 0, 1000),
	{Method= <<"CONNECT">>, Authority, Version, Rest} = cow_http:parse_request_line(Data),
	{Headers, <<>>} = cow_http:parse_headers(Rest),
	timer:sleep(Delay),
	Parent ! {self(), {request, Method, Authority, Version, Headers}},
	{OriginHost, OriginPort} = cow_http_hd:parse_host(Authority),
	ok = gen_tcp:send(ClientSocket, [
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
			inet:setopts(ClientSocket, [{active, true}]),
			inet:setopts(OriginSocket, [{active, true}]),
			do_proxy_loop(ClientSocket, OriginSocket);
		true ->
			%% We send a 501 to the subsequent request.
			{ok, _} = gen_tcp:recv(ClientSocket, 0, 1000),
			ok = gen_tcp:send(ClientSocket, <<
				"HTTP/1.1 501 Not Implemented\r\n"
				"content-length: 0\r\n\r\n">>),
			timer:sleep(2000)
	end.

do_proxy_loop(ClientSocket, OriginSocket) ->
	receive
		{tcp, ClientSocket, Data} ->
			ok = gen_tcp:send(OriginSocket, Data),
			do_proxy_loop(ClientSocket, OriginSocket);
		{tcp, OriginSocket, Data} ->
			ok = gen_tcp:send(ClientSocket, Data),
			do_proxy_loop(ClientSocket, OriginSocket);
		{tcp_closed, _} ->
			ok;
		Msg ->
			error(Msg)
	end.

%% Tests.

connect_http(_) ->
	doc("CONNECT can be used to establish a TCP connection "
		"to an HTTP/1.1 server via an HTTP proxy. (RFC7231 4.3.6)"),
	do_connect_http(tcp).

connect_https(_) ->
	doc("CONNECT can be used to establish a TLS connection "
		"to an HTTP/1.1 server via an HTTP proxy. (RFC7231 4.3.6)"),
	do_connect_http(tls).

do_connect_http(Transport) ->
	{ok, OriginPid, OriginPort} = init_origin(Transport, http),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(),
	Authority = iolist_to_binary(["localhost:", integer_to_binary(OriginPort)]),
	{ok, ConnPid} = gun:open("localhost", ProxyPort),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		transport => Transport
	}),
	{request, <<"CONNECT">>, Authority, 'HTTP/1.1', _} = receive_from(ProxyPid),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef),
	_ = gun:get(ConnPid, "/proxied"),
	Data = receive_from(OriginPid),
	Lines = binary:split(Data, <<"\r\n">>, [global]),
	[<<"host: ", Authority/bits>>] = [L || <<"host: ", _/bits>> = L <- Lines],
	#{
		transport := Transport,
		protocol := http,
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

connect_h2c(_) ->
	doc("CONNECT can be used to establish a TCP connection "
		"to an HTTP/2 server via an HTTP proxy. (RFC7231 4.3.6)"),
	do_connect_h2(tcp).

connect_h2(_) ->
	doc("CONNECT can be used to establish a TLS connection "
		"to an HTTP/2 server via an HTTP proxy. (RFC7231 4.3.6)"),
	do_connect_h2(tls).

do_connect_h2(Transport) ->
	{ok, OriginPid, OriginPort} = init_origin(Transport, http2),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(),
	Authority = iolist_to_binary(["localhost:", integer_to_binary(OriginPort)]),
	{ok, ConnPid} = gun:open("localhost", ProxyPort),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		transport => Transport,
		protocols => [http2]
	}),
	{request, <<"CONNECT">>, Authority, 'HTTP/1.1', _} = receive_from(ProxyPid),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef),
	timer:sleep(100), %% Give enough time for the handshake to fully complete.
	_ = gun:get(ConnPid, "/proxied"),
	<<_:24, 1:8, _/bits>> = receive_from(OriginPid),
	#{
		transport := Transport,
		protocol := http2,
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

connect_through_multiple_proxies(_) ->
	doc("CONNECT can be used to establish a TCP connection "
		"to an HTTP/1.1 server via a tunnel going through "
		"two separate HTTP proxies. (RFC7231 4.3.6)"),
	{ok, OriginPid, OriginPort} = init_origin(tcp),
	{ok, Proxy1Pid, Proxy1Port} = do_proxy_start(),
	{ok, Proxy2Pid, Proxy2Port} = do_proxy_start(),
	{ok, ConnPid} = gun:open("localhost", Proxy1Port),
	{ok, http} = gun:await_up(ConnPid),
	Authority1 = iolist_to_binary(["localhost:", integer_to_binary(Proxy2Port)]),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => Proxy2Port
	}),
	{request, <<"CONNECT">>, Authority1, 'HTTP/1.1', _} = receive_from(Proxy1Pid),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	Authority2 = iolist_to_binary(["localhost:", integer_to_binary(OriginPort)]),
	StreamRef2 = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort
	}),
	{request, <<"CONNECT">>, Authority2, 'HTTP/1.1', _} = receive_from(Proxy2Pid),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef2),
	_ = gun:get(ConnPid, "/proxied"),
	Data = receive_from(OriginPid),
	Lines = binary:split(Data, <<"\r\n">>, [global]),
	[<<"host: ", Authority2/bits>>] = [L || <<"host: ", _/bits>> = L <- Lines],
	#{
		transport := tcp,
		protocol := http,
		origin_host := "localhost",
		origin_port := OriginPort,
		intermediaries := [#{
			type := connect,
			host := "localhost",
			port := Proxy1Port,
			transport := tcp,
			protocol := http
		}, #{
			type := connect,
			host := "localhost",
			port := Proxy2Port,
			transport := tcp,
			protocol := http
	}]} = gun:info(ConnPid),
	gun:close(ConnPid).

connect_delay(_) ->
	doc("The CONNECT response may not be immediate."),
	{ok, OriginPid, OriginPort} = init_origin(tcp),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(201, [], 2000),
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
	_ = gun:get(ConnPid, "/proxied"),
	Data = receive_from(OriginPid),
	Lines = binary:split(Data, <<"\r\n">>, [global]),
	[<<"host: ", Authority/bits>>] = [L || <<"host: ", _/bits>> = L <- Lines],
	#{
		transport := tcp,
		protocol := http,
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
	{ok, ProxyPid, ProxyPort} = do_proxy_start(201),
	Authority = iolist_to_binary(["localhost:", integer_to_binary(OriginPort)]),
	{ok, ConnPid} = gun:open("localhost", ProxyPort),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort
	}),
	{request, <<"CONNECT">>, Authority, 'HTTP/1.1', _} = receive_from(ProxyPid),
	{response, fin, 201, _} = gun:await(ConnPid, StreamRef),
	_ = gun:get(ConnPid, "/proxied"),
	Data = receive_from(OriginPid),
	Lines = binary:split(Data, <<"\r\n">>, [global]),
	[<<"host: ", Authority/bits>>] = [L || <<"host: ", _/bits>> = L <- Lines],
	#{
		transport := tcp,
		protocol := http,
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
	{ok, ProxyPid, ProxyPort} = do_proxy_start(Status, Headers),
	Authority = iolist_to_binary(["localhost:", integer_to_binary(OriginPort)]),
	{ok, ConnPid} = gun:open("localhost", ProxyPort),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort
	}),
	{request, <<"CONNECT">>, Authority, 'HTTP/1.1', _} = receive_from(ProxyPid),
	{response, fin, Status, Headers} = gun:await(ConnPid, StreamRef),
	FailedStreamRef = gun:get(ConnPid, "/proxied"),
	{response, fin, 501, _} = gun:await(ConnPid, FailedStreamRef),
	#{
		transport := tcp,
		protocol := http,
		origin_host := "localhost",
		origin_port := ProxyPort,
		intermediaries := []
	} = gun:info(ConnPid),
	gun:close(ConnPid).

connect_authority_form(_) ->
	doc("CONNECT requests must use the authority-form. (RFC7231 4.3.6)"),
	{ok, _OriginPid, OriginPort} = init_origin(tcp),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(),
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
	{ok, ProxyPid, ProxyPort} = do_proxy_start(),
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
	{ok, ProxyPid, ProxyPort} = do_proxy_start(),
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
	{ok, ProxyPid, ProxyPort} = do_proxy_start(),
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
	{ok, ProxyPid, ProxyPort} = do_proxy_start(200, Headers),
	Authority = iolist_to_binary(["localhost:", integer_to_binary(OriginPort)]),
	{ok, ConnPid} = gun:open("localhost", ProxyPort),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort
	}),
	{request, <<"CONNECT">>, Authority, 'HTTP/1.1', _} = receive_from(ProxyPid),
	{response, fin, 200, Headers} = gun:await(ConnPid, StreamRef),
	_ = gun:get(ConnPid, "/proxied"),
	Data = receive_from(OriginPid),
	Lines = binary:split(Data, <<"\r\n">>, [global]),
	[<<"host: ", Authority/bits>>] = [L || <<"host: ", _/bits>> = L <- Lines],
	gun:close(ConnPid).

connect_response_ignore_content_length(_) ->
	doc("Clients must ignore content-length headers in responses "
		"to CONNECT requests. (RFC7231 4.3.6)"),
	{ok, OriginPid, OriginPort} = init_origin(tcp),
	Headers = [{<<"content-length">>, <<"1000">>}],
	{ok, ProxyPid, ProxyPort} = do_proxy_start(200, Headers),
	Authority = iolist_to_binary(["localhost:", integer_to_binary(OriginPort)]),
	{ok, ConnPid} = gun:open("localhost", ProxyPort),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort
	}),
	{request, <<"CONNECT">>, Authority, 'HTTP/1.1', _} = receive_from(ProxyPid),
	{response, fin, 200, Headers} = gun:await(ConnPid, StreamRef),
	_ = gun:get(ConnPid, "/proxied"),
	Data = receive_from(OriginPid),
	Lines = binary:split(Data, <<"\r\n">>, [global]),
	[<<"host: ", Authority/bits>>] = [L || <<"host: ", _/bits>> = L <- Lines],
	gun:close(ConnPid).
