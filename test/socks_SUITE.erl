%% Copyright (c) 2019, Loïc Hoguin <essen@ninenines.eu>
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

%% This test suite covers the following RFCs and specifications:
%%
%% * RFC 1928
%% * RFC 1929
%% * http://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4.protocol
%% * https://www.openssh.com/txt/socks4a.protocol

-module(socks_SUITE).
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

do_proxy_start(Transport0, Auth) ->
	Transport = case Transport0 of
		tcp -> gun_tcp;
		tls -> gun_tls
	end,
	Self = self(),
	Pid = spawn_link(fun() -> do_proxy_init(Self, Transport, Auth) end),
	Port = receive_from(Pid),
	{ok, Pid, Port}.

do_proxy_init(Parent, Transport, Auth) ->
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
			gen_tcp:accept(ListenSocket, 5000);
		gun_tls ->
			{ok, ClientSocket0} = ssl:transport_accept(ListenSocket, 5000),
			ssl:ssl_accept(ClientSocket0, 5000),
			{ok, ClientSocket0}
	end,
	Recv = case Transport of
		gun_tcp -> fun gen_tcp:recv/3;
		gun_tls -> fun ssl:recv/3
	end,
	%% Authentication method.
	{ok, <<5, NumAuths, Auths0/bits>>} = Recv(ClientSocket, 0, 1000),
	Auths = [case A of
		0 -> none;
		2 -> username_password
	end || <<A>> <= Auths0],
	Parent ! {self(), {auth_methods, NumAuths, Auths}},
	AuthMethod = do_auth_method(Auth),
	ok = case {AuthMethod, lists:member(AuthMethod, Auths)} of
		{none, true} ->
			Transport:send(ClientSocket, <<5, 0>>);
		{username_password, true} ->
			Transport:send(ClientSocket, <<5, 2>>),
			{ok, <<1, ULen, User:ULen/binary, PLen, Pass:PLen/binary>>} = Recv(ClientSocket, 0, 1000),
			Parent ! {self(), {username_password, User, Pass}},
			%% @todo Test errors too (byte 2).
			Transport:send(ClientSocket, <<1, 0>>);
		{_, false} ->
			%% @todo
			not_ok
	end,
	%% Connection request.
	{ok, <<5, 1, 0, AType, Rest/bits>>} = Recv(ClientSocket, 0, 1000),
	{OriginHost, OriginPort} = case AType of
		1 ->
			<<A, B, C, D, P:16>> = Rest,
			{{A, B, C, D}, P};
		3 ->
			<<L, H:L/binary, P:16>> = Rest,
			{H, P};
		4 ->
			<<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16, P:16>> = Rest,
			{{A, B, C, D, E, F, G, H}, P}
	end,
	Parent ! {self(), {connect, OriginHost, OriginPort}},
	%% @todo Test errors too (byte 2).
	%% @todo Configurable bound address.
	Transport:send(ClientSocket, <<5, 0, 0, 1, 1, 2, 3, 4, 33333:16>>),
	if
		true ->
			{ok, OriginSocket} = gen_tcp:connect(
				binary_to_list(OriginHost), OriginPort,
				[binary, {active, false}]),
			Transport:setopts(ClientSocket, [{active, true}]),
			inet:setopts(OriginSocket, [{active, true}]),
			do_proxy_loop(Transport, ClientSocket, OriginSocket)
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
		{tcp_closed, _} ->
			ok;
		{ssl_closed, _} ->
			ok;
		Msg ->
			error(Msg)
	end.

do_auth_method(none) -> none;
do_auth_method({username_password, _, _}) -> username_password.

%% Tests.

socks5_tcp_http_none(_) ->
	doc("Use Socks5 over TCP and without authentication to connect to an HTTP server."),
	do_socks5(<<"http">>, tcp, http, tcp, none).

socks5_tcp_http_username_password(_) ->
	doc("Use Socks5 over TCP and without authentication to connect to an HTTP server."),
	do_socks5(<<"http">>, tcp, http, tcp, {username_password, <<"user">>, <<"password">>}).

socks5_tcp_https_none(_) ->
	doc("Use Socks5 over TCP and without authentication to connect to an HTTPS server."),
	do_socks5(<<"https">>, tls, http, tcp, none).

socks5_tcp_https_username_password(_) ->
	doc("Use Socks5 over TCP and without authentication to connect to an HTTPS server."),
	do_socks5(<<"https">>, tls, http, tcp, {username_password, <<"user">>, <<"password">>}).

socks5_tls_http_none(_) ->
	doc("Use Socks5 over TLS and without authentication to connect to an HTTP server."),
	do_socks5(<<"http">>, tcp, http, tls, none).

socks5_tls_http_username_password(_) ->
	doc("Use Socks5 over TLS and without authentication to connect to an HTTP server."),
	do_socks5(<<"http">>, tcp, http, tls, {username_password, <<"user">>, <<"password">>}).

socks5_tls_https_none(_) ->
	doc("Use Socks5 over TLS and without authentication to connect to an HTTPS server."),
	do_socks5(<<"https">>, tls, http, tls, none).

socks5_tls_https_username_password(_) ->
	doc("Use Socks5 over TLS and without authentication to connect to an HTTPS server."),
	do_socks5(<<"https">>, tls, http, tls, {username_password, <<"user">>, <<"password">>}).

socks5_tcp_h2c_none(_) ->
	doc("Use Socks5 over TCP and without authentication to connect to an HTTP/2 server over TCP."),
	do_socks5(<<"http">>, tcp, http2, tcp, none).

socks5_tcp_h2c_username_password(_) ->
	doc("Use Socks5 over TCP and without authentication to connect to an HTTP/2 server over TCP."),
	do_socks5(<<"http">>, tcp, http2, tcp, {username_password, <<"user">>, <<"password">>}).

socks5_tcp_h2_none(_) ->
	doc("Use Socks5 over TCP and without authentication to connect to an HTTP/2 server over TLS."),
	do_socks5(<<"https">>, tls, http2, tcp, none).

socks5_tcp_h2_username_password(_) ->
	doc("Use Socks5 over TCP and without authentication to connect to an HTTP/2 server over TLS."),
	do_socks5(<<"https">>, tls, http2, tcp, {username_password, <<"user">>, <<"password">>}).

socks5_tls_h2c_none(_) ->
	doc("Use Socks5 over TLS and without authentication to connect to an HTTP/2 server over TCP."),
	do_socks5(<<"http">>, tcp, http2, tls, none).

socks5_tls_h2c_username_password(_) ->
	doc("Use Socks5 over TLS and without authentication to connect to an HTTP/2 server over TCP."),
	do_socks5(<<"http">>, tcp, http2, tls, {username_password, <<"user">>, <<"password">>}).

socks5_tls_h2_none(_) ->
	doc("Use Socks5 over TLS and without authentication to connect to an HTTP/2 server over TLS."),
	do_socks5(<<"https">>, tls, http2, tls, none).

socks5_tls_h2_username_password(_) ->
	doc("Use Socks5 over TLS and without authentication to connect to an HTTP/2 server over TLS."),
	do_socks5(<<"https">>, tls, http2, tls, {username_password, <<"user">>, <<"password">>}).

do_socks5(OriginScheme, OriginTransport, OriginProtocol, ProxyTransport, SocksAuth) ->
	{ok, OriginPid, OriginPort} = init_origin(OriginTransport, OriginProtocol),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(ProxyTransport, SocksAuth),
	Authority = iolist_to_binary(["localhost:", integer_to_binary(OriginPort)]),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		transport => ProxyTransport,
		protocols => [{socks, #{
			auth => [SocksAuth],
			host => "localhost",
			port => OriginPort,
			transport => OriginTransport,
			protocols => [OriginProtocol]
		}}]
	}),
	%% We receive a gun_up and a gun_socks_connected.
	{ok, socks} = gun:await_up(ConnPid),
	{ok, OriginProtocol} = gun:await_up(ConnPid),
	%% The proxy received two packets.
	AuthMethod = do_auth_method(SocksAuth),
	{auth_methods, 1, [AuthMethod]} = receive_from(ProxyPid),
	_ = case AuthMethod of
		none -> ok;
		username_password -> SocksAuth = receive_from(ProxyPid)
	end,
	{connect, <<"localhost">>, OriginPort} = receive_from(ProxyPid),
	handshake_completed = receive_from(OriginPid),
	_ = gun:get(ConnPid, "/proxied"),
	_ = case OriginProtocol of
		http ->
			Data = receive_from(OriginPid),
			Lines = binary:split(Data, <<"\r\n">>, [global]),
			[<<"host: ", Authority/bits>>] = [L || <<"host: ", _/bits>> = L <- Lines];
		http2 ->
			<<_:24, 1:8, _/bits>> = receive_from(OriginPid)
	end,
	#{
		transport := OriginTransport,
		protocol := OriginProtocol,
		origin_scheme := OriginScheme,
		origin_host := "localhost",
		origin_port := OriginPort,
		intermediaries := [#{
			type := socks5,
			host := "localhost",
			port := ProxyPort,
			transport := ProxyTransport,
			protocol := socks
	}]} = gun:info(ConnPid),
	gun:close(ConnPid).
