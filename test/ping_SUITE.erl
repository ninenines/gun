%% Copyright (c) Loïc Hoguin <essen@ninenines.eu>
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

-module(ping_SUITE).
-compile(export_all).
-compile(nowarn_export_all).

-import(ct_helper, [config/2]).
-import(ct_helper, [doc/1]).
-import(gun_test, [init_origin/3]).
-import(gun_test, [receive_from/1]).

all() ->
	ct_helper:all(?MODULE).

%% Tests.

h1_user_ping(Config0) ->
	doc("The PING frame cannot be used to test an HTTP/1.1 connection."),
	Config = gun_test:init_cowboy_tcp(?FUNCTION_NAME, #{}, Config0),
	OriginPort = config(port, Config),
	{ok, ConnPid} = gun:open("localhost", OriginPort, #{
		protocols => [http]
	}),
	{ok, http} = gun:await_up(ConnPid),
	PingRef = gun:ping(ConnPid),
	receive
		{gun_down, ConnPid, http, {error, {ping_unsupported_by_protocol, PingRef}}, []} ->
			gun:close(ConnPid)
	after 1000 ->
		ct:pal("~p", [process_info(self(), messages)]),
		error(timeout)
	end.

h2_user_ping(_) ->
	doc("The PING frame may be used to easily test an HTTP/2 connection."),
	{ok, OriginPid, OriginPort} = init_origin(tcp, http2, fun (_, _, Socket, Transport) ->
		{ok, Data} = Transport:recv(Socket, 9, infinity),
		<<Len:24, 6:8, %% PING
			0:8, %% Flags
			0:1, 0:31>> = Data,
		{ok, Payload} = Transport:recv(Socket, Len, 1000),
		8 = Len = byte_size(Payload),
		Ack = <<8:24, 6:8, %% PING
			1:8, %% Ack flag
			0:1, 0:31, Payload/binary>>,
		ok = Transport:send(Socket, Ack)
	end),
	{ok, ConnPid} = gun:open("localhost", OriginPort, #{
		protocols => [http2]
	}),
	{ok, http2} = gun:await_up(ConnPid),
	handshake_completed = receive_from(OriginPid),
	PingRef = gun:ping(ConnPid),
	{notify, ping_ack, PingRef} = gun:await(ConnPid, undefined),
	gun:close(ConnPid).

h2c_user_ping_via_http(_) ->
	doc("The PING frame may be used to easily test an HTTP/2 connection."),
	do_h2c_user_ping_tunnel(http).

h2c_user_ping_via_https(_) ->
	doc("The PING frame may be used to easily test an HTTP/2 connection."),
	do_h2c_user_ping_tunnel(https).

h2c_user_ping_via_h2c(_) ->
	doc("The PING frame may be used to easily test an HTTP/2 connection."),
	do_h2c_user_ping_tunnel(h2c).

h2c_user_ping_via_h2(_) ->
	doc("The PING frame may be used to easily test an HTTP/2 connection."),
	do_h2c_user_ping_tunnel(h2).

do_h2c_user_ping_tunnel(ProxyType) ->
	{ok, OriginPid, OriginPort} = init_origin(tcp, http2, fun (_, _, Socket, Transport) ->
		{ok, Data} = Transport:recv(Socket, 9, infinity),
		<<Len:24, 6:8, %% PING
			0:8, %% Flags
			0:1, 0:31>> = Data,
		{ok, Payload} = Transport:recv(Socket, Len, 1000),
		8 = Len = byte_size(Payload),
		Ack = <<8:24, 6:8, %% PING
			1:8, %% Ack flag
			0:1, 0:31, Payload/binary>>,
		ok = Transport:send(Socket, Ack)
	end),
	{ok, ProxyPid, ProxyPort} = tunnel_SUITE:do_proxy_start(ProxyType),
	{ProxyTransport, ProxyProtocol} = tunnel_SUITE:do_type(ProxyType),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		transport => ProxyTransport,
		tls_opts => [{verify, verify_none}, {versions, ['tlsv1.2']}],
		protocols => [ProxyProtocol]
	}),
	{ok, ProxyProtocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(ProxyProtocol, ProxyPid),
	StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		transport => tcp,
		protocols => [http2]
	}),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef),
	handshake_completed = receive_from(OriginPid),
	{up, http2} = gun:await(ConnPid, StreamRef),
	PingRef = gun:ping(ConnPid, #{tunnel => StreamRef}),
	{notify, ping_ack, PingRef} = gun:await(ConnPid, undefined),
	gun:close(ConnPid).
