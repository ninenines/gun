%% Copyright (c) 2019-2020, Loïc Hoguin <essen@ninenines.eu>
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

-module(rfc7230_SUITE).
-compile(export_all).
-compile(nowarn_export_all).

-import(ct_helper, [doc/1]).
-import(gun_test, [init_origin/2]).
-import(gun_test, [init_origin/3]).
-import(gun_test, [receive_from/1]).

all() ->
	ct_helper:all(?MODULE).

%% Tests.

host_default_port_http(_) ->
	doc("The default port for http should not be sent in the host header. (RFC7230 2.7.1)"),
	do_host_port(tcp, 80, <<>>).

host_default_port_https(_) ->
	doc("The default port for https should not be sent in the host header. (RFC7230 2.7.2)"),
	do_host_port(tls, 443, <<>>).

host_ipv6(_) ->
	doc("When connecting to a server using an IPv6 address the host "
		"header must wrap the address with brackets. (RFC7230 5.4, RFC3986 3.2.2)"),
	{ok, OriginPid, OriginPort} = init_origin(tcp6, http),
	{ok, ConnPid} = gun:open({0,0,0,0,0,0,0,1}, OriginPort, #{transport => tcp}),
	{ok, http} = gun:await_up(ConnPid),
	_ = gun:get(ConnPid, "/"),
	handshake_completed = receive_from(OriginPid),
	Data = receive_from(OriginPid),
	Lines = binary:split(Data, <<"\r\n">>, [global]),
	[<<"host: [::1]", _/bits>>] = [L || <<"host: ", _/bits>> = L <- Lines],
	gun:close(ConnPid).

host_other_port_http(_) ->
	doc("Non-default ports for http must be sent in the host header. (RFC7230 2.7.1)"),
	do_host_port(tcp, 443, <<":443">>).

host_other_port_https(_) ->
	doc("Non-default ports for https must be sent in the host header. (RFC7230 2.7.2)"),
	do_host_port(tls, 80, <<":80">>).

do_host_port(Transport, DefaultPort, HostHeaderPort) ->
	{ok, OriginPid, OriginPort} = init_origin(Transport, http),
	{ok, ConnPid} = gun:open("localhost", OriginPort, #{transport => Transport}),
	{ok, http} = gun:await_up(ConnPid),
	%% Change the origin's port in the state to trigger the default port behavior.
	_ = sys:replace_state(ConnPid, fun({StateName, StateData}) ->
		{StateName, setelement(8, StateData, DefaultPort)}
	end, 5000),
	%% Confirm the default port is not sent in the request.
	_ = gun:get(ConnPid, "/"),
	handshake_completed = receive_from(OriginPid),
	Data = receive_from(OriginPid),
	Lines = binary:split(Data, <<"\r\n">>, [global]),
	[<<"host: localhost", Rest/bits>>] = [L || <<"host: ", _/bits>> = L <- Lines],
	HostHeaderPort = Rest,
	gun:close(ConnPid).

transfer_encoding_overrides_content_length(_) ->
	doc("When both transfer-encoding and content-length are provided, "
		"content-length must be ignored. (RFC7230 3.3.3)"),
	{ok, _, OriginPort} = init_origin(tcp, http,
		fun(_, ClientSocket, ClientTransport) ->
			{ok, _} = ClientTransport:recv(ClientSocket, 0, 1000),
			ClientTransport:send(ClientSocket,
				"HTTP/1.1 200 OK\r\n"
				"content-length: 12\r\n"
				"transfer-encoding: chunked\r\n"
				"\r\n"
				"6\r\n"
				"hello \r\n"
				"6\r\n"
				"world!\r\n"
				"0\r\n\r\n"
			)
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:get(ConnPid, "/"),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
	{ok, <<"hello world!">>} = gun:await_body(ConnPid, StreamRef),
	gun:close(ConnPid).
