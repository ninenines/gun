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

-module(rfc7230_SUITE).
-compile(export_all).
-compile(nowarn_export_all).

-import(ct_helper, [doc/1]).
-import(gun_test, [init_origin/2]).
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
		{StateName, setelement(7, StateData, DefaultPort)}
	end, 5000),
	%% Confirm the default port is not sent in the request.
	_ = gun:get(ConnPid, "/"),
	Data = receive_from(OriginPid),
	Lines = binary:split(Data, <<"\r\n">>, [global]),
	[<<"host: localhost", Rest/bits>>] = [L || <<"host: ", _/bits>> = L <- Lines],
	HostHeaderPort = Rest,
	gun:close(ConnPid).
