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

-ifdef(OTP_RELEASE).
-compile({nowarn_deprecated_function, [{ssl, ssl_accept, 2}]}).
-endif.

-import(ct_helper, [doc/1]).

all() ->
	ct_helper:all(?MODULE).

%% Server helpers. (Taken from rfc7231_SUITE.)

do_origin_start(Transport) ->
	do_origin_start(Transport, http).

do_origin_start(Transport, Protocol) ->
	Self = self(),
	Pid = spawn_link(fun() ->
		case Transport of
			tcp ->
				do_origin_init_tcp(Self);
			tls when Protocol =:= http ->
				do_origin_init_tls(Self);
			tls when Protocol =:= http2 ->
				do_origin_init_tls_h2(Self)
		end
	end),
	Port = do_receive(Pid),
	{ok, Pid, Port}.

do_origin_init_tcp(Parent) ->
	{ok, ListenSocket} = gen_tcp:listen(0, [binary, {active, false}]),
	{ok, {_, Port}} = inet:sockname(ListenSocket),
	Parent ! {self(), Port},
	{ok, ClientSocket} = gen_tcp:accept(ListenSocket, 5000),
	do_origin_loop(Parent, ClientSocket, gen_tcp).

do_origin_init_tls(Parent) ->
	Opts = ct_helper:get_certs_from_ets(),
	{ok, ListenSocket} = ssl:listen(0, [binary, {active, false}|Opts]),
	{ok, {_, Port}} = ssl:sockname(ListenSocket),
	Parent ! {self(), Port},
	{ok, ClientSocket} = ssl:transport_accept(ListenSocket, 5000),
	ok = ssl:ssl_accept(ClientSocket, 5000),
	do_origin_loop(Parent, ClientSocket, ssl).

do_origin_init_tls_h2(Parent) ->
	Opts = ct_helper:get_certs_from_ets(),
	{ok, ListenSocket} = ssl:listen(0, [binary, {active, false},
		{alpn_preferred_protocols, [<<"h2">>]}|Opts]),
	{ok, {_, Port}} = ssl:sockname(ListenSocket),
	Parent ! {self(), Port},
	{ok, ClientSocket} = ssl:transport_accept(ListenSocket, 5000),
	ok = ssl:ssl_accept(ClientSocket, 5000),
	{ok, <<"h2">>} = ssl:negotiated_protocol(ClientSocket),
	do_origin_loop(Parent, ClientSocket, ssl).

do_origin_loop(Parent, ClientSocket, ClientTransport) ->
	case ClientTransport:recv(ClientSocket, 0, 1000) of
		{ok, Data} ->
			Parent ! {self(), Data},
			do_origin_loop(Parent, ClientSocket, ClientTransport);
		{error, closed} ->
			ok
	end.

do_receive(Pid) ->
	do_receive(Pid, 1000).

do_receive(Pid, Timeout) ->
	receive
		{Pid, Msg} ->
			Msg
	after Timeout ->
		error(timeout)
	end.

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
	{ok, OriginPid, OriginPort} = do_origin_start(Transport, http),
	{ok, ConnPid} = gun:open("localhost", OriginPort, #{transport => Transport}),
	{ok, http} = gun:await_up(ConnPid),
	%% Change the origin's port in the state to trigger the default port behavior.
	_ = sys:replace_state(ConnPid, fun({StateName, StateData}) ->
		{StateName, setelement(7, StateData, DefaultPort)}
	end, 5000),
	%% Confirm the default port is not sent in the request.
	_ = gun:get(ConnPid, "/"),
	Data = do_receive(OriginPid),
	Lines = binary:split(Data, <<"\r\n">>, [global]),
	[<<"host: localhost", Rest/bits>>] = [L || <<"host: ", _/bits>> = L <- Lines],
	HostHeaderPort = Rest,
	gun:close(ConnPid).
