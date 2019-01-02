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

-module(rfc7540_SUITE).
-compile(export_all).
-compile(nowarn_export_all).

-ifdef(OTP_RELEASE).
-compile({nowarn_deprecated_function, [{ssl, ssl_accept, 2}]}).
-endif.

-import(ct_helper, [doc/1]).

all() ->
	ct_helper:all(?MODULE).

%% Server helpers.

do_origin_start(Transport, Fun) ->
	Self = self(),
	Pid = spawn_link(fun() ->
		case Transport of
			tcp ->
				do_origin_init_tcp(Self, Fun);
			tls ->
				do_origin_init_tls_h2(Self, Fun)
		end
	end),
	Port = do_receive(Pid),
	{ok, Pid, Port}.

do_origin_init_tcp(Parent, Fun) ->
	{ok, ListenSocket} = gen_tcp:listen(0, [binary, {active, false}]),
	{ok, {_, Port}} = inet:sockname(ListenSocket),
	Parent ! {self(), Port},
	{ok, ClientSocket} = gen_tcp:accept(ListenSocket, 5000),
	do_handshake(ClientSocket, gen_tcp),
	Fun(Parent, ClientSocket, gen_tcp).

do_origin_init_tls_h2(Parent, Fun) ->
	Opts = ct_helper:get_certs_from_ets(),
	{ok, ListenSocket} = ssl:listen(0, [binary, {active, false},
		{alpn_preferred_protocols, [<<"h2">>]}|Opts]),
	{ok, {_, Port}} = ssl:sockname(ListenSocket),
	Parent ! {self(), Port},
	{ok, ClientSocket} = ssl:transport_accept(ListenSocket, 5000),
	ok = ssl:ssl_accept(ClientSocket, 5000),
	{ok, <<"h2">>} = ssl:negotiated_protocol(ClientSocket),
	do_handshake(ClientSocket, ssl),
	Fun(Parent, ClientSocket, ssl).

do_handshake(Socket, Transport) ->
	%% Send a valid preface.
	ok = Transport:send(Socket, cow_http2:settings(#{})),
	%% Receive the fixed sequence from the preface.
	Preface = <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>,
	{ok, Preface} = Transport:recv(Socket, byte_size(Preface), 5000),
	%% Receive the SETTINGS from the preface.
	{ok, <<Len:24>>} = Transport:recv(Socket, 3, 1000),
	{ok, <<4:8, 0:40, _:Len/binary>>} = Transport:recv(Socket, 6 + Len, 1000),
	%% Send the SETTINGS ack.
	ok = Transport:send(Socket, cow_http2:settings_ack()),
	%% Receive the SETTINGS ack.
	{ok, <<0:24, 4:8, 1:8, 0:32>>} = Transport:recv(Socket, 9, 1000),
	ok.

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

authority_default_port_http(_) ->
	doc("The default port for http should not be sent in "
		"the :authority pseudo-header. (RFC7540 3, RFC7230 2.7.1)"),
	do_authority_port(tcp, 80, <<>>).

authority_default_port_https(_) ->
	doc("The default port for https should not be sent in "
		"the :authority pseudo-header. (RFC7540 3, RFC7230 2.7.2)"),
	do_authority_port(tls, 443, <<>>).

authority_other_port_http(_) ->
	doc("Non-default ports for http must be sent in "
		"the :authority pseudo-header. (RFC7540 3, RFC7230 2.7.1)"),
	do_authority_port(tcp, 443, <<":443">>).

authority_other_port_https(_) ->
	doc("Non-default ports for https must be sent in "
		"the :authority pseudo-header. (RFC7540 3, RFC7230 2.7.2)"),
	do_authority_port(tls, 80, <<":80">>).

do_authority_port(Transport0, DefaultPort, AuthorityHeaderPort) ->
	{ok, OriginPid, OriginPort} = do_origin_start(Transport0, fun(Parent, Socket, Transport) ->
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
	%% Change the origin's port in the state to trigger the default port behavior.
	_ = sys:replace_state(ConnPid, fun({StateName, StateData}) ->
		{StateName, setelement(7, StateData, DefaultPort)}
	end, 5000),
	%% Confirm the default port is not sent in the request.
	timer:sleep(100), %% Give enough time for the handshake to fully complete.
	_ = gun:get(ConnPid, "/"),
	ReqHeaders = do_receive(OriginPid),
	{_, <<"localhost", Rest/bits>>} = lists:keyfind(<<":authority">>, 1, ReqHeaders),
	AuthorityHeaderPort = Rest,
	gun:close(ConnPid).

headers_priority_flag(_) ->
	doc("HEADERS frames may include a PRIORITY flag indicating "
		"that stream dependency information is attached. (RFC7540 6.2)"),
	{ok, _, Port} = do_origin_start(tcp, fun(_, Socket, Transport) ->
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
	timer:sleep(100), %% Give enough time for the handshake to fully complete.
	StreamRef = gun:get(ConnPid, "/"),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef),
	gun:close(ConnPid).
