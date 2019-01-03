%% Copyright (c) 2018-2019, Loïc Hoguin <essen@ninenines.eu>
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
-import(gun_test, [init_origin/3]).
-import(gun_test, [receive_from/1]).

all() ->
	ct_helper:all(?MODULE).

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
	%% Change the origin's port in the state to trigger the default port behavior.
	_ = sys:replace_state(ConnPid, fun({StateName, StateData}) ->
		{StateName, setelement(7, StateData, DefaultPort)}
	end, 5000),
	%% Confirm the default port is not sent in the request.
	timer:sleep(100), %% Give enough time for the handshake to fully complete.
	_ = gun:get(ConnPid, "/"),
	ReqHeaders = receive_from(OriginPid),
	{_, <<"localhost", Rest/bits>>} = lists:keyfind(<<":authority">>, 1, ReqHeaders),
	AuthorityHeaderPort = Rest,
	gun:close(ConnPid).

headers_priority_flag(_) ->
	doc("HEADERS frames may include a PRIORITY flag indicating "
		"that stream dependency information is attached. (RFC7540 6.2)"),
	{ok, _, Port} = init_origin(tcp, http2, fun(_, Socket, Transport) ->
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
