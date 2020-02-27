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

-import(ct_helper, [doc/1]).

all() ->
	ct_helper:all(?MODULE).

%% Server helpers.

do_origin_start(Fun) ->
	Self = self(),
	Pid = spawn_link(fun() -> do_origin_init_tcp(Self, Fun) end),
	Port = do_receive(Pid),
	{ok, Pid, Port}.

do_origin_init_tcp(Parent, Fun) ->
	{ok, ListenSocket} = gen_tcp:listen(0, [binary, {active, false}]),
	{ok, {_, Port}} = inet:sockname(ListenSocket),
	Parent ! {self(), Port},
	{ok, ClientSocket} = gen_tcp:accept(ListenSocket, 5000),
	do_handshake(ClientSocket, gen_tcp),
	Fun(Parent, ClientSocket, gen_tcp).

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

do_init_origin(tcp, http, Fun) ->
	Self = self(),
	Pid = spawn_link(fun() -> do_init_origin_tcp(Self, Fun) end),
	Port = do_receive(Pid),
	{ok, Pid, Port}.

do_init_origin_tcp(Parent, Fun) ->
	{ok, ListenSocket} = gen_tcp:listen(0, [binary, {active, false}]),
	{ok, {_, Port}} = inet:sockname(ListenSocket),
	Parent ! {self(), Port},
	{ok, ClientSocket} = gen_tcp:accept(ListenSocket, 5000),
	%% No handshake.
	Fun(Parent, ClientSocket, gen_tcp).

%% Tests.

prior_knowledge_preface_garbage(_) ->
	doc("A PROTOCOL_ERROR connection error must result from the server sending "
		"an invalid preface in the form of garbage when connecting "
		"using the prior knowledge method. (RFC7540 3.4, RFC7540 3.5)"),
	%% We are going to do the handshake manually.
	{ok, _, Port} = do_init_origin(tcp, http, fun(_, Socket, Transport) ->
		ok = Transport:send(Socket, <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15>>),
		timer:sleep(100)
	end),
	{ok, ConnPid} = gun:open("localhost", Port, #{protocols => [http2]}),
	{ok, http2} = gun:await_up(ConnPid),
	receive
		{gun_down, ConnPid, http2, {error, {connection_error, protocol_error,
				'Invalid connection preface received. (RFC7540 3.5)'}}, [], []} ->
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
	%% We are going to do the handshake manually.
	{ok, _, Port} = do_init_origin(tcp, http, fun(_, Socket, Transport) ->
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
	receive
		{gun_down, ConnPid, http2, {error, {connection_error, protocol_error,
				'Invalid connection preface received. Appears to be an HTTP/1 response? (RFC7540 3.5)'}}, [], []} ->
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
	%% We are going to do the handshake manually.
	{ok, _, Port} = do_init_origin(tcp, http, fun(_, Socket, Transport) ->
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
	{error, {shutdown, {error, {connection_error, protocol_error,
		'Invalid connection preface received. Appears to be an HTTP/1 response? (RFC7540 3.5)'}}}}
		= gun:await(ConnPid, make_ref()),
	gun:close(ConnPid).

prior_knowledge_preface_other_frame(_) ->
	doc("A PROTOCOL_ERROR connection error must result from the server sending "
		"an invalid preface in the form of a non-SETTINGS frame when connecting "
		"using the prior knowledge method. (RFC7540 3.4, RFC7540 3.5)"),
	%% We are going to do the handshake manually.
	{ok, _, Port} = do_init_origin(tcp, http, fun(_, Socket, Transport) ->
		ok = Transport:send(Socket, cow_http2:window_update(1)),
		timer:sleep(100)
	end),
	{ok, ConnPid} = gun:open("localhost", Port, #{protocols => [http2]}),
	{ok, http2} = gun:await_up(ConnPid),
	receive
		{gun_down, ConnPid, http2, {error, {connection_error, protocol_error,
				'Invalid connection preface received. (RFC7540 3.5)'}}, [], []} ->
			gun:close(ConnPid);
		Msg ->
			error({unexpected_msg, Msg})
	after 1000 ->
		error(timeout)
	end.

headers_priority_flag(_) ->
	doc("HEADERS frames may include a PRIORITY flag indicating "
		"that stream dependency information is attached. (RFC7540 6.2)"),
	{ok, _, Port} = do_origin_start(fun(_, Socket, Transport) ->
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
