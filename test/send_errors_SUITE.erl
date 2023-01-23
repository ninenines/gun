%% Copyright (c) 2020-2023, Björn Svensson <bjorn.a.svensson@est.tech>
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

-module(send_errors_SUITE).
-compile(export_all).
-compile(nowarn_export_all).

-import(ct_helper, [doc/1]).
-import(gun_test, [http2_handshake/2]).

suite() ->
	[{timetrap, 180000}].

all() ->
	[{group, gun}].

groups() ->
	[{gun, [parallel], ct_helper:all(?MODULE)}].

init_per_suite(Config) ->
	case os:type() of
		{_, linux} -> Config;
		_ -> {skip, "This test suite is Linux-only due to socket juggling."}
	end.

end_per_suite(_) -> ok.

%% Tests.

http2_send_request_fail(_) ->
	doc("Handle send failures of requests in HTTP/2."),
	{ok, ListenSocket} = gen_tcp:listen(0, [binary, {active, false}]),
	{ok, {_, Port}} = inet:sockname(ListenSocket),
	%% Socket buffers needs to be smaller than local_window/ConnWindow
	{ok, Pid} = gun:open("localhost", Port, #{
		protocols => [http2],
		tcp_opts => [
			{send_timeout, 250},
			{send_timeout_close, true},
			{sndbuf, 2048},
			{nodelay, true}
		]
	}),
	{ok, ClientSocket} = gen_tcp:accept(ListenSocket, 5000),
	inet:setopts(ClientSocket, [{recbuf, 512}]),
	http2_handshake(ClientSocket, gen_tcp),
	{ok, http2} = gun:await_up(Pid),
	post_loop(Pid, 1000), %% Fill buffer
	receive
		{gun_error, Pid, _, {closed, {error, _}}} ->
			gun:close(Pid);
		Msg ->
			error({fail, Msg})
	after 5000 ->
		error(timeout)
	end.

http2_send_ping_fail(_) ->
	doc("Handle send failures of ping in HTTP/2."),
	{ok, ListenSocket} = gen_tcp:listen(0, [binary, {active, false}]),
	{ok, {_, Port}} = inet:sockname(ListenSocket),
	{ok, Pid} = gun:open("localhost", Port, #{
		protocols => [http2],
		http2_opts => #{keepalive => 1},
		tcp_opts => [
			{send_timeout, 250},
			{send_timeout_close, true},
			{sndbuf, 256},
			{nodelay, true}
		]
	}),
	{ok, ClientSocket} = gen_tcp:accept(ListenSocket, 5000),
	inet:setopts(ClientSocket, [{recbuf, 256}]),
	http2_handshake(ClientSocket, gen_tcp),
	{ok, http2} = gun:await_up(Pid),
	receive
		{gun_down, Pid, http2, {error, _}, []} ->
			gun:close(Pid);
		Msg ->
			error({fail, Msg})
	after 5000 ->
		error(timeout)
	end.

http2_send_ping_ack_fail(_) ->
	doc("Handle send failures of ping ack in HTTP/2."),
	{ok, ListenSocket} = gen_tcp:listen(0, [binary, {active, false}]),
	{ok, {_, Port}} = inet:sockname(ListenSocket),
	{ok, Pid} = gun:open("localhost", Port, #{
		protocols => [http2],
		http2_opts => #{keepalive => infinity},
		tcp_opts => [
			{send_timeout, 250},
			{send_timeout_close, true},
			{sndbuf, 256},
			{nodelay, true}
		]
	}),
	{ok, ClientSocket} = gen_tcp:accept(ListenSocket, 5000),
	inet:setopts(ClientSocket, [{recbuf, 256}]),
	http2_handshake(ClientSocket, gen_tcp),
	{ok, http2} = gun:await_up(Pid),
	ping_loop(ClientSocket, 1800), %% Send pings triggering ping acks
	receive
		{gun_down, Pid, http2, {error, _}, []} ->
			gun:close(Pid);
		Msg ->
			error({fail, Msg})
	after 5000 ->
		error(timeout)
	end.

%% Helpers

post_loop(_Pid, 0) ->
	ok;
post_loop(Pid, Loops) ->
	Body = <<0:1000>>,
	gun:post(Pid, "/organizations/ninenines",
		[{<<"content-type">>, "application/octet-stream"}],
		Body),
	post_loop(Pid, Loops - 1).

ping_loop(_Socket, 0) ->
	ok;
ping_loop(Socket, Loops) ->
	gun_tcp:send(Socket, cow_http2:ping(0)),
	ping_loop(Socket, Loops - 1).
