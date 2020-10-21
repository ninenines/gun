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

-module(shutdown_SUITE).
-compile(export_all).
-compile(nowarn_export_all).

-import(ct_helper, [doc/1]).
-import(ct_helper, [config/2]).
-import(gun_test, [init_origin/3]).
-import(gun_test, [receive_from/1]).

suite() ->
	[{timetrap, 30000}].

all() ->
	[{group, shutdown}].

groups() ->
	[{shutdown, [parallel], ct_helper:all(?MODULE)}].

init_per_suite(Config) ->
	ProtoOpts = #{env => #{
		dispatch => cowboy_router:compile([{'_', [
			{"/", hello_h, []},
			{"/delayed", delayed_hello_h, 500},
			{"/delayed_push", delayed_push_h, 500},
			{"/empty", empty_h, []},
			{"/ws", ws_echo_h, []},
			{"/ws_frozen", ws_frozen_h, 500},
			%% This timeout determines how long the test suite will run.
			{"/ws_frozen_long", ws_frozen_h, 1500},
			{"/ws_timeout_close", ws_timeout_close_h, 500}
		]}])
	}},
	{ok, _} = cowboy:start_clear(?MODULE, [], ProtoOpts),
	OriginPort = ranch:get_port(?MODULE),
	[{origin_port, OriginPort}|Config].

end_per_suite(_) ->
	ok = cowboy:stop_listener(?MODULE).

%% Tests.
%%
%% This test suite checks that the various ways to shut down
%% the connection are all working as expected for the different
%% protocols and scenarios.

not_connected_gun_shutdown(_) ->
	doc("Confirm that the Gun process shuts down gracefully "
		"when calling gun:shutdown/1 while it isn't connected."),
	{ok, ConnPid} = gun:open("localhost", 12345),
	ConnRef = monitor(process, ConnPid),
	gun:shutdown(ConnPid),
	gun_is_down(ConnPid, ConnRef, shutdown).

not_connected_owner_down(_) ->
	doc("Confirm that the Gun process shuts down when the owner exits normally "
		"while it isn't connected."),
	do_not_connected_owner_down(normal, normal).

not_connected_owner_down_error(_) ->
	doc("Confirm that the Gun process shuts down when the owner exits with an error "
		"while it isn't connected."),
	do_not_connected_owner_down(unexpected, {shutdown, {owner_down, unexpected}}).

do_not_connected_owner_down(ExitReason, DownReason) ->
	Self = self(),
	spawn(fun() ->
		{ok, ConnPid} = gun:open("localhost", 12345),
		Self ! {conn, ConnPid},
		timer:sleep(500),
		exit(ExitReason)
	end),
	ConnPid = receive {conn, C} -> C end,
	ConnRef = monitor(process, ConnPid),
	gun_is_down(ConnPid, ConnRef, DownReason).

http1_gun_shutdown_no_streams(Config) ->
	doc("HTTP/1.1: Confirm that the Gun process shuts down gracefully "
		"when calling gun:shutdown/1 with no active streams."),
	do_http_gun_shutdown_no_streams(Config, http).

do_http_gun_shutdown_no_streams(Config, Protocol) ->
	{ok, ConnPid} = gun:open("localhost", config(origin_port, Config), #{
		protocols => [Protocol]
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	ConnRef = monitor(process, ConnPid),
	gun:shutdown(ConnPid),
	gun_is_down(ConnPid, ConnRef, shutdown).

http1_gun_shutdown_one_stream(Config) ->
	doc("HTTP/1.1: Confirm that the Gun process shuts down gracefully "
		"when calling gun:shutdown/1 with one active stream."),
	do_http_gun_shutdown_one_stream(Config, http).

do_http_gun_shutdown_one_stream(Config, Protocol) ->
	{ok, ConnPid} = gun:open("localhost", config(origin_port, Config), #{
		protocols => [Protocol]
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	ConnRef = monitor(process, ConnPid),
	StreamRef = gun:get(ConnPid, "/delayed"),
	gun:shutdown(ConnPid),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
	{ok, _} = gun:await_body(ConnPid, StreamRef),
	gun_is_down(ConnPid, ConnRef, shutdown).

http1_gun_shutdown_pipelined_streams(Config) ->
	doc("HTTP/1.1: Confirm that the Gun process shuts down gracefully "
		"when calling gun:shutdown/1 with one active stream and additional pipelined streams."),
	Protocol = http,
	{ok, ConnPid} = gun:open("localhost", config(origin_port, Config), #{
		protocols => [Protocol]
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	ConnRef = monitor(process, ConnPid),
	StreamRef1 = gun:get(ConnPid, "/delayed"),
	StreamRef2 = gun:get(ConnPid, "/delayed"),
	StreamRef3 = gun:get(ConnPid, "/delayed"),
	gun:shutdown(ConnPid),
	%% Pipelined streams are canceled immediately.
	{error, {stream_error, {closing, shutdown}}} = gun:await(ConnPid, StreamRef2),
	{error, {stream_error, {closing, shutdown}}} = gun:await(ConnPid, StreamRef3),
	%% The active stream is still processed.
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef1),
	{ok, _} = gun:await_body(ConnPid, StreamRef1),
	gun_is_down(ConnPid, ConnRef, shutdown).

http1_gun_shutdown_timeout(Config) ->
	doc("HTTP/1.1: Confirm that the Gun process shuts down when the closing_timeout "
		"triggers after calling gun:shutdown/1 with one active stream."),
	do_http_gun_shutdown_timeout(Config, http, http_opts).

do_http_gun_shutdown_timeout(Config, Protocol, ProtoOpts) ->
	{ok, ConnPid} = gun:open("localhost", config(origin_port, Config), #{
		ProtoOpts => #{closing_timeout => 100},
		protocols => [Protocol]
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	ConnRef = monitor(process, ConnPid),
	StreamRef = gun:get(ConnPid, "/delayed"),
	gun:shutdown(ConnPid),
	%% The closing timeout occurs before the server gets to send the response.
	%% We get a 'closed' error instead of 'closing' as a result.
	{error, {stream_error, {closed, shutdown}}} = gun:await(ConnPid, StreamRef),
	gun_is_down(ConnPid, ConnRef, shutdown).

http1_owner_down(Config) ->
	doc("HTTP/1.1: Confirm that the Gun process shuts down when the owner exits normally."),
	do_http_owner_down(Config, http, normal, normal).

http1_owner_down_error(Config) ->
	doc("HTTP/1.1: Confirm that the Gun process shuts down when the owner exits with an error."),
	do_http_owner_down(Config, http, unexpected, {shutdown, {owner_down, unexpected}}).

do_http_owner_down(Config, Protocol, ExitReason, DownReason) ->
	Self = self(),
	spawn(fun() ->
		{ok, ConnPid} = gun:open("localhost", config(origin_port, Config), #{
			protocols => [Protocol]
		}),
		Self ! {conn, ConnPid},
		{ok, Protocol} = gun:await_up(ConnPid),
		timer:sleep(500),
		exit(ExitReason)
	end),
	ConnPid = receive {conn, C} -> C end,
	ConnRef = monitor(process, ConnPid),
	gun_is_down(ConnPid, ConnRef, DownReason).

http1_request_connection_close(Config) ->
	doc("HTTP/1.1: Confirm that the Gun process shuts down gracefully "
		"when sending a request with the connection: close header and "
		"retry is disabled."),
	Protocol = http,
	{ok, ConnPid} = gun:open("localhost", config(origin_port, Config), #{
		protocols => [Protocol],
		retry => 0
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	ConnRef = monitor(process, ConnPid),
	StreamRef = gun:get(ConnPid, "/", #{
		<<"connection">> => <<"close">>
	}),
	%% We get the response followed by Gun shutting down.
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
	{ok, _} = gun:await_body(ConnPid, StreamRef),
	gun_is_down(ConnPid, ConnRef, normal).

http1_request_connection_close_pipeline(Config) ->
	doc("HTTP/1.1: Confirm that the Gun process shuts down gracefully "
		"when sending a request with the connection: close header and "
		"retry is disabled. Pipelined requests get canceled."),
	Protocol = http,
	{ok, ConnPid} = gun:open("localhost", config(origin_port, Config), #{
		protocols => [Protocol],
		retry => 0
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	ConnRef = monitor(process, ConnPid),
	StreamRef1 = gun:get(ConnPid, "/", #{
		<<"connection">> => <<"close">>
	}),
	StreamRef2 = gun:get(ConnPid, "/"),
	StreamRef3 = gun:get(ConnPid, "/"),
	%% We get the response, pipelined streams get canceled, followed by Gun shutting down.
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef1),
	{error, {stream_error, closing}} = gun:await(ConnPid, StreamRef2),
	{error, {stream_error, closing}} = gun:await(ConnPid, StreamRef3),
	{ok, _} = gun:await_body(ConnPid, StreamRef1),
	gun_is_down(ConnPid, ConnRef, normal).

http1_response_connection_close(_) ->
	doc("HTTP/1.1: Confirm that the Gun process shuts down gracefully "
		"when receiving a response with the connection: close header and "
		"retry is disabled."),
	{ok, _} = cowboy:start_clear(?FUNCTION_NAME, [], #{
		env => #{dispatch => cowboy_router:compile([{'_', [{"/", hello_h, []}]}])},
		max_keepalive => 1
	}),
	OriginPort = ranch:get_port(?FUNCTION_NAME),
	try
		Protocol = http,
		{ok, ConnPid} = gun:open("localhost", OriginPort, #{
			protocols => [Protocol],
			retry => 0
		}),
		{ok, Protocol} = gun:await_up(ConnPid),
		ConnRef = monitor(process, ConnPid),
		StreamRef = gun:get(ConnPid, "/"),
		%% We get the response followed by Gun shutting down.
		{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
		{ok, _} = gun:await_body(ConnPid, StreamRef),
		gun_is_down(ConnPid, ConnRef, normal)
	after
		cowboy:stop_listener(?FUNCTION_NAME)
	end.

http1_response_connection_close_pipeline(_) ->
	doc("HTTP/1.1: Confirm that the Gun process shuts down gracefully "
		"when receiving a response with the connection: close header and "
		"retry is disabled. Pipelined requests get canceled."),
	{ok, _} = cowboy:start_clear(?FUNCTION_NAME, [], #{
		env => #{dispatch => cowboy_router:compile([{'_', [{"/", hello_h, []}]}])},
		max_keepalive => 1
	}),
	OriginPort = ranch:get_port(?FUNCTION_NAME),
	try
		Protocol = http,
		{ok, ConnPid} = gun:open("localhost", OriginPort, #{
			protocols => [Protocol],
			retry => 0
		}),
		{ok, Protocol} = gun:await_up(ConnPid),
		ConnRef = monitor(process, ConnPid),
		StreamRef1 = gun:get(ConnPid, "/"),
		StreamRef2 = gun:get(ConnPid, "/"),
		StreamRef3 = gun:get(ConnPid, "/"),
		%% We get the response, pipelined streams get canceled, followed by Gun shutting down.
		{response, nofin, 200, _} = gun:await(ConnPid, StreamRef1),
		{ok, _} = gun:await_body(ConnPid, StreamRef1),
		{error, {stream_error, closing}} = gun:await(ConnPid, StreamRef2),
		{error, {stream_error, closing}} = gun:await(ConnPid, StreamRef3),
		gun_is_down(ConnPid, ConnRef, normal)
	after
		cowboy:stop_listener(?FUNCTION_NAME)
	end.

http10_connection_close(Config) ->
	doc("HTTP/1.0: Confirm that the Gun process shuts down gracefully "
		"when sending a request without a connection header and "
		"retry is disabled."),
	Protocol = http,
	{ok, ConnPid} = gun:open("localhost", config(origin_port, Config), #{
		http_opts => #{version => 'HTTP/1.0'},
		protocols => [Protocol],
		retry => 0
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	ConnRef = monitor(process, ConnPid),
	StreamRef = gun:get(ConnPid, "/"),
	%% We get the response followed by Gun shutting down.
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
	{ok, _} = gun:await_body(ConnPid, StreamRef),
	gun_is_down(ConnPid, ConnRef, normal).

http1_response_connection_close_delayed_body(_) ->
	doc("HTTP/1.1: Confirm that requests initiated when Gun has received a "
		"connection: close response header fail immediately if retry "
		"is disabled, without waiting for the response body."),
	ServerFun = fun(_Parent, ClientSocket, gen_tcp) ->
		try
			{ok, Req} = gen_tcp:recv(ClientSocket, 0, 5000),
			<<"GET / HTTP/1.1\r\n", _/binary>> = Req,
			ok = gen_tcp:send(ClientSocket, <<"HTTP/1.1 200 OK\r\n"
				"Connection: close\r\n"
				"Content-Length: 12\r\n\r\nHello">>),
			timer:sleep(500),
			ok = gen_tcp:send(ClientSocket, " world!")
		after
			gen_tcp:close(ClientSocket)
		end
	end,
	{ok, ServerPid, OriginPort} = gun_test:init_origin(tcp, http, ServerFun),
	%% Client connects.
	{ok, ConnPid} = gun:open("localhost", OriginPort, #{
		protocols => [http],
		retry => 0
	}),
	{ok, _Protocol} = gun:await_up(ConnPid),
	receive {ServerPid, handshake_completed} -> ok end,
	ConnRef = monitor(process, ConnPid),
	StreamRef1 = gun:get(ConnPid, "/"),
	StreamRef2 = gun:get(ConnPid, "/"),
	%% We get the response headers with connection: close.
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef1),
	%% Pipelined request fails immediately.
	{gun_error, ConnPid, StreamRef2, closing} = receive E2 -> E2 end,
	{gun_data, ConnPid, StreamRef1, nofin, <<"Hello">>} =
		receive PartialBody -> PartialBody end,
	%% Request initiated when Gun is in closing state fails immediately.
	StreamRef3 = gun:get(ConnPid, "/"),
	{gun_error, ConnPid, StreamRef3, closing} = receive E3 -> E3 end,
	{gun_data, ConnPid, StreamRef1, fin, <<" world!">>} =
		receive RestBody -> RestBody end,
	gun_is_down(ConnPid, ConnRef, normal).

http2_gun_shutdown_no_streams(Config) ->
	doc("HTTP/2: Confirm that the Gun process shuts down gracefully "
		"when calling gun:shutdown/1 with no active streams."),
	do_http_gun_shutdown_no_streams(Config, http2).

http2_gun_shutdown_one_stream(Config) ->
	doc("HTTP/2: Confirm that the Gun process shuts down gracefully "
		"when calling gun:shutdown/1 with one active stream."),
	do_http_gun_shutdown_one_stream(Config, http2).

http2_gun_shutdown_many_streams(Config) ->
	doc("HTTP/2: Confirm that the Gun process shuts down gracefully "
		"when calling gun:shutdown/1 with many active streams."),
	Protocol = http2,
	{ok, ConnPid} = gun:open("localhost", config(origin_port, Config), #{
		protocols => [Protocol]
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	ConnRef = monitor(process, ConnPid),
	StreamRef1 = gun:get(ConnPid, "/delayed"),
	StreamRef2 = gun:get(ConnPid, "/delayed"),
	StreamRef3 = gun:get(ConnPid, "/delayed"),
	gun:shutdown(ConnPid),
	%% All streams are processed.
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef1),
	{ok, _} = gun:await_body(ConnPid, StreamRef1),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef2),
	{ok, _} = gun:await_body(ConnPid, StreamRef2),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef3),
	{ok, _} = gun:await_body(ConnPid, StreamRef3),
	gun_is_down(ConnPid, ConnRef, shutdown).

http2_gun_shutdown_timeout(Config) ->
	doc("HTTP/2: Confirm that the Gun process shuts down when the closing_timeout "
		"triggers after calling gun:shutdown/1 with one active stream."),
	do_http_gun_shutdown_timeout(Config, http2, http2_opts).

http2_gun_shutdown_ignore_push_promise(Config) ->
	doc("HTTP/2: Confirm that the Gun process shuts down gracefully "
		"when calling gun:shutdown/1 with one active stream. The "
		"resource pushed by the server after we sent the GOAWAY frame "
		"must be ignored."),
	Protocol = http2,
	{ok, ConnPid} = gun:open("localhost", config(origin_port, Config), #{
		protocols => [Protocol]
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	ConnRef = monitor(process, ConnPid),
	StreamRef = gun:get(ConnPid, "/delayed_push"),
	gun:shutdown(ConnPid),
	%% We do not receive the push streams. Only the response.
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
	{ok, _} = gun:await_body(ConnPid, StreamRef),
	gun_is_down(ConnPid, ConnRef, shutdown).

http2_owner_down(Config) ->
	doc("HTTP/2: Confirm that the Gun process shuts down when the owner exits normally."),
	do_http_owner_down(Config, http2, normal, normal).

http2_owner_down_error(Config) ->
	doc("HTTP/2: Confirm that the Gun process shuts down when the owner exits with an error."),
	do_http_owner_down(Config, http2, unexpected, {shutdown, {owner_down, unexpected}}).

http2_server_goaway_no_streams(_) ->
	doc("HTTP/2: Confirm that the Gun process shuts down gracefully "
		"when receiving a GOAWAY frame with no active streams and "
		"retry is disabled."),
	{ok, OriginPid, Port} = init_origin(tcp, http2, fun(_, Socket, Transport) ->
		receive go_away -> ok end,
		Transport:send(Socket, cow_http2:goaway(0, no_error, <<>>)),
		timer:sleep(500)
	end),
	Protocol = http2,
	{ok, ConnPid} = gun:open("localhost", Port, #{
		protocols => [Protocol],
		retry => 0
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	ConnRef = monitor(process, ConnPid),
	OriginPid ! go_away,
	gun_is_down(ConnPid, ConnRef, normal).

http2_server_goaway_one_stream(_) ->
	doc("HTTP/2: Confirm that the Gun process shuts down gracefully "
		"when receiving a GOAWAY frame with one active stream and "
		"retry is disabled."),
	{ok, OriginPid, OriginPort} = init_origin(tcp, http2, fun(_, Socket, Transport) ->
		%% Receive a HEADERS frame.
		{ok, <<SkipLen:24, 1:8, _:8, 1:32>>} = Transport:recv(Socket, 9, 1000),
		%% Skip the header.
		{ok, _} = gen_tcp:recv(Socket, SkipLen, 1000),
		%% Send a GOAWAY frame.
		Transport:send(Socket, cow_http2:goaway(1, no_error, <<>>)),
		%% Wait before sending the response back and closing the connection.
		timer:sleep(500),
		%% Send a HEADERS frame.
		{HeadersBlock, _} = cow_hpack:encode([
			{<<":status">>, <<"200">>}
		]),
		ok = Transport:send(Socket, [
			cow_http2:headers(1, fin, HeadersBlock)
		]),
		timer:sleep(500)
	end),
	Protocol = http2,
	{ok, ConnPid} = gun:open("localhost", OriginPort, #{
		protocols => [Protocol],
		retry => 0
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	handshake_completed = receive_from(OriginPid),
	StreamRef = gun:get(ConnPid, "/"),
	ConnRef = monitor(process, ConnPid),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef),
	gun_is_down(ConnPid, ConnRef, normal).

http2_server_goaway_many_streams(_) ->
	doc("HTTP/2: Confirm that the Gun process shuts down gracefully "
		"when receiving a GOAWAY frame with many active streams and "
		"retry is disabled."),
	{ok, OriginPid, OriginPort} = init_origin(tcp, http2, fun(_, Socket, Transport) ->
		%% Stream 1.
		%% Receive a HEADERS frame.
		{ok, <<SkipLen1:24, 1:8, _:8, 1:32>>} = Transport:recv(Socket, 9, 1000),
		%% Skip the header.
		{ok, _} = gen_tcp:recv(Socket, SkipLen1, 1000),
		%% Stream 2.
		%% Receive a HEADERS frame.
		{ok, <<SkipLen2:24, 1:8, _:8, 3:32>>} = Transport:recv(Socket, 9, 1000),
		%% Skip the header.
		{ok, _} = gen_tcp:recv(Socket, SkipLen2, 1000),
		%% Stream 3.
		%% Receive a HEADERS frame.
		{ok, <<SkipLen3:24, 1:8, _:8, 5:32>>} = Transport:recv(Socket, 9, 1000),
		%% Skip the header.
		{ok, _} = gen_tcp:recv(Socket, SkipLen3, 1000),
		%% Stream 4.
		%% Receive a HEADERS frame, but simulate that it is still
		%% in-flight when the GOAWAY frame is sent.
		{ok, <<SkipLen4:24, 1:8, _:8, 7:32>>} = Transport:recv(Socket, 9, 1000),
		%% Skip the header.
		{ok, _} = gen_tcp:recv(Socket, SkipLen4, 1000),
		%% Send a GOAWAY frame. Simulate that GOAWAY was sent before
		%% receiving stream 4 by including last stream ID of stream 3.
		Transport:send(Socket, cow_http2:goaway(5, no_error, <<>>)),
		%% Gun replies with GOAWAY.
		{ok, <<SkipLen5:24, 7:8, _:8, 0:32>>} = Transport:recv(Socket, 9, 1000),
		{ok, _SkippedPayload} = gen_tcp:recv(Socket, SkipLen5, 1000),
		timer:sleep(500),
		%% Send replies for streams 1-3.
		{HeadersBlock1, State0} = cow_hpack:encode([
			{<<":status">>, <<"200">>}
		]),
		ok = Transport:send(Socket, [
			cow_http2:headers(1, fin, HeadersBlock1)
		]),
		{HeadersBlock2, State} = cow_hpack:encode([
			{<<":status">>, <<"200">>}
		], State0),
		ok = Transport:send(Socket, [
			cow_http2:headers(3, fin, HeadersBlock2)
		]),
		{HeadersBlock3, _} = cow_hpack:encode([
			{<<":status">>, <<"200">>}
		], State),
		ok = Transport:send(Socket, [
			cow_http2:headers(5, fin, HeadersBlock3)
		]),
		%% Gun closes the connection.
		{error, closed} = gen_tcp:recv(Socket, 9)
	end),
	Protocol = http2,
	{ok, ConnPid} = gun:open("localhost", OriginPort, #{
		protocols => [Protocol],
		retry => 0
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	handshake_completed = receive_from(OriginPid),
	StreamRef1 = gun:get(ConnPid, "/"),
	StreamRef2 = gun:get(ConnPid, "/"),
	StreamRef3 = gun:get(ConnPid, "/"),
	StreamRef4 = gun:get(ConnPid, "/"),
	ConnRef = monitor(process, ConnPid),
	%% GOAWAY received. Stream 4 is cancelled.
	{gun_error, ConnPid, StreamRef4, Reason4} = receive E4 -> E4 end,
	{goaway, no_error, _} = Reason4,
	StreamRef5 = gun:get(ConnPid, "/"),
	{gun_error, ConnPid, StreamRef5, closing} = receive E5 -> E5 end,
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef2),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef3),
	gun_is_down(ConnPid, ConnRef, normal).

ws_gun_shutdown(Config) ->
	doc("Websocket: Confirm that the Gun process shuts down gracefully "
		"when calling gun:shutdown/1."),
	{ok, ConnPid} = gun:open("localhost", config(origin_port, Config)),
	{ok, http} = gun:await_up(ConnPid),
	ConnRef = monitor(process, ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/ws", []),
	{upgrade, [<<"websocket">>], _} = gun:await(ConnPid, StreamRef),
	gun:shutdown(ConnPid),
	gun_is_down(ConnPid, ConnRef, shutdown).

ws_gun_shutdown_timeout(Config) ->
	doc("Websocket: Confirm that the Gun process shuts down when "
		"the closing_timeout triggers after calling gun:shutdown/1."),
	{ok, ConnPid} = gun:open("localhost", config(origin_port, Config), #{
		ws_opts => #{closing_timeout => 100}
	}),
	{ok, http} = gun:await_up(ConnPid),
	ConnRef = monitor(process, ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/ws_frozen_long", []),
	{upgrade, [<<"websocket">>], _} = gun:await(ConnPid, StreamRef),
	gun:shutdown(ConnPid),
	gun_is_down(ConnPid, ConnRef, shutdown).

ws_owner_down(Config) ->
	doc("Websocket: Confirm that the Gun process shuts down when the owner exits normally."),
	do_ws_owner_down(Config, normal, normal).

ws_owner_down_error(Config) ->
	doc("Websocket: Confirm that the Gun process shuts down when the owner exits with an error."),
	do_ws_owner_down(Config, unexpected, {shutdown, {owner_down, unexpected}}).

do_ws_owner_down(Config, ExitReason, DownReason) ->
	Self = self(),
	spawn(fun() ->
		{ok, ConnPid} = gun:open("localhost", config(origin_port, Config)),
		Self ! {conn, ConnPid},
		{ok, http} = gun:await_up(ConnPid),
		StreamRef = gun:ws_upgrade(ConnPid, "/ws", []),
		{upgrade, [<<"websocket">>], _} = gun:await(ConnPid, StreamRef),
		timer:sleep(500),
		exit(ExitReason)
	end),
	ConnPid = receive {conn, C} -> C end,
	ConnRef = monitor(process, ConnPid),
	gun_is_down(ConnPid, ConnRef, DownReason).

ws_gun_send_close_frame(Config) ->
	doc("Websocket: Confirm that the Gun process shuts down gracefully "
		"when sending a close frame, with retry disabled."),
	{ok, ConnPid} = gun:open("localhost", config(origin_port, Config), #{
		retry => 0
	}),
	{ok, http} = gun:await_up(ConnPid),
	ConnRef = monitor(process, ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/ws", []),
	{upgrade, [<<"websocket">>], _} = gun:await(ConnPid, StreamRef),
	%% We send a close frame. We expect the same frame back
	%% before the connection is closed.
	Frame = {close, 3333, <<>>},
	gun:ws_send(ConnPid, StreamRef, Frame),
	{ws, Frame} = gun:await(ConnPid, StreamRef),
	gun_is_down(ConnPid, ConnRef, normal).

ws_gun_receive_close_frame(Config) ->
	doc("Websocket: Confirm that the Gun process shuts down gracefully "
		"when receiving a close frame, with retry disabled."),
	{ok, ConnPid} = gun:open("localhost", config(origin_port, Config), #{
		retry => 0
	}),
	{ok, http} = gun:await_up(ConnPid),
	ConnRef = monitor(process, ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/ws_timeout_close", []),
	{upgrade, [<<"websocket">>], _} = gun:await(ConnPid, StreamRef),
	%% We expect a close frame before the connection is closed.
	{ws, {close, 3333, <<>>}} = gun:await(ConnPid, StreamRef),
	gun_is_down(ConnPid, ConnRef, normal).

closing_gun_shutdown(Config) ->
	doc("Confirm that the Gun process shuts down gracefully "
		"when calling gun:shutdown/1 while Gun is closing a connection."),
	{ok, ConnPid} = gun:open("localhost", config(origin_port, Config)),
	{ok, http} = gun:await_up(ConnPid),
	ConnRef = monitor(process, ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/ws_frozen", []),
	{upgrade, [<<"websocket">>], _} = gun:await(ConnPid, StreamRef),
	%% We send a close frame then immediately call gun:shutdown/1.
	%% We expect Gun to go down without retrying to reconnect.
	Frame = {close, 3333, <<>>},
	gun:ws_send(ConnPid, StreamRef, Frame),
	gun:shutdown(ConnPid),
	{ws, Frame} = gun:await(ConnPid, StreamRef),
	gun_is_down(ConnPid, ConnRef, shutdown).

closing_owner_down(Config) ->
	doc("Confirm that the Gun process shuts down gracefully "
		"when the owner exits normally while Gun is closing a connection."),
	do_closing_owner_down(Config, normal, normal).

closing_owner_down_error(Config) ->
	doc("Confirm that the Gun process shuts down gracefully "
		"when the owner exits with an error while Gun is closing a connection."),
	do_closing_owner_down(Config, unexpected, {shutdown, {owner_down, unexpected}}).

do_closing_owner_down(Config, ExitReason, DownReason) ->
	Self = self(),
	spawn(fun() ->
		{ok, ConnPid} = gun:open("localhost", config(origin_port, Config)),
		Self ! {conn, ConnPid},
		{ok, http} = gun:await_up(ConnPid),
		StreamRef = gun:ws_upgrade(ConnPid, "/ws_frozen", []),
		{upgrade, [<<"websocket">>], _} = gun:await(ConnPid, StreamRef),
		gun:ws_send(ConnPid, StreamRef, {close, 3333, <<>>}),
		timer:sleep(100),
		exit(ExitReason)
	end),
	ConnPid = receive {conn, C} -> C end,
	ConnRef = monitor(process, ConnPid),
	gun_is_down(ConnPid, ConnRef, DownReason).

%% Internal.

gun_is_down(ConnPid, ConnRef, Expected) ->
	receive
		{'DOWN', ConnRef, process, ConnPid, Reason} ->
			Expected = Reason,
			ok
	end.
