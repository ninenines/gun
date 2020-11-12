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

-module(flow_SUITE).
-compile(export_all).
-compile(nowarn_export_all).

-import(ct_helper, [doc/1]).

all() ->
	[{group, flow}].

groups() ->
	[{flow, [parallel], ct_helper:all(?MODULE)}].

%% Tests.

default_flow_http(_) ->
	doc("Confirm flow control default can be changed and overriden for HTTP/1.1."),
	{ok, _} = cowboy:start_clear(?FUNCTION_NAME, [], #{env => #{
		dispatch => cowboy_router:compile([{'_', [{"/", sse_clock_h, date}]}])
	}}),
	Port = ranch:get_port(?FUNCTION_NAME),
	try
		%% First we check that we can set the flow for the entire connection.
		{ok, ConnPid1} = gun:open("localhost", Port, #{
			http_opts => #{flow => 1}
		}),
		{ok, http} = gun:await_up(ConnPid1),
		StreamRef1 = gun:get(ConnPid1, "/"),
		{response, nofin, 200, _} = gun:await(ConnPid1, StreamRef1),
		{data, nofin, _} = gun:await(ConnPid1, StreamRef1),
		{error, timeout} = gun:await(ConnPid1, StreamRef1, 1500),
		gun:close(ConnPid1),
		%% Then we confirm that we can override it per request.
		{ok, ConnPid2} = gun:open("localhost", Port, #{
			http_opts => #{flow => 1}
		}),
		{ok, http} = gun:await_up(ConnPid2),
		StreamRef2 = gun:get(ConnPid2, "/", [], #{flow => 2}),
		{response, nofin, 200, _} = gun:await(ConnPid2, StreamRef2),
		{data, nofin, _} = gun:await(ConnPid2, StreamRef2),
		{data, nofin, _} = gun:await(ConnPid2, StreamRef2),
		{error, timeout} = gun:await(ConnPid2, StreamRef2, 1500),
		gun:close(ConnPid2)
	after
		cowboy:stop_listener(?FUNCTION_NAME)
	end.

default_flow_http2(_) ->
	doc("Confirm flow control default can be changed and overriden for HTTP/2."),
	{ok, _} = cowboy:start_clear(?FUNCTION_NAME, [], #{env => #{
		dispatch => cowboy_router:compile([{'_', [{"/", sse_clock_h, 40000}]}])
	}}),
	Port = ranch:get_port(?FUNCTION_NAME),
	try
		%% First we check that we can set the flow for the entire connection.
		{ok, ConnPid} = gun:open("localhost", Port, #{
			http2_opts => #{
				flow => 1,
				%% We set the max frame size to the same as the initial
				%% window size in order to reduce the number of data messages.
				initial_connection_window_size => 65535,
				initial_stream_window_size => 65535,
				max_frame_size_received => 65535
			},
			protocols => [http2]
		}),
		{ok, http2} = gun:await_up(ConnPid),
		StreamRef1 = gun:get(ConnPid, "/"),
		{response, nofin, 200, _} = gun:await(ConnPid, StreamRef1),
		%% We set the flow to 1 therefore we will receive *2* data messages,
		%% and then nothing because the window was fully consumed.
		{data, nofin, _} = gun:await(ConnPid, StreamRef1),
		{data, nofin, _} = gun:await(ConnPid, StreamRef1),
		{error, timeout} = gun:await(ConnPid, StreamRef1, 1500),
		%% Then we confirm that we can override it per request.
		StreamRef2 = gun:get(ConnPid, "/", [], #{flow => 2}),
		{response, nofin, 200, _} = gun:await(ConnPid, StreamRef2),
		%% We set the flow to 2 but due to the ensure_window algorithm
		%% we end up receiving *4* data messages before we consume
		%% the window.
		{data, nofin, _} = gun:await(ConnPid, StreamRef2),
		{data, nofin, _} = gun:await(ConnPid, StreamRef2),
		{data, nofin, _} = gun:await(ConnPid, StreamRef2),
		{data, nofin, _} = gun:await(ConnPid, StreamRef2),
		{error, timeout} = gun:await(ConnPid, StreamRef2, 1500),
		gun:close(ConnPid)
	after
		cowboy:stop_listener(?FUNCTION_NAME)
	end.

flow_http(_) ->
	doc("Confirm flow control works as intended for HTTP/1.1."),
	{ok, _} = cowboy:start_clear(?FUNCTION_NAME, [], #{env => #{
		dispatch => cowboy_router:compile([{'_', [{"/", sse_clock_h, date}]}])
	}}),
	Port = ranch:get_port(?FUNCTION_NAME),
	try
		{ok, ConnPid} = gun:open("localhost", Port),
		{ok, http} = gun:await_up(ConnPid),
		StreamRef = gun:get(ConnPid, "/", [], #{flow => 1}),
		{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
		%% We set the flow to 1 therefore we will receive 1 data message,
		%% and then nothing because Gun doesn't read from the socket.
		{data, nofin, _} = gun:await(ConnPid, StreamRef),
		{error, timeout} = gun:await(ConnPid, StreamRef, 3000),
		%% We then update the flow and get 2 more data messages but no more.
		gun:update_flow(ConnPid, StreamRef, 2),
		{data, nofin, _} = gun:await(ConnPid, StreamRef),
		{data, nofin, _} = gun:await(ConnPid, StreamRef),
		{error, timeout} = gun:await(ConnPid, StreamRef, 1000),
		gun:close(ConnPid)
	after
		cowboy:stop_listener(?FUNCTION_NAME)
	end.

flow_http2(_) ->
	doc("Confirm flow control works as intended for HTTP/2."),
	{ok, _} = cowboy:start_clear(?FUNCTION_NAME, [], #{env => #{
		dispatch => cowboy_router:compile([{'_', [{"/", sse_clock_h, 40000}]}])
	}}),
	Port = ranch:get_port(?FUNCTION_NAME),
	try
		{ok, ConnPid} = gun:open("localhost", Port, #{
			%% We set the max frame size to the same as the initial
			%% window size in order to reduce the number of data messages.
			http2_opts => #{
				initial_connection_window_size => 65535,
				initial_stream_window_size => 65535,
				max_frame_size_received => 65535
			},
			protocols => [http2]
		}),
		{ok, http2} = gun:await_up(ConnPid),
		StreamRef = gun:get(ConnPid, "/", [], #{flow => 1}),
		{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
		%% We set the flow to 1 therefore we will receive *2* data messages,
		%% and then nothing because the window was fully consumed.
		{data, nofin, D1} = gun:await(ConnPid, StreamRef),
		{data, nofin, D2} = gun:await(ConnPid, StreamRef),
		%% We consumed all the window available.
		65535 = byte_size(D1) + byte_size(D2),
		{error, timeout} = gun:await(ConnPid, StreamRef, 3500),
		%% We then update the flow and get *5* more data messages but no more.
		gun:update_flow(ConnPid, StreamRef, 2),
		{data, nofin, D3} = gun:await(ConnPid, StreamRef),
		{data, nofin, D4} = gun:await(ConnPid, StreamRef),
		{data, nofin, D5} = gun:await(ConnPid, StreamRef),
		{data, nofin, D6} = gun:await(ConnPid, StreamRef),
		{data, nofin, D7} = gun:await(ConnPid, StreamRef),
		%% We consumed all the window available again.
		%% D3 is the end of the truncated D2, D4, D5 and D6 are full and D7 truncated.
		131070 = byte_size(D3) + byte_size(D4) + byte_size(D5) + byte_size(D6) + byte_size(D7),
		{error, timeout} = gun:await(ConnPid, StreamRef, 1000),
		gun:close(ConnPid)
	after
		cowboy:stop_listener(?FUNCTION_NAME)
	end.

flow_ws(_) ->
	doc("Confirm flow control works as intended for Websocket."),
	{ok, _} = cowboy:start_clear(?FUNCTION_NAME, [], #{env => #{
		dispatch => cowboy_router:compile([{'_', [{"/", ws_echo_h, []}]}])
	}}),
	Port = ranch:get_port(?FUNCTION_NAME),
	try
		{ok, ConnPid} = gun:open("localhost", Port),
		{ok, http} = gun:await_up(ConnPid),
		StreamRef = gun:ws_upgrade(ConnPid, "/", [], #{flow => 1}),
		{upgrade, [<<"websocket">>], _} = gun:await(ConnPid, StreamRef),
		%% We send 2 frames with some time in between to make sure that
		%% Gun handles them in separate Protocol:handle calls.
		Frame = {text, <<"Hello!">>},
		gun:ws_send(ConnPid, StreamRef, Frame),
		timer:sleep(500),
		gun:ws_send(ConnPid, StreamRef, Frame),
		%% We set the flow to 1 therefore we will receive 1 data message,
		%% and then nothing because Gun doesn't read from the socket.
		{ws, _} = gun:await(ConnPid, StreamRef),
		{error, timeout} = gun:await(ConnPid, StreamRef, 3000),
		%% We then update the flow, send 2 frames with some time in between
		%% and get 2 more data messages but no more.
		gun:update_flow(ConnPid, StreamRef, 2),
		gun:ws_send(ConnPid, StreamRef, Frame),
		timer:sleep(500),
		gun:ws_send(ConnPid, StreamRef, Frame),
		{ws, _} = gun:await(ConnPid, StreamRef),
		{ws, _} = gun:await(ConnPid, StreamRef),
		{error, timeout} = gun:await(ConnPid, StreamRef, 1000),
		gun:close(ConnPid)
	after
		cowboy:stop_listener(?FUNCTION_NAME)
	end.

no_flow_http(_) ->
	doc("Ignore flow updates for no-flow streams for HTTP/1.1."),
	{ok, _} = cowboy:start_clear(?FUNCTION_NAME, [], #{env => #{
		dispatch => cowboy_router:compile([{'_', [{"/", sse_clock_h, date}]}])
	}}),
	Port = ranch:get_port(?FUNCTION_NAME),
	try
		{ok, ConnPid} = gun:open("localhost", Port),
		{ok, http} = gun:await_up(ConnPid),
		StreamRef = gun:get(ConnPid, "/", []),
		{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
		gun:update_flow(ConnPid, StreamRef, 2),
		{data, nofin, _} = gun:await(ConnPid, StreamRef),
		{data, nofin, _} = gun:await(ConnPid, StreamRef),
		{data, nofin, _} = gun:await(ConnPid, StreamRef),
		gun:close(ConnPid)
	after
		cowboy:stop_listener(?FUNCTION_NAME)
	end.

no_flow_http2(_) ->
	doc("Ignore flow updates for no-flow streams for HTTP/2."),
	{ok, _} = cowboy:start_clear(?FUNCTION_NAME, [], #{env => #{
		dispatch => cowboy_router:compile([{'_', [{"/", sse_clock_h, date}]}])
	}}),
	Port = ranch:get_port(?FUNCTION_NAME),
	try
		{ok, ConnPid} = gun:open("localhost", Port, #{
			protocols => [http2]
		}),
		{ok, http2} = gun:await_up(ConnPid),
		StreamRef = gun:get(ConnPid, "/", []),
		{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
		gun:update_flow(ConnPid, StreamRef, 2),
		{data, nofin, _} = gun:await(ConnPid, StreamRef),
		{data, nofin, _} = gun:await(ConnPid, StreamRef),
		{data, nofin, _} = gun:await(ConnPid, StreamRef),
		gun:close(ConnPid)
	after
		cowboy:stop_listener(?FUNCTION_NAME)
	end.

no_flow_ws(_) ->
	doc("Ignore flow updates for no-flow streams for Websocket."),
	{ok, _} = cowboy:start_clear(?FUNCTION_NAME, [], #{env => #{
		dispatch => cowboy_router:compile([{'_', [{"/", ws_echo_h, []}]}])
	}}),
	Port = ranch:get_port(?FUNCTION_NAME),
	try
		{ok, ConnPid} = gun:open("localhost", Port),
		{ok, http} = gun:await_up(ConnPid),
		StreamRef = gun:ws_upgrade(ConnPid, "/", []),
		{upgrade, [<<"websocket">>], _} = gun:await(ConnPid, StreamRef),
		gun:update_flow(ConnPid, StreamRef, 2),
		Frame = {text, <<"Hello!">>},
		gun:ws_send(ConnPid, StreamRef, Frame),
		timer:sleep(100),
		gun:ws_send(ConnPid, StreamRef, Frame),
		{ws, _} = gun:await(ConnPid, StreamRef),
		{ws, _} = gun:await(ConnPid, StreamRef),
		gun:close(ConnPid)
	after
		cowboy:stop_listener(?FUNCTION_NAME)
	end.

sse_flow_http(_) ->
	doc("Confirm flow control works as intended for HTTP/1.1 "
		"when using the gun_sse_h content handler."),
	{ok, _} = cowboy:start_clear(?FUNCTION_NAME, [], #{env => #{
		dispatch => cowboy_router:compile([{'_', [{"/", sse_clock_h, date}]}])
	}}),
	Port = ranch:get_port(?FUNCTION_NAME),
	try
		{ok, ConnPid} = gun:open("localhost", Port, #{
			http_opts => #{content_handlers => [gun_sse_h, gun_data_h]}
		}),
		{ok, http} = gun:await_up(ConnPid),
		StreamRef = gun:get(ConnPid, "/", [], #{flow => 1}),
		{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
		%% We set the flow to 1 therefore we will receive 1 event message,
		%% and then nothing because Gun doesn't read from the socket. We
		%% set the timeout to 2500 to ensure there is only going to be one
		%% message queued up.
		{sse, _} = gun:await(ConnPid, StreamRef),
		{error, timeout} = gun:await(ConnPid, StreamRef, 2500),
		%% We then update the flow and get 2 more event messages but no more.
		gun:update_flow(ConnPid, StreamRef, 2),
		{sse, _} = gun:await(ConnPid, StreamRef),
		{sse, _} = gun:await(ConnPid, StreamRef),
		{error, timeout} = gun:await(ConnPid, StreamRef, 1000),
		gun:close(ConnPid)
	after
		cowboy:stop_listener(?FUNCTION_NAME)
	end.

sse_flow_http2(_) ->
	doc("Confirm flow control works as intended for HTTP/2 "
		"when using the gun_sse_h content handler."),
	{ok, _} = cowboy:start_clear(?FUNCTION_NAME, [], #{env => #{
		dispatch => cowboy_router:compile([{'_', [{"/", sse_clock_h, 40000}]}])
	}}),
	Port = ranch:get_port(?FUNCTION_NAME),
	try
		{ok, ConnPid} = gun:open("localhost", Port, #{
			%% We set the max frame size to the same as the initial
			%% window size in order to reduce the number of data messages.
			http2_opts => #{
				content_handlers => [gun_sse_h, gun_data_h],
				initial_connection_window_size => 65535,
				initial_stream_window_size => 65535,
				max_frame_size_received => 65535
			},
			protocols => [http2]
		}),
		{ok, http2} = gun:await_up(ConnPid),
		StreamRef = gun:get(ConnPid, "/", [], #{flow => 1}),
		{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
		%% We set the flow to 1 therefore we will receive 1 event message,
		%% and then nothing because the window was fully consumed before
		%% the second event was fully received.
		{sse, _} = gun:await(ConnPid, StreamRef),
		{error, timeout} = gun:await(ConnPid, StreamRef, 3000),
		%% We then update the flow and get 3 more event messages but no more.
		%% We get an extra message because of the ensure_window algorithm.
		gun:update_flow(ConnPid, StreamRef, 2),
		{sse, _} = gun:await(ConnPid, StreamRef),
		{sse, _} = gun:await(ConnPid, StreamRef),
		{sse, _} = gun:await(ConnPid, StreamRef),
		{error, timeout} = gun:await(ConnPid, StreamRef, 1000),
		gun:close(ConnPid)
	after
		cowboy:stop_listener(?FUNCTION_NAME)
	end.
