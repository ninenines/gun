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

-module(event_SUITE).
-compile(export_all).
-compile(nowarn_export_all).

-behavior(gun_event).

-import(ct_helper, [config/2]).
-import(ct_helper, [doc/1]).
-import(gun_test, [init_origin/1]).

all() ->
	[
		{group, http},
		{group, http2}
	].

groups() ->
	Tests = ct_helper:all(?MODULE),
	[
		{http, [parallel], Tests},
		{http2, [parallel], Tests -- [ws_upgrade, ws_upgrade_all_events, protocol_changed]}
	].

init_per_suite(Config) ->
	{ok, _} = cowboy:start_clear(?MODULE, [], #{env => #{
		dispatch => cowboy_router:compile([{'_', [
			{"/", hello_h, []},
			{"/empty", empty_h, []},
			{"/inform", inform_h, []},
			{"/stream", stream_h, []},
			{"/trailers", trailers_h, []},
			{"/ws", ws_echo, []}
		]}])
	}}),
	OriginPort = ranch:get_port(?MODULE),
	[{origin_port, OriginPort}|Config].

end_per_suite(_) ->
	ok = cowboy:stop_listener(?MODULE).

%% init.

init(Config) ->
	doc("Confirm that the init event callback is called."),
	Self = self(),
	Opts = #{
		event_handler => {?MODULE, self()},
		protocols => [config(name, config(tc_group_properties, Config))]
	},
	{ok, Pid} = gun:open("localhost", 12345, Opts),
	#{
		owner := Self,
		transport := tcp,
		origin_scheme := <<"http">>,
		origin_host := "localhost",
		origin_port := 12345,
		opts := Opts
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

%% connect_start/connect_end.

connect_start(Config) ->
	doc("Confirm that the connect_start event callback is called."),
	{ok, Pid, _} = do_gun_open(12345, Config),
	#{
		host := "localhost",
		port := 12345,
		transport := tcp,
		transport_opts := _,
		timeout := _
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

connect_end_error(Config) ->
	doc("Confirm that the connect_end event callback is called on connect failure."),
	{ok, Pid, _} = do_gun_open(12345, Config),
	#{
		host := "localhost",
		port := 12345,
		transport := tcp,
		transport_opts := _,
		timeout := _,
		error := _
	} = do_receive_event(connect_end),
	gun:close(Pid).

connect_end_ok(Config) ->
	doc("Confirm that the connect_end event callback is called on connect success."),
	{ok, Pid, OriginPort} = do_gun_open(Config),
	{ok, Protocol} = gun:await_up(Pid),
	#{
		host := "localhost",
		port := OriginPort,
		transport := tcp,
		transport_opts := _,
		timeout := _,
		socket := _,
		protocol := Protocol
	} = do_receive_event(connect_end),
	gun:close(Pid).

request_start(Config) ->
	doc("Confirm that the request_start event callback is called."),
	do_request_event(Config, ?FUNCTION_NAME),
	do_request_event_headers(Config, ?FUNCTION_NAME).

request_headers(Config) ->
	doc("Confirm that the request_headers event callback is called."),
	do_request_event(Config, ?FUNCTION_NAME),
	do_request_event_headers(Config, ?FUNCTION_NAME).

do_request_event(Config, EventName) ->
	{ok, Pid, OriginPort} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:get(Pid, "/"),
	ReplyTo = self(),
	Authority = iolist_to_binary([<<"localhost:">>, integer_to_list(OriginPort)]),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		function := request,
		method := <<"GET">>,
		authority := EventAuthority,
		path := "/",
		headers := [_|_]
	} = do_receive_event(EventName),
	Authority = iolist_to_binary(EventAuthority),
	gun:close(Pid).

do_request_event_headers(Config, EventName) ->
	{ok, Pid, OriginPort} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:put(Pid, "/", [
		{<<"content-type">>, <<"text/plain">>}
	]),
	ReplyTo = self(),
	Authority = iolist_to_binary([<<"localhost:">>, integer_to_list(OriginPort)]),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		function := headers,
		method := <<"PUT">>,
		authority := EventAuthority,
		path := "/",
		headers := [_|_]
	} = do_receive_event(EventName),
	Authority = iolist_to_binary(EventAuthority),
	gun:close(Pid).

request_end(Config) ->
	doc("Confirm that the request_end event callback is called."),
	do_request_end(Config, ?FUNCTION_NAME),
	do_request_end_headers(Config, ?FUNCTION_NAME),
	do_request_end_headers_content_length(Config, ?FUNCTION_NAME),
	do_request_end_headers_content_length_0(Config, ?FUNCTION_NAME).

do_request_end(Config, EventName) ->
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:get(Pid, "/"),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo
	} = do_receive_event(EventName),
	gun:close(Pid).

do_request_end_headers(Config, EventName) ->
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:put(Pid, "/", [
		{<<"content-type">>, <<"text/plain">>}
	]),
	gun:data(Pid, StreamRef, nofin, <<"Hello ">>),
	gun:data(Pid, StreamRef, fin, <<"world!">>),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo
	} = do_receive_event(EventName),
	gun:close(Pid).

do_request_end_headers_content_length(Config, EventName) ->
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:put(Pid, "/", [
		{<<"content-type">>, <<"text/plain">>},
		{<<"content-length">>, <<"12">>}
	]),
	gun:data(Pid, StreamRef, nofin, <<"Hello ">>),
	gun:data(Pid, StreamRef, fin, <<"world!">>),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo
	} = do_receive_event(EventName),
	gun:close(Pid).

do_request_end_headers_content_length_0(Config, EventName) ->
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:put(Pid, "/", [
		{<<"content-type">>, <<"text/plain">>},
		{<<"content-length">>, <<"0">>}
	]),
	gun:data(Pid, StreamRef, fin, <<>>),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo
	} = do_receive_event(EventName),
	gun:close(Pid).

response_start(Config) ->
	doc("Confirm that the request_start event callback is called."),
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:get(Pid, "/"),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

response_inform(Config) ->
	doc("Confirm that the request_inform event callback is called."),
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:get(Pid, "/inform"),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		status := 103,
		headers := [_|_]
	} = do_receive_event(?FUNCTION_NAME),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		status := 103,
		headers := [_|_]
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

response_headers(Config) ->
	doc("Confirm that the request_headers event callback is called."),
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:get(Pid, "/"),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		status := 200,
		headers := [_|_]
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

response_trailers(Config) ->
	doc("Confirm that the request_trailers event callback is called."),
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:get(Pid, "/trailers", [{<<"te">>, <<"trailers">>}]),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		headers := [_|_]
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

response_end(Config) ->
	doc("Confirm that the request_headers event callback is called."),
	do_response_end(Config, ?FUNCTION_NAME, "/"),
	do_response_end(Config, ?FUNCTION_NAME, "/empty"),
	do_response_end(Config, ?FUNCTION_NAME, "/stream"),
	do_response_end(Config, ?FUNCTION_NAME, "/trailers").

do_response_end(Config, EventName, Path) ->
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:get(Pid, Path, [{<<"te">>, <<"trailers">>}]),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo
	} = do_receive_event(EventName),
	gun:close(Pid).

ws_upgrade(Config) ->
	doc("Confirm that the ws_upgrade event callback is called."),
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:ws_upgrade(Pid, "/ws"),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		opts := #{}
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

ws_upgrade_all_events(Config) ->
	doc("Confirm that a Websocket upgrade triggers all relevant events."),
	{ok, Pid, OriginPort} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:ws_upgrade(Pid, "/ws"),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		opts := #{}
	} = do_receive_event(ws_upgrade),
	Authority = iolist_to_binary([<<"localhost:">>, integer_to_list(OriginPort)]),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		function := ws_upgrade,
		method := <<"GET">>,
		authority := EventAuthority1,
		path := "/ws",
		headers := [_|_]
	} = do_receive_event(request_start),
	Authority = iolist_to_binary(EventAuthority1),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		function := ws_upgrade,
		method := <<"GET">>,
		authority := EventAuthority2,
		path := "/ws",
		headers := [_|_]
	} = do_receive_event(request_headers),
	Authority = iolist_to_binary(EventAuthority2),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo
	} = do_receive_event(request_end),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo
	} = do_receive_event(response_start),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		status := 101,
		headers := [_|_]
	} = do_receive_event(response_inform),
	#{
		protocol := ws
	} = do_receive_event(protocol_changed),
	gun:close(Pid).

protocol_changed(Config) ->
	doc("Confirm that the protocol_changed event callback is called."),
	do_protocol_changed_ws(Config, ?FUNCTION_NAME).
	%% @todo do_protocol_changed_connect

do_protocol_changed_ws(Config, EventName) ->
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	_ = gun:ws_upgrade(Pid, "/ws"),
	#{
		protocol := ws
	} = do_receive_event(EventName),
	gun:close(Pid).

disconnect(Config) ->
	doc("Confirm that the disconnect event callback is called on disconnect."),
	{ok, OriginPid, OriginPort} = init_origin(tcp),
	{ok, Pid, _} = do_gun_open(OriginPort, Config),
	{ok, _} = gun:await_up(Pid),
	%% We make the origin exit to trigger a disconnect.
	unlink(OriginPid),
	exit(OriginPid, shutdown),
	#{
		reason := closed
	} = do_receive_event(disconnect),
	gun:close(Pid).

terminate(Config) ->
	doc("Confirm that the terminate event callback is called on terminate."),
	{ok, Pid, _} = do_gun_open(12345, Config),
	gun:close(Pid),
	#{
		state := not_connected,
		reason := shutdown
	} = do_receive_event(terminate),
	ok.

%% Internal.

do_gun_open(Config) ->
	OriginPort = config(origin_port, Config),
	do_gun_open(OriginPort, Config).

do_gun_open(OriginPort, Config) ->
	Opts = #{
		event_handler => {?MODULE, self()},
		protocols => [config(name, config(tc_group_properties, Config))]
	},
	{ok, Pid} = gun:open("localhost", OriginPort, Opts),
	{ok, Pid, OriginPort}.

do_receive_event(Event) ->
	receive
		{Event, EventData} ->
			EventData
	after 5000 ->
		error(timeout)
	end.

%% gun_event callbacks.

init(EventData, Pid) ->
	%% We enable trap_exit to ensure we get a terminate event
	%% when we call gun:close/1.
	process_flag(trap_exit, true),
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

connect_start(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

connect_end(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

request_start(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

request_headers(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

request_end(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

response_start(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

response_inform(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

response_headers(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

response_trailers(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

response_end(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

ws_upgrade(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

protocol_changed(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

disconnect(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

terminate(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.
