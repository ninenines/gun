%% Copyright (c) Loïc Hoguin <essen@ninenines.eu>
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

-module(pool_SUITE).
-compile(export_all).
-compile(nowarn_export_all).

-import(ct_helper, [doc/1]).
-import(ct_helper, [config/2]).
-import(gun_test, [receive_from/1]).

all() ->
	ct_helper:all(?MODULE).

init_per_suite(Config) ->
	{ok, _} = cowboy:start_clear({?MODULE, tcp}, [], do_proto_opts()),
	Port = ranch:get_port({?MODULE, tcp}),
	[{port, Port}|Config].

end_per_suite(_) ->
	ExtraListeners = [
		max_streams_h2_size_1,
		max_streams_h2_size_2,
		reconnect_h1
	],
	_ = [cowboy:stop_listener(Listener) || Listener <- ExtraListeners],
	ok.

do_proto_opts() ->
	Routes = [
		{"/", hello_h, []},
		{"/delay", delayed_hello_h, 3000},
		{"/ws", ws_echo_h, []}
	],
	#{
		env => #{dispatch => cowboy_router:compile([{'_', Routes}])}
	}.

%% Tests.

push_promise_no_crash(_) ->
	doc("A server-pushed stream never goes through request_start, "
		"so response_end and request_end must leave the pool's "
		"stream counter unchanged."),
	Tid = ets:new(?FUNCTION_NAME, [public, set]),
	true = ets:insert(Tid, {self(), 2}),
	StreamRef = make_ref(),
	State0 = #{table => Tid, event_handler => {gun_default_event_h, undefined}},
	Event = #{stream_ref => StreamRef, reply_to => self()},
	State1 = gun_pool_events_h:response_end(Event, State0),
	State2 = gun_pool_events_h:request_end(Event, State1),
	[{_, 2}] = ets:lookup(Tid, self()),
	false = maps:is_key(StreamRef, State2),
	%% A stream that did pass request_start is still counted, in either order.
	EarlyResp = make_ref(),
	EarlyRespEvent = #{stream_ref => EarlyResp, reply_to => self()},
	State3 = gun_pool_events_h:request_start(EarlyRespEvent, State2),
	[{_, 3}] = ets:lookup(Tid, self()),
	State4 = gun_pool_events_h:response_end(EarlyRespEvent, State3),
	State5 = gun_pool_events_h:request_end(EarlyRespEvent, State4),
	[{_, 2}] = ets:lookup(Tid, self()),
	EarlyReq = make_ref(),
	EarlyReqEvent = #{stream_ref => EarlyReq, reply_to => self()},
	State6 = gun_pool_events_h:request_start(EarlyReqEvent, State5),
	State7 = gun_pool_events_h:request_end(EarlyReqEvent, State6),
	_ = gun_pool_events_h:response_end(EarlyReqEvent, State7),
	[{_, 2}] = ets:lookup(Tid, self()),
	true = ets:delete(Tid).

cancel_http2_drops_stream_count(_) ->
	doc("Cancelling an HTTP/2 or HTTP/3 stream retires it, so the pool "
		"counter drops once. A later end event must not drop it again."),
	Tid = ets:new(?FUNCTION_NAME, [public, set]),
	State0 = #{table => Tid, event_handler => {gun_default_event_h, undefined}},
	StreamRef = make_ref(),
	Event = #{stream_ref => StreamRef, reply_to => self()},
	State1 = gun_pool_events_h:request_start(Event, State0),
	[{_, 1}] = ets:lookup(Tid, self()),
	Cancel = Event#{endpoint => local, reason => cancel, protocol => http2},
	State2 = gun_pool_events_h:cancel(Cancel, State1),
	[{_, 0}] = ets:lookup(Tid, self()),
	false = maps:is_key(StreamRef, State2),
	State3 = gun_pool_events_h:request_end(Event, State2),
	_ = gun_pool_events_h:response_end(Event, State3),
	[{_, 0}] = ets:lookup(Tid, self()),
	H3 = make_ref(),
	H3Event = #{stream_ref => H3, reply_to => self()},
	State4 = gun_pool_events_h:request_start(H3Event, State3),
	[{_, 1}] = ets:lookup(Tid, self()),
	_ = gun_pool_events_h:cancel(Cancel#{stream_ref => H3, protocol => http3}, State4),
	_ = gun_pool_events_h:cancel(Cancel#{stream_ref => make_ref()}, State4),
	[{_, 0}] = ets:lookup(Tid, self()),
	true = ets:delete(Tid).

cancel_http1_keeps_stream_count(_) ->
	doc("Cancelling an HTTP/1.1 stream only silences it. The pool slot "
		"stays taken until request_end and response_end have both run."),
	Tid = ets:new(?FUNCTION_NAME, [public, set]),
	State0 = #{table => Tid, event_handler => {gun_default_event_h, undefined}},
	StreamRef = make_ref(),
	Event = #{stream_ref => StreamRef, reply_to => self()},
	State1 = gun_pool_events_h:request_start(Event, State0),
	State2 = gun_pool_events_h:request_end(Event, State1),
	[{_, 1}] = ets:lookup(Tid, self()),
	Cancel = Event#{endpoint => local, reason => cancel, protocol => http},
	State3 = gun_pool_events_h:cancel(Cancel, State2),
	[{_, 1}] = ets:lookup(Tid, self()),
	true = maps:is_key(StreamRef, State3),
	_ = gun_pool_events_h:response_end(Event, State3),
	[{_, 0}] = ets:lookup(Tid, self()),
	%% Cancel before either end: the pair still drops the counter once.
	Early = make_ref(),
	EarlyEvent = #{stream_ref => Early, reply_to => self()},
	State4 = gun_pool_events_h:request_start(EarlyEvent, State3),
	State5 = gun_pool_events_h:cancel(Cancel#{stream_ref => Early}, State4),
	[{_, 1}] = ets:lookup(Tid, self()),
	State6 = gun_pool_events_h:response_end(EarlyEvent, State5),
	_ = gun_pool_events_h:request_end(EarlyEvent, State6),
	[{_, 0}] = ets:lookup(Tid, self()),
	true = ets:delete(Tid).

http1_cancel_keeps_connection_busy(Config) ->
	doc("Cancelling an HTTP/1.1 request must not free the pool's only "
		"connection while that connection is still receiving the response."),
	Port = config(port, Config),
	Scope = ?FUNCTION_NAME,
	{ok, ManagerPid} = gun_pool:start_pool("localhost", Port, #{
		conn_opts => #{protocols => [http]},
		scope => Scope,
		size => 1
	}),
	gun_pool:await_up(ManagerPid),
	Host = #{<<"host">> => ["localhost:", integer_to_binary(Port)]},
	Opts = #{scope => Scope},
	{async, Ref} = gun_pool:get("/delay", Host, Opts),
	{ConnPid, StreamRef} = Ref,
	ok = do_wait_stream(ConnPid, StreamRef, up, 50),
	ok = gun_pool:cancel(Ref),
	{error, no_connection_available, _} = gun_pool:get("/", Host, Opts),
	ok = do_wait_stream(ConnPid, StreamRef, gone, 100),
	{async, Ref2} = gun_pool:get("/", Host, Opts),
	{response, nofin, 200, _} = gun_pool:await(Ref2),
	{ok, <<"Hello world!">>} = gun_pool:await_body(Ref2),
	gun_pool:stop_pool("localhost", Port, #{scope => Scope}).

do_wait_stream(ConnPid, StreamRef, up, 0) ->
	error({stream_not_up, gun:stream_info(ConnPid, StreamRef)});
do_wait_stream(ConnPid, StreamRef, gone, 0) ->
	error({stream_still_up, gun:stream_info(ConnPid, StreamRef)});
do_wait_stream(ConnPid, StreamRef, Expect, N) ->
	case {Expect, gun:stream_info(ConnPid, StreamRef)} of
		{up, {ok, #{}}} ->
			ok;
		{gone, {ok, undefined}} ->
			ok;
		_ ->
			timer:sleep(50),
			do_wait_stream(ConnPid, StreamRef, Expect, N - 1)
	end.

hello_pool_h1(Config) ->
	doc("Confirm the pool can be used for HTTP/1.1 connections."),
	Port = config(port, Config),
	{ok, ManagerPid} = gun_pool:start_pool("localhost", Port, #{
		conn_opts => #{protocols => [http]},
		scope => ?FUNCTION_NAME
	}),
	gun_pool:await_up(ManagerPid),
	Streams = [{async, _} = gun_pool:get("/",
		#{<<"host">> => ["localhost:", integer_to_binary(Port)]},
		#{scope => ?FUNCTION_NAME}
	) || _ <- lists:seq(1, 8)],
	_ = [begin
		{response, nofin, 200, _} = gun_pool:await(StreamRef),
		{ok, <<"Hello world!">>} = gun_pool:await_body(StreamRef)
	end || {async, StreamRef} <- Streams].

hello_pool_h2(Config) ->
	doc("Confirm the pool can be used for HTTP/2 connections."),
	Port = config(port, Config),
	{ok, ManagerPid} = gun_pool:start_pool("localhost", Port, #{
		conn_opts => #{protocols => [http2]},
		scope => ?FUNCTION_NAME
	}),
	gun_pool:await_up(ManagerPid),
	Streams = [{async, _} = gun_pool:get("/",
		#{<<"host">> => ["localhost:", integer_to_binary(Port)]},
		#{scope => ?FUNCTION_NAME}
	) || _ <- lists:seq(1, 800)],
	_ = [begin
		{response, nofin, 200, _} = gun_pool:await(StreamRef),
		{ok, <<"Hello world!">>} = gun_pool:await_body(StreamRef)
	end || {async, StreamRef} <- Streams].

hello_pool_ws(Config) ->
	doc("Confirm the pool can be used for HTTP/1.1 connections upgraded to Websocket."),
	Port = config(port, Config),
	{ok, ManagerPid} = gun_pool:start_pool("localhost", Port, #{
		conn_opts => #{
			protocols => [http],
			ws_opts => #{
				default_protocol => pool_ws_handler,
				user_opts => self()
			}
		},
		scope => ?FUNCTION_NAME,
		setup_fun => {fun
			(ConnPid, {gun_up, _, http}, SetupState) ->
				_ = gun:ws_upgrade(ConnPid, "/ws"),
				{setup, SetupState};
			(_, {gun_upgrade, _, StreamRef, _, _}, _) ->
				{up, ws, #{ws => StreamRef}};
			(ConnPid, Msg, SetupState) ->
				ct:pal("Unexpected setup message for ~p: ~p", [ConnPid, Msg]),
				{setup, SetupState}
		end, undefined}
	}),
	gun_pool:await_up(ManagerPid),
	_ = [gun_pool:ws_send({text, <<"Hello world!">>}, #{
		authority => ["localhost:", integer_to_binary(Port)],
		scope => ?FUNCTION_NAME
	}) || _ <- lists:seq(1, 8)],
	%% The pool_ws_handler module sends frames back to us.
	_ = [receive
		{text, <<"Hello world!">>} ->
			ok
	end || _ <- lists:seq(1, 8)].

max_streams_h1(Config) ->
	doc("Confirm requests are rejected when the maximum number "
		"of streams is reached for HTTP/1.1 connections."),
	Port = config(port, Config),
	Authority = ["localhost:", integer_to_binary(Port)],
	{ok, ManagerPid} = gun_pool:start_pool("localhost", Port, #{
		conn_opts => #{protocols => [http]},
		scope => ?FUNCTION_NAME,
		size => 1
	}),
	gun_pool:await_up(ManagerPid),
	{async, _} = gun_pool:get("/delay",
		#{<<"host">> => Authority}, #{scope => ?FUNCTION_NAME}),
	timer:sleep(500),
	{error, no_connection_available, _} = gun_pool:get("/delay",
		#{<<"host">> => Authority}, #{scope => ?FUNCTION_NAME}).

max_streams_h1_retry(Config) ->
	doc("Confirm connection checkout is retried when the maximum number "
		"of streams is reached for HTTP/1.1 connections."),
	Port = config(port, Config),
	Authority = ["localhost:", integer_to_binary(Port)],
	{ok, ManagerPid} = gun_pool:start_pool("localhost", Port, #{
		conn_opts => #{protocols => [http]},
		scope => ?FUNCTION_NAME,
		size => 1
	}),
	gun_pool:await_up(ManagerPid),
	{async, _} = gun_pool:get("/delay",
		#{<<"host">> => Authority}, #{scope => ?FUNCTION_NAME}),
	timer:sleep(500),
	{error, no_connection_available, _} = gun_pool:get("/delay",
		#{<<"host">> => Authority}, #{scope => ?FUNCTION_NAME}),
	{async, _} = gun_pool:get("/delay", #{<<"host">> => Authority}, #{
		checkout_retry => [100, 500, 500, 500, 500, 500, 500],
		scope => ?FUNCTION_NAME
	}).

max_streams_h2_size_1(_) ->
	doc("Confirm requests are rejected when the maximum number "
		"of streams is reached for HTTP/2 connections."),
	ProtoOpts = do_proto_opts(),
	{ok, _} = cowboy:start_clear(?FUNCTION_NAME, [], ProtoOpts#{
		max_concurrent_streams => 5
	}),
	Port = ranch:get_port(?FUNCTION_NAME),
	Authority = ["localhost:", integer_to_binary(Port)],
	{ok, ManagerPid} = gun_pool:start_pool("localhost", Port, #{
		conn_opts => #{protocols => [http2]},
		size => 1
	}),
	gun_pool:await_up(ManagerPid),
	[{async, _} = gun_pool:get("/delay", #{<<"host">> => Authority}) || _ <- lists:seq(1, 5)],
	timer:sleep(500),
	{error, no_connection_available, _} = gun_pool:get("/delay", #{<<"host">> => Authority}).

max_streams_h2_size_1_retry(_) ->
	doc("Confirm connection checkout is retried when the maximum number "
		"of streams is reached for HTTP/2 connections."),
	ProtoOpts = do_proto_opts(),
	{ok, _} = cowboy:start_clear(?FUNCTION_NAME, [], ProtoOpts#{
		max_concurrent_streams => 5
	}),
	Port = ranch:get_port(?FUNCTION_NAME),
	Authority = ["localhost:", integer_to_binary(Port)],
	{ok, ManagerPid} = gun_pool:start_pool("localhost", Port, #{
		conn_opts => #{protocols => [http2]},
		size => 1
	}),
	gun_pool:await_up(ManagerPid),
	[{async, _} = gun_pool:get("/delay", #{<<"host">> => Authority}) || _ <- lists:seq(1, 5)],
	timer:sleep(500),
	{error, no_connection_available, _} = gun_pool:get("/delay", #{<<"host">> => Authority}),
	{async, _} = gun_pool:get("/delay", #{<<"host">> => Authority}, #{
		checkout_retry => [100, 500, 500, 500, 500, 500, 500]
	}).

max_streams_h2_size_2(_) ->
	doc("Confirm requests are rejected when the maximum number "
		"of streams is reached for HTTP/2 connections."),
	ProtoOpts = do_proto_opts(),
	{ok, _} = cowboy:start_clear(?FUNCTION_NAME, [], ProtoOpts#{
		max_concurrent_streams => 5
	}),
	Port = ranch:get_port(?FUNCTION_NAME),
	Authority = ["localhost:", integer_to_binary(Port)],
	{ok, ManagerPid} = gun_pool:start_pool("localhost", Port, #{
		conn_opts => #{protocols => [http2]},
		size => 2
	}),
	gun_pool:await_up(ManagerPid),
	[begin
		{async, _} = gun_pool:get("/delay", #{<<"host">> => Authority}),
		%% We need to wait a bit for the request to be sent because the
		%% request is sent and counted asynchronously.
		timer:sleep(10)
	end || _ <- lists:seq(1, 10)],
	timer:sleep(500),
	{error, no_connection_available, _} = gun_pool:get("/delay", #{<<"host">> => Authority}).

max_streams_h2_size_2_retry(_) ->
	doc("Confirm connection checkout is retried when the maximum number "
		"of streams is reached for HTTP/2 connections."),
	ProtoOpts = do_proto_opts(),
	{ok, _} = cowboy:start_clear(?FUNCTION_NAME, [], ProtoOpts#{
		max_concurrent_streams => 5
	}),
	Port = ranch:get_port(?FUNCTION_NAME),
	Authority = ["localhost:", integer_to_binary(Port)],
	{ok, ManagerPid} = gun_pool:start_pool("localhost", Port, #{
		conn_opts => #{protocols => [http2]},
		size => 2
	}),
	gun_pool:await_up(ManagerPid),
	[begin
		{async, _} = gun_pool:get("/delay", #{<<"host">> => Authority}),
		%% We need to wait a bit for the request to be sent because the
		%% request is sent and counted asynchronously.
		timer:sleep(10)
	end || _ <- lists:seq(1, 10)],
	timer:sleep(500),
	{error, no_connection_available, _} = gun_pool:get("/delay", #{<<"host">> => Authority}),
	{async, _} = gun_pool:get("/delay", #{<<"host">> => Authority}, #{
		checkout_retry => [100, 500, 500, 500, 500, 500, 500]
	}).

kill_restart_h1(Config) ->
	doc("Confirm the Gun process is restarted and the pool operational "
		"after an HTTP/1.1 Gun process has crashed."),
	Port = config(port, Config),
	Authority = ["localhost:", integer_to_binary(Port)],
	{ok, ManagerPid} = gun_pool:start_pool("localhost", Port, #{
		conn_opts => #{protocols => [http]},
		scope => ?FUNCTION_NAME
	}),
	gun_pool:await_up(ManagerPid),
	Streams1 = [{async, _} = gun_pool:get("/",
		#{<<"host">> => Authority},
		#{scope => ?FUNCTION_NAME}
	) || _ <- lists:seq(1, 8)],
	_ = [begin
		{response, nofin, 200, _} = gun_pool:await(StreamRef),
		{ok, <<"Hello world!">>} = gun_pool:await_body(StreamRef)
	end || {async, StreamRef} <- Streams1],
	%% Get a connection and kill the process.
	{operational, #{conns := Conns}} = gun_pool:info(ManagerPid),
	ConnPid = hd(maps:keys(Conns)),
	MRef = monitor(process, ConnPid),
	exit(ConnPid, {shutdown, ?FUNCTION_NAME}),
	receive {'DOWN', MRef, process, ConnPid, _} -> ok end,
	{degraded, _} = gun_pool:info(ManagerPid),
	gun_pool:await_up(ManagerPid),
	Streams2 = [{async, _} = gun_pool:get("/",
		#{<<"host">> => Authority},
		#{scope => ?FUNCTION_NAME}
	) || _ <- lists:seq(1, 8)],
	_ = [begin
		{response, nofin, 200, _} = gun_pool:await(StreamRef),
		{ok, <<"Hello world!">>} = gun_pool:await_body(StreamRef)
	end || {async, StreamRef} <- Streams2].

kill_restart_h2(Config) ->
	doc("Confirm the Gun process is restarted and the pool operational "
		"after an HTTP/2 Gun process has crashed."),
	Port = config(port, Config),
	Authority = ["localhost:", integer_to_binary(Port)],
	{ok, ManagerPid} = gun_pool:start_pool("localhost", Port, #{
		conn_opts => #{protocols => [http2]},
		scope => ?FUNCTION_NAME
	}),
	gun_pool:await_up(ManagerPid),
	Streams1 = [{async, _} = gun_pool:get("/",
		#{<<"host">> => Authority},
		#{scope => ?FUNCTION_NAME}
	) || _ <- lists:seq(1, 800)],
	_ = [begin
		{response, nofin, 200, _} = gun_pool:await(StreamRef),
		{ok, <<"Hello world!">>} = gun_pool:await_body(StreamRef)
	end || {async, StreamRef} <- Streams1],
	%% Get a connection and kill the process.
	{operational, #{conns := Conns}} = gun_pool:info(ManagerPid),
	ConnPid = hd(maps:keys(Conns)),
	MRef = monitor(process, ConnPid),
	exit(ConnPid, {shutdown, ?FUNCTION_NAME}),
	receive {'DOWN', MRef, process, ConnPid, _} -> ok end,
	{degraded, _} = gun_pool:info(ManagerPid),
	gun_pool:await_up(ManagerPid),
	Streams2 = [{async, _} = gun_pool:get("/",
		#{<<"host">> => Authority},
		#{scope => ?FUNCTION_NAME}
	) || _ <- lists:seq(1, 800)],
	_ = [begin
		{response, nofin, 200, _} = gun_pool:await(StreamRef),
		{ok, <<"Hello world!">>} = gun_pool:await_body(StreamRef)
	end || {async, StreamRef} <- Streams2].

%% @todo kill_restart_ws

reconnect_h1(_) ->
	doc("Confirm the Gun process reconnects automatically for HTTP/1.1 connections."),
	ProtoOpts = do_proto_opts(),
	{ok, _} = cowboy:start_clear(?FUNCTION_NAME, [], ProtoOpts#{
		idle_timeout => 500,
		scope => ?FUNCTION_NAME
	}),
	Port = ranch:get_port(?FUNCTION_NAME),
	Authority = ["localhost:", integer_to_binary(Port)],
	{ok, ManagerPid} = gun_pool:start_pool("localhost", Port, #{
		conn_opts => #{protocols => [http]}
	}),
	gun_pool:await_up(ManagerPid),
	Streams1 = [{async, _} = gun_pool:get("/", #{<<"host">> => Authority}) || _ <- lists:seq(1, 8)],
	_ = [begin
		{response, nofin, 200, _} = gun_pool:await(StreamRef),
		{ok, <<"Hello world!">>} = gun_pool:await_body(StreamRef)
	end || {async, StreamRef} <- Streams1],
	%% Wait for the idle timeout to trigger.
	timer:sleep(600),
%		{degraded, _} = gun_pool:info(ManagerPid),
	gun_pool:await_up(ManagerPid),
	Streams2 = [{async, _} = gun_pool:get("/", #{<<"host">> => Authority}) || _ <- lists:seq(1, 8)],
	_ = [begin
		{response, nofin, 200, _} = gun_pool:await(StreamRef),
		{ok, <<"Hello world!">>} = gun_pool:await_body(StreamRef)
	end || {async, StreamRef} <- Streams2].

reconnect_h2(Config) ->
	doc("Confirm the Gun process reconnects automatically for HTTP/2 connections."),
	Port = config(port, Config),
	Authority = ["localhost:", integer_to_binary(Port)],
	{ok, ManagerPid} = gun_pool:start_pool("localhost", Port, #{
		conn_opts => #{protocols => [http2]},
		scope => ?FUNCTION_NAME
	}),
	gun_pool:await_up(ManagerPid),
	Streams1 = [{async, _} = gun_pool:get("/",
		#{<<"host">> => Authority},
		#{scope => ?FUNCTION_NAME}
	) || _ <- lists:seq(1, 800)],
	_ = [begin
		{response, nofin, 200, _} = gun_pool:await(StreamRef),
		{ok, <<"Hello world!">>} = gun_pool:await_body(StreamRef)
	end || {async, StreamRef} <- Streams1],
	%% Wait for the idle timeout to trigger.
	timer:sleep(600),
%		{degraded, _} = gun_pool:info(ManagerPid),
	gun_pool:await_up(ManagerPid),
	Streams2 = [{async, _} = gun_pool:get("/",
		#{<<"host">> => Authority},
		#{scope => ?FUNCTION_NAME}
	) || _ <- lists:seq(1, 800)],
	_ = [begin
		{response, nofin, 200, _} = gun_pool:await(StreamRef),
		{ok, <<"Hello world!">>} = gun_pool:await_body(StreamRef)
	end || {async, StreamRef} <- Streams2].

%% @todo reconnect_ws

stop_pool(Config) ->
	doc("Confirm the pool can be stopped."),
	Port = config(port, Config),
	{ok, ManagerPid} = gun_pool:start_pool("localhost", Port, #{scope => ?FUNCTION_NAME}),
	gun_pool:await_up(ManagerPid),
	gun_pool:stop_pool("localhost", Port, #{scope => ?FUNCTION_NAME}).

degraded_configuration_error(Config) ->
	case os:type() of
		{win32, _} ->
			{skip, "The initial connect timeout on Windows is too large."};
		_ ->
			do_degraded_configuration_error(Config)
	end.

do_degraded_configuration_error(Config) ->
	doc("Confirm the pool ends up in a degraded state "
		"when connection is impossible because of bad configuration."),
	Port = config(port, Config),
	%% We attempt to connect to an unreachable IP.
	{ok, ManagerPid} = gun_pool:start_pool({20, 20, 20, 1}, Port, #{
		conn_opts => #{tcp_opts => [{ip, {127, 0, 0, 1}}]},
		scope => ?FUNCTION_NAME,
		size => 1
	}),
	%% Wait for the lookup/connect to fail.
	timer:sleep(500),
	{degraded, #{conns := Conns}} = gun_pool:info(ManagerPid),
	true = Conns =:= #{},
	%% We can stop the pool even if degraded.
	gun_pool:stop_pool({20, 20, 20, 1}, Port, #{scope => ?FUNCTION_NAME}).
