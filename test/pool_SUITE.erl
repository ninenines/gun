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
-import(gun_test, [init_origin/3]).
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

setup_down_no_crash(_Config) ->
	doc("A socket close while setup is in progress sends gun_down and "
		"the Gun process retries. The same pid must be marked down, "
		"then become setup again on the next gun_up."),
	{ok, OriginPid, OriginPort} = init_origin(tcp, http, fun do_hold_then_close/4),
	Scope = ?FUNCTION_NAME,
	Parent = self(),
	{ok, ManagerPid} = gun_pool:start_pool("localhost", OriginPort, #{
		conn_opts => #{
			protocols => [http],
			retry => 5,
			retry_fun => fun(_, _) -> #{retries => 4, timeout => 800} end,
			event_handler => {gun_test_event_h, Parent}
		},
		scope => Scope,
		size => 1,
		setup_fun => {fun(ConnPid, {gun_up, _, _}, SetupState) ->
			Parent ! {setup, ConnPid},
			{setup, SetupState}
		end, undefined}
	}),
	handshake_completed = receive_from(OriginPid),
	ConnPid = do_receive_tag(setup),
	{degraded, #{conns := #{ConnPid := {setup, _}}}} = gun_pool:info(ManagerPid),
	OriginPid ! {self(), close_it},
	receive
		{ConnPid, disconnect, _} -> ok
	after 5000 ->
		error(disconnect_timeout)
	end,
	%% disconnect/2 runs this event before it sends gun_down.
	%% gun:info/1 returns after that send, so the pool call is
	%% queued behind gun_down.
	_ = gun:info(ConnPid),
	{degraded, #{conns := #{ConnPid := down}}} = gun_pool:info(ManagerPid),
	ConnPid = do_receive_tag(setup),
	{degraded, #{conns := #{ConnPid := {setup, _}}}} = gun_pool:info(ManagerPid),
	OriginPid ! {self(), stop},
	gun_pool:stop_pool("localhost", OriginPort, #{scope => Scope}).

do_hold_then_close(Parent, ListenSocket, Socket, Transport) ->
	receive {Parent, close_it} -> ok end,
	Transport:close(Socket),
	{ok, Socket2} = gen_tcp:accept(ListenSocket, 5000),
	receive {Parent, stop} -> Transport:close(Socket2) end.

setup_settings_no_crash(Config) ->
	doc("SETTINGS that arrive while an HTTP/2 connection is still in "
		"setup are kept when the Websocket upgrade completes it. "
		"SETTINGS after the connection is up are kept as well."),
	{ok, _} = cowboy:start_clear(?FUNCTION_NAME, [], #{
		enable_connect_protocol => true,
		env => #{dispatch => cowboy_router:compile([{'_', [
			{"/ws", ws_echo_h, []}
		]}])}
	}),
	Port = ranch:get_port(?FUNCTION_NAME),
	Scope = ?FUNCTION_NAME,
	Parent = self(),
	{ok, ManagerPid} = gun_pool:start_pool("localhost", Port, #{
		conn_opts => #{protocols => [http2]},
		scope => Scope,
		size => 1,
		setup_fun => {fun
			(ConnPid, {gun_up, _, http2}, SetupState) ->
				Parent ! {setup, ConnPid},
				{setup, SetupState};
			(ConnPid, {gun_upgrade, _, StreamRef, _, _}, _) ->
				Parent ! {up, ConnPid, StreamRef},
				{up, http2, #{ws => StreamRef}};
			(_, _, SetupState) ->
				{setup, SetupState}
		end, undefined}
	}),
	ConnPid = do_receive_tag(setup),
	%% The server preface is SETTINGS. The PING ack is a later
	%% frame, so settings_changed is already queued for the pool.
	ok = do_ping(ConnPid),
	{degraded, #{conns := #{ConnPid := {setup, _}}}} = gun_pool:info(ManagerPid),
	#{ConnPid := Settings} = do_http2_settings(ManagerPid),
	true = maps:is_key(enable_connect_protocol, Settings),
	%% Extended CONNECT is sent once SETTINGS are buffered. The
	%% gun_upgrade that follows is what marks the connection up.
	_ = gun:ws_upgrade(ConnPid, "/ws", [], #{
		reply_to => ManagerPid,
		default_protocol => pool_ws_handler,
		user_opts => self()
	}),
	StreamRef = receive
		{up, Pid, Ref} when Pid =:= ConnPid -> Ref
	after 5000 ->
		error(upgrade_timeout)
	end,
	{operational, #{
		conns := #{ConnPid := {up, http2, Settings}},
		conns_meta := #{ConnPid := #{ws := StreamRef}}
	}} = gun_pool:info(ManagerPid),
	true = is_reference(StreamRef),
	#{} = do_http2_settings(ManagerPid),
	gun_pool:stop_pool("localhost", Port, #{scope => Scope}),
	cowboy:stop_listener(?FUNCTION_NAME),
	Port2 = config(port, Config),
	Scope2 = {?FUNCTION_NAME, up},
	{ok, ManagerPid2} = gun_pool:start_pool("localhost", Port2, #{
		conn_opts => #{protocols => [http2]},
		scope => Scope2,
		size => 1
	}),
	gun_pool:await_up(ManagerPid2),
	{operational, #{conns := Conns2}} = gun_pool:info(ManagerPid2),
	[ConnPid2] = maps:keys(Conns2),
	ok = do_ping(ConnPid2),
	{operational, #{conns := #{ConnPid2 := {up, http2, Settings2}}}} = gun_pool:info(ManagerPid2),
	true = map_size(Settings2) > 0,
	gun_pool:stop_pool("localhost", Port2, #{scope => Scope2}).

stray_gun_upgrade_no_crash(Config) ->
	doc("setup_fun may return before the Websocket upgrade reply "
		"arrives. That gun_upgrade must not crash the pool while "
		"another connection is still in setup."),
	Port = config(port, Config),
	Scope = ?FUNCTION_NAME,
	Parent = self(),
	Tid = ets:new(?FUNCTION_NAME, [public, set]),
	ets:insert(Tid, {n, 0}),
	{ok, ManagerPid} = gun_pool:start_pool("localhost", Port, #{
		conn_opts => #{
			protocols => [http],
			event_handler => {gun_test_event_h, Parent},
			ws_opts => #{
				default_protocol => pool_ws_handler,
				user_opts => Parent
			}
		},
		scope => Scope,
		size => 2,
		setup_fun => {fun
			(ConnPid, {gun_up, _, http}, SetupState) ->
				case ets:update_counter(Tid, n, 1) of
					1 ->
						%% The upgrade reply is delivered to the pool.
						%% Returning up now leaves that gun_upgrade for
						%% a connection that is no longer in setup.
						_ = gun:ws_upgrade(ConnPid, "/ws"),
						Parent ! {up, ConnPid},
						{up, http, #{}};
					_ ->
						Parent ! {setup, ConnPid},
						{setup, SetupState}
				end;
			(_, {gun_upgrade, _, _, _, _}, SetupState) ->
				ets:insert(Tid, {upgrade, true}),
				{setup, SetupState};
			(_, _, SetupState) ->
				{setup, SetupState}
		end, undefined}
	}),
	{UpPid, SetupPid} = do_receive_up_and_setup(),
	%% gun_upgrade is sent before protocol_changed, so this
	%% info call is queued behind that gun_upgrade.
	receive
		{UpPid, protocol_changed, #{protocol := ws}} -> ok
	after 5000 ->
		error(ws_timeout)
	end,
	{degraded, #{conns := #{
		UpPid := {up, http, #{}},
		SetupPid := {setup, _}
	}}} = gun_pool:info(ManagerPid),
	[] = ets:lookup(Tid, upgrade),
	true = ets:delete(Tid),
	gun_pool:stop_pool("localhost", Port, #{scope => Scope}).

%% #state{} keeps buffered HTTP/2 SETTINGS in this field.
do_http2_settings(ManagerPid) ->
	{_, {state, _, _, _, _, _, _, _, HTTP2Settings}} = sys:get_state(ManagerPid),
	HTTP2Settings.

do_receive_tag(Tag) ->
	receive
		{Tag, Pid} when is_pid(Pid) -> Pid
	after 5000 ->
		error({timeout, Tag})
	end.

do_receive_up_and_setup() ->
	do_receive_up_and_setup(undefined, undefined).

do_receive_up_and_setup(Up, Setup) when is_pid(Up), is_pid(Setup) ->
	{Up, Setup};
do_receive_up_and_setup(Up, Setup) ->
	receive
		{up, Pid} when is_pid(Pid) ->
			do_receive_up_and_setup(Pid, Setup);
		{setup, Pid} when is_pid(Pid) ->
			do_receive_up_and_setup(Up, Pid)
	after 5000 ->
		error({timeout, Up, Setup})
	end.

do_ping(ConnPid) ->
	Ref = gun:ping(ConnPid),
	receive
		{gun_notify, ConnPid, ping_ack, Ref} -> ok
	after 5000 ->
		error({ping_timeout, ConnPid})
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
