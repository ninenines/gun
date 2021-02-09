%% Copyright (c) 2021, Loïc Hoguin <essen@ninenines.eu>
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
	doc("Confirm the pool can be used for HTTP/1.1 connections."),
	Port = config(port, Config),
	{ok, ManagerPid} = gun_pool:start_pool("localhost", Port, #{scope => ?FUNCTION_NAME}),
	gun_pool:await_up(ManagerPid),
	gun_pool:stop_pool("localhost", Port, #{scope => ?FUNCTION_NAME}).
