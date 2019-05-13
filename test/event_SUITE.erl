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
	ct_helper:all(?MODULE).

init_per_suite(Config) ->
	{ok, _} = cowboy:start_clear(?MODULE, [], #{env => #{
		dispatch => cowboy_router:compile([{'_', [{"/", ws_echo, []}]}])
	}}),
	OriginPort = ranch:get_port(?MODULE),
	[{origin_port, OriginPort}|Config].

end_per_suite(_) ->
	ok = cowboy:stop_listener(?MODULE).

%% init.

init(_) ->
	doc("Confirm that the init event callback is called."),
	Self = self(),
	Opts = #{event_handler => {?MODULE, Self}},
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

connect_start(_) ->
	doc("Confirm that the connect_start event callback is called."),
	Self = self(),
	Opts = #{event_handler => {?MODULE, Self}},
	{ok, Pid} = gun:open("localhost", 12345, Opts),
	#{
		host := "localhost",
		port := 12345,
		transport := tcp,
		transport_opts := _,
		timeout := _
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

connect_end_error(_) ->
	doc("Confirm that the connect_end event callback is called on connect failure."),
	Self = self(),
	Opts = #{event_handler => {?MODULE, Self}},
	{ok, Pid} = gun:open("localhost", 12345, Opts),
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
	Self = self(),
	Opts = #{event_handler => {?MODULE, Self}},
	OriginPort = config(origin_port, Config),
	{ok, Pid} = gun:open("localhost", OriginPort, Opts),
	#{
		host := "localhost",
		port := OriginPort,
		transport := tcp,
		transport_opts := _,
		timeout := _,
		socket := _,
		protocol := http
	} = do_receive_event(connect_end),
	gun:close(Pid).

disconnect(_) ->
	doc("Confirm that the disconnect event callback is called on disconnect."),
	Self = self(),
	Opts = #{event_handler => {?MODULE, Self}},
	{ok, OriginPid, OriginPort} = init_origin(tcp),
	{ok, Pid} = gun:open("localhost", OriginPort, Opts),
	{ok, http} = gun:await_up(Pid),
	%% We make the origin exit to trigger a disconnect.
	unlink(OriginPid),
	exit(OriginPid, shutdown),
	#{
		reason := closed
	} = do_receive_event(disconnect),
	gun:close(Pid).

%% Internal.

do_receive_event(Event) ->
	receive
		{Event, EventData} ->
			EventData
	after 5000 ->
		error(timeout)
	end.

%% gun_event callbacks.

init(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

connect_start(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

connect_end(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

disconnect(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.
