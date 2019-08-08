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

-module(ws_SUITE).
-compile(export_all).
-compile(nowarn_export_all).

-import(ct_helper, [config/2]).
-import(ct_helper, [doc/1]).

%% ct.

all() ->
	[{group, ws}].

groups() ->
	[{ws, [], ct_helper:all(?MODULE)}].

init_per_suite(Config) ->
	Routes = [
		{"/", ws_echo_h, []},
		{"/reject", ws_reject_h, []}
	],
	{ok, _} = cowboy:start_clear(ws, [], #{env => #{
		dispatch => cowboy_router:compile([{'_', Routes}])
	}}),
	Port = ranch:get_port(ws),
	[{port, Port}|Config].

end_per_suite(_) ->
	cowboy:stop_listener(ws).

%% Tests.

await(Config) ->
	doc("Ensure gun:await/2 can be used to receive Websocket frames."),
	{ok, ConnPid} = gun:open("localhost", config(port, Config)),
	{ok, _} = gun:await_up(ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/", []),
	{upgrade, [<<"websocket">>], _} = gun:await(ConnPid, StreamRef),
	Frame = {text, <<"Hello!">>},
	gun:ws_send(ConnPid, Frame),
	{ws, Frame} = gun:await(ConnPid, StreamRef),
	gun:close(ConnPid).

reject_upgrade(Config) ->
	doc("Ensure Websocket connections can be rejected."),
	{ok, ConnPid} = gun:open("localhost", config(port, Config)),
	{ok, _} = gun:await_up(ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/reject", []),
	receive
		{gun_response, ConnPid, StreamRef, nofin, 400, _} ->
			{ok, <<"Upgrade rejected">>} = gun:await_body(ConnPid, StreamRef, 1000),
			gun:close(ConnPid);
		Msg ->
			error({fail, Msg})
	after 1000 ->
		error(timeout)
	end.

send_many(Config) ->
	doc("Ensure we can send a list of frames in one gun:ws_send call."),
	{ok, ConnPid} = gun:open("localhost", config(port, Config)),
	{ok, _} = gun:await_up(ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/", []),
	{upgrade, [<<"websocket">>], _} = gun:await(ConnPid, StreamRef),
	Frame1 = {text, <<"Hello!">>},
	Frame2 = {binary, <<"World!">>},
	gun:ws_send(ConnPid, [Frame1, Frame2]),
	{ws, Frame1} = gun:await(ConnPid, StreamRef),
	{ws, Frame2} = gun:await(ConnPid, StreamRef),
	gun:close(ConnPid).

send_many_close(Config) ->
	doc("Ensure we can send a list of frames in one gun:ws_send call, including a close frame."),
	{ok, ConnPid} = gun:open("localhost", config(port, Config)),
	{ok, _} = gun:await_up(ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/", []),
	{upgrade, [<<"websocket">>], _} = gun:await(ConnPid, StreamRef),
	Frame1 = {text, <<"Hello!">>},
	Frame2 = {binary, <<"World!">>},
	gun:ws_send(ConnPid, [Frame1, Frame2, close]),
	{ws, Frame1} = gun:await(ConnPid, StreamRef),
	{ws, Frame2} = gun:await(ConnPid, StreamRef),
	{ws, close} = gun:await(ConnPid, StreamRef),
	gun:close(ConnPid).
