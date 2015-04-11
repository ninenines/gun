%% Copyright (c) 2015, Loïc Hoguin <essen@ninenines.eu>
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

-module(spdy_SUITE).
-compile(export_all).

-import(ct_helper, [doc/1]).

all() -> [{group, spdy31}].

groups() -> [{spdy31, [parallel], ct_helper:all(?MODULE)}].

goaway_on_close(Config) ->
	doc("Send a GOAWAY when the client closes the connection (spdy-protocol-draft3-1 2.1)"),
	{ok, ServerPid, Port} = spdy_server:start_link(),
	{ok, ConnPid} = gun:open("localhost", Port, #{transport=>ssl}),
	{ok, spdy} = gun:await_up(ConnPid),
	gun:close(ConnPid),
	[{goaway, 0, ok}] = spdy_server:stop(ServerPid).

goaway_on_shutdown(Config) ->
	doc("Send a GOAWAY when the client closes the connection (spdy-protocol-draft3-1 2.1)"),
	{ok, ServerPid, Port} = spdy_server:start_link(),
	{ok, ConnPid} = gun:open("localhost", Port, #{transport=>ssl}),
	{ok, spdy} = gun:await_up(ConnPid),
	gun:shutdown(ConnPid),
	[{goaway, 0, ok}] = spdy_server:stop(ServerPid).
