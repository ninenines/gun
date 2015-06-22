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

-module(gun_SUITE).
-export([all/0]).
-export([owner_killed_detection/1]).

all() ->
	[owner_killed_detection].

owner_killed_detection(_) ->
	ok = wait_for(count_equal_fun(0)),

	Pid = spawn(fun init/0),

	ok = wait_for(count_equal_fun(1)),

	Pid ! shutdown,

	ok = wait_for(count_equal_fun(0)).

wait_for(Fun) ->
	wait_for(Fun, 1000).

wait_for(_Fun, Timeout) when Timeout =< 0 ->
	error;
wait_for(Fun, Timeout) ->
	case Fun() of
		true -> ok;
		false ->
			timer:sleep(10),
			wait_for(Fun, Timeout - 10)
	end.

count_equal_fun(N) ->
	fun () -> N == count_active(gun_sup) end.

count_active(SupName) ->
	Count = supervisor:count_children(SupName),
	{active, Active} = lists:keyfind(active, 1, Count),
	Active.

init() ->
	{ok, Conn} = gun:open("google.com", 80),
	loop(Conn).

loop(Conn) ->
	receive
		shutdown ->
			ok;
		X ->
			ct:print("INFO: ~p~n", [X]),
			loop(Conn)
	end.
