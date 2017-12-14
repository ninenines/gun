%% Copyright (c) 2017, Loïc Hoguin <essen@ninenines.eu>
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

-module(sse_SUITE).
-compile(export_all).
-compile(nowarn_export_all).

all() ->
	[http, http2].

http(_) ->
	{ok, Pid} = gun:open("sse.now.sh", 443, #{
		protocols => [http],
		http_opts => #{content_handlers => [gun_sse, gun_data]}
	}),
	{ok, http} = gun:await_up(Pid),
	common(Pid).

http2(_) ->
	{ok, Pid} = gun:open("sse.now.sh", 443, #{
		protocols => [http2],
		http2_opts => #{content_handlers => [gun_sse, gun_data]}
	}),
	{ok, http2} = gun:await_up(Pid),
	common(Pid).

common(Pid) ->
	Ref = gun:get(Pid, "/", [
		{<<"host">>, <<"sse.now.sh">>},
		{<<"accept">>, <<"text/event-stream">>}
	]),
	receive
		{gun_response, Pid, Ref, nofin, Status, Headers} ->
			ct:print("response ~p ~p", [Status, Headers]),
			event_loop(Pid, Ref, 3)
	after 5000 ->
		error(timeout)
	end.

event_loop(_, _, 0) ->
	ok;
event_loop(Pid, Ref, N) ->
	receive
		{gun_sse, Pid, Ref, Event} ->
			ct:print("event ~p", [Event]),
			event_loop(Pid, Ref, N - 1)
	after 10000 ->
		error(timeout)
	end.
