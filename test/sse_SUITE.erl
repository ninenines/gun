%% Copyright (c) 2017-2018, Loïc Hoguin <essen@ninenines.eu>
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

-import(ct_helper, [config/2]).

all() ->
	[http, http2].

init_per_suite(Config) ->
	gun_test:init_cowboy_tls(?MODULE, #{
		env => #{dispatch => cowboy_router:compile(init_routes())}
	}, Config).

end_per_suite(Config) ->
	cowboy:stop_listener(config(ref, Config)).

init_routes() -> [
	{"localhost", [
		{"/", sse_clock_h, []}
	]}
].

http(Config) ->
	{ok, Pid} = gun:open("localhost", config(port, Config), #{
		transport => tls,
		protocols => [http],
		http_opts => #{content_handlers => [gun_sse_h, gun_data_h]}
	}),
	{ok, http} = gun:await_up(Pid),
	common(Pid).

http2(Config) ->
	{ok, Pid} = gun:open("localhost", config(port, Config), #{
		transport => tls,
		protocols => [http2],
		http2_opts => #{content_handlers => [gun_sse_h, gun_data_h]}
	}),
	{ok, http2} = gun:await_up(Pid),
	common(Pid).

common(Pid) ->
	Ref = gun:get(Pid, "/", [
		{<<"host">>, <<"localhost">>},
		{<<"accept">>, <<"text/event-stream">>}
	]),
	receive
		{gun_response, Pid, Ref, nofin, 200, Headers} ->
			{_, <<"text/event-stream">>}
				= lists:keyfind(<<"content-type">>, 1, Headers),
			event_loop(Pid, Ref, 3)
	after 5000 ->
		error(timeout)
	end.

event_loop(Pid, _, 0) ->
	gun:close(Pid);
event_loop(Pid, Ref, N) ->
	receive
		{gun_sse, Pid, Ref, Event} ->
			#{
				last_event_id := <<>>,
				event_type := <<"message">>,
				data := Data
			} = Event,
			true = is_list(Data) orelse is_binary(Data),
			event_loop(Pid, Ref, N - 1)
	after 10000 ->
		error(timeout)
	end.
