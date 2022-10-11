%% Copyright (c) 2017-2020, Loïc Hoguin <essen@ninenines.eu>
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
	[http_clock, http2_clock, lone_id, with_mime_param, http_clock_close].

init_per_suite(Config) ->
	gun_test:init_cowboy_tls(?MODULE, #{
		env => #{dispatch => cowboy_router:compile(init_routes())}
	}, Config).

end_per_suite(Config) ->
	cowboy:stop_listener(config(ref, Config)).

init_routes() -> [
	{"localhost", [
		{"/clock", sse_clock_h, date},
		{"/lone_id", sse_lone_id_h, []},
		{"/with_mime_param", sse_mime_param_h, []},
		{"/connection_close", sse_clock_close_h, []}
	]}
].

http_clock(Config) ->
	{ok, Pid} = gun:open("localhost", config(port, Config), #{
		transport => tls,
		tls_opts => [{verify, verify_none}, {versions, ['tlsv1.2']}],
		protocols => [http],
		http_opts => #{content_handlers => [gun_sse_h, gun_data_h]}
	}),
	{ok, http} = gun:await_up(Pid),
	do_clock_common(Pid, "/clock").

http2_clock(Config) ->
	{ok, Pid} = gun:open("localhost", config(port, Config), #{
		transport => tls,
		tls_opts => [{verify, verify_none}, {versions, ['tlsv1.2']}],
		protocols => [http2],
		http2_opts => #{content_handlers => [gun_sse_h, gun_data_h]}
	}),
	{ok, http2} = gun:await_up(Pid),
	do_clock_common(Pid, "/clock").

http_clock_close(Config) ->
	{ok, Pid} = gun:open("localhost", config(port, Config), #{
		transport => tls,
		tls_opts => [{verify, verify_none}, {versions, ['tlsv1.2']}],
		protocols => [http],
		http_opts => #{
			content_handlers => [gun_sse_h, gun_data_h],
			closing_timeout => 1000
		}
	}),
	{ok, http} = gun:await_up(Pid),
	do_clock_common(Pid, "/connection_close").

do_clock_common(Pid, Path) ->
	Ref = gun:get(Pid, Path, [
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
			ct:pal("Event: ~p~n", [Event]),
			#{
				last_event_id := <<>>,
				event_type := <<"message">>,
				data := Data
			} = Event,
			true = is_list(Data) orelse is_binary(Data),
			event_loop(Pid, Ref, N - 1);
		Other ->
			ct:pal("Other: ~p~n", [Other])
	after 10000 ->
		error(timeout)
	end.

lone_id(Config) ->
	{ok, Pid} = gun:open("localhost", config(port, Config), #{
		transport => tls,
		tls_opts => [{verify, verify_none}, {versions, ['tlsv1.2']}],
		protocols => [http],
		http_opts => #{content_handlers => [gun_sse_h, gun_data_h]}
	}),
	{ok, http} = gun:await_up(Pid),
	Ref = gun:get(Pid, "/lone_id", [
		{<<"host">>, <<"localhost">>},
		{<<"accept">>, <<"text/event-stream">>}
	]),
	receive
		{gun_response, Pid, Ref, nofin, 200, Headers} ->
			{_, <<"text/event-stream">>}
				= lists:keyfind(<<"content-type">>, 1, Headers),
			receive
				{gun_sse, Pid, Ref, Event} ->
					#{last_event_id := <<"hello">>} = Event,
					1 = maps:size(Event),
					gun:close(Pid)
			after 10000 ->
				error(timeout)
			end
	after 5000 ->
		error(timeout)
	end.

with_mime_param(Config) ->
	{ok, Pid} = gun:open("localhost", config(port, Config), #{
		transport => tls,
		tls_opts => [{verify, verify_none}, {versions, ['tlsv1.2']}],
		protocols => [http],
		http_opts => #{content_handlers => [gun_sse_h, gun_data_h]}
	}),
	{ok, http} = gun:await_up(Pid),
	Ref = gun:get(Pid, "/with_mime_param", [
		{<<"host">>, <<"localhost">>},
		{<<"accept">>, <<"text/event-stream">>}
	]),
	receive
		{gun_response, Pid, Ref, nofin, 200, Headers} ->
			{_, <<"text/event-stream;", _Params/binary>>}
				= lists:keyfind(<<"content-type">>, 1, Headers),
			receive
				{gun_sse, Pid, Ref, Event} ->
					#{last_event_id := <<"hello">>} = Event,
					1 = maps:size(Event),
					gun:close(Pid)
			after 10000 ->
				error(timeout)
			end
	after 5000 ->
		error(timeout)
	end.
