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

-module(sse_SUITE).
-compile(export_all).
-compile(nowarn_export_all).

-import(ct_helper, [config/2]).

all() ->
	[http_clock, http2_clock, lone_id, malformed_content_type_no_crash,
		max_event_size_complete, max_event_size_default, max_event_size_http,
		max_event_size_http2,
		max_event_size_http2_fin, max_event_size_infinity, max_event_size_option,
		with_mime_param, http_clock_close].

init_per_suite(Config) ->
	gun_test:init_cowboy_tls(?MODULE, #{
		env => #{dispatch => cowboy_router:compile(init_routes())}
	}, Config).

end_per_suite(Config) ->
	cowboy:stop_listener(config(ref, Config)).

malformed_content_type_no_crash(_) ->
	disable = gun_sse_h:init(self(), make_ref(), 200,
		[{<<"content-type">>, <<"text">>}], #{}),
	disable = gun_sse_h:init(self(), make_ref(), 200,
		[{<<"content-type">>, <<"text/plain">>}], #{}).

init_routes() -> [
	{"localhost", [
		{"/clock", sse_clock_h, date},
		{"/lone_id", sse_lone_id_h, []},
		{"/sized", sse_sized_h, []},
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

%% A finished event is delivered even when it is larger than the limit.
%% An unfinished event of that size is rejected.
max_event_size_complete(_) ->
	Headers = [{<<"content-type">>, <<"text/event-stream">>}],
	{ok, State0} = gun_sse_h:init(self(), make_ref(), 200, Headers,
		#{max_event_size => 1}),
	{done, 1, State} = gun_sse_h:handle(nofin, <<"data: hi\n\n">>, State0),
	receive
		{gun_sse, _, _, #{data := Data, event_type := <<"message">>}} ->
			<<"hi">> = iolist_to_binary(Data)
	after 1000 ->
		error(timeout)
	end,
	{error, {limit_reached, _}} = gun_sse_h:handle(nofin, <<"data: hi\n">>, State).

%% The atom `gun_sse_h` keeps 10 KiB and rejects one byte more.
max_event_size_default(_) ->
	Headers = [{<<"content-type">>, <<"text/event-stream">>}],
	{ok, State0} = gun_sse_h:init(self(), make_ref(), 200, Headers, #{}),
	{done, 0, _} = gun_sse_h:handle(nofin, binary:copy(<<$a>>, 10240), State0),
	{ok, State1} = gun_sse_h:init(self(), make_ref(), 200, Headers, #{}),
	{error, {limit_reached, _}} = gun_sse_h:handle(nofin,
		binary:copy(<<$a>>, 10241), State1).

%% An unfinished event above the limit closes the HTTP/1.1 connection.
max_event_size_http(Config) ->
	Human = "The Server-Sent Events event is too large.",
	{ok, Pid} = gun:open("localhost", config(port, Config), #{
		transport => tls,
		tls_opts => [{verify, verify_none}, {versions, ['tlsv1.2']}],
		protocols => [http],
		http_opts => #{content_handlers =>
			[{gun_sse_h, #{max_event_size => 32}}]}
	}),
	{ok, http} = gun:await_up(Pid),
	Ref = gun:get(Pid, "/sized?n=100&fin=nofin", [
		{<<"host">>, <<"localhost">>},
		{<<"accept">>, <<"text/event-stream">>}
	]),
	{response, nofin, 200, _} = gun:await(Pid, Ref),
	{error, {connection_error, {connection_error, limit_reached, Human}}}
		= gun:await(Pid, Ref),
	receive
		{gun_down, Pid, http, {error, {connection_error, limit_reached, Human}}, _} ->
			gun:close(Pid)
	after 5000 ->
		error(timeout)
	end.

%% An unfinished event above the limit resets the HTTP/2 stream.
max_event_size_http2(Config) ->
	do_max_event_size_http2(Config, "nofin").

%% The same limit on a read that already ended the stream does not
%% reset it, and the connection stays up.
max_event_size_http2_fin(Config) ->
	do_max_event_size_http2(Config, "fin").

do_max_event_size_http2(Config, Fin) ->
	Human = "The Server-Sent Events event is too large.",
	{ok, Pid} = gun:open("localhost", config(port, Config), #{
		transport => tls,
		tls_opts => [{verify, verify_none}, {versions, ['tlsv1.2']}],
		protocols => [http2],
		http2_opts => #{content_handlers =>
			[{gun_sse_h, #{max_event_size => 32}}]}
	}),
	{ok, http2} = gun:await_up(Pid),
	Ref = gun:get(Pid, "/sized?n=100&fin=" ++ Fin, [
		{<<"host">>, <<"localhost">>},
		{<<"accept">>, <<"text/event-stream">>}
	]),
	{response, nofin, 200, _} = gun:await(Pid, Ref),
	{error, {stream_error, {stream_error, internal_error, Human}}}
		= gun:await(Pid, Ref),
	receive
		{gun_down, Pid, _, _, _} ->
			error(gun_down)
	after 500 ->
		gun:close(Pid)
	end.

%% infinity disables the limit. The stream can end on an unfinished event.
max_event_size_infinity(Config) ->
	{ok, Pid} = gun:open("localhost", config(port, Config), #{
		transport => tls,
		tls_opts => [{verify, verify_none}, {versions, ['tlsv1.2']}],
		protocols => [http],
		http_opts => #{content_handlers =>
			[{gun_sse_h, #{max_event_size => infinity}}]}
	}),
	{ok, http} = gun:await_up(Pid),
	Ref = gun:get(Pid, "/sized?n=100&fin=fin", [
		{<<"host">>, <<"localhost">>},
		{<<"accept">>, <<"text/event-stream">>}
	]),
	{response, nofin, 200, _} = gun:await(Pid, Ref),
	{sse, fin} = gun:await(Pid, Ref),
	gun:close(Pid).

max_event_size_option(_) ->
	{error, {options, {http, {content_handlers, _}}}} = gun:open("localhost", 1, #{
		http_opts => #{content_handlers =>
			[{gun_sse_h, #{max_event_size => 0}}]}
	}),
	{error, {options, {http2, {content_handlers, _}}}} = gun:open("localhost", 1, #{
		http2_opts => #{content_handlers =>
			[{gun_sse_h, #{max_event_size => false}}]}
	}),
	ok = gun_sse_h:check_options(#{max_event_size => infinity}),
	ok = gun_sse_h:check_options(#{}).
