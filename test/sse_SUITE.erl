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
-import(ct_helper, [doc/1]).

all() ->
	[http_clock, http2_clock, lone_id, with_mime_param, http_clock_close,
		max_event_size, max_event_size_default,
		max_event_size_batched_small_events, max_event_size_cancels_stream,
		max_event_size_bounds_single_large_read,
		max_event_size_ignores_comments, max_event_size_counts_buffered,
		max_event_size_rejects_completed_event, max_event_size_fin_no_badstate,
		max_event_size_crlf_not_split, max_event_size_trailing_fin_no_badstate,
		max_event_size_http_close, max_event_size_many_events_one_read].

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

max_event_size(_) ->
	doc("An SSE event whose accumulated data exceeds max_event_size "
		"must be rejected instead of buffered without bound."),
	{ok, _, OriginPort} = gun_test:init_origin(tcp, http,
		fun(_, _, ClientSocket, ClientTransport) ->
			{ok, _} = ClientTransport:recv(ClientSocket, 0, 1000),
			ok = ClientTransport:send(ClientSocket, [
				"HTTP/1.1 200 OK\r\n"
				"content-type: text/event-stream\r\n"
				"transfer-encoding: chunked\r\n"
				"\r\n"
			]),
			%% An endless run of "data:" lines without a terminating
			%% blank line, well beyond the 1000-byte max_event_size
			%% configured by the test below.
			Chunk = iolist_to_binary(binary:copy(<<"data: aaaaaaaaaa\n">>, 1000)),
			ChunkHeader = io_lib:format("~.16b\r\n", [byte_size(Chunk)]),
			ok = ClientTransport:send(ClientSocket, [ChunkHeader, Chunk, "\r\n"]),
			receive after infinity -> ok end
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort, #{
		protocols => [http],
		http_opts => #{content_handlers => [{gun_sse_h, #{max_event_size => 1000}}, gun_data_h]}
	}),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:get(ConnPid, "/", [{<<"accept">>, <<"text/event-stream">>}]),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
	{error, {stream_error, {limit_reached, _}}} = gun:await(ConnPid, StreamRef),
	gun:close(ConnPid).

max_event_size_default(_) ->
	doc("max_event_size defaults to 1 MiB, not infinity."),
	{ok, State0} = gun_sse_h:init(self(), make_ref(), 200,
		[{<<"content-type">>, <<"text/event-stream">>}], #{}),
	{done, 1, State1} = gun_sse_h:handle(nofin, <<"data: hi\n\n">>, State0),
	receive
		{gun_sse, _, _, #{data := _}} -> ok
	after 1000 ->
		error(timeout)
	end,
	%% The "data: " prefix plus 1 MiB of value sits in the buffer
	%% of one incomplete line, which is over the default.
	Over = <<"data: ", (binary:copy(<<"a">>, 1048576))/binary>>,
	{done, 0, _, cancel} = gun_sse_h:handle(nofin, Over, State1),
	receive
		{gun_error, _, _, {limit_reached, _}} -> ok
	after 1000 ->
		error(timeout)
	end.

max_event_size_batched_small_events(_) ->
	doc("Multiple small, complete events arriving in a single read must "
		"not have their combined size mistaken for the size of a single "
		"event when checked against max_event_size."),
	EventCount = 20,
	{ok, _, OriginPort} = gun_test:init_origin(tcp, http,
		fun(_, _, ClientSocket, ClientTransport) ->
			{ok, _} = ClientTransport:recv(ClientSocket, 0, 1000),
			ok = ClientTransport:send(ClientSocket, [
				"HTTP/1.1 200 OK\r\n"
				"content-type: text/event-stream\r\n"
				"transfer-encoding: chunked\r\n"
				"\r\n"
			]),
			%% Many small, complete events sent as a single chunk. Their
			%% combined size is well beyond the small max_event_size
			%% configured below even though no individual event is.
			Chunk = iolist_to_binary(binary:copy(<<"data: x\n\n">>, EventCount)),
			ChunkHeader = io_lib:format("~.16b\r\n", [byte_size(Chunk)]),
			ok = ClientTransport:send(ClientSocket, [ChunkHeader, Chunk, "\r\n"]),
			receive after infinity -> ok end
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort, #{
		protocols => [http],
		http_opts => #{content_handlers => [{gun_sse_h, #{max_event_size => 20}}, gun_data_h]}
	}),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:get(ConnPid, "/", [{<<"accept">>, <<"text/event-stream">>}]),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
	ok = do_receive_events(ConnPid, StreamRef, EventCount),
	gun:close(ConnPid).

do_receive_events(_, _, 0) ->
	ok;
do_receive_events(ConnPid, StreamRef, N) ->
	receive
		{gun_sse, ConnPid, StreamRef, #{data := _}} ->
			do_receive_events(ConnPid, StreamRef, N - 1);
		{gun_error, ConnPid, StreamRef, Reason} ->
			error({unexpected_error, Reason})
	after 5000 ->
		error(timeout)
	end.

max_event_size_cancels_stream(_) ->
	doc("When max_event_size is exceeded the stream must be actively "
		"cancelled, not just have its data silently dropped locally."),
	{ok, OriginPid, OriginPort} = gun_test:init_origin(tcp, http2,
		fun(Parent, _, Socket, Transport) ->
			{ok, <<Len:24, 1:8, _:8, StreamID:32>>} = Transport:recv(Socket, 9, 5000),
			{ok, _} = Transport:recv(Socket, Len, 5000),
			{HeadersBlock, _} = cow_hpack:encode([
				{<<":status">>, <<"200">>},
				{<<"content-type">>, <<"text/event-stream">>}
			]),
			ok = Transport:send(Socket, cow_http2:headers(StreamID, nofin, HeadersBlock)),
			%% An endless run of "data:" lines without a terminating
			%% blank line, well beyond the 1000-byte max_event_size
			%% configured by the test below, but still within a
			%% single HTTP/2 DATA frame's default max frame size.
			Chunk = iolist_to_binary(binary:copy(<<"data: aaaaaaaaaa\n">>, 900)),
			ok = Transport:send(Socket, cow_http2:data(StreamID, nofin, Chunk)),
			do_wait_rst_stream(Parent, Socket, Transport, StreamID)
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort, #{
		protocols => [http2],
		http2_opts => #{content_handlers => [{gun_sse_h, #{max_event_size => 1000}}, gun_data_h]}
	}),
	{ok, http2} = gun:await_up(ConnPid),
	handshake_completed = gun_test:receive_from(OriginPid),
	StreamRef = gun:get(ConnPid, "/", [{<<"accept">>, <<"text/event-stream">>}]),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
	{error, {stream_error, {limit_reached, _}}} = gun:await(ConnPid, StreamRef),
	{rst_stream_received, _} = gun_test:receive_from(OriginPid),
	gun:close(ConnPid).

%% Skip other frames (for example WINDOW_UPDATE) until the RST_STREAM
%% for this stream, or a GOAWAY.
do_wait_rst_stream(Parent, Socket, Transport, StreamID) ->
	{ok, <<Len:24, Type:8, _:8, FrameStreamID:32>>} = Transport:recv(Socket, 9, 5000),
	{ok, Payload} = case Len of
		0 -> {ok, <<>>};
		_ -> Transport:recv(Socket, Len, 5000)
	end,
	case {Type, FrameStreamID} of
		{3, StreamID} ->
			<<ErrorCode:32>> = Payload,
			Parent ! {self(), {rst_stream_received, ErrorCode}};
		{7, _} ->
			<<_:32, ErrorCode:32, _/bits>> = Payload,
			Parent ! {self(), {goaway_received, ErrorCode}};
		_ ->
			do_wait_rst_stream(Parent, Socket, Transport, StreamID)
	end.

max_event_size_bounds_single_large_read(_) ->
	doc("A single call to handle/3 carrying data well beyond "
		"max_event_size must not fully parse it before the limit "
		"is enforced."),
	{ok, State0} = gun_sse_h:init(self(), make_ref(), 200,
		[{<<"content-type">>, <<"text/event-stream">>}], #{max_event_size => 100}),
	%% No terminating blank line, so none of this completes an event.
	Data = iolist_to_binary(binary:copy(<<"data: aaaaaaaaaa\n">>, 3000000)),
	{Time, {done, 0, _, cancel}} = timer:tc(gun_sse_h, handle, [nofin, Data, State0]),
	%% Parsing only up to the limit stays well under a second.
	%% Parsing the whole binary takes several.
	true = Time < 1000000,
	receive
		{gun_error, _, _, {limit_reached, _}} -> ok
	after 1000 ->
		error(timeout)
	end.

max_event_size_ignores_comments(_) ->
	doc("Comment lines are not part of an event and must not "
		"consume max_event_size."),
	{ok, State0} = gun_sse_h:init(self(), make_ref(), 200,
		[{<<"content-type">>, <<"text/event-stream">>}], #{max_event_size => 30}),
	Comments = binary:copy(<<": hi\n">>, 20),
	{done, 1, _} = gun_sse_h:handle(nofin, <<Comments/binary, "data: x\n\n">>, State0),
	receive
		{gun_sse, _, _, #{data := [<<"x">>]}} -> ok;
		{gun_error, _, _, Reason} -> error(Reason)
	after 1000 ->
		error(timeout)
	end.

max_event_size_counts_buffered(_) ->
	doc("Bytes already held for the next event are counted, and an "
		"event over the limit is not delivered."),
	{ok, State0} = gun_sse_h:init(self(), make_ref(), 200,
		[{<<"content-type">>, <<"text/event-stream">>}], #{max_event_size => 100}),
	%% id event, then 97 bytes of the next line, still under the limit.
	{done, 1, State1} = gun_sse_h:handle(nofin,
		<<"id\n\n", (binary:copy(<<"b">>, 97))/binary>>, State0),
	receive {gun_sse, _, _, #{last_event_id := <<>>}} -> ok after 1000 -> error(timeout) end,
	%% Another 100 bytes would make 197 bytes of one incomplete line.
	{done, 0, State2, cancel} = gun_sse_h:handle(nofin, binary:copy(<<"c">>, 100), State1),
	receive
		{gun_error, _, _, {limit_reached, _}} -> ok
	after 1000 ->
		error(timeout)
	end,
	%% The oversized event must not be delivered afterwards.
	{done, 0, _} = gun_sse_h:handle(nofin, <<"\n\n">>, State2),
	receive
		{gun_sse, _, _, _} -> error(delivered);
		{gun_error, _, _, _} -> error(second_error)
	after 200 ->
		ok
	end.

max_event_size_rejects_completed_event(_) ->
	doc("A completed event whose data is larger than max_event_size "
		"is rejected instead of delivered. The field name is not counted."),
	{ok, State0} = gun_sse_h:init(self(), make_ref(), 200,
		[{<<"content-type">>, <<"text/event-stream">>}], #{max_event_size => 10}),
	{done, 1, _} = gun_sse_h:handle(nofin, <<"data: abc\n\n">>, State0),
	receive {gun_sse, _, _, #{data := [<<"abc">>]}} -> ok after 1000 -> error(timeout) end,
	{ok, State1} = gun_sse_h:init(self(), make_ref(), 200,
		[{<<"content-type">>, <<"text/event-stream">>}], #{max_event_size => 10}),
	Over = <<"data: ", (binary:copy(<<"a">>, 11))/binary, "\n\n">>,
	{done, 0, _, cancel} = gun_sse_h:handle(nofin, Over, State1),
	receive
		{gun_sse, _, _, _} -> error(delivered);
		{gun_error, _, _, {limit_reached, _}} -> ok
	after 1000 ->
		error(timeout)
	end.

max_event_size_fin_no_badstate(_) ->
	doc("Reaching the limit on the read that ends the stream must not "
		"be followed by a badstate error from cancelling a stream "
		"that has already been removed."),
	Body = binary:copy(<<"data: aaaaaaaaaa\n">>, 50),
	{ok, _, OriginPort} = gun_test:init_origin(tcp, http,
		fun(_, _, ClientSocket, ClientTransport) ->
			{ok, _} = ClientTransport:recv(ClientSocket, 0, 1000),
			Len = integer_to_binary(byte_size(Body)),
			ok = ClientTransport:send(ClientSocket, [
				"HTTP/1.1 200 OK\r\n"
				"content-type: text/event-stream\r\n"
				"content-length: ", Len, "\r\n"
				"\r\n",
				Body
			]),
			receive after infinity -> ok end
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort, #{
		protocols => [http],
		http_opts => #{content_handlers => [{gun_sse_h, #{max_event_size => 100}}, gun_data_h]}
	}),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:get(ConnPid, "/", [{<<"accept">>, <<"text/event-stream">>}]),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
	{error, {stream_error, {limit_reached, _}}} = gun:await(ConnPid, StreamRef),
	receive
		{gun_error, ConnPid, StreamRef, {badstate, _}} ->
			error(badstate)
	after 200 ->
		ok
	end,
	gun:close(ConnPid).

max_event_size_crlf_not_split(_) ->
	doc("A slice boundary must not fall between CR and LF, or one "
		"event is dispatched as two."),
	{ok, State0} = gun_sse_h:init(self(), make_ref(), 200,
		[{<<"content-type">>, <<"text/event-stream">>}], #{max_event_size => 20}),
	{done, 1, _} = gun_sse_h:handle(nofin,
		<<"event: e\r\ndata: aaaa\r\ndata: z\r\n\r\n">>, State0),
	receive
		{gun_sse, _, _, Event} ->
			#{data := Data, event_type := <<"e">>} = Event,
			<<"aaaa\nz">> = iolist_to_binary(Data)
	after 1000 ->
		error(timeout)
	end,
	receive
		{gun_sse, _, _, _} -> error(split)
	after 200 ->
		ok
	end.

max_event_size_trailing_fin_no_badstate(_) ->
	doc("A DATA frame that ends the stream in the same read as the "
		"frame that exceeded max_event_size must not produce a "
		"badstate error."),
	{ok, OriginPid, OriginPort} = gun_test:init_origin(tcp, http2,
		fun(Parent, _, Socket, Transport) ->
			{ok, <<Len:24, 1:8, _:8, StreamID:32>>} = Transport:recv(Socket, 9, 5000),
			{ok, _} = Transport:recv(Socket, Len, 5000),
			{HeadersBlock, _} = cow_hpack:encode([
				{<<":status">>, <<"200">>},
				{<<"content-type">>, <<"text/event-stream">>}
			]),
			Chunk = iolist_to_binary(binary:copy(<<"data: aaaaaaaaaa\n">>, 40)),
			ok = Transport:send(Socket, [
				cow_http2:headers(StreamID, nofin, HeadersBlock),
				cow_http2:data(StreamID, nofin, Chunk),
				cow_http2:data(StreamID, fin, <<>>)
			]),
			do_wait_rst_stream(Parent, Socket, Transport, StreamID)
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort, #{
		protocols => [http2],
		http2_opts => #{content_handlers => [{gun_sse_h, #{max_event_size => 100}}, gun_data_h]}
	}),
	{ok, http2} = gun:await_up(ConnPid),
	handshake_completed = gun_test:receive_from(OriginPid),
	StreamRef = gun:get(ConnPid, "/", [{<<"accept">>, <<"text/event-stream">>}]),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
	{error, {stream_error, {limit_reached, _}}} = gun:await(ConnPid, StreamRef),
	receive
		{gun_error, ConnPid, StreamRef, {badstate, _}} ->
			error(badstate)
	after 200 ->
		ok
	end,
	{rst_stream_received, _} = gun_test:receive_from(OriginPid),
	gun:close(ConnPid).

max_event_size_http_close(_) ->
	doc("HTTP/1 cannot skip the rest of a body. Exceeding "
		"max_event_size closes the connection."),
	{ok, _, OriginPort} = gun_test:init_origin(tcp, http,
		fun(_, _, ClientSocket, ClientTransport) ->
			{ok, _} = ClientTransport:recv(ClientSocket, 0, 1000),
			ok = ClientTransport:send(ClientSocket, [
				"HTTP/1.1 200 OK\r\n"
				"content-type: text/event-stream\r\n"
				"transfer-encoding: chunked\r\n"
				"\r\n"
			]),
			%% No terminating chunk. The body is still open when the
			%% limit is hit, so Gun must close the connection.
			Chunk = iolist_to_binary(binary:copy(<<"data: aaaaaaaaaa\n">>, 50)),
			ChunkHeader = io_lib:format("~.16b\r\n", [byte_size(Chunk)]),
			ok = ClientTransport:send(ClientSocket, [ChunkHeader, Chunk, "\r\n"]),
			receive after infinity -> ok end
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort, #{
		protocols => [http],
		http_opts => #{content_handlers => [{gun_sse_h, #{max_event_size => 100}}, gun_data_h]}
	}),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:get(ConnPid, "/", [{<<"accept">>, <<"text/event-stream">>}]),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
	{error, {stream_error, {limit_reached, _}}} = gun:await(ConnPid, StreamRef),
	receive
		{gun_down, ConnPid, http, normal, _} -> ok
	after 1000 ->
		error(timeout)
	end.

max_event_size_many_events_one_read(_) ->
	doc("A read of many small events must not copy the buffered "
		"tail once per event."),
	{ok, State0} = gun_sse_h:init(self(), make_ref(), 200,
		[{<<"content-type">>, <<"text/event-stream">>}], #{max_event_size => 40000}),
	Data = binary:copy(<<"data: x\n\n">>, 10000),
	{Time, Result} = timer:tc(gun_sse_h, handle, [nofin, Data, State0]),
	{done, 10000, _} = Result,
	%% Copying max_event_size bytes per event takes seconds.
	true = Time < 1000000,
	ok = do_receive_sse(10000).

do_receive_sse(0) ->
	ok;
do_receive_sse(N) ->
	receive
		{gun_sse, _, _, #{data := _}} ->
			do_receive_sse(N - 1)
	after 1000 ->
		error({timeout, N})
	end.

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
