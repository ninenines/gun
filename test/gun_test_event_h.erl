%% Copyright (c) 2020, Loïc Hoguin <essen@ninenines.eu>
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

-module(gun_test_event_h).
-compile(export_all).
-compile(nowarn_export_all).

init(Event, State) -> common(?FUNCTION_NAME, Event, State).
domain_lookup_start(Event, State) -> common(?FUNCTION_NAME, Event, State).
domain_lookup_end(Event, State) -> common(?FUNCTION_NAME, Event, State).
connect_start(Event, State) -> common(?FUNCTION_NAME, Event, State).
connect_end(Event, State) -> common(?FUNCTION_NAME, Event, State).
tls_handshake_start(Event, State) -> common(?FUNCTION_NAME, Event, State).
tls_handshake_end(Event, State) -> common(?FUNCTION_NAME, Event, State).
request_start(Event, State) -> common(?FUNCTION_NAME, Event, State).
request_headers(Event, State) -> common(?FUNCTION_NAME, Event, State).
request_end(Event, State) -> common(?FUNCTION_NAME, Event, State).
push_promise_start(Event, State) -> common(?FUNCTION_NAME, Event, State).
push_promise_end(Event, State) -> common(?FUNCTION_NAME, Event, State).
response_start(Event, State) -> common(?FUNCTION_NAME, Event, State).
response_inform(Event, State) -> common(?FUNCTION_NAME, Event, State).
response_headers(Event, State) -> common(?FUNCTION_NAME, Event, State).
response_trailers(Event, State) -> common(?FUNCTION_NAME, Event, State).
response_end(Event, State) -> common(?FUNCTION_NAME, Event, State).
ws_upgrade(Event, State) -> common(?FUNCTION_NAME, Event, State).
ws_recv_frame_start(Event, State) -> common(?FUNCTION_NAME, Event, State).
ws_recv_frame_header(Event, State) -> common(?FUNCTION_NAME, Event, State).
ws_recv_frame_end(Event, State) -> common(?FUNCTION_NAME, Event, State).
ws_send_frame_start(Event, State) -> common(?FUNCTION_NAME, Event, State).
ws_send_frame_end(Event, State) -> common(?FUNCTION_NAME, Event, State).
protocol_changed(Event, State) -> common(?FUNCTION_NAME, Event, State).
origin_changed(Event, State) -> common(?FUNCTION_NAME, Event, State).
cancel(Event, State) -> common(?FUNCTION_NAME, Event, State).
disconnect(Event, State) -> common(?FUNCTION_NAME, Event, State).
terminate(Event, State) -> common(?FUNCTION_NAME, Event, State).

common(EventType, Event, State=Pid) ->
	Pid ! {self(), EventType, Event#{
		ts => erlang:system_time(millisecond)
	}},
	State.

receive_event(Pid) ->
	receive
		Msg = {Pid, EventType, Event} when is_atom(EventType), is_map(Event) ->
			Msg
	end.

receive_event(Pid, EventType) ->
	receive
		Msg = {Pid, EventType, Event} when is_map(Event) ->
			Msg
	end.
