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

%% ct.

all() -> [{group, spdy31}].

groups() -> [{spdy31, [parallel], ct_helper:all(?MODULE)}].

%% Helper functions.

wait() ->
	receive after 500 -> ok end.

do_req_resp(ConnPid, ServerPid, ServerStreamID) ->
	StreamRef = gun:get(ConnPid, "/"),
	spdy_server:send(ServerPid, [
		{syn_reply, ServerStreamID, false, <<"200">>, <<"HTTP/1.1">>, []},
		{data, ServerStreamID, true, <<"Hello world!">>}
	]),
	receive {gun_response, _, StreamRef, _, _, _} ->
		ok
	after 5000 ->
		exit(timeout)
	end,
	ok.

%% SPDY/3.1 test suite.

goaway_on_close(_) ->
	doc("Send a GOAWAY when the client closes the connection (spdy-protocol-draft3-1 2.1)"),
	{ok, ServerPid, Port} = spdy_server:start_link(),
	{ok, ConnPid} = gun:open("localhost", Port, #{transport=>ssl}),
	{ok, spdy} = gun:await_up(ConnPid),
	gun:close(ConnPid),
	wait(),
	[{goaway, 0, ok}] = spdy_server:stop(ServerPid).

goaway_on_shutdown(_) ->
	doc("Send a GOAWAY when the client closes the connection (spdy-protocol-draft3-1 2.1)"),
	{ok, ServerPid, Port} = spdy_server:start_link(),
	{ok, ConnPid} = gun:open("localhost", Port, #{transport=>ssl}),
	{ok, spdy} = gun:await_up(ConnPid),
	gun:shutdown(ConnPid),
	wait(),
	[{goaway, 0, ok}] = spdy_server:stop(ServerPid).


streamid_is_odd(_) ->
	doc("Client-initiated Stream-ID must be an odd number. (spdy-protocol-draft3-1 2.3.2)"),
	{ok, ServerPid, Port} = spdy_server:start_link(),
	{ok, ConnPid} = gun:open("localhost", Port, #{transport=>ssl}),
	{ok, spdy} = gun:await_up(ConnPid),
	[do_req_resp(ConnPid, ServerPid, N) || N <- lists:seq(1, 5, 2)],
	Rec = spdy_server:stop(ServerPid),
	true = length(Rec) =:= length([ok || {syn_stream, StreamID, _, _, _, _, _, _, _, _, _, _} <- Rec, StreamID rem 2 =:= 1]).

reject_streamid_0(_) ->
	doc("The Stream-ID 0 is not valid and must be rejected with a PROTOCOL_ERROR session error. (spdy-protocol-draft3-1 2.3.2)"),
	{ok, ServerPid, Port} = spdy_server:start_link(),
	{ok, ConnPid} = gun:open("localhost", Port, #{transport=>ssl}),
	{ok, spdy} = gun:await_up(ConnPid),
	_ = gun:get(ConnPid, "/"),
	spdy_server:send(ServerPid, [
		{syn_stream, 0, 1, true, true, 0, <<"GET">>, <<"https">>, ["localhost:", integer_to_binary(Port)], "/a", <<"HTTP/1.1">>, []},
		{syn_reply, 1, true, <<"200">>, <<"HTTP/1.1">>, []}
	]),
	wait(),
	[_, {goaway, 1, protocol_error}] = spdy_server:stop(ServerPid).

streamid_increases_monotonically(_) ->
	doc("The Stream-ID must increase monotonically. (spdy-protocol-draft3-1 2.3.2)"),
	{ok, ServerPid, Port} = spdy_server:start_link(),
	{ok, ConnPid} = gun:open("localhost", Port, #{transport=>ssl}),
	{ok, spdy} = gun:await_up(ConnPid),
	Expected = [1, 3, 5, 7, 9],
	[do_req_resp(ConnPid, ServerPid, N) || N <- Expected],
	Rec = spdy_server:stop(ServerPid),
	Expected = [StreamID || {syn_stream, StreamID, _, _, _, _, _, _, _, _, _, _} <- Rec].

streamid_does_not_wrap(_) ->
	doc("Stream-ID must not wrap. Reconnect when all Stream-IDs are exhausted. (spdy-protocol-draft3-1 2.3.2)"),
	{ok, ServerPid, Port} = spdy_server:start_link(),
	{ok, ConnPid} = gun:open("localhost", Port, #{transport=>ssl}),
	{ok, spdy} = gun:await_up(ConnPid),
	MaxClientStreamID = 2147483647,
	sys:replace_state(ConnPid, fun({loop, State}) ->
		%% Replace the next stream_id value to the maximum allowed value.
		{loop, setelement(11, State, setelement(9, element(11, State), MaxClientStreamID))}
	end),
	do_req_resp(ConnPid, ServerPid, MaxClientStreamID),
	%% Gun has exhausted all Stream-IDs and should now reconnect.
	{ok, spdy} = gun:await_up(ConnPid),
	%% Check that the next request is on a new connection.
	_ = gun:get(ConnPid, "/"),
	[{syn_stream, 1, _, _, _, _, _, _, _, _, _, _}] = spdy_server:stop(ServerPid).

syn_stream_decreasing_streamid(_) ->
	doc("Reject a decreasing Stream-ID with a PROTOCOL_ERROR session error. (spdy-protocol-draft3-1 2.3.2)"),
	{ok, ServerPid, Port} = spdy_server:start_link(),
	{ok, ConnPid} = gun:open("localhost", Port, #{transport=>ssl}),
	{ok, spdy} = gun:await_up(ConnPid),
	_ = gun:get(ConnPid, "/"),
	Host = ["localhost:", integer_to_binary(Port)],
	spdy_server:send(ServerPid, [
		{syn_stream, 2, 1, true, true, 0, <<"GET">>, <<"https">>, Host, "/a", <<"HTTP/1.1">>, []},
		{syn_stream, 6, 1, true, true, 0, <<"GET">>, <<"https">>, Host, "/b", <<"HTTP/1.1">>, []},
		{syn_stream, 4, 1, true, true, 0, <<"GET">>, <<"https">>, Host, "/c", <<"HTTP/1.1">>, []},
		{syn_reply, 1, true, <<"200">>, <<"HTTP/1.1">>, []}
	]),
	wait(),
	[_, {goaway, 1, protocol_error}] = spdy_server:stop(ServerPid).

stream_duplicate_streamid(_) ->
	doc("Reject duplicate Stream-ID with a PROTOCOL_ERROR session error. (spdy-protocol-draft3-1 2.3.2)"),
	{ok, ServerPid, Port} = spdy_server:start_link(),
	{ok, ConnPid} = gun:open("localhost", Port, #{transport=>ssl}),
	{ok, spdy} = gun:await_up(ConnPid),
	_ = gun:get(ConnPid, "/"),
	Host = ["localhost:", integer_to_binary(Port)],
	spdy_server:send(ServerPid, [
		{syn_stream, 2, 1, true, true, 0, <<"GET">>, <<"https">>, Host, "/a", <<"HTTP/1.1">>, []},
		{syn_stream, 2, 1, true, true, 0, <<"GET">>, <<"https">>, Host, "/b", <<"HTTP/1.1">>, []},
		{syn_reply, 1, true, <<"200">>, <<"HTTP/1.1">>, []}
	]),
	wait(),
	[_, {goaway, 1, protocol_error}] = spdy_server:stop(ServerPid).
