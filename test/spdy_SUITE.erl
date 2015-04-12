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

goaway_on_close(_) ->
	doc("Send a GOAWAY when the client closes the connection (spdy-protocol-draft3-1 2.1)"),
	{ok, ServerPid, Port} = spdy_server:start_link(),
	{ok, ConnPid} = gun:open("localhost", Port, #{transport=>ssl}),
	{ok, spdy} = gun:await_up(ConnPid),
	gun:close(ConnPid),
	[{goaway, 0, ok}] = spdy_server:stop(ServerPid).

goaway_on_shutdown(_) ->
	doc("Send a GOAWAY when the client closes the connection (spdy-protocol-draft3-1 2.1)"),
	{ok, ServerPid, Port} = spdy_server:start_link(),
	{ok, ConnPid} = gun:open("localhost", Port, #{transport=>ssl}),
	{ok, spdy} = gun:await_up(ConnPid),
	gun:shutdown(ConnPid),
	[{goaway, 0, ok}] = spdy_server:stop(ServerPid).

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

streamid_is_odd(_) ->
	doc("Client-initiated Stream-ID must be an odd number. (spdy-protocol-draft3-1 2.3.2)"),
	{ok, ServerPid, Port} = spdy_server:start_link(),
	{ok, ConnPid} = gun:open("localhost", Port, #{transport=>ssl}),
	{ok, spdy} = gun:await_up(ConnPid),
	[do_req_resp(ConnPid, ServerPid, N * 2 - 1) || N <- lists:seq(1, 5)],
	Rec = spdy_server:stop(ServerPid),
	true = length(Rec) =:= length([ok || {syn_stream, StreamID, _, _, _, _, _, _, _, _, _, _} <- Rec, StreamID rem 2 =:= 1]).

reject_streamid_0(_) ->
	doc("The Stream-ID 0 is not valid and must be rejected with a PROTOCOL_ERROR session error. (spdy-protocol-draft3-1 2.3.2)"),
	{ok, ServerPid, Port} = spdy_server:start_link(),
	{ok, ConnPid} = gun:open("localhost", Port, #{transport=>ssl}),
	{ok, spdy} = gun:await_up(ConnPid),
	StreamRef = gun:get(ConnPid, "/"),
	spdy_server:send(ServerPid, [{syn_reply, 0, true, <<"200">>, <<"HTTP/1.1">>, []}]),
	receive after 500 -> ok end,
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
