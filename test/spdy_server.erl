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

-module(spdy_server).
-behaviour(gen_server).

%% API.
-export([start_link/0]).
-export([stop/1]).
-export([send/2]).

%% gen_server.
-export([init/1]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_info/2]).
-export([terminate/2]).
-export([code_change/3]).

-type recording() :: [tuple()].

-record(state, {
	owner = undefined :: pid(),
	recording = [] :: recording(),
	state_name = listen :: listen | record,
	socket = undefined :: ssl:sslsocket(),
	zdef = undefined :: zlib:zstream(),
	zinf = undefined :: zlib:zstream(),
	buffer = <<>> :: binary()
}).

%% API.

-spec start_link() -> {ok, pid()}.
start_link() ->
	{ok, Pid} = gen_server:start_link(?MODULE, [self()], []),
	receive {port, Pid, Port} ->
		{ok, Pid, Port}
	after 5000 ->
		exit(timeout)
	end.

-spec stop(pid()) -> recording().
stop(Pid) ->
	gen_server:call(Pid, stop).

send(Pid, Frames) ->
	gen_server:call(Pid, {send, Frames}).

%% gen_server.

init([Owner]) ->
	Opts = ct_helper:get_certs_from_ets(),
	{ok, LSocket} = ssl:listen(0, [binary, {active, false}, {nodelay, true},
		{next_protocols_advertised, [<<"spdy/3.1">>, <<"spdy/3">>]}|Opts]),
	{ok, {_, Port}} = ssl:sockname(LSocket),
	Owner ! {port, self(), Port},
	self() ! listen,
	Zdef = cow_spdy:deflate_init(),
	Zinf = cow_spdy:inflate_init(),
	{ok, #state{owner=Owner, socket=LSocket, zdef=Zdef, zinf=Zinf}}.

handle_call({send, Frames}, {Owner, _}, State=#state{owner=Owner, socket=Socket, zdef=Zdef}) ->
	do_send(Frames, Socket, Zdef),
	{reply, ok, State};
handle_call(stop, {Owner, _}, State=#state{owner=Owner, recording=Recording}) ->
	{stop, normal, lists:reverse(Recording), State};
handle_call(_Request, _From, State) ->
	{reply, ignored, State}.

handle_cast(_Msg, State) ->
	{noreply, State}.

handle_info(listen, State=#state{state_name=listen, socket=LSocket}) ->
	{ok, CSocket} = ssl:transport_accept(LSocket, 5000),
	ok = ssl:ssl_accept(CSocket, 5000),
	ok = ssl:setopts(CSocket, [{active, once}]),
	{noreply, State#state{state_name=record, socket=CSocket}};
handle_info({ssl, Socket, Data}, State=#state{state_name=record, socket=Socket, buffer=Buffer}) ->
	ok = ssl:setopts(Socket, [{active, once}]),
	State2 = handle_data(<< Buffer/binary, Data/binary >>, State),
	{noreply, State2};
%% @todo ssl_closed ssl_error
handle_info(_Info, State) ->
	{noreply, State}.

terminate(_Reason, _State) ->
	ok.

code_change(_OldVsn, State, _Extra) ->
	{ok, State}.

%% Internal.

do_send([], _, _) ->
	ok;
do_send([{syn_stream, StreamID, AssocToStreamID, IsFin, IsUnidirectional, Priority,
		Method, Scheme, Host, Path, Version, Headers}|Tail], Socket, Zdef) ->
	ssl:send(Socket, cow_spdy:syn_stream(Zdef, StreamID, AssocToStreamID, IsFin, IsUnidirectional, Priority,
		Method, Scheme, Host, Path, Version, Headers)),
	do_send(Tail, Socket, Zdef);
do_send([{syn_reply, StreamID, IsFin, Status, Version, Headers}|Tail], Socket, Zdef) ->
	ssl:send(Socket, cow_spdy:syn_reply(Zdef, StreamID, IsFin, Status, Version, Headers)),
	do_send(Tail, Socket, Zdef);
do_send([{rst_stream, StreamID, Status}|Tail], Socket, Zdef) ->
	ssl:send(Socket, cow_spdy:rst_stream(StreamID, Status)),
	do_send(Tail, Socket, Zdef);
do_send([{window_update, StreamID, DeltaWindowSize}|Tail], Socket, Zdef) ->
%% @todo	ssl:send(Socket, cow_spdy:window_update(StreamID, DeltaWindowSize)),
	do_send(Tail, Socket, Zdef);
do_send([{data, StreamID, IsFin, Data}|Tail], Socket, Zdef) ->
	ssl:send(Socket, cow_spdy:data(StreamID, IsFin, Data)),
	do_send(Tail, Socket, Zdef).

handle_data(Data, State=#state{recording=Recording, zinf=Zinf}) ->
	case cow_spdy:split(Data) of
		{true, ParsedFrame, Rest} ->
			Frame = cow_spdy:parse(ParsedFrame, Zinf),
			handle_data(Rest, State#state{recording=[Frame|Recording]});
		false ->
			State#state{buffer=Data}
	end.
