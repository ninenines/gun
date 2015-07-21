%% Copyright (c) 2013-2015, Loïc Hoguin <essen@ninenines.eu>
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

-module(gun).

%% Connection.
-export([open/2]).
-export([open/3]).
-export([close/1]).
-export([shutdown/1]).

%% Requests.
-export([delete/2]).
-export([delete/3]).
-export([get/2]).
-export([get/3]).
-export([head/2]).
-export([head/3]).
-export([options/2]).
-export([options/3]).
-export([patch/3]).
-export([patch/4]).
-export([post/3]).
-export([post/4]).
-export([put/3]).
-export([put/4]).
-export([request/4]).
-export([request/5]).

%% Streaming data.
-export([data/4]).

%% Awaiting gun messages.
-export([await/2]).
-export([await/3]).
-export([await/4]).
-export([await_body/2]).
-export([await_body/3]).
-export([await_body/4]).
-export([await_up/1]).
-export([await_up/2]).
-export([await_up/3]).

%% Flushing gun messages.
-export([flush/1]).

%% Cancelling a stream.
-export([cancel/2]).

%% Websocket.
-export([ws_upgrade/2]).
-export([ws_upgrade/3]).
-export([ws_upgrade/4]).
-export([ws_send/2]).

%% Debug.
-export([dbg_send_raw/2]).

%% Internals.
-export([start_link/4]).
-export([init/5]).
-export([system_continue/3]).
-export([system_terminate/4]).
-export([system_code_change/4]).

-type headers() :: [{binary(), iodata()}].

-type ws_close_code() :: 1000..4999.
-type ws_frame() :: close | ping | pong
	| {text | binary | close | ping | pong, iodata()}
	| {close, ws_close_code(), iodata()}.

-type opts() :: map().
-export_type([opts/0]).

-type http_opts() :: map().
-export_type([http_opts/0]).

-type spdy_opts() :: map().
-export_type([spdy_opts/0]).

-type ws_opts() :: map().
-export_type([ws_opts/0]).

-record(state, {
	parent :: pid(),
	owner :: pid(),
	host :: inet:hostname(),
	port :: inet:port_number(),
	opts :: opts(),
	keepalive_ref :: reference(),
	socket :: inet:socket() | ssl:sslsocket(),
	transport :: module(),
	protocol :: module(),
	protocol_state :: any()
}).

%% Connection.

-spec open(inet:hostname(), inet:port_number())
	-> {ok, pid()} | {error, any()}.
open(Host, Port) ->
	open(Host, Port, #{}).

-spec open(inet:hostname(), inet:port_number(), opts())
	-> {ok, pid()} | {error, any()}.
open(Host, Port, Opts) when is_list(Host); is_atom(Host) ->
	case check_options(maps:to_list(Opts)) of
		ok ->
			case supervisor:start_child(gun_sup, [self(), Host, Port, Opts]) of
				OK = {ok, ServerPid} ->
					consider_tracing(ServerPid, Opts),
					OK;
				StartError ->
					StartError
			end;
		CheckError ->
			CheckError
	end.

check_options([]) ->
	ok;
check_options([{http_opts, ProtoOpts}|Opts]) when is_map(ProtoOpts) ->
	case gun_http:check_options(ProtoOpts) of
		ok ->
			check_options(Opts);
		Error ->
			Error
	end;
check_options([Opt = {protocols, L}|Opts]) when is_list(L) ->
	Len = length(L),
	case length(lists:usort(L)) of
		Len when Len > 0 ->
			Check = lists:usort([(P =:= http) orelse (P =:= spdy) || P <- L]),
			case Check of
				[true] ->
					check_options(Opts);
				_ ->
					{error, {options, Opt}}
			end;
		_ ->
			{error, {options, Opt}}
	end;
check_options([{retry, R}|Opts]) when is_integer(R), R >= 0 ->
	check_options(Opts);
check_options([{retry_timeout, T}|Opts]) when is_integer(T) > 0 ->
	check_options(Opts);
check_options([{spdy_opts, ProtoOpts}|Opts]) when is_map(ProtoOpts) ->
	case gun_spdy:check_options(ProtoOpts) of
		ok ->
			check_options(Opts);
		Error ->
			Error
	end;
check_options([{trace, B}|Opts]) when B =:= true; B =:= false ->
	check_options(Opts);
check_options([{transport, T}|Opts]) when T =:= tcp; T =:= ssl ->
	check_options(Opts);
check_options([{transport_opts, L}|Opts]) when is_list(L) ->
	check_options(Opts);
check_options([{ws_opts, ProtoOpts}|Opts]) when is_map(ProtoOpts) ->
	case gun_ws:check_options(ProtoOpts) of
		ok ->
			check_options(Opts);
		Error ->
			Error
	end;
check_options([Opt|_]) ->
	{error, {options, Opt}}.

consider_tracing(ServerPid, #{trace := true}) ->
	dbg:start(),
	dbg:tracer(),
	dbg:tpl(gun, [{'_', [], [{return_trace}]}]),
	dbg:tpl(gun_http, [{'_', [], [{return_trace}]}]),
	dbg:tpl(gun_spdy, [{'_', [], [{return_trace}]}]),
	dbg:tpl(gun_ws, [{'_', [], [{return_trace}]}]),
	dbg:p(ServerPid, all);
consider_tracing(_, _) ->
	ok.

-spec close(pid()) -> ok.
close(ServerPid) ->
	supervisor:terminate_child(gun_sup, ServerPid).

-spec shutdown(pid()) -> ok.
shutdown(ServerPid) ->
	_ = ServerPid ! {shutdown, self()},
	ok.

%% Requests.

-spec delete(pid(), iodata()) -> reference().
delete(ServerPid, Path) ->
	request(ServerPid, <<"DELETE">>, Path, []).

-spec delete(pid(), iodata(), headers()) -> reference().
delete(ServerPid, Path, Headers) ->
	request(ServerPid, <<"DELETE">>, Path, Headers).

-spec get(pid(), iodata()) -> reference().
get(ServerPid, Path) ->
	request(ServerPid, <<"GET">>, Path, []).

-spec get(pid(), iodata(), headers()) -> reference().
get(ServerPid, Path, Headers) ->
	request(ServerPid, <<"GET">>, Path, Headers).

-spec head(pid(), iodata()) -> reference().
head(ServerPid, Path) ->
	request(ServerPid, <<"HEAD">>, Path, []).

-spec head(pid(), iodata(), headers()) -> reference().
head(ServerPid, Path, Headers) ->
	request(ServerPid, <<"HEAD">>, Path, Headers).

-spec options(pid(), iodata()) -> reference().
options(ServerPid, Path) ->
	request(ServerPid, <<"OPTIONS">>, Path, []).

-spec options(pid(), iodata(), headers()) -> reference().
options(ServerPid, Path, Headers) ->
	request(ServerPid, <<"OPTIONS">>, Path, Headers).

-spec patch(pid(), iodata(), headers()) -> reference().
patch(ServerPid, Path, Headers) ->
	request(ServerPid, <<"PATCH">>, Path, Headers).

-spec patch(pid(), iodata(), headers(), iodata()) -> reference().
patch(ServerPid, Path, Headers, Body) ->
	request(ServerPid, <<"PATCH">>, Path, Headers, Body).

-spec post(pid(), iodata(), headers()) -> reference().
post(ServerPid, Path, Headers) ->
	request(ServerPid, <<"POST">>, Path, Headers).

-spec post(pid(), iodata(), headers(), iodata()) -> reference().
post(ServerPid, Path, Headers, Body) ->
	request(ServerPid, <<"POST">>, Path, Headers, Body).

-spec put(pid(), iodata(), headers()) -> reference().
put(ServerPid, Path, Headers) ->
	request(ServerPid, <<"PUT">>, Path, Headers).

-spec put(pid(), iodata(), headers(), iodata()) -> reference().
put(ServerPid, Path, Headers, Body) ->
	request(ServerPid, <<"PUT">>, Path, Headers, Body).

-spec request(pid(), iodata(), iodata(), headers()) -> reference().
request(ServerPid, Method, Path, Headers) ->
	StreamRef = make_ref(),
	_ = ServerPid ! {request, self(), StreamRef, Method, Path, Headers},
	StreamRef.

-spec request(pid(), iodata(), iodata(), headers(), iodata()) -> reference().
request(ServerPid, Method, Path, Headers, Body) ->
	StreamRef = make_ref(),
	_ = ServerPid ! {request, self(), StreamRef, Method, Path, Headers, Body},
	StreamRef.

%% Streaming data.

-spec data(pid(), reference(), fin | nofin, iodata()) -> ok.
data(ServerPid, StreamRef, IsFin, Data) ->
	_ = ServerPid ! {data, self(), StreamRef, IsFin, Data},
	ok.

%% Awaiting gun messages.

await(ServerPid, StreamRef) ->
	MRef = monitor(process, ServerPid),
	Res = await(ServerPid, StreamRef, 5000, MRef),
	demonitor(MRef, [flush]),
	Res.

await(ServerPid, StreamRef, MRef) when is_reference(MRef) ->
	await(ServerPid, StreamRef, 5000, MRef);
await(ServerPid, StreamRef, Timeout) ->
	MRef = monitor(process, ServerPid),
	Res = await(ServerPid, StreamRef, Timeout, MRef),
	demonitor(MRef, [flush]),
	Res.

await(ServerPid, StreamRef, Timeout, MRef) ->
	receive
		{gun_response, ServerPid, StreamRef, IsFin, Status, Headers} ->
			{response, IsFin, Status, Headers};
		{gun_data, ServerPid, StreamRef, IsFin, Data} ->
			{data, IsFin, Data};
		{gun_push, ServerPid, StreamRef, NewStreamRef, Method, Host, Path, Headers} ->
			{push, NewStreamRef, Method, Host, Path, Headers};
		{gun_error, ServerPid, StreamRef, Reason} ->
			{error, Reason};
		{gun_error, ServerPid, Reason} ->
			{error, Reason};
		{'DOWN', MRef, process, ServerPid, Reason} ->
			{error, Reason}
	after Timeout ->
		{error, timeout}
	end.

await_body(ServerPid, StreamRef) ->
	MRef = monitor(process, ServerPid),
	Res = await_body(ServerPid, StreamRef, 5000, MRef, <<>>),
	demonitor(MRef, [flush]),
	Res.

await_body(ServerPid, StreamRef, MRef) when is_reference(MRef) ->
	await_body(ServerPid, StreamRef, 5000, MRef, <<>>);
await_body(ServerPid, StreamRef, Timeout) ->
	MRef = monitor(process, ServerPid),
	Res = await_body(ServerPid, StreamRef, Timeout, MRef, <<>>),
	demonitor(MRef, [flush]),
	Res.

await_body(ServerPid, StreamRef, Timeout, MRef) ->
	await_body(ServerPid, StreamRef, Timeout, MRef, <<>>).

await_body(ServerPid, StreamRef, Timeout, MRef, Acc) ->
	receive
		{gun_data, ServerPid, StreamRef, nofin, Data} ->
			await_body(ServerPid, StreamRef, Timeout, MRef,
				<< Acc/binary, Data/binary >>);
		{gun_data, ServerPid, StreamRef, fin, Data} ->
			{ok, << Acc/binary, Data/binary >>};
		{gun_error, ServerPid, StreamRef, Reason} ->
			{error, Reason};
		{gun_error, ServerPid, Reason} ->
			{error, Reason};
		{'DOWN', MRef, process, ServerPid, Reason} ->
			{error, Reason}
	after Timeout ->
		{error, timeout}
	end.

-spec await_up(pid()) -> {ok, http | spdy} | {error, atom()}.
await_up(ServerPid) ->
	MRef = monitor(process, ServerPid),
	Res = await_up(ServerPid, 5000, MRef),
	demonitor(MRef, [flush]),
	Res.

-spec await_up(pid(), reference() | timeout()) -> {ok, http | spdy} | {error, atom()}.
await_up(ServerPid, MRef) when is_reference(MRef) ->
	await_up(ServerPid, 5000, MRef);
await_up(ServerPid, Timeout) ->
	MRef = monitor(process, ServerPid),
	Res = await_up(ServerPid, Timeout, MRef),
	demonitor(MRef, [flush]),
	Res.

-spec await_up(pid(), timeout(), reference()) -> {ok, http | spdy} | {error, atom()}.
await_up(ServerPid, Timeout, MRef) ->
	receive
		{gun_up, ServerPid, Protocol} ->
			{ok, Protocol};
		{'DOWN', MRef, process, ServerPid, Reason} ->
			{error, Reason}
	after Timeout ->
		{error, timeout}
	end.

-spec flush(pid() | reference()) -> ok.
flush(ServerPid) when is_pid(ServerPid) ->
	flush_pid(ServerPid);
flush(StreamRef) ->
	flush_ref(StreamRef).

flush_pid(ServerPid) ->
	receive
		{gun_up, ServerPid, _} ->
			flush_pid(ServerPid);
		{gun_down, ServerPid, _, _, _, _} ->
			flush_pid(ServerPid);
		{gun_response, ServerPid, _, _, _, _} ->
			flush_pid(ServerPid);
		{gun_data, ServerPid, _, _, _} ->
			flush_pid(ServerPid);
		{gun_push, ServerPid, _, _, _, _, _, _} ->
			flush_pid(ServerPid);
		{gun_error, ServerPid, _, _} ->
			flush_pid(ServerPid);
		{gun_error, ServerPid, _} ->
			flush_pid(ServerPid);
		{gun_ws_upgrade, ServerPid, _, _} ->
			flush_pid(ServerPid);
		{gun_ws, ServerPid, _} ->
			flush_pid(ServerPid);
		{'DOWN', _, process, ServerPid, _} ->
			flush_pid(ServerPid)
	after 0 ->
		ok
	end.

flush_ref(StreamRef) ->
	receive
		{gun_response, _, StreamRef, _, _, _} ->
			flush_ref(StreamRef);
		{gun_data, _, StreamRef, _, _} ->
			flush_ref(StreamRef);
		{gun_push, _, StreamRef, _, _, _, _, _} ->
			flush_ref(StreamRef);
		{gun_error, _, StreamRef, _} ->
			flush_ref(StreamRef)
	after 0 ->
		ok
	end.

%% Cancelling a stream.

-spec cancel(pid(), reference()) -> ok.
cancel(ServerPid, StreamRef) ->
	_ = ServerPid ! {cancel, self(), StreamRef},
	ok.

%% Websocket.

-spec ws_upgrade(pid(), iodata()) -> reference().
ws_upgrade(ServerPid, Path) ->
	ws_upgrade(ServerPid, Path, []).

-spec ws_upgrade(pid(), iodata(), headers()) -> reference().
ws_upgrade(ServerPid, Path, Headers) ->
	StreamRef = make_ref(),
	_ = ServerPid ! {ws_upgrade, self(), StreamRef, Path, Headers},
	StreamRef.

-spec ws_upgrade(pid(), iodata(), headers(), ws_opts()) -> reference().
ws_upgrade(ServerPid, Path, Headers, Opts) ->
	ok = gun_ws:check_options(Opts),
	StreamRef = make_ref(),
	_ = ServerPid ! {ws_upgrade, self(), StreamRef, Path, Headers, Opts},
	StreamRef.

-spec ws_send(pid(), ws_frame() | [ws_frame()]) -> ok.
ws_send(ServerPid, Frames) ->
	_ = ServerPid ! {ws_send, self(), Frames},
	ok.

%% Debug.

-spec dbg_send_raw(pid(), iodata()) -> ok.
dbg_send_raw(ServerPid, Data) ->
	_ = ServerPid ! {dbg_send_raw, self(), Data},
	ok.

%% Internals.

start_link(Owner, Host, Port, Opts) ->
	proc_lib:start_link(?MODULE, init,
		[self(), Owner, Host, Port, Opts]).

init(Parent, Owner, Host, Port, Opts) ->
	ok = proc_lib:init_ack(Parent, {ok, self()}),
	Retry = maps:get(retry, Opts, 5),
	Transport = case maps:get(transport, Opts, default_transport(Port)) of
		tcp -> ranch_tcp;
		ssl -> ranch_ssl
	end,
	connect(#state{parent=Parent, owner=Owner, host=Host, port=Port, opts=Opts, transport=Transport}, Retry).

default_transport(443) -> ssl;
default_transport(_) -> tcp.

connect(State=#state{host=Host, port=Port, opts=Opts, transport=Transport=ranch_ssl}, Retries) ->
	Protocols = lists:flatten([case P of
		http -> <<"http/1.1">>;
		spdy -> [<<"spdy/3.1">>, <<"spdy/3">>]
	end || P <- maps:get(protocols, Opts, [spdy, http])]),
	TransportOpts = [binary, {active, false},
		{client_preferred_next_protocols, {client, Protocols, <<"http/1.1">>}}
		|maps:get(transport_opts, Opts, [])],
	case Transport:connect(Host, Port, TransportOpts) of
		{ok, Socket} ->
			{Protocol, ProtoOptsKey} = case ssl:negotiated_protocol(Socket) of
				{ok, <<"spdy/3", _/bits>>} -> {gun_spdy, spdy_opts};
				_ -> {gun_http, http_opts}
			end,
			up(State, Socket, Protocol, ProtoOptsKey);
		{error, _} ->
			retry(State, Retries - 1)
	end;
connect(State=#state{host=Host, port=Port, opts=Opts, transport=Transport}, Retries) ->
	TransportOpts = [binary, {active, false}
		|maps:get(transport_opts, Opts, [])],
	case Transport:connect(Host, Port, TransportOpts) of
		{ok, Socket} ->
			{Protocol, ProtoOptsKey} = case maps:get(protocols, Opts, [http]) of
				[http] -> {gun_http, http_opts};
				[spdy] -> {gun_spdy, spdy_opts}
			end,
			up(State, Socket, Protocol, ProtoOptsKey);
		{error, _} ->
			retry(State, Retries - 1)
	end.

up(State=#state{owner=Owner, opts=Opts, transport=Transport}, Socket, Protocol, ProtoOptsKey) ->
	ProtoOpts = maps:get(ProtoOptsKey, Opts, #{}),
	ProtoState = Protocol:init(Owner, Socket, Transport, ProtoOpts),
	Owner ! {gun_up, self(), Protocol:name()},
	before_loop(State#state{socket=Socket, protocol=Protocol, protocol_state=ProtoState}).

down(State=#state{owner=Owner, opts=Opts, protocol=Protocol, protocol_state=ProtoState}, Reason) ->
	{KilledStreams, UnprocessedStreams} = Protocol:down(ProtoState),
	Owner ! {gun_down, self(), Protocol:name(), Reason, KilledStreams, UnprocessedStreams},
	retry(State#state{socket=undefined, protocol=undefined, protocol_state=undefined},
		maps:get(retry, Opts, 5)).

%% Exit normally if the retry functionality has been disabled.
retry(_, 0) ->
	ok;
retry(State=#state{keepalive_ref=KeepaliveRef}, Retries) when is_reference(KeepaliveRef) ->
	_ = erlang:cancel_timer(KeepaliveRef),
	%% Flush if we have a keepalive message
	receive
		keepalive -> ok
	after 0 ->
		ok
	end,
	retry_loop(State#state{keepalive_ref=undefined}, Retries);
retry(State, Retries) ->
	retry_loop(State, Retries).

%% Too many retries, give up.
retry_loop(_, 0) ->
	error(gone);
retry_loop(State=#state{parent=Parent, opts=Opts}, Retries) ->
	_ = erlang:send_after(maps:get(retry_timeout, Opts, 5000), self(), retry),
	receive
		retry ->
			connect(State, Retries);
		{system, From, Request} ->
			sys:handle_system_msg(Request, From, Parent, ?MODULE, [],
				{retry_loop, State, Retries})
	end.

before_loop(State=#state{opts=Opts, protocol=Protocol}) ->
	ProtoOptsKey = case Protocol of
		gun_http -> http_opts;
		gun_spdy -> spdy_opts
	end,
	ProtoOpts = maps:get(ProtoOptsKey, Opts, #{}),
	Keepalive = maps:get(keepalive, ProtoOpts, 5000),
	KeepaliveRef = erlang:send_after(Keepalive, self(), keepalive),
	loop(State#state{keepalive_ref=KeepaliveRef}).

loop(State=#state{parent=Parent, owner=Owner, host=Host, port=Port, opts=Opts,
		socket=Socket, transport=Transport, protocol=Protocol, protocol_state=ProtoState}) ->
	{OK, Closed, Error} = Transport:messages(),
	Transport:setopts(Socket, [{active, once}]),
	receive
		{OK, Socket, Data} ->
			case Protocol:handle(Data, ProtoState) of
				close ->
					Transport:close(Socket),
					down(State, normal);
				{upgrade, Protocol2, ProtoState2} ->
					ws_loop(State#state{protocol=Protocol2, protocol_state=ProtoState2});
			ProtoState2 ->
					loop(State#state{protocol_state=ProtoState2})
			end;
		{Closed, Socket} ->
			Protocol:close(ProtoState),
			Transport:close(Socket),
			down(State, closed);
		{Error, Socket, Reason} ->
			Protocol:close(ProtoState),
			Transport:close(Socket),
			down(State, {error, Reason});
		{OK, _PreviousSocket, _Data} ->
			loop(State);
		{Closed, _PreviousSocket} ->
			loop(State);
		{Error, _PreviousSocket, _} ->
			loop(State);
		keepalive ->
			ProtoState2 = Protocol:keepalive(ProtoState),
			before_loop(State#state{protocol_state=ProtoState2});
		{request, Owner, StreamRef, Method, Path, Headers} ->
			ProtoState2 = Protocol:request(ProtoState,
				StreamRef, Method, Host, Port, Path, Headers),
			loop(State#state{protocol_state=ProtoState2});
		{request, Owner, StreamRef, Method, Path, Headers, Body} ->
			ProtoState2 = Protocol:request(ProtoState,
				StreamRef, Method, Host, Port, Path, Headers, Body),
			loop(State#state{protocol_state=ProtoState2});
		{data, Owner, StreamRef, IsFin, Data} ->
			ProtoState2 = Protocol:data(ProtoState,
				StreamRef, IsFin, Data),
			loop(State#state{protocol_state=ProtoState2});
		{cancel, Owner, StreamRef} ->
			ProtoState2 = Protocol:cancel(ProtoState, StreamRef),
			loop(State#state{protocol_state=ProtoState2});
		{ws_upgrade, Owner, StreamRef, Path, Headers} when Protocol =/= gun_spdy ->
			WsOpts = maps:get(ws_opts, Opts, #{}),
			ProtoState2 = Protocol:ws_upgrade(ProtoState, StreamRef, Host, Port, Path, Headers, WsOpts),
			loop(State#state{protocol_state=ProtoState2});
		{ws_upgrade, Owner, StreamRef, Path, Headers, WsOpts} when Protocol =/= gun_spdy ->
			ProtoState2 = Protocol:ws_upgrade(ProtoState, StreamRef, Host, Port, Path, Headers, WsOpts),
			loop(State#state{protocol_state=ProtoState2});
			%% @todo can fail if http/1.0
		{shutdown, Owner} ->
			%% @todo Protocol:shutdown?
			ok;
		{system, From, Request} ->
			sys:handle_system_msg(Request, From, Parent, ?MODULE, [],
				{loop, State});
		{dbg_send_raw, Owner, Data} ->
			Transport:send(Socket, Data),
			loop(State);
		{ws_upgrade, _, StreamRef, _, _} ->
			Owner ! {gun_error, self(), StreamRef, {badstate,
				"Websocket is only supported over HTTP/1.1."}},
			loop(State);
		{ws_upgrade, _, StreamRef, _, _, _} ->
			Owner ! {gun_error, self(), StreamRef, {badstate,
				"Websocket is only supported over HTTP/1.1."}},
			loop(State);
		{ws_send, _, _} ->
			Owner ! {gun_error, self(), {badstate,
				"Connection needs to be upgraded to Websocket "
				"before the gun:ws_send/1 function can be used."}},
			loop(State);
		Any when is_tuple(Any), is_pid(element(2, Any)) ->
			element(2, Any) ! {gun_error, self(), {notowner,
				"Operations are restricted to the owner of the connection."}},
			loop(State);
		Any ->
			error_logger:error_msg("Unexpected message: ~w~n", [Any]),
			loop(State)
	end.

ws_loop(State=#state{parent=Parent, owner=Owner, socket=Socket,
		transport=Transport, protocol=Protocol, protocol_state=ProtoState}) ->
	{OK, Closed, Error} = Transport:messages(),
	ok = Transport:setopts(Socket, [{active, once}]),
	receive
		{OK, Socket, Data} ->
			case Protocol:handle(Data, ProtoState) of
				close ->
					Transport:close(Socket),
					down(State, normal);
				ProtoState2 ->
					ws_loop(State#state{protocol_state=ProtoState2})
			end;
		{Closed, Socket} ->
			Transport:close(Socket),
			down(State, closed);
		{Error, Socket, Reason} ->
			Transport:close(Socket),
			down(State, {error, Reason});
		%% Ignore any previous HTTP keep-alive.
		keepalive ->
			ws_loop(State);
%		{ws_send, Owner, Frames} when is_list(Frames) ->
%			todo; %% @todo
		{ws_send, Owner, Frame} ->
			case Protocol:send(Frame, ProtoState) of
				close ->
					Transport:close(Socket),
					down(State, normal);
				ProtoState2 ->
					ws_loop(State#state{protocol_state=ProtoState2})
			end;
		{shutdown, Owner} ->
			%% @todo Protocol:shutdown? %% @todo close frame
			ok;
		{system, From, Request} ->
			sys:handle_system_msg(Request, From, Parent, ?MODULE, [],
				{ws_loop, State});
		Any when is_tuple(Any), is_pid(element(2, Any)) ->
			element(2, Any) ! {gun_error, self(), {notowner,
				"Operations are restricted to the owner of the connection."}},
			ws_loop(State);
		Any ->
			error_logger:error_msg("Unexpected message: ~w~n", [Any])
	end.

system_continue(_, _, {retry_loop, State, Retry}) ->
	retry_loop(State, Retry);
system_continue(_, _, {loop, State}) ->
	loop(State);
system_continue(_, _, {ws_loop, State}) ->
	ws_loop(State).

-spec system_terminate(any(), _, _, _) -> no_return().
system_terminate(Reason, _, _, _) ->
	exit(Reason).

system_code_change(Misc, _, _, _) ->
	{ok, Misc}.
