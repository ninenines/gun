%% Copyright (c) 2013, Loïc Hoguin <essen@ninenines.eu>
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

%% Cancelling a stream.
-export([cancel/2]).

%% Websocket.
-export([ws_upgrade/2]).
-export([ws_upgrade/3]).
-export([ws_send/2]).

%% Internals.
-export([start_link/4]).
-export([init/5]).

-record(state, {
	parent,
	owner,
	host,
	port,
	keepalive,
	type,
	retry,
	retry_timeout,
	socket,
	transport,
	protocol,
	protocol_state
}).

%% Connection.

open(Host, Port) ->
	open(Host, Port, []).

open(Host, Port, Opts) ->
	case open_opts(Opts) of
		ok ->
			supervisor:start_child(gun_sup, [self(), Host, Port, Opts]);
		Error ->
			Error
	end.

%% @private
open_opts([]) ->
	ok;
open_opts([{keepalive, K}|Opts]) when is_integer(K) ->
	open_opts(Opts);
open_opts([{retry, R}|Opts]) when is_integer(R) ->
	open_opts(Opts);
open_opts([{retry_timeout, T}|Opts]) when is_integer(T) ->
	open_opts(Opts);
open_opts([{type, T}|Opts])
		when T =:= tcp; T =:= tcp_spdy; T =:= ssl ->
	open_opts(Opts);
open_opts([Opt|_]) ->
	{error, {options, Opt}}.

close(ServerPid) ->
	supervisor:terminate_child(gun_sup, ServerPid).

shutdown(ServerPid) ->
	gen_server:call(ServerPid, {shutdown, self()}).

%% Requests.

delete(ServerPid, Path) ->
	request(ServerPid, <<"DELETE">>, Path, []).
delete(ServerPid, Path, Headers) ->
	request(ServerPid, <<"DELETE">>, Path, Headers).

get(ServerPid, Path) ->
	request(ServerPid, <<"GET">>, Path, []).
get(ServerPid, Path, Headers) ->
	request(ServerPid, <<"GET">>, Path, Headers).

head(ServerPid, Path) ->
	request(ServerPid, <<"HEAD">>, Path, []).
head(ServerPid, Path, Headers) ->
	request(ServerPid, <<"HEAD">>, Path, Headers).

options(ServerPid, Path) ->
	request(ServerPid, <<"OPTIONS">>, Path, []).
options(ServerPid, Path, Headers) ->
	request(ServerPid, <<"OPTIONS">>, Path, Headers).

patch(ServerPid, Path, Headers) ->
	request(ServerPid, <<"PATCH">>, Path, Headers).
patch(ServerPid, Path, Headers, Body) ->
	request(ServerPid, <<"PATCH">>, Path, Headers, Body).

post(ServerPid, Path, Headers) ->
	request(ServerPid, <<"POST">>, Path, Headers).
post(ServerPid, Path, Headers, Body) ->
	request(ServerPid, <<"POST">>, Path, Headers, Body).

put(ServerPid, Path, Headers) ->
	request(ServerPid, <<"PUT">>, Path, Headers).
put(ServerPid, Path, Headers, Body) ->
	request(ServerPid, <<"PUT">>, Path, Headers, Body).

request(ServerPid, Method, Path, Headers) ->
	StreamRef = make_ref(),
	_ = ServerPid ! {request, self(), StreamRef, Method, Path, Headers},
	StreamRef.
request(ServerPid, Method, Path, Headers, Body) ->
	StreamRef = make_ref(),
	_ = ServerPid ! {request, self(), StreamRef, Method, Path, Headers, Body},
	StreamRef.

%% Streaming data.

data(ServerPid, StreamRef, IsFin, Data) ->
	_ = ServerPid ! {data, self(), StreamRef, IsFin, Data},
	ok.

%% Cancelling a stream.

cancel(ServerPid, StreamRef) ->
	_ = ServerPid ! {cancel, self(), StreamRef},
	ok.

%% Websocket.

ws_upgrade(ServerPid, Path) ->
	ws_upgrade(ServerPid, Path, []).
ws_upgrade(ServerPid, Path, Headers) ->
	_ = ServerPid ! {ws_upgrade, self(), Path, Headers},
	ok.

ws_send(ServerPid, Payload) ->
	_ = ServerPid ! {ws_send, self(), Payload},
	ok.

%% Internals.

start_link(Owner, Host, Port, Opts) ->
	proc_lib:start_link(?MODULE, init,
		[self(), Owner, Host, Port, Opts]).

%% @doc Faster alternative to proplists:get_value/3.
%% @private
get_value(Key, Opts, Default) ->
	case lists:keyfind(Key, 1, Opts) of
		{_, Value} -> Value;
		_ -> Default
	end.

init(Parent, Owner, Host, Port, Opts) ->
	try
		ok = proc_lib:init_ack(Parent, {ok, self()}),
		Keepalive = get_value(keepalive, Opts, 5000),
		Retry = get_value(retry, Opts, 5),
		RetryTimeout = get_value(retry_timeout, Opts, 5000),
		Type = get_value(type, Opts, ssl),
		connect(#state{parent=Parent, owner=Owner, host=Host, port=Port,
			keepalive=Keepalive, type=Type,
			retry=Retry, retry_timeout=RetryTimeout}, Retry)
	catch Class:Reason ->
		Owner ! {gun_error, self(), {{Class, Reason, erlang:get_stacktrace()},
			"An unexpected error occurred."}}
	end.

connect(State=#state{owner=Owner, host=Host, port=Port, type=ssl}, Retries) ->
	Transport = ranch_ssl,
	Opts = [binary, {active, false}, {client_preferred_next_protocols,
		client, [<<"spdy/3">>, <<"http/1.1">>], <<"http/1.1">>}],
	case Transport:connect(Host, Port, Opts) of
		{ok, Socket} ->
			Protocol = gun_spdy,
%% @todo For some reasons this function doesn't work? Bug submitted.
%			Protocol = case ssl:negotiated_next_protocol(Socket) of
%				{ok, <<"spdy/3">>} -> gun_spdy;
%				_ -> gun_http
%			end,
			ProtoState = Protocol:init(Owner, Socket, Transport),
			before_loop(State#state{socket=Socket, transport=Transport,
				protocol=Protocol, protocol_state=ProtoState});
		{error, _} ->
			retry_loop(State, Retries - 1)
	end;
connect(State=#state{owner=Owner, host=Host, port=Port, type=Type}, Retries) ->
	Transport = ranch_tcp,
	Opts = [binary, {active, false}],
	case Transport:connect(Host, Port, Opts) of
		{ok, Socket} ->
			Protocol = case Type of
				tcp_spdy -> gun_spdy;
				tcp -> gun_http
			end,
			ProtoState = Protocol:init(Owner, Socket, Transport),
			before_loop(State#state{socket=Socket, transport=Transport,
				protocol=Protocol, protocol_state=ProtoState});
		{error, _} ->
			retry_loop(State, Retries - 1)
	end.

%% Too many failures, give up.
retry_loop(_, 0) ->
	error(too_many_retries);
retry_loop(State=#state{parent=Parent, retry_timeout=RetryTimeout}, Retries) ->
	_ = erlang:send_after(RetryTimeout, self(), retry),
	receive
		retry ->
			connect(State, Retries);
		{system, From, Request} ->
			sys:handle_system_msg(Request, From, Parent, ?MODULE, [],
				{retry_loop, [State, Retries]})
	end.

before_loop(State=#state{keepalive=Keepalive}) ->
	_ = erlang:send_after(Keepalive, self(), keepalive),
	loop(State).

loop(State=#state{parent=Parent, owner=Owner, host=Host,
		retry=Retry, socket=Socket, transport=Transport,
		protocol=Protocol, protocol_state=ProtoState}) ->
	{OK, Closed, Error} = Transport:messages(),
	ok = Transport:setopts(Socket, [{active, once}]),
	receive
		{OK, Socket, Data} ->
			case Protocol:handle(Data, ProtoState) of
				error ->
					Transport:close(Socket),
					retry_loop(State#state{socket=undefined,
						transport=undefined, protocol=undefined}, Retry);
				ProtoState2 ->
					loop(State#state{protocol_state=ProtoState2})
			end;
		{Closed, Socket} ->
			Transport:close(Socket),
			retry_loop(State#state{socket=undefined, transport=undefined,
				protocol=undefined}, Retry);
		{Error, Socket, _} ->
			Transport:close(Socket),
			retry_loop(State#state{socket=undefined, transport=undefined,
				protocol=undefined}, Retry);
		keepalive ->
			ProtoState2 = Protocol:keepalive(ProtoState),
			before_loop(State#state{protocol_state=ProtoState2});
		{request, Owner, StreamRef, Method, Path, Headers} ->
			ProtoState2 = Protocol:request(ProtoState,
				StreamRef, Method, Host, Path, Headers),
			loop(State#state{protocol_state=ProtoState2});
		{request, Owner, StreamRef, Method, Path, Headers, Body} ->
			ProtoState2 = Protocol:request(ProtoState,
				StreamRef, Method, Host, Path, Headers, Body),
			loop(State#state{protocol_state=ProtoState2});
		{data, Owner, StreamRef, IsFin, Data} ->
			ProtoState2 = Protocol:data(ProtoState,
				StreamRef, IsFin, Data),
			loop(State#state{protocol_state=ProtoState2});
		{cancel, Owner, StreamRef} ->
			ProtoState2 = Protocol:cancel(ProtoState, StreamRef),
			loop(State#state{protocol_state=ProtoState2});
		{ws_upgrade, Owner, Path, Headers} when Protocol =/= gun_spdy ->
			%% @todo
			ProtoState2 = Protocol:ws_upgrade(ProtoState,
				Path, Headers),
			ws_loop(State#state{protocol=gun_ws, protocol_state=ProtoState2});
		{shutdown, Owner} ->
			%% @todo Protocol:shutdown?
			ok;
		{system, From, Request} ->
			sys:handle_system_msg(Request, From, Parent, ?MODULE, [],
				{loop, [State]});
		Any when is_tuple(Any), is_pid(element(2, Any)) ->
			element(2, Any) ! {gun_error, self(), {notowner,
				"Operations are restricted to the owner of the connection."}},
			loop(State);
		{ws_upgrade, _, _, _} ->
			Owner ! {gun_error, self(), {badstate,
				"Websocket over SPDY isn't supported."}},
			loop(State);
		{ws_send, _, _} ->
			Owner ! {gun_error, self(), {badstate,
				"Connection needs to be upgraded to Websocket "
				"before the gun:ws_send/1 function can be used."}},
			loop(State);
		Any ->
			error_logger:error_msg("Unexpected message: ~w~n", [Any])
	end.

ws_loop(State=#state{parent=Parent, owner=Owner, retry=Retry, socket=Socket,
		transport=Transport, protocol=Protocol, protocol_state=ProtoState}) ->
	{OK, Closed, Error} = Transport:messages(),
	ok = Transport:setopts(Socket, [{active, once}]),
	receive
		{OK, Socket, Data} ->
			ProtoState2 = Protocol:handle(ProtoState, Data),
			ws_loop(State#state{protocol_state=ProtoState2});
		{Closed, Socket} ->
			Transport:close(Socket),
			retry_loop(State#state{socket=undefined, transport=undefined,
				protocol=undefined}, Retry);
		{Error, Socket, _} ->
			Transport:close(Socket),
			retry_loop(State#state{socket=undefined, transport=undefined,
				protocol=undefined}, Retry);
		{ws_send, Owner, Frames} when is_list(Frames) ->
			todo; %% @todo
		{ws_send, Owner, Frame} ->
			{todo, Frame}; %% @todo
		{shutdown, Owner} ->
			%% @todo Protocol:shutdown?
			ok;
		{system, From, Request} ->
			sys:handle_system_msg(Request, From, Parent, ?MODULE, [],
				{loop, [State]});
		Any when is_tuple(Any), is_pid(element(2, Any)) ->
			element(2, Any) ! {gun_error, self(), {notowner,
				"Operations are restricted to the owner of the connection."}},
			loop(State);
		Any ->
			error_logger:error_msg("Unexpected message: ~w~n", [Any])
	end.
