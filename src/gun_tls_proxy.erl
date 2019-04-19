%% Copyright (c) 2019, Loïc Hoguin <essen@ninenines.eu>
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

%% Intermediary process for proxying TLS connections. This process
%% is started by Gun when CONNECT request is issued and stays alive
%% while the proxy connection exists.
%%
%% Data comes in and out of this process, which is responsible for
%% passing incoming/outgoing data through the fake ssl socket process
%% it created to perform the decoding/encoding operations.
%%
%% Normal scenario:
%%   Gun process -> TLS socket
%%
%% One proxy socket scenario:
%%   Gun process -> gun_tls_proxy (proxied socket) -> TLS socket
%%
%% N proxy socket scenario:
%%   Gun process -> gun_tls_proxy -> ... -> gun_tls_proxy -> TLS socket
%%
%% The difficult part is the connection. Because ssl:connect/4 does
%% not return until the connection is setup, and we need to send and
%% receive data for the TLS handshake, we need a temporary process
%% to call this function, and communicate with it. Once the connection
%% is setup the temporary process is gone and things go back to normal.
%% The send operations also require a temporary process in order to avoid
%% blocking because the same gun_tls_proxy process must send twice (first
%% to the fake ssl socket and then to the outgoing socket).

-module(gun_tls_proxy).

-behaviour(gen_server).

%% Gun-specific interface.
-export([start_link/6]).

%% gun_tls_proxy_cb interface.
-export([cb_controlling_process/2]).
-export([cb_send/2]).
-export([cb_setopts/2]).

%% Gun transport.
-export([name/0]).
-export([messages/0]).
-export([connect/3]).
-export([connect/4]).
-export([send/2]).
-export([setopts/2]).
-export([sockname/1]).
-export([close/1]).

%% gen_server.
-export([init/1]).
-export([connect_proc/5]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_info/2]).

-record(state, {
	%% The pid of the owner process. This is where we send active messages.
	owner_pid :: pid(),
	owner_active = false :: false | once | true | pos_integer(),
	owner_buffer = <<>> :: binary(),

	%% The host/port the fake ssl socket thinks it's connected to.
	host :: inet:ip_address() | inet:hostname(),
	port :: inet:port_number(),

	%% The fake ssl socket we are using in the proxy.
	proxy_socket :: any(),
	proxy_pid :: pid(),
	proxy_active = false :: false | once | true | pos_integer(),
	proxy_buffer = <<>> :: binary(),

	%% The socket or proxy process we are sending to.
	out_socket :: any(),
	out_transport :: module(),
	out_messages :: {atom(), atom(), atom()} %% @todo Missing passive.
}).

-ifdef(DEBUG_PROXY).
-define(DEBUG_LOG(Format, Args),
	io:format(user, "(~p) ~p:~p/~p:" ++ Format ++ "~n",
		[self(), ?MODULE, ?FUNCTION_NAME, ?FUNCTION_ARITY] ++ Args)).
-else.
-define(DEBUG_LOG(Format, Args), _ = Format, _ = Args, ok).
-endif.

%% Gun-specific interface.

start_link(Host, Port, Opts, Timeout, OutSocket, OutTransport) ->
	?DEBUG_LOG("host ~0p port ~0p opts ~0p timeout ~0p out_socket ~0p out_transport ~0p",
		[Host, Port, Opts, Timeout, OutSocket, OutTransport]),

	case gen_server:start_link(?MODULE,
			{self(), Host, Port, Opts, Timeout, OutSocket, OutTransport},
			[]) of
		{ok, Pid} when is_port(OutSocket) ->
			gen_tcp:controlling_process(OutSocket, Pid),
			{ok, Pid};
		{ok, Pid} when not is_pid(OutSocket) ->
			ssl:controlling_process(OutSocket, Pid),
			{ok, Pid};
		Other ->
			Other
	end.

%% gun_tls_proxy_cb interface.

cb_controlling_process(Pid, ControllingPid) ->
	?DEBUG_LOG("pid ~0p controlling_pid ~0p", [Pid, ControllingPid]),
	gen_server:cast(Pid, {?FUNCTION_NAME, ControllingPid}).

cb_send(Pid, Data) ->
	?DEBUG_LOG("pid ~0p data ~0p", [Pid, Data]),
	try
		gen_server:call(Pid, {?FUNCTION_NAME, Data})
	catch
		exit:{noproc, _} ->
			{error, closed}
	end.

cb_setopts(Pid, Opts) ->
	?DEBUG_LOG("pid ~0p opts ~0p", [Pid, Opts]),
	try
		gen_server:call(Pid, {?FUNCTION_NAME, Opts})
	catch
		exit:{noproc, _} ->
			{error, einval}
	end.

%% Transport.

name() -> tls_proxy.

messages() -> {tls_proxy, tls_proxy_closed, tls_proxy_error}.

-spec connect(_, _, _) -> no_return().
connect(_, _, _) ->
	error(not_implemented).

-spec connect(_, _, _, _) -> no_return().
connect(_, _, _, _) ->
	error(not_implemented).

-spec send(pid(), iodata()) -> ok | {error, atom()}.
send(Pid, Data) ->
	?DEBUG_LOG("pid ~0p data ~0p", [Pid, Data]),
	gen_server:call(Pid, {?FUNCTION_NAME, Data}).

-spec setopts(pid(), list()) -> ok.
setopts(Pid, Opts) ->
	?DEBUG_LOG("pid ~0p opts ~0p", [Pid, Opts]),
	gen_server:cast(Pid, {?FUNCTION_NAME, Opts}).

-spec sockname(pid())
	-> {ok, {inet:ip_address(), inet:port_number()}} | {error, atom()}.
sockname(Pid) ->
	?DEBUG_LOG("pid ~0p", [Pid]),
	gen_server:call(Pid, ?FUNCTION_NAME).

-spec close(pid()) -> ok.
close(Pid) ->
	?DEBUG_LOG("pid ~0p", [Pid]),
	gen_server:call(Pid, ?FUNCTION_NAME).

%% gen_server.
%% @todo Probably need to gen_statem it to avoid trying to send stuff before being connected.

init({OwnerPid, Host, Port, Opts, Timeout, OutSocket, OutTransport}) ->
	if
		is_pid(OutSocket) ->
			gen_server:cast(OutSocket, {set_owner, self()});
		true ->
			ok
	end,
	Messages = case OutTransport of
		gen_tcp -> {tcp, tcp_closed, tcp_error};
		ssl -> {ssl, ssl_closed, ssl_error};
		_ -> OutTransport:messages()
	end,
	ProxyPid = spawn_link(?MODULE, connect_proc, [self(), Host, Port, Opts, Timeout]),
	?DEBUG_LOG("owner_pid ~0p host ~0p port ~0p opts ~0p timeout ~0p"
		" out_socket ~0p out_transport ~0p proxy_pid ~0p",
		[OwnerPid, Host, Port, Opts, Timeout, OutSocket, OutTransport, ProxyPid]),
	{ok, #state{owner_pid=OwnerPid, host=Host, port=Port, proxy_pid=ProxyPid,
		out_socket=OutSocket, out_transport=OutTransport, out_messages=Messages}}.

connect_proc(ProxyPid, Host, Port, Opts, Timeout) ->
	?DEBUG_LOG("proxy_pid ~0p host ~0p port ~0p opts ~0p timeout ~0p",
		[ProxyPid, Host, Port, Opts, Timeout]),
	_ = case ssl:connect(Host, Port, [
		{active, false}, binary,
		{cb_info, {gun_tls_proxy_cb, tls_proxy, tls_proxy_closed, tls_proxy_error}},
		{?MODULE, ProxyPid}
	|Opts], Timeout) of
		{ok, Socket} ->
			?DEBUG_LOG("socket ~0p", [Socket]),
			ssl:controlling_process(Socket, ProxyPid),
			gen_server:cast(ProxyPid, {?FUNCTION_NAME, {ok, Socket}});
		Error ->
			?DEBUG_LOG("error ~0p", [Error]),
			gen_server:cast(ProxyPid, {?FUNCTION_NAME, Error})
	end,
	ok.

handle_call(Msg={cb_send, Data}, From, State=#state{
		out_socket=OutSocket, out_transport=OutTransport}) ->
	?DEBUG_LOG("msg ~0p from ~0p state ~0p", [Msg, From, State]),
	Self = self(),
	SpawnedPid = spawn(fun() ->
		gen_server:cast(Self, {send_result, From, OutTransport:send(OutSocket, Data)})
	end),
	?DEBUG_LOG("spawned ~0p", [SpawnedPid]),
	{noreply, State};
handle_call(Msg={cb_setopts, Opts}, From, State=#state{
		out_socket=OutSocket, out_transport=OutTransport0}) ->
	?DEBUG_LOG("msg ~0p from ~0p state ~0p", [Msg, From, State]),
	OutTransport = case OutTransport0 of
		gen_tcp -> inet;
		_ -> OutTransport0
	end,
	{reply, OutTransport:setopts(OutSocket, [{active, true}]), proxy_setopts(Opts, State)};
%% @todo If Socket is undefined here we need to buffer input
%% and send it when we receive the {connect_proc, {ok, Socket}} message.
handle_call(Msg={send, Data}, From, State=#state{proxy_socket=Socket}) ->
	?DEBUG_LOG("msg ~0p from ~0p state ~0p", [Msg, From, State]),
	Self = self(),
	SpawnedPid = spawn(fun() ->
		gen_server:cast(Self, {send_result, From, ssl:send(Socket, Data)})
	end),
	?DEBUG_LOG("spawned ~0p", [SpawnedPid]),
	{noreply, State};
handle_call(Msg=sockname, From, State=#state{
		out_socket=OutSocket, out_transport=OutTransport}) ->
	?DEBUG_LOG("msg ~0p from ~0p state ~0p", [Msg, From, State]),
	{reply, OutTransport:sockname(OutSocket), State};
handle_call(Msg=close, From, State) ->
	?DEBUG_LOG("msg ~0p from ~0p state ~0p", [Msg, From, State]),
	{stop, {shutdown, close}, State};
handle_call(Msg, From, State) ->
	?DEBUG_LOG("IGNORED msg ~0p from ~0p state ~0p", [Msg, From, State]),
	{reply, {error, bad_call}, State}.

handle_cast(Msg={set_owner, OwnerPid}, State) ->
	?DEBUG_LOG("msg ~0p state ~0p", [Msg, State]),
	{noreply, State#state{owner_pid=OwnerPid}};
handle_cast(Msg={connect_proc, {ok, Socket}}, State) ->
	?DEBUG_LOG("msg ~0p state ~0p", [Msg, State]),
	ok = ssl:setopts(Socket, [{active, true}]),
	{noreply, State#state{proxy_socket=Socket}};
handle_cast(Msg={connect_proc, Error}, State) ->
	?DEBUG_LOG("msg ~0p state ~0p", [Msg, State]),
	{stop, Error, State};
handle_cast(Msg={cb_controlling_process, ProxyPid}, State) ->
	?DEBUG_LOG("msg ~0p state ~0p", [Msg, State]),
	%% We link so that the ssl process terminates when we do.
	link(ProxyPid),
	{noreply, State#state{proxy_pid=ProxyPid}};
handle_cast(Msg={setopts, Opts}, State) ->
	?DEBUG_LOG("msg ~0p state ~0p", [Msg, State]),
	{noreply, owner_setopts(Opts, State)};
handle_cast(Msg={send_result, From, Result}, State) ->
	?DEBUG_LOG("msg ~0p state ~0p", [Msg, State]),
	gen_server:reply(From, Result),
	{noreply, State};
handle_cast(Msg, State) ->
	?DEBUG_LOG("IGNORED msg ~0p state ~0p", [Msg, State]),
	{noreply, State}.

%% Messages from the real socket.
handle_info(Msg={OK, Socket, Data}, State=#state{proxy_pid=ProxyPid,
		out_socket=Socket, out_messages={OK, _, _}}) ->
	?DEBUG_LOG("msg ~0p state ~0p", [Msg, State]),
	ProxyPid ! {tls_proxy, self(), Data},
	{noreply, State};
handle_info(Msg={Closed, Socket}, State=#state{proxy_pid=ProxyPid,
		out_socket=Socket, out_messages={_, Closed, _}}) ->
	?DEBUG_LOG("msg ~0p state ~0p", [Msg, State]),
	ProxyPid ! {tls_proxy_closed, self()},
	{noreply, State};
handle_info(Msg={Error, Socket, Reason}, State=#state{proxy_pid=ProxyPid,
		out_socket=Socket, out_messages={_, _, Error}}) ->
	?DEBUG_LOG("msg ~0p state ~0p", [Msg, State]),
	ProxyPid ! {tls_proxy_error, self(), Reason},
	{noreply, State};
%% Messages from the proxy socket.
handle_info(Msg={ssl, Socket, Data}, State=#state{owner_pid=OwnerPid, proxy_socket=Socket}) ->
	?DEBUG_LOG("msg ~0p state ~0p", [Msg, State]),
	OwnerPid ! {tls_proxy, self(), Data},
	{noreply, State};
handle_info(Msg={ssl_closed, Socket}, State=#state{owner_pid=OwnerPid, proxy_socket=Socket}) ->
	?DEBUG_LOG("msg ~0p state ~0p", [Msg, State]),
	OwnerPid ! {tls_proxy_closed, self()},
	{noreply, State};
handle_info(Msg={ssl_error, Socket, Reason}, State=#state{owner_pid=OwnerPid, proxy_socket=Socket}) ->
	?DEBUG_LOG("msg ~0p state ~0p", [Msg, State]),
	OwnerPid ! {tls_proxy_error, self(), Reason},
	{noreply, State};
%% Other messages.
handle_info(Msg, State) ->
	?DEBUG_LOG("IGNORED msg ~0p state ~0p", [Msg, State]),
	{noreply, State}.

%% Internal.

owner_setopts(Opts, State0) ->
	case [A || {active, A} <- Opts] of
		[] -> State0;
		[false] -> State0#state{owner_active=false};
%		[0] -> OwnerPid ! {tls_proxy_passive, self()}, State0#state{owner_active=false};
		[Active] -> owner_active(State0#state{owner_active=Active})
	end.

owner_active(State=#state{owner_buffer= <<>>}) ->
	State;
owner_active(State=#state{owner_active=false}) ->
	State;
owner_active(State=#state{owner_pid=OwnerPid, owner_active=Active0, owner_buffer=Buffer}) ->
	OwnerPid ! {tls_proxy, self(), Buffer},
	Active = case Active0 of
		true -> true;
		once -> false%;
%		1 -> OwnerPid ! {tls_proxy_passive, self()}, false;
%		N -> N - 1
	end,
	State#state{owner_active=Active, owner_buffer= <<>>}.

proxy_setopts(Opts, State0=#state{proxy_socket=ProxySocket, proxy_pid=ProxyPid}) ->
	case [A || {active, A} <- Opts] of
		[] -> State0;
		[false] -> State0#state{proxy_active=false};
		[0] -> ProxyPid ! {tls_proxy_passive, ProxySocket}, State0#state{proxy_active=false};
		[Active] -> proxy_active(State0#state{proxy_active=Active})
	end.

proxy_active(State=#state{proxy_buffer= <<>>}) ->
	State;
proxy_active(State=#state{proxy_active=false}) ->
	State;
proxy_active(State=#state{proxy_pid=ProxyPid, proxy_active=Active0, proxy_buffer=Buffer}) ->
	ProxyPid ! {tls_proxy, self(), Buffer},
	Active = case Active0 of
		true -> true;
		once -> false;
		%% Note that tcp_passive is hardcoded in ssl until OTP-21.3.1.
		1 -> ProxyPid ! {tcp_passive, self()}, false;
		N -> N - 1
	end,
	State#state{proxy_active=Active, proxy_buffer= <<>>}.

-ifdef(TEST).
tcp_test() ->
	ssl:start(),
	{ok, Socket} = gen_tcp:connect("google.com", 443, [binary, {active, false}]),
	{ok, ProxyPid1} = start_link("google.com", 443, [], 5000, Socket, gen_tcp),
	timer:sleep(500),
	send(ProxyPid1, <<"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n">>),
	timer:sleep(1000),
	receive {tls_proxy, ProxyPid1, <<"HTTP/1.1 ", _/bits>>} -> ok after 1000 -> error(timeout) end.

ssl_test() ->
	ssl:start(),
	_ = (catch ct_helper:make_certs_in_ets()),
	{ok, _, Port} = do_proxy_start("google.com", 443),
	{ok, Socket} = ssl:connect("localhost", Port, [binary, {active, false}]),
	timer:sleep(500),
	{ok, ProxyPid1} = start_link("google.com", 443, [], 5000, Socket, ssl),
	timer:sleep(500),
	send(ProxyPid1, <<"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n">>),
	timer:sleep(1000),
	receive {tls_proxy, ProxyPid1, <<"HTTP/1.1 ", _/bits>>} -> ok after 1000 -> error(timeout) end.

ssl2_test() ->
	ssl:start(),
	_ = (catch ct_helper:make_certs_in_ets()),
	{ok, _, Port1} = do_proxy_start("google.com", 443),
	{ok, _, Port2} = do_proxy_start("localhost", Port1),
	{ok, Socket} = ssl:connect("localhost", Port2, [binary, {active, false}]),
	timer:sleep(500),
	{ok, ProxyPid1} = start_link("localhost", Port1, [], 5000, Socket, ssl),
	timer:sleep(500),
	{ok, ProxyPid2} = start_link("google.com", 443, [], 5000, ProxyPid1, ?MODULE),
	timer:sleep(500),
	send(ProxyPid2, <<"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n">>),
	timer:sleep(1000),
	receive {tls_proxy, ProxyPid2, <<"HTTP/1.1 ", _/bits>>} -> ok after 1000 -> error(timeout) end.

do_proxy_start(Host, Port) ->
	Self = self(),
	Pid = spawn_link(fun() -> do_proxy_init(Self, Host, Port) end),
	ListenPort = receive_from(Pid),
	{ok, Pid, ListenPort}.

do_proxy_init(Parent, Host, Port) ->
	Opts = ct_helper:get_certs_from_ets(),
	{ok, ListenSocket} = ssl:listen(0, [binary, {active, false}|Opts]),
	{ok, {_, ListenPort}} = ssl:sockname(ListenSocket),
	Parent ! {self(), ListenPort},
	{ok, ClientSocket} = ssl:transport_accept(ListenSocket, 10000),
	{ok, _} = ssl:handshake(ClientSocket, 10000),
	{ok, OriginSocket} = gen_tcp:connect(
		Host, Port,
		[binary, {active, false}]),
	ssl:setopts(ClientSocket, [{active, true}]),
	inet:setopts(OriginSocket, [{active, true}]),
	do_proxy_loop(ClientSocket, OriginSocket).

do_proxy_loop(ClientSocket, OriginSocket) ->
	receive
		{ssl, ClientSocket, Data} ->
			ok = gen_tcp:send(OriginSocket, Data),
			do_proxy_loop(ClientSocket, OriginSocket);
		{tcp, OriginSocket, Data} ->
			ok = ssl:send(ClientSocket, Data),
			do_proxy_loop(ClientSocket, OriginSocket);
		{tcp_closed, _} ->
			ok;
		Msg ->
			error(Msg)
	end.

receive_from(Pid) ->
	receive_from(Pid, 5000).

receive_from(Pid, Timeout) ->
	receive
		{Pid, Msg} ->
			Msg
	after Timeout ->
		error(timeout)
	end.
-endif.
