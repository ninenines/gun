%% Copyright (c) 2013-2019, Loïc Hoguin <essen@ninenines.eu>
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
-behavior(gen_statem).

-ifdef(OTP_RELEASE).
-compile({nowarn_deprecated_function, [{erlang, get_stacktrace, 0}]}).
-endif.

%% Connection.
-export([open/2]).
-export([open/3]).
-export([open_unix/2]).
-export([info/1]).
-export([close/1]).
-export([shutdown/1]).

%% Requests.
-export([delete/2]).
-export([delete/3]).
-export([delete/4]).
-export([get/2]).
-export([get/3]).
-export([get/4]).
-export([head/2]).
-export([head/3]).
-export([head/4]).
-export([options/2]).
-export([options/3]).
-export([options/4]).
-export([patch/3]).
-export([patch/4]).
-export([patch/5]).
-export([post/3]).
-export([post/4]).
-export([post/5]).
-export([put/3]).
-export([put/4]).
-export([put/5]).

%% Generic requests interface.
-export([headers/4]).
-export([headers/5]).
-export([request/5]).
-export([request/6]).

%% Streaming data.
-export([data/4]).

%% Tunneling.
-export([connect/2]).
-export([connect/3]).
-export([connect/4]).

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

%% Streams.
-export([update_flow/3]).
-export([cancel/2]).
-export([stream_info/2]).

%% Websocket.
-export([ws_upgrade/2]).
-export([ws_upgrade/3]).
-export([ws_upgrade/4]).
-export([ws_send/2]).

%% Internals.
-export([start_link/4]).
-export([callback_mode/0]).
-export([init/1]).
-export([not_connected/3]).
-export([domain_lookup/3]).
-export([connecting/3]).
-export([tls_handshake/3]).
-export([connected/3]).
-export([closing/3]).
-export([terminate/3]).

-type req_headers() :: [{binary() | string() | atom(), iodata()}]
	| #{binary() | string() | atom() => iodata()}.
-export_type([req_headers/0]).

-type ws_close_code() :: 1000..4999.

-type ws_frame() :: close | ping | pong
	| {text | binary | close | ping | pong, iodata()}
	| {close, ws_close_code(), iodata()}.
-export_type([ws_frame/0]).

-type opts() :: #{
	connect_timeout => timeout(),
	domain_lookup_timeout => timeout(),
	event_handler => {module(), any()},
	http_opts => http_opts(),
	http2_opts => http2_opts(),
	protocols => [http | http2],
	retry => non_neg_integer(),
	retry_fun => fun((non_neg_integer(), opts())
		-> #{retries => non_neg_integer(), timeout => pos_integer()}),
	retry_timeout => pos_integer(),
	supervise => boolean(),
	tcp_opts => [gen_tcp:connect_option()],
	tls_handshake_timeout => timeout(),
	tls_opts => [ssl:tls_client_option()],
	trace => boolean(),
	transport => tcp | tls | ssl,
	ws_opts => ws_opts()
}.
-export_type([opts/0]).
%% @todo Add an option to disable/enable the notowner behavior.

-type connect_destination() :: #{
	host := inet:hostname() | inet:ip_address(),
	port := inet:port_number(),
	username => iodata(),
	password => iodata(),
	protocol => http | http2, %% @todo Remove in Gun 2.0.
	protocols => [http | http2],
	transport => tcp | tls,
	tls_opts => [ssl:tls_client_option()],
	tls_handshake_timeout => timeout()
}.
-export_type([connect_destination/0]).

-type intermediary() :: #{
	type := connect,
	host := inet:hostname() | inet:ip_address(),
	port := inet:port_number(),
	transport := tcp | tls,
	protocol := http | http2
}.

%% @todo When/if HTTP/2 CONNECT gets implemented, we will want an option here
%% to indicate that the request must be sent on an existing CONNECT stream.
%% This is of course not required for HTTP/1.1 since the CONNECT takes over
%% the entire connection.
-type req_opts() :: #{
	flow => pos_integer(),
	reply_to => pid()
}.
-export_type([req_opts/0]).

-type http_opts() :: #{
	closing_timeout => timeout(),
	flow => pos_integer(),
	keepalive => timeout(),
	transform_header_name => fun((binary()) -> binary()),
	version => 'HTTP/1.1' | 'HTTP/1.0'
}.
-export_type([http_opts/0]).

-type http2_opts() :: #{
	closing_timeout => timeout(),
	flow => pos_integer(),
	keepalive => timeout()
}.
-export_type([http2_opts/0]).

%% @todo keepalive
-type ws_opts() :: #{
	closing_timeout => timeout(),
	compress => boolean(),
	flow => pos_integer(),
	protocols => [{binary(), module()}]
}.
-export_type([ws_opts/0]).

-record(state, {
	owner :: pid(),
	status :: {up, reference()} | {down, any()} | shutdown,
	host :: inet:hostname() | inet:ip_address(),
	port :: inet:port_number(),
	origin_scheme :: binary(),
	origin_host :: inet:hostname() | inet:ip_address(),
	origin_port :: inet:port_number(),
	intermediaries = [] :: [intermediary()],
	opts :: opts(),
	keepalive_ref :: undefined | reference(),
	socket :: undefined | inet:socket() | ssl:sslsocket() | pid(),
	transport :: module(),
	active = true :: boolean(),
	messages :: {atom(), atom(), atom()},
	protocol :: module(),
	protocol_state :: any(),
	event_handler :: module(),
	event_handler_state :: any()
}).

%% Connection.

-spec open(inet:hostname() | inet:ip_address(), inet:port_number())
	-> {ok, pid()} | {error, any()}.
open(Host, Port) ->
	open(Host, Port, #{}).

-spec open(inet:hostname() | inet:ip_address(), inet:port_number(), opts())
	-> {ok, pid()} | {error, any()}.
open(Host, Port, Opts) when is_list(Host); is_atom(Host); is_tuple(Host) ->
	do_open(Host, Port, Opts).

-spec open_unix(Path::string(), opts())
	-> {ok, pid()} | {error, any()}.
open_unix(SocketPath, Opts) ->
	do_open({local, SocketPath}, 0, Opts).

do_open(Host, Port, Opts0) ->
	%% We accept both ssl and tls but only use tls in the code.
	Opts = case Opts0 of
		#{transport := ssl} -> Opts0#{transport => tls};
		_ -> Opts0
	end,
	case check_options(maps:to_list(Opts)) of
		ok ->
			Result = case maps:get(supervise, Opts, true) of
				true -> supervisor:start_child(gun_sup, [self(), Host, Port, Opts]);
				false -> start_link(self(), Host, Port, Opts)
			end,
			case Result of
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
check_options([{connect_timeout, infinity}|Opts]) ->
	check_options(Opts);
check_options([{connect_timeout, T}|Opts]) when is_integer(T), T >= 0 ->
	check_options(Opts);
check_options([{domain_lookup_timeout, infinity}|Opts]) ->
	check_options(Opts);
check_options([{domain_lookup_timeout, T}|Opts]) when is_integer(T), T >= 0 ->
	check_options(Opts);
check_options([{event_handler, {Mod, _}}|Opts]) when is_atom(Mod) ->
	check_options(Opts);
check_options([{http_opts, ProtoOpts}|Opts]) when is_map(ProtoOpts) ->
	case gun_http:check_options(ProtoOpts) of
		ok ->
			check_options(Opts);
		Error ->
			Error
	end;
check_options([{http2_opts, ProtoOpts}|Opts]) when is_map(ProtoOpts) ->
	case gun_http2:check_options(ProtoOpts) of
		ok ->
			check_options(Opts);
		Error ->
			Error
	end;
check_options([Opt = {protocols, L}|Opts]) when is_list(L) ->
	Len = length(L),
	case length(lists:usort(L)) of
		Len when Len > 0 ->
			Check = lists:usort([(P =:= http) orelse (P =:= http2) || P <- L]),
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
check_options([{retry_fun, F}|Opts]) when is_function(F, 2) ->
	check_options(Opts);
check_options([{retry_timeout, T}|Opts]) when is_integer(T), T >= 0 ->
	check_options(Opts);
check_options([{supervise, B}|Opts]) when B =:= true; B =:= false ->
	check_options(Opts);
check_options([{tcp_opts, L}|Opts]) when is_list(L) ->
	check_options(Opts);
check_options([{tls_handshake_timeout, infinity}|Opts]) ->
	check_options(Opts);
check_options([{tls_handshake_timeout, T}|Opts]) when is_integer(T), T >= 0 ->
	check_options(Opts);
check_options([{tls_opts, L}|Opts]) when is_list(L) ->
	check_options(Opts);
check_options([{trace, B}|Opts]) when B =:= true; B =:= false ->
	check_options(Opts);
check_options([{transport, T}|Opts]) when T =:= tcp; T =:= tls ->
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
	dbg:tracer(),
	dbg:tpl(gun, [{'_', [], [{return_trace}]}]),
	dbg:tpl(gun_http, [{'_', [], [{return_trace}]}]),
	dbg:tpl(gun_http2, [{'_', [], [{return_trace}]}]),
	dbg:tpl(gun_ws, [{'_', [], [{return_trace}]}]),
	dbg:p(ServerPid, all);
consider_tracing(_, _) ->
	ok.

-spec info(pid()) -> map().
info(ServerPid) ->
	{_, #state{
		socket=Socket,
		transport=Transport,
		protocol=Protocol,
		origin_scheme=OriginScheme,
		origin_host=OriginHost,
		origin_port=OriginPort,
		intermediaries=Intermediaries
	}} = sys:get_state(ServerPid),
	{ok, {SockIP, SockPort}} = Transport:sockname(Socket),
	#{
		socket => Socket,
		transport => case OriginScheme of
			<<"http">> -> tcp;
			<<"https">> -> tls
		end,
		protocol => Protocol:name(),
		sock_ip => SockIP,
		sock_port => SockPort,
		origin_scheme => OriginScheme,
		origin_host => OriginHost,
		origin_port => OriginPort,
		%% Intermediaries are listed in the order data goes through them.
		intermediaries => lists:reverse(Intermediaries)
	}.

-spec close(pid()) -> ok.
close(ServerPid) ->
	supervisor:terminate_child(gun_sup, ServerPid).

-spec shutdown(pid()) -> ok.
shutdown(ServerPid) ->
	gen_statem:cast(ServerPid, {shutdown, self()}).

%% Requests.

-spec delete(pid(), iodata()) -> reference().
delete(ServerPid, Path) ->
	request(ServerPid, <<"DELETE">>, Path, [], <<>>).

-spec delete(pid(), iodata(), req_headers()) -> reference().
delete(ServerPid, Path, Headers) ->
	request(ServerPid, <<"DELETE">>, Path, Headers, <<>>).

-spec delete(pid(), iodata(), req_headers(), req_opts()) -> reference().
delete(ServerPid, Path, Headers, ReqOpts) ->
	request(ServerPid, <<"DELETE">>, Path, Headers, <<>>, ReqOpts).

-spec get(pid(), iodata()) -> reference().
get(ServerPid, Path) ->
	request(ServerPid, <<"GET">>, Path, [], <<>>).

-spec get(pid(), iodata(), req_headers()) -> reference().
get(ServerPid, Path, Headers) ->
	request(ServerPid, <<"GET">>, Path, Headers, <<>>).

-spec get(pid(), iodata(), req_headers(), req_opts()) -> reference().
get(ServerPid, Path, Headers, ReqOpts) ->
	request(ServerPid, <<"GET">>, Path, Headers, <<>>, ReqOpts).

-spec head(pid(), iodata()) -> reference().
head(ServerPid, Path) ->
	request(ServerPid, <<"HEAD">>, Path, [], <<>>).

-spec head(pid(), iodata(), req_headers()) -> reference().
head(ServerPid, Path, Headers) ->
	request(ServerPid, <<"HEAD">>, Path, Headers, <<>>).

-spec head(pid(), iodata(), req_headers(), req_opts()) -> reference().
head(ServerPid, Path, Headers, ReqOpts) ->
	request(ServerPid, <<"HEAD">>, Path, Headers, <<>>, ReqOpts).

-spec options(pid(), iodata()) -> reference().
options(ServerPid, Path) ->
	request(ServerPid, <<"OPTIONS">>, Path, [], <<>>).

-spec options(pid(), iodata(), req_headers()) -> reference().
options(ServerPid, Path, Headers) ->
	request(ServerPid, <<"OPTIONS">>, Path, Headers, <<>>).

-spec options(pid(), iodata(), req_headers(), req_opts()) -> reference().
options(ServerPid, Path, Headers, ReqOpts) ->
	request(ServerPid, <<"OPTIONS">>, Path, Headers, <<>>, ReqOpts).

-spec patch(pid(), iodata(), req_headers()) -> reference().
patch(ServerPid, Path, Headers) ->
	headers(ServerPid, <<"PATCH">>, Path, Headers).

-spec patch(pid(), iodata(), req_headers(), iodata() | req_opts()) -> reference().
patch(ServerPid, Path, Headers, ReqOpts) when is_map(ReqOpts) ->
	headers(ServerPid, <<"PATCH">>, Path, Headers, ReqOpts);
patch(ServerPid, Path, Headers, Body) ->
	request(ServerPid, <<"PATCH">>, Path, Headers, Body).

-spec patch(pid(), iodata(), req_headers(), iodata(), req_opts()) -> reference().
patch(ServerPid, Path, Headers, Body, ReqOpts) ->
	request(ServerPid, <<"PATCH">>, Path, Headers, Body, ReqOpts).

-spec post(pid(), iodata(), req_headers()) -> reference().
post(ServerPid, Path, Headers) ->
	headers(ServerPid, <<"POST">>, Path, Headers).

-spec post(pid(), iodata(), req_headers(), iodata() | req_opts()) -> reference().
post(ServerPid, Path, Headers, ReqOpts) when is_map(ReqOpts) ->
	headers(ServerPid, <<"POST">>, Path, Headers, ReqOpts);
post(ServerPid, Path, Headers, Body) ->
	request(ServerPid, <<"POST">>, Path, Headers, Body).

-spec post(pid(), iodata(), req_headers(), iodata(), req_opts()) -> reference().
post(ServerPid, Path, Headers, Body, ReqOpts) ->
	request(ServerPid, <<"POST">>, Path, Headers, Body, ReqOpts).

-spec put(pid(), iodata(), req_headers()) -> reference().
put(ServerPid, Path, Headers) ->
	headers(ServerPid, <<"PUT">>, Path, Headers).

-spec put(pid(), iodata(), req_headers(), iodata() | req_opts()) -> reference().
put(ServerPid, Path, Headers, ReqOpts) when is_map(ReqOpts) ->
	headers(ServerPid, <<"PUT">>, Path, Headers, ReqOpts);
put(ServerPid, Path, Headers, Body) ->
	request(ServerPid, <<"PUT">>, Path, Headers, Body).

-spec put(pid(), iodata(), req_headers(), iodata(), req_opts()) -> reference().
put(ServerPid, Path, Headers, Body, ReqOpts) ->
	request(ServerPid, <<"PUT">>, Path, Headers, Body, ReqOpts).

%% Generic requests interface.

-spec headers(pid(), iodata(), iodata(), req_headers()) -> reference().
headers(ServerPid, Method, Path, Headers) ->
	headers(ServerPid, Method, Path, Headers, #{}).

-spec headers(pid(), iodata(), iodata(), req_headers(), req_opts()) -> reference().
headers(ServerPid, Method, Path, Headers, ReqOpts) ->
	StreamRef = make_ref(),
	InitialFlow = maps:get(flow, ReqOpts, infinity),
	ReplyTo = maps:get(reply_to, ReqOpts, self()),
	gen_statem:cast(ServerPid, {headers, ReplyTo, StreamRef,
		Method, Path, normalize_headers(Headers), InitialFlow}),
	StreamRef.

-spec request(pid(), iodata(), iodata(), req_headers(), iodata()) -> reference().
request(ServerPid, Method, Path, Headers, Body) ->
	request(ServerPid, Method, Path, Headers, Body, #{}).

-spec request(pid(), iodata(), iodata(), req_headers(), iodata(), req_opts()) -> reference().
request(ServerPid, Method, Path, Headers, Body, ReqOpts) ->
	StreamRef = make_ref(),
	InitialFlow = maps:get(flow, ReqOpts, infinity),
	ReplyTo = maps:get(reply_to, ReqOpts, self()),
	gen_statem:cast(ServerPid, {request, ReplyTo, StreamRef,
		Method, Path, normalize_headers(Headers), Body, InitialFlow}),
	StreamRef.

normalize_headers([]) ->
	[];
normalize_headers([{Name, Value}|Tail]) when is_binary(Name) ->
	[{string:lowercase(Name), Value}|normalize_headers(Tail)];
normalize_headers([{Name, Value}|Tail]) when is_list(Name) ->
	[{string:lowercase(unicode:characters_to_binary(Name)), Value}|normalize_headers(Tail)];
normalize_headers([{Name, Value}|Tail]) when is_atom(Name) ->
	[{string:lowercase(atom_to_binary(Name, latin1)), Value}|normalize_headers(Tail)];
normalize_headers(Headers) when is_map(Headers) ->
	normalize_headers(maps:to_list(Headers)).

%% Streaming data.

-spec data(pid(), reference(), fin | nofin, iodata()) -> ok.
data(ServerPid, StreamRef, IsFin, Data) ->
	case iolist_size(Data) of
		0 when IsFin =:= nofin ->
			ok;
		_ ->
			gen_statem:cast(ServerPid, {data, self(), StreamRef, IsFin, Data})
	end.

%% Tunneling.

-spec connect(pid(), connect_destination()) -> reference().
connect(ServerPid, Destination) ->
	connect(ServerPid, Destination, [], #{}).

-spec connect(pid(), connect_destination(), req_headers()) -> reference().
connect(ServerPid, Destination, Headers) ->
	connect(ServerPid, Destination, Headers, #{}).

-spec connect(pid(), connect_destination(), req_headers(), req_opts()) -> reference().
connect(ServerPid, Destination, Headers, ReqOpts) ->
	StreamRef = make_ref(),
	InitialFlow = maps:get(flow, ReqOpts, infinity),
	ReplyTo = maps:get(reply_to, ReqOpts, self()),
	gen_statem:cast(ServerPid, {connect, ReplyTo, StreamRef,
		Destination, Headers, InitialFlow}),
	StreamRef.

%% Awaiting gun messages.

-type resp_headers() :: [{binary(), binary()}].
-type await_result() :: {inform, 100..199, resp_headers()}
	| {response, fin | nofin, non_neg_integer(), resp_headers()}
	| {data, fin | nofin, binary()}
	| {sse, cow_sse:event() | fin}
	| {trailers, resp_headers()}
	| {push, reference(), binary(), binary(), resp_headers()}
	| {upgrade, [binary()], resp_headers()}
	| {ws, ws_frame()} %% @todo Excluding ping/pong, for now.
	| {error, {stream_error | connection_error | down, any()} | timeout}.

-spec await(pid(), reference()) -> await_result().
await(ServerPid, StreamRef) ->
	MRef = monitor(process, ServerPid),
	Res = await(ServerPid, StreamRef, 5000, MRef),
	demonitor(MRef, [flush]),
	Res.

-spec await(pid(), reference(), timeout() | reference()) -> await_result().
await(ServerPid, StreamRef, MRef) when is_reference(MRef) ->
	await(ServerPid, StreamRef, 5000, MRef);
await(ServerPid, StreamRef, Timeout) ->
	MRef = monitor(process, ServerPid),
	Res = await(ServerPid, StreamRef, Timeout, MRef),
	demonitor(MRef, [flush]),
	Res.

-spec await(pid(), reference(), timeout(), reference()) -> await_result().
await(ServerPid, StreamRef, Timeout, MRef) ->
	receive
		{gun_inform, ServerPid, StreamRef, Status, Headers} ->
			{inform, Status, Headers};
		{gun_response, ServerPid, StreamRef, IsFin, Status, Headers} ->
			{response, IsFin, Status, Headers};
		{gun_data, ServerPid, StreamRef, IsFin, Data} ->
			{data, IsFin, Data};
		{gun_sse, ServerPid, StreamRef, Event} ->
			{sse, Event};
		{gun_trailers, ServerPid, StreamRef, Trailers} ->
			{trailers, Trailers};
		{gun_push, ServerPid, StreamRef, NewStreamRef, Method, URI, Headers} ->
			{push, NewStreamRef, Method, URI, Headers};
		{gun_upgrade, ServerPid, StreamRef, Protocols, Headers} ->
			{upgrade, Protocols, Headers};
		{gun_ws, ServerPid, StreamRef, Frame} ->
			{ws, Frame};
		{gun_error, ServerPid, StreamRef, Reason} ->
			{error, {stream_error, Reason}};
		{gun_error, ServerPid, Reason} ->
			{error, {connection_error, Reason}};
		{'DOWN', MRef, process, ServerPid, Reason} ->
			{error, {down, Reason}}
	after Timeout ->
		{error, timeout}
	end.

-type await_body_result() :: {ok, binary()}
	| {ok, binary(), resp_headers()}
	| {error, {stream_error | connection_error | down, any()} | timeout}.

-spec await_body(pid(), reference()) -> await_body_result().
await_body(ServerPid, StreamRef) ->
	MRef = monitor(process, ServerPid),
	Res = await_body(ServerPid, StreamRef, 5000, MRef, <<>>),
	demonitor(MRef, [flush]),
	Res.

-spec await_body(pid(), reference(), timeout() | reference()) -> await_body_result().
await_body(ServerPid, StreamRef, MRef) when is_reference(MRef) ->
	await_body(ServerPid, StreamRef, 5000, MRef, <<>>);
await_body(ServerPid, StreamRef, Timeout) ->
	MRef = monitor(process, ServerPid),
	Res = await_body(ServerPid, StreamRef, Timeout, MRef, <<>>),
	demonitor(MRef, [flush]),
	Res.

-spec await_body(pid(), reference(), timeout(), reference()) -> await_body_result().
await_body(ServerPid, StreamRef, Timeout, MRef) ->
	await_body(ServerPid, StreamRef, Timeout, MRef, <<>>).

await_body(ServerPid, StreamRef, Timeout, MRef, Acc) ->
	receive
		{gun_data, ServerPid, StreamRef, nofin, Data} ->
			await_body(ServerPid, StreamRef, Timeout, MRef,
				<< Acc/binary, Data/binary >>);
		{gun_data, ServerPid, StreamRef, fin, Data} ->
			{ok, << Acc/binary, Data/binary >>};
		%% It's OK to return trailers here because the client
		%% specifically requested them.
		{gun_trailers, ServerPid, StreamRef, Trailers} ->
			{ok, Acc, Trailers};
		{gun_error, ServerPid, StreamRef, Reason} ->
			{error, {stream_error, Reason}};
		{gun_error, ServerPid, Reason} ->
			{error, {connection_error, Reason}};
		{'DOWN', MRef, process, ServerPid, Reason} ->
			{error, {down, Reason}}
	after Timeout ->
		{error, timeout}
	end.

-spec await_up(pid()) -> {ok, http | http2} | {error, {down, any()} | timeout}.
await_up(ServerPid) ->
	MRef = monitor(process, ServerPid),
	Res = await_up(ServerPid, 5000, MRef),
	demonitor(MRef, [flush]),
	Res.

-spec await_up(pid(), reference() | timeout()) -> {ok, http | http2} | {error, {down, any()} | timeout}.
await_up(ServerPid, MRef) when is_reference(MRef) ->
	await_up(ServerPid, 5000, MRef);
await_up(ServerPid, Timeout) ->
	MRef = monitor(process, ServerPid),
	Res = await_up(ServerPid, Timeout, MRef),
	demonitor(MRef, [flush]),
	Res.

-spec await_up(pid(), timeout(), reference()) -> {ok, http | http2} | {error, {down, any()} | timeout}.
await_up(ServerPid, Timeout, MRef) ->
	receive
		{gun_up, ServerPid, Protocol} ->
			{ok, Protocol};
		{'DOWN', MRef, process, ServerPid, Reason} ->
			{error, {down, Reason}}
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
		{gun_inform, ServerPid, _, _, _} ->
			flush_pid(ServerPid);
		{gun_response, ServerPid, _, _, _, _} ->
			flush_pid(ServerPid);
		{gun_data, ServerPid, _, _, _} ->
			flush_pid(ServerPid);
		{gun_trailers, ServerPid, _, _} ->
			flush_pid(ServerPid);
		{gun_push, ServerPid, _, _, _, _, _, _} ->
			flush_pid(ServerPid);
		{gun_error, ServerPid, _, _} ->
			flush_pid(ServerPid);
		{gun_error, ServerPid, _} ->
			flush_pid(ServerPid);
		{gun_upgrade, ServerPid, _, _, _} ->
			flush_pid(ServerPid);
		{gun_ws, ServerPid, _, _} ->
			flush_pid(ServerPid);
		{'DOWN', _, process, ServerPid, _} ->
			flush_pid(ServerPid)
	after 0 ->
		ok
	end.

flush_ref(StreamRef) ->
	receive
		{gun_inform, _, StreamRef, _, _} ->
			flush_pid(StreamRef);
		{gun_response, _, StreamRef, _, _, _} ->
			flush_ref(StreamRef);
		{gun_data, _, StreamRef, _, _} ->
			flush_ref(StreamRef);
		{gun_trailers, _, StreamRef, _} ->
			flush_ref(StreamRef);
		{gun_push, _, StreamRef, _, _, _, _, _} ->
			flush_ref(StreamRef);
		{gun_error, _, StreamRef, _} ->
			flush_ref(StreamRef);
		{gun_upgrade, _, StreamRef, _, _} ->
			flush_ref(StreamRef);
		{gun_ws, _, StreamRef, _} ->
			flush_ref(StreamRef)
	after 0 ->
		ok
	end.

%% Flow control.

-spec update_flow(pid(), reference(), pos_integer()) -> ok.
update_flow(ServerPid, StreamRef, Flow) ->
	gen_statem:cast(ServerPid, {update_flow, self(), StreamRef, Flow}).

%% Cancelling a stream.

-spec cancel(pid(), reference()) -> ok.
cancel(ServerPid, StreamRef) ->
	gen_statem:cast(ServerPid, {cancel, self(), StreamRef}).

%% Information about a stream.

-spec stream_info(pid(), reference()) -> {ok, map() | undefined} | {error, not_connected}.
stream_info(ServerPid, StreamRef) ->
	gen_statem:call(ServerPid, {stream_info, StreamRef}).

%% @todo Allow upgrading an HTTP/1.1 connection to HTTP/2.
%% http2_upgrade

%% Websocket.

-spec ws_upgrade(pid(), iodata()) -> reference().
ws_upgrade(ServerPid, Path) ->
	ws_upgrade(ServerPid, Path, []).

-spec ws_upgrade(pid(), iodata(), req_headers()) -> reference().
ws_upgrade(ServerPid, Path, Headers) ->
	StreamRef = make_ref(),
	gen_statem:cast(ServerPid, {ws_upgrade, self(), StreamRef, Path, Headers}),
	StreamRef.

-spec ws_upgrade(pid(), iodata(), req_headers(), ws_opts()) -> reference().
ws_upgrade(ServerPid, Path, Headers, Opts) ->
	ok = gun_ws:check_options(Opts),
	StreamRef = make_ref(),
	gen_statem:cast(ServerPid, {ws_upgrade, self(), StreamRef, Path, Headers, Opts}),
	StreamRef.

%% @todo ws_send/2 will need to be deprecated in favor of a variant with StreamRef.
%% But it can be kept for the time being since it can still work for HTTP/1.1.
-spec ws_send(pid(), ws_frame() | [ws_frame()]) -> ok.
ws_send(ServerPid, Frames) ->
	gen_statem:cast(ServerPid, {ws_send, self(), Frames}).

%% Internals.

callback_mode() -> state_functions.

start_link(Owner, Host, Port, Opts) ->
	gen_statem:start_link(?MODULE, {Owner, Host, Port, Opts}, []).

init({Owner, Host, Port, Opts}) ->
	Retry = maps:get(retry, Opts, 5),
	OriginTransport = maps:get(transport, Opts, default_transport(Port)),
	{OriginScheme, Transport} = case OriginTransport of
		tcp -> {<<"http">>, gun_tcp};
		tls -> {<<"https">>, gun_tls}
	end,
	OwnerRef = monitor(process, Owner),
	{EvHandler, EvHandlerState0} = maps:get(event_handler, Opts,
		{gun_default_event_h, undefined}),
	EvHandlerState = EvHandler:init(#{
		owner => Owner,
		transport => OriginTransport,
		origin_scheme => OriginScheme,
		origin_host => Host,
		origin_port => Port,
		opts => Opts
	}, EvHandlerState0),
	State = #state{owner=Owner, status={up, OwnerRef},
		host=Host, port=Port, origin_scheme=OriginScheme,
		origin_host=Host, origin_port=Port, opts=Opts,
		transport=Transport, messages=Transport:messages(),
		event_handler=EvHandler, event_handler_state=EvHandlerState},
	{ok, domain_lookup, State,
		{next_event, internal, {retries, Retry, not_connected}}}.

default_transport(443) -> tls;
default_transport(_) -> tcp.

not_connected(_, {retries, 0, Reason}, State) ->
	{stop, {shutdown, Reason}, State};
not_connected(_, {retries, Retries0, _}, State=#state{opts=Opts}) ->
	Fun = maps:get(retry_fun, Opts, fun default_retry_fun/2),
	#{
		timeout := Timeout,
		retries := Retries
	} = Fun(Retries0, Opts),
	{next_state, domain_lookup, State,
		{state_timeout, Timeout, {retries, Retries, not_connected}}};
not_connected({call, From}, {stream_info, _}, _) ->
	{keep_state_and_data, {reply, From, {error, not_connected}}};
not_connected(Type, Event, State) ->
	handle_common(Type, Event, ?FUNCTION_NAME, State).

default_retry_fun(Retries, Opts) ->
	#{
		retries => Retries - 1,
		timeout => maps:get(retry_timeout, Opts, 5000)
	}.

domain_lookup(_, {retries, Retries, _}, State=#state{host=Host, port=Port, opts=Opts,
		event_handler=EvHandler, event_handler_state=EvHandlerState0}) ->
	TransOpts = maps:get(tcp_opts, Opts, []),
	DomainLookupTimeout = maps:get(domain_lookup_timeout, Opts, infinity),
	DomainLookupEvent = #{
		host => Host,
		port => Port,
		tcp_opts => TransOpts,
		timeout => DomainLookupTimeout
	},
	EvHandlerState1 = EvHandler:domain_lookup_start(DomainLookupEvent, EvHandlerState0),
	case gun_tcp:domain_lookup(Host, Port, TransOpts, DomainLookupTimeout) of
		{ok, LookupInfo} ->
			EvHandlerState = EvHandler:domain_lookup_end(DomainLookupEvent#{
				lookup_info => LookupInfo
			}, EvHandlerState1),
			{next_state, connecting, State#state{event_handler_state=EvHandlerState},
				{next_event, internal, {retries, Retries, LookupInfo}}};
		{error, Reason} ->
			EvHandlerState = EvHandler:domain_lookup_end(DomainLookupEvent#{
				error => Reason
			}, EvHandlerState1),
			{next_state, not_connected, State#state{event_handler_state=EvHandlerState},
				{next_event, internal, {retries, Retries, Reason}}}
	end;
domain_lookup({call, From}, {stream_info, _}, _) ->
	{keep_state_and_data, {reply, From, {error, not_connected}}};
domain_lookup(Type, Event, State) ->
	handle_common(Type, Event, ?FUNCTION_NAME, State).

connecting(_, {retries, Retries, LookupInfo}, State=#state{opts=Opts,
		transport=Transport, event_handler=EvHandler, event_handler_state=EvHandlerState0}) ->
	ConnectTimeout = maps:get(connect_timeout, Opts, infinity),
	ConnectEvent = #{
		lookup_info => LookupInfo,
		timeout => ConnectTimeout
	},
	EvHandlerState1 = EvHandler:connect_start(ConnectEvent, EvHandlerState0),
	case gun_tcp:connect(LookupInfo, ConnectTimeout) of
		{ok, Socket} when Transport =:= gun_tcp ->
			Protocol = case maps:get(protocols, Opts, [http]) of
				[http] -> gun_http;
				[http2] -> gun_http2
			end,
			EvHandlerState = EvHandler:connect_end(ConnectEvent#{
				socket => Socket,
				protocol => Protocol:name()
			}, EvHandlerState1),
			{next_state, connected, State#state{event_handler_state=EvHandlerState},
				{next_event, internal, {connected, Socket, Protocol}}};
		{ok, Socket} when Transport =:= gun_tls ->
			EvHandlerState = EvHandler:connect_end(ConnectEvent#{
				socket => Socket
			}, EvHandlerState1),
			{next_state, tls_handshake, State#state{event_handler_state=EvHandlerState},
				{next_event, internal, {retries, Retries, Socket}}};
		{error, Reason} ->
			EvHandlerState = EvHandler:connect_end(ConnectEvent#{
				error => Reason
			}, EvHandlerState1),
			{next_state, not_connected, State#state{event_handler_state=EvHandlerState},
				{next_event, internal, {retries, Retries, Reason}}}
	end.

tls_handshake(_, {retries, Retries, Socket0}, State=#state{opts=Opts,
		event_handler=EvHandler, event_handler_state=EvHandlerState0}) ->
	TransOpts0 = maps:get(tls_opts, Opts, []),
	TransOpts = ensure_alpn(maps:get(protocols, Opts, [http2, http]), TransOpts0),
	HandshakeTimeout = maps:get(tls_handshake_timeout, Opts, infinity),
	HandshakeEvent = #{
		socket => Socket0,
		tls_opts => TransOpts,
		timeout => HandshakeTimeout
	},
	EvHandlerState1 = EvHandler:tls_handshake_start(HandshakeEvent, EvHandlerState0),
	case gun_tls:connect(Socket0, TransOpts, HandshakeTimeout) of
		{ok, Socket} ->
			Protocol = case ssl:negotiated_protocol(Socket) of
				{ok, <<"h2">>} -> gun_http2;
				_ -> gun_http
			end,
			EvHandlerState = EvHandler:tls_handshake_end(HandshakeEvent#{
				socket => Socket,
				protocol => Protocol:name()
			}, EvHandlerState1),
			{next_state, connected, State#state{event_handler_state=EvHandlerState},
				{next_event, internal, {connected, Socket, Protocol}}};
		{error, Reason} ->
			EvHandlerState = EvHandler:tls_handshake_end(HandshakeEvent#{
				error => Reason
			}, EvHandlerState1),
			{next_state, not_connected, State#state{event_handler_state=EvHandlerState},
				{next_event, internal, {retries, Retries, Reason}}}
	end.

ensure_alpn(Protocols0, TransOpts) ->
	Protocols = [case P of
		http -> <<"http/1.1">>;
		http2 -> <<"h2">>
	end || P <- Protocols0],
	[
		{alpn_advertised_protocols, Protocols},
		{client_preferred_next_protocols, {client, Protocols, <<"http/1.1">>}}
	|TransOpts].

connected(internal, {connected, Socket, Protocol},
		State=#state{owner=Owner, opts=Opts, transport=Transport}) ->
	ProtoOptsKey = case Protocol of
		gun_http -> http_opts;
		gun_http2 -> http2_opts
	end,
	ProtoOpts = maps:get(ProtoOptsKey, Opts, #{}),
	ProtoState = Protocol:init(Owner, Socket, Transport, ProtoOpts),
	Owner ! {gun_up, self(), Protocol:name()},
	{keep_state, keepalive_timeout(active(State#state{socket=Socket,
		protocol=Protocol, protocol_state=ProtoState}))};
%% Public HTTP interface.
connected(cast, {headers, ReplyTo, StreamRef, Method, Path, Headers, InitialFlow},
		State=#state{origin_host=Host, origin_port=Port,
			protocol=Protocol, protocol_state=ProtoState,
			event_handler=EvHandler, event_handler_state=EvHandlerState0}) ->
	{ProtoState2, EvHandlerState} = Protocol:headers(ProtoState,
		StreamRef, ReplyTo, Method, Host, Port, Path, Headers,
		InitialFlow, EvHandler, EvHandlerState0),
	{keep_state, State#state{protocol_state=ProtoState2, event_handler_state=EvHandlerState}};
connected(cast, {request, ReplyTo, StreamRef, Method, Path, Headers, Body, InitialFlow},
		State=#state{origin_host=Host, origin_port=Port,
			protocol=Protocol, protocol_state=ProtoState,
			event_handler=EvHandler, event_handler_state=EvHandlerState0}) ->
	{ProtoState2, EvHandlerState} = Protocol:request(ProtoState,
		StreamRef, ReplyTo, Method, Host, Port, Path, Headers, Body,
		InitialFlow, EvHandler, EvHandlerState0),
	{keep_state, State#state{protocol_state=ProtoState2, event_handler_state=EvHandlerState}};
connected(cast, {connect, ReplyTo, StreamRef, Destination0, Headers, InitialFlow},
		State=#state{protocol=Protocol, protocol_state=ProtoState}) ->
	%% The protocol option has been deprecated in favor of the protocols option.
	%% Nobody probably ended up using it, but let's not break the interface.
	Destination1 = case Destination0 of
		#{protocols := _} ->
			Destination0;
		#{protocol := DestProto} ->
			Destination0#{protocols => [DestProto]};
		_ ->
			Destination0
	end,
	Destination = case Destination1 of
		#{transport := tls} ->
			Destination1#{tls_opts => ensure_alpn(
				maps:get(protocols, Destination1, [http]),
				maps:get(tls_opts, Destination1, []))};
		_ ->
			Destination1
	end,
	ProtoState2 = Protocol:connect(ProtoState, StreamRef, ReplyTo, Destination, Headers, InitialFlow),
	{keep_state, State#state{protocol_state=ProtoState2}};
%% Public Websocket interface.
%% @todo Maybe make an interface in the protocol module instead of checking on protocol name.
%% An interface would also make sure that HTTP/1.0 can't upgrade.
connected(cast, {ws_upgrade, Owner, StreamRef, Path, Headers}, State=#state{opts=Opts}) ->
	WsOpts = maps:get(ws_opts, Opts, #{}),
	connected(cast, {ws_upgrade, Owner, StreamRef, Path, Headers, WsOpts}, State);
connected(cast, {ws_upgrade, Owner, StreamRef, Path, Headers, WsOpts},
		State=#state{owner=Owner, origin_host=Host, origin_port=Port,
			protocol=Protocol, protocol_state=ProtoState,
			event_handler=EvHandler, event_handler_state=EvHandlerState0})
		when Protocol =:= gun_http ->
	EvHandlerState1 = EvHandler:ws_upgrade(#{
		stream_ref => StreamRef,
		reply_to => Owner, %% Only the owner can upgrade the connection at this time.
		opts => WsOpts
	}, EvHandlerState0),
	%% @todo Can fail if HTTP/1.0.
	{ProtoState2, EvHandlerState} = Protocol:ws_upgrade(ProtoState,
		StreamRef, Host, Port, Path, Headers, WsOpts,
		EvHandler, EvHandlerState1),
	{keep_state, State#state{protocol_state=ProtoState2,
		event_handler_state=EvHandlerState}};
connected(cast, {ws_upgrade, ReplyTo, StreamRef, _, _, _}, _) ->
	ReplyTo ! {gun_error, self(), StreamRef, {badstate,
		"Websocket is only supported over HTTP/1.1."}},
	keep_state_and_data;
connected(cast, {ws_send, Owner, Frames}, State=#state{
		owner=Owner, protocol=Protocol=gun_ws, protocol_state=ProtoState,
		event_handler=EvHandler, event_handler_state=EvHandlerState0}) ->
	{Commands, EvHandlerState} = Protocol:send(Frames, ProtoState, EvHandler, EvHandlerState0),
	commands(Commands, State#state{event_handler_state=EvHandlerState});
connected(cast, {ws_send, ReplyTo, _}, _) ->
	ReplyTo ! {gun_error, self(), {badstate,
		"Connection needs to be upgraded to Websocket "
		"before the gun:ws_send/1 function can be used."}},
	keep_state_and_data;
connected(Type, Event, State) ->
	handle_common_connected(Type, Event, ?FUNCTION_NAME, State).

%% Switch to the graceful connection close state.
closing(State=#state{protocol=Protocol, protocol_state=ProtoState,
		event_handler=EvHandler, event_handler_state=EvHandlerState0}, Reason) ->
	{Commands, EvHandlerState} = Protocol:closing(Reason, ProtoState, EvHandler, EvHandlerState0),
	commands(Commands, State#state{event_handler_state=EvHandlerState}).

%% @todo Should explicitly reject ws_send in this state?
closing(state_timeout, closing_timeout, State=#state{status=Status}) ->
	Reason = case Status of
		shutdown -> shutdown;
		{down, _} -> owner_down;
		_ -> normal
	end,
	disconnect(State, Reason);
closing(Type, Event, State) ->
	handle_common_connected(Type, Event, ?FUNCTION_NAME, State).

%% Common events when we have a connection.
%%
%% Socket events.
handle_common_connected(info, {OK, Socket, Data}, _, State0=#state{socket=Socket, messages={OK, _, _},
		protocol=Protocol, protocol_state=ProtoState,
		event_handler=EvHandler, event_handler_state=EvHandlerState0}) ->
	{Commands, EvHandlerState} = Protocol:handle(Data, ProtoState, EvHandler, EvHandlerState0),
	case commands(Commands, State0#state{event_handler_state=EvHandlerState}) of
		{keep_state, State} ->
			{keep_state, active(State)};
		{next_state, closing, State, Actions} ->
			{next_state, closing, active(State), Actions};
		Res ->
			Res
	end;
handle_common_connected(info, {Closed, Socket}, _, State=#state{socket=Socket, messages={_, Closed, _}}) ->
	disconnect(State, closed);
handle_common_connected(info, {Error, Socket, Reason}, _, State=#state{socket=Socket, messages={_, _, Error}}) ->
	disconnect(State, {error, Reason});
%% Timeouts.
%% @todo HTTP/2 requires more timeouts than just the keepalive timeout.
%% We should have a timeout function in protocols that deal with
%% received timeouts. Currently the timeout messages are ignored.
handle_common_connected(info, keepalive, _, State=#state{protocol=Protocol, protocol_state=ProtoState}) ->
	ProtoState2 = Protocol:keepalive(ProtoState),
	{keep_state, keepalive_timeout(State#state{protocol_state=ProtoState2})};
%% When using gun_tls_proxy we need a separate message to know whether
%% the handshake succeeded and whether we need to switch to a different protocol.
handle_common_connected(info, {gun_tls_proxy, Socket, {ok, NewProtocol}, HandshakeEvent}, _,
		State0=#state{socket=Socket, protocol=CurrentProtocol, protocol_state=ProtoState,
			event_handler=EvHandler, event_handler_state=EvHandlerState0}) ->
	EvHandlerState = EvHandler:tls_handshake_end(HandshakeEvent#{
		socket => Socket,
		protocol => NewProtocol:name()
	}, EvHandlerState0),
	State = State0#state{event_handler_state=EvHandlerState},
	case NewProtocol of
		CurrentProtocol -> {keep_state, State};
		_ -> commands([{switch_protocol, NewProtocol, ProtoState}], State)
	end;
handle_common_connected(info, {gun_tls_proxy, Socket, Error = {error, Reason}, HandshakeEvent}, _,
		State=#state{socket=Socket, event_handler=EvHandler, event_handler_state=EvHandlerState0}) ->
	EvHandlerState = EvHandler:tls_handshake_end(HandshakeEvent#{
		error => Reason
	}, EvHandlerState0),
	commands([Error], State#state{event_handler_state=EvHandlerState});
%% @todo Do we want to reject ReplyTo if it's not the process
%% who initiated the connection? For both data and cancel.
handle_common_connected(cast, {data, ReplyTo, StreamRef, IsFin, Data}, _,
		State=#state{protocol=Protocol, protocol_state=ProtoState,
			event_handler=EvHandler, event_handler_state=EvHandlerState0}) ->
	{ProtoState2, EvHandlerState} = Protocol:data(ProtoState,
		StreamRef, ReplyTo, IsFin, Data, EvHandler, EvHandlerState0),
	{keep_state, State#state{protocol_state=ProtoState2, event_handler_state=EvHandlerState}};
handle_common_connected(cast, {update_flow, ReplyTo, StreamRef, Flow}, _, State0=#state{
		protocol=Protocol, protocol_state=ProtoState}) ->
	Commands = Protocol:update_flow(ProtoState, ReplyTo, StreamRef, Flow),
	case commands(Commands, State0) of
		{keep_state, State} ->
			{keep_state, active(State)};
		Res ->
			Res
	end;
handle_common_connected(cast, {cancel, ReplyTo, StreamRef}, _, State=#state{
		protocol=Protocol, protocol_state=ProtoState,
		event_handler=EvHandler, event_handler_state=EvHandlerState0}) ->
	{ProtoState2, EvHandlerState} = Protocol:cancel(ProtoState,
		StreamRef, ReplyTo, EvHandler, EvHandlerState0),
	{keep_state, State#state{protocol_state=ProtoState2, event_handler_state=EvHandlerState}};
handle_common_connected({call, From}, {stream_info, StreamRef}, _,
		#state{protocol=Protocol, protocol_state=ProtoState}) ->
	{keep_state_and_data, {reply, From, Protocol:stream_info(ProtoState, StreamRef)}};
handle_common_connected(Type, Event, StateName, State) ->
	handle_common(Type, Event, StateName, State).

%% Common events.
handle_common(cast, {shutdown, Owner}, StateName, State=#state{
		owner=Owner, status=Status, socket=Socket, transport=Transport, protocol=Protocol}) ->
	case {Socket, Protocol} of
		{undefined, _} ->
			{stop, shutdown};
		{_, undefined} ->
			%% @todo This is missing the disconnect event.
			Transport:close(Socket),
			{stop, shutdown};
		_ when StateName =:= closing, element(1, Status) =:= up ->
			{keep_state, status(State, shutdown)};
		_ when StateName =:= closing ->
			keep_state_and_data;
		_ ->
			closing(status(State, shutdown), shutdown)
	end;
%% We stop when the owner is down.
%% @todo We need to demonitor/flush when the status is no longer up.
handle_common(info, {'DOWN', OwnerRef, process, Owner, Reason}, StateName, State=#state{
		owner=Owner, status={up, OwnerRef}, socket=Socket, transport=Transport, protocol=Protocol}) ->
	case Socket of
		undefined ->
			owner_down(Reason, State);
		_ ->
			case Protocol of
				undefined ->
					%% @todo This is missing the disconnect event.
					Transport:close(Socket),
					owner_down(Reason, State);
				%% We are already closing so no need to initiate closing again.
				_ when StateName =:= closing ->
					{keep_state, status(State, {down, Reason})};
				_ ->
					closing(status(State, {down, Reason}), owner_down)
			end
	end;
handle_common({call, From}, _, _, _) ->
	{keep_state_and_data, {reply, From, {error, bad_call}}};
%% @todo The ReplyTo patch disabled the notowner behavior.
%% We need to add an option to enforce this behavior if needed.
handle_common(cast, Any, _, #state{owner=Owner}) when element(2, Any) =/= Owner ->
	element(2, Any) ! {gun_error, self(), {notowner,
		"Operations are restricted to the owner of the connection."}},
	keep_state_and_data;
%% We postpone all HTTP/Websocket operations until we are connected.
handle_common(cast, _, StateName, _) when StateName =/= connected ->
	{keep_state_and_data, postpone};
handle_common(Type, Event, StateName, StateData) ->
	error_logger:error_msg("Unexpected event in state ~p of type ~p:~n~w~n~p~n",
		[StateName, Type, Event, StateData]),
	keep_state_and_data.

commands(Command, State) when not is_list(Command) ->
	commands([Command], State);
commands([], State) ->
	{keep_state, State};
commands([close|_], State) ->
	disconnect(State, normal);
commands([{closing, Timeout}|_], State) ->
	{next_state, closing, keepalive_cancel(State),
		{state_timeout, Timeout, closing_timeout}};
commands([Error={error, _}|_], State) ->
	disconnect(State, Error);
commands([{active, Active}|Tail], State) when is_boolean(Active) ->
	commands(Tail, State#state{active=Active});
commands([{state, ProtoState}|Tail], State) ->
	commands(Tail, State#state{protocol_state=ProtoState});
%% Order is important: the origin must be changed before
%% the transport and/or protocol in order to keep track
%% of the intermediaries properly.
commands([{origin, Scheme, Host, Port, Type}|Tail],
		State=#state{transport=Transport, protocol=Protocol,
			origin_host=IntermediateHost, origin_port=IntermediatePort, intermediaries=Intermediaries,
			event_handler=EvHandler, event_handler_state=EvHandlerState0}) ->
	EvHandlerState = EvHandler:origin_changed(#{
		type => Type,
		origin_scheme => Scheme,
		origin_host => Host,
		origin_port => Port
	}, EvHandlerState0),
	Info = #{
		type => Type,
		host => IntermediateHost,
		port => IntermediatePort,
		transport => Transport:name(),
		protocol => Protocol:name()
	},
	commands(Tail, State#state{origin_scheme=Scheme,
		origin_host=Host, origin_port=Port, intermediaries=[Info|Intermediaries],
		event_handler_state=EvHandlerState});
commands([{switch_transport, Transport, Socket}|Tail], State=#state{
		event_handler=EvHandler, event_handler_state=EvHandlerState0}) ->
	EvHandlerState = EvHandler:transport_changed(#{
		socket => Socket,
		transport => Transport:name()
	}, EvHandlerState0),
	commands(Tail, active(State#state{socket=Socket, transport=Transport,
		messages=Transport:messages(), event_handler_state=EvHandlerState}));
%% @todo The two loops should be reunified and this clause generalized.
commands([{switch_protocol, Protocol=gun_ws, ProtoState}], State=#state{
		event_handler=EvHandler, event_handler_state=EvHandlerState0}) ->
	EvHandlerState = EvHandler:protocol_changed(#{protocol => Protocol:name()}, EvHandlerState0),
	{keep_state, keepalive_cancel(State#state{protocol=Protocol, protocol_state=ProtoState,
		event_handler_state=EvHandlerState})};
%% @todo And this state should probably not be ignored.
commands([{switch_protocol, Protocol, _ProtoState0}|Tail], State=#state{
		owner=Owner, opts=Opts, socket=Socket, transport=Transport,
		event_handler=EvHandler, event_handler_state=EvHandlerState0}) ->
	ProtoOpts = maps:get(http2_opts, Opts, #{}),
	ProtoState = Protocol:init(Owner, Socket, Transport, ProtoOpts),
	EvHandlerState = EvHandler:protocol_changed(#{protocol => Protocol:name()}, EvHandlerState0),
	commands(Tail, keepalive_timeout(State#state{protocol=Protocol, protocol_state=ProtoState,
		event_handler_state=EvHandlerState})).

disconnect(State0=#state{owner=Owner, status=Status, opts=Opts,
		socket=Socket, transport=Transport,
		protocol=Protocol, protocol_state=ProtoState,
		event_handler=EvHandler, event_handler_state=EvHandlerState0}, Reason) ->
	EvHandlerState1 = Protocol:close(Reason, ProtoState, EvHandler, EvHandlerState0),
	_ = Transport:close(Socket),
	EvHandlerState = EvHandler:disconnect(#{reason => Reason}, EvHandlerState1),
	State = State0#state{event_handler_state=EvHandlerState},
	case Status of
		{down, DownReason} ->
			owner_down(DownReason, State);
		shutdown ->
			{stop, shutdown, State};
		{up, _} ->
			%% We closed the socket, discard any remaining socket events.
			disconnect_flush(State),
			%% @todo Stop keepalive timeout, flush message.
			{KilledStreams, UnprocessedStreams} = Protocol:down(ProtoState),
			Owner ! {gun_down, self(), Protocol:name(), Reason, KilledStreams, UnprocessedStreams},
			Retry = maps:get(retry, Opts, 5),
			case Retry of
				0 when Reason =:= normal ->
					{stop, normal, State};
				0 ->
					{stop, {shutdown, Reason}, State};
				_ ->
					{next_state, not_connected,
						keepalive_cancel(State#state{socket=undefined,
							protocol=undefined, protocol_state=undefined}),
						{next_event, internal, {retries, Retry - 1, Reason}}}
			end
	end.

disconnect_flush(State=#state{socket=Socket, messages={OK, Closed, Error}}) ->
	receive
		{OK, Socket, _} -> disconnect_flush(State);
		{Closed, Socket} -> disconnect_flush(State);
		{Error, Socket, _} -> disconnect_flush(State)
	after 0 ->
		ok
	end.

active(State=#state{active=false}) ->
	State;
active(State=#state{socket=Socket, transport=Transport}) ->
	Transport:setopts(Socket, [{active, once}]),
	State.

status(State=#state{status={up, OwnerRef}}, NewStatus) ->
	demonitor(OwnerRef, [flush]),
	State#state{status=NewStatus};
status(State, NewStatus) ->
	State#state{status=NewStatus}.

keepalive_timeout(State=#state{opts=Opts, protocol=Protocol}) ->
	{ProtoOptsKey, Default} = case Protocol of
		gun_http -> {http_opts, infinity};
		gun_http2 -> {http2_opts, 5000}
	end,
	ProtoOpts = maps:get(ProtoOptsKey, Opts, #{}),
	Keepalive = maps:get(keepalive, ProtoOpts, Default),
	KeepaliveRef = case Keepalive of
		infinity -> undefined;
		%% @todo Maybe change that to a start_timer.
		_ -> erlang:send_after(Keepalive, self(), keepalive)
	end,
	State#state{keepalive_ref=KeepaliveRef}.

keepalive_cancel(State=#state{keepalive_ref=undefined}) ->
	State;
keepalive_cancel(State=#state{keepalive_ref=KeepaliveRef}) ->
	_ = erlang:cancel_timer(KeepaliveRef),
	%% Flush if we have a keepalive message
	receive
		keepalive -> ok
	after 0 ->
		ok
	end,
	State#state{keepalive_ref=undefined}.

owner_down(normal, State) -> {stop, normal, State};
owner_down(shutdown, State) -> {stop, shutdown, State};
owner_down(Shutdown = {shutdown, _}, State) -> {stop, Shutdown, State};
owner_down(Reason, State) -> {stop, {shutdown, {owner_down, Reason}}, State}.

terminate(Reason, StateName, #state{event_handler=EvHandler,
		event_handler_state=EvHandlerState}) ->
	TerminateEvent = #{
		state => StateName,
		reason => Reason
	},
	EvHandler:terminate(TerminateEvent, EvHandlerState).
