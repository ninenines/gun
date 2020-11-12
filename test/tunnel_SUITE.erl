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

-module(tunnel_SUITE).
-compile(export_all).
-compile(nowarn_export_all).

-import(ct_helper, [doc/1]).
-import(gun_test, [receive_from/1]).

all() ->
	ct_helper:all(?MODULE).

%% Tests.
%%
%% Test names list the endpoint in the order the connection
%% goes through, with proxies first and the origin server last.
%% Each endpoint is identified by one of the following identifiers:
%%
%% Identifier | Protocol | Transport
%% ---------- |----------|--------
%% http       | HTTP/1.1 | TCP
%% https      | HTTP/1.1 | TLS
%% h2c        | HTTP/2   | TCP
%% h2         | HTTP/2   | TLS
%% socks5     | SOCKS5   | TCP
%% socks5tls  | SOCKS5   | TLS
%% raw        | Raw      | TCP
%% rawtls     | Raw      | TLS

http_http_http(_) ->
	do_tunnel(?FUNCTION_NAME).

http_http_https(_) ->
	do_tunnel(?FUNCTION_NAME).

http_http_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

http_http_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

http_http_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

http_http_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

http_https_http(_) ->
	do_tunnel(?FUNCTION_NAME).

http_https_https(_) ->
	do_tunnel(?FUNCTION_NAME).

http_https_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

http_https_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

http_https_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

http_https_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

http_h2c_http(_) ->
	do_tunnel(?FUNCTION_NAME).

http_h2c_https(_) ->
	do_tunnel(?FUNCTION_NAME).

http_h2c_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

http_h2c_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

http_h2c_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

http_h2c_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

http_h2_http(_) ->
	do_tunnel(?FUNCTION_NAME).

http_h2_https(_) ->
	do_tunnel(?FUNCTION_NAME).

http_h2_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

http_h2_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

http_h2_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

http_h2_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

http_socks5_http(_) ->
	do_tunnel(?FUNCTION_NAME).

http_socks5_https(_) ->
	do_tunnel(?FUNCTION_NAME).

http_socks5_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

http_socks5_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

http_socks5_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

http_socks5_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

http_socks5tls_http(_) ->
	do_tunnel(?FUNCTION_NAME).

http_socks5tls_https(_) ->
	do_tunnel(?FUNCTION_NAME).

http_socks5tls_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

http_socks5tls_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

http_socks5tls_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

http_socks5tls_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

https_http_http(_) ->
	do_tunnel(?FUNCTION_NAME).

https_http_https(_) ->
	do_tunnel(?FUNCTION_NAME).

https_http_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

https_http_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

https_http_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

https_http_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

https_https_http(_) ->
	do_tunnel(?FUNCTION_NAME).

https_https_https(_) ->
	do_tunnel(?FUNCTION_NAME).

https_https_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

https_https_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

https_https_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

https_https_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

https_h2c_http(_) ->
	do_tunnel(?FUNCTION_NAME).

https_h2c_https(_) ->
	do_tunnel(?FUNCTION_NAME).

https_h2c_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

https_h2c_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

https_h2c_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

https_h2c_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

https_h2_http(_) ->
	do_tunnel(?FUNCTION_NAME).

https_h2_https(_) ->
	do_tunnel(?FUNCTION_NAME).

https_h2_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

https_h2_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

https_h2_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

https_h2_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

https_socks5_http(_) ->
	do_tunnel(?FUNCTION_NAME).

https_socks5_https(_) ->
	do_tunnel(?FUNCTION_NAME).

https_socks5_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

https_socks5_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

https_socks5_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

https_socks5_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

https_socks5tls_http(_) ->
	do_tunnel(?FUNCTION_NAME).

https_socks5tls_https(_) ->
	do_tunnel(?FUNCTION_NAME).

https_socks5tls_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

https_socks5tls_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

https_socks5tls_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

https_socks5tls_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

h2c_http_http(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_http_https(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_http_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_http_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_http_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_http_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

h2c_https_http(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_https_https(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_https_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_https_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_https_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_https_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

h2c_h2c_http(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_h2c_https(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_h2c_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_h2c_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_h2c_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_h2c_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

h2c_h2_http(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_h2_https(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_h2_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_h2_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_h2_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_h2_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

h2c_socks5_http(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_socks5_https(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_socks5_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_socks5_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_socks5_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_socks5_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

h2c_socks5tls_http(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_socks5tls_https(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_socks5tls_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_socks5tls_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_socks5tls_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

h2c_socks5tls_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

h2_http_http(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_http_https(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_http_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_http_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_http_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_http_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

h2_https_http(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_https_https(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_https_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_https_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_https_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_https_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

h2_h2c_http(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_h2c_https(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_h2c_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_h2c_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_h2c_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_h2c_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

h2_h2_http(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_h2_https(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_h2_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_h2_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_h2_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_h2_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

h2_socks5_http(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_socks5_https(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_socks5_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_socks5_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_socks5_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_socks5_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

h2_socks5tls_http(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_socks5tls_https(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_socks5tls_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_socks5tls_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_socks5tls_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

h2_socks5tls_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

socks5_http_http(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_http_https(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_http_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_http_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_http_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_http_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

socks5_https_http(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_https_https(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_https_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_https_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_https_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_https_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

socks5_h2c_http(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_h2c_https(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_h2c_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_h2c_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_h2c_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_h2c_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

socks5_h2_http(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_h2_https(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_h2_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_h2_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_h2_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_h2_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

socks5_socks5_http(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_socks5_https(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_socks5_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_socks5_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_socks5_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_socks5_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

socks5_socks5tls_http(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_socks5tls_https(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_socks5tls_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_socks5tls_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_socks5tls_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5_socks5tls_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

socks5tls_http_http(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_http_https(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_http_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_http_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_http_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_http_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

socks5tls_https_http(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_https_https(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_https_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_https_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_https_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_https_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

socks5tls_h2c_http(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_h2c_https(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_h2c_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_h2c_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_h2c_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_h2c_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

socks5tls_h2_http(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_h2_https(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_h2_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_h2_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_h2_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_h2_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

socks5tls_socks5_http(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_socks5_https(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_socks5_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_socks5_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_socks5_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_socks5_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%%

socks5tls_socks5tls_http(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_socks5tls_https(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_socks5tls_h2c(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_socks5tls_h2(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_socks5tls_raw(_) ->
	do_tunnel(?FUNCTION_NAME).

socks5tls_socks5tls_rawtls(_) ->
	do_tunnel(?FUNCTION_NAME).

%% Common code for all the test cases.

-record(st, {
	proxy1,
	proxy1_pid,
	proxy1_port,

	proxy2,
	proxy2_pid,
	proxy2_port,

	origin,
	origin_pid,
	origin_port
}).

do_tunnel(FunctionName) ->
	[Proxy1, Proxy2, Origin] = [list_to_atom(Lex) || Lex <- string:lexemes(atom_to_list(FunctionName), "_")],
	do_doc(Proxy1, Proxy2, Origin),
	{ok, OriginPid, OriginPort} = do_origin_start(Origin),
	{ok, Proxy1Pid, Proxy1Port} = do_proxy_start(Proxy1),
	{ok, Proxy2Pid, Proxy2Port} = do_proxy_start(Proxy2),
	State = #st{
		proxy1=Proxy1, proxy1_pid=Proxy1Pid, proxy1_port=Proxy1Port,
		proxy2=Proxy2, proxy2_pid=Proxy2Pid, proxy2_port=Proxy2Port,
		origin=Origin, origin_pid=OriginPid, origin_port=OriginPort
	},
	ConnPid = do_proxy1(State),
	StreamRef1 = do_proxy2(State, ConnPid),
	StreamRef2 = do_origin(State, ConnPid, StreamRef1),
	StreamRef3 = do_origin_stream(State, ConnPid, StreamRef2),
	do_proxy1_stream_info(State, ConnPid, StreamRef1),
	do_proxy2_stream_info(State, ConnPid, StreamRef2),
	do_origin_stream_info(State, ConnPid, StreamRef3),
	do_info(State, ConnPid).

do_doc(Proxy1, Proxy2, Origin) ->
	doc(do_doc(Proxy1, "proxy") ++ " -> " ++ do_doc(Proxy2, "proxy") ++ " -> " ++ do_doc(Origin, "origin")).

do_doc(Type, Endpoint) ->
	{Transport, Protocol} = do_type(Type),
	case Protocol of
		http -> "HTTP/1.1";
		http2 -> "HTTP/2";
		socks -> "SOCKS5";
		raw -> "Raw"
	end
	++ " " ++ Endpoint ++ " over " ++
	case Transport of
		tcp -> "TCP";
		tls -> "TLS"
	end.

do_origin_start(Type) when Type =:= raw; Type =:= rawtls ->
	{Transport, Protocol} = do_type(Type),
	gun_test:init_origin(Transport, Protocol, fun raw_SUITE:do_echo/3);
do_origin_start(Type) ->
	{Transport, Protocol} = do_type(Type),
	rfc7540_SUITE:do_cowboy_origin(Transport, Protocol).

do_proxy_start(Type) when Type =:= http; Type =:= https ->
	{Transport, _} = do_type(Type),
	rfc7231_SUITE:do_proxy_start(Transport);
do_proxy_start(Type) when Type =:= h2; Type =:= h2c ->
	{Transport, _} = do_type(Type),
	rfc7540_SUITE:do_proxy_start(Transport);
do_proxy_start(Type) when Type =:= socks5; Type =:= socks5tls ->
	{Transport, _} = do_type(Type),
	socks_SUITE:do_proxy_start(Transport, none).

do_proxy1(State=#st{proxy1=Type, proxy1_pid=Proxy1Pid, proxy1_port=Port}) ->
	{Transport, Protocol} = do_type(Type),
	{ok, ConnPid} = gun:open("localhost", Port, #{
		transport => Transport,
		protocols => [case Protocol of
			socks ->
				{Protocol, do_proxy2_socks_opts(State)};
			_ ->
				Protocol
		end]
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	do_handshake_completed(Protocol, Proxy1Pid),
	ConnPid.

do_proxy2_socks_opts(State=#st{proxy2=Type, proxy2_port=Port}) ->
	{Transport, Protocol} = do_type(Type),
	#{
		host => "localhost",
		port => Port,
		transport => Transport,
		protocols => [case Protocol of
			socks ->
				{Protocol, do_origin_socks_opts(State)};
			_ ->
				Protocol
		end]
	}.

do_origin_socks_opts(#st{origin=Type, origin_port=Port}) ->
	{Transport, Protocol} = do_type(Type),
	#{
		host => "localhost",
		port => Port,
		transport => Transport,
		protocols => [Protocol]
	}.

%% When the first proxy was socks all we need to do is wait for
%% the second proxy to be up.
do_proxy2(#st{proxy1=Proxy1Type, proxy2=Proxy2Type, proxy2_pid=Proxy2Pid}, ConnPid)
		when Proxy1Type =:= socks5; Proxy1Type =:= socks5tls ->
	{_, Protocol} = do_type(Proxy2Type),
	{up, Protocol} = gun:await(ConnPid, undefined),
	do_handshake_completed(Protocol, Proxy2Pid),
	undefined;
do_proxy2(State=#st{proxy2=Type, proxy2_pid=Proxy2Pid, proxy2_port=Port}, ConnPid) ->
	{Transport, Protocol} = do_type(Type),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => Port,
		transport => Transport,
		protocols => [case Protocol of
			socks ->
				{Protocol, do_origin_socks_opts(State)};
			_ ->
				Protocol
		end]
	}),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{up, Protocol} = gun:await(ConnPid, StreamRef1),
	do_handshake_completed(Protocol, Proxy2Pid),
	StreamRef1.

%% When the second proxy was socks all we need to do is wait for
%% the origin to be up.
do_origin(#st{proxy2=Proxy2Type, origin=OriginType}, ConnPid, StreamRef)
		when Proxy2Type =:= socks5; Proxy2Type =:= socks5tls ->
	{_, Protocol} = do_type(OriginType),
	{up, Protocol} = gun:await(ConnPid, StreamRef),
	StreamRef;
%% We can't have a socks5/socks5tls origin.
do_origin(#st{origin=Type, origin_port=Port}, ConnPid, StreamRef1) ->
	{Transport, Protocol} = do_type(Type),
	StreamRef2 = gun:connect(ConnPid, #{
		host => "localhost",
		port => Port,
		transport => Transport,
		protocols => [Protocol]
	}, [], #{tunnel => StreamRef1}),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef2),
	{up, Protocol} = gun:await(ConnPid, StreamRef2),
	StreamRef2.

do_handshake_completed(http2, ProxyPid) ->
	handshake_completed = receive_from(ProxyPid),
	ok;
do_handshake_completed(_, _) ->
	ok.

do_origin_stream(#st{origin=Type}, ConnPid, StreamRef2)
		when Type =:= raw; Type =:= rawtls ->
	gun:data(ConnPid, StreamRef2, nofin, <<"Hello world!">>),
	{data, nofin, <<"Hello world!">>} = gun:await(ConnPid, StreamRef2),
	StreamRef2;
do_origin_stream(#st{}, ConnPid, StreamRef2) ->
	StreamRef3 = gun:get(ConnPid, "/proxied", #{}, #{tunnel => StreamRef2}),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef3),
	StreamRef3.

do_proxy1_stream_info(#st{proxy1=Proxy1}, _, _)
		when Proxy1 =:= socks5; Proxy1 =:= socks5tls ->
	ok;
do_proxy1_stream_info(#st{proxy1=Proxy1, proxy2=Proxy2, proxy2_port=Proxy2Port}, ConnPid, StreamRef1) ->
	ct:log("1: ~p~n~p", [StreamRef1, gun:stream_info(ConnPid, StreamRef1)]),
	Self = if
		%% We do not currently keep reply_to after switch_protocol.
		Proxy1 =:= http; Proxy1 =:= https ->
			undefined;
		true ->
			self()
	end,
	{Proxy2Transport, Proxy2Protocol} = do_type(Proxy2),
	Proxy2Scheme = case Proxy2Transport of
		tcp -> <<"http">>;
		tls -> <<"https">>
	end,
	{ok, #{
		ref := StreamRef1,
		reply_to := Self,
		state := running,
		tunnel := #{
			transport := Proxy2Transport,
			protocol := Proxy2Protocol,
			origin_scheme := Proxy2Scheme,
			origin_host := "localhost",
			origin_port := Proxy2Port
		}
	}} = gun:stream_info(ConnPid, StreamRef1),
	ok.

do_proxy2_stream_info(#st{proxy2=Proxy2}, _, _)
		when Proxy2 =:= socks5; Proxy2 =:= socks5tls ->
	ok;
do_proxy2_stream_info(#st{proxy1=Proxy1, proxy1_port=Proxy1Port, proxy2=Proxy2,
		origin=Origin, origin_port=OriginPort}, ConnPid, StreamRef2) ->
	ct:log("2: ~p~n~p", [StreamRef2, gun:stream_info(ConnPid, StreamRef2)]),
	Self = if
		%% We do not currently keep reply_to after switch_protocol.
		Proxy1 =/= h2, Proxy1 =/= h2c, (Proxy2 =:= http) orelse (Proxy2 =:= https) ->
			undefined;
		true ->
			self()
	end,
	{Proxy1Transport, Proxy1Protocol} = do_type(Proxy1),
	Proxy1Type = case Proxy1 of
		socks5 -> socks5;
		socks5tls -> socks5;
		_ -> connect
	end,
	{OriginTransport, OriginProtocol} = do_type(Origin),
	OriginScheme = case {OriginTransport, OriginProtocol} of
		{_, raw} -> undefined;
		{tcp, _} -> <<"http">>;
		{tls, _} -> <<"https">>
	end,
	{ok, #{
		ref := StreamRef2,
		reply_to := Self,
		state := running,
		intermediaries := [#{
			type := Proxy1Type,
			host := "localhost",
			port := Proxy1Port,
			transport := Proxy1Transport,
			protocol := Proxy1Protocol
		}],
		tunnel := #{
			transport := OriginTransport,
			protocol := OriginProtocol,
			origin_scheme := OriginScheme,
			origin_host := "localhost",
			origin_port := OriginPort
		}
	}} = gun:stream_info(ConnPid, StreamRef2),
	ok.

do_origin_stream_info(#st{origin=Type}, _, _)
		when Type =:= raw; Type =:= rawtls ->
	ok;
do_origin_stream_info(#st{proxy1=Proxy1, proxy1_port=Proxy1Port,
		proxy2=Proxy2, proxy2_port=Proxy2Port}, ConnPid, StreamRef3) ->
	ct:log("3: ~p~n~p", [StreamRef3, gun:stream_info(ConnPid, StreamRef3)]),
	{Proxy1Transport, Proxy1Protocol} = do_type(Proxy1),
	Proxy1Type = case Proxy1 of
		socks5 -> socks5;
		socks5tls -> socks5;
		_ -> connect
	end,
	{Proxy2Transport, Proxy2Protocol} = do_type(Proxy2),
	Proxy2Type = case Proxy2 of
		socks5 -> socks5;
		socks5tls -> socks5;
		_ -> connect
	end,
	{ok, #{
		ref := StreamRef3,
		reply_to := _, %% @todo
		state := running,
		intermediaries := [#{
			type := Proxy1Type,
			host := "localhost",
			port := Proxy1Port,
			transport := Proxy1Transport,
			protocol := Proxy1Protocol
		}, #{
			type := Proxy2Type,
			host := "localhost",
			port := Proxy2Port,
			transport := Proxy2Transport,
			protocol := Proxy2Protocol
		}]
	}} = gun:stream_info(ConnPid, StreamRef3),
	ok.

do_info(#st{
			proxy1=Proxy1, proxy1_port=Proxy1Port,
			proxy2=Proxy2, proxy2_port=Proxy2Port,
			origin=Origin, origin_port=OriginPort
		}, ConnPid) ->
	{Proxy1Transport, Proxy1Protocol} = do_type(Proxy1),
	Proxy1Type = case Proxy1Protocol of
		socks -> socks5;
		_ -> connect
	end,
	{Proxy2Transport, Proxy2Protocol} = do_type(Proxy2),
	Proxy2Type = case Proxy2Protocol of
		socks -> socks5;
		_ -> connect
	end,
	Intermediary1 = #{
		type => Proxy1Type,
		host => "localhost",
		port => Proxy1Port,
		transport => Proxy1Transport,
		protocol => Proxy1Protocol
	},
	Intermediary2 = #{
		type => Proxy2Type,
		host => "localhost",
		port => Proxy2Port,
		transport => Proxy2Transport,
		protocol => Proxy2Protocol
	},
	%% There are no connection-wide intermediaries for HTTP/2.
	Intermediaries = case {Proxy1Protocol, Proxy2Protocol} of
		{http2, _} -> [];
		{_, http2} -> [Intermediary1];
		_ -> [Intermediary1, Intermediary2]
	end,
	%% The transport, protocol, scheme and port of the origin
	%% will also vary depending on where we started using HTTP/2 CONNECT.
	%% In that case the connection-wide origin is the first HTTP/2 endpoint.
	{OriginTransport, OriginProtocol} = do_type(Origin),
	{InfoTransport, InfoProtocol, InfoPort} = case {Proxy1Protocol, Proxy2Protocol} of
		{http2, _} -> {Proxy1Transport, Proxy1Protocol, Proxy1Port};
		{_, http2} -> {Proxy2Transport, Proxy2Protocol, Proxy2Port};
		_ -> {OriginTransport, OriginProtocol, OriginPort}
	end,
	InfoScheme = case {InfoTransport, InfoProtocol} of
		{_, raw} -> undefined;
		{tcp, _} -> <<"http">>;
		{tls, _} -> <<"https">>
	end,
	#{
		transport := InfoTransport,
		protocol := InfoProtocol,
		origin_scheme := InfoScheme,
		origin_host := "localhost",
		origin_port := InfoPort,
		intermediaries := Intermediaries
	} = gun:info(ConnPid),
	ok.

do_type(http) -> {tcp, http};
do_type(https) -> {tls, http};
do_type(h2c) -> {tcp, http2};
do_type(h2) -> {tls, http2};
do_type(socks5) -> {tcp, socks};
do_type(socks5tls) -> {tls, socks};
do_type(raw) -> {tcp, raw};
do_type(rawtls) -> {tls, raw}.
