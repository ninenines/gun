%% Copyright (c) 2018-2020, Loïc Hoguin <essen@ninenines.eu>
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

-module(gun_test).
-compile(export_all).
-compile(nowarn_export_all).

%% Cowboy listeners.

init_cowboy_tcp(Ref, ProtoOpts, Config) ->
	{ok, _} = cowboy:start_clear(Ref, [{port, 0}], ProtoOpts),
	[{ref, Ref}, {port, ranch:get_port(Ref)}|Config].

init_cowboy_tls(Ref, ProtoOpts, Config) ->
	Opts = ct_helper:get_certs_from_ets(),
	{ok, _} = cowboy:start_tls(Ref, Opts ++ [{port, 0}], ProtoOpts),
	[{ref, Ref}, {port, ranch:get_port(Ref)}|Config].

%% Origin server helpers.

init_origin(Transport) ->
	init_origin(Transport, http).

init_origin(Transport, Protocol) ->
	init_origin(Transport, Protocol, fun loop_origin/3).

init_origin(Transport, Protocol, Fun) ->
	Pid = spawn_link(?MODULE, init_origin, [self(), Transport, Protocol, Fun]),
	Port = receive_from(Pid),
	{ok, Pid, Port}.

init_origin(Parent, Transport, Protocol, Fun)
		when Transport =:= tcp; Transport =:= tcp6 ->
	InetOpt = case Transport of
		tcp -> inet;
		tcp6 -> inet6
	end,
	{ok, ListenSocket} = gen_tcp:listen(0, [binary, {active, false}, InetOpt]),
	{ok, {_, Port}} = inet:sockname(ListenSocket),
	Parent ! {self(), Port},
	{ok, ClientSocket} = gen_tcp:accept(ListenSocket, 5000),
	case Protocol of
		http2 -> http2_handshake(ClientSocket, gen_tcp);
		_ -> ok
	end,
	Parent ! {self(), handshake_completed},
	Fun(Parent, ClientSocket, gen_tcp);
init_origin(Parent, tls, Protocol, Fun) ->
	Opts0 = ct_helper:get_certs_from_ets(),
	Opts1 = case Protocol of
		http2 -> [{alpn_preferred_protocols, [<<"h2">>]}|Opts0];
		_ -> Opts0
	end,
	%% sni_hosts is necessary for SNI tests to succeed.
	Opts = [{sni_hosts, [{net_adm:localhost(), []}]}|Opts1],
	{ok, ListenSocket} = ssl:listen(0, [binary, {active, false}|Opts]),
	{ok, {_, Port}} = ssl:sockname(ListenSocket),
	Parent ! {self(), Port},
	{ok, ClientSocket0} = ssl:transport_accept(ListenSocket, 5000),
	{ok, ClientSocket} = ssl:handshake(ClientSocket0, 5000),
	case Protocol of
		http2 ->
			{ok, <<"h2">>} = ssl:negotiated_protocol(ClientSocket),
			http2_handshake(ClientSocket, ssl);
		_ ->
			ok
	end,
	Parent ! {self(), handshake_completed},
	Fun(Parent, ClientSocket, ssl).

http2_handshake(Socket, Transport) ->
	%% Send a valid preface.
	ok = Transport:send(Socket, cow_http2:settings(#{})),
	%% Receive the fixed sequence from the preface.
	Preface = <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>,
	{ok, Preface} = Transport:recv(Socket, byte_size(Preface), 5000),
	%% Receive the SETTINGS from the preface.
	{ok, <<Len:24>>} = Transport:recv(Socket, 3, 5000),
	{ok, <<4:8, 0:40, _:Len/binary>>} = Transport:recv(Socket, 6 + Len, 5000),
	%% Receive the WINDOW_UPDATE sent with the preface.
	{ok, <<4:24, 8:8, 0:40, _:32>>} = Transport:recv(Socket, 13, 5000),
	%% Send the SETTINGS ack.
	ok = Transport:send(Socket, cow_http2:settings_ack()),
	%% Receive the SETTINGS ack.
	{ok, <<0:24, 4:8, 1:8, 0:32>>} = Transport:recv(Socket, 9, 5000),
	ok.

loop_origin(Parent, ClientSocket, ClientTransport) ->
	case ClientTransport:recv(ClientSocket, 0, 5000) of
		{ok, Data} ->
			Parent ! {self(), Data},
			loop_origin(Parent, ClientSocket, ClientTransport);
		{error, closed} ->
			ok
	end.

%% Common helpers.

receive_from(Pid) ->
	receive_from(Pid, 5000).

receive_from(Pid, Timeout) ->
	receive
		{Pid, Msg} ->
			Msg
	after Timeout ->
		error(timeout)
	end.

receive_all_from(Pid, Timeout) ->
	receive_all_from(Pid, Timeout, <<>>).

receive_all_from(Pid, Timeout, Acc) ->
	try
		More = receive_from(Pid, Timeout),
		receive_all_from(Pid, Timeout, <<Acc/binary, More/binary>>)
	catch error:timeout ->
		Acc
	end.
