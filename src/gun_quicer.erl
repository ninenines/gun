%% Copyright (c) Loïc Hoguin <essen@ninenines.eu>
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

-module(gun_quicer).

-export([name/0]).
-export([messages/0]).
-export([connect/2]).
-export([sockname/1]).
-export([close/1]).

-export([start_bidi_stream/1]).
-export([start_unidi_stream/2]).
-export([send/3]).
-export([send/4]).
-export([shutdown_stream/4]).
-export([handle/1]).

%% @todo Make quicer export this type.
-type quicer_connection_handle() :: reference().
-export_type([quicer_connection_handle/0]).

-ifndef(GUN_QUICER).

-spec name() -> no_return().
name() -> no_quicer().

-spec messages() -> no_return().
messages() -> no_quicer().

-spec connect(_, _) -> no_return().
connect(_, _) -> no_quicer().

-spec sockname(_) -> no_return().
sockname(_) -> no_quicer().

-spec close(_) -> no_return().
close(_) -> no_quicer().

-spec start_bidi_stream(_) -> no_return().
start_bidi_stream(_) -> no_quicer().

-spec start_unidi_stream(_, _) -> no_return().
start_unidi_stream(_, _) -> no_quicer().

-spec send(_, _, _) -> no_return().
send(_, _, _) -> no_quicer().

-spec send(_, _, _, _) -> no_return().
send(_, _, _, _) -> no_quicer().

-spec shutdown_stream(_, _, _, _) -> no_return().
shutdown_stream(_, _, _, _) -> no_quicer().

-spec handle(_) -> no_return().
handle(_) -> no_quicer().

-spec no_quicer() -> no_return().
no_quicer() ->
	error({no_quicer,
		"Cowboy must be compiled with environment variable COWBOY_QUICER=1 "
		"or with compilation flag -D COWBOY_QUICER=1 in order to enable "
		"QUIC support using the emqx/quic NIF"}).

-else.

%% @todo Make quicer export this type.
-type quicer_app_errno() :: non_neg_integer().

-include_lib("quicer/include/quicer.hrl").

-spec name() -> quic.

name() -> quic.

-spec messages() -> {quic, quic, quic}.

%% Quicer messages aren't compatible with gen_tcp/ssl.
messages() -> {quic, quic, quic}.

connect(#{ip_addresses := IPs, port := Port, tcp_opts := _Opts}, Timeout) ->
	Timer = inet:start_timer(Timeout),
	%% @todo We must not disable security by default.
	QuicOpts = #{
		alpn => ["h3"],
		peer_unidi_stream_count => 3,
		verify => none
	}, %% @todo We need quic_opts not tcp_opts.
	Res = try
		try_connect(IPs, Port, QuicOpts, Timer, {error, einval})
	after
		_ = inet:stop_timer(Timer)
	end,
	case Res of
		{ok, Conn} -> {ok, Conn};
		Error -> maybe_exit(Error)
	end.

-dialyzer({nowarn_function, try_connect/5}).

try_connect([IP|IPs], Port, Opts, Timer, _) ->
	Timeout = inet:timeout(Timer),
	case quicer:connect(IP, Port, Opts, Timeout) of
		{ok, Conn} ->
			{ok, Conn};
		{error, Reason} ->
			{error, Reason};
		{error, transport_down, #{error := 2, status := connection_refused}} ->
			timer:sleep(1),
			try_connect([IP|IPs], Port, Opts, Timer, {error, einval});
		{error, Reason, Flags} ->
			try_connect(IPs, Port, Opts, Timer, {error, {Reason, Flags}})
	end;
try_connect([], _, _, _, Error) ->
	Error.

-dialyzer({nowarn_function, maybe_exit/1}).

maybe_exit({error, einval}) -> exit(badarg);
maybe_exit({error, eaddrnotavail}) -> exit(badarg);
maybe_exit(Error) -> Error.

-spec sockname(quicer_connection_handle())
	-> {ok, {inet:ip_address(), inet:port_number()}}
	| {error, any()}.

sockname(Conn) ->
	quicer:sockname(Conn).

-spec close(quicer_connection_handle()) -> ok.

close(Conn) ->
	quicer:close_connection(Conn).

-spec start_bidi_stream(quicer_connection_handle())
	-> {ok, cow_http3:stream_id()}
	| {error, any()}.

%% We cannot send data immediately because we need the
%% StreamID in order to compress the headers.
start_bidi_stream(Conn) ->
	case quicer:start_stream(Conn, #{active => true}) of
		{ok, StreamRef} ->
			{ok, StreamID} = quicer:get_stream_id(StreamRef),
			put({quicer_stream, StreamID}, StreamRef),
			{ok, StreamID};
		{error, Reason1, Reason2} ->
			{error, {Reason1, Reason2}};
		Error ->
			Error
	end.

-spec start_unidi_stream(quicer_connection_handle(), iodata())
	-> {ok, cow_http3:stream_id()}
	| {error, any()}.

%% Function copied from cowboy_quicer.
start_unidi_stream(Conn, HeaderData) ->
	case quicer:start_stream(Conn, #{
			active => true,
			open_flag => ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}) of
		{ok, StreamRef} ->
			case quicer:send(StreamRef, HeaderData) of
				{ok, _} ->
					{ok, StreamID} = quicer:get_stream_id(StreamRef),
					put({quicer_stream, StreamID}, StreamRef),
					{ok, StreamID};
				Error ->
					Error
			end;
		{error, Reason1, Reason2} ->
			{error, {Reason1, Reason2}};
		Error ->
			Error
	end.

-spec send(quicer_connection_handle(), cow_http3:stream_id(), iodata())
	-> ok | {error, any()}.

send(Conn, StreamID, Data) ->
	send(Conn, StreamID, Data, nofin).

-spec send(quicer_connection_handle(), cow_http3:stream_id(), iodata(), cow_http:fin())
	-> ok | {error, any()}.

send(_Conn, StreamID, Data, nofin) ->
	Len = iolist_size(Data),
	StreamRef = get({quicer_stream, StreamID}),
	{ok, Len} = quicer:send(StreamRef, Data),
	ok;
send(_Conn, StreamID, Data, fin) ->
	Len = iolist_size(Data),
	StreamRef = get({quicer_stream, StreamID}),
	{ok, Len} = quicer:send(StreamRef, Data, ?QUIC_SEND_FLAG_FIN),
	ok.

-spec shutdown_stream(quicer_connection_handle(),
	cow_http3:stream_id(), both | receiving, quicer_app_errno())
	-> ok.

%% Function copied from cowboy_quicer.
shutdown_stream(_Conn, StreamID, Dir, ErrorCode) ->
	StreamRef = get({quicer_stream, StreamID}),
	_ = quicer:shutdown_stream(StreamRef, shutdown_flag(Dir), ErrorCode, infinity),
	ok.

shutdown_flag(both) -> ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT;
shutdown_flag(receiving) -> ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE.

%% @todo Probably should have the Conn given as argument too?
-spec handle({quic, _, _, _})
	-> {data, cow_http3:stream_id(), cow_http:fin(), binary()}
	| {stream_started, cow_http3:stream_id(), unidi | bidi}
	| {stream_closed, cow_http3:stream_id(), quicer_app_errno()}
	| closed
	| ok
	| unknown
	| {socket_error, any()}.

handle({quic, peer_send_aborted, QStreamRef, ErrorCode}) ->
	{ok, StreamID} = quicer:get_stream_id(QStreamRef),
	{stream_peer_send_aborted, StreamID, ErrorCode};
%% Clauses past this point copied from cowboy_quicer.
handle({quic, Data, StreamRef, #{flags := Flags}}) when is_binary(Data) ->
	{ok, StreamID} = quicer:get_stream_id(StreamRef),
	IsFin = case Flags band ?QUIC_RECEIVE_FLAG_FIN of
		?QUIC_RECEIVE_FLAG_FIN -> fin;
		_ -> nofin
	end,
	{data, StreamID, IsFin, Data};
%% QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED.
handle({quic, new_stream, StreamRef, #{flags := Flags}}) ->
	case quicer:setopt(StreamRef, active, true) of
		ok ->
			{ok, StreamID} = quicer:get_stream_id(StreamRef),
			put({quicer_stream, StreamID}, StreamRef),
			StreamType = case quicer:is_unidirectional(Flags) of
				true -> unidi;
				false -> bidi
			end,
			{stream_started, StreamID, StreamType};
		{error, Reason} ->
			{socket_error, Reason}
	end;
%% QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE.
handle({quic, stream_closed, StreamRef, #{error := ErrorCode}}) ->
	{ok, StreamID} = quicer:get_stream_id(StreamRef),
	{stream_closed, StreamID, ErrorCode};
%% QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE.
handle({quic, closed, Conn, _Flags}) ->
	_ = quicer:close_connection(Conn),
	closed;
%% The following events are currently ignored either because
%% I do not know what they do or because we do not need to
%% take action.
handle({quic, streams_available, _Conn, _Props}) ->
	ok;
handle({quic, dgram_state_changed, _Conn, _Props}) ->
	ok;
%% QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT
handle({quic, transport_shutdown, _Conn, _Flags}) ->
	ok;
handle({quic, peer_send_shutdown, _StreamRef, undefined}) ->
	ok;
handle({quic, send_shutdown_complete, _StreamRef, _IsGraceful}) ->
	ok;
handle({quic, shutdown, _Conn, success}) ->
	ok;
handle(_Msg) ->
	unknown.

-endif.
