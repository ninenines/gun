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

-module(gun_quic).

-export([name/0]).
-export([messages/0]).
-export([connect/2]).
-export([sockname/1]).
-export([close/1]).

-export([open_bidi_stream/1]).
-export([open_unidi_stream/2]).
-export([send/3]).
-export([send/4]).
-export([stop_sending/3]).
-export([make_event/1]).

-opaque conn() :: any().
-export_type([conn/0]).

-ifndef(CORRAL).

-spec name() -> no_return().
name() -> no_quic().

-spec messages() -> no_return().
messages() -> no_quic().

-spec connect(_, _) -> no_return().
connect(_, _) -> no_quic().

-spec sockname(_) -> no_return().
sockname(_) -> no_quic().

-spec close(_) -> no_return().
close(_) -> no_quic().

-spec open_bidi_stream(_) -> no_return().
open_bidi_stream(_) -> no_quic().

-spec open_unidi_stream(_, _) -> no_return().
open_unidi_stream(_, _) -> no_quic().

-spec send(_, _, _) -> no_return().
send(_, _, _) -> no_quic().

-spec send(_, _, _, _) -> no_return().
send(_, _, _, _) -> no_quic().

-spec shutdown_stream(_, _, _, _) -> no_return().
shutdown_stream(_, _, _, _) -> no_quic().

-spec handle(_) -> no_return().
handle(_) -> no_quic().

-spec no_quic() -> no_return().
no_quic() ->
	error({no_quic,
		"Gun must be compiled with environment variable CORRAL_DEPS "
		"(with a value that includes 'quicer') "
		"or with compilation flag -D CORRAL=1 in order to enable "
		"QUIC support"}).

-else.

-spec name() -> quic.

name() -> quic.

-spec messages() -> {quic, quic, quic}.

%% Quic messages aren't compatible with gen_tcp/ssl; unused.
messages() -> {quic, quic, quic}.

connect(#{ip_addresses := IPs, port := Port, tcp_opts := _Opts}, Timeout) ->
	Timer = inet:start_timer(Timeout),
	%% @todo We must not disable security by default.
	QuicOpts = #{
		alpn => [<<"h3">>],
		max_streams_unidi => 3,
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
	case corral_quicer:connect(IP, Port, Opts#{connect_timeout => Timeout}) of
		{ok, Conn} ->
			{ok, Conn};
		{error, econnrefused} ->
			timer:sleep(1),
			try_connect([IP|IPs], Port, Opts, Timer, {error, econnrefused});
		{error, Reason} ->
			try_connect(IPs, Port, Opts, Timer, {error, Reason})
	end;
try_connect([], _, _, _, Error) ->
	Error.

-dialyzer({nowarn_function, maybe_exit/1}).

maybe_exit({error, einval}) -> exit(badarg);
maybe_exit({error, eaddrnotavail}) -> exit(badarg); %% @todo Probably dead code right now.
maybe_exit(Error) -> Error.

-spec sockname(conn())
	-> {ok, {inet:ip_address(), inet:port_number()}}
	| {error, any()}.

sockname(Conn) ->
	corral_quicer:sockname(Conn).

-spec close(conn()) -> ok.

close(Conn) ->
	corral_quicer:close(Conn).

-spec open_bidi_stream(conn())
	-> {ok, cow_http3:stream_id()}
	| {error, any()}.

%% We cannot send data immediately because we need the
%% StreamID in order to compress the headers.
open_bidi_stream(Conn) ->
	corral_quicer:open_bidi_stream(Conn, <<>>).

-spec open_unidi_stream(conn(), iodata())
	-> {ok, cow_http3:stream_id()}
	| {error, any()}.

open_unidi_stream(Conn, InitialData) ->
	corral_quicer:open_unidi_stream(Conn, InitialData).

-spec send(conn(), cow_http3:stream_id(), iodata())
	-> ok | {error, any()}.

send(Conn, StreamID, Data) ->
	corral_quicer:send(Conn, StreamID, Data).

-spec send(conn(), cow_http3:stream_id(), iodata(), cow_http:fin())
	-> ok | {error, any()}.

send(Conn, StreamID, IsFin, Data) ->
	corral_quicer:send(Conn, StreamID, IsFin, Data).

-spec stop_sending(conn(), cow_http3:stream_id(), corral_backend:app_errno())
	-> ok | {error, any()}.

stop_sending(Conn, StreamID, AppErrno) ->
	corral_quicer:stop_sending(Conn, StreamID, AppErrno).

-spec make_event(tuple()) -> corral_backend:event().

make_event(Msg) ->
	corral_quicer:make_event(Msg).






%% @todo Probably should have the Conn given as argument too?
%-spec handle({quic, _, _, _})
%	-> {data, cow_http3:stream_id(), cow_http:fin(), binary()}
%	| {stream_started, cow_http3:stream_id(), unidi | bidi}
%	| {stream_closed, cow_http3:stream_id(), corral_backend:app_errno()}
%	| closed
%	| ok
%	| unknown
%	| {socket_error, any()}.
%
%handle({quic, peer_send_aborted, QStreamRef, ErrorCode}) ->
%	{ok, StreamID} = quicer:get_stream_id(QStreamRef),
%	{stream_peer_send_aborted, StreamID, ErrorCode};
%%% Clauses past this point copied from cowboy_quicer.
%handle({quic, Data, StreamRef, #{flags := Flags}}) when is_binary(Data) ->
%	{ok, StreamID} = quicer:get_stream_id(StreamRef),
%	IsFin = case Flags band ?QUIC_RECEIVE_FLAG_FIN of
%		?QUIC_RECEIVE_FLAG_FIN -> fin;
%		_ -> nofin
%	end,
%	{data, StreamID, IsFin, Data};
%%% QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED.
%handle({quic, new_stream, StreamRef, #{flags := Flags}}) ->
%	case quicer:setopt(StreamRef, active, true) of
%		ok ->
%			{ok, StreamID} = quicer:get_stream_id(StreamRef),
%			put({quicer_stream, StreamID}, StreamRef),
%			StreamType = case quicer:is_unidirectional(Flags) of
%				true -> unidi;
%				false -> bidi
%			end,
%			{stream_started, StreamID, StreamType};
%		{error, Reason} ->
%			{socket_error, Reason}
%	end;
%%% QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE.
%handle({quic, stream_closed, StreamRef, #{error := ErrorCode}}) ->
%	{ok, StreamID} = quicer:get_stream_id(StreamRef),
%	{stream_closed, StreamID, ErrorCode};
%%% QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE.
%handle({quic, closed, Conn, _Flags}) ->
%	_ = quicer:close_connection(Conn),
%	closed;
%%% The following events are currently ignored either because
%%% I do not know what they do or because we do not need to
%%% take action.
%handle({quic, streams_available, _Conn, _Props}) ->
%	ok;
%handle({quic, dgram_state_changed, _Conn, _Props}) ->
%	ok;
%%% QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT
%handle({quic, transport_shutdown, _Conn, _Flags}) ->
%	ok;
%handle({quic, peer_send_shutdown, _StreamRef, undefined}) ->
%	ok;
%handle({quic, send_shutdown_complete, _StreamRef, _IsGraceful}) ->
%	ok;
%handle({quic, shutdown, _Conn, success}) ->
%	ok;
%handle(_Msg) ->
%	unknown.

-endif.
