%% Copyright (c) 2013-2014, Loïc Hoguin <essen@ninenines.eu>
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

-module(gun_spdy).

-export([init/4]).
-export([handle/2]).
-export([close/1]).
-export([keepalive/1]).
-export([request/6]).
-export([request/7]).
-export([data/4]).
-export([cancel/2]).

-record(stream, {
	id :: non_neg_integer(),
	ref :: reference(),
	in :: boolean(), %% true = open
	out :: boolean(), %% true = open
	version :: binary()
}).

-record(spdy_state, {
	owner :: pid(),
	socket :: inet:socket() | ssl:sslsocket(),
	transport :: module(),
	buffer = <<>> :: binary(),
	zdef :: zlib:zstream(),
	zinf :: zlib:zstream(),
	streams = [] :: [#stream{}],
	stream_id = 1 :: non_neg_integer(),
	ping_id = 1 :: non_neg_integer()
}).

init(Owner, Socket, Transport, []) ->
	#spdy_state{owner=Owner, socket=Socket, transport=Transport,
		zdef=cow_spdy:deflate_init(), zinf=cow_spdy:inflate_init()}.

handle(Data, State=#spdy_state{buffer=Buffer}) ->
	handle_loop(<< Buffer/binary, Data/binary >>,
		State#spdy_state{buffer= <<>>}).

handle_loop(Data, State=#spdy_state{zinf=Zinf}) ->
	case cow_spdy:split(Data) of
		{true, Frame, Rest} ->
			P = cow_spdy:parse(Frame, Zinf),
			handle_frame(Rest, State, P);
		false ->
			State#spdy_state{buffer=Data}
	end.

handle_frame(Rest, State=#spdy_state{owner=Owner,
		socket=Socket, transport=Transport},
		{data, StreamID, IsFin, Data}) ->
	case get_stream_by_id(StreamID, State) of
		#stream{in=false} ->
			Transport:send(Socket,
				cow_spdy:rst_stream(StreamID, stream_already_closed)),
			handle_loop(Rest, delete_stream(StreamID, State));
		S = #stream{ref=StreamRef} when IsFin ->
			Owner ! {gun_data, self(), StreamRef, fin, Data},
			handle_loop(Rest, in_fin_stream(S, State));
		#stream{ref=StreamRef} ->
			Owner ! {gun_data, self(), StreamRef, nofin, Data},
			handle_loop(Rest, State);
		false ->
			Transport:send(Socket,
				cow_spdy:rst_stream(StreamID, invalid_stream)),
			handle_loop(Rest, delete_stream(StreamID, State))
	end;
handle_frame(Rest, State=#spdy_state{owner=Owner,
		socket=Socket, transport=Transport},
		{syn_stream, StreamID, AssocToStreamID, IsFin, IsUnidirectional,
		_, Method, _, Host, Path, Version, Headers})
		when AssocToStreamID =/= 0, IsUnidirectional ->
	case get_stream_by_id(StreamID, State) of
		false ->
			case get_stream_by_id(AssocToStreamID, State) of
				#stream{ref=AssocToStreamRef} ->
					StreamRef = make_ref(),
					Owner ! {gun_push, self(), StreamRef,
						AssocToStreamRef, Method, Host, Path, Headers},
					handle_loop(Rest, new_stream(StreamID, StreamRef,
						not IsFin, false, Version, State));
				false ->
					Transport:send(Socket,
						cow_spdy:rst_stream(AssocToStreamID, invalid_stream)),
					handle_loop(Rest, State)
			end;
		#stream{} ->
			Transport:send(Socket,
				cow_spdy:rst_stream(StreamID, stream_in_use)),
			handle_loop(Rest, State)
	end;
handle_frame(Rest, State=#spdy_state{socket=Socket, transport=Transport},
		{syn_stream, StreamID, _, _, _, _, _, _, _, _, _, _}) ->
	Transport:send(Socket,
		cow_spdy:rst_stream(StreamID, protocol_error)),
	handle_loop(Rest, State);
handle_frame(Rest, State=#spdy_state{owner=Owner,
		socket=Socket, transport=Transport},
		{syn_reply, StreamID, IsFin, Status, _, Headers}) ->
	case get_stream_by_id(StreamID, State) of
		#stream{in=false} ->
			Transport:send(Socket,
				cow_spdy:rst_stream(StreamID, stream_already_closed)),
			handle_loop(Rest, delete_stream(StreamID, State));
		S = #stream{ref=StreamRef} when IsFin ->
			Owner ! {gun_response, self(), StreamRef, fin,
				parse_status(Status), Headers},
			handle_loop(Rest, in_fin_stream(S, State));
		#stream{ref=StreamRef} ->
			Owner ! {gun_response, self(), StreamRef, nofin,
				parse_status(Status), Headers},
			handle_loop(Rest, State);
		false ->
			Transport:send(Socket,
				cow_spdy:rst_stream(StreamID, invalid_stream)),
			handle_loop(Rest, delete_stream(StreamID, State))
	end;
handle_frame(Rest, State=#spdy_state{owner=Owner},
		{rst_stream, StreamID, Status}) ->
	case get_stream_by_id(StreamID, State) of
		#stream{ref=StreamRef} ->
			Owner ! {gun_error, self(), StreamRef, Status},
			handle_loop(Rest, delete_stream(StreamID, State));
		false ->
			handle_loop(Rest, State)
	end;
handle_frame(Rest, State, {settings, ClearSettings, Settings}) ->
	error_logger:error_msg("Ignored SETTINGS control frame ~p ~p~n",
		[ClearSettings, Settings]),
	handle_loop(Rest, State);
%% Server PING.
handle_frame(Rest, State=#spdy_state{socket=Socket, transport=Transport},
		{ping, PingID}) when PingID rem 2 =:= 0 ->
	Transport:send(Socket, cow_spdy:ping(PingID)),
	handle_loop(Rest, State);
%% Client PING.
handle_frame(Rest, State, {ping, _}) ->
	handle_loop(Rest, State);
handle_frame(Rest, State, {goaway, LastGoodStreamID, Status}) ->
	error_logger:error_msg("Ignored GOAWAY control frame ~p ~p~n",
		[LastGoodStreamID, Status]),
	handle_loop(Rest, State);
handle_frame(Rest, State, {headers, StreamID, IsFin, Headers}) ->
	error_logger:error_msg("Ignored HEADERS control frame ~p ~p ~p~n",
		[StreamID, IsFin, Headers]),
	handle_loop(Rest, State);
handle_frame(Rest, State, {window_update, StreamID, DeltaWindowSize}) ->
	error_logger:error_msg("Ignored WINDOW_UPDATE control frame ~p ~p~n",
		[StreamID, DeltaWindowSize]),
	handle_loop(Rest, State);
handle_frame(_, #spdy_state{owner=Owner, socket=Socket, transport=Transport},
		{error, badprotocol}) ->
	Owner ! {gun_error, self(), {badprotocol,
		"The remote endpoint sent invalid data."}},
	%% @todo LastGoodStreamID
	Transport:send(Socket, cow_spdy:goaway(0, protocol_error)),
	close.

parse_status(Status) ->
	<< Code:3/binary, _/bits >> = Status,
	list_to_integer(binary_to_list(Code)).

close(#spdy_state{owner=Owner, streams=Streams}) ->
	close_streams(Owner, Streams).

close_streams(_, []) ->
	ok;
close_streams(Owner, [#stream{ref=StreamRef}|Tail]) ->
	Owner ! {gun_error, self(), StreamRef, {closed,
		"The connection was lost."}},
	close_streams(Owner, Tail).

keepalive(State=#spdy_state{socket=Socket, transport=Transport,
		ping_id=PingID}) ->
	Transport:send(Socket, cow_spdy:ping(PingID)),
	State#spdy_state{ping_id=PingID + 2}.

%% @todo Allow overriding the host when doing requests.
request(State=#spdy_state{socket=Socket, transport=Transport, zdef=Zdef,
		stream_id=StreamID}, StreamRef, Method, Host, Path, Headers) ->
	Out = false =/= lists:keyfind(<<"content-type">>, 1, Headers),
	Transport:send(Socket, cow_spdy:syn_stream(Zdef,
		StreamID, 0, not Out, false, 0,
		Method, <<"https">>, Host, Path, <<"HTTP/1.1">>, Headers)),
	new_stream(StreamID, StreamRef, true, Out, <<"HTTP/1.1">>,
		State#spdy_state{stream_id=StreamID + 2}).

%% @todo Handle Body > 16MB. (split it out into many frames)
request(State=#spdy_state{socket=Socket, transport=Transport, zdef=Zdef,
		stream_id=StreamID}, StreamRef, Method, Host, Path, Headers, Body) ->
	Headers2 = lists:keystore(<<"content-length">>, 1, Headers,
		{<<"content-length">>, integer_to_list(iolist_size(Body))}),
	Transport:send(Socket, [
		cow_spdy:syn_stream(Zdef,
			StreamID, 0, false, false, 0,
			Method, <<"https">>, Host, Path, <<"HTTP/1.1">>, Headers2),
		cow_spdy:data(StreamID, true, Body)
	]),
	new_stream(StreamID, StreamRef, true, false, <<"HTTP/1.1">>,
		State#spdy_state{stream_id=StreamID + 2}).

data(State=#spdy_state{socket=Socket, transport=Transport},
		StreamRef, IsFin, Data) ->
	case get_stream_by_ref(StreamRef, State) of
		#stream{out=false} ->
			error_stream_closed(State);
		S = #stream{} ->
			IsFin2 = IsFin =:= fin,
			Transport:send(Socket, cow_spdy:data(S#stream.id, IsFin2, Data)),
			if IsFin2 ->
				out_fin_stream(S, State);
			true ->
				State
			end;
		false ->
			error_stream_not_found(State)
	end.

cancel(State=#spdy_state{socket=Socket, transport=Transport},
		StreamRef) ->
	case get_stream_by_ref(StreamRef, State) of
		#stream{id=StreamID} ->
			Transport:send(Socket, cow_spdy:rst_stream(StreamID, cancel)),
			delete_stream(StreamID, State);
		false ->
			error_stream_not_found(State)
	end.

error_stream_closed(State=#spdy_state{owner=Owner}) ->
	Owner ! {gun_error, self(), {badstate,
		"The stream has already been closed."}},
	State.

error_stream_not_found(State=#spdy_state{owner=Owner}) ->
	Owner ! {gun_error, self(), {badstate,
		"The stream cannot be found."}},
	State.

%% Streams.
%% @todo probably change order of args and have state first?

new_stream(StreamID, StreamRef, In, Out, Version,
		State=#spdy_state{streams=Streams}) ->
	New = #stream{id=StreamID, ref=StreamRef,
		in=In, out=Out, version=Version},
	State#spdy_state{streams=[New|Streams]}.

get_stream_by_id(StreamID, #spdy_state{streams=Streams}) ->
	lists:keyfind(StreamID, #stream.id, Streams).

get_stream_by_ref(StreamRef, #spdy_state{streams=Streams}) ->
	lists:keyfind(StreamRef, #stream.ref, Streams).

delete_stream(StreamID, State=#spdy_state{streams=Streams}) ->
	Streams2 = lists:keydelete(StreamID, #stream.id, Streams),
	State#spdy_state{streams=Streams2}.

in_fin_stream(S=#stream{out=false}, State) ->
	delete_stream(S#stream.id, State);
in_fin_stream(S, State=#spdy_state{streams=Streams}) ->
	Streams2 = lists:keyreplace(S#stream.id, #stream.id, Streams,
		S#stream{in=false}),
	State#spdy_state{streams=Streams2}.

out_fin_stream(S=#stream{in=false}, State) ->
	delete_stream(S#stream.id, State);
out_fin_stream(S, State=#spdy_state{streams=Streams}) ->
	Streams2 = lists:keyreplace(S#stream.id, #stream.id, Streams,
		S#stream{out=false}),
	State#spdy_state{streams=Streams2}.
