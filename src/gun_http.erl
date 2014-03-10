%% Copyright (c) 2014, Loïc Hoguin <essen@ninenines.eu>
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

-module(gun_http).

-export([init/3]).
-export([handle/2]).
-export([close/1]).
-export([keepalive/1]).
-export([request/6]).
-export([request/7]).
-export([data/4]).
-export([cancel/2]).

-type io() :: head | {body, non_neg_integer()} | body_close | body_chunked.

-record(http_state, {
	owner :: pid(),
	socket :: inet:socket() | ssl:sslsocket(),
	transport :: module(),
	connection = keepalive :: keepalive | close,
	buffer = <<>> :: binary(),
	streams = [] :: [{reference(), boolean()}], %% ref + whether stream is alive
	in = head :: io(),
	in_state :: {non_neg_integer(), non_neg_integer()},
	out = head :: io()
}).

init(Owner, Socket, Transport) ->
	#http_state{owner=Owner, socket=Socket, transport=Transport}.

%% Wait for the full response headers before trying to parse them.
handle(Data, State=#http_state{in=head, buffer=Buffer}) ->
	Data2 = << Buffer/binary, Data/binary >>,
	case binary:match(Data, <<"\r\n\r\n">>) of
		nomatch -> State#http_state{buffer=Data2};
		{_, _} -> handle_head(Data2, State#http_state{buffer= <<>>})
	end;
%% Everything sent to the socket until it closes is part of the response body.
handle(Data, State=#http_state{in=body_close,
		owner=Owner, streams=[{StreamRef, true}|_]}) ->
	Owner ! {gun_data, self(), StreamRef, nofin, Data},
	State;
handle(_, State=#http_state{in=body_close, streams=[{_StreamRef, false}|_]}) ->
	State;
handle(Data, State=#http_state{in=body_chunked, in_state=InState,
		buffer=Buffer, connection=Conn}) ->
	case cow_http_te:stream_chunked(<< Buffer/binary, Data/binary >>, InState) of
		more ->
			State;
		{more, Data2, InState2} ->
			send_data_if_alive(Data2, State, nofin),
			State#http_state{buffer= <<>>, in_state=InState2};
		{more, Data2, _Length, InState2} ->
			%% @todo See if we can recv faster than one message at a time.
			send_data_if_alive(Data2, State, nofin),
			State#http_state{buffer= <<>>, in_state=InState2};
		{more, Data2, _Length, Rest, InState2} ->
			%% @todo See if we can recv faster than one message at a time.
			send_data_if_alive(Data2, State, nofin),
			State#http_state{buffer=Rest, in_state=InState2};
		{done, _TotalLength, Rest} ->
			%% I suppose it doesn't hurt to append an empty binary.
			send_data_if_alive(<<>>, State, fin),
			case Conn of
				keepalive ->
					handle(Rest, end_stream(State#http_state{buffer= <<>>}));
				close ->
					close
			end;
		{done, Data2, _TotalLength, Rest} ->
			send_data_if_alive(Data2, State, fin),
			case Conn of
				keepalive ->
					handle(Rest, end_stream(State#http_state{buffer= <<>>}));
				close ->
					close
			end
	end;
%% We know the length of the rest of the body.
handle(Data, State=#http_state{in={body, Length}, connection=Conn}) ->
	DataSize = byte_size(Data),
	if
		%% More data coming.
		DataSize < Length ->
			send_data_if_alive(Data, State, nofin),
			State;
		%% Stream finished, no rest.
		DataSize =:= Length ->
			send_data_if_alive(Data, State, fin),
			case Conn of
				keepalive -> end_stream(State);
				close -> close
			end;
		%% Stream finished, rest.
		true ->
			<< Body:Length/binary, Rest/bits >> = Data,
			send_data_if_alive(Body, State, fin),
			case Conn of
				keepalive -> handle(Rest, end_stream(State));
				close -> close
			end
	end.

handle_head(Data, State=#http_state{owner=Owner, connection=Conn,
		streams=[{StreamRef, IsAlive}|_]}) ->
	{Version, Status, StatusStr, Rest} = cow_http:parse_status_line(Data),
	{Headers, Rest2} = cow_http:parse_headers(Rest),
	case IsAlive of
		false ->
			ok;
		true ->
			Owner ! {gun, response, self(), StreamRef,
				Status, StatusStr, Headers},
			ok
	end,
	Conn2 = if
		Conn =:= close -> close;
		Version =:= 'HTTP/1.0' -> close;
		true -> conn_from_headers(Headers)
	end,
	In = io_from_headers(Version, Headers),
	%% We always reset in_state even if not chunked.
	handle(Rest2, State#http_state{in=In, in_state={0, 0}, connection=Conn2}).

send_data_if_alive(Data, #http_state{owner=Owner,
		streams=[{StreamRef, true}|_]}, IsFin) ->
	Owner ! {gun_data, self(), StreamRef, IsFin, Data},
	ok;
send_data_if_alive(_, _, _) ->
	ok.

close(State=#http_state{in=body_close, owner=Owner, streams=[_|Tail]}) ->
	send_data_if_alive(<<>>, State, fin),
	close_streams(Owner, Tail);
close(#http_state{owner=Owner, streams=Streams}) ->
	close_streams(Owner, Streams).

close_streams(_, []) ->
	ok;
close_streams(Owner, [{_, false}|Tail]) ->
	close_streams(Owner, Tail);
close_streams(Owner, [{StreamRef, _}|Tail]) ->
	Owner ! {gun_error, self(), StreamRef, {closed,
		"The connection was lost."}},
	close_streams(Owner, Tail).

%% We can only keep-alive by sending an empty line in-between streams.
keepalive(State=#http_state{socket=Socket, transport=Transport}) ->
	Transport:send(Socket, <<"\r\n">>),
	State.

request(State=#http_state{socket=Socket, transport=Transport, out=head},
		StreamRef, Method, Host, Path, Headers) ->
	Conn = conn_from_headers(Headers),
	Out = io_from_headers('HTTP/1.1', Headers),
	Transport:send(Socket,
		cow_http:request(Method, Path, 'HTTP/1.1',
			[{<<"host">>, Host}|Headers])
	),
	new_stream(State#http_state{connection=Conn, out=Out}, StreamRef).

request(State=#http_state{socket=Socket, transport=Transport, out=head},
		StreamRef, Method, Host, Path, Headers, Body) ->
	Headers2 = lists:keydelete(<<"content-length">>, 1,
		lists:keydelete(<<"transfer-encoding">>, 1, Headers)),
	Conn = conn_from_headers(Headers2),
	Transport:send(Socket,
		cow_http:request(Method, Path, 'HTTP/1.1', [
			{<<"host">>, Host},
			{<<"content-length">>, integer_to_list(iolist_size(Body))}
		|Headers2]),
		Body
	),
	new_stream(State#http_state{connection=Conn}, StreamRef).

%% We are expecting a new stream.
data(State=#http_state{out=head}, _, _, _) ->
	error_stream_closed(State);
%% There are no active streams.
data(State=#http_state{streams=[]}, _, _, _) ->
	error_stream_not_found(State);
%% We can only send data on the last created stream.
data(State=#http_state{socket=Socket, transport=Transport, out=Out,
		streams=Streams}, StreamRef, IsFin, Data) ->
	case lists:last(Streams) of
		{StreamRef, true} ->
			DataSize = byte_size(Data),
			case Out of
				body_chunked when IsFin ->
					Transport:send(Socket, [
						integer_to_list(DataSize), <<"\r\n">>,
						Data, <<"\r\n0\r\n\r\n">>
					]),
					State#http_state{out=head};
				body_chunked ->
					Transport:send(Socket, [
						integer_to_list(DataSize), <<"\r\n">>,
						Data, <<"\r\n">>
					]),
					State;
				{body, Length} when DataSize =< Length ->
					Transport:send(Socket, Data),
					Length2 = Length - DataSize,
					if
						Length2 =:= 0, IsFin ->
							State#http_state{out=head};
						Length2 > 0, not IsFin ->
							State#http_state{out={body, Length2}}
					end
			end;
		{_, _} ->
			error_stream_not_found(State)
	end.

%% We can't cancel anything, we can just stop forwarding messages to the owner.
cancel(State, StreamRef) ->
	case is_stream(State, StreamRef) of
		true ->
			cancel_stream(State, StreamRef);
		false ->
			error_stream_not_found(State)
	end.

error_stream_closed(State=#http_state{owner=Owner}) ->
	Owner ! {gun_error, self(), {badstate,
		"The stream has already been closed."}},
	State.

error_stream_not_found(State=#http_state{owner=Owner}) ->
	Owner ! {gun_error, self(), {badstate,
		"The stream cannot be found."}},
	State.

%% Headers information retrieval.

conn_from_headers(Headers) ->
	case lists:keyfind(<<"connection">>, 1, Headers) of
		false ->
			keepalive;
		{_, ConnHd} ->
			cow_http_hd:parse_connection(ConnHd)
	end.

io_from_headers(Version, Headers) ->
	case lists:keyfind(<<"content-length">>, 1, Headers) of
		{_, <<"0">>} ->
			head;
		{_, Length} ->
			{body, cow_http_hd:parse_content_length(Length)};
		_ when Version =:= 'HTTP/1.0' ->
			body_close;
		_ ->
			case lists:keyfind(<<"transfer-encoding">>, 1, Headers) of
				false ->
					head;
				{_, TE} ->
					%% We only support chunked transfer-encoding.
					[<<"chunked">>] = cow_http_hd:parse_transfer_encoding(TE),
					body_chunked
			end
	end.

%% Streams.

new_stream(State=#http_state{streams=Streams}, StreamRef) ->
	State#http_state{streams=Streams ++ [{StreamRef, true}]}.

is_stream(#http_state{streams=Streams}, StreamRef) ->
	lists:keymember(StreamRef, 1, Streams).

cancel_stream(State=#http_state{streams=Streams}, StreamRef) ->
	Streams2 = [case Ref of
		StreamRef ->
			{Ref, false};
		_ ->
			Tuple
	end || Tuple = {Ref, _} <- Streams],
	State#http_state{streams=Streams2}.

end_stream(State=#http_state{streams=[_|Tail]}) ->
	State#http_state{in=head, streams=Tail}.
