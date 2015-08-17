%% Copyright (c) 2014-2015, Loïc Hoguin <essen@ninenines.eu>
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

-export([check_options/1]).
-export([name/0]).
-export([init/4]).
-export([handle/2]).
-export([close/1]).
-export([keepalive/1]).
-export([request/7]).
-export([request/8]).
-export([data/4]).
-export([cancel/2]).
-export([down/1]).
-export([ws_upgrade/7]).

-type io() :: head | {body, non_neg_integer()} | body_close | body_chunked.

-type websocket_info() :: {websocket, reference(), binary(), [binary()], [], gun:ws_opts()}. %% key, extensions, protocols, options

-record(http_state, {
	owner :: pid(),
	socket :: inet:socket() | ssl:sslsocket(),
	transport :: module(),
	version = 'HTTP/1.1' :: cow_http:version(),
	connection = keepalive :: keepalive | close,
	buffer = <<>> :: binary(),
	streams = [] :: [{reference() | websocket_info(), boolean()}], %% ref + whether stream is alive
	in = head :: io(),
	in_state :: {non_neg_integer(), non_neg_integer()},
	out = head :: io()
}).

check_options(Opts) ->
	do_check_options(maps:to_list(Opts)).

do_check_options([]) ->
	ok;
do_check_options([{keepalive, K}|Opts]) when is_integer(K), K > 0 ->
	do_check_options(Opts);
do_check_options([{version, V}|Opts]) when V =:= 'HTTP/1.1'; V =:= 'HTTP/1.0' ->
	do_check_options(Opts);
do_check_options([Opt|_]) ->
	{error, {options, {http, Opt}}}.

name() -> http.

init(Owner, Socket, Transport, Opts) ->
	Version = maps:get(version, Opts, 'HTTP/1.1'),
	#http_state{owner=Owner, socket=Socket, transport=Transport, version=Version}.

%% Stop looping when we got no more data.
handle(<<>>, State) ->
	State;
%% Close when server responds and we don't have any open streams.
handle(_, #http_state{streams=[]}) ->
	close;
%% Wait for the full response headers before trying to parse them.
handle(Data, State=#http_state{in=head, buffer=Buffer}) ->
	Data2 = << Buffer/binary, Data/binary >>,
	case binary:match(Data, <<"\r\n\r\n">>) of
		nomatch -> State#http_state{buffer=Data2};
		{_, _} -> handle_head(Data2, State#http_state{buffer= <<>>})
	end;
%% Everything sent to the socket until it closes is part of the response body.
handle(Data, State=#http_state{in=body_close}) ->
	send_data_if_alive(Data, State, nofin),
	State;
handle(Data, State=#http_state{in=body_chunked, in_state=InState,
		buffer=Buffer, connection=Conn}) ->
	Buffer2 = << Buffer/binary, Data/binary >>,
	case cow_http_te:stream_chunked(Buffer2, InState) of
		more ->
			State#http_state{buffer=Buffer2};
		{more, Data2, InState2} ->
			send_data_if_alive(Data2, State, nofin),
			State#http_state{buffer= <<>>, in_state=InState2};
		{more, Data2, Length, InState2} when is_integer(Length) ->
			%% @todo See if we can recv faster than one message at a time.
			send_data_if_alive(Data2, State, nofin),
			State#http_state{buffer= <<>>, in_state=InState2};
		{more, Data2, Rest, InState2} ->
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
			State#http_state{in={body, Length - DataSize}};
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

handle_head(Data, State=#http_state{owner=Owner, version=ClientVersion,
		connection=Conn, streams=[{StreamRef, IsAlive}|_]}) ->
	{Version, Status, _, Rest} = cow_http:parse_status_line(Data),
	{Headers, Rest2} = cow_http:parse_headers(Rest),
	case {Status, StreamRef} of
		{101, {websocket, _, WsKey, WsExtensions, WsProtocols, WsOpts}} ->
			ws_handshake(Rest2, State, Headers, WsKey, WsExtensions, WsProtocols, WsOpts);
		_ ->
			In = response_io_from_headers(Version, Status, Headers),
			IsFin = case In of head -> fin; _ -> nofin end,
			case IsAlive of
				false ->
					ok;
				true ->
					StreamRef2 = case StreamRef of
						{websocket, SR, _, _, _, _} -> SR;
						_ -> StreamRef
					end,
					Owner ! {gun_response, self(), StreamRef2,
						IsFin, Status, Headers},
					ok
			end,
			Conn2 = if
				Conn =:= close -> close;
				Version =:= 'HTTP/1.0' -> close;
				ClientVersion =:= 'HTTP/1.0' -> close;
				true -> conn_from_headers(Version, Headers)
			end,
			%% We always reset in_state even if not chunked.
			if
				IsFin =:= fin, Conn2 =:= close ->
					close;
				IsFin =:= fin ->
					handle(Rest2, end_stream(State#http_state{in=In,
						in_state={0, 0}, connection=Conn2}));
				true ->
					handle(Rest2, State#http_state{in=In, in_state={0, 0}, connection=Conn2})
			end
	end.

send_data_if_alive(<<>>, _, nofin) ->
	ok;
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
keepalive(State=#http_state{socket=Socket, transport=Transport, out=head}) ->
	Transport:send(Socket, <<"\r\n">>),
	State;
keepalive(State) ->
	State.

request(State=#http_state{socket=Socket, transport=Transport, version=Version,
		out=head}, StreamRef, Method, Host, Port, Path, Headers) ->
	Headers2 = lists:keydelete(<<"transfer-encoding">>, 1, Headers),
	Headers3 = case lists:keymember(<<"host">>, 1, Headers) of
		false -> [{<<"host">>, [Host, $:, integer_to_binary(Port)]}|Headers2];
		true -> Headers2
	end,
	%% We use Headers2 because this is the smallest list.
	Conn = conn_from_headers(Version, Headers2),
	Out = request_io_from_headers(Headers2),
	Headers4 = case Out of
		body_chunked -> [{<<"transfer-encoding">>, <<"chunked">>}|Headers3];
		_ -> Headers3
	end,
	Transport:send(Socket, cow_http:request(Method, Path, Version, Headers4)),
	new_stream(State#http_state{connection=Conn, out=Out}, StreamRef).

request(State=#http_state{socket=Socket, transport=Transport, version=Version,
		out=head}, StreamRef, Method, Host, Port, Path, Headers, Body) ->
	Headers2 = lists:keydelete(<<"content-length">>, 1,
		lists:keydelete(<<"transfer-encoding">>, 1, Headers)),
	Headers3 = case lists:keymember(<<"host">>, 1, Headers) of
		false -> [{<<"host">>, [Host, $:, integer_to_binary(Port)]}|Headers2];
		true -> Headers2
	end,
	%% We use Headers2 because this is the smallest list.
	Conn = conn_from_headers(Version, Headers2),
	Transport:send(Socket, [
		cow_http:request(Method, Path, Version, [
			{<<"content-length">>, integer_to_binary(iolist_size(Body))}
		|Headers3]),
		Body]),
	new_stream(State#http_state{connection=Conn}, StreamRef).

%% We are expecting a new stream.
data(State=#http_state{out=head}, StreamRef, _, _) ->
	error_stream_closed(State, StreamRef);
%% There are no active streams.
data(State=#http_state{streams=[]}, StreamRef, _, _) ->
	error_stream_not_found(State, StreamRef);
%% We can only send data on the last created stream.
data(State=#http_state{socket=Socket, transport=Transport, version=Version,
		out=Out, streams=Streams}, StreamRef, IsFin, Data) ->
	case lists:last(Streams) of
		{StreamRef, true} ->
			case Out of
				body_chunked when Version =:= 'HTTP/1.1', IsFin =:= fin ->
					case Data of
						<<>> ->
							Transport:send(Socket, cow_http_te:last_chunk());
						_ ->
							Transport:send(Socket, [
								cow_http_te:chunk(Data),
								cow_http_te:last_chunk()
							])
					end,
					State#http_state{out=head};
				body_chunked when Version =:= 'HTTP/1.1' ->
					Transport:send(Socket, cow_http_te:chunk(Data)),
					State;
				{body, Length} when byte_size(Data) =< Length ->
					Transport:send(Socket, Data),
					Length2 = Length - byte_size(Data),
					if
						Length2 =:= 0, IsFin =:= fin ->
							State#http_state{out=head};
						Length2 > 0, IsFin =:= nofin ->
							State#http_state{out={body, Length2}}
					end;
				body_chunked -> %% HTTP/1.0
					Transport:send(Socket, Data),
					State
			end;
		{_, _} ->
			error_stream_not_found(State, StreamRef)
	end.

%% We can't cancel anything, we can just stop forwarding messages to the owner.
cancel(State, StreamRef) ->
	case is_stream(State, StreamRef) of
		true ->
			cancel_stream(State, StreamRef);
		false ->
			error_stream_not_found(State, StreamRef)
	end.

%% HTTP does not provide any way to figure out what streams are unprocessed.
down(#http_state{streams=Streams}) ->
	KilledStreams = [case Ref of
		{websocket, Ref2, _, _, _, _} -> Ref2;
		_ -> Ref
	end || {Ref, _} <- Streams],
	{KilledStreams, []}.

error_stream_closed(State=#http_state{owner=Owner}, StreamRef) ->
	Owner ! {gun_error, self(), StreamRef, {badstate,
		"The stream has already been closed."}},
	State.

error_stream_not_found(State=#http_state{owner=Owner}, StreamRef) ->
	Owner ! {gun_error, self(), StreamRef, {badstate,
		"The stream cannot be found."}},
	State.

%% Headers information retrieval.

conn_from_headers(Version, Headers) ->
	case lists:keyfind(<<"connection">>, 1, Headers) of
		false when Version =:= 'HTTP/1.0' ->
			close;
		false ->
			keepalive;
		{_, ConnHd} ->
			ConnList = cow_http_hd:parse_connection(ConnHd),
			case lists:member(<<"keep-alive">>, ConnList) of
				true -> keepalive;
				false -> close
			end
	end.

request_io_from_headers(Headers) ->
	case lists:keyfind(<<"content-length">>, 1, Headers) of
		{_, <<"0">>} ->
			head;
		{_, Length} ->
			{body, cow_http_hd:parse_content_length(Length)};
		_ ->
			case lists:keymember(<<"content-type">>, 1, Headers) of
				true -> body_chunked;
				false -> head
			end
	end.

response_io_from_headers(_, 204, _) ->
	head;
response_io_from_headers(Version, _Status, Headers) ->
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
					body_close;
				{_, TE} ->
					case cow_http_hd:parse_transfer_encoding(TE) of
						[<<"chunked">>] -> body_chunked;
						[<<"identity">>] -> body_close
					end
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

%% Websocket upgrade.

%% Ensure version is 1.1.
ws_upgrade(#http_state{version='HTTP/1.0'}, _, _, _, _, _, _) ->
	error; %% @todo
ws_upgrade(State=#http_state{socket=Socket, transport=Transport, out=head},
		StreamRef, Host, Port, Path, Headers, WsOpts) ->
	{Headers1, GunExtensions} = case maps:get(compress, WsOpts, false) of
		true -> {[{<<"sec-websocket-extensions">>,
				<<"permessage-deflate; client_max_window_bits; server_max_window_bits=15">>}
			|Headers],
			[<<"permessage-deflate">>]};
		false -> {Headers, []}
	end,
	Key = cow_ws:key(),
	Headers2 = [
		{<<"connection">>, <<"upgrade">>},
		{<<"upgrade">>, <<"websocket">>},
		{<<"sec-websocket-version">>, <<"13">>},
		{<<"sec-websocket-key">>, Key}
		|Headers1
	],
	IsSecure = Transport:secure(),
	Headers3 = case lists:keymember(<<"host">>, 1, Headers) of
		true -> Headers2;
		false when Port =:= 80, not IsSecure -> [{<<"host">>, Host}|Headers2];
		false when Port =:= 443, IsSecure -> [{<<"host">>, Host}|Headers2];
		false -> [{<<"host">>, [Host, $:, integer_to_binary(Port)]}|Headers2]
	end,
	Transport:send(Socket, cow_http:request(<<"GET">>, Path, 'HTTP/1.1', Headers3)),
	new_stream(State#http_state{connection=keepalive, out=head},
		{websocket, StreamRef, Key, GunExtensions, [], WsOpts}).

ws_handshake(Buffer, State, Headers, Key, GunExtensions, GunProtocols, Opts) ->
	%% @todo check upgrade, connection
	case lists:keyfind(<<"sec-websocket-accept">>, 1, Headers) of
		false ->
			close;
		{_, Accept} ->
			case cow_ws:encode_key(Key) of
				Accept -> ws_handshake_extensions(Buffer, State, Headers, GunExtensions, GunProtocols, Opts);
				_ -> close
			end
	end.

ws_handshake_extensions(Buffer, State, Headers, GunExtensions, GunProtocols, Opts) ->
	case lists:keyfind(<<"sec-websocket-extensions">>, 1, Headers) of
		false ->
			ws_handshake_protocols(Buffer, State, Headers, #{}, GunProtocols);
		{_, ExtHd} ->
			case ws_validate_extensions(cow_http_hd:parse_sec_websocket_extensions(ExtHd), GunExtensions, #{}, Opts) of
				close -> close;
				Extensions -> ws_handshake_protocols(Buffer, State, Headers, Extensions, GunProtocols)
			end
	end.

ws_validate_extensions([], _, Acc, _) ->
	Acc;
ws_validate_extensions([{Name = <<"permessage-deflate">>, Params}|Tail], GunExts, Acc, Opts) ->
	case lists:member(Name, GunExts) of
		true ->
			case cow_ws:validate_permessage_deflate(Params, Acc, Opts) of
				{ok, Acc2} -> ws_validate_extensions(Tail, GunExts, Acc2, Opts);
				error -> close
			end;
		%% Fail the connection if extension was not requested.
		false ->
			close
	end;
%% Fail the connection on unknown extension.
ws_validate_extensions(_, _, _, _) ->
	close.

%% @todo Validate protocols.
ws_handshake_protocols(Buffer, State, Headers, Extensions, _GunProtocols = []) ->
	Protocols = [],
	ws_handshake_end(Buffer, State, Headers, Extensions, Protocols).

ws_handshake_end(Buffer, #http_state{owner=Owner, socket=Socket, transport=Transport}, Headers, Extensions, Protocols) ->
	%% Send ourselves the remaining buffer, if any.
	_ = case Buffer of
		<<>> ->
			ok;
		_ ->
			{OK, _, _} = Transport:messages(),
			self() ! {OK, Socket, Buffer}
	end,
	gun_ws:init(Owner, Socket, Transport, Headers, Extensions, Protocols).
