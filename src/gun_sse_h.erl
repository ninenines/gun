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

-module(gun_sse_h).
-behavior(gun_content_handler).

-export([init/5]).
-export([handle/3]).

-record(state, {
	reply_to :: gun:reply_to(),
	stream_ref :: reference(),
	sse_state :: cow_sse:state(),
	%% Maximum size of one event still held by cow_sse: its data,
	%% event type, id, and the current incomplete line. Comment
	%% lines are not part of that. cow_sse itself does not bound it.
	max_event_size = 1048576 :: non_neg_integer() | infinity,
	limit_exceeded = false :: boolean()
}).

%% @todo In the future we want to allow different media types.

-spec init(pid(), reference(), _, cow_http:headers(), _)
	-> {ok, #state{}} | disable.
init(ReplyTo, StreamRef, _, Headers, Opts) ->
	case lists:keyfind(<<"content-type">>, 1, Headers) of
		{_, ContentType} ->
			case cow_http_hd:parse_content_type(ContentType) of
				{<<"text">>, <<"event-stream">>, _Ignored} ->
					{ok, #state{reply_to=ReplyTo, stream_ref=StreamRef,
						sse_state=cow_sse:init(),
						max_event_size=maps:get(max_event_size, Opts, 1048576)}};
				_ ->
					disable
			end;
		_ ->
			disable
	end.

-spec handle(_, binary(), State) ->
	{done, non_neg_integer(), State} | {done, non_neg_integer(), State, cancel}
	when State::#state{}.
handle(IsFin, Data, State) ->
	handle(IsFin, Data, State, 0).

%% The limit was already exceeded. Do not feed cow_sse any further data.
handle(_, _, State=#state{limit_exceeded=true}, Flow) ->
	{done, Flow, State};
%% No limit: parse the whole read. Several complete events in one
%% read are each dispatched; their combined size is not one event.
handle(IsFin, Data, State=#state{reply_to=ReplyTo, stream_ref=StreamRef,
		sse_state=SSE0, max_event_size=infinity}, Flow) ->
	case cow_sse:parse(Data, SSE0) of
		{event, Event, SSE} ->
			gun:reply(ReplyTo, {gun_sse, self(), StreamRef, Event}),
			handle(IsFin, <<>>, State#state{sse_state=SSE}, Flow + 1);
		{more, SSE} ->
			Inc = case IsFin of
				fin ->
					gun:reply(ReplyTo, {gun_sse, self(), StreamRef, fin}),
					1;
				_ ->
					0
			end,
			{done, Flow + Inc, State#state{sse_state=SSE}}
	end;
handle(IsFin, Data, State=#state{sse_state=SSE0, max_event_size=MaxEventSize}, Flow) ->
	%% Events already sitting in cow_sse's buffer must be dispatched
	%% before more input is sliced. Otherwise the next slice is a few
	%% bytes and parse copies the whole buffer onto it for every event.
	case element(3, SSE0) of
		<<>> ->
			read_more(IsFin, Data, State, SSE0, MaxEventSize, Flow);
		_ ->
			case cow_sse:parse(<<>>, SSE0) of
				{event, Event, SSE} ->
					dispatch_event(IsFin, Data, Event, SSE, State, MaxEventSize, Flow);
				%% Only an incomplete line is left. Take more input.
				{more, SSE} ->
					read_more(IsFin, Data, State#state{sse_state=SSE},
						SSE, MaxEventSize, Flow)
			end
	end.

%% Feed at most one byte past what the current event may still hold.
%% A single read can be as large as the socket buffer.
read_more(IsFin, Data, State, SSE0, MaxEventSize, Flow) ->
	Held = sse_held(SSE0),
	case Held > MaxEventSize of
		true ->
			exceeded(IsFin, State, Flow);
		false ->
			{Slice, Rest} = slice_event(Data, MaxEventSize - Held + 1),
			parse_slice(IsFin, Slice, Rest, State, SSE0, MaxEventSize, Flow)
	end.

parse_slice(IsFin, Slice, Rest, State, SSE0, MaxEventSize, Flow) ->
	case cow_sse:parse(Slice, SSE0) of
		{event, Event, SSE} ->
			dispatch_event(IsFin, Rest, Event, SSE, State, MaxEventSize, Flow);
		{more, SSE} ->
			case sse_held(SSE) > MaxEventSize of
				true ->
					exceeded(IsFin, State, Flow);
				false when Rest =:= <<>> ->
					Inc = case IsFin of
						fin ->
							gun:reply(State#state.reply_to,
								{gun_sse, self(), State#state.stream_ref, fin}),
							1;
						_ ->
							0
					end,
					{done, Flow + Inc, State#state{sse_state=SSE}};
				false ->
					handle(IsFin, Rest, State#state{sse_state=SSE}, Flow)
			end
	end.

dispatch_event(IsFin, Rest, Event, SSE, State, MaxEventSize, Flow) ->
	case event_size(Event) > MaxEventSize orelse sse_held(SSE) > MaxEventSize of
		true ->
			exceeded(IsFin, State, Flow);
		false ->
			gun:reply(State#state.reply_to,
				{gun_sse, self(), State#state.stream_ref, Event}),
			handle(IsFin, Rest, State#state{sse_state=SSE}, Flow + 1)
	end.

%% Bytes cow_sse is still holding for the event that has not been
%% dispatched. Comment lines are dropped by the parser and are not
%% counted. The tuple layout is cow_sse's #state{}: buffer, id,
%% id-set flag, event type, data.
sse_held(SSE) ->
	Buffer = element(3, SSE),
	IdSize = case element(5, SSE) of
		true -> byte_size(element(4, SSE));
		false -> 0
	end,
	EventType = element(6, SSE),
	Data = element(7, SSE),
	byte_size(Buffer) + IdSize + byte_size(EventType) + iolist_size(Data).

event_size(Event) ->
	iolist_size(maps:get(data, Event, []))
		+ byte_size(maps:get(last_event_id, Event, <<>>))
		+ byte_size(maps:get(event_type, Event, <<>>)).

%% Do not end a slice between the CR and LF of one CRLF. cow_sse
%% treats a buffer that ends in CR as a finished line, so the LF
%% would be parsed later as a blank line and dispatch early.
slice_event(Data, Budget) ->
	{Slice0, Rest0} = case Data of
		<<S:Budget/binary, R/binary>> ->
			{S, R};
		_ ->
			{Data, <<>>}
	end,
	case {Slice0, Rest0} of
		{_, <<>>} ->
			{Slice0, Rest0};
		_ ->
			case {binary:last(Slice0), Rest0} of
				{$\r, <<$\n, Rest/binary>>} ->
					{<<Slice0/binary, $\n>>, Rest};
				_ ->
					{Slice0, Rest0}
			end
	end.

exceeded(fin, State=#state{reply_to=ReplyTo, stream_ref=StreamRef}, Flow) ->
	gun:reply(ReplyTo, {gun_error, self(), StreamRef, {limit_reached,
		"The Server-Sent Events buffer is larger than configuration allows."}}),
	%% This read ends the stream. Cancelling after that reports a
	%% second badstate error for a stream that is already gone.
	{done, Flow, State#state{limit_exceeded=true, sse_state=cow_sse:init()}};
exceeded(nofin, State=#state{reply_to=ReplyTo, stream_ref=StreamRef}, Flow) ->
	gun:reply(ReplyTo, {gun_error, self(), StreamRef, {limit_reached,
		"The Server-Sent Events buffer is larger than configuration allows."}}),
	%% Ask the protocol to reset the stream before it parses the
	%% rest of this read. A cast would run only after those frames,
	%% and a later END_STREAM would already have removed the stream.
	{done, Flow, State#state{limit_exceeded=true, sse_state=cow_sse:init()}, cancel}.
