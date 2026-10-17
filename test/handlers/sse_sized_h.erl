%% Send one unfinished Server-Sent Events line of the requested size.
%%
%% Query `n` is the number of value bytes after `data: `. Query `fin`
%% is `fin` or `nofin` (the default). The line has no blank line, so
%% the event stays unfinished.

-module(sse_sized_h).

-export([init/2]).
-export([info/3]).

init(Req0, State) ->
	Qs = cowboy_req:parse_qs(Req0),
	{_, NBin} = lists:keyfind(<<"n">>, 1, Qs),
	N = binary_to_integer(NBin),
	IsFin = case lists:keyfind(<<"fin">>, 1, Qs) of
		{_, <<"fin">>} -> fin;
		_ -> nofin
	end,
	Body = <<"data: ", (binary:copy(<<$x>>, N))/binary>>,
	Headers = case IsFin of
		fin ->
			#{
				<<"content-type">> => <<"text/event-stream">>,
				<<"content-length">> => integer_to_binary(byte_size(Body))
			};
		nofin ->
			#{<<"content-type">> => <<"text/event-stream">>}
	end,
	Req = cowboy_req:stream_reply(200, Headers, Req0),
	cowboy_req:stream_body(Body, IsFin, Req),
	case IsFin of
		fin ->
			{ok, Req, State};
		nofin ->
			{cowboy_loop, Req, State}
	end.

info(_Info, Req, State) ->
	{ok, Req, State}.
