%% Feel free to use, reuse and abuse the code in this file.

-module(stream_h).

-export([init/2]).

init(Req0, State) ->
	Req = cowboy_req:stream_reply(200, #{
		<<"content-type">> => <<"text/plain">>
	}, Req0),
	cowboy_req:stream_body(<<"Hello ">>, nofin, Req),
	cowboy_req:stream_body(<<"world!">>, nofin, Req),
	%% The stream will be closed by Cowboy.
	{ok, Req, State}.
