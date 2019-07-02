%% Feel free to use, reuse and abuse the code in this file.

-module(trailers_h).

-export([init/2]).

init(Req0, State) ->
	Req = cowboy_req:stream_reply(200, #{
		<<"content-type">> => <<"text/plain">>,
		<<"trailer">> => <<"expires">>
	}, Req0),
	cowboy_req:stream_body(<<"Hello ">>, nofin, Req),
	cowboy_req:stream_body(<<"world!">>, nofin, Req),
	cowboy_req:stream_trailers(#{
		<<"expires">> => <<"Sun, 10 Dec 2017 19:13:47 GMT">>
	}, Req),
	{ok, Req, State}.

