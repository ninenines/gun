%% Feel free to use, reuse and abuse the code in this file.

-module(delayed_push_h).

-export([init/2]).

init(Req, Timeout) ->
	timer:sleep(Timeout),
	cowboy_req:push("/", #{<<"accept">> => <<"text/plain">>}, Req),
	cowboy_req:push("/empty", #{<<"accept">> => <<"text/plain">>}, Req),
	{ok, cowboy_req:reply(200, #{
		<<"content-type">> => <<"text/plain">>
	}, <<"Hello world!">>, Req), Timeout}.
