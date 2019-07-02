%% Feel free to use, reuse and abuse the code in this file.

-module(inform_h).

-export([init/2]).

init(Req, State) ->
	cowboy_req:inform(103, #{
		<<"content-type">> => <<"text/plain">>
	}, Req),
	cowboy_req:inform(103, #{
		<<"content-type">> => <<"text/plain">>
	}, Req),
	{ok, cowboy_req:reply(200, #{
		<<"content-type">> => <<"text/plain">>
	}, <<"Hello world!">>, Req), State}.
