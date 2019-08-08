%% Feel free to use, reuse and abuse the code in this file.

-module(delayed_hello_h).

-export([init/2]).

init(Req, Timeout) ->
	timer:sleep(Timeout),
	{ok, cowboy_req:reply(200, #{
		<<"content-type">> => <<"text/plain">>
	}, <<"Hello world!">>, Req), Timeout}.
