%% Feel free to use, reuse and abuse the code in this file.

-module(proxied_h).

-export([init/2]).

init(Req, State) ->
	{ok, cowboy_req:reply(200,
		#{<<"content-type">> => <<"text/plain">>},
		<<"TODO">>,
		Req), State}.
