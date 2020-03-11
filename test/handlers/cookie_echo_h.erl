%% Feel free to use, reuse and abuse the code in this file.

-module(cookie_echo_h).

-export([init/2]).

init(Req, State) ->
	{ok, cowboy_req:reply(200,
		#{<<"content-type">> => <<"text/plain">>},
		cowboy_req:header(<<"cookie">>, Req, <<"UNDEF">>),
		Req), State}.
