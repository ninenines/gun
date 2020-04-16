%% Feel free to use, reuse and abuse the code in this file.

-module(cookie_informational_h).

-export([init/2]).

init(Req0, State) ->
	cowboy_req:inform(103, #{<<"set-cookie">> => [<<"informational=1">>]}, Req0),
	Req = cowboy_req:reply(204, #{<<"set-cookie">> => [<<"final=1">>]}, Req0),
	{ok, Req, State}.
