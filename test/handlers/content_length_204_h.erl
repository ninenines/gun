%% Feel free to use, reuse and abuse the code in this file.

-module(content_length_204_h).

-export([init/2]).

init(Req0, State) ->
	Req = cowboy_req:reply(204, #{<<"content-length">> => <<"0">>}, <<>>, Req0),
	{ok, Req, State}.
