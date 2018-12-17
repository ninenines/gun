%% This handler rejects all Websocket connections.
-module(ws_reject_h).

-export([init/2]).

init(Req0, Env) ->
    {ok, cowboy_req:reply(400, #{}, <<"Upgrade rejected">>, Req0), Env}.
