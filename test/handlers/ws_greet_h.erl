%% Feel free to use, reuse and abuse the code in this file.

-module(ws_greet_h).

-export([init/2]).
-export([websocket_init/1]).
-export([websocket_handle/2]).
-export([websocket_info/2]).

init(Req, _) ->
	{cowboy_websocket, Req, undefined}.

websocket_init(State) ->
	{[{text, <<"hi">>}], State}.

websocket_handle(_, State) ->
	{[], State}.

websocket_info(_, State) ->
	{[], State}.
