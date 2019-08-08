%% Feel free to use, reuse and abuse the code in this file.

-module(ws_frozen_h).

-export([init/2]).
-export([websocket_init/1]).
-export([websocket_handle/2]).
-export([websocket_info/2]).

init(Req, State) ->
	{cowboy_websocket, Req, State, #{
		compress => true
	}}.

websocket_init(Timeout) ->
	timer:sleep(Timeout),
	{ok, undefined}.

websocket_handle(_Frame, State) ->
	{[], State}.

websocket_info(_Info, State) ->
	{[], State}.
