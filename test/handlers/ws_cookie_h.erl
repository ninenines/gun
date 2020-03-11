%% Feel free to use, reuse and abuse the code in this file.

-module(ws_cookie_h).

-export([init/2]).
-export([websocket_handle/2]).
-export([websocket_info/2]).

init(Req0, _) ->
	Req = cowboy_req:set_resp_header(<<"set-cookie">>,
		[<<"ws_cookie=1; Secure; path=/">>], Req0),
	{cowboy_websocket, Req, undefined, #{
		compress => true
	}}.

websocket_handle({text, Data}, State) ->
	{[{text, Data}], State};
websocket_handle({binary, Data}, State) ->
	{[{binary, Data}], State};
websocket_handle(_Frame, State) ->
	{[], State}.

websocket_info(_Info, State) ->
	{[], State}.
