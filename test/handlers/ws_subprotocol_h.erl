%% Feel free to use, reuse and abuse the code in this file.

-module(ws_subprotocol_h).

-export([init/2]).
-export([websocket_handle/2]).
-export([websocket_info/2]).

init(Req, State) ->
	Protos = cowboy_req:parse_header(<<"sec-websocket-protocol">>, Req),
	init_protos(Req, State, Protos).

init_protos(Req, State, undefined) ->
	{ok, cowboy_req:reply(400, #{}, <<"undefined">>, Req), State};
init_protos(Req, State, []) ->
	{ok, cowboy_req:reply(400, #{}, <<"nomatch">>, Req), State};
init_protos(Req0, State, [<<"echo">> | _]) ->
	Req = cowboy_req:set_resp_header(<<"sec-websocket-protocol">>, <<"echo">>, Req0),
	{cowboy_websocket, Req, State};
init_protos(Req, State, [_ | Protos]) ->
	init_protos(Req, State, Protos).

websocket_handle({text, Data}, State) ->
	{[{text, Data}], State};
websocket_handle({binary, Data}, State) ->
	{[{binary, Data}], State};
websocket_handle(_Frame, State) ->
	{[], State}.

websocket_info(_Info, State) ->
	{[], State}.
