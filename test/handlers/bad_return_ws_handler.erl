%% Feel free to use, reuse and abuse the code in this file.

-module(bad_return_ws_handler).

-export([init/4]).
-export([handle/2]).

init(_, _, _, _) ->
	bad.

handle(_, State) ->
	{ok, 0, State}.
