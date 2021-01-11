%% Feel free to use, reuse and abuse the code in this file.

-module(pool_ws_handler).

-export([init/4]).
-export([handle/2]).

init(_, _, _, #{user_opts := ReplyTo}) ->
	{ok, ReplyTo}.

handle(Frame, ReplyTo) ->
	ReplyTo ! Frame,
	{ok, 0, ReplyTo}.
