%% This module implements a loop handler that sends
%% a lone id: line.

-module(sse_mime_param_h).

-export([init/2]).
-export([info/3]).

init(Req, State) ->
	self() ! timeout,
	{cowboy_loop, cowboy_req:stream_reply(200, #{
		<<"content-type">> => <<"text/event-stream;encoding=UTF-8">>
	}, Req), State}.

info(timeout, Req, State) ->
	cowboy_req:stream_events(#{
		id => <<"hello">>
	}, nofin, Req),
	{stop, Req, State}.
