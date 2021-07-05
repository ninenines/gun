%% This module implements a loop handler that sends
%% the current time every second using SSE. In contrast
%% to sse_clock_h, this one sends a "Connection: close"
%% header.

-module(sse_clock_close_h).

-export([init/2]).
-export([info/3]).

init(Req, State) ->
	self() ! timeout,
	{cowboy_loop, cowboy_req:stream_reply(200, #{
		<<"content-type">> => <<"text/event-stream">>,
		<<"connection">> => <<"close">>
	}, Req), State}.

info(timeout, Req, State) ->
	erlang:send_after(1000, self(), timeout),
	cowboy_req:stream_events(#{
		data => cowboy_clock:rfc1123()
	}, nofin, Req),
	{ok, Req, State}.
