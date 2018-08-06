%% This module implements a loop handler that sends
%% the current time every second using SSE.

-module(sse_clock_h).

-export([init/2]).
-export([info/3]).

init(Req, State) ->
	self() ! timeout,
	{cowboy_loop, cowboy_req:stream_reply(200, #{
		<<"content-type">> => <<"text/event-stream">>
	}, Req), State}.

info(timeout, Req, State) ->
	erlang:send_after(1000, self(), timeout),
	Time = calendar:system_time_to_rfc3339(erlang:system_time(second)),
	cowboy_req:stream_events(#{
		data => Time
	}, nofin, Req),
	{ok, Req, State}.
