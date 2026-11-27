%% One Server-Sent Events event larger than the default limit.

-module(sse_large_h).

-export([init/2]).

init(Req0, _Opts) ->
	Body = <<"data: ", (binary:copy(<<$x>>, 12000))/binary, "\n\n">>,
	Req = cowboy_req:stream_reply(200, #{
		<<"content-type">> => <<"text/event-stream">>
	}, Req0),
	ok = cowboy_req:stream_body(Body, fin, Req),
	{ok, Req, []}.
