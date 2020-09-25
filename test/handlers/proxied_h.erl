%% Feel free to use, reuse and abuse the code in this file.

-module(proxied_h).

-export([init/2]).

-spec init(cowboy_req:req(), _) -> no_return().
init(Req, _) ->
	_ = cowboy_req:stream_reply(200, #{<<"content-type">> => <<"text/plain">>}, Req),
	%% We never return to allow querying the stream_info.
	receive after infinity -> ok end.
