%% Feel free to use, reuse and abuse the code in this file.

-module(cookie_parser_result_h).

-export([init/2]).

init(Req=#{qs := Qs}, State) ->
	%% Hardcoded path, but I doubt it's going to break anytime soon.
	ExpectedFile = iolist_to_binary(["../../test/wpt/cookies/", Qs, "-expected"]),
	CookieHd = cowboy_req:header(<<"cookie">>, Req),
	case file:read_file(ExpectedFile) of
		{ok, Expected} when Expected =:= <<>>; Expected =:= <<"\n">> ->
			undefined = CookieHd,
			ok;
		{ok, <<"Cookie: ",CookiesBin0/bits>>} ->
			%% We only care about the first line.
			[CookiesBin, <<>>|_] = string:split(CookiesBin0, <<"\n">>, all),
			CookiesBin = CookieHd,
			ok
	end,
	%% We echo back the cookie header in order to log it.
	{ok, cowboy_req:reply(204, case CookieHd of
		undefined -> #{<<"x-no-cookie-received">> => <<"Cookie header missing.">>};
		_ -> #{<<"x-cookie-received">> => CookieHd}
	end, Req), State}.
