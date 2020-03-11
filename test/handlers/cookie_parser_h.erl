%% Feel free to use, reuse and abuse the code in this file.

-module(cookie_parser_h).

-export([init/2]).

init(Req0=#{qs := Qs}, State) ->
	%% Hardcoded path, but I doubt it's going to break anytime soon.
	TestFile = iolist_to_binary(["../../test/wpt/cookies/", Qs, "-test"]),
	{ok, Test} = file:read_file(TestFile),
	%% We don't want the final empty line.
	Lines = lists:reverse(tl(lists:reverse(string:split(Test, <<"\n">>, all)))),
	Req = lists:foldl(fun
		(<<"Set-Cookie: ",SetCookie/bits>>, Req1) ->
			%% We do not use set_resp_cookie because we want to preserve ordering.
			SetCookieList = cowboy_req:resp_header(<<"set-cookie">>, Req1, []),
			cowboy_req:set_resp_header(<<"set-cookie">>, SetCookieList ++ [SetCookie], Req1);
		(<<"Set-Cookie:">>, Req1) ->
			Req1;
		(<<"Location: ",Location/bits>>, Req1) ->
			cowboy_req:set_resp_header(<<"location">>, Location, Req1)
	end, Req0, Lines),
	{ok, cowboy_req:reply(204, Req), State}.
