%% Feel free to use, reuse and abuse the code in this file.

-module(cookie_set_h).

-export([init/2]).

init(Req0, State) ->
	SetCookieList = set_cookie_list(Req0),
	Req = cowboy_req:set_resp_header(<<"set-cookie">>, SetCookieList, Req0),
	{ok, cowboy_req:reply(204, Req), State}.

-define(HOST, "web-platform.test").

set_cookie_list(#{qs := <<"domain_with_and_without_leading_period">>}) ->
	[
		<<"a=b; Path=/; Domain=." ?HOST>>,
		<<"a=c; Path=/; Domain=" ?HOST>>
	];
set_cookie_list(#{qs := <<"domain_with_leading_period">>}) ->
	[<<"a=b; Path=/; Domain=." ?HOST>>];
set_cookie_list(#{qs := <<"domain_matches_host">>}) ->
	[<<"a=b; Path=/; Domain=" ?HOST>>];
set_cookie_list(#{qs := <<"domain_missing">>}) ->
	[<<"a=b; Path=/;">>];
set_cookie_list(#{qs := <<"path_default">>}) ->
	[<<"cookie-path-default=1">>];
set_cookie_list(#{qs := <<"path_default_expire">>}) ->
	[<<"cookie-path-default=1; Max-Age=0">>];
set_cookie_list(#{qs := <<"path=",Path/bits>>}) ->
	[[<<"a=b; Path=">>, Path]];
set_cookie_list(Req=#{qs := <<"prefix">>}) ->
	[cowboy_req:header(<<"please-set-cookie">>, Req)];
set_cookie_list(#{qs := <<"secure_http">>}) ->
	[<<"secure_from_nonsecure_http=1; Secure; Path=/">>];
set_cookie_list(#{qs := <<"secure_https">>}) ->
	[<<"secure_from_secure_http=1; Secure; Path=/">>].
