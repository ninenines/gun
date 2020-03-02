%% Copyright (c) 2020, Loïc Hoguin <essen@ninenines.eu>
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

%% @todo A test suite can be created based on https://github.com/web-platform-tests/wpt/tree/master/cookies
-module(gun_cookies).

-export([domain_match/2]).
-export([gc/1]).
-export([path_match/2]).
-export([query/2]).
-export([session_gc/1]).
-export([set_cookie/5]).

-type store_state() :: any().

-type store() :: {module(), store_state()}.
-export_type([store/0]).

-type cookie() :: #{
	name := binary(),
	value := binary(),
	domain := binary(),
	path := binary(),
	creation_time := calendar:datetime(),
	last_access_time := calendar:datetime(),
	expiry_time := calendar:datetime(),
	persistent := boolean(),
	host_only => boolean(),
	secure_only := boolean(),
	http_only := boolean(),
	same_site := strict | lax | none
}.
-export_type([cookie/0]).

-callback init() -> store().

-callback query(State, uri_string:uri_map())
	-> {ok, [{binary(), binary()}], State}
	when State::store_state().

-callback set_cookie_secure_match(store_state(), #{
	name := binary(),
%	secure_only := true,
	domain := binary(),
	path := binary()
}) -> match | nomatch.

-callback set_cookie_exact_match(store_state(), #{
	name := binary(),
	domain := binary(),
	host_only := boolean(),
	path := binary()
}) -> {match, cookie()} | nomatch.

-callback store(State, cookie())
	-> {ok, State} | {error, any()}
	when State::store_state().

-spec domain_match(binary(), binary()) -> boolean().
domain_match(String, String) ->
	true;
domain_match(String, DomainString) ->
	SkipLen = byte_size(String) - byte_size(DomainString) - 1,
	case String of
		<<_:SkipLen/unit:8, $., DomainString/binary>> ->
			case inet:parse_strict_address(binary_to_list(String)) of
				{ok, _} ->
					false;
				{error, einval} ->
					true
			end;
		_ ->
			false
	end.

-spec gc(Store) -> {ok, Store} when Store::store().
gc(Store) ->
%The user agent MUST evict all expired cookies from the cookie store if, at any time, an expired cookie exists in the cookie store.
%At any time, the user agent MAY “remove excess cookies” from the cookie store if the number of cookies sharing a domain field exceeds some implementation-defined upper bound (such as 50 cookies).
%At any time, the user agent MAY “remove excess cookies” from the cookie store if the cookie store exceeds some predetermined upper bound (such as 3000 cookies).
	{todo, Store}.

-spec path_match(binary(), binary()) -> boolean().
path_match(Path, Path) ->
	true;
path_match(ReqPath, CookiePath) ->
	Len = byte_size(CookiePath),
	CookieLast = binary:last(CookiePath),
	case ReqPath of
		<<CookiePath:Len/binary, _/bits>> when CookieLast =:= $/ ->
			true;
		<<CookiePath:Len/binary, $/, _/bits>> ->
			true;
		_ ->
			false
	end.

-ifdef(TEST).
path_match_test_() ->
	Tests = [
		{<<"/">>, <<"/">>, true},
		{<<"/path/to/resource">>, <<"/path/to/resource">>, true},
		{<<"/path/">>, <<"/path/">>, true},
		{<<"/path/to/resource">>, <<"/path/">>, true},
		{<<"/path/to/resource">>, <<"/path">>, true},
		{<<"/path/to/resource">>, <<"/path/to/">>, true},
		{<<"/path/to/resource">>, <<"/path/to">>, true},
		{<<"/path/to/resource">>, <<"/pa">>, false},
		{<<"/path/to/resource">>, <<"/pat">>, false},
		{<<"/path/to/resource">>, <<"/path/to/r">>, false},
		{<<"/abc">>, <<"/def">>, false}
	],
	[{iolist_to_binary(io_lib:format("(~p,~p)", [PA, PB])),
		fun() -> Res = path_match(PA, PB) end}
	|| {PA, PB, Res} <- Tests].
-endif.

%% @todo The given URI must be normalized.
-spec query(Store, uri_string:uri_map())
	-> {ok, [{binary(), binary()}], Store}
	when Store::store().
query({Mod, State0}, URI) ->
	{ok, Cookies0, State} = Mod:query(State0, URI),
	Cookies = lists:sort(fun
		(#{path := P, creation_time := CTA}, #{path := P, creation_time := CTB}) ->
			CTA =< CTB;
		(#{path := PA}, #{path := PB}) ->
			PA > PB
	end, Cookies0),
	{ok, Cookies, {Mod, State}}.

-spec session_gc(Store) -> {ok, Store} when Store::store().
session_gc(Store) ->
%When “the current session is over” (as defined by the user agent), the user agent MUST remove from the cookie store all cookies with the persistent-flag set to false.
	{todo, Store}.

%% @todo Not cookie_opts()
%% @todo The given URI must be normalized.
-spec set_cookie(Store, uri_string:uri_map(), binary(), binary(), cow_cookie:cookie_opts())
	-> {ok, Store} | {error, any()} when Store::store().
set_cookie(Store, URI, Name, Value, Attrs) ->
	%% @todo This is where we would add a feature to block cookies (like a blacklist).
	CurrentTime = erlang:universaltime(),
	Cookie0 = #{
		name => Name,
		value => Value,
		creation_time => CurrentTime,
		last_access_time => CurrentTime
	},
	Cookie = case Attrs of
		#{max_age := ExpiryTime} ->
			Cookie0#{
				persistent => true,
				expiry_time => ExpiryTime
			};
		#{expires := ExpiryTime} ->
			Cookie0#{
				persistent => true,
				expiry_time => ExpiryTime
			};
		_ ->
			Cookie0#{
				persistent => false,
				expiry_time => infinity
			}
	end,
	Domain = maps:get(domain, Attrs, <<>>),
	%% @todo This is where we would reject public suffixes. https://publicsuffix.org/
	case Domain of
		<<>> ->
			set_cookie(Store, URI, Attrs, Cookie#{
				host_only => true,
				domain => maps:get(host, URI)
			});
		_ ->
			%% @todo Domain must already be canonicalized here.
			case domain_match(maps:get(host, URI), Domain) of
				true ->
					set_cookie(Store, URI, Attrs, Cookie#{
						host_only => false,
						domain => Domain
					});
				false ->
					{error, domain_match_failed}
			end
	end.

set_cookie(Store, URI, Attrs, Cookie0) ->
	Cookie1 = case Attrs of
		#{path := Path} ->
			Cookie0#{path => Path};
		_ ->
			Cookie0#{path => default_path(URI)}
	end,
	SecureOnly = maps:get(secure, Attrs, false),
	case {SecureOnly, maps:get(scheme, URI)} of
		{true, <<"http">>} ->
			{error, secure_scheme_only};
		_ ->
			Cookie = Cookie1#{
				secure_only => SecureOnly,
				http_only => maps:get(http_only, Attrs, false)
			},
			%% @todo This is where we would drop cookies from non-HTTP APIs.
			set_cookie1(Store, URI, Attrs, Cookie)
	end.

default_path(#{path := Path}) ->
	case string:split(Path, <<"/">>, trailing) of
		[_] -> <<"/">>;
		[<<>>, _] -> <<"/">>;
		[DefaultPath, _] -> DefaultPath
	end;
default_path(_) ->
	<<"/">>.

set_cookie1(Store, URI=#{scheme := <<"http">>}, Attrs, Cookie=#{secure_only := false}) ->
	Match = maps:with([name, domain, path], Cookie),
	case set_cookie_secure_match(Store, Match) of
		match ->
			{error, secure_cookie_matches};
		nomatch ->
			set_cookie2(Store, URI, Attrs, Cookie)
	end;
set_cookie1(Store, URI, Attrs, Cookie) ->
	set_cookie2(Store, URI, Attrs, Cookie).

set_cookie_secure_match({Mod, State}, Match) ->
	Mod:set_cookie_secure_match(State, Match).

set_cookie2(Store, _URI, Attrs, Cookie0) ->
	Cookie = Cookie0#{same_site => maps:get(same_site, Attrs, none)},
	%% @todo This is where we would perform the same-site checks.
	%%
	%% It seems that an option would need to be added to Gun
	%% in order to define the "site for cookies" value. It is
	%% not the same as the site identified by the URI. Although
	%% I do wonder if in the case of server push we may consider
	%% the requested URI to be the "site for cookies", at least
	%% by default.
	%%
	%% The URI argument will be used if/when the above gets
	%% implemented.
	set_cookie3(Store, Attrs, Cookie).

set_cookie3(Store, Attrs, Cookie=#{name := Name,
		host_only := HostOnly, secure_only := SecureOnly}) ->
	Path = maps:get(path, Attrs, undefined),
	case Name of
		<<"__Secure-",_/bits>> when not SecureOnly ->
			{error, name_prefix_secure_requires_secure_only};
		<<"__Host-",_/bits>> when not SecureOnly ->
			{error, name_prefix_host_requires_secure_only};
		<<"__Host-",_/bits>> when not HostOnly ->
			{error, name_prefix_host_requires_host_only};
		<<"__Host-",_/bits>> when Path =/= <<"/">> ->
			{error, name_prefix_host_requires_top_level_path};
		_ ->
			set_cookie_store(Store, Cookie)
	end.

%% @todo Cookies with an expiry_time in the past result in the cookie getting deleted.
set_cookie_store(Store0, Cookie) ->
	Match = maps:with([name, domain, host_only, path], Cookie),
	case set_cookie_take_exact_match(Store0, Match) of
		{ok, #{creation_time := CreationTime}, Store} ->
			%% @todo This is where we would reject a new non-HTTP cookie
			%% if the OldCookie has http_only set to true.
			store(Store, Cookie#{creation_time => CreationTime});
		error ->
			store(Store0, Cookie)
	end.

set_cookie_take_exact_match({Mod, State0}, Match) ->
	case Mod:set_cookie_take_exact_match(State0, Match) of
		{ok, Cookie, State} ->
			{ok, Cookie, {Mod, State}};
		Error ->
			Error
	end.

store({Mod, State0}, Cookie) ->
	case Mod:store(State0, Cookie) of
		{ok, State} ->
			{ok, {Mod, State}};
		%% @todo Is this return value useful? Can't it just return {ok, State}?
		Error ->
			Error
	end.

-ifdef(TEST).
%% Most of the tests for this module are converted from the
%% Web platform test suite. At the time of writing they could
%% be found at https://github.com/web-platform-tests/wpt/tree/master/cookies
%%
%% Some of the tests use files from wpt directly, namely the
%% http-state ones. They are copied to the test/wpt/cookies directory.
%%
%% @todo Go over all the tests to add expire cases.

-define(HOST, "web-platform.test").

%% WPT: domain/domain-attribute-host-with-and-without-leading-period
%% WPT: domain/domain-attribute-host-with-leading-period
wpt_domain_with_and_without_leading_period_test() ->
	URIMap = #{scheme => <<"http">>, host => <<?HOST>>, path => <<"/path/to/resource">>},
	Store0 = gun_cookies_list:init(),
	%% Add a cookie with a leading period in the domain. Cookie can be retrieved.
	{ok, N0, V0, A0} = cow_cookie:parse_set_cookie(<<"a=b; Path=/; Domain=." ?HOST>>),
	{ok, Store1} = set_cookie(Store0, URIMap, N0, V0, A0),
	{ok, [#{value := <<"b">>}], _} = query(Store1, URIMap),
	{ok, [#{value := <<"b">>}], _} = query(Store1, URIMap#{host => <<"sub." ?HOST>>}),
	%% Add a cookie without a leading period in the domain. Overrides the existing cookie.
	{ok, N1, V1, A1} = cow_cookie:parse_set_cookie(<<"a=c; Path=/; Domain=" ?HOST>>),
	{ok, Store} = set_cookie(Store1, URIMap, N1, V1, A1),
	{ok, [#{value := <<"c">>}], _} = query(Store, URIMap),
	{ok, [#{value := <<"c">>}], _} = query(Store, URIMap#{host => <<"sub." ?HOST>>}),
	ok.

%% WPT: domain/domain-attribute-matches-host
wpt_domain_matches_host_test() ->
	URIMap = #{scheme => <<"http">>, host => <<?HOST>>, path => <<"/path/to/resource">>},
	Store0 = gun_cookies_list:init(),
	%% Add a cookie without a leading period in the domain. Cookie can be retrieved.
	{ok, N1, V1, A1} = cow_cookie:parse_set_cookie(<<"a=c; Path=/; Domain=" ?HOST>>),
	{ok, Store} = set_cookie(Store0, URIMap, N1, V1, A1),
	{ok, [#{value := <<"c">>}], _} = query(Store, URIMap),
	{ok, [#{value := <<"c">>}], _} = query(Store, URIMap#{host => <<"sub." ?HOST>>}),
	ok.

%% WPT: domain/domain-attribute-missing
wpt_domain_missing_test() ->
	URIMap = #{scheme => <<"http">>, host => <<?HOST>>, path => <<"/path/to/resource">>},
	Store0 = gun_cookies_list:init(),
	%% Add a cookie without a domain attribute. Cookie is not sent on subdomains.
	{ok, N1, V1, A1} = cow_cookie:parse_set_cookie(<<"a=c; Path=/">>),
	{ok, Store} = set_cookie(Store0, URIMap, N1, V1, A1),
	{ok, [#{value := <<"c">>}], _} = query(Store, URIMap),
	{ok, [], _} = query(Store, URIMap#{host => <<"sub." ?HOST>>}),
	ok.

%% WPT: http-state/general-tests
%%
%% The WPT http-state test suite is either broken or complicated to setup.
%% The original http-state test suite is a better reference at the time
%% of writing. The server running these tests is at
%% https://github.com/abarth/http-state/blob/master/tools/testserver/testserver.py
wpt_http_state_test_() ->
	URIMap0 = #{scheme => <<"http">>, host => <<"home.example.org">>, path => <<"/cookie-parser">>},
	TestFiles = filelib:wildcard("test/wpt/cookies/*-test") -- [
		"test/wpt/cookies/attribute0023-test", %% Doesn't match the spec (path override).
		"test/wpt/cookies/chromium0009-test", %% Doesn't match the spec (empty names).
		"test/wpt/cookies/chromium0010-test", %% Doesn't match the spec (empty names).
		"test/wpt/cookies/chromium0012-test", %% Doesn't match the spec (empty names).
		"test/wpt/cookies/disabled-chromium0020-test", %% Doesn't match the spec (empty names).
		"test/wpt/cookies/disabled-chromium0022-test", %% Nonsense.
		"test/wpt/cookies/domain0017-test", %% This requires rejecting public suffixes.
		"test/wpt/cookies/mozilla0012-test", %% Doesn't match the spec (empty names).
		"test/wpt/cookies/mozilla0014-test", %% Doesn't match the spec (empty names).
		"test/wpt/cookies/mozilla0015-test", %% Doesn't match the spec (empty names).
		"test/wpt/cookies/mozilla0016-test", %% Doesn't match the spec (empty names).
		"test/wpt/cookies/mozilla0017-test", %% Doesn't match the spec (empty names).
		"test/wpt/cookies/name0017-test", %% Doesn't match the spec (empty names).
		"test/wpt/cookies/name0023-test", %% Doesn't match the spec (empty names).
		"test/wpt/cookies/name0025-test", %% Doesn't match the spec (empty names).
		"test/wpt/cookies/name0028-test", %% Doesn't match the spec (empty names).
		"test/wpt/cookies/name0031-test", %% Doesn't match the spec (name with quotes).
		"test/wpt/cookies/name0032-test", %% Doesn't match the spec (name with quotes).
		"test/wpt/cookies/name0033-test", %% Doesn't match the spec (empty names).
		"test/wpt/cookies/optional-domain0042-test" %% Doesn't match the spec (empty domain override).
	],
	[{F, fun() ->
		{ok, Test} = file:read_file(F),
		%% We don't want the final empty line.
		Lines = lists:reverse(tl(lists:reverse(string:split(Test, <<"\n">>, all)))),
		{Store, URIMap2} = lists:foldl(fun
			(<<"Set-Cookie: ",SetCookie/bits>>, Acc={Store0, URIMap1}) ->
				case cow_cookie:parse_set_cookie(SetCookie) of
					{ok, N, V, A} ->
						%% We use the URIMap that corresponds to the request.
						case set_cookie(Store0, URIMap0, N, V, A) of
							{ok, Store1} -> {Store1, URIMap1};
							{error, _} -> Acc
						end;
					ignore ->
						Acc
				end;
			(<<"Set-Cookie:">>, Acc) ->
				Acc;
			(<<"Location: ",Location/bits>>, {Store0, URIMap1}) ->
				{Store0, maps:merge(URIMap1, uri_string:normalize(Location, [return_map]))}
		end, {gun_cookies_list:init(), URIMap0}, Lines),
		%% We must change the URI if it wasn't already changed by the test.
		URIMap = case URIMap2 of
			URIMap0 -> maps:merge(URIMap0, uri_string:normalize(<<"/cookie-parser-result">>, [return_map]));
			_ -> URIMap2
		end,
		{ok, Cookies, _} = query(Store, URIMap),
		case file:read_file(iolist_to_binary(string:replace(F, <<"-test">>, <<"-expected">>))) of
			{ok, ExpectedFile} when ExpectedFile =:= <<>>; ExpectedFile =:= <<"\n">> ->
				[] = Cookies,
				ok;
			{ok, <<"Cookie: ",CookiesBin0/bits>>} ->
				%% We only care about the first line.
				[CookiesBin, <<>>|_] = string:split(CookiesBin0, <<"\n">>, all),
				ExpectedCookies = cow_cookie:parse_cookie(CookiesBin),
				wpt_http_state_test_validate_cookies(Cookies, ExpectedCookies)
		end
	end} || F <- TestFiles].

wpt_http_state_test_validate_cookies([], []) ->
	ok;
wpt_http_state_test_validate_cookies([Cookie|Tail], [{Name, Value}|ExpectedTail]) ->
	#{name := Name, value := Value} = Cookie,
	wpt_http_state_test_validate_cookies(Tail, ExpectedTail).

%% WPT: path/default
wpt_path_default_test() ->
	URIMap = #{scheme => <<"http">>, host => <<?HOST>>, path => <<"/path/to/resource">>},
	Store0 = gun_cookies_list:init(),
	%% Add a cookie without a path attribute.
	{ok, N1, V1, A1} = cow_cookie:parse_set_cookie(<<"cookies-path-default=1">>),
	{ok, Store} = set_cookie(Store0, URIMap, N1, V1, A1),
	%% Confirm the cookie was stored with the proper default path,
	%% and gets sent for the same path, other resources at the same level or child paths.
	{ok, [#{path := <<"/path/to">>}], _} = query(Store, URIMap),
	{ok, [#{path := <<"/path/to">>}], _} = query(Store, URIMap#{path => <<"/path/to/other">>}),
	{ok, [#{path := <<"/path/to">>}], _} = query(Store, URIMap#{path => <<"/path/to/resource/sub">>}),
	%% Confirm that the cookie cannot be retrieved for parent or unrelated paths.
	{ok, [], _} = query(Store, URIMap#{path => <<"/path">>}),
	{ok, [], _} = query(Store, URIMap#{path => <<"/path/toon">>}),
	{ok, [], _} = query(Store, URIMap#{path => <<"/">>}),
	ok.

%% WPT: path/match
wpt_path_match_test_() ->
	URIMap = #{
		scheme => <<"http">>,
		host => <<?HOST>>,
		path => <<"/cookies/resources/echo-cookie.html">>
	},
	MatchTests = [
		<<"/">>,
		<<"match.html">>,
		<<"cookies">>,
		<<"/cookies">>,
		<<"/cookies/">>,
		<<"/cookies/resources/echo-cookie.html">>
	],
	NegTests = [
		<<"/cook">>,
		<<"/w/">>
	],
	[{P, fun() ->
		{ok, N, V, A} = cow_cookie:parse_set_cookie(<<"a=b; Path=",P/binary>>),
		{ok, Store} = set_cookie(gun_cookies_list:init(), URIMap, N, V, A),
		{ok, [#{name := <<"a">>}], _} = query(Store, URIMap)
	end} || P <- MatchTests]
	++
	[{P, fun() ->
		{ok, N, V, A} = cow_cookie:parse_set_cookie(<<"a=b; Path=",P/binary>>),
		{ok, Store} = set_cookie(gun_cookies_list:init(), URIMap, N, V, A),
		{ok, [], _} = query(Store, URIMap)
	end} || P <- NegTests].

%% WPT: prefix/__host.header
wpt_prefix_host_test_() ->
	Tests = [
		{<<"http">>, <<"__Host-foo=bar; Path=/;">>, false},
		{<<"http">>, <<"__Host-foo=bar; Path=/;domain=" ?HOST>>, false},
		{<<"http">>, <<"__Host-foo=bar; Path=/;Max-Age=10">>, false},
		{<<"http">>, <<"__Host-foo=bar; Path=/;HttpOnly">>, false},
		{<<"http">>, <<"__Host-foo=bar; Secure; Path=/;">>, false},
		{<<"http">>, <<"__Host-foo=bar; Secure; Path=/;domain=" ?HOST>>, false},
		{<<"http">>, <<"__Host-foo=bar; Secure; Path=/;Max-Age=10">>, false},
		{<<"http">>, <<"__Host-foo=bar; Secure; Path=/;HttpOnly">>, false},
		{<<"http">>, <<"__Host-foo=bar; Secure; Path=/; Domain=" ?HOST "; ">>, false},
		{<<"http">>, <<"__Host-foo=bar; Secure; Path=/; Domain=" ?HOST "; domain=" ?HOST>>, false},
		{<<"http">>, <<"__Host-foo=bar; Secure; Path=/; Domain=" ?HOST "; Max-Age=10">>, false},
		{<<"http">>, <<"__Host-foo=bar; Secure; Path=/; Domain=" ?HOST "; HttpOnly">>, false},
		{<<"http">>, <<"__Host-foo=bar; Secure; Path=/cookies/resources/list.py">>, false},
		{<<"https">>, <<"__Host-foo=bar; Path=/;">>, false},
		{<<"https">>, <<"__Host-foo=bar; Path=/;Max-Age=10">>, false},
		{<<"https">>, <<"__Host-foo=bar; Path=/;HttpOnly">>, false},
		{<<"https">>, <<"__Host-foo=bar; Secure; Path=/;">>, true},
		{<<"https">>, <<"__Host-foo=bar; Secure; Path=/;Max-Age=10">>, true},
		{<<"https">>, <<"__Host-foo=bar; Secure; Path=/;HttpOnly">>, true},
		{<<"https">>, <<"__Host-foo=bar; Secure; Path=/; Domain=" ?HOST "; ">>, false},
		{<<"https">>, <<"__Host-foo=bar; Secure; Path=/; Domain=" ?HOST "; Max-Age=10">>, false},
		{<<"https">>, <<"__Host-foo=bar; Secure; Path=/; Domain=" ?HOST "; HttpOnly">>, false},
		{<<"https">>, <<"__Host-foo=bar; Secure; Path=/cookies/resources/list.py">>, false}
	],
	wpt_prefix_common(Tests, <<"__Host-foo">>).

%% WPT: prefix/__secure.header
wpt_prefix_secure_test_() ->
	Tests = [
		{<<"http">>, <<"__Secure-foo=bar; Path=/;">>, false},
		{<<"http">>, <<"__Secure-foo=bar; Path=/;domain=" ?HOST>>, false},
		{<<"http">>, <<"__Secure-foo=bar; Path=/;Max-Age=10">>, false},
		{<<"http">>, <<"__Secure-foo=bar; Path=/;HttpOnly">>, false},
		{<<"http">>, <<"__Secure-foo=bar; Secure; Path=/;">>, false},
		{<<"http">>, <<"__Secure-foo=bar; Secure; Path=/;domain=" ?HOST>>, false},
		{<<"http">>, <<"__Secure-foo=bar; Secure; Path=/;Max-Age=10">>, false},
		{<<"http">>, <<"__Secure-foo=bar; Secure; Path=/;HttpOnly">>, false},
		{<<"https">>, <<"__Secure-foo=bar; Path=/;">>, false},
		{<<"https">>, <<"__Secure-foo=bar; Path=/;Max-Age=10">>, false},
		{<<"https">>, <<"__Secure-foo=bar; Path=/;HttpOnly">>, false},
		{<<"https">>, <<"__Secure-foo=bar; Secure; Path=/;">>, true},
		{<<"https">>, <<"__Secure-foo=bar; Secure; Path=/;Max-Age=10">>, true},
		{<<"https">>, <<"__Secure-foo=bar; Secure; Path=/;HttpOnly">>, true}
		%% @todo Missing two SameSite cases from prefix/__secure.header.https.
	],
	wpt_prefix_common(Tests, <<"__Secure-foo">>).

wpt_prefix_common(Tests, Name) ->
	URIMap0 = #{
		host => <<?HOST>>,
		path => <<"/cookies/resources/set.py">>
	},
	[{<<S/binary," ",H/binary>>, fun() ->
		URIMap1 = URIMap0#{scheme => S},
		{ok, N, V, A} = cow_cookie:parse_set_cookie(H),
		case set_cookie(gun_cookies_list:init(), URIMap1, N, V, A) of
			{ok, Store} when Res =:= true ->
				URIMap = URIMap1#{path => <<"/cookies/resources/list.py">>},
				{ok, [#{name := Name}], _} = query(Store, URIMap),
				ok;
			{error, _} ->
				ok
		end
	end} || {S, H, Res} <- Tests].

%% @todo WPT: samesite-none-secure/
%% @todo WPT: samesite/

wpt_secure_https_test() ->
	URIMap = #{
		scheme => <<"https">>,
		host => <<?HOST>>,
		path => <<"/cookies/secure/any.html">>
	},
	{ok, N, V, A} = cow_cookie:parse_set_cookie(<<"secure_from_secure_http=1; Secure; Path=/">>),
	{ok, Store} = set_cookie(gun_cookies_list:init(), URIMap, N, V, A),
	{ok, [#{name := <<"secure_from_secure_http">>}], _} = query(Store, URIMap),
	ok.

wpt_secure_http_test() ->
	URIMap = #{
		scheme => <<"http">>,
		host => <<?HOST>>,
		path => <<"/cookies/secure/any.html">>
	},
	{ok, N, V, A} = cow_cookie:parse_set_cookie(<<"secure_from_nonsecure_http=1; Secure; Path=/">>),
	{error, secure_scheme_only} = set_cookie(gun_cookies_list:init(), URIMap, N, V, A),
	ok.

%% @todo WPT: secure/set-from-ws* - Anything special required?
-endif.
