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

-module(rfc6265bis_SUITE).
-compile(export_all).
-compile(nowarn_export_all).

-import(ct_helper, [config/2]).
-import(ct_helper, [doc/1]).

%% ct.

all() ->
	[
		{group, http},
		{group, https},
		{group, h2c},
		{group, h2}
	].

groups() ->
	CommonTests = ct_helper:all(?MODULE) -- [wpt_http_state],
	NumFiles = length(get_test_files()),
	NumDisabledTlsFiles = length(get_disabled_tls_test_files()),
	[
		{http, [parallel], CommonTests
			++ [{testcase, wpt_http_state, [{repeat, NumFiles}]}]},
		{https, [parallel], CommonTests
			++ [{testcase, wpt_http_state, [{repeat, NumFiles - NumDisabledTlsFiles}]}]},
		%% Websocket over HTTP/2 is currently not supported.
		{h2c, [parallel], (CommonTests -- [wpt_secure_ws])
			++ [{testcase, wpt_http_state, [{repeat, NumFiles}]}]},
		{h2, [parallel], (CommonTests -- [wpt_secure_ws])
			++ [{testcase, wpt_http_state, [{repeat, NumFiles - NumDisabledTlsFiles}]}]}
	].

init_per_group(Ref, Config0) when Ref =:= http; Ref =:= h2c ->
	Protocol = case Ref of
		http -> http;
		h2c -> http2
	end,
	Config = gun_test:init_cowboy_tcp(Ref, #{
		env => #{dispatch => cowboy_router:compile(init_routes())}
	}, Config0),
	init_per_group_common([{transport, tcp}, {protocol, Protocol}|Config]);
init_per_group(Ref, Config0) when Ref =:= https; Ref =:= h2 ->
	Protocol = case Ref of
		https -> http;
		h2 -> http2
	end,
	Config = gun_test:init_cowboy_tls(Ref, #{
		env => #{dispatch => cowboy_router:compile(init_routes())}
	}, Config0),
	init_per_group_common([{transport, tls}, {protocol, Protocol}|Config]).

init_per_group_common(Config = [{transport, Transport}|_]) ->
	GiverPid = spawn(fun() -> do_test_giver_init(Transport) end),
	[{test_giver_pid, GiverPid}|Config].

end_per_group(Ref, _) ->
	cowboy:stop_listener(Ref).

init_routes() -> [
	{'_', [
		{"/cookie-echo/[...]", cookie_echo_h, []},
		{"/cookie-parser/[...]", cookie_parser_h, []},
		{"/cookie-parser-result/[...]", cookie_parser_result_h, []},
		{"/cookie-set/[...]", cookie_set_h, []},
		{"/cookies/resources/echo-cookie.html", cookie_echo_h, []},
		{"/cookies/resources/set-cookie.html", cookie_set_h, []},
		{"/cookies/resources/echo.py", cookie_echo_h, []},
		{"/cookies/resources/set.py", cookie_set_h, []},
		{"/informational", cookie_informational_h, []},
		{"/ws", ws_cookie_h, []}
	]}
].

%% Test files.

get_test_files() ->
	%% Hardcoded path, but I doubt it's going to break anytime soon.
	gun_cookies:wpt_http_state_test_files("../../test/").

get_disabled_tls_test_files() ->
	%% These tests include the Secure attribute and are written for
	%% clear text. They must therefore be disabled over TLS.
	[
		"../../test/wpt/cookies/0010-test",
		"../../test/wpt/cookies/attribute0001-test",
		"../../test/wpt/cookies/attribute0002-test",
		"../../test/wpt/cookies/attribute0004-test",
		"../../test/wpt/cookies/attribute0005-test",
		"../../test/wpt/cookies/attribute0007-test",
		"../../test/wpt/cookies/attribute0008-test",
		"../../test/wpt/cookies/attribute0009-test",
		"../../test/wpt/cookies/attribute0010-test",
		"../../test/wpt/cookies/attribute0011-test",
		"../../test/wpt/cookies/attribute0012-test",
		"../../test/wpt/cookies/attribute0013-test",
		"../../test/wpt/cookies/attribute0025-test",
		"../../test/wpt/cookies/attribute0026-test"
	].

do_test_giver_init(Transport) ->
	TestFiles0 = get_test_files(),
	TestFiles = case Transport of
		tcp -> TestFiles0;
		tls -> TestFiles0 -- get_disabled_tls_test_files()
	end,
	do_test_giver_loop(TestFiles).

do_test_giver_loop([]) ->
	ok;
do_test_giver_loop([TestFile|Tail]) ->
	receive
		{request_test_file, FromPid, FromRef} ->
			FromPid ! {FromRef, TestFile},
			do_test_giver_loop(Tail)
	end.

do_request_test_file(Config) ->
	Ref = make_ref(),
	GiverPid = config(test_giver_pid, Config),
	GiverPid ! {request_test_file, self(), Ref},
	receive
		{Ref, TestFile} ->
			TestFile
	after 1000 ->
		error(timeout)
	end.

%% Tests.

dont_ignore_informational_set_cookie(Config) ->
	doc("User agents may accept set-cookie headers "
		"sent in informational responses. (RFC6265bis 3)"),
	[{<<"informational">>, <<"1">>}, {<<"final">>, <<"1">>}]
		= do_informational_set_cookie(Config, false).

ignore_informational_set_cookie(Config) ->
	doc("User agents may ignore set-cookie headers "
		"sent in informational responses. (RFC6265bis 3)"),
	[{<<"final">>, <<"1">>}]
		= do_informational_set_cookie(Config, true).

do_informational_set_cookie(Config, Boolean) ->
	Protocol = config(protocol, Config),
	{ok, ConnPid} = gun:open("localhost", config(port, Config), #{
		transport => config(transport, Config),
		protocols => [{Protocol, #{cookie_ignore_informational => Boolean}}],
		cookie_store => gun_cookies_list:init()
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	StreamRef1 = gun:get(ConnPid, "/informational"),
	{inform, 103, Headers1} = gun:await(ConnPid, StreamRef1),
	ct:log("Headers1:~n~p", [Headers1]),
	{response, fin, 204, Headers2} = gun:await(ConnPid, StreamRef1),
	ct:log("Headers2:~n~p", [Headers2]),
	StreamRef2 = gun:get(ConnPid, "/cookie-echo"),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef2),
	{ok, Body2} = gun:await_body(ConnPid, StreamRef2),
	ct:log("Body2:~n~p", [Body2]),
	Res = cow_cookie:parse_cookie(Body2),
	gun:close(ConnPid),
	Res.

set_cookie_connect_tcp(Config) ->
	doc("Cookies may also be set in responses going through CONNECT tunnels."),
	Transport = config(transport, Config),
	Protocol = config(protocol, Config),
	{ok, ProxyPid, ProxyPort} = event_SUITE:do_proxy_start(Protocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		transport => tcp,
		protocols => [Protocol],
		cookie_store => gun_cookies_list:init()
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(Protocol, ProxyPid),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => config(port, Config),
		transport => Transport,
		protocols => [Protocol]
	}),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{up, Protocol} = gun:await(ConnPid, StreamRef1),
	StreamRef2 = gun:get(ConnPid, "/cookie-set?prefix", #{
		<<"please-set-cookie">> => <<"a=b">>
	}, #{tunnel => StreamRef1}),
	{response, fin, 204, Headers2} = gun:await(ConnPid, StreamRef2),
	ct:log("Headers2:~n~p", [Headers2]),
	StreamRef3 = gun:get(ConnPid, "/cookie-echo", [], #{tunnel => StreamRef1}),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef3),
	{ok, Body3} = gun:await_body(ConnPid, StreamRef3),
	ct:log("Body3:~n~p", [Body3]),
	[{<<"a">>, <<"b">>}] = cow_cookie:parse_cookie(Body3),
	gun:close(ConnPid).

set_cookie_connect_tls(Config) ->
	doc("Cookies may also be set in responses going through CONNECT tunnels."),
	Transport = config(transport, Config),
	Protocol = config(protocol, Config),
	{ok, ProxyPid, ProxyPort} = event_SUITE:do_proxy_start(Protocol, tls),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		transport => tls,
		protocols => [Protocol],
		cookie_store => gun_cookies_list:init()
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(Protocol, ProxyPid),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => config(port, Config),
		transport => Transport,
		protocols => [Protocol]
	}),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{up, Protocol} = gun:await(ConnPid, StreamRef1),
	StreamRef2 = gun:get(ConnPid, "/cookie-set?prefix", #{
		<<"please-set-cookie">> => <<"a=b">>
	}, #{tunnel => StreamRef1}),
	{response, fin, 204, Headers2} = gun:await(ConnPid, StreamRef2),
	ct:log("Headers2:~n~p", [Headers2]),
	StreamRef3 = gun:get(ConnPid, "/cookie-echo", [], #{tunnel => StreamRef1}),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef3),
	{ok, Body3} = gun:await_body(ConnPid, StreamRef3),
	ct:log("Body3:~n~p", [Body3]),
	[{<<"a">>, <<"b">>}] = cow_cookie:parse_cookie(Body3),
	gun:close(ConnPid).

-define(HOST, "web-platform.test").

%% WPT: domain/domain-attribute-host-with-and-without-leading-period
wpt_domain_with_and_without_leading_period(Config) ->
	doc("Domain with and without leading period."),
	#{
		same_origin := [{<<"a">>, <<"c">>}],
		subdomain := [{<<"a">>, <<"c">>}]
	} = do_domain_test(Config, "domain_with_and_without_leading_period"),
	ok.

%% WPT: domain/domain-attribute-host-with-leading-period
wpt_domain_with_leading_period(Config) ->
	doc("Domain with leading period."),
	#{
		same_origin := [{<<"a">>, <<"b">>}],
		subdomain := [{<<"a">>, <<"b">>}]
	} = do_domain_test(Config, "domain_with_leading_period"),
	ok.

%% WPT: domain/domain-attribute-matches-host
wpt_domain_matches_host(Config) ->
	doc("Domain matches host header."),
	#{
		same_origin := [{<<"a">>, <<"b">>}],
		subdomain := [{<<"a">>, <<"b">>}]
	} = do_domain_test(Config, "domain_matches_host"),
	ok.

%% WPT: domain/domain-attribute-missing
wpt_domain_missing(Config) ->
	doc("Domain attribute missing."),
	#{
		same_origin := [{<<"a">>, <<"b">>}],
		subdomain := undefined
	} = do_domain_test(Config, "domain_missing"),
	ok.

do_domain_test(Config, TestCase) ->
	Protocol = config(protocol, Config),
	{ok, ConnPid} = gun:open("localhost", config(port, Config), #{
		transport => config(transport, Config),
		protocols => [Protocol],
		cookie_store => gun_cookies_list:init()
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	StreamRef1 = gun:get(ConnPid, ["/cookie-set?", TestCase], #{<<"host">> => ?HOST}),
	{response, fin, 204, Headers1} = gun:await(ConnPid, StreamRef1),
	ct:log("Headers1:~n~p", [Headers1]),
	StreamRef2 = gun:get(ConnPid, "/cookie-echo", #{<<"host">> => ?HOST}),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef2),
	{ok, Body2} = gun:await_body(ConnPid, StreamRef2),
	ct:log("Body2:~n~p", [Body2]),
	StreamRef3 = gun:get(ConnPid, "/cookie-echo", #{<<"host">> => "sub." ?HOST}),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef3),
	{ok, Body3} = gun:await_body(ConnPid, StreamRef3),
	ct:log("Body3:~n~p", [Body3]),
	gun:close(ConnPid),
	#{
		same_origin => case Body2 of <<"UNDEF">> -> undefined; _ -> cow_cookie:parse_cookie(Body2) end,
		subdomain => case Body3 of <<"UNDEF">> -> undefined; _ -> cow_cookie:parse_cookie(Body3) end
	}.

%% WPT: http-state/*-tests
wpt_http_state(Config) ->
	TestFile = do_request_test_file(Config),
	Test = string:replace(filename:basename(TestFile), "-test", ""),
	doc("http-state: " ++ Test),
	ct:log("Test file:~n~s", [element(2, file:read_file(TestFile))]),
	ct:log("Expected file:~n~s", [element(2, file:read_file(string:replace(TestFile, "-test", "-expected")))]),
	Protocol = config(protocol, Config),
	{ok, ConnPid} = gun:open("localhost", config(port, Config), #{
		transport => config(transport, Config),
		protocols => [Protocol],
		cookie_store => gun_cookies_list:init()
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	StreamRef1 = gun:get(ConnPid, "/cookie-parser?" ++ Test, #{<<"host">> => "home.example.org"}),
	{response, fin, 204, Headers1} = gun:await(ConnPid, StreamRef1),
	ct:log("Headers1:~n~p", [Headers1]),
	{Host, Path} = case lists:keyfind(<<"location">>, 1, Headers1) of
		false ->
			{"home.example.org", "/cookie-parser-result?" ++ Test};
		{_, Location} ->
			case uri_string:parse(Location) of
				#{host := Host0, path := Path0, query := Qs0} ->
					{Host0, [Path0, $?, Qs0]};
				#{path := Path0, query := Qs0} ->
					{"home.example.org", [Path0, $?, Qs0]}
			end
	end,
	StreamRef2 = gun:get(ConnPid, Path, #{<<"host">> => Host}),
	%% The validation is done in the handler. An error results in a 4xx or 5xx.
	{response, fin, 204, Headers2} = gun:await(ConnPid, StreamRef2),
	ct:log("Headers2:~n~p", [Headers2]),
	gun:close(ConnPid).

%% WPT: path/default
wpt_path_default(Config) ->
	doc("Cookie set on the default path can be retrieved."),
	Protocol = config(protocol, Config),
	{ok, ConnPid} = gun:open("localhost", config(port, Config), #{
		transport => config(transport, Config),
		protocols => [Protocol],
		cookie_store => gun_cookies_list:init()
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	%% Set and retrieve the cookie.
	StreamRef1 = gun:get(ConnPid, "/cookie-set?path_default"),
	{response, fin, 204, Headers1} = gun:await(ConnPid, StreamRef1),
	ct:log("Headers1:~n~p", [Headers1]),
	StreamRef2 = gun:get(ConnPid, "/cookie-echo"),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef2),
	{ok, Body2} = gun:await_body(ConnPid, StreamRef2),
	ct:log("Body2:~n~p", [Body2]),
	[{<<"cookie-path-default">>, <<"1">>}] = cow_cookie:parse_cookie(Body2),
	%% Expire the cookie.
	StreamRef3 = gun:get(ConnPid, "/cookie-set?path_default_expire"),
	{response, fin, 204, Headers3} = gun:await(ConnPid, StreamRef3),
	ct:log("Headers3:~n~p", [Headers3]),
	StreamRef4 = gun:get(ConnPid, "/cookie-echo"),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef4),
	{ok, Body4} = gun:await_body(ConnPid, StreamRef4),
	ct:log("Body4:~n~p", [Body4]),
	<<"UNDEF">> = Body4,
	gun:close(ConnPid).

%% WPT: path/match
wpt_path_match(Config) ->
	doc("Cookie path match."),
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
	Protocol = config(protocol, Config),
	 _ = [begin
		ct:log("Positive test: ~s", [P]),
		{ok, ConnPid} = gun:open("localhost", config(port, Config), #{
			transport => config(transport, Config),
			protocols => [Protocol],
			cookie_store => gun_cookies_list:init()
		}),
		{ok, Protocol} = gun:await_up(ConnPid),
		%% Set and retrieve the cookie.
		StreamRef1 = gun:get(ConnPid, ["/cookies/resources/set-cookie.html?path=", P]),
		{response, fin, 204, Headers1} = gun:await(ConnPid, StreamRef1),
		ct:log("Headers1:~n~p", [Headers1]),
		StreamRef2 = gun:get(ConnPid, "/cookies/resources/echo-cookie.html"),
		{response, nofin, 200, _} = gun:await(ConnPid, StreamRef2),
		{ok, Body2} = gun:await_body(ConnPid, StreamRef2),
		ct:log("Body2:~n~p", [Body2]),
		[{<<"a">>, <<"b">>}] = cow_cookie:parse_cookie(Body2),
		gun:close(ConnPid)
	end || P <- MatchTests],
	_ = [begin
		ct:log("Negative test: ~s", [P]),
		{ok, ConnPid} = gun:open("localhost", config(port, Config), #{
			transport => config(transport, Config),
			protocols => [Protocol],
			cookie_store => gun_cookies_list:init()
		}),
		{ok, Protocol} = gun:await_up(ConnPid),
		%% Set and retrieve the cookie.
		StreamRef1 = gun:get(ConnPid, ["/cookies/resources/set-cookie.html?path=", P]),
		{response, fin, 204, Headers1} = gun:await(ConnPid, StreamRef1),
		ct:log("Headers1:~n~p", [Headers1]),
		StreamRef2 = gun:get(ConnPid, "/cookies/resources/echo-cookie.html"),
		{response, nofin, 200, _} = gun:await(ConnPid, StreamRef2),
		{ok, Body2} = gun:await_body(ConnPid, StreamRef2),
		ct:log("Body2:~n~p", [Body2]),
		<<"UNDEF">> = Body2,
		gun:close(ConnPid)
	end || P <- NegTests],
	ok.

%% WPT: prefix/__host.header
wpt_prefix_host(Config) ->
	doc("__Host- prefix."),
	Tests = case config(transport, Config) of
		tcp -> [
			{<<"__Host-foo=bar; Path=/;">>, false},
			{<<"__Host-foo=bar; Path=/;domain=" ?HOST>>, false},
			{<<"__Host-foo=bar; Path=/;Max-Age=10">>, false},
			{<<"__Host-foo=bar; Path=/;HttpOnly">>, false},
			{<<"__Host-foo=bar; Secure; Path=/;">>, false},
			{<<"__Host-foo=bar; Secure; Path=/;domain=" ?HOST>>, false},
			{<<"__Host-foo=bar; Secure; Path=/;Max-Age=10">>, false},
			{<<"__Host-foo=bar; Secure; Path=/;HttpOnly">>, false},
			{<<"__Host-foo=bar; Secure; Path=/; Domain=" ?HOST "; ">>, false},
			{<<"__Host-foo=bar; Secure; Path=/; Domain=" ?HOST "; domain=" ?HOST>>, false},
			{<<"__Host-foo=bar; Secure; Path=/; Domain=" ?HOST "; Max-Age=10">>, false},
			{<<"__Host-foo=bar; Secure; Path=/; Domain=" ?HOST "; HttpOnly">>, false},
			{<<"__Host-foo=bar; Secure; Path=/cookies/resources/list.py">>, false}
		];
		tls -> [
			{<<"__Host-foo=bar; Path=/;">>, false},
			{<<"__Host-foo=bar; Path=/;Max-Age=10">>, false},
			{<<"__Host-foo=bar; Path=/;HttpOnly">>, false},
			{<<"__Host-foo=bar; Secure; Path=/;">>, true},
			{<<"__Host-foo=bar; Secure; Path=/;Max-Age=10">>, true},
			{<<"__Host-foo=bar; Secure; Path=/;HttpOnly">>, true},
			{<<"__Host-foo=bar; Secure; Path=/; Domain=" ?HOST "; ">>, false},
			{<<"__Host-foo=bar; Secure; Path=/; Domain=" ?HOST "; Max-Age=10">>, false},
			{<<"__Host-foo=bar; Secure; Path=/; Domain=" ?HOST "; HttpOnly">>, false},
			{<<"__Host-foo=bar; Secure; Path=/cookies/resources/list.py">>, false}
		]
	end,
	_ = [do_wpt_prefix_common(Config, TestCase, Expected, <<"__Host-foo">>)
		|| {TestCase, Expected} <- Tests],
	ok.

%% WPT: prefix/__secure.header
wpt_prefix_secure(Config) ->
	doc("__Secure- prefix."),
	Tests = case config(transport, Config) of
		tcp -> [
			{<<"__Secure-foo=bar; Path=/;">>, false},
			{<<"__Secure-foo=bar; Path=/;domain=" ?HOST>>, false},
			{<<"__Secure-foo=bar; Path=/;Max-Age=10">>, false},
			{<<"__Secure-foo=bar; Path=/;HttpOnly">>, false},
			{<<"__Secure-foo=bar; Secure; Path=/;">>, false},
			{<<"__Secure-foo=bar; Secure; Path=/;domain=" ?HOST>>, false},
			{<<"__Secure-foo=bar; Secure; Path=/;Max-Age=10">>, false},
			{<<"__Secure-foo=bar; Secure; Path=/;HttpOnly">>, false}
		];
		tls -> [
			{<<"__Secure-foo=bar; Path=/;">>, false},
			{<<"__Secure-foo=bar; Path=/;Max-Age=10">>, false},
			{<<"__Secure-foo=bar; Path=/;HttpOnly">>, false},
			{<<"__Secure-foo=bar; Secure; Path=/;">>, true},
			{<<"__Secure-foo=bar; Secure; Path=/;Max-Age=10">>, true},
			{<<"__Secure-foo=bar; Secure; Path=/;HttpOnly">>, true}
			%% Missing two SameSite cases from prefix/__secure.header.https. (Not implemented.)
		]
	end,
	_ = [do_wpt_prefix_common(Config, TestCase, Expected, <<"__Secure-foo">>)
		|| {TestCase, Expected} <- Tests],
	ok.

do_wpt_prefix_common(Config, TestCase, Expected, Name) ->
	Protocol = config(protocol, Config),
	ct:log("Test case: ~s~nCookie must be set? ~s", [TestCase, Expected]),
	{ok, ConnPid} = gun:open("localhost", config(port, Config), #{
		transport => config(transport, Config),
		protocols => [Protocol],
		cookie_store => gun_cookies_list:init()
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	%% Set and retrieve the cookie.
	StreamRef1 = gun:get(ConnPid, "/cookies/resources/set.py?prefix", #{
		<<"host">> => ?HOST,
		<<"please-set-cookie">> => TestCase
	}),
	{response, fin, 204, Headers1} = gun:await(ConnPid, StreamRef1),
	ct:log("Headers1:~n~p", [Headers1]),
	StreamRef2 = gun:get(ConnPid, "/cookies/resources/echo.py", #{
		<<"host">> => ?HOST
	}),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef2),
	{ok, Body2} = gun:await_body(ConnPid, StreamRef2),
	ct:log("Body2:~n~p", [Body2]),
	case Expected of
		true ->
			[{Name, _}] = cow_cookie:parse_cookie(Body2),
			ok;
		false ->
			<<"UNDEF">> = Body2,
			ok
	end,
	gun:close(ConnPid).

%% WPT: samesite-none-secure/ (Not implemented.)
%% WPT: samesite/ (Not implemented.)

wpt_secure(Config) ->
	doc("Secure attribute."),
	case config(transport, Config) of
		tcp ->
			undefined = do_wpt_secure_common(Config, <<"secure_http">>),
			ok;
		tls ->
			[{<<"secure_from_secure_http">>, <<"1">>}] = do_wpt_secure_common(Config, <<"secure_https">>),
			ok
	end.

do_wpt_secure_common(Config, TestCase) ->
	Protocol = config(protocol, Config),
	{ok, ConnPid} = gun:open("localhost", config(port, Config), #{
		transport => config(transport, Config),
		protocols => [Protocol],
		cookie_store => gun_cookies_list:init()
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	StreamRef1 = gun:get(ConnPid, ["/cookie-set?", TestCase]),
	{response, fin, 204, Headers1} = gun:await(ConnPid, StreamRef1),
	ct:log("Headers1:~n~p", [Headers1]),
	StreamRef2 = gun:get(ConnPid, "/cookie-echo"),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef2),
	{ok, Body2} = gun:await_body(ConnPid, StreamRef2),
	ct:log("Body2:~n~p", [Body2]),
	gun:close(ConnPid),
	case Body2 of
		<<"UNDEF">> -> undefined;
		_ -> cow_cookie:parse_cookie(Body2)
	end.

%% WPT: secure/set-from-ws*
wpt_secure_ws(Config) ->
	doc("Secure attribute in Websocket upgrade response."),
	case config(transport, Config) of
		tcp ->
			undefined = do_wpt_secure_ws_common(Config),
			ok;
		tls ->
			[{<<"ws_cookie">>, <<"1">>}] = do_wpt_secure_ws_common(Config),
			ok
	end.

do_wpt_secure_ws_common(Config) ->
	Protocol = config(protocol, Config),
	{ok, ConnPid1} = gun:open("localhost", config(port, Config), #{
		transport => config(transport, Config),
		protocols => [Protocol],
		cookie_store => gun_cookies_list:init()
	}),
	{ok, Protocol} = gun:await_up(ConnPid1),
	StreamRef1 = gun:ws_upgrade(ConnPid1, "/ws"),
	{upgrade, [<<"websocket">>], Headers1} = gun:await(ConnPid1, StreamRef1),
	ct:log("Headers1:~n~p", [Headers1]),
	%% We must extract the cookie store because it is tied to the connection.
	#{cookie_store := CookieStore} = gun:info(ConnPid1),
	gun:close(ConnPid1),
	{ok, ConnPid2} = gun:open("localhost", config(port, Config), #{
		transport => config(transport, Config),
		protocols => [Protocol],
		cookie_store => CookieStore
	}),
	StreamRef2 = gun:get(ConnPid2, "/cookie-echo"),
	{response, nofin, 200, _} = gun:await(ConnPid2, StreamRef2),
	{ok, Body2} = gun:await_body(ConnPid2, StreamRef2),
	ct:log("Body2:~n~p", [Body2]),
	gun:close(ConnPid2),
	case Body2 of
		<<"UNDEF">> -> undefined;
		_ -> cow_cookie:parse_cookie(Body2)
	end.
