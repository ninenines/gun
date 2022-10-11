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
	CommonTests = ct_helper:all(?MODULE),
	[
		{http, [parallel], CommonTests},
		{https, [parallel], CommonTests},
		%% Websocket over HTTP/2 is currently not supported.
		{h2c, [parallel], (CommonTests -- [wpt_secure_ws])},
		{h2, [parallel], (CommonTests -- [wpt_secure_ws])}
	].

init_per_group(Ref, Config0) when Ref =:= http; Ref =:= h2c ->
	Protocol = case Ref of
		http -> http;
		h2c -> http2
	end,
	Config = gun_test:init_cowboy_tcp(Ref, #{
		env => #{dispatch => cowboy_router:compile(init_routes())}
	}, Config0),
	[{transport, tcp}, {protocol, Protocol}|Config];
init_per_group(Ref, Config0) when Ref =:= https; Ref =:= h2 ->
	Protocol = case Ref of
		https -> http;
		h2 -> http2
	end,
	Config = gun_test:init_cowboy_tls(Ref, #{
		env => #{dispatch => cowboy_router:compile(init_routes())}
	}, Config0),
	[{transport, tls}, {protocol, Protocol}|Config].

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
		tls_opts => [{verify, verify_none}, {versions, ['tlsv1.2']}],
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
		tls_opts => [{verify, verify_none}, {versions, ['tlsv1.2']}],
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
		tls_opts => [{verify, verify_none}, {versions, ['tlsv1.2']}],
		protocols => [Protocol],
		cookie_store => gun_cookies_list:init()
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(Protocol, ProxyPid),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => config(port, Config),
		transport => Transport,
		tls_opts => [{verify, verify_none}, {versions, ['tlsv1.2']}],
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

%% Web Platform Tests converted to Erlang.
%%
%% Tests are not automatically updated, the process is manual.
%% Some test data is exported in JSON files in the "test/wpt" directory.
%% https://github.com/web-platform-tests/wpt/tree/master/cookies

-define(WPT_HOST, "web-platform.test").

%% WPT: browser-only tests
%%
%% cookie-enabled-noncookie-frame.html
%% meta-blocked.html
%% navigated-away.html
%% prefix/document-cookie.non-secure.html
%% prefix/__host.document-cookie.html
%% prefix/__host.document-cookie.https.html
%% prefix/__secure.document-cookie.html
%% prefix/__secure.document-cookie.https.html
%% secure/set-from-dom.https.sub.html
%% secure/set-from-dom.sub.html

%% WPT: attributes/attributes-ctl
%%
%% attributes/attributes-ctl.sub.html
%%
%% The original tests use the DOM. We can't do that so
%% we use a simple HTTP test instead. The original test
%% also includes a string representation of the CTL in
%% the cookie name. We don't bother.
%%
%% The expected value is only used for the \t CTL.
%% The original test retains the \t in the value because
%% it uses the DOM. The Set-Cookie algorithm requires
%% us to drop it.
wpt_attributes_ctl_domain(Config) ->
	doc("Test cookie attribute parsing with control characters: "
		"in Domain attribute value."),
	do_wpt_ctl_test(fun(CTL) -> {
		<<"testdomain">>,
		<<"testdomain=t; Domain=test", CTL, ".co; Domain=", ?WPT_HOST>>,
		<<"testdomain=t">>
	} end, "/cookies/attributes", Config).

wpt_attributes_ctl_domain2(Config) ->
	doc("Test cookie attribute parsing with control characters: "
		"after Domain attribute value."),
	do_wpt_ctl_test(fun(CTL) -> {
		<<"testdomain2">>,
		<<"testdomain2=t; Domain=", ?WPT_HOST, CTL>>,
		<<"testdomain2=t">>
	} end, "/cookies/attributes", Config).

wpt_attributes_ctl_path(Config) ->
	doc("Test cookie attribute parsing with control characters: "
		"in Path attribute value."),
	do_wpt_ctl_test(fun(CTL) -> {
		<<"testpath">>,
		<<"testpath=t; Path=/te", CTL, "st; Path=/cookies/attributes">>,
		<<"testpath=t">>
	} end, "/cookies/attributes", Config).

wpt_attributes_ctl_path2(Config) ->
	doc("Test cookie attribute parsing with control characters: "
		"after Path attribute value."),
	do_wpt_ctl_test(fun(CTL) -> {
		<<"testpath2">>,
		<<"testpath2=t; Path=/cookies/attributes", CTL>>,
		<<"testpath2=t">>
	} end, "/cookies/attributes", Config).

wpt_attributes_ctl_max_age(Config) ->
	doc("Test cookie attribute parsing with control characters: "
		"in Max-Age attribute value."),
	do_wpt_ctl_test(fun(CTL) -> {
		<<"testmaxage">>,
		<<"testmaxage=t; Max-Age=10", CTL, "00; Max-Age=1000">>,
		<<"testmaxage=t">>
	} end, "/cookies/attributes", Config).

wpt_attributes_ctl_max_age2(Config) ->
	doc("Test cookie attribute parsing with control characters: "
		"after Max-Age attribute value."),
	do_wpt_ctl_test(fun(CTL) -> {
		<<"testmaxage2">>,
		<<"testmaxage2=t; Max-Age=1000", CTL>>,
		<<"testmaxage2=t">>
	} end, "/cookies/attributes", Config).

wpt_attributes_ctl_expires(Config) ->
	doc("Test cookie attribute parsing with control characters: "
		"in Expires attribute value."),
	do_wpt_ctl_test(fun(CTL) -> {
		<<"testexpires">>,
		<<"testexpires=t"
			"; Expires=Fri, 01 Jan 20", CTL, "38 00:00:00 GMT"
			"; Expires=Fri, 01 Jan 2038 00:00:00 GMT">>,
		<<"testexpires=t">>
	} end, "/cookies/attributes", Config).

wpt_attributes_ctl_expires2(Config) ->
	doc("Test cookie attribute parsing with control characters: "
		"after Expires attribute value."),
	do_wpt_ctl_test(fun(CTL) -> {
		<<"testexpires2">>,
		<<"testexpires2=t; Expires=Fri, 01 Jan 2038 00:00:00 GMT", CTL>>,
		<<"testexpires2=t">>
	} end, "/cookies/attributes", Config).

wpt_attributes_ctl_secure(Config) ->
	doc("Test cookie attribute parsing with control characters: "
		"in Secure attribute."),
	do_wpt_ctl_test(fun(CTL) -> {
		<<"testsecure">>,
		<<"testsecure=t; Sec", CTL, "ure">>,
		<<"testsecure=t">>
	} end, "/cookies/attributes", Config).

wpt_attributes_ctl_secure2(Config) ->
	doc("Test cookie attribute parsing with control characters: "
		"after Secure attribute."),
	do_wpt_ctl_test(fun(CTL) -> {
		<<"testsecure2">>,
		<<"testsecure2=t; Secure", CTL>>,
		case config(transport, Config) of
			tcp -> <<>>; %% Secure causes the cookie to be rejected over TCP.
			tls -> <<"testsecure2=t">>
		end
	} end, "/cookies/attributes", Config).

wpt_attributes_ctl_httponly(Config) ->
	doc("Test cookie attribute parsing with control characters: "
		"in HttpOnly attribute."),
	do_wpt_ctl_test(fun(CTL) -> {
		<<"testhttponly">>,
		<<"testhttponly=t; Http", CTL, "Only">>,
		<<"testhttponly=t">>
	} end, "/cookies/attributes", Config).

wpt_attributes_ctl_samesite(Config) ->
	doc("Test cookie attribute parsing with control characters: "
		"in SameSite attribute value."),
	do_wpt_ctl_test(fun(CTL) -> {
		<<"testsamesite">>,
		<<"testsamesite=t; SameSite=No", CTL, "ne; SameSite=None">>,
		<<"testsamesite=t">>
	} end, "/cookies/attributes", Config).

wpt_attributes_ctl_samesite2(Config) ->
	doc("Test cookie attribute parsing with control characters: "
		"after SameSite attribute value."),
	do_wpt_ctl_test(fun(CTL) -> {
		<<"testsamesite2">>,
		<<"testsamesite2=t; SameSite=None", CTL>>,
		<<"testsamesite2=t">>
	} end, "/cookies/attributes", Config).

%% @todo Redirect cookie test.
%% attributes/domain.sub.html
%% attributes/resources/domain-child.sub.html

%% WPT: attributes/expires
%%
%% attributes/expires.html
wpt_attributes_expires(Config) ->
	doc("Test expires attribute parsing."),
	do_wpt_json_test("attributes_expires", "/cookies/attributes", Config).

%% WPT: attributes/invalid
%%
%% attributes/invalid.html
wpt_attributes_invalid(Config) ->
	doc("Test invalid attribute parsing."),
	do_wpt_json_test("attributes_invalid", "/cookies/attributes", Config).

%% WPT: attributes/max_age
%%
%% attributes/max-age.html
wpt_attributes_max_age(Config) ->
	doc("Test max-age attribute parsing."),
	do_wpt_json_test("attributes_max_age", "/cookies/attributes", Config).

%% WPT: attributes/path
%%
%% attributes/path.html
wpt_attributes_path(Config) ->
	doc("Test cookie path attribute parsing."),
	do_wpt_json_test("attributes_path", "/cookies/attributes", Config).

%% @todo Redirect cookie test.
%% attributes/path-redirect.html
%% attributes/resources/pathfakeout.html
%% attributes/resources/path-redirect-shared.js
%% attributes/resources/path.html
%% attributes/resources/path.html.headers
%% attributes/resources/path/one.html
%% attributes/resources/path/three.html
%% attributes/resources/path/two.html
%% attributes/resources/pathfakeout/one.html

%% WPT: attributes/secure
%%
%% attributes/secure.https.html
%% attributes/secure-non-secure.html
%% attributes/resources/secure-non-secure-child.html
wpt_attributes_secure(Config) ->
	doc("Test cookie secure attribute parsing."),
	TestFile = case config(transport, Config) of
		tcp -> "attributes_secure_non_secure";
		tls -> "attributes_secure"
	end,
	do_wpt_json_test(TestFile, "/cookies/attributes", Config).

%% WPT: domain/domain-attribute-host-with-and-without-leading-period
%%
%% domain/domain-attribute-host-with-and-without-leading-period.sub.https.html
%% domain/domain-attribute-host-with-and-without-leading-period.sub.https.html.sub.headers
wpt_domain_with_and_without_leading_period(Config) ->
	doc("Domain with and without leading period."),
	#{
		same_origin := [{<<"a">>, <<"c">>}],
		subdomain := [{<<"a">>, <<"c">>}]
	} = do_wpt_domain_test(Config, "domain_with_and_without_leading_period"),
	ok.

%% WPT: domain/domain-attribute-host-with-leading-period
%%
%% domain/domain-attribute-host-with-leading-period.sub.https.html
%% domain/domain-attribute-host-with-leading-period.sub.https.html.sub.headers
wpt_domain_with_leading_period(Config) ->
	doc("Domain with leading period."),
	#{
		same_origin := [{<<"a">>, <<"b">>}],
		subdomain := [{<<"a">>, <<"b">>}]
	} = do_wpt_domain_test(Config, "domain_with_leading_period"),
	ok.

%% @todo WPT: domain/domain-attribute-idn-host
%%
%% domain/domain-attribute-idn-host.sub.https.html
%% domain/support/idn-child.sub.https.html
%% domain/support/idn.py

%% WPT: domain/domain-attribute-matches-host
%%
%% domain/domain-attribute-matches-host.sub.https.html
%% domain/domain-attribute-matches-host.sub.https.html.sub.headers
wpt_domain_matches_host(Config) ->
	doc("Domain matches host header."),
	#{
		same_origin := [{<<"a">>, <<"b">>}],
		subdomain := [{<<"a">>, <<"b">>}]
	} = do_wpt_domain_test(Config, "domain_matches_host"),
	ok.

%% WPT: domain/domain-attribute-missing
%%
%% domain/domain-attribute-missing.sub.html
%% domain/domain-attribute-missing.sub.html.headers
wpt_domain_missing(Config) ->
	doc("Domain attribute missing."),
	#{
		same_origin := [{<<"a">>, <<"b">>}],
		subdomain := undefined
	} = do_wpt_domain_test(Config, "domain_missing"),
	ok.

do_wpt_domain_test(Config, TestCase) ->
	Protocol = config(protocol, Config),
	{ok, ConnPid} = gun:open("localhost", config(port, Config), #{
		transport => config(transport, Config),
		tls_opts => [{verify, verify_none}, {versions, ['tlsv1.2']}],
		protocols => [Protocol],
		cookie_store => gun_cookies_list:init()
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	StreamRef1 = gun:get(ConnPid, ["/cookie-set?", TestCase], #{<<"host">> => ?WPT_HOST}),
	{response, fin, 204, Headers1} = gun:await(ConnPid, StreamRef1),
	ct:log("Headers1:~n~p", [Headers1]),
	StreamRef2 = gun:get(ConnPid, "/cookie-echo", #{<<"host">> => ?WPT_HOST}),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef2),
	{ok, Body2} = gun:await_body(ConnPid, StreamRef2),
	ct:log("Body2:~n~p", [Body2]),
	StreamRef3 = gun:get(ConnPid, "/cookie-echo", #{<<"host">> => "sub." ?WPT_HOST}),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef3),
	{ok, Body3} = gun:await_body(ConnPid, StreamRef3),
	ct:log("Body3:~n~p", [Body3]),
	gun:close(ConnPid),
	#{
		same_origin => case Body2 of <<"UNDEF">> -> undefined; _ -> cow_cookie:parse_cookie(Body2) end,
		subdomain => case Body3 of <<"UNDEF">> -> undefined; _ -> cow_cookie:parse_cookie(Body3) end
	}.

%% WPT: encoding/charset
%%
%% encoding/charset.html
wpt_encoding(Config) ->
	doc("Test UTF-8 and ASCII cookie parsing."),
	do_wpt_json_test("encoding_charset", "/cookies/encoding", Config).

%% WPT: name/name
%%
%% name/name.html
wpt_name(Config) ->
	doc("Test cookie name parsing."),
	do_wpt_json_test("name", "/cookies/name", Config).

%% WPT: name/name-ctl
%%
%% name/name-ctl.html
%%
%% The original tests use the DOM. We can't do that so
%% we use a simple HTTP test instead. The original test
%% also includes a string representation of the CTL in
%% the cookie name. We don't bother.
%%
%% The expected value is only used for the \t CTL.
%% The original test retains the \t in the value because
%% it uses the DOM. The Set-Cookie algorithm requires
%% us to drop it.
wpt_name_ctl(Config) ->
	doc("Test cookie name parsing with control characters."),
	do_wpt_ctl_test(fun(CTL) -> {
		<<"test", CTL, "name">>,
		<<"test", CTL, "name=", CTL>>,
		<<"test", CTL, "name=">>
	} end, "/cookies/name", Config).

%% @todo Redirect cookie test.
%% ordering/ordering.sub.html
%% ordering/resources/ordering-child.sub.html

%% WPT: partitioned-cookies (Not implemented; proposal.)

%% WPT: path/default
%%
%% path/default.html
wpt_path_default(Config) ->
	doc("Cookie set on the default path can be retrieved."),
	Protocol = config(protocol, Config),
	{ok, ConnPid} = gun:open("localhost", config(port, Config), #{
		transport => config(transport, Config),
		tls_opts => [{verify, verify_none}, {versions, ['tlsv1.2']}],
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
%%
%% path/match.html
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
			tls_opts => [{verify, verify_none}, {versions, ['tlsv1.2']}],
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
			tls_opts => [{verify, verify_none}, {versions, ['tlsv1.2']}],
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
%%
%% prefix/__host.header.html
%% prefix/__host.header.https.html
wpt_prefix_host(Config) ->
	doc("__Host- prefix."),
	Tests = case config(transport, Config) of
		tcp -> [
			{<<"__Host-foo=bar; Path=/;">>, false},
			{<<"__Host-foo=bar; Path=/;domain=" ?WPT_HOST>>, false},
			{<<"__Host-foo=bar; Path=/;Max-Age=10">>, false},
			{<<"__Host-foo=bar; Path=/;HttpOnly">>, false},
			{<<"__Host-foo=bar; Secure; Path=/;">>, false},
			{<<"__Host-foo=bar; Secure; Path=/;domain=" ?WPT_HOST>>, false},
			{<<"__Host-foo=bar; Secure; Path=/;Max-Age=10">>, false},
			{<<"__Host-foo=bar; Secure; Path=/;HttpOnly">>, false},
			{<<"__Host-foo=bar; Secure; Path=/; Domain=" ?WPT_HOST "; ">>, false},
			{<<"__Host-foo=bar; Secure; Path=/; Domain=" ?WPT_HOST "; domain=" ?WPT_HOST>>, false},
			{<<"__Host-foo=bar; Secure; Path=/; Domain=" ?WPT_HOST "; Max-Age=10">>, false},
			{<<"__Host-foo=bar; Secure; Path=/; Domain=" ?WPT_HOST "; HttpOnly">>, false},
			{<<"__Host-foo=bar; Secure; Path=/cookies/resources/list.py">>, false}
		];
		tls -> [
			{<<"__Host-foo=bar; Path=/;">>, false},
			{<<"__Host-foo=bar; Path=/;Max-Age=10">>, false},
			{<<"__Host-foo=bar; Path=/;HttpOnly">>, false},
			{<<"__Host-foo=bar; Secure; Path=/;">>, true},
			{<<"__Host-foo=bar; Secure; Path=/;Max-Age=10">>, true},
			{<<"__Host-foo=bar; Secure; Path=/;HttpOnly">>, true},
			{<<"__Host-foo=bar; Secure; Path=/; Domain=" ?WPT_HOST "; ">>, false},
			{<<"__Host-foo=bar; Secure; Path=/; Domain=" ?WPT_HOST "; Max-Age=10">>, false},
			{<<"__Host-foo=bar; Secure; Path=/; Domain=" ?WPT_HOST "; HttpOnly">>, false},
			{<<"__Host-foo=bar; Secure; Path=/cookies/resources/list.py">>, false}
		]
	end,
	_ = [do_wpt_prefix_common(Config, TestCase, Expected, <<"__Host-foo">>)
		|| {TestCase, Expected} <- Tests],
	ok.

%% WPT: prefix/__secure.header
%%
%% prefix/__secure.header.html
%% prefix/__secure.header.https.html
wpt_prefix_secure(Config) ->
	doc("__Secure- prefix."),
	Tests = case config(transport, Config) of
		tcp -> [
			{<<"__Secure-foo=bar; Path=/;">>, false},
			{<<"__Secure-foo=bar; Path=/;domain=" ?WPT_HOST>>, false},
			{<<"__Secure-foo=bar; Path=/;Max-Age=10">>, false},
			{<<"__Secure-foo=bar; Path=/;HttpOnly">>, false},
			{<<"__Secure-foo=bar; Secure; Path=/;">>, false},
			{<<"__Secure-foo=bar; Secure; Path=/;domain=" ?WPT_HOST>>, false},
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
		tls_opts => [{verify, verify_none}, {versions, ['tlsv1.2']}],
		protocols => [Protocol],
		cookie_store => gun_cookies_list:init()
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	%% Set and retrieve the cookie.
	StreamRef1 = gun:get(ConnPid, "/cookies/resources/set.py?prefix", #{
		<<"host">> => ?WPT_HOST,
		<<"please-set-cookie">> => TestCase
	}),
	{response, fin, 204, Headers1} = gun:await(ConnPid, StreamRef1),
	ct:log("Headers1:~n~p", [Headers1]),
	StreamRef2 = gun:get(ConnPid, "/cookies/resources/echo.py", #{
		<<"host">> => ?WPT_HOST
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

%% WPT: samesite/ (Not implemented.)
%% WPT: samesite-none-secure/ (Not implemented.)
%% WPT: schemeful-same-site/ (Not implemented.)

%% WPT: secure/set-from-http.*
%%
%% secure/set-from-http.sub.html
%% secure/set-from-http.sub.html.headers
%% secure/set-from-http.https.sub.html
%% secure/set-from-http.https.sub.html.headers
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
		tls_opts => [{verify, verify_none}, {versions, ['tlsv1.2']}],
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
%%
%% secure/set-from-ws.sub.html
%% secure/set-from-wss.https.sub.html
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
		tls_opts => [{verify, verify_none}, {versions, ['tlsv1.2']}],
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
		tls_opts => [{verify, verify_none}, {versions, ['tlsv1.2']}],
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

%% WPT: size/attributes
%%
%% size/attributes.www.sub.html
wpt_size_attributes(Config) ->
	doc("Test cookie attribute size restrictions."),
	do_wpt_json_test("size_attributes", "/cookies/size", Config).

%% WPT: size/name-and-value
%%
%% size/name-and-value.html
wpt_size_name_and_value(Config) ->
	doc("Test cookie name/value size restrictions."),
	do_wpt_json_test("size_name_and_value", "/cookies/size", Config).

%% WPT: value/value
%%
%% value/value.html
wpt_value(Config) ->
	doc("Test cookie value parsing."),
	Tests = do_load_json("value"),
	_ = [begin
		#{
			<<"name">> := Name,
			<<"cookie">> := Cookie,
			<<"expected">> := Expected
		} = Test,
		false = maps:is_key(<<"defaultPath">>, Test),
		do_wpt_set_test(<<"/cookies/value">>,
			Name, Cookie, Expected, Config)
	end || Test <- Tests,
		%% The original test uses the DOM, we use HTTP, and are
		%% required to drop the cookie entirely if it contains
		%% a \n (RFC6265bis 5.4) so we skip this test.
		maps:get(<<"expected">>, Test) =/= <<"test=13">>],
	ok.

%% WPT: value/value-ctl
%%
%% value/value-ctl.html
%%
%% The original tests use the DOM. We can't do that so
%% we use a simple HTTP test instead. The original test
%% also includes a string representation of the CTL in
%% the cookie value. We don't bother.
%%
%% The expected value is only used for the \t CTL.
%% The original test retains the \t in the value because
%% it uses the DOM. The Set-Cookie algorithm requires
%% us to drop it.
wpt_value_ctl(Config) ->
	doc("Test cookie value parsing with control characters."),
	do_wpt_ctl_test(fun(CTL) -> {
		<<"test">>,
		<<"test=", CTL, "value">>,
		<<"test=value">>
	} end, "/cookies/value", Config).

%% JSON files are created by taking the Javascript Object
%% from the HTML files in the WPT suite, using the browser
%% Developer console to convert into JSON:
%%   Obj = <Paste>
%%   JSON.stringify(Obj)
%% Then copying the result into the JSON file; removing
%% the quoting (first and last character) and if needed
%% fixing the escaping in Vim using:
%%   :%s/\\\\/\\/g
%% The host may also need to be replaced to match WPT_HOST.
do_load_json(File0) ->
	File = "../../test/wpt/cookies/" ++ File0 ++ ".json",
	{ok, Bin} = file:read_file(File),
	jsx:decode(Bin, [{return_maps, true}]).

do_wpt_json_test(TestFile, TestPath, Config) ->
	Tests = do_load_json(TestFile),
	_ = [begin
		#{
			<<"name">> := Name,
			<<"cookie">> := Cookie,
			<<"expected">> := Expected
		} = Test,
		DefaultPath = maps:get(<<"defaultPath">>, Test, true),
		do_wpt_set_test(TestPath, Name, Cookie, Expected, DefaultPath, Config)
	end || Test <- Tests],
	ok.

do_wpt_ctl_test(Fun, TestPath, Config) ->
	%% Control characters are defined by RFC5234 to be %x00-1F / %x7F.
	%% We exclude \r for HTTP/1.1 because this causes errors
	%% at the header parsing level.
	CTLs0 = lists:seq(0, 16#1F) ++ [16#7F],
	CTLs = case config(protocol, Config) of
		http -> CTLs0 -- "\r";
		http2 -> CTLs0
	end,
	%% All CTLs except \t should cause the cookie to be rejected.
	_ = [begin
		{Name, Cookie, Expected} = Fun(CTL),
		case CTL of
			$\t ->
				do_wpt_set_test(TestPath, Name, Cookie, Expected, false, Config);
			_ ->
				do_wpt_set_test(TestPath, Name, Cookie, <<>>, false, Config)
		end
	end || CTL <- CTLs],
	ok.

%% Equivalent to httpCookieTest.
do_wpt_set_test(TestPath, Name, Cookie, Expected, Config) ->
	do_wpt_set_test(TestPath, Name, Cookie, Expected, true, Config).

do_wpt_set_test(TestPath, Name, Cookie, Expected, DefaultPath, Config) ->
	ct:log("Name: ~s", [Name]),
	Protocol = config(protocol, Config),
	{ok, ConnPid} = gun:open("localhost", config(port, Config), #{
		transport => config(transport, Config),
		tls_opts => [{verify, verify_none}, {versions, ['tlsv1.2']}],
		protocols => [Protocol],
		cookie_store => gun_cookies_list:init()
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	StreamRef1 = gun:get(ConnPid,
		["/cookie-set?ttb=", cow_qs:urlencode(term_to_binary(Cookie))],
		#{<<"host">> => ?WPT_HOST}),
	{response, fin, 204, Headers} = gun:await(ConnPid, StreamRef1),
	ct:log("Headers:~n~p", [Headers]),
	#{cookie_store := Store} = gun:info(ConnPid),
	ct:log("Store:~n~p", [Store]),
	Result1 = case DefaultPath of
		true ->
			%% We do another request to get the cookie.
			StreamRef2 = gun:get(ConnPid, "/cookie-echo",
				#{<<"host">> => ?WPT_HOST}),
			{response, nofin, 200, _} = gun:await(ConnPid, StreamRef2),
			{ok, Body2} = gun:await_body(ConnPid, StreamRef2),
			case Body2 of
				<<"UNDEF">> -> <<>>;
				_ -> Body2
			end;
		false ->
			%% We call this function to get a request header representation
			%% of a cookie, similar to what document.cookie returns.
			case gun_cookies:add_cookie_header(
				case config(transport, Config) of
					tcp -> <<"http">>;
					tls -> <<"https">>
				end,
				<<?WPT_HOST>>, TestPath, [], Store) of
				{[{<<"cookie">>, Result0}], _} ->
					Result0;
				{[], _} ->
					<<>>
			end
	end,
	Result = unicode:characters_to_binary(Result1),
	ct:log("Expected:~n~p~nResult:~n~p", [Expected, Result]),
	{Name, Cookie, Expected} = {Name, Cookie, Result},
	gun:close(ConnPid).
