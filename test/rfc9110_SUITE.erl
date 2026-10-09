%% Copyright (c) Loïc Hoguin <essen@ninenines.eu>
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

-module(rfc9110_SUITE).
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
		{h2c, [parallel], CommonTests},
		{h2, [parallel], CommonTests}
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
		{"/content_length_204", content_length_204_h, []}
	]}
].

%% Tests.

content_length_zero_on_204(Config) ->
	doc("Gun accepts a 204 response that includes "
		"content-length 0. (RFC9110 8.6)"),
	Protocol = config(protocol, Config),
	{ok, ConnPid} = gun:open("localhost", config(port, Config), #{
		transport => config(transport, Config),
		tls_opts => [{verify, verify_none}, {versions, ['tlsv1.2']}],
		protocols => [Protocol]
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	StreamRef1 = gun:get(ConnPid, "/content_length_204"),
	{response, fin, 204, Headers1} = gun:await(ConnPid, StreamRef1),
	{<<"content-length">>, <<"0">>}
		= lists:keyfind(<<"content-length">>, 1, Headers1),
	StreamRef2 = gun:get(ConnPid, "/content_length_204"),
	{response, fin, 204, Headers2} = gun:await(ConnPid, StreamRef2),
	{<<"content-length">>, <<"0">>}
		= lists:keyfind(<<"content-length">>, 1, Headers2),
	gun:close(ConnPid).
