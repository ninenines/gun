%% Copyright (c) 2013-2014, Loïc Hoguin <essen@ninenines.eu>
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

-module(twitter_SUITE).

-include_lib("common_test/include/ct.hrl").

%% ct.
-export([all/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).

%% Tests.
-export([spdy/1]).

%% ct.

all() ->
	[spdy].

init_per_suite(Config) ->
	ok = application:start(ranch),
	ok = application:start(crypto),
	ok = application:start(cowlib),
	ok = application:start(asn1),
	ok = application:start(public_key),
	ok = application:start(ssl),
	ok = application:start(gun),
	Config.

end_per_suite(_) ->
	ok = application:stop(gun),
	ok = application:stop(ssl),
	ok = application:stop(public_key),
	ok = application:stop(asn1),
	ok = application:stop(cowlib),
	ok = application:stop(crypto),
	ok = application:stop(ranch),
	ok.

spdy(_) ->
	{ok, Pid} = gun:open("twitter.com", 443),
	Ref = gun:get(Pid, "/"),
	receive
		{gun_response, Pid, Ref, nofin, Status, Headers} ->
			ct:print("response ~p ~p", [Status, Headers]),
			data_loop(Pid, Ref)
	after 5000 ->
		error(timeout)
	end.

data_loop(Pid, Ref) ->
	receive
		{gun_data, Pid, Ref, nofin, Data} ->
			ct:print("data ~p", [Data]),
			data_loop(Pid, Ref);
		{gun_data, Pid, Ref, fin, Data} ->
			ct:print("data ~p~nend", [Data])
	after 5000 ->
		error(timeout)
	end.
