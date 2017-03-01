%% Copyright (c) 2013-2015, Loïc Hoguin <essen@ninenines.eu>
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
-compile(export_all).

all() ->
	[
		{group, http},
		{group, http2},
		{group, spdy}
	].

groups() ->
	Tests = ct_helper:all(?MODULE),
	[
		{http, [parallel], Tests},
		{http2, [parallel], Tests},
		{spdy, [parallel], Tests}
	].

init_per_group(Protocol, Config) ->
	[{protocol, Protocol}|Config].

end_per_group(_Protocol, _Config) ->
	ok.

common(Config) ->
	Pid = do_open(ct_helper:config(protocol, Config)),
	Ref = gun:get(Pid, "/"),
	do_wait(Pid, Ref).

common_spawn(Config) ->
	Parent = self(),
	DoneMsg = make_ref(),
	Receiver =
		spawn_link(
			fun() ->
				receive
					{await, Pid, Ref} -> do_wait(Pid, Ref), Parent ! DoneMsg
					after 5000 -> error(timeout)
				end
			end),

	spawn_link(
		fun() ->
			Pid = do_open(ct_helper:config(protocol, Config)),
			Ref = gun:get(Pid, "/", [], #{reply_to => Receiver}),
			Receiver ! {await, Pid, Ref}
		end),

	receive
		DoneMsg -> ok
		after 5000 -> error(timeout)
	end.

%% Support functions.
do_open(Protocol) ->
	{ok, Pid} = gun:open("twitter.com", 443, #{protocols => [Protocol]}),
	{ok, Protocol} = gun:await_up(Pid),
	Pid.

do_wait(Pid, Ref) ->
	case gun:await(Pid, Ref) of
		{response, nofin, _, _} -> {ok, _} = gun:await_body(Pid, Ref);
		{response, fin, _, _} -> ok
	end.
