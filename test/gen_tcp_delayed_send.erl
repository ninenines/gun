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

-module(gen_tcp_delayed_send).
-export([connect/4]).
-export([controlling_process/2]).
-export([send/2]).
-export([peername/1]).
-export([getopts/2]).
-export([setopts/2]).
-export([close/1]).

%% The connect/4 function is called by the process
%% that calls ssl:connect/2,3,4.
connect(Address, Port, Opts, Timeout) ->
	gen_tcp:connect(Address, Port, Opts, Timeout).

controlling_process(Socket, ControllingPid) ->
	gen_tcp:controlling_process(Socket, ControllingPid).

send(Socket, [Data|Tail]) ->
	ct:pal("~p", [Data]),
	timer:sleep(100),
	gen_tcp:send(Socket, Data),
	send(Socket, Tail);
send(Socket, Data) ->
	ct:pal("~p", [Data]),
	timer:sleep(100),
	gen_tcp:send(Socket, Data).

peername(Socket) ->
	inet:peername(Socket).

getopts(Socket, Opts) ->
	inet:getopts(Socket, Opts).

setopts(Socket, Opts) ->
	inet:setopts(Socket, Opts).

close(Socket) ->
	gen_tcp:close(Socket).
