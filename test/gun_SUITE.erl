%% Copyright (c) 2017-2019, Loïc Hoguin <essen@ninenines.eu>
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

-module(gun_SUITE).
-compile(export_all).
-compile(nowarn_export_all).

-import(ct_helper, [doc/1]).
-import(ct_helper, [name/0]).
-import(gun_test, [init_origin/2]).
-import(gun_test, [init_origin/3]).
-import(gun_test, [receive_from/1]).
-import(gun_test, [receive_all_from/2]).

all() ->
	ct_helper:all(?MODULE).

%% Tests.

atom_hostname(_) ->
	doc("Hostnames may be given as atom."),
	{ok, OriginPid, OriginPort} = init_origin(tcp, http),
	{ok, Pid} = gun:open('localhost', OriginPort),
	{ok, http} = gun:await_up(Pid),
	_ = gun:get(Pid, "/"),
	Data = receive_from(OriginPid),
	Lines = binary:split(Data, <<"\r\n">>, [global]),
	[<<"host: localhost:", _/bits>>] = [L || <<"host: ", _/bits>> = L <- Lines],
	gun:close(Pid).

connect_timeout(_) ->
	doc("Ensure an integer value for connect_timeout is accepted."),
	{ok, Pid} = gun:open("localhost", 12345, #{connect_timeout => 1000, retry => 0}),
	Ref = monitor(process, Pid),
	receive
		{'DOWN', Ref, process, Pid, {shutdown, _}} ->
			ok
	after 5000 ->
		error(timeout)
	end.

connect_timeout_infinity(_) ->
	doc("Ensure infinity for connect_timeout is accepted."),
	{ok, Pid} = gun:open("localhost", 12345, #{connect_timeout => infinity, retry => 0}),
	Ref = monitor(process, Pid),
	receive
		{'DOWN', Ref, process, Pid, {shutdown, _}} ->
			ok
	after 5000 ->
		error(timeout)
	end.

detect_owner_gone(_) ->
	{ok, ListenSocket} = gen_tcp:listen(0, [binary, {active, false}]),
	{ok, {_, Port}} = inet:sockname(ListenSocket),
	Self = self(),
	spawn(fun() ->
		{ok, ConnPid} = gun:open("localhost", Port),
		Self ! {conn, ConnPid},
		gun:await_up(ConnPid)
	end),
	{ok, _} = gen_tcp:accept(ListenSocket, 5000),
	Pid = receive
		{conn, C} ->
			C
	after 1000 ->
		error(timeout)
	end,
	Ref = monitor(process, Pid),
	receive
		{'DOWN', Ref, process, Pid, normal} ->
			ok
	after 1000 ->
		true = erlang:is_process_alive(Pid),
		error(timeout)
	end.

detect_owner_gone_ws(_) ->
	Name = name(),
	{ok, _} = cowboy:start_clear(Name, [], #{env => #{
		dispatch => cowboy_router:compile([{'_', [{"/", ws_echo, []}]}])
	}}),
	Port = ranch:get_port(Name),
	Self = self(),
	spawn(fun() ->
		{ok, ConnPid} = gun:open("localhost", Port),
		Self ! {conn, ConnPid},
		gun:await_up(ConnPid),
		gun:ws_upgrade(ConnPid, "/", []),
		receive
			{gun_upgrade, ConnPid, _, [<<"websocket">>], _} ->
				ok
		after 1000 ->
			error(timeout)
		end
	end),
	Pid = receive
		{conn, C} ->
			C
	after 1000 ->
		error(timeout)
	end,
	Ref = monitor(process, Pid),
	receive
		{'DOWN', Ref, process, Pid, normal} ->
			ok
	after 1000 ->
		true = erlang:is_process_alive(Pid),
		error(timeout)
	end,
	cowboy:stop_listener(Name).

ignore_empty_data_http(_) ->
	doc("When gun:data/4 is called with nofin and empty data, it must be ignored."),
	{ok, OriginPid, OriginPort} = init_origin(tcp, http),
	{ok, Pid} = gun:open("localhost", OriginPort),
	{ok, http} = gun:await_up(Pid),
	Ref = gun:put(Pid, "/", []),
	gun:data(Pid, Ref, nofin, "hello "),
	gun:data(Pid, Ref, nofin, ["", <<>>]),
	gun:data(Pid, Ref, fin, "world!"),
	Data = receive_all_from(OriginPid, 500),
	Lines = binary:split(Data, <<"\r\n">>, [global]),
	Zero = [Z || <<"0">> = Z <- Lines],
	1 = length(Zero),
	gun:close(Pid).

ignore_empty_data_http2(_) ->
	doc("When gun:data/4 is called with nofin and empty data, it must be ignored."),
	{ok, OriginPid, OriginPort} = init_origin(tcp, http2),
	{ok, Pid} = gun:open("localhost", OriginPort, #{protocols => [http2]}),
	{ok, http2} = gun:await_up(Pid),
	timer:sleep(100), %% Give enough time for the handshake to fully complete.
	Ref = gun:put(Pid, "/", []),
	gun:data(Pid, Ref, nofin, "hello "),
	gun:data(Pid, Ref, nofin, ["", <<>>]),
	gun:data(Pid, Ref, fin, "world!"),
	Data = receive_all_from(OriginPid, 500),
	<<
		%% HEADERS frame.
		Len1:24, 1, _:40, _:Len1/unit:8,
		%% First DATA frame.
		6:24, 0, _:7, 0:1, _:32, "hello ",
		%% Second and final DATA frame.
		6:24, 0, _:7, 1:1, _:32, "world!"
	>> = Data,
	gun:close(Pid).

info(_) ->
	doc("Get info from the Gun connection."),
	{ok, ListenSocket} = gen_tcp:listen(0, [binary, {active, false}]),
	{ok, {_, Port}} = inet:sockname(ListenSocket),
	{ok, Pid} = gun:open("localhost", Port),
	{ok, _} = gen_tcp:accept(ListenSocket, 5000),
	#{sock_ip := _, sock_port := _} = gun:info(Pid),
	ok.

keepalive_infinity(_) ->
	doc("Ensure infinity for keepalive is accepted by all protocols."),
	{ok, Pid} = gun:open("localhost", 12345, #{
		http_opts => #{keepalive => infinity},
		http2_opts => #{keepalive => infinity},
		retry => 0}),
	Ref = monitor(process, Pid),
	receive
		{'DOWN', Ref, process, Pid, {shutdown, _}} ->
			ok
	after 5000 ->
		error(timeout)
	end.

reply_to(_) ->
	doc("The reply_to option allows using a separate process for requests."),
	do_reply_to(http),
	do_reply_to(http2).

do_reply_to(Protocol) ->
	{ok, ListenSocket} = gen_tcp:listen(0, [binary, {active, false}]),
	{ok, {_, Port}} = inet:sockname(ListenSocket),
	Self = self(),
	{ok, Pid} = gun:open("localhost", Port, #{protocols => [Protocol]}),
	{ok, ClientSocket} = gen_tcp:accept(ListenSocket, 5000),
	ok = case Protocol of
		http -> ok;
		http2 ->
			{ok, _} = gen_tcp:recv(ClientSocket, 0, 5000),
			gen_tcp:send(ClientSocket, [
				<<0:24, 4:8, 0:40>>, %% Empty SETTINGS frame.
				<<0:24, 4:8, 1:8, 0:32>> %% SETTINGS ack.
			])
	end,
	{ok, Protocol} = gun:await_up(Pid),
	ReplyTo = spawn(fun() ->
		receive Ref ->
			Response = gun:await(Pid, Ref),
			Self ! Response
		after 1000 ->
			error(timeout)
		end
	end),
	Ref = gun:get(Pid, "/", [], #{reply_to => ReplyTo}),
	{ok, _} = gen_tcp:recv(ClientSocket, 0, 5000),
	ResponseData = case Protocol of
		http ->
			"HTTP/1.1 200 OK\r\n"
			"Content-length: 12\r\n"
			"\r\n"
			"Hello world!";
		http2 ->
			%% Send a HEADERS frame with PRIORITY back.
			{HeadersBlock, _} = cow_hpack:encode([
				{<<":status">>, <<"200">>}
			]),
			Len = iolist_size(HeadersBlock),
			[
				<<Len:24, 1:8,
					0:2, %% Undefined.
					0:1, %% PRIORITY.
					0:1, %% Undefined.
					0:1, %% PADDED.
					1:1, %% END_HEADERS.
					0:1, %% Undefined.
					1:1, %% END_STREAM.
					0:1, 1:31>>,
				HeadersBlock
			]
	end,
	ok = gen_tcp:send(ClientSocket, ResponseData),
	ReplyTo ! Ref,
	receive
		{response, _, _, _} ->
			ok
	after 1000 ->
		error(timeout)
	end.

retry_0(_) ->
	doc("Ensure Gun gives up immediately with retry=0."),
	{ok, Pid} = gun:open("localhost", 12345, #{retry => 0, retry_timeout => 500}),
	Ref = monitor(process, Pid),
	receive
		{'DOWN', Ref, process, Pid, {shutdown, _}} ->
			ok
	after 200 ->
		error(timeout)
	end.

retry_1(_) ->
	doc("Ensure Gun gives up with retry=1."),
	{ok, Pid} = gun:open("localhost", 12345, #{retry => 1, retry_timeout => 500}),
	Ref = monitor(process, Pid),
	receive
		{'DOWN', Ref, process, Pid, {shutdown, _}} ->
			ok
	after 700 ->
		error(timeout)
	end.

retry_immediately(_) ->
	doc("Ensure Gun retries immediately."),
	%% We have to make a first successful connection in order to test this.
	{ok, _, OriginPort} = init_origin(tcp, http,
		fun(_, ClientSocket, ClientTransport) ->
			ClientTransport:close(ClientSocket)
		end),
	{ok, Pid} = gun:open("localhost", OriginPort, #{retry => 1, retry_timeout => 500}),
	Ref = monitor(process, Pid),
	receive
		{'DOWN', Ref, process, Pid, {shutdown, _}} ->
			ok
	after 200 ->
		error(timeout)
	end.

retry_timeout(_) ->
	doc("Ensure the retry_timeout value is enforced."),
	{ok, Pid} = gun:open("localhost", 12345, #{retry => 1, retry_timeout => 1000}),
	Ref = monitor(process, Pid),
	receive
		{'DOWN', Ref, process, Pid, {shutdown, _}} ->
			error(shutdown_too_early)
	after 800 ->
		ok
	end,
	receive
		{'DOWN', Ref, process, Pid, {shutdown, _}} ->
			ok
	after 400 ->
		error(shutdown_too_late)
	end.

shutdown_reason(_) ->
	doc("The last connection failure must be propagated."),
	{ok, Pid} = gun:open("localhost", 12345, #{retry => 0}),
	Ref = monitor(process, Pid),
	receive
		{'DOWN', Ref, process, Pid, {shutdown, econnrefused}} ->
			ok
	after 200 ->
		error(timeout)
	end.

transform_header_name(_) ->
	doc("The transform_header_name option allows changing the case of header names."),
	{ok, ListenSocket} = gen_tcp:listen(0, [binary, {active, false}]),
	{ok, {_, Port}} = inet:sockname(ListenSocket),
	{ok, Pid} = gun:open("localhost", Port, #{
		protocols => [http],
		http_opts => #{
			transform_header_name => fun(<<"host">>) -> <<"HOST">>; (N) -> N end
		}
	}),
	{ok, ClientSocket} = gen_tcp:accept(ListenSocket, 5000),
	{ok, http} = gun:await_up(Pid),
	_ = gun:get(Pid, "/"),
	{ok, Data} = gen_tcp:recv(ClientSocket, 0, 5000),
	%% We do some very crude parsing of the response headers
	%% to check that the header name was properly transformed.
	Lines = binary:split(Data, <<"\r\n">>, [global]),
	HostLines = [L || <<"HOST: ", _/bits>> = L <- Lines],
	1 = length(HostLines),
	ok.

unix_socket_connect(_) ->
	case os:type() of
		{win32, _} ->
			doc("Unix Domain Sockets are not available on Windows.");
		_ ->
			do_unix_socket_connect()
	end.

do_unix_socket_connect() ->
	doc("Ensure we can send data via a unix domain socket."),
	DataDir = "/tmp/gun",
	SocketPath = filename:join(DataDir, "gun.sock"),
	ok = filelib:ensure_dir(SocketPath),
	_ = file:delete(SocketPath),
	TCPOpts = [
		{ifaddr, {local, SocketPath}},
		binary, {nodelay, true}, {active, false},
		{packet, raw}, {reuseaddr, true}
	],
	{ok, LSock} = gen_tcp:listen(0, TCPOpts),
	Tester = self(),
	Acceptor = fun() ->
		{ok, S} = gen_tcp:accept(LSock),
		{ok, R} = gen_tcp:recv(S, 0),
		Tester ! {recv, R},
		ok = gen_tcp:close(S),
		ok = gen_tcp:close(LSock)
	end,
	spawn(Acceptor),
	{ok, Pid} = gun:open_unix(SocketPath, #{}),
	_ = gun:get(Pid, "/", [{<<"host">>, <<"localhost">>}]),
	receive
		{recv, _} ->
			ok
	after 250 ->
		error(timeout)
	end.
