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
	[{group, gun}].

groups() ->
	%% On Windows we sometimes have timeout related failures due to
	%% some operations taking longer on Windows. Best retry a few times.
	Props = case os:type() of
		{win32, _} -> [{repeat_until_all_ok, 100}];
		_ -> []
	end,
	[{gun, [parallel|Props], ct_helper:all(?MODULE)}].

%% Tests.

atom_header_name(_) ->
	doc("Header names may be given as atom."),
	{ok, OriginPid, OriginPort} = init_origin(tcp, http),
	{ok, Pid} = gun:open("localhost", OriginPort),
	{ok, http} = gun:await_up(Pid),
	handshake_completed = receive_from(OriginPid),
	_ = gun:get(Pid, "/", [
		{'User-Agent', "Gun/atom-headers"}
	]),
	Data = receive_from(OriginPid),
	Lines = binary:split(Data, <<"\r\n">>, [global]),
	[<<"user-agent: Gun/atom-headers">>] = [L || <<"user-agent: ", _/bits>> = L <- Lines],
	gun:close(Pid).

atom_hostname(_) ->
	doc("Hostnames may be given as atom."),
	{ok, OriginPid, OriginPort} = init_origin(tcp, http),
	{ok, Pid} = gun:open('localhost', OriginPort),
	{ok, http} = gun:await_up(Pid),
	handshake_completed = receive_from(OriginPid),
	_ = gun:get(Pid, "/"),
	Data = receive_from(OriginPid),
	Lines = binary:split(Data, <<"\r\n">>, [global]),
	[<<"host: localhost:", _/bits>>] = [L || <<"host: ", _/bits>> = L <- Lines],
	gun:close(Pid).

connect_timeout(_) ->
	doc("Ensure an integer value for connect_timeout is accepted."),
	do_timeout(connect_timeout, 1000).

connect_timeout_infinity(_) ->
	doc("Ensure infinity for connect_timeout is accepted."),
	do_timeout(connect_timeout, infinity).

domain_lookup_timeout(_) ->
	doc("Ensure an integer value for domain_lookup_timeout is accepted."),
	do_timeout(domain_lookup_timeout, 1000).

domain_lookup_timeout_infinity(_) ->
	doc("Ensure infinity for domain_lookup_timeout is accepted."),
	do_timeout(domain_lookup_timeout, infinity).

do_timeout(Opt, Timeout) ->
	{ok, Pid} = gun:open("localhost", 12345, #{Opt => Timeout, retry => 0}),
	Ref = monitor(process, Pid),
	receive
		{'DOWN', Ref, process, Pid, {shutdown, _}} ->
			ok
	after 2000 ->
		%% This is not an error, the timeout was accepted but
		%% the connect or domain lookup is just taking too long,
		%% for example when it was set to infinity.
		gun:close(Pid)
	end.

ignore_empty_data_http(_) ->
	doc("When gun:data/4 is called with nofin and empty data, it must be ignored."),
	{ok, OriginPid, OriginPort} = init_origin(tcp, http),
	{ok, Pid} = gun:open("localhost", OriginPort),
	{ok, http} = gun:await_up(Pid),
	handshake_completed = receive_from(OriginPid),
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
	handshake_completed = receive_from(OriginPid),
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
	gun:close(Pid).

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

killed_streams_http(_) ->
	doc("Ensure completed responses with a connection: close are not considered killed streams."),
	{ok, _, OriginPort} = init_origin(tcp, http,
		fun (_, ClientSocket, ClientTransport) ->
			{ok, _} = ClientTransport:recv(ClientSocket, 0, 1000),
			ClientTransport:send(ClientSocket,
				"HTTP/1.1 200 OK\r\n"
				"connection: close\r\n"
				"content-length: 12\r\n"
				"\r\n"
				"hello world!"
			)
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:get(ConnPid, "/"),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
	{ok, <<"hello world!">>} = gun:await_body(ConnPid, StreamRef),
	receive
		{gun_down, ConnPid, http, normal, KilledStreams} ->
			[] = KilledStreams,
			gun:close(ConnPid)
	after 1000 ->
		error(timeout)
	end.

list_header_name(_) ->
	doc("Header names may be given as list."),
	{ok, OriginPid, OriginPort} = init_origin(tcp, http),
	{ok, Pid} = gun:open("localhost", OriginPort),
	{ok, http} = gun:await_up(Pid),
	handshake_completed = receive_from(OriginPid),
	_ = gun:get(Pid, "/", [
		{"User-Agent", "Gun/list-headers"}
	]),
	Data = receive_from(OriginPid),
	Lines = binary:split(Data, <<"\r\n">>, [global]),
	[<<"user-agent: Gun/list-headers">>] = [L || <<"user-agent: ", _/bits>> = L <- Lines],
	gun:close(Pid).

map_headers(_) ->
	doc("Header names may be given as a map."),
	{ok, OriginPid, OriginPort} = init_origin(tcp, http),
	{ok, Pid} = gun:open("localhost", OriginPort),
	{ok, http} = gun:await_up(Pid),
	handshake_completed = receive_from(OriginPid),
	_ = gun:get(Pid, "/", #{
		<<"USER-agent">> => "Gun/map-headers"
	}),
	Data = receive_from(OriginPid),
	Lines = binary:split(Data, <<"\r\n">>, [global]),
	[<<"user-agent: Gun/map-headers">>] = [L || <<"user-agent: ", _/bits>> = L <- Lines],
	gun:close(Pid).

postpone_request_while_not_connected(_) ->
	doc("Ensure Gun doesn't raise error when requesting in retries"),
	%% Try connecting to a server that isn't up yet.
	{ok, Pid} = gun:open("localhost", 23456, #{retry => 5, retry_timeout => 1000}),
	_ = gun:get(Pid, "/postponed"),
	%% Make sure the connect call completed and we are waiting for a retry.
	Timeout = case os:type() of
		{win32, _} -> 2500;
		_ -> 500
	end,
	timer:sleep(Timeout),
	%% Start the server so that next retry will result in the client connecting successfully.
	{ok, ListenSocket} = gen_tcp:listen(23456, [binary, {active, false}, {reuseaddr, true}]),
	{ok, ClientSocket} = gen_tcp:accept(ListenSocket, 5000),
	%% The client should now be up.
	{ok, http} = gun:await_up(Pid),
	%% The server receives the postponed request.
	{ok, <<"GET /postponed HTTP/1.1\r\n", _/bits>>} = gen_tcp:recv(ClientSocket, 0, 5000),
	ok.

reply_to(_) ->
	doc("The reply_to option allows using a separate process for requests."),
	do_reply_to(http),
	do_reply_to(http2).

do_reply_to(Protocol) ->
	{ok, ListenSocket} = gen_tcp:listen(0, [binary, {active, false}, {nodelay, true}]),
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
			gun:close(Pid)
	after 1000 ->
		error(timeout)
	end.

retry_0(_) ->
	doc("Ensure Gun gives up immediately with retry=0."),
	{ok, Pid} = gun:open("localhost", 12345, #{retry => 0, retry_timeout => 500}),
	Ref = monitor(process, Pid),
	%% On Windows when the connection is refused the OS will retry
	%% 3 times before giving up, with a 500ms delay between tries.
	%% This adds approximately 1 second to connection failures.
	After = case os:type() of
		{win32, _} -> 1200;
		_ -> 200
	end,
	receive
		{'DOWN', Ref, process, Pid, {shutdown, _}} ->
			ok
	after After ->
		error(timeout)
	end.

retry_0_disconnect(_) ->
	doc("Ensure Gun gives up immediately with retry=0 after a successful connection."),
	{ok, ListenSocket} = gen_tcp:listen(0, [binary, {active, false}]),
	{ok, {_, Port}} = inet:sockname(ListenSocket),
	{ok, Pid} = gun:open("localhost", Port, #{retry => 0, retry_timeout => 500}),
	Ref = monitor(process, Pid),
	%% On Windows when the connection is refused the OS will retry
	%% 3 times before giving up, with a 500ms delay between tries.
	%% This adds approximately 1 second to connection failures.
	After = case os:type() of
		{win32, _} -> 1200;
		_ -> 200
	end,
	%% We accept the connection and then close it to trigger a disconnect.
	{ok, ClientSocket} = gen_tcp:accept(ListenSocket, 5000),
	gen_tcp:close(ClientSocket),
	receive
		{'DOWN', Ref, process, Pid, {shutdown, _}} ->
			ok
	after After ->
		error(timeout)
	end.

retry_1(_) ->
	doc("Ensure Gun gives up with retry=1."),
	{ok, Pid} = gun:open("localhost", 12345, #{retry => 1, retry_timeout => 500}),
	Ref = monitor(process, Pid),
	After = case os:type() of
		{win32, _} -> 2700;
		_ -> 700
	end,
	receive
		{'DOWN', Ref, process, Pid, {shutdown, _}} ->
			ok
	after After ->
		error(timeout)
	end.

retry_1_disconnect(_) ->
	doc("Ensure Gun gives up with retry=1 after a successful connection."),
	{ok, ListenSocket} = gen_tcp:listen(0, [binary, {active, false}]),
	{ok, {_, Port}} = inet:sockname(ListenSocket),
	{ok, Pid} = gun:open("localhost", Port, #{retry => 1, retry_timeout => 500}),
	%% We accept the connection and then close it to trigger a disconnect.
	{ok, ClientSocket} = gen_tcp:accept(ListenSocket, 5000),
	gen_tcp:close(ClientSocket),
	%% We confirm that Gun reconnects immediately.
	{ok, _} = gen_tcp:accept(ListenSocket, 200),
	gun:close(Pid).

retry_fun(_) ->
	doc("Ensure the retry_fun is used when provided."),
	{ok, Pid} = gun:open("localhost", 12345, #{
		retry => 5,
		retry_fun => fun(_, _) -> #{retries => 0, timeout => 500} end,
		retry_timeout => 5000
	}),
	Ref = monitor(process, Pid),
	After = case os:type() of
		{win32, _} -> 2800;
		_ -> 800
	end,
	receive
		{'DOWN', Ref, process, Pid, {shutdown, _}} ->
			ok
	after After ->
		error(shutdown_too_late)
	end.

retry_timeout(_) ->
	doc("Ensure the retry_timeout value is enforced. The first retry is immediate "
		"and therefore does not use the timeout."),
	{ok, Pid} = gun:open("localhost", 12345, #{retry => 2, retry_timeout => 1000}),
	Ref = monitor(process, Pid),
	After = case os:type() of
		{win32, _} -> 2800;
		_ -> 800
	end,
	receive
		{'DOWN', Ref, process, Pid, {shutdown, _}} ->
			error(shutdown_too_early)
	after After ->
		ok
	end,
	receive
		{'DOWN', Ref, process, Pid, {shutdown, _}} ->
			ok
	after After ->
		error(shutdown_too_late)
	end.

set_owner(_) ->
	doc("The owner of the connection can be changed."),
	Self = self(),
	Pid = spawn(fun() ->
		{ok, ConnPid} = gun:open("localhost", 12345),
		gun:set_owner(ConnPid, Self),
		Self ! {conn, ConnPid}
	end),
	Ref = monitor(process, Pid),
	receive {'DOWN', Ref, process, Pid, _} -> ok after 1000 -> error(timeout) end,
	ConnPid = receive {conn, C} -> C after 1000 -> error(timeout) end,
	#{owner := Self} = gun:info(ConnPid),
	gun:close(ConnPid).

shutdown_reason(_) ->
	doc("The last connection failure must be propagated."),
	{ok, Pid} = gun:open("localhost", 12345, #{retry => 0}),
	Ref = monitor(process, Pid),
	After = case os:type() of
		{win32, _} -> 1200;
		_ -> 200
	end,
	receive
		{'DOWN', Ref, process, Pid, {shutdown, econnrefused}} ->
			ok
	after After ->
		error(timeout)
	end.

stream_info_http(_) ->
	doc("Ensure the function gun:stream_info/2 works as expected for HTTP/1.1."),
	{ok, _, OriginPort} = init_origin(tcp, http,
		fun(_, ClientSocket, ClientTransport) ->
			%% Give some time to detect the cancel.
			timer:sleep(200),
			%% Then terminate the stream.
			ClientTransport:send(ClientSocket,
				"HTTP/1.1 200 OK\r\n"
				"content-length: 0\r\n"
				"\r\n"
			),
			timer:sleep(400)
		end),
	{ok, Pid} = gun:open("localhost", OriginPort),
	{ok, http} = gun:await_up(Pid),
	{ok, undefined} = gun:stream_info(Pid, make_ref()),
	StreamRef = gun:get(Pid, "/"),
	Self = self(),
	{ok, #{
		ref := StreamRef,
		reply_to := Self,
		state := running
	}} = gun:stream_info(Pid, StreamRef),
	gun:cancel(Pid, StreamRef),
	{ok, #{
		ref := StreamRef,
		reply_to := Self,
		state := stopping
	}} = gun:stream_info(Pid, StreamRef),
	%% Wait a little for the stream to terminate.
	timer:sleep(400),
	{ok, undefined} = gun:stream_info(Pid, StreamRef),
	%% Wait a little more for the connection to terminate.
	timer:sleep(400),
	{error, not_connected} = gun:stream_info(Pid, StreamRef),
	gun:close(Pid).

stream_info_http2(_) ->
	doc("Ensure the function gun:stream_info/2 works as expected for HTTP/2."),
	{ok, OriginPid, OriginPort} = init_origin(tcp, http2,
		fun(_, _, _) -> timer:sleep(200) end),
	{ok, Pid} = gun:open("localhost", OriginPort, #{
		protocols => [http2]
	}),
	{ok, http2} = gun:await_up(Pid),
	handshake_completed = receive_from(OriginPid),
	{ok, undefined} = gun:stream_info(Pid, make_ref()),
	StreamRef = gun:get(Pid, "/"),
	Self = self(),
	{ok, #{
		ref := StreamRef,
		reply_to := Self,
		state := running
	}} = gun:stream_info(Pid, StreamRef),
	gun:cancel(Pid, StreamRef),
	%% Wait a little for the connection to terminate.
	timer:sleep(300),
	{error, not_connected} = gun:stream_info(Pid, StreamRef),
	gun:close(Pid).

supervise_false(_) ->
	doc("The supervise option allows starting without a supervisor."),
	{ok, _, OriginPort} = init_origin(tcp, http),
	{ok, Pid} = gun:open("localhost", OriginPort, #{supervise => false}),
	{ok, http} = gun:await_up(Pid),
	[] = [P || {_, P, _, _} <- supervisor:which_children(gun_sup), P =:= Pid],
	ok.

tls_handshake_timeout(_) ->
	doc("Ensure an integer value for tls_handshake_timeout is accepted."),
	do_timeout(tls_handshake_timeout, 1000).

tls_handshake_timeout_infinity(_) ->
	doc("Ensure infinity for tls_handshake_timeout is accepted."),
	do_timeout(tls_handshake_timeout, infinity).

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
	gun:close(Pid).

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
			gun:close(Pid)
	after 250 ->
		error(timeout)
	end.

uppercase_header_name(_) ->
	doc("Header names may be given with uppercase characters."),
	{ok, OriginPid, OriginPort} = init_origin(tcp, http),
	{ok, Pid} = gun:open("localhost", OriginPort),
	{ok, http} = gun:await_up(Pid),
	handshake_completed = receive_from(OriginPid),
	_ = gun:get(Pid, "/", [
		{<<"USER-agent">>, "Gun/uppercase-headers"}
	]),
	Data = receive_from(OriginPid),
	Lines = binary:split(Data, <<"\r\n">>, [global]),
	[<<"user-agent: Gun/uppercase-headers">>] = [L || <<"user-agent: ", _/bits>> = L <- Lines],
	gun:close(Pid).
