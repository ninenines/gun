%% Copyright (c) 2017-2020, Loïc Hoguin <essen@ninenines.eu>
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
-import(gun_test_event_h, [receive_event/1]).
-import(gun_test_event_h, [receive_event/2]).

suite() ->
	[{timetrap, 30000}].

all() ->
	[{group, gun}].

groups() ->
	[{gun, [parallel], ct_helper:all(?MODULE)}].

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
	{ok, ConnPid} = gun:open("localhost", 12345, #{
		Opt => Timeout,
		event_handler => {gun_test_event_h, self()},
		retry => 0
	}),
	%% The connection will not succeed. We will however receive
	%% an init event from the connection process that indicates
	%% that the timeout value was accepted, since the timeout
	%% checks occur earlier.
	{_, init, _} = receive_event(ConnPid),
	gun:close(ConnPid).

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

ignore_empty_data_fin_http(_) ->
	doc("When gun:data/4 is called with fin and empty data, it must send a final empty chunk."),
	{ok, OriginPid, OriginPort} = init_origin(tcp, http),
	{ok, Pid} = gun:open("localhost", OriginPort),
	{ok, http} = gun:await_up(Pid),
	handshake_completed = receive_from(OriginPid),
	Ref = gun:post(Pid, "/", []),
	gun:data(Pid, Ref, nofin, "hello"),
	gun:data(Pid, Ref, fin, ["", <<>>]),
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

ignore_empty_data_fin_http2(_) ->
	doc("When gun:data/4 is called with fin and empty data, it must send a final empty DATA frame."),
	{ok, OriginPid, OriginPort} = init_origin(tcp, http2),
	{ok, Pid} = gun:open("localhost", OriginPort, #{protocols => [http2]}),
	{ok, http2} = gun:await_up(Pid),
	handshake_completed = receive_from(OriginPid),
	Ref = gun:put(Pid, "/", []),
	gun:data(Pid, Ref, nofin, "hello "),
	gun:data(Pid, Ref, nofin, "world!"),
	gun:data(Pid, Ref, fin, ["", <<>>]),
	Data = receive_all_from(OriginPid, 500),
	<<
		%% HEADERS frame.
		Len1:24, 1, _:40, _:Len1/unit:8,
		%% First DATA frame.
		6:24, 0, _:7, 0:1, _:32, "hello ",
		%% Second DATA frame.
		6:24, 0, _:7, 0:1, _:32, "world!",
		%% Final empty DATA frame.
		0:24, 0, _:7, 1:1, _:32
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
	{ok, ConnPid} = gun:open("localhost", 12345, #{
		event_handler => {gun_test_event_h, self()},
		http_opts => #{keepalive => infinity},
		http2_opts => #{keepalive => infinity},
		retry => 0
	}),
	%% The connection will not succeed. We will however receive
	%% an init event from the connection process that indicates
	%% that the timeout value was accepted, since the timeout
	%% checks occur earlier.
	{_, init, _} = receive_event(ConnPid),
	gun:close(ConnPid).

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
	{ok, ConnPid} = gun:open("localhost", 23456, #{
		event_handler => {gun_test_event_h, self()},
		retry => 5,
		retry_timeout => 1000
	}),
	_ = gun:get(ConnPid, "/postponed"),
	%% Wait for the connection attempt. to fail.
	{_, connect_end, #{error := _}} = receive_event(ConnPid, connect_end),
	%% Start the server so that next retry will result in the client connecting successfully.
	{ok, ListenSocket} = gen_tcp:listen(23456, [binary, {active, false}, {reuseaddr, true}]),
	{ok, ClientSocket} = gen_tcp:accept(ListenSocket, 5000),
	%% The client should now be up.
	{ok, http} = gun:await_up(ConnPid),
	%% The server receives the postponed request.
	{ok, <<"GET /postponed HTTP/1.1\r\n", _/bits>>} = gen_tcp:recv(ClientSocket, 0, 5000),
	gun:close(ConnPid).

reply_to_http(_) ->
	doc("The reply_to option allows using a separate process for requests."),
	do_reply_to(http).

reply_to_http2(_) ->
	doc("The reply_to option allows using a separate process for requests."),
	do_reply_to(http2).

do_reply_to(Protocol) ->
	{ok, OriginPid, OriginPort} = init_origin(tcp, Protocol,
		fun(_, ClientSocket, ClientTransport) ->
			{ok, _} = ClientTransport:recv(ClientSocket, 0, infinity),
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
			ok = ClientTransport:send(ClientSocket, ResponseData),
			timer:sleep(1000)
		end),
	{ok, Pid} = gun:open("localhost", OriginPort, #{protocols => [Protocol]}),
	{ok, Protocol} = gun:await_up(Pid),
	handshake_completed = receive_from(OriginPid),
	Self = self(),
	ReplyTo = spawn(fun() ->
		receive Ref when is_reference(Ref) ->
			Response = gun:await(Pid, Ref, infinity),
			Self ! Response
		end
	end),
	Ref = gun:get(Pid, "/", [], #{reply_to => ReplyTo}),
	ReplyTo ! Ref,
	receive
		Msg ->
			{response, _, _, _} = Msg,
			gun:close(Pid)
	end.

retry_0(_) ->
	doc("Ensure Gun gives up immediately with retry=0."),
	{ok, ConnPid} = gun:open("localhost", 12345, #{
		event_handler => {gun_test_event_h, self()},
		retry => 0,
		retry_timeout => 500
	}),
	{_, init, _} = receive_event(ConnPid),
	{_, domain_lookup_start, _} = receive_event(ConnPid),
	{_, domain_lookup_end, _} = receive_event(ConnPid),
	{_, connect_start, _} = receive_event(ConnPid),
	{_, connect_end, #{error := _}} = receive_event(ConnPid),
	{_, terminate, _} = receive_event(ConnPid),
	ok.

retry_0_disconnect(_) ->
	doc("Ensure Gun gives up immediately with retry=0 after a successful connection."),
	{ok, ListenSocket} = gen_tcp:listen(0, [binary, {active, false}]),
	{ok, {_, Port}} = inet:sockname(ListenSocket),
	{ok, ConnPid} = gun:open("localhost", Port, #{
		event_handler => {gun_test_event_h, self()},
		retry => 0,
		retry_timeout => 500
	}),
	{_, init, _} = receive_event(ConnPid),
	{_, domain_lookup_start, _} = receive_event(ConnPid),
	{_, domain_lookup_end, _} = receive_event(ConnPid),
	{_, connect_start, _} = receive_event(ConnPid),
	%% We accept the connection and then close it to trigger a disconnect.
	{ok, ClientSocket} = gen_tcp:accept(ListenSocket, 5000),
	gen_tcp:close(ClientSocket),
	%% Connection was successful.
	{_, connect_end, ConnectEndEvent} = receive_event(ConnPid),
	false = maps:is_key(error, ConnectEndEvent),
	%% When the connection is closed we terminate immediately.
	{_, disconnect, _} = receive_event(ConnPid),
	{_, terminate, _} = receive_event(ConnPid),
	ok.

retry_1(_) ->
	doc("Ensure Gun gives up with retry=1."),
	{ok, ConnPid} = gun:open("localhost", 12345, #{
		event_handler => {gun_test_event_h, self()},
		retry => 1,
		retry_timeout => 500
	}),
	{_, init, _} = receive_event(ConnPid),
	%% Initial attempt.
	{_, domain_lookup_start, _} = receive_event(ConnPid),
	{_, domain_lookup_end, _} = receive_event(ConnPid),
	{_, connect_start, _} = receive_event(ConnPid),
	{_, connect_end, #{error := _}} = receive_event(ConnPid),
	%% Retry.
	{_, domain_lookup_start, _} = receive_event(ConnPid),
	{_, domain_lookup_end, _} = receive_event(ConnPid),
	{_, connect_start, _} = receive_event(ConnPid),
	{_, connect_end, #{error := _}} = receive_event(ConnPid),
	{_, terminate, _} = receive_event(ConnPid),
	ok.

retry_1_disconnect(_) ->
	doc("Ensure Gun doesn't give up with retry=1 after a successful connection "
		"and attempts to reconnect immediately, ignoring retry_timeout."),
	{ok, ListenSocket} = gen_tcp:listen(0, [binary, {active, false}]),
	{ok, {_, Port}} = inet:sockname(ListenSocket),
	{ok, ConnPid} = gun:open("localhost", Port, #{
		event_handler => {gun_test_event_h, self()},
		retry => 1,
		retry_timeout => 30000
	}),
	{_, init, _} = receive_event(ConnPid),
	{_, domain_lookup_start, _} = receive_event(ConnPid),
	{_, domain_lookup_end, _} = receive_event(ConnPid),
	{_, connect_start, _} = receive_event(ConnPid),
	%% We accept the connection and then close it to trigger a disconnect.
	{ok, ClientSocket} = gen_tcp:accept(ListenSocket, 5000),
	gen_tcp:close(ClientSocket),
	%% Connection was successful.
	{_, connect_end, ConnectEndEvent} = receive_event(ConnPid),
	false = maps:is_key(error, ConnectEndEvent),
	%% We confirm that Gun reconnects before the retry timeout,
	%% as it is ignored on the first reconnection.
	{ok, _} = gen_tcp:accept(ListenSocket, 5000),
	gun:close(ConnPid).

retry_fun(_) ->
	doc("Ensure the retry_fun is used when provided."),
	{ok, ConnPid} = gun:open("localhost", 12345, #{
		event_handler => {gun_test_event_h, self()},
		retry => 5,
		retry_fun => fun(_, _) -> #{retries => 0, timeout => 0} end,
		retry_timeout => 60000
	}),
	{_, init, _} = receive_event(ConnPid),
	%% Initial attempt.
	{_, domain_lookup_start, _} = receive_event(ConnPid),
	{_, domain_lookup_end, _} = receive_event(ConnPid),
	{_, connect_start, _} = receive_event(ConnPid),
	{_, connect_end, #{error := _}} = receive_event(ConnPid),
	%% When retry is not disabled (retry!=0) we necessarily
	%% have at least one retry attempt using the fun.
	{_, domain_lookup_start, _} = receive_event(ConnPid),
	{_, domain_lookup_end, _} = receive_event(ConnPid),
	{_, connect_start, _} = receive_event(ConnPid),
	{_, connect_end, #{error := _}} = receive_event(ConnPid),
	{_, terminate, _} = receive_event(ConnPid),
	ok.

retry_timeout(_) ->
	doc("Ensure the retry_timeout value is enforced. The first retry is immediate "
		"and therefore does not use the timeout."),
	{ok, ConnPid} = gun:open("localhost", 12345, #{
		event_handler => {gun_test_event_h, self()},
		retry => 2,
		retry_timeout => 1000
	}),
	{_, init, _} = receive_event(ConnPid),
	%% Initial attempt.
	{_, domain_lookup_start, _} = receive_event(ConnPid),
	{_, domain_lookup_end, _} = receive_event(ConnPid),
	{_, connect_start, _} = receive_event(ConnPid),
	{_, connect_end, #{error := _, ts := TS1}} = receive_event(ConnPid),
	%% First retry is immediate.
	{_, domain_lookup_start, #{ts := TS2}} = receive_event(ConnPid),
	true = (TS2 - TS1) < 1000,
	{_, domain_lookup_end, _} = receive_event(ConnPid),
	{_, connect_start, _} = receive_event(ConnPid),
	{_, connect_end, #{error := _, ts := TS3}} = receive_event(ConnPid),
	%% Second retry occurs after the retry_timeout.
	{_, domain_lookup_start, #{ts := TS4}} = receive_event(ConnPid),
	true = (TS4 - TS3) >= 1000,
	{_, domain_lookup_end, _} = receive_event(ConnPid),
	{_, connect_start, _} = receive_event(ConnPid),
	{_, connect_end, #{error := _}} = receive_event(ConnPid),
	{_, terminate, _} = receive_event(ConnPid),
	ok.

server_name_indication_custom(_) ->
	doc("Ensure a custom server_name_indication is accepted."),
	do_server_name_indication("localhost", net_adm:localhost(), #{
		tls_opts => [{server_name_indication, net_adm:localhost()}]
	}).

server_name_indication_default(_) ->
	doc("Ensure a default server_name_indication is accepted."),
	do_server_name_indication(net_adm:localhost(), net_adm:localhost(), #{}).

do_server_name_indication(Host, Expected, GunOpts) ->
	Self = self(),
	{ok, OriginPid, OriginPort} = init_origin(tls, http,
		fun(_, ClientSocket, _) ->
			{ok, Info} = ssl:connection_information(ClientSocket),
			Msg = {sni_hostname, _} = lists:keyfind(sni_hostname, 1, Info),
			Self ! Msg
		end),
	{ok, ConnPid} = gun:open(Host, OriginPort, GunOpts#{
		transport => tls,
		retry => 0
	}),
	handshake_completed = receive_from(OriginPid),
	%% The connection will succeed, look up the SNI hostname
	%% and send it to us as a message, where we can check it.
	{sni_hostname, Expected} = receive Msg = {sni_hostname, _} -> Msg end,
	gun:close(ConnPid).

set_owner(_) ->
	doc("The owner of the connection can be changed."),
	Self = self(),
	spawn(fun() ->
		{ok, ConnPid} = gun:open("localhost", 12345),
		gun:set_owner(ConnPid, Self),
		Self ! {conn, ConnPid}
	end),
	ConnPid = receive {conn, C} -> C end,
	#{owner := Self} = gun:info(ConnPid),
	gun:close(ConnPid).

shutdown_reason(_) ->
	doc("The last connection failure must be propagated."),
	do_shutdown_reason().

do_shutdown_reason() ->
	%% We set retry=1 so that we can monitor before the process terminates.
	{ok, ConnPid} = gun:open("localhost", 12345, #{
		retry => 1,
		retry_timeout => 500
	}),
	Ref = monitor(process, ConnPid),
	receive
		%% Depending on timings we may monitor AFTER the process already
		%% failed to connect and exited. In that case we just try again.
		%% We rely on timetrap_timeout to stop the test if it takes too long.
		{'DOWN', Ref, process, ConnPid, noproc} ->
			ct:log("Monitor got noproc, trying again..."),
			do_shutdown_reason();
		{'DOWN', Ref, process, ConnPid, Reason} ->
			{shutdown, econnrefused} = Reason,
			gun:close(ConnPid)
	end.

stream_info_http(_) ->
	doc("Ensure the function gun:stream_info/2 works as expected for HTTP/1.1."),
	{ok, OriginPid, OriginPort} = init_origin(tcp, http,
		fun(_, ClientSocket, ClientTransport) ->
			%% Wait for the cancel signal.
			receive cancel -> ok end,
			%% Then terminate the stream.
			ClientTransport:send(ClientSocket,
				"HTTP/1.1 200 OK\r\n"
				"content-length: 0\r\n"
				"\r\n"
			),
			receive disconnect -> ok end
		end),
	{ok, Pid} = gun:open("localhost", OriginPort, #{
		event_handler => {gun_test_event_h, self()}
	}),
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
	OriginPid ! cancel,
	{ok, #{
		ref := StreamRef,
		reply_to := Self,
		state := stopping
	}} = gun:stream_info(Pid, StreamRef),
	%% Wait for the stream to be canceled.
	receive_event(Pid, cancel),
	fun F() ->
		case gun:stream_info(Pid, StreamRef) of
			{ok, undefined} -> ok;
			{ok, #{state := stopping}} -> F()
		end
	end(),
	%% Wait for the connection to terminate.
	OriginPid ! disconnect,
	receive_event(Pid, disconnect),
	{error, not_connected} = gun:stream_info(Pid, StreamRef),
	gun:close(Pid).

stream_info_http2(_) ->
	doc("Ensure the function gun:stream_info/2 works as expected for HTTP/2."),
	{ok, OriginPid, OriginPort} = init_origin(tcp, http2,
		fun(_, _, _) -> receive disconnect -> ok end end),
	{ok, Pid} = gun:open("localhost", OriginPort, #{
		event_handler => {gun_test_event_h, self()},
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
	%% Wait for the connection to terminate.
	OriginPid ! disconnect,
	receive_event(Pid, disconnect),
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
