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

-module(ws_SUITE).
-compile(export_all).
-compile(nowarn_export_all).

-import(ct_helper, [config/2]).
-import(ct_helper, [doc/1]).
-import(gun_test, [init_origin/3]).

%% ct.

all() ->
	[{group, http}, {group, http2}].

groups() ->
	Tests = ct_helper:all(?MODULE),
	HTTP1Tests = [
		http10_upgrade_error,
		http11_request_error,
		http11_keepalive,
		http11_keepalive_default_silence_pings,
		max_frame_size_compressed,
		max_frame_size_control_during_fragment,
		max_frame_size_fragmented,
		max_frame_size_infinity,
		max_frame_size_single,
		reject_masked_frame_from_server,
		unix_socket_hostname
	],
	[
		{http, [], Tests},
		{http2, [], Tests -- HTTP1Tests}
	].

init_per_suite(Config) ->
	Routes = [
		{"/", ws_echo_h, []},
		{"/reject", ws_reject_h, []},
		{"/subprotocol", ws_subprotocol_h, []}
	],
	{ok, _} = cowboy:start_clear(ws, [], #{
		enable_connect_protocol => true,
		env => #{dispatch => cowboy_router:compile([{'_', Routes}])}
	}),
	Port = ranch:get_port(ws),
	[{port, Port}|Config].

end_per_suite(_) ->
	cowboy:stop_listener(ws).

%% Tests.

await(Config) ->
	doc("Ensure gun:await/2 can be used to receive Websocket frames."),
	Protocol = config(name, config(tc_group_properties, Config)),
	{ok, ConnPid} = gun:open("localhost", config(port, Config), #{
		protocols => [Protocol],
		http2_opts => #{notify_settings_changed => true}
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	do_await_enable_connect_protocol(Protocol, ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/", []),
	{upgrade, [<<"websocket">>], _} = gun:await(ConnPid, StreamRef),
	Frame = {text, <<"Hello!">>},
	gun:ws_send(ConnPid, StreamRef, Frame),
	{ws, Frame} = gun:await(ConnPid, StreamRef),
	gun:close(ConnPid).

headers_normalized_upgrade(Config) ->
	doc("Headers passed to ws_upgrade are normalized before being used."),
	Protocol = config(name, config(tc_group_properties, Config)),
	{ok, ConnPid} = gun:open("localhost", config(port, Config), #{
		protocols => [Protocol],
		http2_opts => #{notify_settings_changed => true}
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	do_await_enable_connect_protocol(Protocol, ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/", #{
		atom_header_name => <<"value">>,
		"string_header_name" => <<"value">>
	}),
	{upgrade, [<<"websocket">>], _} = gun:await(ConnPid, StreamRef),
	gun:close(ConnPid).

http10_upgrade_error(Config) ->
	doc("Attempting to upgrade HTTP/1.0 to Websocket produces an error."),
	{ok, ConnPid} = gun:open("localhost", config(port, Config), #{
		http_opts => #{version => 'HTTP/1.0'}
	}),
	{ok, _} = gun:await_up(ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/", []),
	receive
		{gun_error, ConnPid, StreamRef, {badstate, _}} ->
			gun:close(ConnPid);
		Msg ->
			error({fail, Msg})
	after 1000 ->
		error(timeout)
	end.

http11_keepalive(Config) ->
	doc("Ensure that Gun automatically sends ping frames."),
	{ok, ConnPid} = gun:open("localhost", config(port, Config), #{
		ws_opts => #{
			keepalive => 100,
			silence_pings => false
		}
	}),
	{ok, _} = gun:await_up(ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/", []),
	{upgrade, [<<"websocket">>], _} = gun:await(ConnPid, StreamRef),
	%% Gun sent a ping automatically, we therefore receive a pong.
	{ws, pong} = gun:await(ConnPid, StreamRef),
	gun:close(ConnPid).

http11_keepalive_default_silence_pings(Config) ->
	doc("Ensure that Gun does not forward ping/pong by default."),
	{ok, ConnPid} = gun:open("localhost", config(port, Config), #{
		ws_opts => #{keepalive => 100}
	}),
	{ok, _} = gun:await_up(ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/", []),
	{upgrade, [<<"websocket">>], _} = gun:await(ConnPid, StreamRef),
	%% Gun sent a ping automatically, but we silence ping/pong by default.
	{error, timeout} = gun:await(ConnPid, StreamRef, 1000),
	gun:close(ConnPid).

max_frame_size_compressed(_) ->
	doc("A compressed Websocket frame whose inflated size exceeds "
		"max_frame_size must close the connection even when its "
		"wire size does not."),
	{ok, _, OriginPort} = init_origin(tcp, http,
		fun(_, _, ClientSocket, ClientTransport) ->
			{ok, ReqData} = ClientTransport:recv(ClientSocket, 0, 5000),
			Lines = binary:split(ReqData, <<"\r\n">>, [global]),
			[KeyLine] = [L || <<"sec-websocket-key: ", _/bits>> = L <- Lines],
			<<"sec-websocket-key: ", Key/bits>> = KeyLine,
			Accept = cow_ws:encode_key(Key),
			ok = ClientTransport:send(ClientSocket, [
				"HTTP/1.1 101 Switching Protocols\r\n"
				"connection: upgrade\r\n"
				"upgrade: websocket\r\n"
				"sec-websocket-accept: ", Accept, "\r\n"
				"sec-websocket-extensions: permessage-deflate\r\n"
				"\r\n"
			]),
			Z = zlib:open(),
			ok = zlib:deflateInit(Z, default, deflated, -15, 8, default),
			Payload = binary:copy(<<0>>, 1000000),
			Deflated = iolist_to_binary(zlib:deflate(Z, Payload, sync)),
			zlib:close(Z),
			CompressedSize = byte_size(Deflated) - 4,
			true = CompressedSize < 1000,
			<<Compressed:CompressedSize/binary, 0, 0, 255, 255>> = Deflated,
			Frame = <<1:1, 1:1, 0:2, 2:4, 0:1, 126:7, CompressedSize:16, Compressed/binary>>,
			ok = ClientTransport:send(ClientSocket, Frame),
			{ok, CloseData} = ClientTransport:recv(ClientSocket, 0, 5000),
			1009 = do_ws_close_code(CloseData),
			ok = ClientTransport:close(ClientSocket)
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort, #{protocols => [http]}),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/", [], #{compress => true, max_frame_size => 1000}),
	{upgrade, _, _} = gun:await(ConnPid, StreamRef),
	receive
		{gun_ws, ConnPid, StreamRef, _} ->
			error(unexpected_ws_frame);
		{gun_down, ConnPid, ws, _, _} ->
			ok
	after 5000 ->
		error(timeout)
	end,
	gun:close(ConnPid).

max_frame_size_control_during_fragment(_) ->
	doc("A ping interleaved with a fragmented message must not count "
		"toward max_frame_size of that message. (RFC6455 5.4)"),
	{ok, _, OriginPort} = init_origin(tcp, http,
		fun(_, _, ClientSocket, ClientTransport) ->
			{ok, ReqData} = ClientTransport:recv(ClientSocket, 0, 5000),
			Lines = binary:split(ReqData, <<"\r\n">>, [global]),
			[KeyLine] = [L || <<"sec-websocket-key: ", _/bits>> = L <- Lines],
			<<"sec-websocket-key: ", Key/bits>> = KeyLine,
			Accept = cow_ws:encode_key(Key),
			ok = ClientTransport:send(ClientSocket, [
				"HTTP/1.1 101 Switching Protocols\r\n"
				"connection: upgrade\r\n"
				"upgrade: websocket\r\n"
				"sec-websocket-accept: ", Accept, "\r\n"
				"\r\n"
			]),
			Chunk = binary:copy(<<"a">>, 30),
			Frag1 = <<0:1, 0:3, 1:4, 0:1, 30:7, Chunk/binary>>,
			Ping = <<1:1, 0:3, 9:4, 0:1, 50:7, (binary:copy(<<"p">>, 50))/binary>>,
			Frag2 = <<0:1, 0:3, 0:4, 0:1, 30:7, Chunk/binary>>,
			Frag3 = <<1:1, 0:3, 0:4, 0:1, 30:7, Chunk/binary>>,
			ok = ClientTransport:send(ClientSocket, [Frag1, Ping, Frag2, Frag3]),
			{ok, PongData} = ClientTransport:recv(ClientSocket, 0, 5000),
			<<1:1, 0:3, 10:4, 1:1, _:7, _/bits>> = PongData,
			receive after infinity -> ok end
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort, #{protocols => [http]}),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/", [], #{max_frame_size => 100}),
	{upgrade, _, _} = gun:await(ConnPid, StreamRef),
	{ws, {text, Data}} = gun:await(ConnPid, StreamRef),
	Data = binary:copy(<<"a">>, 90),
	gun:close(ConnPid).

max_frame_size_fragmented(_) ->
	doc("A fragmented Websocket message larger in total than max_frame_size "
		"must close the connection instead of being buffered without bound."),
	{ok, _, OriginPort} = init_origin(tcp, http,
		fun(_, _, ClientSocket, ClientTransport) ->
			{ok, ReqData} = ClientTransport:recv(ClientSocket, 0, 5000),
			Lines = binary:split(ReqData, <<"\r\n">>, [global]),
			[KeyLine] = [L || <<"sec-websocket-key: ", _/bits>> = L <- Lines],
			<<"sec-websocket-key: ", Key/bits>> = KeyLine,
			Accept = cow_ws:encode_key(Key),
			ok = ClientTransport:send(ClientSocket, [
				"HTTP/1.1 101 Switching Protocols\r\n"
				"connection: upgrade\r\n"
				"upgrade: websocket\r\n"
				"sec-websocket-accept: ", Accept, "\r\n"
				"\r\n"
			]),
			Chunk = binary:copy(<<"a">>, 80),
			Frame1 = <<0:1, 0:3, 1:4, 0:1, (byte_size(Chunk)):7, Chunk/binary>>,
			Frame2 = <<0:1, 0:3, 0:4, 0:1, (byte_size(Chunk)):7, Chunk/binary>>,
			ok = ClientTransport:send(ClientSocket, [Frame1, Frame2]),
			{ok, CloseData} = ClientTransport:recv(ClientSocket, 0, 5000),
			1009 = do_ws_close_code(CloseData),
			ok = ClientTransport:close(ClientSocket)
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort, #{protocols => [http]}),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/", [], #{max_frame_size => 100}),
	{upgrade, _, _} = gun:await(ConnPid, StreamRef),
	receive
		{gun_ws, ConnPid, StreamRef, _} ->
			error(unexpected_ws_frame);
		{gun_down, ConnPid, ws, _, _} ->
			ok
	after 5000 ->
		error(timeout)
	end,
	gun:close(ConnPid).

max_frame_size_infinity(_) ->
	doc("max_frame_size set to infinity must accept a frame larger "
		"than the default limit."),
	{ok, _, OriginPort} = init_origin(tcp, http,
		fun(_, _, ClientSocket, ClientTransport) ->
			{ok, ReqData} = ClientTransport:recv(ClientSocket, 0, 5000),
			Lines = binary:split(ReqData, <<"\r\n">>, [global]),
			[KeyLine] = [L || <<"sec-websocket-key: ", _/bits>> = L <- Lines],
			<<"sec-websocket-key: ", Key/bits>> = KeyLine,
			Accept = cow_ws:encode_key(Key),
			ok = ClientTransport:send(ClientSocket, [
				"HTTP/1.1 101 Switching Protocols\r\n"
				"connection: upgrade\r\n"
				"upgrade: websocket\r\n"
				"sec-websocket-accept: ", Accept, "\r\n"
				"\r\n"
			]),
			ok = ClientTransport:send(ClientSocket,
				cow_ws:frame({binary, binary:copy(<<"a">>, 1000001)}, #{})),
			receive after infinity -> ok end
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort, #{protocols => [http]}),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/", [], #{max_frame_size => infinity}),
	{upgrade, _, _} = gun:await(ConnPid, StreamRef),
	{ws, {binary, Data}} = gun:await(ConnPid, StreamRef),
	1000001 = byte_size(Data),
	gun:close(ConnPid).

max_frame_size_single(_) ->
	doc("A single Websocket frame declaring a length larger than "
		"max_frame_size must close the connection immediately, "
		"without buffering the oversized payload."),
	{ok, _, OriginPort} = init_origin(tcp, http,
		fun(_, _, ClientSocket, ClientTransport) ->
			{ok, ReqData} = ClientTransport:recv(ClientSocket, 0, 5000),
			Lines = binary:split(ReqData, <<"\r\n">>, [global]),
			[KeyLine] = [L || <<"sec-websocket-key: ", _/bits>> = L <- Lines],
			<<"sec-websocket-key: ", Key/bits>> = KeyLine,
			Accept = cow_ws:encode_key(Key),
			ok = ClientTransport:send(ClientSocket, [
				"HTTP/1.1 101 Switching Protocols\r\n"
				"connection: upgrade\r\n"
				"upgrade: websocket\r\n"
				"sec-websocket-accept: ", Accept, "\r\n"
				"\r\n"
			]),
			Header = <<1:1, 0:3, 1:4, 0:1, 126:7, 1000:16>>,
			ok = ClientTransport:send(ClientSocket, Header),
			{ok, CloseData} = ClientTransport:recv(ClientSocket, 0, 5000),
			1009 = do_ws_close_code(CloseData),
			ok = ClientTransport:close(ClientSocket)
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort, #{protocols => [http]}),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/", [], #{max_frame_size => 100}),
	{upgrade, _, _} = gun:await(ConnPid, StreamRef),
	receive
		{gun_ws, ConnPid, StreamRef, _} ->
			error(unexpected_ws_frame);
		{gun_down, ConnPid, ws, _, _} ->
			ok
	after 5000 ->
		error(timeout)
	end,
	gun:close(ConnPid).

http11_request_error(Config) ->
	doc("Ensure that HTTP/1.1 requests are rejected while using Websocket."),
	{ok, ConnPid} = gun:open("localhost", config(port, Config)),
	{ok, _} = gun:await_up(ConnPid),
	StreamRef1 = gun:ws_upgrade(ConnPid, "/", []),
	{upgrade, [<<"websocket">>], _} = gun:await(ConnPid, StreamRef1),
	StreamRef2 = gun:get(ConnPid, "/"),
	{error, {connection_error, {badstate, _}}} = gun:await(ConnPid, StreamRef2),
	gun:close(ConnPid).

do_ws_close_code(<<1:1, 0:3, 8:4, 1:1, 2:7, MA, MB, _, _, X, Y, _/bits>>) ->
	<<Code:16>> = <<(X bxor MA), (Y bxor MB)>>,
	Code.

reject_masked_frame_from_server(_) ->
	doc("A client must close the connection upon receiving a masked "
		"frame from the server, rather than accepting and unmasking "
		"it, since only clients are allowed to mask frames. (RFC6455 5.1)"),
	{ok, _, OriginPort} = init_origin(tcp, http,
		fun(_, _, ClientSocket, ClientTransport) ->
			{ok, ReqData} = ClientTransport:recv(ClientSocket, 0, 5000),
			Lines = binary:split(ReqData, <<"\r\n">>, [global]),
			[KeyLine] = [L || <<"sec-websocket-key: ", _/bits>> = L <- Lines],
			<<"sec-websocket-key: ", Key/bits>> = KeyLine,
			Accept = cow_ws:encode_key(Key),
			ok = ClientTransport:send(ClientSocket, [
				"HTTP/1.1 101 Switching Protocols\r\n"
				"connection: upgrade\r\n"
				"upgrade: websocket\r\n"
				"sec-websocket-accept: ", Accept, "\r\n"
				"\r\n"
			]),
			ok = ClientTransport:send(ClientSocket,
				cow_ws:masked_frame({text, <<"hello">>}, #{})),
			{ok, CloseData} = ClientTransport:recv(ClientSocket, 0, 5000),
			%% Client close: masked, opcode 8, 2-byte payload (status 1002).
			<<1:1, 0:3, 8:4, 1:1, 2:7, _:32, _:16, _/bits>> = CloseData,
			ok = ClientTransport:close(ClientSocket)
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort, #{protocols => [http]}),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/", []),
	{upgrade, _, _} = gun:await(ConnPid, StreamRef),
	receive
		{gun_ws, ConnPid, StreamRef, _} ->
			error(unexpected_ws_frame);
		{gun_down, ConnPid, ws, _, _} ->
			ok
	after 5000 ->
		error(timeout)
	end,
	gun:close(ConnPid).

reject_upgrade(Config) ->
	doc("Ensure Websocket connections can be rejected."),
	Protocol = config(name, config(tc_group_properties, Config)),
	{ok, ConnPid} = gun:open("localhost", config(port, Config), #{
		protocols => [Protocol],
		http2_opts => #{notify_settings_changed => true}
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	do_await_enable_connect_protocol(Protocol, ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/reject", []),
	receive
		{gun_response, ConnPid, StreamRef, nofin, 400, _} ->
			{ok, <<"Upgrade rejected">>} = gun:await_body(ConnPid, StreamRef, 1000),
			gun:close(ConnPid);
		Msg ->
			error({fail, Msg})
	after 1000 ->
		error(timeout)
	end.

reply_to(Config) ->
	doc("Ensure the reply_to request option is respected."),
	Self = self(),
	Frame = {text, <<"Hello!">>},
	ReplyTo = spawn(fun() ->
		{ConnPid, StreamRef} = receive
			{C, S} when is_pid(C), is_reference(S) -> {C, S}
		after 1000 ->
			error(timeout)
		end,
		{upgrade, [<<"websocket">>], _} = gun:await(ConnPid, StreamRef),
		Self ! {self(), ready},
		{ws, Frame} = gun:await(ConnPid, StreamRef),
		Self ! {self(), ok}
	end),
	Protocol = config(name, config(tc_group_properties, Config)),
	{ok, ConnPid} = gun:open("localhost", config(port, Config), #{
		protocols => [Protocol],
		http2_opts => #{notify_settings_changed => true}
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	do_await_enable_connect_protocol(Protocol, ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/", [], #{reply_to => ReplyTo}),
	ReplyTo ! {ConnPid, StreamRef},
	receive {ReplyTo, ready} -> gun:ws_send(ConnPid, StreamRef, Frame) after 1000 -> error(timeout) end,
	receive {ReplyTo, ok} -> gun:close(ConnPid) after 1000 -> error(timeout) end.

send_many(Config) ->
	doc("Ensure we can send a list of frames in one gun:ws_send call."),
	Protocol = config(name, config(tc_group_properties, Config)),
	{ok, ConnPid} = gun:open("localhost", config(port, Config), #{
		protocols => [Protocol],
		http2_opts => #{notify_settings_changed => true}
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	do_await_enable_connect_protocol(Protocol, ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/", []),
	{upgrade, [<<"websocket">>], _} = gun:await(ConnPid, StreamRef),
	Frame1 = {text, <<"Hello!">>},
	Frame2 = {binary, <<"World!">>},
	gun:ws_send(ConnPid, StreamRef, [Frame1, Frame2]),
	{ws, Frame1} = gun:await(ConnPid, StreamRef),
	{ws, Frame2} = gun:await(ConnPid, StreamRef),
	gun:close(ConnPid).

send_many_close(Config) ->
	doc("Ensure we can send a list of frames in one gun:ws_send call, including a close frame."),
	Protocol = config(name, config(tc_group_properties, Config)),
	{ok, ConnPid} = gun:open("localhost", config(port, Config), #{
		protocols => [Protocol],
		http2_opts => #{notify_settings_changed => true}
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	do_await_enable_connect_protocol(Protocol, ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/", []),
	{upgrade, [<<"websocket">>], _} = gun:await(ConnPid, StreamRef),
	Frame1 = {text, <<"Hello!">>},
	Frame2 = {binary, <<"World!">>},
	gun:ws_send(ConnPid, StreamRef, [Frame1, Frame2, close]),
	{ws, Frame1} = gun:await(ConnPid, StreamRef),
	{ws, Frame2} = gun:await(ConnPid, StreamRef),
	{ws, close} = gun:await(ConnPid, StreamRef),
	gun:close(ConnPid).

subprotocol_match(Config) ->
	doc("Websocket subprotocol successfully negotiated."),
	Protocols = [{P, gun_ws_h} || P <- [<<"dummy">>, <<"echo">>, <<"junk">>]],
	{ok, ConnPid} = gun:open("localhost", config(port, Config)),
	{ok, _} = gun:await_up(ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/subprotocol", [], #{
		protocols => Protocols
	}),
	{upgrade, [<<"websocket">>], _} = gun:await(ConnPid, StreamRef),
	Frame = {text, <<"Hello!">>},
	gun:ws_send(ConnPid, StreamRef, Frame),
	{ws, Frame} = gun:await(ConnPid, StreamRef),
	gun:close(ConnPid).

subprotocol_nomatch(Config) ->
	doc("Websocket subprotocol negotiation failure."),
	Protocols = [{P, gun_ws_h} || P <- [<<"dummy">>, <<"junk">>]],
	{ok, ConnPid} = gun:open("localhost", config(port, Config)),
	{ok, _} = gun:await_up(ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/subprotocol", [], #{
		protocols => Protocols
	}),
	{response, nofin, 400, _} = gun:await(ConnPid, StreamRef),
	{ok, <<"nomatch">>} = gun:await_body(ConnPid, StreamRef),
	gun:close(ConnPid).

subprotocol_required_but_missing(Config) ->
	doc("Websocket subprotocol not negotiated but required by the server."),
	{ok, ConnPid} = gun:open("localhost", config(port, Config)),
	{ok, _} = gun:await_up(ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/subprotocol", []),
	{response, nofin, 400, _} = gun:await(ConnPid, StreamRef),
	{ok, <<"undefined">>} = gun:await_body(ConnPid, StreamRef),
	gun:close(ConnPid).

unix_socket_hostname(_) ->
	case os:type() of
		{win32, _} ->
			{skip, "Unix Domain Sockets are not available on Windows."};
		_ ->
			do_unix_socket_hostname()
	end.

do_unix_socket_hostname() ->
	doc("Ensure that the hostname used for Websocket upgrades "
		"on Unix Domain Sockets is 'localhost' by default."),
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
	{ok, ConnPid} = gun:open_unix(SocketPath, #{}),
	#{origin_host := <<"localhost">>} = gun:info(ConnPid),
	_ = gun:ws_upgrade(ConnPid, "/", []),
	receive
		{recv, Recv} ->
			{_, _} = binary:match(Recv, <<"\r\nhost: localhost\r\n">>),
			gun:close(ConnPid)
	end.

%% Internal.

do_await_enable_connect_protocol(http, _) ->
	ok;
%% We cannot do a CONNECT :protocol request until the server tells us we can.
do_await_enable_connect_protocol(http2, ConnPid) ->
	{notify, settings_changed, #{enable_connect_protocol := true}}
		= gun:await(ConnPid, undefined), %% @todo Maybe have a gun:await/1?
	ok.
