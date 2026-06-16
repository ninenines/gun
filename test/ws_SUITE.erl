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
		unix_socket_hostname,
		deflate_opts_offer_wire
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

http11_request_error(Config) ->
	doc("Ensure that HTTP/1.1 requests are rejected while using Websocket."),
	{ok, ConnPid} = gun:open("localhost", config(port, Config)),
	{ok, _} = gun:await_up(ConnPid),
	StreamRef1 = gun:ws_upgrade(ConnPid, "/", []),
	{upgrade, [<<"websocket">>], _} = gun:await(ConnPid, StreamRef1),
	StreamRef2 = gun:get(ConnPid, "/"),
	{error, {connection_error, {badstate, _}}} = gun:await(ConnPid, StreamRef2),
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

deflate_opts_offer_wire(_) ->
	doc("The sec-websocket-extensions request header sent on the wire "
		"contains exactly the parameters configured in deflate_opts."),
	TCPOpts = [binary, {nodelay, true}, {active, false},
		{packet, raw}, {reuseaddr, true}],
	{ok, LSock} = gen_tcp:listen(0, TCPOpts),
	{ok, Port} = inet:port(LSock),
	Tester = self(),
	Acceptor = fun() ->
		{ok, S} = gen_tcp:accept(LSock),
		{ok, R} = gen_tcp:recv(S, 0),
		Tester ! {recv, R},
		ok = gen_tcp:close(S),
		ok = gen_tcp:close(LSock)
	end,
	spawn(Acceptor),
	{ok, ConnPid} = gun:open("localhost", Port, #{
		protocols => [http],
		ws_opts => #{
			compress => true,
			deflate_opts => #{
				server_context_takeover => no_takeover,
				client_context_takeover => no_takeover,
				server_max_window_bits => 10,
				client_max_window_bits => 12
			}
		}
	}),
	{ok, http} = gun:await_up(ConnPid),
	_ = gun:ws_upgrade(ConnPid, "/"),
	receive
		{recv, Recv} ->
			Needle = <<"\r\nsec-websocket-extensions: ">>,
			{HdrStart, _} = binary:match(Recv, Needle),
			ValueStart = HdrStart + byte_size(Needle),
			Rest = binary:part(Recv, ValueStart, byte_size(Recv) - ValueStart),
			{EolPos, _} = binary:match(Rest, <<"\r\n">>),
			Value = binary:part(Rest, 0, EolPos),
			<<"permessage-deflate", _/binary>> = Value,
			{_, _} = binary:match(Value, <<"; server_no_context_takeover">>),
			{_, _} = binary:match(Value, <<"; client_no_context_takeover">>),
			{_, _} = binary:match(Value, <<"; server_max_window_bits=10">>),
			{_, _} = binary:match(Value, <<"; client_max_window_bits=12">>),
			gun:close(ConnPid)
	after 5000 ->
		ct:fail(timeout)
	end.

%% deflate_opts tests.

deflate_opts_offer_default(_) ->
	doc("deflate_offer/1 returns the historical default offer "
		"when deflate_opts is not set."),
	<<"permessage-deflate; client_max_window_bits; server_max_window_bits=15">>
		= gun_ws:deflate_offer(#{}),
	<<"permessage-deflate; client_max_window_bits; server_max_window_bits=15">>
		= gun_ws:deflate_offer(#{compress => true}),
	ok.

deflate_opts_offer_builds(_) ->
	doc("deflate_offer/1 builds the offer header from deflate_opts."),
	<<"permessage-deflate">> = gun_ws:deflate_offer(
		#{deflate_opts => #{}}),
	Offer1 = gun_ws:deflate_offer(
		#{deflate_opts => #{
			client_context_takeover => no_takeover,
			server_context_takeover => no_takeover}}),
	{_, _} = binary:match(Offer1, <<"client_no_context_takeover">>),
	{_, _} = binary:match(Offer1, <<"server_no_context_takeover">>),
	Offer2 = gun_ws:deflate_offer(
		#{deflate_opts => #{
			client_max_window_bits => 12,
			server_max_window_bits => 10}}),
	{_, _} = binary:match(Offer2, <<"client_max_window_bits=12">>),
	{_, _} = binary:match(Offer2, <<"server_max_window_bits=10">>),
	Offer3 = gun_ws:deflate_offer(
		#{deflate_opts => #{client_max_window_bits => bare}}),
	{_, _} = binary:match(Offer3, <<"client_max_window_bits">>),
	%% A bare client_max_window_bits has no '=' after it.
	nomatch = binary:match(Offer3, <<"client_max_window_bits=">>),
	%% takeover (default) is omitted from the offer.
	<<"permessage-deflate">> = gun_ws:deflate_offer(
		#{deflate_opts => #{
			client_context_takeover => takeover,
			server_context_takeover => takeover}}),
	%% Local zlib codec opts have no wire representation and
	%% must not appear in the offer.
	<<"permessage-deflate">> = gun_ws:deflate_offer(
		#{deflate_opts => #{
			level => best_speed,
			mem_level => 9,
			strategy => huffman_only}}),
	ok.

deflate_opts_check_options(_) ->
	doc("ws_opts validation accepts well-formed deflate_opts "
		"and rejects malformed ones."),
	ok = gun_ws:check_options(#{compress => true,
		deflate_opts => #{
			server_context_takeover => no_takeover,
			client_context_takeover => no_takeover,
			server_max_window_bits => 15,
			client_max_window_bits => 8,
			level => best_compression,
			mem_level => 8,
			strategy => default}}),
	ok = gun_ws:check_options(#{deflate_opts => #{}}),
	ok = gun_ws:check_options(
		#{deflate_opts => #{client_max_window_bits => bare}}),
	%% Reject the legacy boolean form.
	{error, {options, {ws, {deflate_opts, _}}}}
		= gun_ws:check_options(
			#{deflate_opts => #{client_max_window_bits => true}}),
	{error, {options, {ws, {deflate_opts, _}}}}
		= gun_ws:check_options(
			#{deflate_opts => #{client_max_window_bits => false}}),
	%% Each zlib tuning atom and integer is accepted.
	ok = gun_ws:check_options(#{deflate_opts => #{level => none}}),
	ok = gun_ws:check_options(#{deflate_opts => #{level => 0}}),
	ok = gun_ws:check_options(#{deflate_opts => #{level => 9}}),
	ok = gun_ws:check_options(#{deflate_opts => #{strategy => filtered}}),
	ok = gun_ws:check_options(#{deflate_opts => #{strategy => rle}}),
	ok = gun_ws:check_options(#{deflate_opts => #{mem_level => 1}}),
	%% Out-of-range window bits are rejected.
	{error, {options, {ws, {deflate_opts, _}}}}
		= gun_ws:check_options(
			#{deflate_opts => #{server_max_window_bits => 7}}),
	{error, {options, {ws, {deflate_opts, _}}}}
		= gun_ws:check_options(
			#{deflate_opts => #{client_max_window_bits => 16}}),
	%% Invalid takeover values are rejected.
	{error, {options, {ws, {deflate_opts, _}}}}
		= gun_ws:check_options(
			#{deflate_opts =>
				#{server_context_takeover => yes}}),
	%% Out-of-range zlib tuning values are rejected.
	{error, {options, {ws, {deflate_opts, _}}}}
		= gun_ws:check_options(#{deflate_opts => #{level => 10}}),
	{error, {options, {ws, {deflate_opts, _}}}}
		= gun_ws:check_options(#{deflate_opts => #{level => bogus}}),
	{error, {options, {ws, {deflate_opts, _}}}}
		= gun_ws:check_options(#{deflate_opts => #{mem_level => 0}}),
	{error, {options, {ws, {deflate_opts, _}}}}
		= gun_ws:check_options(#{deflate_opts => #{mem_level => 10}}),
	{error, {options, {ws, {deflate_opts, _}}}}
		= gun_ws:check_options(#{deflate_opts => #{strategy => bogus}}),
	%% Unknown keys are rejected.
	{error, {options, {ws, {deflate_opts, _}}}}
		= gun_ws:check_options(
			#{deflate_opts => #{foo => bar}}),
	%% Wrong outer type is rejected.
	{error, {options, {ws, {deflate_opts, _}}}}
		= gun_ws:check_options(#{deflate_opts => not_a_map}),
	ok.

compress_with_no_context_takeover(Config) ->
	doc("Negotiate permessage-deflate with both *_no_context_takeover "
		"requested and round-trip a few echo frames."),
	do_compress_roundtrip(Config, #{
		server_context_takeover => no_takeover,
		client_context_takeover => no_takeover}).

compress_with_max_window_bits(Config) ->
	doc("Negotiate permessage-deflate with explicit *_max_window_bits "
		"and round-trip a few echo frames."),
	do_compress_roundtrip(Config, #{
		client_max_window_bits => 12,
		server_max_window_bits => 10}).

compress_with_zlib_tuning(Config) ->
	doc("Round-trip echo frames with local zlib codec tuning "
		"(level/mem_level/strategy) forwarded to Cowlib."),
	do_compress_roundtrip(Config, #{
		level => best_speed,
		mem_level => 9,
		strategy => default}).

do_compress_roundtrip(Config, CompressOpts) ->
	Protocol = config(name, config(tc_group_properties, Config)),
	{ok, ConnPid} = gun:open("localhost", config(port, Config), #{
		protocols => [Protocol],
		http2_opts => #{notify_settings_changed => true},
		ws_opts => #{
			compress => true,
			deflate_opts => CompressOpts
		}
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	do_await_enable_connect_protocol(Protocol, ConnPid),
	StreamRef = gun:ws_upgrade(ConnPid, "/"),
	{upgrade, [<<"websocket">>], RespHeaders} = gun:await(ConnPid, StreamRef),
	%% The server accepted permessage-deflate.
	{_, ExtHd} = lists:keyfind(<<"sec-websocket-extensions">>, 1, RespHeaders),
	{_, _} = binary:match(ExtHd, <<"permessage-deflate">>),
	%% A non-trivial text frame round-trips correctly through the
	%% compressed channel.
	Frame = {text, binary:copy(<<"Hello, compressed world! ">>, 64)},
	gun:ws_send(ConnPid, StreamRef, Frame),
	{ws, Frame} = gun:await(ConnPid, StreamRef),
	gun:ws_send(ConnPid, StreamRef, Frame),
	{ws, Frame} = gun:await(ConnPid, StreamRef),
	gun:close(ConnPid).
