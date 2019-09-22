%% Copyright (c) 2019, Loïc Hoguin <essen@ninenines.eu>
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

-module(event_SUITE).
-compile(export_all).
-compile(nowarn_export_all).

-behavior(gun_event).

-import(ct_helper, [config/2]).
-import(ct_helper, [doc/1]).
-import(gun_test, [init_origin/1]).

all() ->
	[
		{group, http},
		{group, http2}
	].

groups() ->
	Tests = ct_helper:all(?MODULE),
	%% Some tests are written only for HTTP/1.0 or HTTP/1.1.
	HTTP1Tests = [T || T <- Tests, lists:sublist(atom_to_list(T), 6) =:= "http1_"],
	%% Push is not possible over HTTP/1.1.
	PushTests = [T || T <- Tests, lists:sublist(atom_to_list(T), 5) =:= "push_"],
	%% We currently do not support Websocket over HTTP/2.
	WsTests = [T || T <- Tests, lists:sublist(atom_to_list(T), 3) =:= "ws_"],
	[
		{http, [parallel], Tests -- [cancel_remote|PushTests]},
		{http2, [parallel], (Tests -- WsTests) -- HTTP1Tests}
	].

init_per_suite(Config) ->
	ProtoOpts = #{env => #{
		dispatch => cowboy_router:compile([{'_', [
			{"/", hello_h, []},
			{"/empty", empty_h, []},
			{"/inform", inform_h, []},
			{"/push", push_h, []},
			{"/stream", stream_h, []},
			{"/trailers", trailers_h, []},
			{"/ws", ws_echo_h, []}
		]}])
	}},
	{ok, _} = cowboy:start_clear({?MODULE, tcp}, [], ProtoOpts),
	TCPOriginPort = ranch:get_port({?MODULE, tcp}),
	{ok, _} = cowboy:start_tls({?MODULE, tls}, ct_helper:get_certs_from_ets(), ProtoOpts),
	TLSOriginPort = ranch:get_port({?MODULE, tls}),
	[{tcp_origin_port, TCPOriginPort}, {tls_origin_port, TLSOriginPort}|Config].

end_per_suite(_) ->
	ok = cowboy:stop_listener({?MODULE, tls}),
	ok = cowboy:stop_listener({?MODULE, tcp}).

%% init.

init(Config) ->
	doc("Confirm that the init event callback is called."),
	Self = self(),
	Opts = #{
		event_handler => {?MODULE, self()},
		protocols => [config(name, config(tc_group_properties, Config))]
	},
	{ok, Pid} = gun:open("localhost", 12345, Opts),
	#{
		owner := Self,
		transport := tcp,
		origin_scheme := <<"http">>,
		origin_host := "localhost",
		origin_port := 12345,
		opts := Opts
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

%% domain_lookup_start/domain_lookup_end.

domain_lookup_start(Config) ->
	doc("Confirm that the domain_lookup_start event callback is called."),
	{ok, Pid, _} = do_gun_open(12345, Config),
	#{
		host := "localhost",
		port := 12345,
		tcp_opts := _,
		timeout := _
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

domain_lookup_end_error(Config) ->
	doc("Confirm that the domain_lookup_end event callback is called on lookup failure."),
	Opts = #{
		event_handler => {?MODULE, self()},
		protocols => [config(name, config(tc_group_properties, Config))]
	},
	{ok, Pid} = gun:open("this.should.not.exist", 12345, Opts),
	#{
		host := "this.should.not.exist",
		port := 12345,
		tcp_opts := _,
		timeout := _,
		error := nxdomain
	} = do_receive_event(domain_lookup_end),
	gun:close(Pid).

domain_lookup_end_ok(Config) ->
	doc("Confirm that the domain_lookup_end event callback is called on lookup success."),
	{ok, Pid, _} = do_gun_open(12345, Config),
	#{
		host := "localhost",
		port := 12345,
		tcp_opts := _,
		timeout := _,
		lookup_info := #{
			ip_addresses := [_|_],
			port := 12345,
			tcp_module := _,
			tcp_opts := _
		}
	} = do_receive_event(domain_lookup_end),
	gun:close(Pid).

%% connect_start/connect_end.

connect_start(Config) ->
	doc("Confirm that the connect_start event callback is called."),
	{ok, Pid, _} = do_gun_open(12345, Config),
	#{
		lookup_info := #{
			ip_addresses := [_|_],
			port := 12345,
			tcp_module := _,
			tcp_opts := _
		},
		timeout := _
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

connect_end_error(Config) ->
	doc("Confirm that the connect_end event callback is called on connect failure."),
	{ok, Pid, _} = do_gun_open(12345, Config),
	#{
		lookup_info := #{
			ip_addresses := [_|_],
			port := 12345,
			tcp_module := _,
			tcp_opts := _
		},
		timeout := _,
		error := _
	} = do_receive_event(connect_end),
	gun:close(Pid).

connect_end_ok_tcp(Config) ->
	doc("Confirm that the connect_end event callback is called on connect success with TCP."),
	{ok, Pid, OriginPort} = do_gun_open(Config),
	{ok, Protocol} = gun:await_up(Pid),
	#{
		lookup_info := #{
			ip_addresses := [_|_],
			port := OriginPort,
			tcp_module := _,
			tcp_opts := _
		},
		timeout := _,
		socket := _,
		protocol := Protocol
	} = do_receive_event(connect_end),
	gun:close(Pid).

connect_end_ok_tls(Config) ->
	doc("Confirm that the connect_end event callback is called on connect success with TLS."),
	{ok, Pid, OriginPort} = do_gun_open_tls(Config),
	Event = #{
		lookup_info := #{
			ip_addresses := [_|_],
			port := OriginPort,
			tcp_module := _,
			tcp_opts := _
		},
		timeout := _,
		socket := _
	} = do_receive_event(connect_end),
	false = maps:is_key(protocol, Event),
	gun:close(Pid).

tls_handshake_start(Config) ->
	doc("Confirm that the tls_handshake_start event callback is called."),
	{ok, Pid, _} = do_gun_open_tls(Config),
	#{
		socket := Socket,
		tls_opts := _,
		timeout := _
	} = do_receive_event(?FUNCTION_NAME),
	true = is_port(Socket),
	gun:close(Pid).

tls_handshake_end_error(Config) ->
	doc("Confirm that the tls_handshake_end event callback is called on TLS handshake error."),
	%% We use the wrong port on purpose to trigger a handshake error.
	OriginPort = config(tcp_origin_port, Config),
	Opts = #{
		event_handler => {?MODULE, self()},
		protocols => [config(name, config(tc_group_properties, Config))],
		transport => tls
	},
	{ok, Pid} = gun:open("localhost", OriginPort, Opts),
	#{
		socket := Socket,
		tls_opts := _,
		timeout := _,
		error := {tls_alert, _}
	} = do_receive_event(tls_handshake_end),
	true = is_port(Socket),
	gun:close(Pid).

tls_handshake_end_ok(Config) ->
	doc("Confirm that the tls_handshake_end event callback is called on TLS handshake success."),
	{ok, Pid, _} = do_gun_open_tls(Config),
	{ok, Protocol} = gun:await_up(Pid),
	#{
		socket := Socket,
		tls_opts := _,
		timeout := _,
		protocol := Protocol
	} = do_receive_event(tls_handshake_end),
	true = is_tuple(Socket),
	gun:close(Pid).

http1_tls_handshake_start_connect(Config) ->
	doc("Confirm that the tls_handshake_start event callback is called "
		"when using CONNECT to a TLS server via a TCP proxy."),
	OriginPort = config(tls_origin_port, Config),
	{ok, _, ProxyPort} = rfc7231_SUITE:do_proxy_start(tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [config(name, config(tc_group_properties, Config))],
		transport => tcp
	}),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		transport => tls
	}),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		socket := Socket,
		tls_opts := _,
		timeout := _
	} = do_receive_event(tls_handshake_start),
	true = is_port(Socket),
	gun:close(ConnPid).

http1_tls_handshake_end_error_connect(Config) ->
	doc("Confirm that the tls_handshake_end event callback is called on TLS handshake error "
		"when using CONNECT to a TLS server via a TCP proxy."),
	%% We use the wrong port on purpose to trigger a handshake error.
	OriginPort = config(tcp_origin_port, Config),
	{ok, _, ProxyPort} = rfc7231_SUITE:do_proxy_start(tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [config(name, config(tc_group_properties, Config))],
		transport => tcp
	}),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		transport => tls
	}),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		socket := Socket,
		tls_opts := _,
		timeout := _,
		error := {tls_alert, _}
	} = do_receive_event(tls_handshake_end),
	true = is_port(Socket),
	gun:close(ConnPid).

http1_tls_handshake_end_ok_connect(Config) ->
	doc("Confirm that the tls_handshake_end event callback is called on TLS handshake success "
		"when using CONNECT to a TLS server via a TCP proxy."),
	OriginPort = config(tls_origin_port, Config),
	{ok, _, ProxyPort} = rfc7231_SUITE:do_proxy_start(tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [config(name, config(tc_group_properties, Config))],
		transport => tcp
	}),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		transport => tls
	}),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		socket := Socket,
		tls_opts := _,
		timeout := _,
		protocol := http2
	} = do_receive_event(tls_handshake_end),
	true = is_tuple(Socket),
	gun:close(ConnPid).

http1_tls_handshake_start_connect_over_https_proxy(Config) ->
	doc("Confirm that the tls_handshake_start event callback is called "
		"when using CONNECT to a TLS server via a TLS proxy."),
	OriginPort = config(tls_origin_port, Config),
	{ok, _, ProxyPort} = rfc7231_SUITE:do_proxy_start(tls),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [config(name, config(tc_group_properties, Config))],
		transport => tls
	}),
	{ok, http} = gun:await_up(ConnPid),
	%% We skip the TLS handshake event to the TLS proxy.
	_ = do_receive_event(tls_handshake_start),
	StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		transport => tls
	}),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		socket := Socket,
		tls_opts := _,
		timeout := _
	} = do_receive_event(tls_handshake_start),
	true = is_tuple(Socket),
	gun:close(ConnPid).

http1_tls_handshake_end_error_connect_over_https_proxy(Config) ->
	doc("Confirm that the tls_handshake_end event callback is called on TLS handshake error "
		"when using CONNECT to a TLS server via a TLS proxy."),
	%% We use the wrong port on purpose to trigger a handshake error.
	OriginPort = config(tcp_origin_port, Config),
	{ok, _, ProxyPort} = rfc7231_SUITE:do_proxy_start(tls),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [config(name, config(tc_group_properties, Config))],
		transport => tls
	}),
	{ok, http} = gun:await_up(ConnPid),
	%% We skip the TLS handshake event to the TLS proxy.
	_ = do_receive_event(tls_handshake_end),
	StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		transport => tls
	}),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		socket := Socket,
		tls_opts := _,
		timeout := _,
		error := {tls_alert, _}
	} = do_receive_event(tls_handshake_end),
	true = is_tuple(Socket),
	gun:close(ConnPid).

http1_tls_handshake_end_ok_connect_over_https_proxy(Config) ->
	doc("Confirm that the tls_handshake_end event callback is called on TLS handshake success "
		"when using CONNECT to a TLS server via a TLS proxy."),
	OriginPort = config(tls_origin_port, Config),
	{ok, _, ProxyPort} = rfc7231_SUITE:do_proxy_start(tls),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [config(name, config(tc_group_properties, Config))],
		transport => tls
	}),
	{ok, http} = gun:await_up(ConnPid),
	%% We skip the TLS handshake event to the TLS proxy.
	_ = do_receive_event(tls_handshake_end),
	StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		transport => tls
	}),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		socket := Socket,
		tls_opts := _,
		timeout := _,
		protocol := http2
	} = do_receive_event(tls_handshake_end),
	true = is_pid(Socket),
	gun:close(ConnPid).

request_start(Config) ->
	doc("Confirm that the request_start event callback is called."),
	do_request_event(Config, ?FUNCTION_NAME),
	do_request_event_headers(Config, ?FUNCTION_NAME).

request_headers(Config) ->
	doc("Confirm that the request_headers event callback is called."),
	do_request_event(Config, ?FUNCTION_NAME),
	do_request_event_headers(Config, ?FUNCTION_NAME).

do_request_event(Config, EventName) ->
	{ok, Pid, OriginPort} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:get(Pid, "/"),
	ReplyTo = self(),
	Authority = iolist_to_binary([<<"localhost:">>, integer_to_list(OriginPort)]),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		function := request,
		method := <<"GET">>,
		authority := EventAuthority,
		path := "/",
		headers := [_|_]
	} = do_receive_event(EventName),
	Authority = iolist_to_binary(EventAuthority),
	gun:close(Pid).

do_request_event_headers(Config, EventName) ->
	{ok, Pid, OriginPort} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:put(Pid, "/", [
		{<<"content-type">>, <<"text/plain">>}
	]),
	ReplyTo = self(),
	Authority = iolist_to_binary([<<"localhost:">>, integer_to_list(OriginPort)]),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		function := headers,
		method := <<"PUT">>,
		authority := EventAuthority,
		path := "/",
		headers := [_|_]
	} = do_receive_event(EventName),
	Authority = iolist_to_binary(EventAuthority),
	gun:close(Pid).

request_end(Config) ->
	doc("Confirm that the request_end event callback is called."),
	do_request_end(Config, ?FUNCTION_NAME),
	do_request_end_headers(Config, ?FUNCTION_NAME),
	do_request_end_headers_content_length(Config, ?FUNCTION_NAME),
	do_request_end_headers_content_length_0(Config, ?FUNCTION_NAME).

do_request_end(Config, EventName) ->
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:get(Pid, "/"),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo
	} = do_receive_event(EventName),
	gun:close(Pid).

do_request_end_headers(Config, EventName) ->
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:put(Pid, "/", [
		{<<"content-type">>, <<"text/plain">>}
	]),
	gun:data(Pid, StreamRef, nofin, <<"Hello ">>),
	gun:data(Pid, StreamRef, fin, <<"world!">>),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo
	} = do_receive_event(EventName),
	gun:close(Pid).

do_request_end_headers_content_length(Config, EventName) ->
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:put(Pid, "/", [
		{<<"content-type">>, <<"text/plain">>},
		{<<"content-length">>, <<"12">>}
	]),
	gun:data(Pid, StreamRef, nofin, <<"Hello ">>),
	gun:data(Pid, StreamRef, fin, <<"world!">>),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo
	} = do_receive_event(EventName),
	gun:close(Pid).

do_request_end_headers_content_length_0(Config, EventName) ->
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:put(Pid, "/", [
		{<<"content-type">>, <<"text/plain">>},
		{<<"content-length">>, <<"0">>}
	]),
	gun:data(Pid, StreamRef, fin, <<>>),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo
	} = do_receive_event(EventName),
	gun:close(Pid).

push_promise_start(Config) ->
	doc("Confirm that the push_promise_start event callback is called."),
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:get(Pid, "/push"),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo
	} = do_receive_event(?FUNCTION_NAME),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

push_promise_end(Config) ->
	doc("Confirm that the push_promise_end event callback is called."),
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:get(Pid, "/push"),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		promised_stream_ref := _,
		method := <<"GET">>,
		uri := <<"http://",_/bits>>,
		headers := [_|_]
	} = do_receive_event(?FUNCTION_NAME),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		promised_stream_ref := _,
		method := <<"GET">>,
		uri := <<"http://",_/bits>>,
		headers := [_|_]
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

push_promise_followed_by_response(Config) ->
	doc("Confirm that the push_promise_end event callbacks are followed by response_start."),
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	_ = gun:get(Pid, "/push"),
	#{promised_stream_ref := PromisedStreamRef} = do_receive_event(push_promise_end),
	#{stream_ref := StreamRef1} = do_receive_event(response_start),
	#{stream_ref := StreamRef2} = do_receive_event(response_start),
	#{stream_ref := StreamRef3} = do_receive_event(response_start),
	true = lists:member(PromisedStreamRef, [StreamRef1, StreamRef2, StreamRef3]),
	gun:close(Pid).

response_start(Config) ->
	doc("Confirm that the request_start event callback is called."),
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:get(Pid, "/"),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

response_inform(Config) ->
	doc("Confirm that the request_inform event callback is called."),
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:get(Pid, "/inform"),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		status := 103,
		headers := [_|_]
	} = do_receive_event(?FUNCTION_NAME),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		status := 103,
		headers := [_|_]
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

response_headers(Config) ->
	doc("Confirm that the request_headers event callback is called."),
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:get(Pid, "/"),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		status := 200,
		headers := [_|_]
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

response_trailers(Config) ->
	doc("Confirm that the request_trailers event callback is called."),
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:get(Pid, "/trailers", [{<<"te">>, <<"trailers">>}]),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		headers := [_|_]
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

response_end(Config) ->
	doc("Confirm that the request_headers event callback is called."),
	do_response_end(Config, ?FUNCTION_NAME, "/"),
	do_response_end(Config, ?FUNCTION_NAME, "/empty"),
	do_response_end(Config, ?FUNCTION_NAME, "/stream"),
	do_response_end(Config, ?FUNCTION_NAME, "/trailers").

do_response_end(Config, EventName, Path) ->
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:get(Pid, Path, [{<<"te">>, <<"trailers">>}]),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo
	} = do_receive_event(EventName),
	gun:close(Pid).

http1_response_end_body_close(Config) ->
	doc("Confirm that the request_headers event callback is called "
		"when using HTTP/1.0 and the content-length header is not set."),
	OriginPort = config(tcp_origin_port, Config),
	Opts = #{
		event_handler => {?MODULE, self()},
		http_opts => #{version => 'HTTP/1.0'},
		protocols => [config(name, config(tc_group_properties, Config))]
	},
	{ok, Pid} = gun:open("localhost", OriginPort, Opts),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:get(Pid, "/stream"),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo
	} = do_receive_event(response_end),
	gun:close(Pid).

ws_upgrade(Config) ->
	doc("Confirm that the ws_upgrade event callback is called."),
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:ws_upgrade(Pid, "/ws"),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		opts := #{}
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

ws_upgrade_all_events(Config) ->
	doc("Confirm that a Websocket upgrade triggers all relevant events."),
	{ok, Pid, OriginPort} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:ws_upgrade(Pid, "/ws"),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		opts := #{}
	} = do_receive_event(ws_upgrade),
	Authority = iolist_to_binary([<<"localhost:">>, integer_to_list(OriginPort)]),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		function := ws_upgrade,
		method := <<"GET">>,
		authority := EventAuthority1,
		path := "/ws",
		headers := [_|_]
	} = do_receive_event(request_start),
	Authority = iolist_to_binary(EventAuthority1),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		function := ws_upgrade,
		method := <<"GET">>,
		authority := EventAuthority2,
		path := "/ws",
		headers := [_|_]
	} = do_receive_event(request_headers),
	Authority = iolist_to_binary(EventAuthority2),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo
	} = do_receive_event(request_end),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo
	} = do_receive_event(response_start),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		status := 101,
		headers := [_|_]
	} = do_receive_event(response_inform),
	#{
		protocol := ws
	} = do_receive_event(protocol_changed),
	gun:close(Pid).

ws_recv_frame_start(Config) ->
	doc("Confirm that the ws_recv_frame_start event callback is called."),
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:ws_upgrade(Pid, "/ws"),
	{upgrade, [<<"websocket">>], _} = gun:await(Pid, StreamRef),
	gun:ws_send(Pid, {text, <<"Hello!">>}),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		frag_state := undefined,
		extensions := #{}
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

ws_recv_frame_header(Config) ->
	doc("Confirm that the ws_recv_frame_header event callback is called."),
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:ws_upgrade(Pid, "/ws"),
	{upgrade, [<<"websocket">>], _} = gun:await(Pid, StreamRef),
	gun:ws_send(Pid, {text, <<"Hello!">>}),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		frag_state := undefined,
		extensions := #{},
		type := text,
		rsv := <<0:3>>,
		len := 6,
		mask_key := _
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

ws_recv_frame_end(Config) ->
	doc("Confirm that the ws_recv_frame_end event callback is called."),
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:ws_upgrade(Pid, "/ws"),
	{upgrade, [<<"websocket">>], _} = gun:await(Pid, StreamRef),
	gun:ws_send(Pid, {text, <<"Hello!">>}),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		extensions := #{},
		close_code := undefined,
		payload := <<"Hello!">>
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

ws_send_frame_start(Config) ->
	doc("Confirm that the ws_send_frame_start event callback is called."),
	do_ws_send_frame(Config, ?FUNCTION_NAME).

ws_send_frame_end(Config) ->
	doc("Confirm that the ws_send_frame_end event callback is called."),
	do_ws_send_frame(Config, ?FUNCTION_NAME).

do_ws_send_frame(Config, EventName) ->
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:ws_upgrade(Pid, "/ws"),
	{upgrade, [<<"websocket">>], _} = gun:await(Pid, StreamRef),
	gun:ws_send(Pid, {text, <<"Hello!">>}),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		extensions := #{},
		frame := {text, <<"Hello!">>}
	} = do_receive_event(EventName),
	gun:close(Pid).

ws_protocol_changed(Config) ->
	doc("Confirm that the protocol_changed event callback is called on Websocket upgrade success."),
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	_ = gun:ws_upgrade(Pid, "/ws"),
	#{
		protocol := ws
	} = do_receive_event(protocol_changed),
	gun:close(Pid).

http1_protocol_changed_connect(Config) ->
	doc("Confirm that the protocol_changed event callback is called on CONNECT success "
		"when connecting through a TCP server via a TCP proxy."),
	OriginPort = config(tcp_origin_port, Config),
	{ok, _, ProxyPort} = rfc7231_SUITE:do_proxy_start(tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [config(name, config(tc_group_properties, Config))],
		transport => tcp
	}),
	{ok, http} = gun:await_up(ConnPid),
	_ = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		protocols => [http2]
	}),
	#{protocol := http2} = do_receive_event(protocol_changed),
	gun:close(ConnPid).

http1_protocol_changed_connect_over_https_proxy(Config) ->
	doc("Confirm that the protocol_changed event callback is called on CONNECT success "
		"when connecting through a TLS server via a TLS proxy."),
	OriginPort = config(tls_origin_port, Config),
	{ok, _, ProxyPort} = rfc7231_SUITE:do_proxy_start(tls),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [config(name, config(tc_group_properties, Config))],
		transport => tls
	}),
	{ok, http} = gun:await_up(ConnPid),
	_ = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		transport => tls,
		protocols => [http2]
	}),
	#{protocol := http2} = do_receive_event(protocol_changed),
	gun:close(ConnPid).

http1_transport_changed_connect(Config) ->
	doc("Confirm that the transport_changed event callback is called on CONNECT success "
		"when connecting through a TLS server via a TCP proxy."),
	OriginPort = config(tls_origin_port, Config),
	{ok, _, ProxyPort} = rfc7231_SUITE:do_proxy_start(tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [config(name, config(tc_group_properties, Config))],
		transport => tcp
	}),
	{ok, http} = gun:await_up(ConnPid),
	_ = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		transport => tls
	}),
	#{
		socket := Socket,
		transport := tls
	} = do_receive_event(transport_changed),
	true = is_tuple(Socket),
	gun:close(ConnPid).

http1_transport_changed_connect_over_https_proxy(Config) ->
	doc("Confirm that the transport_changed event callback is called on CONNECT success "
		"when connecting through a TLS server via a TLS proxy."),
	OriginPort = config(tls_origin_port, Config),
	{ok, _, ProxyPort} = rfc7231_SUITE:do_proxy_start(tls),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [config(name, config(tc_group_properties, Config))],
		transport => tls
	}),
	{ok, http} = gun:await_up(ConnPid),
	_ = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		transport => tls
	}),
	#{
		socket := Socket,
		transport := tls_proxy
	} = do_receive_event(transport_changed),
	true = is_pid(Socket),
	gun:close(ConnPid).

http1_origin_changed_connect(Config) ->
	doc("Confirm that the origin_changed event callback is called on CONNECT success."),
	OriginPort = config(tcp_origin_port, Config),
	{ok, _, ProxyPort} = rfc7231_SUITE:do_proxy_start(tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [config(name, config(tc_group_properties, Config))],
		transport => tcp
	}),
	{ok, http} = gun:await_up(ConnPid),
	_ = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort
	}),
	#{
		type := connect,
		origin_scheme := <<"http">>,
		origin_host := "localhost",
		origin_port := OriginPort
	} = do_receive_event(origin_changed),
	gun:close(ConnPid).

cancel(Config) ->
	doc("Confirm that the cancel event callback is called when we cancel a stream."),
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:post(Pid, "/stream", []),
	gun:cancel(Pid, StreamRef),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		endpoint := local,
		reason := cancel
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

cancel_remote(Config) ->
	doc("Confirm that the cancel event callback is called "
		"when the remote endpoint cancels the stream."),
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:post(Pid, "/stream", []),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		endpoint := remote,
		reason := _
	} = do_receive_event(cancel),
	gun:close(Pid).

disconnect(Config) ->
	doc("Confirm that the disconnect event callback is called on disconnect."),
	{ok, OriginPid, OriginPort} = init_origin(tcp),
	{ok, Pid, _} = do_gun_open(OriginPort, Config),
	{ok, _} = gun:await_up(Pid),
	%% We make the origin exit to trigger a disconnect.
	unlink(OriginPid),
	exit(OriginPid, shutdown),
	#{
		reason := closed
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

terminate(Config) ->
	doc("Confirm that the terminate event callback is called on terminate."),
	{ok, Pid, _} = do_gun_open(12345, Config),
	gun:close(Pid),
	#{
		state := _,
		reason := shutdown
	} = do_receive_event(?FUNCTION_NAME),
	ok.

%% Internal.

do_gun_open(Config) ->
	OriginPort = config(tcp_origin_port, Config),
	do_gun_open(OriginPort, Config).

do_gun_open(OriginPort, Config) ->
	Opts = #{
		event_handler => {?MODULE, self()},
		protocols => [config(name, config(tc_group_properties, Config))]
	},
	{ok, Pid} = gun:open("localhost", OriginPort, Opts),
	{ok, Pid, OriginPort}.

do_gun_open_tls(Config) ->
	OriginPort = config(tls_origin_port, Config),
	Opts = #{
		event_handler => {?MODULE, self()},
		protocols => [config(name, config(tc_group_properties, Config))],
		transport => tls
	},
	{ok, Pid} = gun:open("localhost", OriginPort, Opts),
	{ok, Pid, OriginPort}.

do_receive_event(Event) ->
	receive
		{Event, EventData} ->
			EventData
	after 5000 ->
		error(timeout)
	end.

%% gun_event callbacks.

init(EventData, Pid) ->
	%% We enable trap_exit to ensure we get a terminate event
	%% when we call gun:close/1.
	process_flag(trap_exit, true),
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

domain_lookup_start(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

domain_lookup_end(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

connect_start(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

connect_end(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

tls_handshake_start(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

tls_handshake_end(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

request_start(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

request_headers(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

request_end(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

push_promise_start(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

push_promise_end(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

response_start(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

response_inform(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

response_headers(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

response_trailers(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

response_end(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

ws_upgrade(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

ws_recv_frame_start(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

ws_recv_frame_header(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

ws_recv_frame_end(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

ws_send_frame_start(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

ws_send_frame_end(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

protocol_changed(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

transport_changed(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

origin_changed(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

cancel(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

disconnect(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.

terminate(EventData, Pid) ->
	Pid ! {?FUNCTION_NAME, EventData},
	Pid.
