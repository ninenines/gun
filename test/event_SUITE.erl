%% Copyright (c) 2019-2020, Loïc Hoguin <essen@ninenines.eu>
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
	[
		{http, [parallel], Tests -- [cancel_remote, cancel_remote_connect|PushTests]},
		{http2, [parallel], Tests -- HTTP1Tests}
	].

init_per_suite(Config) ->
	Routes = [
		{"/", hello_h, []},
		{"/empty", empty_h, []},
		{"/inform", inform_h, []},
		{"/push", push_h, []},
		{"/stream", stream_h, []},
		{"/trailers", trailers_h, []},
		{"/ws", ws_echo_h, []}
	],
	ProtoOpts = #{
		enable_connect_protocol => true,
		env => #{dispatch => cowboy_router:compile([{'_', Routes}])}
	},
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

%% tls_handshake_start/tls_handshake_end.

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

tls_handshake_start_tcp_connect_tls(Config) ->
	doc("Confirm that the tls_handshake_start event callback is called "
		"when using CONNECT to a TLS server via a TCP proxy."),
	OriginPort = config(tls_origin_port, Config),
	Protocol = config(name, config(tc_group_properties, Config)),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(Protocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [Protocol],
		transport => tcp
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(Protocol, ProxyPid),
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
	true = case Protocol of
		http -> is_port(Socket);
		http2 -> is_map(Socket)
	end,
	gun:close(ConnPid).

tls_handshake_end_error_tcp_connect_tls(Config) ->
	doc("Confirm that the tls_handshake_end event callback is called on TLS handshake error "
		"when using CONNECT to a TLS server via a TCP proxy."),
	%% We use the wrong port on purpose to trigger a handshake error.
	OriginPort = config(tcp_origin_port, Config),
	Protocol = config(name, config(tc_group_properties, Config)),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(Protocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [Protocol],
		transport => tcp
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(Protocol, ProxyPid),
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
	true = case Protocol of
		http -> is_port(Socket);
		http2 -> is_map(Socket)
	end,
	gun:close(ConnPid).

tls_handshake_end_ok_tcp_connect_tls(Config) ->
	doc("Confirm that the tls_handshake_end event callback is called on TLS handshake success "
		"when using CONNECT to a TLS server via a TCP proxy."),
	OriginPort = config(tls_origin_port, Config),
	Protocol = config(name, config(tc_group_properties, Config)),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(Protocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [Protocol],
		transport => tcp
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(Protocol, ProxyPid),
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
	true = case Protocol of
		http -> is_tuple(Socket);
		http2 -> is_pid(Socket)
	end,
	gun:close(ConnPid).

tls_handshake_start_tls_connect_tls(Config) ->
	doc("Confirm that the tls_handshake_start event callback is called "
		"when using CONNECT to a TLS server via a TLS proxy."),
	OriginPort = config(tls_origin_port, Config),
	Protocol = config(name, config(tc_group_properties, Config)),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(Protocol, tls),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [Protocol],
		transport => tls
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(Protocol, ProxyPid),
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
	true = case Protocol of
		http -> is_tuple(Socket);
		http2 -> is_map(Socket)
	end,
	gun:close(ConnPid).

tls_handshake_end_error_tls_connect_tls(Config) ->
	doc("Confirm that the tls_handshake_end event callback is called on TLS handshake error "
		"when using CONNECT to a TLS server via a TLS proxy."),
	%% We use the wrong port on purpose to trigger a handshake error.
	OriginPort = config(tcp_origin_port, Config),
	Protocol = config(name, config(tc_group_properties, Config)),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(Protocol, tls),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [Protocol],
		transport => tls
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(Protocol, ProxyPid),
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
	true = case Protocol of
		http -> is_tuple(Socket);
		http2 -> is_map(Socket)
	end,
	gun:close(ConnPid).

tls_handshake_end_ok_tls_connect_tls(Config) ->
	doc("Confirm that the tls_handshake_end event callback is called on TLS handshake success "
		"when using CONNECT to a TLS server via a TLS proxy."),
	OriginPort = config(tls_origin_port, Config),
	Protocol = config(name, config(tc_group_properties, Config)),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(Protocol, tls),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [Protocol],
		transport => tls
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(Protocol, ProxyPid),
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

%% request_start/request_headers/request_end.

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

request_start_connect(Config) ->
	doc("Confirm that the request_start event callback is called "
		"for requests going through a CONNECT proxy."),
	do_request_event_connect(Config, request_start),
	do_request_event_headers_connect(Config, request_start).

request_headers_connect(Config) ->
	doc("Confirm that the request_headers event callback is called "
		"for requests going through a CONNECT proxy."),
	do_request_event_connect(Config, request_headers),
	do_request_event_headers_connect(Config, request_headers).

do_request_event_connect(Config, EventName) ->
	OriginPort = config(tcp_origin_port, Config),
	Authority = iolist_to_binary([<<"localhost:">>, integer_to_list(OriginPort)]),
	Protocol = config(name, config(tc_group_properties, Config)),
	ReplyTo = self(),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(Protocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [Protocol]
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(Protocol, ProxyPid),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		protocols => [Protocol]
	}, []),
	#{
		stream_ref := StreamRef1,
		reply_to := ReplyTo,
		function := connect,
		method := <<"CONNECT">>,
		authority := EventAuthority1,
		headers := Headers1
	} = do_receive_event(EventName),
	Authority = iolist_to_binary(EventAuthority1),
	%% Gun doesn't send headers with an HTTP/2 CONNECT request
	%% so we only check that the headers are given as a list.
	true = is_list(Headers1),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{up, Protocol} = gun:await(ConnPid, StreamRef1),
	StreamRef2 = gun:get(ConnPid, "/", [], #{tunnel => StreamRef1}),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo,
		function := request,
		method := <<"GET">>,
		authority := EventAuthority2,
		path := "/",
		headers := [_|_]
	} = do_receive_event(EventName),
	Authority = iolist_to_binary(EventAuthority2),
	gun:close(ConnPid).

do_request_event_headers_connect(Config, EventName) ->
	OriginPort = config(tcp_origin_port, Config),
	Authority = iolist_to_binary([<<"localhost:">>, integer_to_list(OriginPort)]),
	Protocol = config(name, config(tc_group_properties, Config)),
	ReplyTo = self(),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(Protocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [Protocol]
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(Protocol, ProxyPid),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		protocols => [Protocol]
	}, []),
	#{
		stream_ref := StreamRef1,
		reply_to := ReplyTo,
		function := connect,
		method := <<"CONNECT">>,
		authority := EventAuthority1,
		headers := Headers1
	} = do_receive_event(EventName),
	Authority = iolist_to_binary(EventAuthority1),
	%% Gun doesn't send headers with an HTTP/2 CONNECT request
	%% so we only check that the headers are given as a list.
	true = is_list(Headers1),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{up, Protocol} = gun:await(ConnPid, StreamRef1),
	StreamRef2 = gun:put(ConnPid, "/", [
		{<<"content-type">>, <<"text/plain">>}
	], #{tunnel => StreamRef1}),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo,
		function := headers,
		method := <<"PUT">>,
		authority := EventAuthority2,
		path := "/",
		headers := [_|_]
	} = do_receive_event(EventName),
	Authority = iolist_to_binary(EventAuthority2),
	gun:close(ConnPid).

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

request_end_connect(Config) ->
	doc("Confirm that the request_end event callback is called "
		"for requests going through a CONNECT proxy."),
	do_request_end_connect(Config, request_end),
	do_request_end_headers_connect(Config, request_end),
	do_request_end_headers_content_length_connect(Config, request_end),
	do_request_end_headers_content_length_0_connect(Config, request_end).

do_request_end_connect(Config, EventName) ->
	OriginPort = config(tcp_origin_port, Config),
	Protocol = config(name, config(tc_group_properties, Config)),
	ReplyTo = self(),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(Protocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [Protocol]
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(Protocol, ProxyPid),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		protocols => [Protocol]
	}, []),
	#{
		stream_ref := StreamRef1,
		reply_to := ReplyTo
	} = do_receive_event(EventName),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{up, Protocol} = gun:await(ConnPid, StreamRef1),
	StreamRef2 = gun:get(ConnPid, "/", [], #{tunnel => StreamRef1}),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo
	} = do_receive_event(EventName),
	gun:close(ConnPid).

do_request_end_headers_connect(Config, EventName) ->
	OriginPort = config(tcp_origin_port, Config),
	Protocol = config(name, config(tc_group_properties, Config)),
	ReplyTo = self(),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(Protocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [Protocol]
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(Protocol, ProxyPid),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		protocols => [Protocol]
	}, []),
	#{
		stream_ref := StreamRef1,
		reply_to := ReplyTo
	} = do_receive_event(EventName),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{up, Protocol} = gun:await(ConnPid, StreamRef1),
	StreamRef2 = gun:put(ConnPid, "/", [
		{<<"content-type">>, <<"text/plain">>}
	], #{tunnel => StreamRef1}),
	gun:data(ConnPid, StreamRef2, nofin, <<"Hello ">>),
	gun:data(ConnPid, StreamRef2, fin, <<"world!">>),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo
	} = do_receive_event(EventName),
	gun:close(ConnPid).

do_request_end_headers_content_length_connect(Config, EventName) ->
	OriginPort = config(tcp_origin_port, Config),
	Protocol = config(name, config(tc_group_properties, Config)),
	ReplyTo = self(),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(Protocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [Protocol]
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(Protocol, ProxyPid),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		protocols => [Protocol]
	}, []),
	#{
		stream_ref := StreamRef1,
		reply_to := ReplyTo
	} = do_receive_event(EventName),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{up, Protocol} = gun:await(ConnPid, StreamRef1),
	StreamRef2 = gun:put(ConnPid, "/", [
		{<<"content-type">>, <<"text/plain">>},
		{<<"content-length">>, <<"12">>}
	], #{tunnel => StreamRef1}),
	gun:data(ConnPid, StreamRef2, nofin, <<"Hello ">>),
	gun:data(ConnPid, StreamRef2, fin, <<"world!">>),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo
	} = do_receive_event(EventName),
	gun:close(ConnPid).

do_request_end_headers_content_length_0_connect(Config, EventName) ->
	OriginPort = config(tcp_origin_port, Config),
	Protocol = config(name, config(tc_group_properties, Config)),
	ReplyTo = self(),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(Protocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [Protocol]
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(Protocol, ProxyPid),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		protocols => [Protocol]
	}, []),
	#{
		stream_ref := StreamRef1,
		reply_to := ReplyTo
	} = do_receive_event(EventName),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{up, Protocol} = gun:await(ConnPid, StreamRef1),
	StreamRef2 = gun:put(ConnPid, "/", [
		{<<"content-type">>, <<"text/plain">>},
		{<<"content-length">>, <<"0">>}
	], #{tunnel => StreamRef1}),
	gun:data(ConnPid, StreamRef2, fin, <<>>),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo
	} = do_receive_event(EventName),
	gun:close(ConnPid).

%% push_promise_start/push_promise_end.

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

push_promise_start_connect(Config) ->
	doc("Confirm that the push_promise_start event callback is called "
		"for requests going through a CONNECT proxy."),
	do_push_promise_start_connect(Config, http),
	do_push_promise_start_connect(Config, http2).

do_push_promise_start_connect(Config, ProxyProtocol) ->
	OriginPort = config(tcp_origin_port, Config),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(ProxyProtocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [ProxyProtocol]
	}),
	{ok, ProxyProtocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(ProxyProtocol, ProxyPid),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		protocols => [http2]
	}, []),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{up, http2} = gun:await(ConnPid, StreamRef1),
	StreamRef2 = gun:get(ConnPid, "/push", [], #{tunnel => StreamRef1}),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo
	} = do_receive_event(push_promise_start),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo
	} = do_receive_event(push_promise_start),
	gun:close(ConnPid).

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

push_promise_end_connect(Config) ->
	doc("Confirm that the push_promise_end event callback is called "
		"for requests going through a CONNECT proxy."),
	do_push_promise_end_connect(Config, http),
	do_push_promise_end_connect(Config, http2).

do_push_promise_end_connect(Config, ProxyProtocol) ->
	OriginPort = config(tcp_origin_port, Config),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(ProxyProtocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [ProxyProtocol]
	}),
	{ok, ProxyProtocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(ProxyProtocol, ProxyPid),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		protocols => [http2]
	}, []),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{up, http2} = gun:await(ConnPid, StreamRef1),
	StreamRef2 = gun:get(ConnPid, "/push", [], #{tunnel => StreamRef1}),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo,
		promised_stream_ref := [StreamRef1|_],
		method := <<"GET">>,
		uri := <<"http://",_/bits>>,
		headers := [_|_]
	} = do_receive_event(push_promise_end),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo,
		promised_stream_ref := [StreamRef1|_],
		method := <<"GET">>,
		uri := <<"http://",_/bits>>,
		headers := [_|_]
	} = do_receive_event(push_promise_end),
	gun:close(ConnPid).

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

%% response_start/response_inform/response_headers/response_trailers/response_end.

response_start(Config) ->
	doc("Confirm that the response_start event callback is called."),
	{ok, Pid, _} = do_gun_open(Config),
	{ok, _} = gun:await_up(Pid),
	StreamRef = gun:get(Pid, "/"),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

response_start_connect(Config) ->
	doc("Confirm that the response_start event callback is called "
		"for requests going through a CONNECT proxy."),
	OriginPort = config(tcp_origin_port, Config),
	Protocol = config(name, config(tc_group_properties, Config)),
	ReplyTo = self(),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(Protocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [Protocol]
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(Protocol, ProxyPid),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		protocols => [Protocol]
	}, []),
	#{
		stream_ref := StreamRef1,
		reply_to := ReplyTo
	} = do_receive_event(response_start),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{up, Protocol} = gun:await(ConnPid, StreamRef1),
	StreamRef2 = gun:get(ConnPid, "/", [], #{tunnel => StreamRef1}),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo
	} = do_receive_event(response_start),
	gun:close(ConnPid).

response_inform(Config) ->
	doc("Confirm that the response_inform event callback is called."),
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

response_inform_connect(Config) ->
	doc("Confirm that the response_inform event callback is called "
		"for requests going through a CONNECT proxy."),
	OriginPort = config(tcp_origin_port, Config),
	Protocol = config(name, config(tc_group_properties, Config)),
	ReplyTo = self(),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(Protocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [Protocol]
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(Protocol, ProxyPid),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		protocols => [Protocol]
	}, []),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{up, Protocol} = gun:await(ConnPid, StreamRef1),
	StreamRef2 = gun:get(ConnPid, "/inform", [], #{tunnel => StreamRef1}),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo,
		status := 103,
		headers := [_|_]
	} = do_receive_event(response_inform),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo,
		status := 103,
		headers := [_|_]
	} = do_receive_event(response_inform),
	gun:close(ConnPid).

response_headers(Config) ->
	doc("Confirm that the response_headers event callback is called."),
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

response_headers_connect(Config) ->
	doc("Confirm that the response_headers event callback is called "
		"for requests going through a CONNECT proxy."),
	OriginPort = config(tcp_origin_port, Config),
	Protocol = config(name, config(tc_group_properties, Config)),
	ReplyTo = self(),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(Protocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [Protocol]
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(Protocol, ProxyPid),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		protocols => [Protocol]
	}, []),
	#{
		stream_ref := StreamRef1,
		reply_to := ReplyTo,
		status := 200,
		headers := Headers1
	} = do_receive_event(response_headers),
	true = is_list(Headers1),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{up, Protocol} = gun:await(ConnPid, StreamRef1),
	StreamRef2 = gun:get(ConnPid, "/", [], #{tunnel => StreamRef1}),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo,
		status := 200,
		headers := [_|_]
	} = do_receive_event(response_headers),
	gun:close(ConnPid).

response_trailers(Config) ->
	doc("Confirm that the response_trailers event callback is called "
		"for requests going through a CONNECT proxy."),
	OriginPort = config(tcp_origin_port, Config),
	Protocol = config(name, config(tc_group_properties, Config)),
	ReplyTo = self(),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(Protocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [Protocol]
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(Protocol, ProxyPid),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		protocols => [Protocol]
	}, []),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{up, Protocol} = gun:await(ConnPid, StreamRef1),
	StreamRef2 = gun:get(ConnPid, "/trailers", [{<<"te">>, <<"trailers">>}], #{tunnel => StreamRef1}),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo,
		headers := [_|_]
	} = do_receive_event(response_trailers),
	gun:close(ConnPid).

response_end(Config) ->
	doc("Confirm that the response_end event callback is called."),
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

response_end_connect(Config) ->
	doc("Confirm that the response_end event callback is called "
		"for requests going through a CONNECT proxy."),
	do_response_end_connect(Config, response_end, "/"),
	do_response_end_connect(Config, response_end, "/empty"),
	do_response_end_connect(Config, response_end, "/stream"),
	do_response_end_connect(Config, response_end, "/trailers").

do_response_end_connect(Config, EventName, Path) ->
	OriginPort = config(tcp_origin_port, Config),
	Protocol = config(name, config(tc_group_properties, Config)),
	ReplyTo = self(),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(Protocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [Protocol]
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(Protocol, ProxyPid),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		protocols => [Protocol]
	}, []),
	#{
		stream_ref := StreamRef1,
		reply_to := ReplyTo
	} = do_receive_event(EventName),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{up, Protocol} = gun:await(ConnPid, StreamRef1),
	StreamRef2 = gun:get(ConnPid, Path, [{<<"te">>, <<"trailers">>}], #{tunnel => StreamRef1}),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo
	} = do_receive_event(EventName),
	gun:close(ConnPid).

http1_response_end_body_close(Config) ->
	doc("Confirm that the response_end event callback is called "
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

%% @todo Figure out how to test both this and TLS handshake errors. Maybe a proxy option?
%response_end_body_close_connect(Config) ->
%	doc("Confirm that the response_end event callback is called "
%		"when using HTTP/1.0 and the content-length header is not set "
%		"for requests going through a CONNECT proxy."),
%	OriginPort = config(tcp_origin_port, Config),
%	Protocol = config(name, config(tc_group_properties, Config)),
%	ReplyTo = self(),
%	{ok, ProxyPid, ProxyPort} = do_proxy_start(Protocol, tcp),
%	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
%		event_handler => {?MODULE, self()},
%		protocols => [Protocol]
%	}),
%	{ok, Protocol} = gun:await_up(ConnPid),
%	tunnel_SUITE:do_handshake_completed(Protocol, ProxyPid),
%	StreamRef1 = gun:connect(ConnPid, #{
%		host => "localhost",
%		port => OriginPort,
%		protocols => [{http, #{version => 'HTTP/1.0'}}]
%	}, []),
%	#{
%		stream_ref := StreamRef1,
%		reply_to := ReplyTo
%	} = do_receive_event(response_end),
%	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
%	{up, http} = gun:await(ConnPid, StreamRef1),
%	StreamRef2 = gun:get(ConnPid, "/stream", [], #{tunnel => StreamRef1}),
%	#{
%		stream_ref := StreamRef2,
%		reply_to := ReplyTo
%	} = do_receive_event(response_end),
%	gun:close(ConnPid).

%% ws_upgrade.

ws_upgrade(Config) ->
	doc("Confirm that the ws_upgrade event callback is called."),
	Protocol = config(name, config(tc_group_properties, Config)),
	{ok, Pid, _} = do_gun_open(Config),
	{ok, Protocol} = gun:await_up(Pid),
	ws_SUITE:do_await_enable_connect_protocol(Protocol, Pid),
	StreamRef = gun:ws_upgrade(Pid, "/ws"),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		opts := #{}
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

ws_upgrade_connect(Config) ->
	doc("Confirm that the ws_upgrade event callback is called "
		"for requests going through a CONNECT proxy."),
	do_ws_upgrade_connect(Config, http),
	do_ws_upgrade_connect(Config, http2).

do_ws_upgrade_connect(Config, ProxyProtocol) ->
	OriginPort = config(tcp_origin_port, Config),
	OriginProtocol = config(name, config(tc_group_properties, Config)),
	ReplyTo = self(),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(ProxyProtocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [ProxyProtocol]
	}),
	{ok, ProxyProtocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(ProxyProtocol, ProxyPid),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		protocols => [case OriginProtocol of
			http -> http;
			http2 -> {http2, #{notify_settings_changed => true}}
		end]
	}, []),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{up, OriginProtocol} = gun:await(ConnPid, StreamRef1),
	ws_SUITE:do_await_enable_connect_protocol(OriginProtocol, ConnPid),
	StreamRef2 = gun:ws_upgrade(ConnPid, "/ws", [], #{tunnel => StreamRef1}),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo,
		opts := #{}
	} = do_receive_event(ws_upgrade),
	gun:close(ConnPid).

ws_upgrade_all_events(Config) ->
	doc("Confirm that a Websocket upgrade triggers all relevant events."),
	Protocol = config(name, config(tc_group_properties, Config)),
	{ok, Pid, OriginPort} = do_gun_open(Config),
	{ok, Protocol} = gun:await_up(Pid),
	ws_SUITE:do_await_enable_connect_protocol(Protocol, Pid),
	StreamRef = gun:ws_upgrade(Pid, "/ws"),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		opts := #{}
	} = do_receive_event(ws_upgrade),
	Authority = iolist_to_binary([<<"localhost:">>, integer_to_list(OriginPort)]),
	Method = case Protocol of
		http -> <<"GET">>;
		http2 -> <<"CONNECT">>
	end,
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		function := ws_upgrade,
		method := Method,
		authority := EventAuthority1,
		path := "/ws",
		headers := [_|_]
	} = do_receive_event(request_start),
	Authority = iolist_to_binary(EventAuthority1),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		function := ws_upgrade,
		method := Method,
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
	_ = case Protocol of
		http ->
			#{
				stream_ref := StreamRef,
				reply_to := ReplyTo,
				status := 101,
				headers := [_|_]
			} = do_receive_event(response_inform);
		http2 ->
			#{
				stream_ref := StreamRef,
				reply_to := ReplyTo,
				status := 200,
				headers := [_|_]
			} = do_receive_event(response_headers),
			#{
				stream_ref := StreamRef,
				reply_to := ReplyTo
			} = do_receive_event(response_end)
	end,
	#{
		stream_ref := StreamRef,
		protocol := ws
	} = do_receive_event(protocol_changed),
	gun:close(Pid).

ws_upgrade_all_events_connect(Config) ->
	doc("Confirm that a Websocket upgrade triggers all relevant events "
		"for requests going through a CONNECT proxy."),
	do_ws_upgrade_all_events_connect(Config, http),
	do_ws_upgrade_all_events_connect(Config, http2).

do_ws_upgrade_all_events_connect(Config, ProxyProtocol) ->
	OriginPort = config(tcp_origin_port, Config),
	OriginProtocol = config(name, config(tc_group_properties, Config)),
	ReplyTo = self(),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(ProxyProtocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [ProxyProtocol]
	}),
	{ok, ProxyProtocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(ProxyProtocol, ProxyPid),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		protocols => [case OriginProtocol of
			http -> http;
			http2 -> {http2, #{notify_settings_changed => true}}
		end]
	}, []),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{up, OriginProtocol} = gun:await(ConnPid, StreamRef1),
	ws_SUITE:do_await_enable_connect_protocol(OriginProtocol, ConnPid),
	%% Skip all CONNECT-related events that may conflict.
	_ = do_receive_event(request_start),
	_ = do_receive_event(request_headers),
	_ = do_receive_event(request_end),
	_ = do_receive_event(response_start),
	_ = do_receive_event(response_headers),
	_ = do_receive_event(response_end),
	_ = do_receive_event(protocol_changed),
	%% Check the Websocket events.
	StreamRef2 = gun:ws_upgrade(ConnPid, "/ws", [], #{tunnel => StreamRef1}),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo,
		opts := #{}
	} = do_receive_event(ws_upgrade),
	Authority = iolist_to_binary([<<"localhost:">>, integer_to_list(OriginPort)]),
	Method = case OriginProtocol of
		http -> <<"GET">>;
		http2 -> <<"CONNECT">>
	end,
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo,
		function := ws_upgrade,
		method := Method,
		authority := EventAuthority1,
		path := "/ws",
		headers := [_|_]
	} = do_receive_event(request_start),
	Authority = iolist_to_binary(EventAuthority1),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo,
		function := ws_upgrade,
		method := Method,
		authority := EventAuthority2,
		path := "/ws",
		headers := [_|_]
	} = do_receive_event(request_headers),
	Authority = iolist_to_binary(EventAuthority2),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo
	} = do_receive_event(request_end),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo
	} = do_receive_event(response_start),
	_ = case OriginProtocol of
		http ->
			#{
				stream_ref := StreamRef2,
				reply_to := ReplyTo,
				status := 101,
				headers := [_|_]
			} = do_receive_event(response_inform);
		http2 ->
			#{
				stream_ref := StreamRef2,
				reply_to := ReplyTo,
				status := 200,
				headers := [_|_]
			} = do_receive_event(response_headers),
			#{
				stream_ref := StreamRef2,
				reply_to := ReplyTo
			} = do_receive_event(response_end)
	end,
	#{
		stream_ref := StreamRef2,
		protocol := ws
	} = do_receive_event(protocol_changed),
	gun:close(ConnPid).

%% ws_recv_frame_start/ws_recv_frame_header/ws_recv_frame_end.

ws_recv_frame_start(Config) ->
	doc("Confirm that the ws_recv_frame_start event callback is called."),
	Protocol = config(name, config(tc_group_properties, Config)),
	{ok, Pid, _} = do_gun_open(Config),
	{ok, Protocol} = gun:await_up(Pid),
	ws_SUITE:do_await_enable_connect_protocol(Protocol, Pid),
	StreamRef = gun:ws_upgrade(Pid, "/ws"),
	{upgrade, [<<"websocket">>], _} = gun:await(Pid, StreamRef),
	gun:ws_send(Pid, StreamRef, {text, <<"Hello!">>}),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		frag_state := undefined,
		extensions := #{}
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

ws_recv_frame_start_connect(Config) ->
	doc("Confirm that the ws_recv_frame_start event callback is called "
		"for requests going through a CONNECT proxy."),
	do_ws_recv_frame_start_connect(Config, http),
	do_ws_recv_frame_start_connect(Config, http2).

do_ws_recv_frame_start_connect(Config, ProxyProtocol) ->
	OriginPort = config(tcp_origin_port, Config),
	OriginProtocol = config(name, config(tc_group_properties, Config)),
	ReplyTo = self(),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(ProxyProtocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [ProxyProtocol]
	}),
	{ok, ProxyProtocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(ProxyProtocol, ProxyPid),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		protocols => [case OriginProtocol of
			http -> http;
			http2 -> {http2, #{notify_settings_changed => true}}
		end]
	}, []),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{up, OriginProtocol} = gun:await(ConnPid, StreamRef1),
	ws_SUITE:do_await_enable_connect_protocol(OriginProtocol, ConnPid),
	StreamRef2 = gun:ws_upgrade(ConnPid, "/ws", [], #{tunnel => StreamRef1}),
	{upgrade, [<<"websocket">>], _} = gun:await(ConnPid, StreamRef2),
	gun:ws_send(ConnPid, StreamRef2, {text, <<"Hello!">>}),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo,
		frag_state := undefined,
		extensions := #{}
	} = do_receive_event(ws_recv_frame_start),
	gun:close(ConnPid).

ws_recv_frame_header(Config) ->
	doc("Confirm that the ws_recv_frame_header event callback is called."),
	Protocol = config(name, config(tc_group_properties, Config)),
	{ok, Pid, _} = do_gun_open(Config),
	{ok, Protocol} = gun:await_up(Pid),
	ws_SUITE:do_await_enable_connect_protocol(Protocol, Pid),
	StreamRef = gun:ws_upgrade(Pid, "/ws"),
	{upgrade, [<<"websocket">>], _} = gun:await(Pid, StreamRef),
	gun:ws_send(Pid, StreamRef, {text, <<"Hello!">>}),
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

ws_recv_frame_header_connect(Config) ->
	doc("Confirm that the ws_recv_frame_header event callback is called "
		"for requests going through a CONNECT proxy."),
	do_ws_recv_frame_header_connect(Config, http),
	do_ws_recv_frame_header_connect(Config, http2).

do_ws_recv_frame_header_connect(Config, ProxyProtocol) ->
	OriginPort = config(tcp_origin_port, Config),
	OriginProtocol = config(name, config(tc_group_properties, Config)),
	ReplyTo = self(),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(ProxyProtocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [ProxyProtocol]
	}),
	{ok, ProxyProtocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(ProxyProtocol, ProxyPid),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		protocols => [case OriginProtocol of
			http -> http;
			http2 -> {http2, #{notify_settings_changed => true}}
		end]
	}, []),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{up, OriginProtocol} = gun:await(ConnPid, StreamRef1),
	ws_SUITE:do_await_enable_connect_protocol(OriginProtocol, ConnPid),
	StreamRef2 = gun:ws_upgrade(ConnPid, "/ws", [], #{tunnel => StreamRef1}),
	{upgrade, [<<"websocket">>], _} = gun:await(ConnPid, StreamRef2),
	gun:ws_send(ConnPid, StreamRef2, {text, <<"Hello!">>}),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo,
		frag_state := undefined,
		extensions := #{},
		type := text,
		rsv := <<0:3>>,
		len := 6,
		mask_key := _
	} = do_receive_event(ws_recv_frame_header),
	gun:close(ConnPid).

ws_recv_frame_end(Config) ->
	doc("Confirm that the ws_recv_frame_end event callback is called."),
	Protocol = config(name, config(tc_group_properties, Config)),
	{ok, Pid, _} = do_gun_open(Config),
	{ok, Protocol} = gun:await_up(Pid),
	ws_SUITE:do_await_enable_connect_protocol(Protocol, Pid),
	StreamRef = gun:ws_upgrade(Pid, "/ws"),
	{upgrade, [<<"websocket">>], _} = gun:await(Pid, StreamRef),
	gun:ws_send(Pid, StreamRef, {text, <<"Hello!">>}),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		extensions := #{},
		close_code := undefined,
		payload := <<"Hello!">>
	} = do_receive_event(?FUNCTION_NAME),
	gun:close(Pid).

ws_recv_frame_end_connect(Config) ->
	doc("Confirm that the ws_recv_frame_end event callback is called "
		"for requests going through a CONNECT proxy."),
	do_ws_recv_frame_end_connect(Config, http),
	do_ws_recv_frame_end_connect(Config, http2).

do_ws_recv_frame_end_connect(Config, ProxyProtocol) ->
	OriginPort = config(tcp_origin_port, Config),
	OriginProtocol = config(name, config(tc_group_properties, Config)),
	ReplyTo = self(),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(ProxyProtocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [ProxyProtocol]
	}),
	{ok, ProxyProtocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(ProxyProtocol, ProxyPid),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		protocols => [case OriginProtocol of
			http -> http;
			http2 -> {http2, #{notify_settings_changed => true}}
		end]
	}, []),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{up, OriginProtocol} = gun:await(ConnPid, StreamRef1),
	ws_SUITE:do_await_enable_connect_protocol(OriginProtocol, ConnPid),
	StreamRef2 = gun:ws_upgrade(ConnPid, "/ws", [], #{tunnel => StreamRef1}),
	{upgrade, [<<"websocket">>], _} = gun:await(ConnPid, StreamRef2),
	gun:ws_send(ConnPid, StreamRef2, {text, <<"Hello!">>}),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo,
		extensions := #{},
		close_code := undefined,
		payload := <<"Hello!">>
	} = do_receive_event(ws_recv_frame_end),
	gun:close(ConnPid).

%% ws_send_frame_start/ws_send_frame_end.

ws_send_frame_start(Config) ->
	doc("Confirm that the ws_send_frame_start event callback is called."),
	do_ws_send_frame(Config, ?FUNCTION_NAME).

ws_send_frame_end(Config) ->
	doc("Confirm that the ws_send_frame_end event callback is called."),
	do_ws_send_frame(Config, ?FUNCTION_NAME).

do_ws_send_frame(Config, EventName) ->
	Protocol = config(name, config(tc_group_properties, Config)),
	{ok, Pid, _} = do_gun_open(Config),
	{ok, Protocol} = gun:await_up(Pid),
	ws_SUITE:do_await_enable_connect_protocol(Protocol, Pid),
	StreamRef = gun:ws_upgrade(Pid, "/ws"),
	{upgrade, [<<"websocket">>], _} = gun:await(Pid, StreamRef),
	gun:ws_send(Pid, StreamRef, {text, <<"Hello!">>}),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef,
		reply_to := ReplyTo,
		extensions := #{},
		frame := {text, <<"Hello!">>}
	} = do_receive_event(EventName),
	gun:close(Pid).

ws_send_frame_start_connect(Config) ->
	doc("Confirm that the ws_send_frame_start event callback is called "
		"for requests going through a CONNECT proxy."),
	do_ws_send_frame_connect(Config, http, ws_send_frame_start),
	do_ws_send_frame_connect(Config, http2, ws_send_frame_start).

ws_send_frame_end_connect(Config) ->
	doc("Confirm that the ws_send_frame_end event callback is called "
		"for requests going through a CONNECT proxy."),
	do_ws_send_frame_connect(Config, http, ws_send_frame_end),
	do_ws_send_frame_connect(Config, http2, ws_send_frame_end).

do_ws_send_frame_connect(Config, ProxyProtocol, EventName) ->
	OriginPort = config(tcp_origin_port, Config),
	OriginProtocol = config(name, config(tc_group_properties, Config)),
	ReplyTo = self(),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(ProxyProtocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [ProxyProtocol]
	}),
	{ok, ProxyProtocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(ProxyProtocol, ProxyPid),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		protocols => [case OriginProtocol of
			http -> http;
			http2 -> {http2, #{notify_settings_changed => true}}
		end]
	}, []),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{up, OriginProtocol} = gun:await(ConnPid, StreamRef1),
	ws_SUITE:do_await_enable_connect_protocol(OriginProtocol, ConnPid),
	StreamRef2 = gun:ws_upgrade(ConnPid, "/ws", [], #{tunnel => StreamRef1}),
	{upgrade, [<<"websocket">>], _} = gun:await(ConnPid, StreamRef2),
	gun:ws_send(ConnPid, StreamRef2, {text, <<"Hello!">>}),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo,
		extensions := #{},
		frame := {text, <<"Hello!">>}
	} = do_receive_event(EventName),
	gun:close(ConnPid).

%% protocol_changed.

ws_protocol_changed(Config) ->
	doc("Confirm that the protocol_changed event callback is called on Websocket upgrade success."),
	Protocol = config(name, config(tc_group_properties, Config)),
	{ok, Pid, _} = do_gun_open(Config),
	{ok, Protocol} = gun:await_up(Pid),
	ws_SUITE:do_await_enable_connect_protocol(Protocol, Pid),
	_ = gun:ws_upgrade(Pid, "/ws"),
	#{
		protocol := ws
	} = do_receive_event(protocol_changed),
	gun:close(Pid).

ws_protocol_changed_connect(Config) ->
	doc("Confirm that the protocol_changed event callback is called on Websocket upgrade success "
		"for requests going through a CONNECT proxy."),
	do_ws_protocol_changed_connect(Config, http),
	do_ws_protocol_changed_connect(Config, http2).

do_ws_protocol_changed_connect(Config, ProxyProtocol) ->
	OriginPort = config(tcp_origin_port, Config),
	OriginProtocol = config(name, config(tc_group_properties, Config)),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(ProxyProtocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [ProxyProtocol]
	}),
	{ok, ProxyProtocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(ProxyProtocol, ProxyPid),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		protocols => [case OriginProtocol of
			http -> http;
			http2 -> {http2, #{notify_settings_changed => true}}
		end]
	}, []),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{up, OriginProtocol} = gun:await(ConnPid, StreamRef1),
	ws_SUITE:do_await_enable_connect_protocol(OriginProtocol, ConnPid),
	#{
		stream_ref := StreamRef1,
		protocol := OriginProtocol
	} = do_receive_event(protocol_changed),
	StreamRef2 = gun:ws_upgrade(ConnPid, "/ws", [], #{tunnel => StreamRef1}),
	#{
		stream_ref := StreamRef2,
		protocol := ws
	} = do_receive_event(protocol_changed),
	gun:close(ConnPid).

protocol_changed_connect(Config) ->
	doc("Confirm that the protocol_changed event callback is called on CONNECT success "
		"when connecting through a TCP server via a TCP proxy."),
	do_protocol_changed_connect(Config, http),
	do_protocol_changed_connect(Config, http2).

do_protocol_changed_connect(Config, OriginProtocol) ->
	OriginPort = config(tcp_origin_port, Config),
	ProxyProtocol = config(name, config(tc_group_properties, Config)),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(ProxyProtocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [ProxyProtocol],
		transport => tcp
	}),
	{ok, ProxyProtocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(ProxyProtocol, ProxyPid),
	StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		protocols => [OriginProtocol]
	}),
	#{
		stream_ref := StreamRef,
		protocol := OriginProtocol
	} = do_receive_event(protocol_changed),
	gun:close(ConnPid).

protocol_changed_tls_connect(Config) ->
	doc("Confirm that the protocol_changed event callback is called on CONNECT success "
		"when connecting to a TLS server via a TLS proxy."),
	do_protocol_changed_tls_connect(Config, http),
	do_protocol_changed_tls_connect(Config, http2).

do_protocol_changed_tls_connect(Config, OriginProtocol) ->
	OriginPort = config(tls_origin_port, Config),
	ProxyProtocol = config(name, config(tc_group_properties, Config)),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(ProxyProtocol, tls),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [ProxyProtocol],
		transport => tls
	}),
	{ok, ProxyProtocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(ProxyProtocol, ProxyPid),
	StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		transport => tls,
		protocols => [OriginProtocol]
	}),
	#{
		stream_ref := StreamRef,
		protocol := OriginProtocol
	} = do_receive_event(protocol_changed),
	gun:close(ConnPid).

%% origin_changed.

origin_changed_connect(Config) ->
	doc("Confirm that the origin_changed event callback is called on CONNECT success."),
	OriginPort = config(tcp_origin_port, Config),
	ProxyProtocol = config(name, config(tc_group_properties, Config)),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(ProxyProtocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [ProxyProtocol],
		transport => tcp
	}),
	{ok, ProxyProtocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(ProxyProtocol, ProxyPid),
	StreamRef = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort
	}),
	Event = #{
		type := connect,
		origin_scheme := <<"http">>,
		origin_host := "localhost",
		origin_port := OriginPort
	} = do_receive_event(origin_changed),
	case ProxyProtocol of
		http -> ok;
		http2 ->
			#{stream_ref := StreamRef} = Event
	end,
	gun:close(ConnPid).

origin_changed_connect_connect(Config) ->
	doc("Confirm that the origin_changed event callback is called on CONNECT success "
		"when performed inside another CONNECT tunnel."),
	OriginPort = config(tcp_origin_port, Config),
	ProxyProtocol = config(name, config(tc_group_properties, Config)),
	{ok, Proxy1Pid, Proxy1Port} = do_proxy_start(ProxyProtocol, tcp),
	{ok, Proxy2Pid, Proxy2Port} = do_proxy_start(ProxyProtocol, tcp),
	{ok, ConnPid} = gun:open("localhost", Proxy1Port, #{
		event_handler => {?MODULE, self()},
		protocols => [ProxyProtocol],
		transport => tcp
	}),
	{ok, ProxyProtocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(ProxyProtocol, Proxy1Pid),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => Proxy2Port,
		protocols => [ProxyProtocol]
	}),
	Event1 = #{
		type := connect,
		origin_scheme := <<"http">>,
		origin_host := "localhost",
		origin_port := Proxy2Port
	} = do_receive_event(origin_changed),
	case ProxyProtocol of
		http -> ok;
		http2 ->
			#{stream_ref := StreamRef1} = Event1
	end,
	tunnel_SUITE:do_handshake_completed(ProxyProtocol, Proxy2Pid),
	StreamRef2 = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort
	}, [], #{tunnel => StreamRef1}),
	Event2 = #{
		type := connect,
		origin_scheme := <<"http">>,
		origin_host := "localhost",
		origin_port := OriginPort
	} = do_receive_event(origin_changed),
	case ProxyProtocol of
		http -> ok;
		http2 ->
			#{stream_ref := StreamRef2} = Event2
	end,
	gun:close(ConnPid).

%% cancel.

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

cancel_connect(Config) ->
	doc("Confirm that the cancel event callback is called when we "
		"cancel a stream running inside a CONNECT proxy."),
	OriginPort = config(tcp_origin_port, Config),
	Protocol = config(name, config(tc_group_properties, Config)),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(Protocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [Protocol],
		transport => tcp
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(Protocol, ProxyPid),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		protocols => [Protocol]
	}),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{up, Protocol} = gun:await(ConnPid, StreamRef1),
	StreamRef2 = gun:post(ConnPid, "/stream", [], #{tunnel => StreamRef1}),
	gun:cancel(ConnPid, StreamRef2),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo,
		endpoint := local,
		reason := cancel
	} = do_receive_event(cancel),
	gun:close(ConnPid).

cancel_remote_connect(Config) ->
	doc("Confirm that the cancel event callback is called when the "
		"remote endpoint cancels a stream running inside a CONNECT proxy."),
	OriginPort = config(tcp_origin_port, Config),
	Protocol = config(name, config(tc_group_properties, Config)),
	{ok, ProxyPid, ProxyPort} = do_proxy_start(Protocol, tcp),
	{ok, ConnPid} = gun:open("localhost", ProxyPort, #{
		event_handler => {?MODULE, self()},
		protocols => [Protocol],
		transport => tcp
	}),
	{ok, Protocol} = gun:await_up(ConnPid),
	tunnel_SUITE:do_handshake_completed(Protocol, ProxyPid),
	StreamRef1 = gun:connect(ConnPid, #{
		host => "localhost",
		port => OriginPort,
		protocols => [Protocol]
	}),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef1),
	{up, Protocol} = gun:await(ConnPid, StreamRef1),
	StreamRef2 = gun:post(ConnPid, "/stream", [], #{tunnel => StreamRef1}),
	ReplyTo = self(),
	#{
		stream_ref := StreamRef2,
		reply_to := ReplyTo,
		endpoint := remote,
		reason := _
	} = do_receive_event(cancel),
	gun:close(ConnPid).

%% disconnect.

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

%% terminate.

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
		http2_opts => #{notify_settings_changed => true},
		protocols => [config(name, config(tc_group_properties, Config))]
	},
	{ok, Pid} = gun:open("localhost", OriginPort, Opts),
	{ok, Pid, OriginPort}.

do_gun_open_tls(Config) ->
	OriginPort = config(tls_origin_port, Config),
	Opts = #{
		event_handler => {?MODULE, self()},
		http2_opts => #{notify_settings_changed => true},
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

do_proxy_start(Protocol, Transport) ->
	case Protocol of
		http -> rfc7231_SUITE:do_proxy_start(Transport);
		http2 -> rfc7540_SUITE:do_proxy_start(Transport)
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
