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

-module(gun_event).

%% init.

-type init_event() :: #{
	owner := pid(),
	transport := tcp | tls,
	origin_scheme := binary(),
	origin_host := inet:hostname() | inet:ip_address(),
	origin_port := inet:port_number(),
	opts := gun:opts()
}.

-callback init(init_event(), State) -> State.

%% domain_lookup_start/domain_lookup_end.

-type domain_lookup_event() :: #{
	host := inet:hostname() | inet:ip_address(),
	port := inet:port_number(),
	tcp_opts := [gen_tcp:connect_option()],
	timeout := timeout(),
	lookup_info => gun_tcp:lookup_info(),
	error => any()
}.

-callback domain_lookup_start(domain_lookup_event(), State) -> State.
-callback domain_lookup_end(domain_lookup_event(), State) -> State.

%% connect_start/connect_end.

-type connect_event() :: #{
	lookup_info := gun_tcp:lookup_info(),
	timeout := timeout(),
	socket => inet:socket(),
	protocol => http | http2 | socks, %% Only when transport is tcp.
	error => any()
}.

-callback connect_start(connect_event(), State) -> State.
-callback connect_end(connect_event(), State) -> State.

%% tls_handshake_start/tls_handshake_end.
%%
%% These events occur when connecting to a TLS server or when
%% upgrading the connection to use TLS, for example using CONNECT.
%% The stream_ref/reply_to values are only present when the TLS
%% handshake occurs as a result of a request.

-type tls_handshake_event() :: #{
	stream_ref => reference(),
	reply_to => pid(),
	socket := inet:socket() | ssl:sslsocket() | pid(), %% The socket before/after will be different.
	tls_opts := [ssl:tls_client_option()],
	timeout := timeout(),
	protocol => http | http2 | socks,
	error => any()
}.

-callback tls_handshake_start(tls_handshake_event(), State) -> State.
-callback tls_handshake_end(tls_handshake_event(), State) -> State.

%% request_start/request_headers.

-type request_start_event() :: #{
	stream_ref := reference(),
	reply_to := pid(),
	function := headers | request | ws_upgrade,
	method := iodata(),
	scheme => binary(),
	authority := iodata(),
	path := iodata(),
	headers := [{binary(), iodata()}]
}.

-callback request_start(request_start_event(), State) -> State.
-callback request_headers(request_start_event(), State) -> State.

%% request_end.

-type request_end_event() :: #{
	stream_ref := reference(),
	reply_to := pid()
}.

-callback request_end(request_end_event(), State) -> State.

%% push_promise_start.

-type push_promise_start_event() :: #{
	stream_ref := reference(),
	reply_to := pid()
}.

-callback push_promise_start(push_promise_start_event(), State) -> State.

%% push_promise_end.

-type push_promise_end_event() :: #{
	stream_ref := reference(),
	reply_to := pid(),
	%% No stream is created if we receive the push_promise while
	%% in the process of gracefully shutting down the connection.
	%% The promised stream is canceled immediately.
	promised_stream_ref => reference(),
	method := binary(),
	uri := binary(),
	headers := [{binary(), iodata()}]
}.

-callback push_promise_end(push_promise_end_event(), State) -> State.

%% response_start.

-type response_start_event() :: #{
	stream_ref := reference(),
	reply_to := pid()
}.

-callback response_start(response_start_event(), State) -> State.

%% response_inform/response_headers.

-type response_headers_event() :: #{
	stream_ref := reference(),
	reply_to := pid(),
	status := non_neg_integer(),
	headers := [{binary(), binary()}]
}.

-callback response_inform(response_headers_event(), State) -> State.
-callback response_headers(response_headers_event(), State) -> State.

%% response_trailers.

-type response_trailers_event() :: #{
	stream_ref := reference(),
	reply_to := pid(),
	headers := [{binary(), binary()}]
}.

-callback response_trailers(response_trailers_event(), State) -> State.

%% response_end.

-type response_end_event() :: #{
	stream_ref := reference(),
	reply_to := pid()
}.

-callback response_end(response_end_event(), State) -> State.

%% ws_upgrade.
%%
%% This event is a signal that the following request and response
%% result from a gun:ws_upgrade/2,3,4 call.
%%
%% There is no corresponding "end" event. Instead, the success is
%% indicated by a protocol_changed event following the informational
%% response.

-type ws_upgrade_event() :: #{
	stream_ref := reference(),
	reply_to := pid(),
	opts := gun:ws_opts()
}.

-callback ws_upgrade(ws_upgrade_event(), State) -> State.

%% ws_recv_frame_start.

-type ws_recv_frame_start_event() :: #{
	stream_ref := reference(),
	reply_to := pid(),
	frag_state := cow_ws:frag_state(),
	extensions := cow_ws:extensions()
}.

-callback ws_recv_frame_start(ws_recv_frame_start_event(), State) -> State.

%% ws_recv_frame_header.

-type ws_recv_frame_header_event() :: #{
	stream_ref := reference(),
	reply_to := pid(),
	frag_state := cow_ws:frag_state(),
	extensions := cow_ws:extensions(),
	type := cow_ws:frame_type(),
	rsv := cow_ws:rsv(),
	len := non_neg_integer(),
	mask_key := cow_ws:mask_key()
}.

-callback ws_recv_frame_header(ws_recv_frame_header_event(), State) -> State.

%% ws_recv_frame_end.

-type ws_recv_frame_end_event() :: #{
	stream_ref := reference(),
	reply_to := pid(),
	extensions := cow_ws:extensions(),
	close_code := undefined | cow_ws:close_code(),
	payload := binary()
}.

-callback ws_recv_frame_end(ws_recv_frame_end_event(), State) -> State.

%% ws_send_frame_start/ws_send_frame_end.

-type ws_send_frame_event() :: #{
	stream_ref := reference(),
	reply_to := pid(),
	extensions := cow_ws:extensions(),
	frame := gun:ws_frame()
}.

-callback ws_send_frame_start(ws_send_frame_event(), State) -> State.
-callback ws_send_frame_end(ws_send_frame_event(), State) -> State.

%% protocol_changed.
%%
%% This event can occur either following a successful ws_upgrade
%% event or following a successful CONNECT request.
%%
%% @todo Currently there is only a connection-wide variant of this
%% event. In the future there will be a stream-wide variant to
%% support CONNECT and Websocket over HTTP/2.

-type protocol_changed_event() :: #{
	protocol := http | http2 | socks | ws
}.

-callback protocol_changed(protocol_changed_event(), State) -> State.

%% transport_changed.
%%
%% This event can occur following a successful CONNECT request.
%%
%% @todo Currently there is only a connection-wide variant of this
%% event. In the future there will be a stream-wide variant to
%% support CONNECT through TLS proxies over HTTP/2.

-type transport_changed_event() :: #{
	socket := ssl:sslsocket() | pid(),
	transport := tls | tls_proxy
}.

-callback transport_changed(transport_changed_event(), State) -> State.

%% origin_changed.

-type origin_changed_event() :: #{
	type := connect,
	origin_scheme := binary(),
	origin_host := inet:hostname() | inet:ip_address(),
	origin_port := inet:port_number()
}.

-callback origin_changed(origin_changed_event(), State) -> State.

%% cancel.
%%
%% In the case of HTTP/1.1 we cannot actually cancel the stream,
%% we only silence the stream to the user. Further response events
%% may therefore be received and they provide a useful metric as
%% these canceled requests monopolize the connection.
%%
%% For HTTP/2 both the client and the server may cancel streams.
%% Events may still occur for a short time after the cancel.

-type cancel_event() :: #{
	stream_ref := reference(),
	reply_to := pid(),
	endpoint := local | remote,
	reason := atom()
}.

-callback cancel(cancel_event(), State) -> State.

%% disconnect.

-type disconnect_event() :: #{
	reason := normal | closed | {error, any()}
}.

-callback disconnect(disconnect_event(), State) -> State.

%% terminate.

-type terminate_event() :: #{
	state := not_connected | domain_lookup | connecting | tls_handshake | connected,
	reason := normal | shutdown | {shutdown, any()} | any()
}.

-callback terminate(terminate_event(), State) -> State.
