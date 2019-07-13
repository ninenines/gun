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

%% connect_start/connect_end.

-type connect_event() :: #{
	host := inet:hostname() | inet:ip_address(),
	port := inet:port_number(),
	transport := tcp | tls,
	transport_opts := [gen_tcp:connect_option()] | [ssl:connect_option()],
	timeout := timeout(),
	socket => inet:socket() | ssl:sslsocket() | pid(),
	protocol => http | http2,
	error => any()
}.

-callback connect_start(connect_event(), State) -> State.
-callback connect_end(connect_event(), State) -> State.

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

%% protocol_changed.
%%
%% This event can occur either following a successful ws_upgrade
%% event or following a successful CONNECT request.
%%
%% @todo Currently there is only a connection-wide variant of this
%% event. In the future there will be a stream-wide variant to
%% support CONNECT and Websocket over HTTP/2.

-type protocol_changed_event() :: #{
	protocol := http2 | ws
}.

-callback protocol_changed(protocol_changed_event(), State) -> State.

%% disconnect.

-type disconnect_event() :: #{
	reason := normal | closed | {error, any()}
}.

-callback disconnect(disconnect_event(), State) -> State.

%% terminate.

-type terminate_event() :: #{
	state := not_connected | connected,
	reason := normal | shutdown | {shutdown, any()} | any()
}.

-callback terminate(terminate_event(), State) -> State.

%% @todo domain_lookup_start
%% @todo domain_lookup_end
%% @todo tls_handshake_start
%% @todo tls_handshake_end
%% @todo origin_changed
%% @todo transport_changed
%% @todo push_promise_start
%% @todo push_promise_end
%% @todo cancel_start
%% @todo cancel_end
%% @todo ws_frame_read_start
%% @todo ws_frame_read_header
%% @todo ws_frame_read_end
%% @todo ws_frame_write_start
%% @todo ws_frame_write_end
