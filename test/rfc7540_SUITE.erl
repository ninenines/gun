%% Copyright (c) 2018-2019, Loïc Hoguin <essen@ninenines.eu>
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

-module(rfc7540_SUITE).
-compile(export_all).
-compile(nowarn_export_all).

-import(ct_helper, [doc/1]).
-import(gun_test, [init_origin/3]).
-import(gun_test, [receive_from/1]).

all() ->
	ct_helper:all(?MODULE).

%% Tests.

authority_default_port_http(_) ->
	doc("The default port for http should not be sent in "
		"the :authority pseudo-header. (RFC7540 3, RFC7230 2.7.1)"),
	do_authority_port(tcp, 80, <<>>).

authority_default_port_https(_) ->
	doc("The default port for https should not be sent in "
		"the :authority pseudo-header. (RFC7540 3, RFC7230 2.7.2)"),
	do_authority_port(tls, 443, <<>>).

authority_ipv6(_) ->
	doc("When connecting to a server using an IPv6 address the :authority "
		"pseudo-header must wrap the address with brackets. (RFC7540 8.1.2.3, RFC3986 3.2.2)"),
	{ok, OriginPid, OriginPort} = init_origin(tcp6, http2, fun(Parent, Socket, Transport) ->
		%% Receive the HEADERS frame and send the headers decoded.
		{ok, <<Len:24, 1:8, _:8, 1:32>>} = Transport:recv(Socket, 9, 1000),
		{ok, ReqHeadersBlock} = Transport:recv(Socket, Len, 1000),
		{ReqHeaders, _} = cow_hpack:decode(ReqHeadersBlock),
		Parent ! {self(), ReqHeaders}
	end),
	{ok, ConnPid} = gun:open({0,0,0,0,0,0,0,1}, OriginPort, #{
		transport => tcp,
		protocols => [http2]
	}),
	{ok, http2} = gun:await_up(ConnPid),
	handshake_completed = receive_from(OriginPid),
	_ = gun:get(ConnPid, "/"),
	ReqHeaders = receive_from(OriginPid),
	{_, <<"[::1]", _/bits>>} = lists:keyfind(<<":authority">>, 1, ReqHeaders),
	gun:close(ConnPid).

authority_other_port_http(_) ->
	doc("Non-default ports for http must be sent in "
		"the :authority pseudo-header. (RFC7540 3, RFC7230 2.7.1)"),
	do_authority_port(tcp, 443, <<":443">>).

authority_other_port_https(_) ->
	doc("Non-default ports for https must be sent in "
		"the :authority pseudo-header. (RFC7540 3, RFC7230 2.7.2)"),
	do_authority_port(tls, 80, <<":80">>).

do_authority_port(Transport0, DefaultPort, AuthorityHeaderPort) ->
	{ok, OriginPid, OriginPort} = init_origin(Transport0, http2, fun(Parent, Socket, Transport) ->
		%% Receive the HEADERS frame and send the headers decoded.
		{ok, <<Len:24, 1:8, _:8, 1:32>>} = Transport:recv(Socket, 9, 1000),
		{ok, ReqHeadersBlock} = Transport:recv(Socket, Len, 1000),
		{ReqHeaders, _} = cow_hpack:decode(ReqHeadersBlock),
		Parent ! {self(), ReqHeaders}
	end),
	{ok, ConnPid} = gun:open("localhost", OriginPort, #{
		transport => Transport0,
		protocols => [http2]
	}),
	{ok, http2} = gun:await_up(ConnPid),
	handshake_completed = receive_from(OriginPid),
	%% Change the origin's port in the state to trigger the default port behavior.
	_ = sys:replace_state(ConnPid, fun({StateName, StateData}) ->
		{StateName, setelement(8, StateData, DefaultPort)}
	end, 5000),
	%% Confirm the default port is not sent in the request.
	_ = gun:get(ConnPid, "/"),
	ReqHeaders = receive_from(OriginPid),
	{_, <<"localhost", Rest/bits>>} = lists:keyfind(<<":authority">>, 1, ReqHeaders),
	AuthorityHeaderPort = Rest,
	gun:close(ConnPid).

prior_knowledge_preface_garbage(_) ->
	doc("A PROTOCOL_ERROR connection error must result from the server sending "
		"an invalid preface in the form of garbage when connecting "
		"using the prior knowledge method. (RFC7540 3.4, RFC7540 3.5)"),
	%% We use 'http' here because we are going to do the handshake manually.
	{ok, OriginPid, Port} = init_origin(tcp, http, fun(_, Socket, Transport) ->
		ok = Transport:send(Socket, <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15>>),
		timer:sleep(100)
	end),
	{ok, ConnPid} = gun:open("localhost", Port, #{protocols => [http2]}),
	{ok, http2} = gun:await_up(ConnPid),
	handshake_completed = receive_from(OriginPid),
	receive
		{gun_down, ConnPid, http2, {error, {connection_error, protocol_error,
				'Invalid connection preface received. (RFC7540 3.5)'}}, []} ->
			gun:close(ConnPid);
		Msg ->
			error({unexpected_msg, Msg})
	after 1000 ->
		error(timeout)
	end.

prior_knowledge_preface_http1(_) ->
	doc("A PROTOCOL_ERROR connection error must result from the server sending "
		"an invalid preface in the form of an HTTP/1.1 response when connecting "
		"using the prior knowledge method. (RFC7540 3.4, RFC7540 3.5)"),
	%% We use 'http' here because we are going to do the handshake manually.
	{ok, OriginPid, Port} = init_origin(tcp, http, fun(_, Socket, Transport) ->
		ok = Transport:send(Socket, <<
			"HTTP/1.1 400 Bad Request\r\n"
			"Connection: close\r\n"
			"Content-Length: 0\r\n"
			"Date: Thu, 27 Feb 2020 09:32:17 GMT\r\n"
			"\r\n">>),
		timer:sleep(100)
	end),
	{ok, ConnPid} = gun:open("localhost", Port, #{protocols => [http2]}),
	{ok, http2} = gun:await_up(ConnPid),
	handshake_completed = receive_from(OriginPid),
	receive
		{gun_down, ConnPid, http2, {error, {connection_error, protocol_error,
				'Invalid connection preface received. Appears to be an HTTP/1 response? (RFC7540 3.5)'}}, []} ->
			gun:close(ConnPid);
		Msg ->
			error({unexpected_msg, Msg})
	after 1000 ->
		error(timeout)
	end.

prior_knowledge_preface_http1_await(_) ->
	doc("A PROTOCOL_ERROR connection error must result from the server sending "
		"an invalid preface in the form of an HTTP/1.1 response when connecting "
		"using the prior knowledge method. (RFC7540 3.4, RFC7540 3.5)"),
	%% We use 'http' here because we are going to do the handshake manually.
	{ok, OriginPid, Port} = init_origin(tcp, http, fun(_, Socket, Transport) ->
		timer:sleep(100),
		ok = Transport:send(Socket, <<
			"HTTP/1.1 400 Bad Request\r\n"
			"Connection: close\r\n"
			"Content-Length: 0\r\n"
			"Date: Thu, 27 Feb 2020 09:32:17 GMT\r\n"
			"\r\n">>),
		timer:sleep(100)
	end),
	{ok, ConnPid} = gun:open("localhost", Port, #{protocols => [http2], retry => 0}),
	{ok, http2} = gun:await_up(ConnPid),
	handshake_completed = receive_from(OriginPid),
	{error, {down, {shutdown, {error, {connection_error, protocol_error,
		'Invalid connection preface received. Appears to be an HTTP/1 response? (RFC7540 3.5)'}}}}}
		= gun:await(ConnPid, make_ref()),
	gun:close(ConnPid).

prior_knowledge_preface_other_frame(_) ->
	doc("A PROTOCOL_ERROR connection error must result from the server sending "
		"an invalid preface in the form of a non-SETTINGS frame when connecting "
		"using the prior knowledge method. (RFC7540 3.4, RFC7540 3.5)"),
	%% We use 'http' here because we are going to do the handshake manually.
	{ok, OriginPid, Port} = init_origin(tcp, http, fun(_, Socket, Transport) ->
		ok = Transport:send(Socket, cow_http2:window_update(1)),
		timer:sleep(100)
	end),
	{ok, ConnPid} = gun:open("localhost", Port, #{protocols => [http2]}),
	{ok, http2} = gun:await_up(ConnPid),
	handshake_completed = receive_from(OriginPid),
	receive
		{gun_down, ConnPid, http2, {error, {connection_error, protocol_error,
				'Invalid connection preface received. (RFC7540 3.5)'}}, []} ->
			gun:close(ConnPid);
		Msg ->
			error({unexpected_msg, Msg})
	after 1000 ->
		error(timeout)
	end.

lingering_data_counts_toward_connection_window(_) ->
	doc("DATA frames received after sending RST_STREAM must be counted "
		"toward the connection flow-control window. (RFC7540 5.1)"),
	{ok, OriginPid, Port} = init_origin(tcp, http2, fun(_, Socket, Transport) ->
		%% Step 2.
		%% Receive a HEADERS frame.
		{ok, <<SkipLen:24, 1:8, _:8, 1:32>>} = Transport:recv(Socket, 9, 1000),
		%% Skip the header.
		{ok, _} = gen_tcp:recv(Socket, SkipLen, 1000),
		%% Step 3.
		%% Send a HEADERS frame.
		{HeadersBlock, _} = cow_hpack:encode([
			{<<":status">>, <<"200">>}
		]),
		ok = Transport:send(Socket, [
			cow_http2:headers(1, nofin, HeadersBlock)
		]),
		%% Step 5.
		%% Make sure Gun sends the RST_STREAM.
		timer:sleep(100),
		%% Step 7.
		ok = Transport:send(Socket, [
			cow_http2:data(1, nofin, <<0:0/unit:8>>),
			cow_http2:data(1, nofin, <<0:1000/unit:8>>)
		]),
		%% Skip RST_STREAM.
		{ok, << 4:24, 3:8, 1:40, _:32 >>} = gen_tcp:recv(Socket, 13, 1000),
		%% Received a WINDOW_UPDATE frame after we got RST_STREAM.
		{ok, << 4:24, 8:8, 0:40, Increment:32 >>} = gen_tcp:recv(Socket, 13, 1000),
		true = Increment > 0
	end),
	{ok, ConnPid} = gun:open("localhost", Port, #{
		protocols => [http2],
		http2_opts => #{
			%% We don't set 65535 because we still want to have an initial WINDOW_UPDATE.
			initial_connection_window_size => 65536,
			initial_stream_window_size => 65535
		}
	}),
	{ok, http2} = gun:await_up(ConnPid),
	handshake_completed = receive_from(OriginPid),
	%% Step 1.
	StreamRef = gun:get(ConnPid, "/"),
	%% Step 4.
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
	%% Step 6.
	gun:cancel(ConnPid, StreamRef),
	%% Make sure Gun sends the WINDOW_UPDATE and the server test passes.
	timer:sleep(300),
	gun:close(ConnPid).

headers_priority_flag(_) ->
	doc("HEADERS frames may include a PRIORITY flag indicating "
		"that stream dependency information is attached. (RFC7540 6.2)"),
	{ok, OriginPid, Port} = init_origin(tcp, http2, fun(_, Socket, Transport) ->
		%% Receive a HEADERS frame.
		{ok, <<_:24, 1:8, _:8, 1:32>>} = Transport:recv(Socket, 9, 1000),
		%% Send a HEADERS frame with PRIORITY back.
		{HeadersBlock, _} = cow_hpack:encode([
			{<<":status">>, <<"200">>}
		]),
		Len = iolist_size(HeadersBlock) + 5,
		ok = Transport:send(Socket, [
			<<Len:24, 1:8,
				0:2, %% Undefined.
				1:1, %% PRIORITY.
				0:1, %% Undefined.
				0:1, %% PADDED.
				1:1, %% END_HEADERS.
				0:1, %% Undefined.
				1:1, %% END_STREAM.
				0:1, 1:31,
				1:1, %% Exclusive?
				3:31, %% Stream dependency.
				42:8 >>, %% Weight.
			HeadersBlock
		]),
		timer:sleep(1000)
	end),
	{ok, ConnPid} = gun:open("localhost", Port, #{protocols => [http2]}),
	{ok, http2} = gun:await_up(ConnPid),
	handshake_completed = receive_from(OriginPid),
	StreamRef = gun:get(ConnPid, "/"),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef),
	gun:close(ConnPid).

settings_ack_timeout(_) ->
	doc("Failure to acknowledge the client's SETTINGS frame "
		"results in a SETTINGS_TIMEOUT connection error. (RFC7540 6.5.3)"),
	%% We use 'http' here because we are going to do the handshake manually.
	{ok, _, Port} = init_origin(tcp, http, fun(_, Socket, Transport) ->
		%% Send a valid preface.
		ok = Transport:send(Socket, cow_http2:settings(#{})),
		%% Receive the fixed sequence from the preface.
		Preface = <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>,
		{ok, Preface} = Transport:recv(Socket, byte_size(Preface), 5000),
		%% Receive the SETTINGS from the preface.
		{ok, <<Len:24>>} = Transport:recv(Socket, 3, 5000),
		{ok, <<4:8, 0:40, _:Len/binary>>} = Transport:recv(Socket, 6 + Len, 5000),
		%% Receive the WINDOW_UPDATE sent with the preface.
		{ok, <<4:24, 8:8, 0:40, _:32>>} = Transport:recv(Socket, 13, 5000),
		%% Receive the SETTINGS ack.
		{ok, <<0:24, 4:8, 1:8, 0:32>>} = Transport:recv(Socket, 9, 5000),
		%% Do not ack the client preface. Expect a GOAWAY with reason SETTINGS_TIMEOUT.
		{ok, << _:24, 7:8, _:72, 4:32 >>} = Transport:recv(Socket, 17, 6000)
	end),
	{ok, ConnPid} = gun:open("localhost", Port, #{protocols => [http2]}),
	{ok, http2} = gun:await_up(ConnPid),
	timer:sleep(6000),
	gun:close(ConnPid).
