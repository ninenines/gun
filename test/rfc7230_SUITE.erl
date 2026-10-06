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

-module(rfc7230_SUITE).
-compile(export_all).
-compile(nowarn_export_all).

-import(ct_helper, [doc/1]).
-import(gun_test, [init_origin/2]).
-import(gun_test, [init_origin/3]).
-import(gun_test, [receive_from/1]).

all() ->
	ct_helper:all(?MODULE).

%% Tests.

content_length_duplicate_error(_) ->
	doc("Multiple differing content-length values must be rejected "
		"with a protocol error connection error. (RFC9112 6.3)"),
	{ok, _, OriginPort} = init_origin(tcp, http,
		fun(_, _, ClientSocket, ClientTransport) ->
			{ok, _} = ClientTransport:recv(ClientSocket, 0, 1000),
			ClientTransport:send(ClientSocket,
				"HTTP/1.1 200 OK\r\n"
				"content-length: 4\r\n"
				"content-length: 40\r\n"
				"\r\n"
			)
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:get(ConnPid, "/"),
	{error, {connection_error, {connection_error, protocol_error, _}}} =
		gun:await(ConnPid, StreamRef),
	gun:close(ConnPid).

content_length_equivalent_duplicate_error(_) ->
	doc("Multiple differing content-length values must be rejected "
		"with a protocol error connection error. (RFC9112 6.3)"),
	{ok, _, OriginPort} = init_origin(tcp, http,
		fun(_, _, ClientSocket, ClientTransport) ->
			{ok, _} = ClientTransport:recv(ClientSocket, 0, 1000),
			ClientTransport:send(ClientSocket,
				"HTTP/1.1 200 OK\r\n"
				"content-length: 0\r\n"
				"content-length: 00\r\n"
				"\r\n"
			)
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:get(ConnPid, "/"),
	{error, {connection_error, {connection_error, protocol_error, _}}} =
		gun:await(ConnPid, StreamRef),
	gun:close(ConnPid).

content_length_duplicate_same_value(_) ->
	doc("Identical repeated content-length values must be tolerated. (RFC9112 6.3)"),
	{ok, _, OriginPort} = init_origin(tcp, http,
		fun(_, _, ClientSocket, ClientTransport) ->
			{ok, _} = ClientTransport:recv(ClientSocket, 0, 1000),
			ClientTransport:send(ClientSocket,
				"HTTP/1.1 200 OK\r\n"
				"content-length: 4\r\n"
				"content-length: 4\r\n"
				"\r\n"
				"data"
			)
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:get(ConnPid, "/"),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
	{ok, <<"data">>} = gun:await_body(ConnPid, StreamRef),
	gun:close(ConnPid).

content_length_unparseable_error(_) ->
	doc("An unparseable content-length value must be rejected "
		"with a protocol error connection error. (RFC9112 6.3)"),
	{ok, _, OriginPort} = init_origin(tcp, http,
		fun(_, _, ClientSocket, ClientTransport) ->
			{ok, _} = ClientTransport:recv(ClientSocket, 0, 1000),
			ClientTransport:send(ClientSocket,
				"HTTP/1.1 200 OK\r\n"
				"content-length: abc\r\n"
				"\r\n"
			)
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:get(ConnPid, "/"),
	{error, {connection_error, {connection_error, protocol_error, _}}} =
		gun:await(ConnPid, StreamRef),
	gun:close(ConnPid).

host_default_port_http(_) ->
	doc("The default port for http should not be sent in the host header. (RFC7230 2.7.1)"),
	do_host_port(tcp, 80, <<>>).

host_default_port_https(_) ->
	doc("The default port for https should not be sent in the host header. (RFC7230 2.7.2)"),
	do_host_port(tls, 443, <<>>).

host_ipv6(_) ->
	doc("When connecting to a server using an IPv6 address the host "
		"header must wrap the address with brackets. (RFC7230 5.4, RFC3986 3.2.2)"),
	{ok, OriginPid, OriginPort} = init_origin(tcp6, http),
	{ok, ConnPid} = gun:open({0,0,0,0,0,0,0,1}, OriginPort, #{transport => tcp}),
	{ok, http} = gun:await_up(ConnPid),
	_ = gun:get(ConnPid, "/"),
	handshake_completed = receive_from(OriginPid),
	Data = receive_from(OriginPid),
	Lines = binary:split(Data, <<"\r\n">>, [global]),
	[<<"host: [::1]", _/bits>>] = [L || <<"host: ", _/bits>> = L <- Lines],
	gun:close(ConnPid).

host_other_port_http(_) ->
	doc("Non-default ports for http must be sent in the host header. (RFC7230 2.7.1)"),
	do_host_port(tcp, 443, <<":443">>).

host_other_port_https(_) ->
	doc("Non-default ports for https must be sent in the host header. (RFC7230 2.7.2)"),
	do_host_port(tls, 80, <<":80">>).

do_host_port(Transport, DefaultPort, HostHeaderPort) ->
	{ok, OriginPid, OriginPort} = init_origin(Transport, http),
	{ok, ConnPid} = gun:open("localhost", OriginPort, #{
		transport => Transport,
		tls_opts => [{verify, verify_none}, {versions, ['tlsv1.2']}]
	}),
	{ok, http} = gun:await_up(ConnPid),
	%% Change the origin's port in the state to trigger the default port behavior.
	_ = sys:replace_state(ConnPid, fun({StateName, StateData}) ->
		{StateName, setelement(8, StateData, DefaultPort)}
	end, 5000),
	%% Confirm the default port is not sent in the request.
	_ = gun:get(ConnPid, "/"),
	handshake_completed = receive_from(OriginPid),
	Data = receive_from(OriginPid),
	Lines = binary:split(Data, <<"\r\n">>, [global]),
	[<<"host: localhost", Rest/bits>>] = [L || <<"host: ", _/bits>> = L <- Lines],
	HostHeaderPort = Rest,
	gun:close(ConnPid).

max_headers(_) ->
	doc("The number of headers in a response must be limited "
		"to prevent excessive resource usage. (RFC9110 5.4)"),
	ExtraHeaders = [io_lib:format("h~p: v\r\n", [N]) || N <- lists:seq(1, 150)],
	{ok, _, OriginPort} = init_origin(tcp, http,
		fun(_, _, ClientSocket, ClientTransport) ->
			{ok, _} = ClientTransport:recv(ClientSocket, 0, 1000),
			ClientTransport:send(ClientSocket, [
				"HTTP/1.1 200 OK\r\n",
				ExtraHeaders,
				"content-length: 0\r\n"
				"\r\n"
			])
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:get(ConnPid, "/"),
	{error, _} = gun:await(ConnPid, StreamRef),
	gun:close(ConnPid).

malformed_connection_header(_) ->
	doc("A malformed Connection response header must not crash the connection. (RFC9110 7.6.1)"),
	{ok, _, OriginPort} = init_origin(tcp, http,
		fun(_, _, ClientSocket, ClientTransport) ->
			{ok, _} = ClientTransport:recv(ClientSocket, 0, 1000),
			ClientTransport:send(ClientSocket,
				"HTTP/1.1 200 OK\r\n"
				"connection: @invalid\r\n"
				"content-length: 0\r\n"
				"\r\n"
			)
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:get(ConnPid, "/"),
	{response, fin, 200, _} = gun:await(ConnPid, StreamRef),
	%% The response is delivered, then the connection closes.
	%% A crash in conn_from_headers exits the process instead.
	receive
		{gun_down, ConnPid, http, normal, _} ->
			ok
	after 1000 ->
		error(timeout)
	end,
	true = is_process_alive(ConnPid),
	gun:close(ConnPid).

malformed_status_line_no_crash(_) ->
	doc("A status line that cannot be parsed must not crash the connection. (RFC9112 4)"),
	{ok, _, OriginPort} = init_origin(tcp, http,
		fun(_, _, ClientSocket, ClientTransport) ->
			{ok, _} = ClientTransport:recv(ClientSocket, 0, 1000),
			ClientTransport:send(ClientSocket,
				"HTTP/0.9 200 OK\r\n"
				"\r\n"
			)
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:get(ConnPid, "/"),
	{error, {connection_error, {connection_error, protocol_error, _}}} =
		gun:await(ConnPid, StreamRef),
	gun:close(ConnPid).

malformed_response_headers_no_crash(_) ->
	doc("A header line with no colon must not crash the connection. (RFC9112 5)"),
	{ok, _, OriginPort} = init_origin(tcp, http,
		fun(_, _, ClientSocket, ClientTransport) ->
			{ok, _} = ClientTransport:recv(ClientSocket, 0, 1000),
			ClientTransport:send(ClientSocket,
				"HTTP/1.1 200 OK\r\n"
				"Malformed\r\n"
				"\r\n"
			)
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:get(ConnPid, "/"),
	{error, {connection_error, {connection_error, protocol_error, _}}} =
		gun:await(ConnPid, StreamRef),
	gun:close(ConnPid).

malformed_transfer_encoding_header(_) ->
	doc("A malformed Transfer-Encoding response header must not crash "
		"the connection, and must instead be treated as a protocol error. (RFC9112 6.1)"),
	{ok, _, OriginPort} = init_origin(tcp, http,
		fun(_, _, ClientSocket, ClientTransport) ->
			{ok, _} = ClientTransport:recv(ClientSocket, 0, 1000),
			ClientTransport:send(ClientSocket,
				"HTTP/1.1 200 OK\r\n"
				"transfer-encoding: gzip\r\n"
				"\r\n"
			)
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:get(ConnPid, "/"),
	{error, {connection_error, {connection_error, protocol_error, _}}} =
		gun:await(ConnPid, StreamRef),
	gun:close(ConnPid).

transfer_encoding_multiple_lines(_) ->
	doc("Transfer-Encoding field lines combine into one field. "
		"chunked followed by another coding is a protocol error. (RFC9112 6.1)"),
	{ok, _, OriginPort} = init_origin(tcp, http,
		fun(_, _, ClientSocket, ClientTransport) ->
			{ok, _} = ClientTransport:recv(ClientSocket, 0, 1000),
			ClientTransport:send(ClientSocket,
				"HTTP/1.1 200 OK\r\n"
				"transfer-encoding: chunked\r\n"
				"transfer-encoding: gzip\r\n"
				"\r\n"
			)
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:get(ConnPid, "/"),
	{error, {connection_error, {connection_error, protocol_error, _}}} =
		gun:await(ConnPid, StreamRef),
	gun:close(ConnPid).

malformed_trailers_no_crash(_) ->
	doc("A trailer line with no colon must not crash the connection. (RFC9112 7.1.2, 5)"),
	{ok, _, OriginPort} = init_origin(tcp, http,
		fun(_, _, ClientSocket, ClientTransport) ->
			{ok, _} = ClientTransport:recv(ClientSocket, 0, 1000),
			ClientTransport:send(ClientSocket,
				"HTTP/1.1 200 OK\r\n"
				"transfer-encoding: chunked\r\n"
				"trailer: x-gun\r\n"
				"\r\n"
				"0\r\n"
				"Malformed\r\n"
				"\r\n"
			)
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:get(ConnPid, "/"),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
	{error, {connection_error, {connection_error, protocol_error, _}}} =
		gun:await(ConnPid, StreamRef),
	gun:close(ConnPid).

transfer_encoding_chunk_size_limit(_) ->
	doc("Recipients must anticipate very large chunk sizes. "
		"Reject messages with chunk sizes above 16 digits. (RFC9112 7.1)"),
	{ok, _, OriginPort} = init_origin(tcp, http,
		fun(_, _, ClientSocket, ClientTransport) ->
			{ok, _} = ClientTransport:recv(ClientSocket, 0, 1000),
			ClientTransport:send(ClientSocket,
				"HTTP/1.1 200 OK\r\n"
				"transfer-encoding: chunked\r\n"
				"\r\n"
				"11111111111111111\r\n"
			)
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort, #{retry => 0}),
	{ok, http} = gun:await_up(ConnPid),
	MRef = monitor(process, ConnPid),
	StreamRef = gun:get(ConnPid, "/"),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
	{error, {connection_error, {connection_error, protocol_error, _}}} =
		gun:await(ConnPid, StreamRef),
	receive
		{'DOWN', MRef, process, ConnPid, {shutdown, _}} ->
			ok;
		{'DOWN', MRef, process, ConnPid, Reason} ->
			error({unexpected_crash, Reason})
	after 2000 ->
		error(timeout)
	end.

transfer_encoding_invalid_last_chunk(_) ->
	doc("A last-chunk followed by an octet other than CR must be rejected. "
		"The rest of the data must not be buffered. (RFC9112 7.1)"),
	{ok, _, OriginPort} = init_origin(tcp, http,
		fun(_, _, ClientSocket, ClientTransport) ->
			{ok, _} = ClientTransport:recv(ClientSocket, 0, 1000),
			ClientTransport:send(ClientSocket, [
				"HTTP/1.1 200 OK\r\n"
				"transfer-encoding: chunked\r\n"
				"\r\n"
				"0",
				binary:copy(<<"Z">>, 8000)
			])
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort, #{retry => 0}),
	{ok, http} = gun:await_up(ConnPid),
	MRef = monitor(process, ConnPid),
	StreamRef = gun:get(ConnPid, "/"),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
	{error, {connection_error, {connection_error, protocol_error, _}}} =
		gun:await(ConnPid, StreamRef),
	receive
		{'DOWN', MRef, process, ConnPid, {shutdown, _}} ->
			ok;
		{'DOWN', MRef, process, ConnPid, Reason} ->
			error({unexpected_crash, Reason})
	after 2000 ->
		error(timeout)
	end.

transfer_encoding_incomplete_last_chunk(_) ->
	doc("A finished chunk must be delivered before the last-chunk "
		"line is complete. (RFC9112 7.1)"),
	{ok, OriginPid, OriginPort} = init_origin(tcp, http,
		fun(_, _, ClientSocket, ClientTransport) ->
			{ok, _} = ClientTransport:recv(ClientSocket, 0, 1000),
			ClientTransport:send(ClientSocket,
				"HTTP/1.1 200 OK\r\n"
				"transfer-encoding: chunked\r\n"
				"\r\n"
				"4\r\n"
				"Wiki\r\n"
				"0\r\n"
			),
			receive send_tail ->
				ClientTransport:send(ClientSocket, "\r\n")
			end
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort, #{retry => 0}),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:get(ConnPid, "/"),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
	{data, nofin, <<"Wiki">>} = gun:await(ConnPid, StreamRef),
	{error, timeout} = gun:await(ConnPid, StreamRef, 1000),
	OriginPid ! send_tail,
	{data, fin, <<>>} = gun:await(ConnPid, StreamRef),
	gun:close(ConnPid).

transfer_encoding_overrides_content_length(_) ->
	doc("When both transfer-encoding and content-length are provided, "
		"content-length must be ignored. (RFC7230 3.3.3)"),
	{ok, _, OriginPort} = init_origin(tcp, http,
		fun(_, _, ClientSocket, ClientTransport) ->
			{ok, _} = ClientTransport:recv(ClientSocket, 0, 1000),
			ClientTransport:send(ClientSocket,
				"HTTP/1.1 200 OK\r\n"
				"content-length: 12\r\n"
				"transfer-encoding: chunked\r\n"
				"\r\n"
				"6\r\n"
				"hello \r\n"
				"6\r\n"
				"world!\r\n"
				"0\r\n\r\n"
			)
		end),
	{ok, ConnPid} = gun:open("localhost", OriginPort),
	{ok, http} = gun:await_up(ConnPid),
	StreamRef = gun:get(ConnPid, "/"),
	{response, nofin, 200, _} = gun:await(ConnPid, StreamRef),
	{ok, <<"hello world!">>} = gun:await_body(ConnPid, StreamRef),
	gun:close(ConnPid).
