Supported protocols
===================

This chapter describes the supported protocols and lists
the calls that are valid for each of them.

HTTP
----

HTTP is a text request-response protocol. The client
initiates requests and then waits for the server responses.
The server has no means of creating requests or pushing
data to the client.

SPDY
----

SPDY is a binary protocol based on HTTP, compatible with
the HTTP semantics, that reduces the complexity of parsing
requests and responses, compresses the HTTP headers and
allows the server to push data directly to the client.

Websocket
---------

Websocket is a binary protocol established over HTTP that
allows asynchronous concurrent communication between the
client and the server. A Websocket server can push data to
the client at any time.

Websocket over SPDY is not supported by the Gun client at
this time.

Operations by protocol
----------------------

This table lists all Gun operations and whether they are
compatible with the supported protocols.

| Operation  | SPDY | HTTP | Websocket |
| ---------- | ---- | ---- | --------- |
| delete     | yes  | yes  | no        |
| get        | yes  | yes  | no        |
| head       | yes  | yes  | no        |
| options    | yes  | yes  | no        |
| patch      | yes  | yes  | no        |
| post       | yes  | yes  | no        |
| put        | yes  | yes  | no        |
| request    | yes  | yes  | no        |
| response   | yes  | no   | no        |
| data       | yes  | yes  | no        |
| cancel     | yes  | yes  | no        |
| ws_upgrade | no   | yes  | no        |
| ws_send    | no   | no   | yes       |

While the `cancel` operation is available to HTTP, its effects
will only be local, as there is no way to tell the server to
stop sending data. Gun instead just doesn't forward the messages
for this stream anymore.

Messages by protocol
--------------------

This table lists all messages that can be received depending
on the current protocol.

| Message                         | SPDY | HTTP | Websocket |
| ------------------------------- | ---- | ---- | --------- |
| {gun_push, ...}                 | yes  | no   | no        |
| {gun_response, ...}             | yes  | yes  | no        |
| {gun_data, ...}                 | yes  | yes  | no        |
| {gun_error, _, StreamRef, _}    | yes  | yes  | no        |
| {gun_error, _, _}               | yes  | yes  | yes       |
| {gun_ws_upgrade, _, ok}         | no   | yes  | no        |
| {gun_ws_upgrade, _, error, ...} | no   | yes  | no        |
| {gun_ws, ...}                   | no   | no   | yes       |

Do not forget that other messages may still be in the mailbox
after you upgrade to Websocket.
