gun
===

The `gun` module provides an asynchronous interface for
connecting and communicating with Web servers over SPDY,
HTTP or Websocket.

Types
-----

### opts() = [{keepalive, pos_integer()}
	| {retry, non_neg_integer()}
	| {retry_timeout, pos_integer()}
	| {type, ssl | tcp | tcp_spdy}].

> Configuration for the connection.

Option descriptions
-------------------

The default value is given next to the option name.

 -  keepalive (5000)
   -  Time between pings in milliseconds.
 -  retry (5)
   -  Number of times Gun will try to reconnect on failure before giving up.
 -  retry_timeout (5000)
   -  Time between retries in milliseconds.
 -  type (ssl)
   -  Whether to use SSL, plain TCP (for HTTP/Websocket) or SPDY over TCP.

Messages
--------

Calling functions from this module may result in the following
messages being sent.

### {gun_push, ServerPid, StreamRef, AssocToStreamRef,
	Method, Host, Path, Headers}

> Types:
>  *  ServerPid = pid()
>  *  StreamRef = AssocToStreamRef = reference()
>  *  Method = binary()
>  *  Host = binary()
>  *  Path = binary()
>  *  Headers = [{binary(), binary()}]
>
> A resource pushed alongside an HTTP response.

### {gun_response, ServerPid, StreamRef, IsFin, Status, Headers}

> Types:
>  *  ServerPid = pid()
>  *  StreamRef = reference()
>  *  IsFin = fin | nofin
>  *  Status = binary()
>  *  Headers = [{binary(), binary()}]
>
> A response to an HTTP request.

### {gun_data, ServerPid, StreamRef, IsFin, Data}

> Types:
>  *  ServerPid = pid()
>  *  StreamRef = reference()
>  *  IsFin = fin | nofin
>  *  Data = binary()
>
> Data associated with a response or pushed resource.

### {gun_error, ServerPid, StreamRef, Reason}

> Types:
>  *  ServerPid = pid()
>  *  StreamRef = reference()
>  *  Reason = any()
>
> An error specific to a particular stream.

### {gun_error, ServerPid, Reason}

> Types:
>  *  ServerPid = pid()
>  *  Reason = any()
>
> A general error.

### {gun_ws_upgrade, ServerPid, ok}

> Types:
>  *  ServerPid = pid()
>
> Websocket upgrade success.

### {gun_ws_upgrade, ServerPid, error, IsFin, Status, Headers}

> Types:
>  *  ServerPid = pid()
>  *  IsFin = fin | nofin
>  *  Status = binary()
>  *  Headers = [{binary(), binary()}]
>
> Websocket upgrade failure, with the HTTP response received.

### {gun_ws, ServerPid, Frame}

> Types:
>  *  ServerPid = pid()
>  *  Frame = ws_frame()
>
> A Websocket frame just received.

Exports
-------

### open(Host, Port) -> open(Host, Port, [])
### open(Host, Port, Opts) -> {ok, ServerPid} | {error, any()}

> Types:
>  *  Host = inet:hostname()
>  *  Port = inet:port_number()
>  *  Opts = opts()
>  *  ServerPid = pid()
>
> Open a connection to the given host.

### close(ServerPid) -> ok

> Types:
>  *  ServerPid = pid()
>
> Brutally close the connection.

### shutdown(ServerPid) -> ok

> Types:
>  *  ServerPid = pid()
>
> Gracefully close the connection.
>
> A monitor can be used to be notified when the connection is
> effectively closed.

### delete(ServerPid, Path) -> delete(ServerPid, Path, [])
### delete(ServerPid, Path, Headers) -> StreamRef

> Types:
>  *  ServerPid = pid()
>  *  Path = iodata()
>  *  Headers = [{binary(), iodata()}]
>  *  StreamRef = reference()
>
> Delete a resource.

### get(ServerPid, Path) -> delete(ServerPid, Path, [])
### get(ServerPid, Path, Headers) -> StreamRef

> Types:
>  *  ServerPid = pid()
>  *  Path = iodata()
>  *  Headers = [{binary(), iodata()}]
>  *  StreamRef = reference()
>
> Fetch a resource.

### head(ServerPid, Path) -> delete(ServerPid, Path, [])
### head(ServerPid, Path, Headers) -> StreamRef

> Types:
>  *  ServerPid = pid()
>  *  Path = iodata()
>  *  Headers = [{binary(), iodata()}]
>  *  StreamRef = reference()
>
> Fetch a resource's headers.
>
> The server will not send the resource content, only headers.

### options(ServerPid, Path) -> delete(ServerPid, Path, [])
### options(ServerPid, Path, Headers) -> StreamRef

> Types:
>  *  ServerPid = pid()
>  *  Path = iodata()
>  *  Headers = [{binary(), iodata()}]
>  *  StreamRef = reference()
>
> Obtain information about the capabilities of the server or a resource.
>
> The special path "*" can be used to obtain information about
> the server as a whole. Any other path will return information
> about the resource only.

### patch(ServerPid, Path, Headers) -> StreamRef
### patch(ServerPid, Path, Headers, Body) -> StreamRef

> Types:
>  *  ServerPid = pid()
>  *  Path = iodata()
>  *  Headers = [{binary(), iodata()}]
>  *  StreamRef = reference()
>  *  Body = iodata()
>
> Partially update a resource.
>
> Always set the content-type header so that Gun and the server
> can be made aware that a body is going to be sent. Also try
> to set the content-length header when possible.
>
> If a body is given, even an empty one, it is expected to be
> the full resource.
>
> If not, Gun will assume there is no body if content-type
> isn't set, and otherwise will expect you to stream the body.

### post(ServerPid, Path, Headers) -> StreamRef
### post(ServerPid, Path, Headers, Body) -> StreamRef

> Types:
>  *  ServerPid = pid()
>  *  Path = iodata()
>  *  Headers = [{binary(), iodata()}]
>  *  StreamRef = reference()
>  *  Body = iodata()
>
> Create or update a resource.
>
> The resource may be created at a different URL than the one
> given.
>
> Always set the content-type header so that Gun and the server
> can be made aware that a body is going to be sent. Also try
> to set the content-length header when possible.
>
> If a body is given, even an empty one, it is expected to be
> the full resource.
>
> If not, Gun will assume there is no body if content-type
> isn't set, and otherwise will expect you to stream the body.

### put(ServerPid, Path, Headers) -> StreamRef
### put(ServerPid, Path, Headers, Body) -> StreamRef

> Types:
>  *  ServerPid = pid()
>  *  Path = iodata()
>  *  Headers = [{binary(), iodata()}]
>  *  StreamRef = reference()
>  *  Body = iodata()
>
> Create or update a resource.
>
> The resource will be created at this exact URL.
>
> Always set the content-type header so that Gun and the server
> can be made aware that a body is going to be sent. Also try
> to set the content-length header when possible.
>
> If a body is given, even an empty one, it is expected to be
> the full resource.
>
> If not, Gun will assume there is no body if content-type
> isn't set, and otherwise will expect you to stream the body.

### request(ServerPid, Method, Path, Headers) -> StreamRef
### request(ServerPid, Method, Path, Headers, Body) -> StreamRef

> Types:
>  *  ServerPid = pid()
>  *  Method = iodata()
>  *  Path = iodata()
>  *  Headers = [{binary(), iodata()}]
>  *  StreamRef = reference()
>  *  Body = iodata()
>
> Perform the given request on a resource.
>
> This is a general purpose function that should only be used
> when no other function can be used.
>
> Method names are case sensitive.
>
> Always set the content-type header so that Gun and the server
> can be made aware that a body is going to be sent. Also try
> to set the content-length header when possible.
>
> If a body is given, even an empty one, it is expected to be
> the full resource.
>
> If not, Gun will assume there is no body if content-type
> isn't set, and otherwise will expect you to stream the body.

### data(ServerPid, StreamRef, IsFin, Data) -> ok

> Types:
>  *  ServerPid = pid()
>  *  StreamRef = reference()
>  *  IsFin = fin | nofin
>  *  Data = iodata()
>
> Stream data.
>
> The `StreamRef` argument is the one returned by any of the
> request functions beforehand and uniquely identifies a request.
>
> Use `nofin` for all chunks except the last which should be `fin`.
> The last chunk may be empty.

### cancel(ServerPid, StreamRef) -> ok

> Types:
>  *  ServerPid = pid()
>  *  StreamRef = reference()
>
> Cancel the given stream.
>
> The `StreamRef` argument is the one returned by any of the
> request functions beforehand and uniquely identifies a request.
>
> This function will do a best effort at canceling the stream,
> depending on the capabilities of the protocol.

### ws_upgrade(ServerPid, Path) -> ws_upgrade(ServerPid, Path, [])
### ws_upgrade(ServerPid, Path, Headers) -> ok

> Types:
>  *  ServerPid = pid()
>  *  Path = iodata()
>  *  Headers = [{binary(), iodata()}]
>
> Upgrade the connection to Websocket.

### ws_send(ServerPid, Frames) -> ok

> Types:
>  *  ServerPid = pid()
>  *  Frames = ws_frame() | [ws_frame()]
>
> Send a Websocket frame.
