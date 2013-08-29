Using HTTP
==========

This chapter describes how to use the Gun client for
communicating with an HTTP or SPDY server.

Streams
-------

Every time a request is initiated, either by the client or the
server, Gun creates a "stream". The stream controls whether
the endpoints are still sending any data, and allows you to
identify incoming messages.

Streams are references in Gun, and are therefore always unique.

Streams can be canceled at any time. This will stop any further
messages being sent to the controlling process. Depending on
its capabilities, the server will also be instructed to drop
the request.

Canceling a stream may result in Gun dropping the connection
temporarily, to avoid uploading or downloading data that will
not be used. This situation can only occur with HTTP, as SPDY
features stream canceling as part of its protocol.

To cancel a stream, the `gun:cancel/2` function can be used.

``` erlang
gun:cancel(Pid, StreamRef}.
```

Sending requests
----------------

Gun provides many convenient functions for performing common
operations, like GET, POST or DELETE. It also provides a
general purpose function in case you need other methods.

The availability of these methods on the server can vary
depending on the software used but also on a per-resource
basis.

To retrieve a resource, `gun:get/{2,3}` can be used. If you
don't need the response body, `gun:head/{2,3}` is available.
As this type of requests can't have a request body, only the
path and optionally the headers can be specified.

``` erlang
%% Without headers.
StreamRef = gun:get(Pid, "/organizations/extend").
%% With headers.
StreamRef = gun:get(Pid, "/organizations/extend", [
    {"accept", "application/json"},
    {"user-agent", "revolver/1.0"}]).
```

To create or update a resource, the functions `gun:patch/{3,4}`,
`gun:post/{3,4}` and `gun:put/{3,4}` can be used. As this type
of request is meant to come with a body, headers are not optional,
because you must specify at least the content-type of the body,
and if possible also the content-length. The body is however
optional, because there might not be any at all, or because it
will be subsequently streamed. If a body is set here it is assumed
to be the full body.

``` erlang
%% Without body.
StreamRef = gun:put(Pid, "/organizations/extend", [
    {"content-length", 23},
    {"content-type", "application/json"}]).
%% With body.
StreamRef = gun:put(Pid, "/organizations/extend", [
    {"content-length", 23},
    {"content-type", "application/json"}],
    "{\"msg\": \"Hello world!\"}").
```

To delete a resource, the `gun:delete/{2,3}` function can be
used. It works similarly to the GET and HEAD functions.

``` erlang
%% Without headers.
StreamRef = gun:delete(Pid, "/organizations/extend").
%% With headers.
StreamRef = gun:delete(Pid, "/organizations/extend", [
    {"accept", "application/json"},
    {"user-agent", "revolver/1.0"}]).
```

To obtain the functionality available for a given resource,
the `gun:options/{2,3}` can be used. It also works like the
GET and HEAD functions.

``` erlang
%% Without headers.
StreamRef = gun:options(Pid, "/organizations/extend").
%% With headers.
StreamRef = gun:options(Pid, "/organizations/extend", [
    {"accept", "application/json"},
    {"user-agent", "revolver/1.0"}]).
```

You can obtain information about the server as a whole by
using the special path `"*"`.

``` erlang
StreamRef = gun:options(Pid, "*").
```

Streaming data
--------------

When a PATCH, POST or PUT operation is performed, and a
content-type is specified but no body is given, Gun will
expect data to be streamed to the connection using the
`gun:data/4` function.

This function can be called as many times as needed until
all data is sent. The third argument needs to be `nofin`
when there is remaining data to be sent, and `fin` for the
last chunk. The last chunk may be empty if needed.

For example, with an `IoDevice` opened like follow:

``` erlang
{ok, IoDevice} = file:open(Filepath, [read, binary, raw]).
```

The following function will stream all data until the end
of the file:

``` erlang
sendfile(Pid, StreamRef, IoDevice) ->
    case file:read(IoDevice, 8000) of
        eof ->
            gun:data(Pid, StreamRef, fin, <<>>),
            file:close(IoDevice);
        {ok, Bin} ->
            gun:data(Pid, StreamRef, nofin, Bin),
            sendfile(Pid, StreamRef, IoDevice)
    end.
```

Receiving responses
-------------------

All data received from the server is sent to the controlling
process as a message. First a response message is sent, then
zero or more data messages. If something goes wrong, error
messages are sent instead.

The response message will inform you whether there will be
data messages following. If it contains `fin` then no data
will follow. If it contains `nofin` then one or more data
messages will arrive.

When using SPDY this value is sent along the frame and simply
passed on in the message. When using HTTP however Gun must
guess whether data will follow by looking at the headers
as documented in the HTTP RFC.

``` erlang
StreamRef = gun:get(Pid, "/"),
receive
    {'DOWN', Tag, _, _, Reason} ->
        error_logger:error_msg("Oops!"),
        exit(Reason);
    {gun_response, Pid, StreamRef, fin, Status, Headers} ->
        no_data;
    {gun_response, Pid, StreamRef, nofin, Status, Headers} ->
        receive_data(Pid, StreamRef)
after 1000 ->
    exit(timeout)
end.
```

The `receive_data/2` function could look like this:

``` erlang
receive_data(Pid, Tag, StreamRef) ->
    receive
        {'DOWN', Tag, _, _, Reason} ->
            {error, incomplete};
        {gun_data, Pid, StreamRef, nofin, Data} ->
            io:format("~s~n", [Data]),
            receive_data(Pid, Tag, StreamRef);
        {gun_data, Pid, StreamRef, fin, Data} ->
            io:format("~s~n", [Data])
    after 1000 ->
        {error, timeout}
    end.
```

While it may seem verbose, using messages like this has the
advantage of never locking your process, allowing you to
easily debug your code. It also allows you to start more than
one connection and concurrently perform queries on all of them
at the same time.

You may also use Gun in a synchronous manner by writing your
own functions that perform a receive like demonstrated above.

Dealing with server-pushed streams
----------------------------------

When using SPDY the server may decide to push extra resources
after a request is performed. It will send a `gun_push` message
which contains two references, one for the pushed stream, and
one for the request this stream is associated with.

Pushed streams typically feature a body. Replying to a pushed
stream is forbidden and Gun will send an error message if
attempted.

Pushed streams can be received like this:

``` erlang
receive
    {gun_push, Pid, PushedStreamRef, StreamRef,
            Method, Host, Path, Headers} ->
        %% ...
end
```

The pushed stream gets a new identifier but you still receive
the `StreamRef` this stream is associated to.
