Connection
==========

This chapter describes how to open, monitor and close
a connection using the Gun client.

Opening a new connection
------------------------

Gun is designed with the SPDY and Websocket protocols in mind,
and as such establishes a permanent connection to the remote
server. Because of this, the connection must be initiated
before being able to send any request.

The process that creates the connection is also known as the
owner of the connection, or the controlling process.. Only
this process can perform operations on the connection, and
only this process will receive messages from the connection.

To open a new connection, the `gun:open/{2,3}` function can be used.

``` erlang
{ok, Pid} = gun:open("twitter.com", 443).
```

Gun will by default assume that SSL should be used.

The connection is managed by a separate process and is supervised
by the Gun supervisor directly.

The connection can later be stopped either gracefully or abruptly
by the client. If an unexpected disconnection occurs, the client
will retry connecting every few seconds until it succeeds and
can resume normal operations.

Monitoring the connection process
---------------------------------

The connection is managed by a separate process. Because
software errors are a reality, it is important to monitor
this process for failure. Thankfully, due to the asynchronous
nature of Gun, we only need to create a monitor once when
the connection is established.

``` erlang
{ok, Pid} = gun:open("twitter.com", 443).
MRef = monitor(process, Pid).
```

There is no need to monitor again after that regardless of
the number of requests sent or messages received.

You can detect the process failure when receiving messages.

``` erlang
receive
    {'DOWN', Tag, _, _, Reason} ->
        error_logger:error_msg("Oops!"),
        exit(Reason);
    %% Receive Gun messages here...
end.
```

You will probably want to reopen the connection when that
happens.

Closing the connection abruptly
-------------------------------

The connection can be stopped abruptly at any time by calling
the `gun:close/1` function.

``` erlang
gun:close(Pid).
```

The process is stopped immediately.

Closing the connection gracefully
---------------------------------

The connection can also be stopped gracefully by calling the
`gun:shutdown/1` function.

``` erlang
gun:shutdown(Pid).
```

Gun will refuse any new requests from both the Erlang side and
the server and will attempt to finish the currently opened
streams. For example if you performed a GET request just before
calling `gun:shutdown/1`, you will still receive the response
before Gun closes the connection.

If you set a monitor beforehand, it will inform you when the
connection has finally been shutdown.
