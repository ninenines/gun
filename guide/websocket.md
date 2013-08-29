Using Websocket
===============

This chapter describes how to use the Gun client for
communicating with a Websocket server.

HTTP upgrade
------------

Websocket is a protocol built on top of HTTP. To use Websocket,
you must first request for the connection to be upgraded.

Gun allows you to perform Websocket upgrade requests by using
the `gun:ws_upgrade/{2,3}` function. Gun will fill out all
necessary headers for performing the Websocket upgrade, but
you can optionally specify additional headers, for example if
you would like to setup a custom sub-protocol.

``` erlang
%% Without headers.
gun:ws_upgrade(Pid, "/websocket").
%% With headers.
gun:ws_upgrade(Pid, "/websocket", [
    {"sec-websocket-protocol", "mychat"}
]).
```

The success or failure of this operation will be sent as a
message.

``` erlang
receive
    {gun_ws_upgrade, Pid, ok} ->
        upgrade_success(Pid);
    {gun_ws_upgrade, Pid, error, IsFin, Status, Headers} ->
        exit({ws_upgrade_failed, Status, Headers});
    %% More clauses here as needed.
after 1000 ->
    exit(timeout);
end.
```

Sending data
------------

You can then use the `gun:ws_send/2` function to send one or
more frames to the server.

``` erlang
%% Send one text frame.
gun:ws_send(Pid, {text, "Hello!"}).
%% Send one text frame, one binary frame and close the connection.
gun:ws_send(Pid, [
    {text, "Hello!"},
    {binary, SomeBin},
    close
]).
```

Note that if you send a close frame, Gun will close the connection
cleanly and will not attempt to reconnect afterwards, similar to
calling `gun:shutdown/1`.

Receiving data
--------------

Every time Gun receives a frame from the server a message will be
sent to the controlling process. This message will always contain
a single frame.

``` erlang
receive
    {gun_ws, Pid, Frame} ->
        handle_frame(Pid, Frame);
    {gun_error, Pid, Reason} ->
        error_logger:error_msg("Oops! ~p~n", [Reason]),
        upgrade_again(Pid)
end.
```

Gun will automatically send ping messages to the server to keep
the connection alive, however if the connection dies and Gun has
to reconnect it will not upgrade to Websocket automatically, you
need to perform the operation when you receive the `gun_error`
message.
