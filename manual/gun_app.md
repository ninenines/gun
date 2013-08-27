The Gun Application
===================

Asynchronous SPDY, HTTP and Websocket client.

Dependencies
------------

The `gun` application uses the Erlang applications `ranch`
for abstracting TCP and SSL over a common interface, and
the applications `asn1`, `public_key` and `ssl` for using
the SSL transport. These dependencies must be loaded for
the `gun` application to work. In an embedded environment
this means that they need to be started with the
`application:start/{1,2}` function before the `gun`
application is started.

Environment
-----------

The `gun` application does not define any application
environment configuration parameters.
