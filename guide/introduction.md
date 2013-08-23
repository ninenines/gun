Introduction
============

Purpose
-------

Gun is an asynchronous SPDY, HTTP and Websocket client.

Prerequisites
-------------

Knowledge of Erlang, but also of the HTTP, SPDY and Websocket
protocols is required in order to read this guide.

Supported platforms
-------------------

Gun is tested and supported on Linux.

Gun is developed for Erlang R16B+.

Gun may be compiled on earlier Erlang versions with small source code
modifications but there is no guarantee that it will work as expected.

Conventions
-----------

In the HTTP protocol, the method name is case sensitive. All standard
method names are uppercase.

Header names are case insensitive. Gun converts all the header names
to lowercase, and expects your application to provide lowercase header
names also.

The same applies to any other case insensitive value.
