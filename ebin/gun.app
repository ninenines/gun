{application, gun, [
	{description, "HTTP/1.1, HTTP/2 and Websocket client for Erlang/OTP."},
	{vsn, "1.0.0-pre.2"},
	{modules, ['gun','gun_app','gun_content_handler','gun_data','gun_http','gun_http2','gun_sse','gun_sup','gun_ws','gun_ws_handler']},
	{registered, [gun_sup]},
	{applications, [kernel,stdlib,ssl,cowlib,ranch]},
	{mod, {gun_app, []}},
	{env, []}
]}.