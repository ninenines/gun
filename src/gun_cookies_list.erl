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

%% A reference cookie store implemented as a list of cookies.
%% This cookie store cannot be shared between connections.
-module(gun_cookies_list).
-behavior(gun_cookies).

-export([init/0]).
-export([init/1]).
-export([query/2]).
-export([set_cookie_secure_match/2]).
-export([set_cookie_get_exact_match/2]).
-export([store/2]).
-export([gc/1]).
-export([session_gc/1]).

-type state() :: #{
	cookies := [gun_cookies:cookie()],
	max_cookies := non_neg_integer() | infinity,
	max_cookies_per_domain := non_neg_integer() | infinity
}.

-type opts() :: #{
	max_cookies => non_neg_integer() | infinity,
	max_cookies_per_domain => non_neg_integer() | infinity
}.
-export_type([opts/0]).

-spec init() -> {?MODULE, state()}.
init() ->
	init(#{}).

-spec init(opts()) -> {?MODULE, state()}.
init(Opts) ->
	{?MODULE, #{
		cookies => [],
		max_cookies => maps:get(max_cookies, Opts, 50),
		max_cookies_per_domain => maps:get(max_cookies_per_domain, Opts, 20)
	}}.

-spec query(State, uri_string:uri_map())
	-> {ok, [gun_cookies:cookie()], State}
	when State::state().
query(State=#{cookies := Cookies}, URI) ->
	CurrentTime = erlang:universaltime(),
	query(State, URI, Cookies, CurrentTime, [], []).

query(State, _, [], _, CookieList, Cookies) ->
	{ok, CookieList, State#{cookies => Cookies}};
query(State, URI=#{scheme := Scheme, host := Host, path := Path},
		[Cookie|Tail], CurrentTime, CookieList, Acc) ->
	Match0 = case Cookie of
		#{host_only := true, domain := Host} ->
			true;
		#{host_only := false, domain := Domain} ->
			gun_cookies:domain_match(Host, Domain);
		_ ->
			false
	end,
	Match1 = Match0 andalso
		gun_cookies:path_match(Path, maps:get(path, Cookie)),
	Match = Match1 andalso
		case {Cookie, Scheme} of
			{#{secure_only := true}, <<"https">>} -> true;
			{#{secure_only := false}, _} -> true;
			_ -> false
		end,
	%% This is where we would check the http_only flag should
	%% we want to implement a non-HTTP interface.
	%% This is where we would check for same-site/cross-site.
	case Match of
		true ->
			UpdatedCookie = Cookie#{last_access_time => CurrentTime},
			query(State, URI, Tail, CurrentTime,
				[UpdatedCookie|CookieList],
				[UpdatedCookie|Acc]);
		false ->
			query(State, URI, Tail, CurrentTime, CookieList, [Cookie|Acc])
	end.

-spec set_cookie_secure_match(state(), #{
	name := binary(),
%	secure_only := true,
	domain := binary(),
	path := binary()
}) -> match | nomatch.
set_cookie_secure_match(#{cookies := Cookies},
		#{name := Name, domain := Domain, path := Path}) ->
	Result = [Cookie || Cookie=#{name := CookieName, secure_only := true} <- Cookies,
		CookieName =:= Name,
		gun_cookies:domain_match(Domain, maps:get(domain, Cookie))
			orelse gun_cookies:domain_match(maps:get(domain, Cookie), Domain),
		gun_cookies:path_match(Path, maps:get(path, Cookie))],
	case Result of
		[] -> nomatch;
		_ -> match
	end.

-spec set_cookie_get_exact_match(State, #{
	name := binary(),
	domain := binary(),
	host_only := boolean(),
	path := binary()
}) -> {ok, gun_cookies:cookie(), State} | error when State::state().
set_cookie_get_exact_match(State=#{cookies := Cookies0}, Match) ->
	Result = [Cookie || Cookie <- Cookies0,
		Match =:= maps:with([name, domain, host_only, path], Cookie)],
	Cookies = [Cookie || Cookie <- Cookies0,
		Match =/= maps:with([name, domain, host_only, path], Cookie)],
	case Result of
		[] -> error;
		[Cookie] -> {ok, Cookie, State#{cookies => Cookies}}
	end.

-spec store(State, gun_cookies:cookie())
	-> {ok, State} | {error, any()}
	when State::state().
store(State=#{cookies := Cookies0, max_cookies := MaxCookies,
		max_cookies_per_domain := MaxPerDomain},
		NewCookie=#{expiry_time := ExpiryTime, domain := Domain}) ->
	CurrentTime = erlang:universaltime(),
	if
		%% Do not store cookies with an expiry time in the past.
		ExpiryTime =/= infinity, CurrentTime >= ExpiryTime ->
			{ok, State};
		MaxCookies =:= 0; MaxPerDomain =:= 0 ->
			{ok, State};
		true ->
			Cookies1 = drop_expired(Cookies0, CurrentTime),
			{Same0, Other} = partition_quota(Cookies1, Domain),
			Same = trim(Same0, room(MaxPerDomain)),
			Cookies = make_room(Same, Other, room(MaxCookies)),
			{ok, State#{cookies => [NewCookie|Cookies]}}
	end.

-spec gc(State) -> {ok, State} when State::state().
gc(State=#{cookies := Cookies0, max_cookies := MaxCookies,
		max_cookies_per_domain := MaxPerDomain}) ->
	CurrentTime = erlang:universaltime(),
	Cookies1 = drop_expired(Cookies0, CurrentTime),
	Cookies = trim(trim_domains(Cookies1, MaxPerDomain), MaxCookies),
	{ok, State#{cookies => Cookies}}.

drop_expired(Cookies, CurrentTime) ->
	[C || C=#{expiry_time := ExpiryTime} <- Cookies,
		(ExpiryTime =:= infinity) orelse (ExpiryTime >= CurrentTime)].

room(infinity) -> infinity;
room(Max) -> Max - 1.

%% Same registrable domain first, then insecure, then earliest last-access-time.
trim_domains(Cookies, infinity) ->
	Cookies;
trim_domains(Cookies, Max) ->
	Groups = maps:groups_from_list(fun(#{domain := D}) -> quota_key(D) end, Cookies),
	lists:append([trim(Group, Max) || Group <- maps:values(Groups)]).

make_room(Same, Other, infinity) ->
	Same ++ Other;
make_room(Same, Other, Keep) when length(Same) + length(Other) =< Keep ->
	Same ++ Other;
make_room(Same, Other, Keep) ->
	Need = length(Same) + length(Other) - Keep,
	SameSorted = evict_sort(Same),
	case length(SameSorted) of
		N when N >= Need ->
			lists:nthtail(Need, SameSorted) ++ Other;
		N ->
			lists:nthtail(Need - N, evict_sort(Other))
	end.

partition_quota(Cookies, Domain) ->
	Key = quota_key(Domain),
	lists:partition(fun(#{domain := D}) -> quota_key(D) =:= Key end, Cookies).

quota_key(Domain0) ->
	Domain = trim_trailing_dots(ascii_lower(Domain0)),
	case Domain of
		<<>> ->
			<<>>;
		_ ->
			case inet:parse_strict_address(binary_to_list(Domain)) of
				{ok, _} -> Domain;
				{error, einval} -> registrable_domain(Domain)
			end
	end.

trim_trailing_dots(<<>>) ->
	<<>>;
trim_trailing_dots(Domain) ->
	case binary:last(Domain) of
		$. -> trim_trailing_dots(binary:part(Domain, 0, byte_size(Domain) - 1));
		_ -> Domain
	end.

ascii_lower(Bin) ->
	<< <<(ascii_lower_byte(C))>> || <<C>> <= Bin >>.

ascii_lower_byte(C) when C >= $A, C =< $Z -> C + 32;
ascii_lower_byte(C) -> C.

registrable_domain(Domain) ->
	Labels0 = binary:split(Domain, <<$.>>, [global]),
	Labels = case length(Labels0) of
		N when N > 16 -> lists:nthtail(N - 16, Labels0);
		_ -> Labels0
	end,
	PSLabels = public_suffix_labels(Labels),
	case length(Labels) - length(PSLabels) of
		0 ->
			join(Labels);
		Extra ->
			join(lists:nthtail(Extra - 1, Labels))
	end.

public_suffix_labels([Label]) ->
	[Label];
public_suffix_labels(Labels) ->
	try gun_public_suffix:match(join(Labels)) of
		true -> Labels;
		false -> public_suffix_labels(tl(Labels))
	catch error:badarg ->
		public_suffix_labels(tl(Labels))
	end.

join(Labels) ->
	iolist_to_binary(lists:join(<<$.>>, Labels)).

trim(Cookies, infinity) ->
	Cookies;
trim(_Cookies, 0) ->
	[];
trim(Cookies, Keep) when length(Cookies) =< Keep ->
	Cookies;
trim(Cookies, Keep) ->
	lists:nthtail(length(Cookies) - Keep, evict_sort(Cookies)).

evict_sort(Cookies) ->
	lists:sort(fun evict_le/2, lists:reverse(Cookies)).

evict_le(#{secure_only := SA, last_access_time := LA, creation_time := CA},
		#{secure_only := SB, last_access_time := LB, creation_time := CB}) ->
	{secure_rank(SA), LA, CA} =< {secure_rank(SB), LB, CB}.

secure_rank(false) -> 0;
secure_rank(true) -> 1.

-spec session_gc(State) -> {ok, State} when State::state().
session_gc(State=#{cookies := Cookies0}) ->
	Cookies = [C || C=#{persistent := true} <- Cookies0],
	{ok, State#{cookies => Cookies}}.
