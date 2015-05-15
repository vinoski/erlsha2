%% @author Jared Flatow, Steve Vinoski
%% @doc HMAC wrappers for erlsha2
%% @reference
%%  Based on the
%%  <a href="http://erlang.org/pipermail/erlang-questions/2011-May/058174.html">
%%  mailing list response
%%  </a>
%%  by Steve Davis.

-module(hmac).
-export([hexlify/1,
         hexlify/2,
         hmac/2,
         hmac/4,
         hmac224/2,
         hmac256/2,
         hmac384/2,
         hmac512/2]).
-on_load(init/0).
-version("2.2.1").

-ifdef(USE_CRYPTO_SHA_MAC).
-define(CRYPTO_HMAC(Key,Data), crypto:sha_mac(Key,Data)).
-else.
-define(CRYPTO_HMAC(Key,Data), crypto:hmac(sha,Key,Data)).
-endif.

-define(SHA_224_BLOCKSIZE, 64).
-define(SHA_256_BLOCKSIZE, 64).
-define(SHA_384_BLOCKSIZE, 128).
-define(SHA_512_BLOCKSIZE, 128).

-define(HMAC_STRING, 1).
-define(HMAC_UPPER, 2).
-define(DEFAULT_HMAC_FLAGS, (?HMAC_STRING bor ?HMAC_UPPER)).

%% @spec init() -> ok | {error, term()}
%% @doc Initialize hmac NIF.
%%
init() ->
    SoName = filename:join(case code:priv_dir(?MODULE) of
                               {error, bad_name} ->
                                   %% this is here for testing purposes
                                   filename:join(
                                     [filename:dirname(
                                        code:which(?MODULE)),"..","priv"]);
                               Dir ->
                                   Dir
                           end, atom_to_list(?MODULE) ++ "_nif"),
    erlang:load_nif(SoName, 0).

%% @spec hexlify(binary()) -> list()
%% @doc Convert binary to equivalent hexadecimal string.
%%
hexlify(Binary) when is_binary(Binary) ->
    hexlify_nif(Binary, ?DEFAULT_HMAC_FLAGS).

%% @spec hexlify(binary(), hmac_opts()) -> string() | binary()
%% @doc Convert binary to equivalent hexadecimal string or binary depending
%% on the options passed in the second argument. If the options list
%% contains the atom 'string' a string is returned, or if the option
%% 'binary' is passed a binary is returned. If the options list contains
%% the atom 'upper' then the alphabetic hexadecimal characters in the
%% return value are uppercase, or if the option 'lower' is passed then the
%% alphabetic hexadecimal characters in the return value are lowercase. The
%% default if no options are passed is to return an uppercase string.
%%
hexlify(Binary, []) when is_binary(Binary) ->
    hexlify_nif(Binary, ?DEFAULT_HMAC_FLAGS);
hexlify(Binary, [string,upper]) when is_binary(Binary) ->
    hexlify_nif(Binary, ?DEFAULT_HMAC_FLAGS);
hexlify(Binary, [upper,string]) when is_binary(Binary) ->
    hexlify_nif(Binary, ?DEFAULT_HMAC_FLAGS);
hexlify(Binary, [string,lower]) when is_binary(Binary) ->
    hexlify_nif(Binary, ?HMAC_STRING);
hexlify(Binary, [lower,string]) when is_binary(Binary) ->
    hexlify_nif(Binary, ?HMAC_STRING);
hexlify(Binary, [binary,upper]) when is_binary(Binary) ->
    hexlify_nif(Binary, ?HMAC_UPPER);
hexlify(Binary, [upper,binary]) when is_binary(Binary) ->
    hexlify_nif(Binary, ?HMAC_UPPER);
hexlify(Binary, [binary,lower]) when is_binary(Binary) ->
    hexlify_nif(Binary, 0);
hexlify(Binary, [lower,binary]) when is_binary(Binary) ->
    hexlify_nif(Binary, 0);
hexlify(Binary, Opts) when is_binary(Binary), is_list(Opts) ->
    Flags = lists:foldl(fun(string, Acc) ->
                                Acc bor ?HMAC_STRING;
                           (binary, Acc) ->
                                Acc band bnot ?HMAC_STRING;
                           (upper, Acc) ->
                                Acc bor ?HMAC_UPPER;
                           (lower, Acc) ->
                                Acc band bnot ?HMAC_UPPER
                        end, ?DEFAULT_HMAC_FLAGS, Opts),
    hexlify_nif(Binary, Flags).

hexlify_nif(_Bin, _Opts) ->
    erlang:nif_error(nif_not_loaded).

%% @spec hmac224(key(), data()) -> mac()
%% where
%%       key()  = iolist() | binary()
%%       data() = iolist() | binary()
%%       mac()  = binary()
%% @doc Compute a SHA-224 MAC message authentication code from key and data.
%%
hmac224(Key, Data) ->
    hmac(Key, Data, fun erlsha2:sha224/1, ?SHA_224_BLOCKSIZE).

%% @spec hmac256(key(), data()) -> mac()
%% where
%%       key()  = iolist() | binary()
%%       data() = iolist() | binary()
%%       mac()  = binary()
%% @doc Compute a SHA-256 MAC message authentication code from key and data.
%%
hmac256(Key, Data) ->
    hmac(Key, Data, fun erlsha2:sha256/1, ?SHA_256_BLOCKSIZE).

%% @spec hmac384(key(), data()) -> mac()
%% where
%%       key()  = iolist() | binary()
%%       data() = iolist() | binary()
%%       mac()  = binary()
%% @doc Compute a SHA-384 MAC message authentication code from key and data.
%%
hmac384(Key, Data) ->
    hmac(Key, Data, fun erlsha2:sha384/1, ?SHA_384_BLOCKSIZE).

%% @spec hmac512(key(), data()) -> mac()
%% where
%%       key()  = iolist() | binary()
%%       data() = iolist() | binary()
%%       mac()  = binary()
%% @doc Compute a SHA-512 MAC message authentication code from key and data.
%%
hmac512(Key, Data) ->
    hmac(Key, Data, fun erlsha2:sha512/1, ?SHA_512_BLOCKSIZE).

%% @spec hmac(key(), data()) -> mac()
%% where
%%       key()  = iolist() | binary()
%%       data() = iolist() | binary()
%%       mac()  = binary()
%% @doc Compute a SHA MAC message authentication code from key and data.
%%
hmac(Key, Data) ->
    ?CRYPTO_HMAC(Key, Data).

%% @spec hmac(key(), data(), hash(), blocksize()) -> mac()
%% where
%%       key()  = iolist() | binary()
%%       data() = iolist() | binary()
%%       hash() = fun((binary()) -> binary())
%%       blocksize() = non_neg_integer()
%%       mac()  = binary()
%% @doc Compute a SHA MAC message authentication code from key and data using
%%      the specified hash function and blocksize.
%%
hmac(Key, Data, Hash, Blocksize) when is_list(Key) ->
    hmac(iolist_to_binary(Key), Data, Hash, Blocksize);
hmac(Key, Data, Hash, Blocksize) when is_list(Data) ->
    hmac(Key, iolist_to_binary(Data), Hash, Blocksize);
hmac(Key, Data, Hash, Blocksize) when is_binary(Key), is_binary(Data) ->
    HashKey =
        case Blocksize - byte_size(Key) of
            X when X < 0 ->
                KeyDigest = Hash(Key),
                Pad = Blocksize - byte_size(KeyDigest),
                <<KeyDigest/binary, 0:(Pad * 8)>>;
            X when X > 0 ->
                <<Key/binary, 0:(X * 8)>>;
            X when X =:= 0 ->
                Key
        end,
    IPad = binary:copy(<<16#36>>, Blocksize),
    OPad = binary:copy(<<16#5c>>, Blocksize),
    HVal = Hash(<<(crypto:exor(HashKey, IPad))/binary, Data/binary>>),
    Hash(<<(crypto:exor(HashKey, OPad))/binary, HVal/binary>>).
