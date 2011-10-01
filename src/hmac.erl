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
         hmac/2,
         hmac/4,
         hmac224/2,
         hmac256/2,
         hmac384/2,
         hmac512/2]).

-define(SHA_224_BLOCKSIZE, 64).
-define(SHA_256_BLOCKSIZE, 64).
-define(SHA_384_BLOCKSIZE, 128).
-define(SHA_512_BLOCKSIZE, 128).

%% @spec hexlify(binary()) -> list()
%% @doc Convert binary to equivalent hexadecimal string.
%%
hexlify(Binary) when is_binary(Binary) ->
    lists:flatten([io_lib:format("~2.16.0B", [B]) ||
                      B <- binary_to_list(Binary)]).

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
    crypto:sha_mac(Key, Data).

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
