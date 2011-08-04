%% @author Jared Flatow
%% @doc hmac wrappers for erlsha2
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

hexlify(Binary) when is_binary(Binary) ->
    lists:flatten([io_lib:format("~2.16.0B", [B]) || B <- binary_to_list(Binary)]).

hmac224(Key, Data) ->
    hmac(Key, Data, fun erlsha2:sha224/1, ?SHA_224_BLOCKSIZE).

hmac256(Key, Data) ->
    hmac(Key, Data, fun erlsha2:sha256/1, ?SHA_256_BLOCKSIZE).

hmac384(Key, Data) ->
    hmac(Key, Data, fun erlsha2:sha384/1, ?SHA_384_BLOCKSIZE).

hmac512(Key, Data) ->
    hmac(Key, Data, fun erlsha2:sha512/1, ?SHA_512_BLOCKSIZE).

hmac(Key, Data) ->
    crypto:sha_mac(Key, Data).

hmac(Key, Data, Hash, Blocksize) when is_list(Key) ->
    hmac(list_to_binary(Key), Data, Hash, Blocksize);
hmac(Key, Data, Hash, Blocksize) when is_list(Data) ->
    hmac(Key, list_to_binary(Data), Hash, Blocksize);
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
