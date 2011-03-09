%%% @author  Steve Vinoski <vinoski@ieee.org> [http://steve.vinoski.net/]
%%% @doc Implementations of SHA-224, SHA-256, SHA-384, SHA-512 in Erlang NIFs.
%%% @reference See <a
%%%  href="http://csrc.nist.gov/publications/fips/fips180-3/fips180-3_final.pdf">
%%%  the Secure Hash Standard</a> and the <a
%%%  href="http://en.wikipedia.org/wiki/SHA1">Wikipedia SHA1
%%%  article</a>. Find the code <a
%%%  href="http://github.com/vinoski/erlsha2">here</a>.
%%% @since 03 Jan 2009
%%%
%%% @copyright 2009-2011 Stephen B. Vinoski, All rights reserved. Open source, BSD License
%%% @version 2.0
%%%

%%%
%%% Copyright (c) 2009-2011 Stephen B. Vinoski
%%% All rights reserved.
%%%
%%% Redistribution and use in source and binary forms, with or without
%%% modification, are permitted provided that the following conditions
%%% are met:
%%%
%%% 1. Redistributions of source code must retain the above copyright
%%%    notice, this list of conditions and the following disclaimer.
%%% 2. Redistributions in binary form must reproduce the above copyright
%%%    notice, this list of conditions and the following disclaimer in the
%%%    documentation and/or other materials provided with the distribution.
%%% 3. Neither the name of the copyright holder nor the names of contributors
%%%    may be used to endorse or promote products derived from this software
%%%    without specific prior written permission.
%%%
%%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTOR(S) ``AS IS'' AND
%%% ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
%%% IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
%%% ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTOR(S) BE LIABLE
%%% FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
%%% DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
%%% OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
%%% HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
%%% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
%%% OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
%%% SUCH DAMAGE.
%%%

-module(erlsha2).
-export([sha224/1, sha256/1, sha384/1, sha512/1]).
-export([sha224_init/0, sha224_update/2, sha224_final/1]).
-export([sha256_init/0, sha256_update/2, sha256_final/1]).
-export([sha384_init/0, sha384_update/2, sha384_final/1]).
-export([sha512_init/0, sha512_update/2, sha512_final/1]).
-version(2.0).
-on_load(init/0).

-define(H224, [16#C1059ED8, 16#367CD507, 16#3070DD17, 16#F70E5939,
               16#FFC00B31, 16#68581511, 16#64F98FA7, 16#BEFA4FA4]).

-define(H256, [16#6A09E667, 16#BB67AE85, 16#3C6EF372, 16#A54FF53A,
               16#510E527F, 16#9B05688C, 16#1F83D9AB, 16#5BE0CD19]).

-define(H384, [16#CBBB9D5DC1059ED8, 16#629A292A367CD507, 16#9159015A3070DD17,
               16#152FECD8F70E5939, 16#67332667FFC00B31, 16#8EB44A8768581511,
               16#DB0C2E0D64F98FA7, 16#47B5481DBEFA4FA4]).

-define(H512, [16#6A09E667F3BCC908, 16#BB67AE8584CAA73B, 16#3C6EF372FE94F82B,
               16#A54FF53A5F1D36F1, 16#510E527FADE682D1, 16#9B05688C2B3E6C1F,
               16#1F83D9ABFB41BD6B, 16#5BE0CD19137E2179]).

-define(K256, <<16#428A2F98:32/big-unsigned, 16#71374491:32/big-unsigned,
                16#B5C0FBCF:32/big-unsigned, 16#E9B5DBA5:32/big-unsigned,
                16#3956C25B:32/big-unsigned, 16#59F111F1:32/big-unsigned,
                16#923F82A4:32/big-unsigned, 16#AB1C5ED5:32/big-unsigned,
                16#D807AA98:32/big-unsigned, 16#12835B01:32/big-unsigned,
                16#243185BE:32/big-unsigned, 16#550C7DC3:32/big-unsigned,
                16#72BE5D74:32/big-unsigned, 16#80DEB1FE:32/big-unsigned,
                16#9BDC06A7:32/big-unsigned, 16#C19BF174:32/big-unsigned,
                16#E49B69C1:32/big-unsigned, 16#EFBE4786:32/big-unsigned,
                16#0FC19DC6:32/big-unsigned, 16#240CA1CC:32/big-unsigned,
                16#2DE92C6F:32/big-unsigned, 16#4A7484AA:32/big-unsigned,
                16#5CB0A9DC:32/big-unsigned, 16#76F988DA:32/big-unsigned,
                16#983E5152:32/big-unsigned, 16#A831C66D:32/big-unsigned,
                16#B00327C8:32/big-unsigned, 16#BF597FC7:32/big-unsigned,
                16#C6E00BF3:32/big-unsigned, 16#D5A79147:32/big-unsigned,
                16#06CA6351:32/big-unsigned, 16#14292967:32/big-unsigned,
                16#27B70A85:32/big-unsigned, 16#2E1B2138:32/big-unsigned,
                16#4D2C6DFC:32/big-unsigned, 16#53380D13:32/big-unsigned,
                16#650A7354:32/big-unsigned, 16#766A0ABB:32/big-unsigned,
                16#81C2C92E:32/big-unsigned, 16#92722C85:32/big-unsigned,
                16#A2BFE8A1:32/big-unsigned, 16#A81A664B:32/big-unsigned,
                16#C24B8B70:32/big-unsigned, 16#C76C51A3:32/big-unsigned,
                16#D192E819:32/big-unsigned, 16#D6990624:32/big-unsigned,
                16#F40E3585:32/big-unsigned, 16#106AA070:32/big-unsigned,
                16#19A4C116:32/big-unsigned, 16#1E376C08:32/big-unsigned,
                16#2748774C:32/big-unsigned, 16#34B0BCB5:32/big-unsigned,
                16#391C0CB3:32/big-unsigned, 16#4ED8AA4A:32/big-unsigned,
                16#5B9CCA4F:32/big-unsigned, 16#682E6FF3:32/big-unsigned,
                16#748F82EE:32/big-unsigned, 16#78A5636F:32/big-unsigned,
                16#84C87814:32/big-unsigned, 16#8CC70208:32/big-unsigned,
                16#90BEFFFA:32/big-unsigned, 16#A4506CEB:32/big-unsigned,
                16#BEF9A3F7:32/big-unsigned, 16#C67178F2:32/big-unsigned>>).

-define(K512, <<16#428A2F98D728AE22:64/big-unsigned,
                16#7137449123EF65CD:64/big-unsigned,
                16#B5C0FBCFEC4D3B2F:64/big-unsigned,
                16#E9B5DBA58189DBBC:64/big-unsigned,
                16#3956C25BF348B538:64/big-unsigned,
                16#59F111F1B605D019:64/big-unsigned,
                16#923F82A4AF194F9B:64/big-unsigned,
                16#AB1C5ED5DA6D8118:64/big-unsigned,
                16#D807AA98A3030242:64/big-unsigned,
                16#12835B0145706FBE:64/big-unsigned,
                16#243185BE4EE4B28C:64/big-unsigned,
                16#550C7DC3D5FFB4E2:64/big-unsigned,
                16#72BE5D74F27B896F:64/big-unsigned,
                16#80DEB1FE3B1696B1:64/big-unsigned,
                16#9BDC06A725C71235:64/big-unsigned,
                16#C19BF174CF692694:64/big-unsigned,
                16#E49B69C19EF14AD2:64/big-unsigned,
                16#EFBE4786384F25E3:64/big-unsigned,
                16#0FC19DC68B8CD5B5:64/big-unsigned,
                16#240CA1CC77AC9C65:64/big-unsigned,
                16#2DE92C6F592B0275:64/big-unsigned,
                16#4A7484AA6EA6E483:64/big-unsigned,
                16#5CB0A9DCBD41FBD4:64/big-unsigned,
                16#76F988DA831153B5:64/big-unsigned,
                16#983E5152EE66DFAB:64/big-unsigned,
                16#A831C66D2DB43210:64/big-unsigned,
                16#B00327C898FB213F:64/big-unsigned,
                16#BF597FC7BEEF0EE4:64/big-unsigned,
                16#C6E00BF33DA88FC2:64/big-unsigned,
                16#D5A79147930AA725:64/big-unsigned,
                16#06CA6351E003826F:64/big-unsigned,
                16#142929670A0E6E70:64/big-unsigned,
                16#27B70A8546D22FFC:64/big-unsigned,
                16#2E1B21385C26C926:64/big-unsigned,
                16#4D2C6DFC5AC42AED:64/big-unsigned,
                16#53380D139D95B3DF:64/big-unsigned,
                16#650A73548BAF63DE:64/big-unsigned,
                16#766A0ABB3C77B2A8:64/big-unsigned,
                16#81C2C92E47EDAEE6:64/big-unsigned,
                16#92722C851482353B:64/big-unsigned,
                16#A2BFE8A14CF10364:64/big-unsigned,
                16#A81A664BBC423001:64/big-unsigned,
                16#C24B8B70D0F89791:64/big-unsigned,
                16#C76C51A30654BE30:64/big-unsigned,
                16#D192E819D6EF5218:64/big-unsigned,
                16#D69906245565A910:64/big-unsigned,
                16#F40E35855771202A:64/big-unsigned,
                16#106AA07032BBD1B8:64/big-unsigned,
                16#19A4C116B8D2D0C8:64/big-unsigned,
                16#1E376C085141AB53:64/big-unsigned,
                16#2748774CDF8EEB99:64/big-unsigned,
                16#34B0BCB5E19B48A8:64/big-unsigned,
                16#391C0CB3C5C95A63:64/big-unsigned,
                16#4ED8AA4AE3418ACB:64/big-unsigned,
                16#5B9CCA4F7763E373:64/big-unsigned,
                16#682E6FF3D6B2B8A3:64/big-unsigned,
                16#748F82EE5DEFB2FC:64/big-unsigned,
                16#78A5636F43172F60:64/big-unsigned,
                16#84C87814A1F0AB72:64/big-unsigned,
                16#8CC702081A6439EC:64/big-unsigned,
                16#90BEFFFA23631E28:64/big-unsigned,
                16#A4506CEBDE82BDE9:64/big-unsigned,
                16#BEF9A3F7B2C67915:64/big-unsigned,
                16#C67178F2E372532B:64/big-unsigned,
                16#CA273ECEEA26619C:64/big-unsigned,
                16#D186B8C721C0C207:64/big-unsigned,
                16#EADA7DD6CDE0EB1E:64/big-unsigned,
                16#F57D4F7FEE6ED178:64/big-unsigned,
                16#06F067AA72176FBA:64/big-unsigned,
                16#0A637DC5A2C898A6:64/big-unsigned,
                16#113F9804BEF90DAE:64/big-unsigned,
                16#1B710B35131C471B:64/big-unsigned,
                16#28DB77F523047D84:64/big-unsigned,
                16#32CAAB7B40C72493:64/big-unsigned,
                16#3C9EBE0A15C9BEBC:64/big-unsigned,
                16#431D67C49C100D4C:64/big-unsigned,
                16#4CC5D4BECB3E42B6:64/big-unsigned,
                16#597F299CFC657E2A:64/big-unsigned,
                16#5FCB6FAB3AD6FAEC:64/big-unsigned,
                16#6C44198C4A475817:64/big-unsigned>>).

-define(ADD32(X, Y), (X + Y) band 16#FFFFFFFF).
-define(ADD64(X, Y), (X + Y) band 16#FFFFFFFFFFFFFFFF).

%% @spec init() -> ok
%% @doc Initialize sha2 NIF.
%%      If the platform supports NIFs, load the NIF library. If the library
%%      isn't available, still return ok so we fall back to the Erlang
%%      implementations below.
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
    erlang:load_nif(SoName, 0),
    ok.

%% @spec sha224(message()) -> digest()
%% where
%%       message() = binary() | iolist()
%%       digest()  = binary()
%% @doc Returns a SHA-224 hexadecimal digest.
%%
sha224(M) when is_binary(M) ->
    digest_bin(M, ?H224, 64, fun sha256_pad/1, fun sha224/2, 32);
sha224(Iolist) ->
    Bin = list_to_binary(Iolist),
    digest_bin(Bin, ?H224, 64, fun sha256_pad/1, fun sha224/2, 32).

%% @spec sha224_init() -> context()
%% where
%%       context() = binary()
%% @doc Creates a SHA-224 context to be in subsequent calls to
%%      sha224_update/2.
%%
sha224_init() ->
    <<>>.

%% @spec sha224_update(context(), message()) -> newcontext()
%% where
%%       message()    = binary() | iolist()
%%       context()    = binary()
%%       newcontext() = binary()
%% @doc Updates a SHA-224 context with message data and returns a new
%%      context.
%%
sha224_update(Context, M) ->
    list_to_binary([Context, M]).

%% @spec sha224_final(context()) -> digest()
%% where
%%       context() = binary()
%%       digest()  = binary()
%% @doc Finishes the update of a SHA-224 Context and returns the computed
%%      message digest.
%%
sha224_final(Context) ->
    sha224(Context).

%% @spec sha256(message()) -> digest()
%% where
%%       message() = binary() | iolist()
%%       digest()  = binary()
%% @doc Returns a SHA-256 hexadecimal digest.
%%
sha256(M) when is_binary(M) ->
    digest_bin(M, ?H256, 64, fun sha256_pad/1, fun sha256/2, 32);
sha256(Iolist) ->
    Bin = list_to_binary(Iolist),
    digest_bin(Bin, ?H256, 64, fun sha256_pad/1, fun sha256/2, 32).

%% @spec sha256_init() -> context()
%% where
%%       context() = binary()
%% @doc Creates a SHA-256 context to be in subsequent calls to
%%      sha256_update/2.
%%
sha256_init() ->
    <<>>.

%% @spec sha256_update(context(), message()) -> newcontext()
%% where
%%       message()     = binary() | iolist()
%%       context()     = binary()
%%%      newcontext()  = binary()
%% @doc Updates a SHA-256 context with message data and returns a new
%%      context.
%%
sha256_update(Context, M) ->
    list_to_binary([Context, M]).

%% @spec sha256_final(context()) -> digest()
%% where
%%       context() = binary()
%%       digest()  = binary()
%% @doc Finishes the update of a SHA-256 Context and returns the computed
%%      message digest.
%%
sha256_final(Context) ->
    sha256(Context).

%% @spec sha384(message()) -> digest()
%% where
%%       message() = binary() | iolist()
%%       digest()  = binary()
%% @doc Returns a SHA-384 hexadecimal digest.
%%      If the argument is a binary, the result is a binary, otherwise the
%%
sha384(M) when is_binary(M) ->
    digest_bin(M, ?H384, 128, fun sha512_pad/1, fun sha384/2, 64);
sha384(Iolist) ->
    Bin = list_to_binary(Iolist),
    digest_bin(Bin, ?H384, 128, fun sha512_pad/1, fun sha384/2, 64).

%% @spec sha384_init() -> context()
%% where
%%       context()  = binary()
%% @doc Creates a SHA-384 context to be in subsequent calls to
%%      sha384_update/2.
%%
sha384_init() ->
    <<>>.

%% @spec sha384_update(context(), message()) -> newcontext()
%% where
%%       message()     = binary() | iolist()
%%       context()     = binary()
%%       newcontext()  = binary()
%% @doc Updates a SHA-384 context with message data and returns a new
%%      context.
%%
sha384_update(Context, M) ->
    list_to_binary([Context, M]).

%% @spec sha384_final(context()) -> digest()
%% where
%%       context() = binary()
%%       digest()  = binary()
%% @doc Finishes the update of a SHA-384 Context and returns the computed
%%      message digest.
%%
sha384_final(Context) ->
    sha384(Context).

%% @spec sha512(message()) -> digest()
%% where
%%       message() = binary() | iolist()
%%       digest()  = binary()
%% @doc Returns a SHA-512 hexadecimal digest.
%%
sha512(M) when is_binary(M) ->
    digest_bin(M, ?H512, 128, fun sha512_pad/1, fun sha512/2, 64);
sha512(Iolist) ->
    Bin = list_to_binary(Iolist),
    digest_bin(Bin, ?H512, 128, fun sha512_pad/1, fun sha512/2, 64).

%% @spec sha512_init() -> context()
%% where
%%       context()  = binary()
%% @doc Creates a SHA-512 context to be in subsequent calls to
%%      sha512_update/2.
%%
sha512_init() ->
    <<>>.

%% @spec sha512_update(context(), message()) -> newcontext()
%% where
%%       message()     = binary() | iolist()
%%       context()     = binary()
%%       newcontext()  = binary()
%% @doc Updates a SHA-512 context with message data and returns a new
%%      context.
%%
sha512_update(Context, M) ->
    list_to_binary([Context, M]).

%% @spec sha512_final(context()) -> digest()
%% where
%%       context() = binary()
%%       digest()  = binary()
%% @doc Finishes the update of a SHA-512 Context and returns the computed
%%      message digest.
%%
sha512_final(Context) ->
    sha512(Context).


digest_bin(M, Hashes, BitLen, Pad, Sha, WordSize) ->
    list_to_binary([<<V:WordSize/big-unsigned>> ||
                       V <- Sha(split_binary(Pad(M), BitLen), Hashes)]).

rotate32(V, Count) ->
    Rest = 32 - Count,
    <<Top:Rest/unsigned, Bottom:Count/unsigned>> = <<V:32/big-unsigned>>,
    <<New:32/big-unsigned>> = <<Bottom:Count/unsigned, Top:Rest/unsigned>>,
    New.

rotate64(V, Count) ->
    Rest = 64 - Count,
    <<Top:Rest/unsigned, Bottom:Count/unsigned>> = <<V:64/big-unsigned>>,
    <<New:64/big-unsigned>> = <<Bottom:Count/unsigned, Top:Rest/unsigned>>,
    New.

sha_pad(M, Base) ->
    Len = size(M),
    LenBits = Len*8,
    PadBits = (Len + 1 + Base div 8) rem Base,
    Pad = case PadBits of
              0 -> 0;
              _ -> (Base - PadBits) * 8
          end,
    list_to_binary([M, <<16#80:8, 0:Pad, LenBits:Base/big-unsigned>>]).

sha256_pad(M) ->
    sha_pad(M, 64).

sha512_pad(M) ->
    sha_pad(M, 128).

sha256_extend(W, 64) ->
    W;
sha256_extend(W, Count) ->
    Off1 = (Count - 15) * 4,
    Off2 = (Count - 2) * 4 - Off1 - 4,
    <<_:Off1/binary, Word1:32/big-unsigned,
      _:Off2/binary, Word2:32/big-unsigned, _/binary>> = <<W/binary>>,
    S0 = rotate32(Word1, 7) bxor rotate32(Word1, 18) bxor (Word1 bsr 3),
    S1 = rotate32(Word2, 17) bxor rotate32(Word2, 19) bxor (Word2 bsr 10),
    Off3 = (Count - 16) * 4,
    Off4 = (Count - 7) * 4 - Off3 - 4,
    <<_:Off3/binary, W16:32/big-unsigned,
      _:Off4/binary, W7:32/big-unsigned, _/binary>> = <<W/binary>>,
    Next = (W16 + S0 + W7 + S1) band 16#FFFFFFFF,
    sha256_extend(<<W/binary, Next:32/big-unsigned>>, Count+1).

sha512_extend(W, 80) ->
    W;
sha512_extend(W, Count) ->
    Off1 = (Count - 15) * 8,
    Off2 = (Count - 2) * 8 - Off1 - 8,
    <<_:Off1/binary, Word1:64/big-unsigned,
      _:Off2/binary, Word2:64/big-unsigned, _/binary>> = <<W/binary>>,
    S0 = rotate64(Word1, 1) bxor rotate64(Word1, 8) bxor (Word1 bsr 7),
    S1 = rotate64(Word2, 19) bxor rotate64(Word2, 61) bxor (Word2 bsr 6),
    Off3 = (Count - 16) * 8,
    Off4 = (Count - 7) * 8 - Off3 - 8,
    <<_:Off3/binary, W16:64/big-unsigned,
      _:Off4/binary, W7:64/big-unsigned, _/binary>> = <<W/binary>>,
    Next = (W16 + S0 + W7 + S1) band 16#FFFFFFFFFFFFFFFF,
    sha512_extend(<<W/binary, Next:64/big-unsigned>>, Count+1).

sha256_loop(_W, Hashes, Next, 64) ->
    lists:map(fun({X, Y}) -> ?ADD32(X, Y) end, lists:zip(Hashes, Next));
sha256_loop(W, Hashes, [A, B, C, D, E, F, G, H], Count) ->
    S0 = rotate32(A, 2) bxor rotate32(A, 13) bxor rotate32(A, 22),
    Maj = (A band B) bxor (A band C) bxor (B band C),
    T2 = ?ADD32(S0, Maj),
    S1 = rotate32(E, 6) bxor rotate32(E, 11) bxor rotate32(E, 25),
    Ch = (E band F) bxor (((bnot E) + 1 + 16#FFFFFFFF) band G),
    Offset = Count * 4,
    <<_:Offset/binary, K:32/big-unsigned, _/binary>> = ?K256,
    <<_:Offset/binary, Wval:32/big-unsigned, _/binary>> = <<W/binary>>,
    T1 = (H + S1 + Ch + K + Wval) band 16#FFFFFFFF,
    sha256_loop(W, Hashes, [?ADD32(T1, T2), A, B, C, ?ADD32(D, T1), E, F, G],
                Count+1).

sha512_loop(_W, Hashes, Next, 80) ->
    lists:map(fun({X, Y}) -> ?ADD64(X, Y) end, lists:zip(Hashes, Next));
sha512_loop(W, Hashes, [A, B, C, D, E, F, G, H], Count) ->
    S0 = rotate64(A, 28) bxor rotate64(A, 34) bxor rotate64(A, 39),
    Maj = (A band B) bxor (A band C) bxor (B band C),
    T2 = ?ADD64(S0, Maj),
    S1 = rotate64(E, 14) bxor rotate64(E, 18) bxor rotate64(E, 41),
    Ch = (E band F) bxor (((bnot E) + 1 + 16#FFFFFFFFFFFFFFFF) band G),
    Offset = Count * 8,
    <<_:Offset/binary, K:64/big-unsigned, _/binary>> = ?K512,
    <<_:Offset/binary, Wval:64/big-unsigned, _/binary>> = <<W/binary>>,
    T1 = (H + S1 + Ch + K + Wval) band 16#FFFFFFFFFFFFFFFF,
    sha512_loop(W, Hashes, [?ADD64(T1, T2), A, B, C, ?ADD64(D, T1), E, F, G],
                Count+1).

sha256(M, Hashes) when is_binary(M) ->
    Words64 = sha256_extend(M, 16),
    sha256_loop(Words64, Hashes, Hashes, 0);
sha256({M, <<>>}, Hashes) ->
    sha256(M, Hashes);
sha256({M, T}, Hashes) ->
    sha256(split_binary(T, 64), sha256(M, Hashes)).

sha224({M, <<>>}, Hashes) ->
    [H0, H1, H2, H3, H4, H5, H6, _H7] = sha256(M, Hashes),
    [H0, H1, H2, H3, H4, H5, H6];
sha224({M, T}, Hashes) ->
    sha224(split_binary(T, 64), sha256(M, Hashes)).

sha512(M, Hashes) when is_binary(M) ->
    Words128 = sha512_extend(M, 16),
    sha512_loop(Words128, Hashes, Hashes, 0);
sha512({M, <<>>}, Hashes) ->
    sha512(M, Hashes);
sha512({M, T}, Hashes) ->
    sha512(split_binary(T, 128), sha512(M, Hashes)).

sha384({M, <<>>}, Hashes) ->
    [H0, H1, H2, H3, H4, H5 | _] = sha512(M, Hashes),
    [H0, H1, H2, H3, H4, H5];
sha384({M, T}, Hashes) ->
    sha384(split_binary(T, 128), sha512(M, Hashes)).
