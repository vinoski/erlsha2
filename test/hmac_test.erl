%% @author Jared Flatow
%% @doc tests for hmac erlsha2 wrappers
%% @reference
%%  See also
%%  <a href="http://tools.ietf.org/html/rfc4231">
%%  Identifiers and Test Vectors for HMAC-SHA*
%%  </a>.

-module(hmac_test).

-include_lib("eunit/include/eunit.hrl").

hex_int(Binary) ->
    list_to_integer(hmac:hexlify(Binary), 16).

wikipedia_test() ->
    ?assertMatch(16#fbdb1d1b18aa6c08324b7d64b71fb76370690e1d,
                 hex_int(hmac:hmac("", ""))),
    ?assertMatch(16#b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad,
                 hex_int(hmac:hmac256("", ""))),
    ?assertMatch(16#b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47,
                 hex_int(hmac:hmac512("", ""))),
    ?assertMatch(16#de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9,
                 hex_int(hmac:hmac("key", "The quick brown fox jumps over the lazy dog"))),
    ?assertMatch(16#f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8,
                 hex_int(hmac:hmac256("key", "The quick brown fox jumps over the lazy dog"))),
    ?assertMatch(16#b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a,
                 hex_int(hmac:hmac512("key", "The quick brown fox jumps over the lazy dog"))),
    ok.

rfc_4231_1_test() ->
    Key = binary:copy(<<16#0b>>, 20),
    Val = "Hi There",
    ?assertMatch(16#896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22,
                 hex_int(hmac:hmac224(Key, Val))),
    ?assertMatch(16#b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7,
                 hex_int(hmac:hmac256(Key, Val))),
    ?assertMatch(16#afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6,
                 hex_int(hmac:hmac384(Key, Val))),
    ?assertMatch(16#87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854,
                 hex_int(hmac:hmac512(Key, Val))),
    ok.

%% Test with a key shorter than the length of the HMAC output.
rfc_4231_2_test() ->
    Key = "Jefe",
    Val = "what do ya want for nothing?",
    ?assertMatch(16#a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44,
                 hex_int(hmac:hmac224(Key, Val))),
    ?assertMatch(16#5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843,
                 hex_int(hmac:hmac256(Key, Val))),
    ?assertMatch(16#af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649,
                 hex_int(hmac:hmac384(Key, Val))),
    ?assertMatch(16#164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737,
                 hex_int(hmac:hmac512(Key, Val))),
    ok.

%% Test with a combined length of key and data that is larger than 64 bytes
%%  (= block-size of SHA-224 and SHA-256).
rfc_4231_3_test() ->
    Key = binary:copy(<<16#aa>>, 20),
    Val = binary:copy(<<16#dd>>, 50),
    ?assertMatch(16#7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea,
                 hex_int(hmac:hmac224(Key, Val))),
    ?assertMatch(16#773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe,
                 hex_int(hmac:hmac256(Key, Val))),
    ?assertMatch(16#88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27,
                 hex_int(hmac:hmac384(Key, Val))),
    ?assertMatch(16#fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb,
                 hex_int(hmac:hmac512(Key, Val))),
    ok.

%% Test with a combined length of key and data that is larger than 64 bytes
%% (= block-size of SHA-224 and SHA-256).
rfc_4231_4_test() ->
    Key = list_to_binary(lists:seq(1, 16#19)),
    Val = binary:copy(<<16#cd>>, 50),
    ?assertMatch(16#6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a,
                 hex_int(hmac:hmac224(Key, Val))),
    ?assertMatch(16#82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b,
                 hex_int(hmac:hmac256(Key, Val))),
    ?assertMatch(16#3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb,
                 hex_int(hmac:hmac384(Key, Val))),
    ?assertMatch(16#b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd,
                 hex_int(hmac:hmac512(Key, Val))),
    ok.

%% Test with a truncation of output to 128 bits.
rfc_4231_5_test() ->
    Key = binary:copy(<<16#0c>>, 20),
    Val = "Test With Truncation",
    <<Left224:16/binary, _Rest224/binary>> = hmac:hmac224(Key, Val),
    <<Left256:16/binary, _Rest256/binary>> = hmac:hmac256(Key, Val),
    <<Left384:16/binary, _Rest384/binary>> = hmac:hmac384(Key, Val),
    <<Left512:16/binary, _Rest512/binary>> = hmac:hmac512(Key, Val),
    ?assertMatch(16#0e2aea68a90c8d37c988bcdb9fca6fa8, hex_int(Left224)),
    ?assertMatch(16#a3b6167473100ee06e0c796c2955552b, hex_int(Left256)),
    ?assertMatch(16#3abf34c3503b2a23a46efc619baef897, hex_int(Left384)),
    ?assertMatch(16#415fad6271580a531d4179bc891d87a6, hex_int(Left512)),
    ok.

%% Test with a key larger than 128 bytes
%% (= block-size of SHA-384 and SHA-512).
rfc_4231_6_test() ->
    Key = binary:copy(<<16#aa>>, 131),
    Val = "Test Using Larger Than Block-Size Key - Hash Key First",
    ?assertMatch(16#95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e,
                 hex_int(hmac:hmac224(Key, Val))),
    ?assertMatch(16#60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54,
                 hex_int(hmac:hmac256(Key, Val))),
    ?assertMatch(16#4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952,
                 hex_int(hmac:hmac384(Key, Val))),
    ?assertMatch(16#80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598,
                 hex_int(hmac:hmac512(Key, Val))),
    ok.

%% Test with a key and data that is larger than 128 bytes
%% (= block-size of SHA-384 and SHA-512).
rfc_4231_7_test() ->
    Key = binary:copy(<<16#aa>>, 131),
    Val =
        "This is a test using a larger than block-size key and a larger than block-size data. "
        "The key needs to be hashed before being used by the HMAC algorithm.",
    ?assertMatch(16#3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1,
                 hex_int(hmac:hmac224(Key, Val))),
    ?assertMatch(16#9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2,
                 hex_int(hmac:hmac256(Key, Val))),
    ?assertMatch(16#6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e,
                 hex_int(hmac:hmac384(Key, Val))),
    ?assertMatch(16#e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58,
                 hex_int(hmac:hmac512(Key, Val))),
    ok.
