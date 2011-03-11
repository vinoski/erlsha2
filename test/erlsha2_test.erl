%%%
%%% These tests come from
%%% <http://www.aarongifford.com/computers/sha.html>. These tests read the
%%% test data from files in the testvector directory and compare against
%%% the expected results. The test vectors and expected results are subject
%%% to the license in testvectors/LICENSE.
%%%
-module(erlsha2_test).
-compile([export_all]).

-include_lib("eunit/include/eunit.hrl").

all_test_() ->
    {setup, fun read_test_vectors/0,
     {with, [fun sha224_test/1,
             fun sha224_update_test/1,
             fun sha256_test/1,
             fun sha256_update_test/1,
             fun sha384_test/1,
             fun sha384_update_test/1,
             fun sha512_test/1,
             fun sha512_update_test/1]}}.

badarg_224_test() ->
    try
        erlsha2:sha224(1234)
    catch
        error:badarg ->
            ok;
        Type:Error ->
            ?assertMatch(error, Type),
            ?assertMatch(badarg, Error)
    end.

badarg_224_update_test() ->
    Ctx1 = erlsha2:sha224_init(),
    try
        NCtx1 = erlsha2:sha224_update(Ctx1, not_an_iolist),
        erlsha2:sha224_final(NCtx1)
    catch
        error:badarg ->
            ok;
        Type1:Error1 ->
            ?assertMatch(error, Type1),
            ?assertMatch(badarg, Error1)
    end,
    _Ctx2 = erlsha2:sha224_init(),
    try
        NCtx2 = erlsha2:sha224_update(not_a_context, <<"a">>),
        erlsha2:sha224_final(NCtx2)
    catch
        error:badarg ->
            ok;
        Type2:Error2 ->
            ?assertMatch(error, Type2),
            ?assertMatch(badarg, Error2)
    end.

badarg_256_test() ->
    try
        erlsha2:sha256(1234)
    catch
        error:badarg ->
            ok;
        Type:Error ->
            ?assertMatch(error, Type),
            ?assertMatch(badarg, Error)
    end.

badarg_256_update_test() ->
    Ctx1 = erlsha2:sha256_init(),
    try
        NCtx1 = erlsha2:sha256_update(Ctx1, not_an_iolist),
        erlsha2:sha256_final(NCtx1)
    catch
        error:badarg ->
            ok;
        Type1:Error1 ->
            ?assertMatch(error, Type1),
            ?assertMatch(badarg, Error1)
    end,
    _Ctx2 = erlsha2:sha256_init(),
    try
        NCtx2 = erlsha2:sha256_update(not_a_context, <<"a">>),
        erlsha2:sha256_final(NCtx2)
    catch
        error:badarg ->
            ok;
        Type2:Error2 ->
            ?assertMatch(error, Type2),
            ?assertMatch(badarg, Error2)
    end.

badarg_384_test() ->
    try
        erlsha2:sha384(1234)
    catch
        error:badarg ->
            ok;
        Type:Error ->
            ?assertMatch(error, Type),
            ?assertMatch(badarg, Error)
    end.

badarg_384_update_test() ->
    Ctx1 = erlsha2:sha384_init(),
    try
        NCtx1 = erlsha2:sha384_update(Ctx1, not_an_iolist),
        erlsha2:sha384_final(NCtx1)
    catch
        error:badarg ->
            ok;
        Type1:Error1 ->
            ?assertMatch(error, Type1),
            ?assertMatch(badarg, Error1)
    end,
    _Ctx2 = erlsha2:sha384_init(),
    try
        NCtx2 = erlsha2:sha384_update(not_a_context, <<"a">>),
        erlsha2:sha384_final(NCtx2)
    catch
        error:badarg ->
            ok;
        Type2:Error2 ->
            ?assertMatch(error, Type2),
            ?assertMatch(badarg, Error2)
    end.

badarg_512_test() ->
    try
        erlsha2:sha512(1234)
    catch
        error:badarg ->
            ok;
        Type:Error ->
            ?assertMatch(error, Type),
            ?assertMatch(badarg, Error)
    end.

badarg_512_update_test() ->
    Ctx1 = erlsha2:sha512_init(),
    try
        NCtx1 = erlsha2:sha512_update(Ctx1, not_an_iolist),
        erlsha2:sha512_final(NCtx1)
    catch
        error:badarg ->
            ok;
        Type1:Error1 ->
            ?assertMatch(error, Type1),
            ?assertMatch(badarg, Error1)
    end,
    _Ctx2 = erlsha2:sha512_init(),
    try
        NCtx2 = erlsha2:sha512_update(not_a_context, <<"a">>),
        erlsha2:sha512_final(NCtx2)
    catch
        error:badarg ->
            ok;
        Type2:Error2 ->
            ?assertMatch(error, Type2),
            ?assertMatch(badarg, Error2)
    end.

sha224_test(Vectors) ->
    Expected224 = sha224_expected(),
    lists:foreach(fun({Vector, Expected}) ->
                          Actual = erlsha2:sha224(Vector),
                          ?assertMatch(Expected, Actual)
                  end, lists:zip(Vectors, Expected224)),
    ok.

sha224_update_test(Vectors) ->
    Expected224 = sha224_expected(),
    ExpectedActual = lists:zip(Vectors, Expected224),
    lists:foreach(fun({Vector, Expected}) ->
                          Ctx = erlsha2:sha224_init(),
                          NCtx = case size(Vector) of
                                     0 ->
                                         erlsha2:sha224_update(
                                           Ctx, Vector);
                                     Sz ->
                                         Pos = Sz div 2,
                                         {V1,V2} = split_binary(Vector, Pos),
                                         NCtx0 = erlsha2:sha224_update(
                                                   Ctx, V1),
                                         erlsha2:sha224_update(
                                           NCtx0, V2)
                                 end,
                          Actual = erlsha2:sha224_final(NCtx),
                          ?assertMatch(Expected, Actual)
                  end, ExpectedActual),
    lists:foreach(fun({Vector, Expected}) ->
                          case size(Vector) of
                              0 ->
                                  ok;
                              _ ->
                                  Ctx = erlsha2:sha224_init(),
                                  Vals = binary_to_list(Vector),
                                  NCtx = lists:foldl(
                                           fun(V, LastCtx) ->
                                                   erlsha2:sha224_update(
                                                     LastCtx, <<V:8>>)
                                           end, Ctx, Vals),
                                  Actual = erlsha2:sha224_final(NCtx),
                                  ?assertMatch(Expected, Actual)
                          end
                  end, ExpectedActual),
    ok.

sha256_test(Vectors) ->
    Expected256 = sha256_expected(),
    lists:foreach(fun({Vector, Expected}) ->
                          Actual = erlsha2:sha256(Vector),
                          ?assertMatch(Expected, Actual)
                  end, lists:zip(Vectors, Expected256)),
    ok.

sha256_update_test(Vectors) ->
    Expected256 = sha256_expected(),
    ExpectedActual = lists:zip(Vectors, Expected256),
    lists:foreach(fun({Vector, Expected}) ->
                          Ctx = erlsha2:sha256_init(),
                          NCtx = case size(Vector) of
                                     0 ->
                                         erlsha2:sha256_update(
                                           Ctx, Vector);
                                     Sz ->
                                         Pos = Sz div 2,
                                         {V1,V2} = split_binary(Vector, Pos),
                                         NCtx0 = erlsha2:sha256_update(
                                                   Ctx, V1),
                                         erlsha2:sha256_update(
                                           NCtx0, V2)
                                 end,
                          Actual = erlsha2:sha256_final(NCtx),
                          ?assertMatch(Expected, Actual)
                  end, ExpectedActual),
    lists:foreach(fun({Vector, Expected}) ->
                          case size(Vector) of
                              0 ->
                                  ok;
                              _ ->
                                  Ctx = erlsha2:sha256_init(),
                                  Vals = binary_to_list(Vector),
                                  NCtx = lists:foldl(
                                           fun(V, LastCtx) ->
                                                   erlsha2:sha256_update(
                                                     LastCtx, <<V:8>>)
                                           end, Ctx, Vals),
                                  Actual = erlsha2:sha256_final(NCtx),
                                  ?assertMatch(Expected, Actual)
                          end
                  end, ExpectedActual),
    ok.

sha384_test(Vectors) ->
    Expected384 = sha384_expected(),
    lists:foreach(fun({Vector, Expected}) ->
                          Actual = erlsha2:sha384(Vector),
                          ?assertMatch(Expected, Actual)
                  end, lists:zip(Vectors, Expected384)),
    ok.

sha384_update_test(Vectors) ->
    Expected384 = sha384_expected(),
    ExpectedActual = lists:zip(Vectors, Expected384),
    lists:foreach(fun({Vector, Expected}) ->
                          Ctx = erlsha2:sha384_init(),
                          NCtx = case size(Vector) of
                                     0 ->
                                         erlsha2:sha384_update(
                                           Ctx, Vector);
                                     Sz ->
                                         Pos = Sz div 2,
                                         {V1,V2} = split_binary(Vector, Pos),
                                         NCtx0 = erlsha2:sha384_update(
                                                   Ctx, V1),
                                         erlsha2:sha384_update(
                                           NCtx0, V2)
                                 end,
                          Actual = erlsha2:sha384_final(NCtx),
                          ?assertMatch(Expected, Actual)
                  end, ExpectedActual),
    lists:foreach(fun({Vector, Expected}) ->
                          case size(Vector) of
                              0 ->
                                  ok;
                              _ ->
                                  Ctx = erlsha2:sha384_init(),
                                  Vals = binary_to_list(Vector),
                                  NCtx = lists:foldl(
                                           fun(V, LastCtx) ->
                                                   erlsha2:sha384_update(
                                                     LastCtx, <<V:8>>)
                                           end, Ctx, Vals),
                                  Actual = erlsha2:sha384_final(NCtx),
                                  ?assertMatch(Expected, Actual)
                          end
                  end, ExpectedActual),
    ok.

sha512_test(Vectors) ->
    Expected512 = sha512_expected(),
    lists:foreach(fun({Vector, Expected}) ->
                          Actual = erlsha2:sha512(Vector),
                          ?assertMatch(Expected, Actual)
                  end, lists:zip(Vectors, Expected512)),
    ok.

sha512_update_test(Vectors) ->
    Expected512 = sha512_expected(),
    ExpectedActual = lists:zip(Vectors, Expected512),
    lists:foreach(fun({Vector, Expected}) ->
                          Ctx = erlsha2:sha512_init(),
                          NCtx = case size(Vector) of
                                     0 ->
                                         erlsha2:sha512_update(
                                           Ctx, Vector);
                                     Sz ->
                                         Pos = Sz div 2,
                                         {V1,V2} = split_binary(Vector, Pos),
                                         NCtx0 = erlsha2:sha512_update(
                                                   Ctx, V1),
                                         erlsha2:sha512_update(
                                           NCtx0, V2)
                                 end,
                          Actual = erlsha2:sha512_final(NCtx),
                          ?assertMatch(Expected, Actual)
                  end, ExpectedActual),
    lists:foreach(fun({Vector, Expected}) ->
                          case size(Vector) of
                              0 ->
                                  ok;
                              _ ->
                                  Ctx = erlsha2:sha512_init(),
                                  Vals = binary_to_list(Vector),
                                  NCtx = lists:foldl(
                                           fun(V, LastCtx) ->
                                                   erlsha2:sha512_update(
                                                     LastCtx, <<V:8>>)
                                           end, Ctx, Vals),
                                  Actual = erlsha2:sha512_final(NCtx),
                                  ?assertMatch(Expected, Actual)
                          end
                  end, ExpectedActual),
    ok.

read_test_vectors() ->
    read_test_vectors([], 1).
read_test_vectors(Vectors, 19) ->
    lists:reverse(Vectors);
read_test_vectors(Vectors, Num) ->
    VecFile = io_lib:format("../test/testvectors/vector~3.10.0b.dat", [Num]),
    {ok, Vector} = file:read_file(lists:flatten(VecFile)),
    read_test_vectors([Vector|Vectors], Num+1).

sha224_expected() ->
    [<<16#23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7:224/big-unsigned>>,
     <<16#75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525:224/big-unsigned>>,
     <<16#c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3:224/big-unsigned>>,
     <<16#62a41ab0961bcdd22db70b896db3955c1d04096af6de47f5aaad1226:224/big-unsigned>>,
     <<16#d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f:224/big-unsigned>>,
     <<16#d92622d56f83d869a884f6cc0763e90c4520a21e1cc429841e4584d2:224/big-unsigned>>,
     <<16#0873433e1c8749dad0e34f92aff11c4b2ca310356283817747aa6940:224/big-unsigned>>,
     <<16#5a69ccca0b5e7f84efda7c026d010fa46569c03f97b4440eba32b941:224/big-unsigned>>,
     <<16#49e54148d21d457f2ffe28532543d91da98724c9883e67682301dec4:224/big-unsigned>>,
     <<16#6417acfccd1d78cc14f1dd2de4ffcafe9cff0f92f0e28139866c2e2d:224/big-unsigned>>,
     <<16#d4126ce69e15fc0c06cb1bf763f112b139ffd81189e3899e4e275560:224/big-unsigned>>,
     <<16#0ace93ff0cfa76006af9db847f4ff2e702c2518dc946948807be0a47:224/big-unsigned>>,
     <<16#91e452cfc8f22f9c69e637ec9dcf80d5798607a52234686fcf8880ad:224/big-unsigned>>,
     <<16#bdaac28698611eba163f232785d8f4caffe29ac2fd8133651baf8212:224/big-unsigned>>,
     <<16#4f41e1e6839ed85883ee0f259ac9025d19ecccbfc4d9d72f075ba5f2:224/big-unsigned>>,
     <<16#4215dc642269cfd6d9b4b6da78fd01a9094bc89f4780905714b0a896:224/big-unsigned>>,
     <<16#a1b0964a6d8188eb2980e126fefc70eb79d0745a91cc2f629af34ece:224/big-unsigned>>,
     <<16#cc9286e04c4a39a6bb92a42f2ffabce02156090b6882b0ca22026294:224/big-unsigned>>].

sha256_expected() ->
    [<<16#ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad:256/big-unsigned>>,
     <<16#248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1:256/big-unsigned>>,
     <<16#cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1:256/big-unsigned>>,
     <<16#4d25fccf8752ce470a58cd21d90939b7eb25f3fa418dd2da4c38288ea561e600:256/big-unsigned>>,
     <<16#e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855:256/big-unsigned>>,
     <<16#ab64eff7e88e2e46165e29f2bce41826bd4c7b3552f6b382a9e7d3af47c245f8:256/big-unsigned>>,
     <<16#f08a78cbbaee082b052ae0708f32fa1e50c5c421aa772ba5dbb406a2ea6be342:256/big-unsigned>>,
     <<16#0ab803344830f92089494fb635ad00d76164ad6e57012b237722df0d7ad26896:256/big-unsigned>>,
     <<16#e4326d0459653d7d3514674d713e74dc3df11ed4d30b4013fd327fdb9e394c26:256/big-unsigned>>,
     <<16#a7f001d996dd25af402d03b5f61aef950565949c1a6ad5004efa730328d2dbf3:256/big-unsigned>>,
     <<16#6dcd63a07b0922cc3a9b3315b158478681cc32543b0a4180abe58a73c5e14cc2:256/big-unsigned>>,
     <<16#af6ebfde7d93d5badb6cde6287ecc2061c1cafc5b1c1217cd984fbcdb9c61aaa:256/big-unsigned>>,
     <<16#8ff59c6d33c5a991088bc44dd38f037eb5ad5630c91071a221ad6943e872ac29:256/big-unsigned>>,
     <<16#1818e87564e0c50974ecaabbb2eb4ca2f6cc820234b51861e2590be625f1f703:256/big-unsigned>>,
     <<16#5e3dfe0cc98fd1c2de2a9d2fd893446da43d290f2512200c515416313cdf3192:256/big-unsigned>>,
     <<16#80fced5a97176a5009207cd119551b42c5b51ceb445230d02ecc2663bbfb483a:256/big-unsigned>>,
     <<16#88ee6ada861083094f4c64b373657e178d88ef0a4674fce6e4e1d84e3b176afb:256/big-unsigned>>,
     <<16#5a2e925a7f8399fa63a20a1524ae83a7e3c48452f9af4df493c8c51311b04520:256/big-unsigned>>].

sha384_expected() ->
    [<<16#cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed:256/big-unsigned,
       16#8086072ba1e7cc2358baeca134c825a7:128/big-unsigned>>,
     <<16#3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6:256/big-unsigned,
       16#b0455a8520bc4e6f5fe95b1fe3c8452b:128/big-unsigned>>,
     <<16#09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712:256/big-unsigned,
       16#fcc7c71a557e2db966c3e9fa91746039:128/big-unsigned>>,
     <<16#69cc75b95280bdd9e154e743903e37b1205aa382e92e051b1f48a6db9d0203f8:256/big-unsigned,
       16#a17c1762d46887037275606932d3381e:128/big-unsigned>>,
     <<16#38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da:256/big-unsigned,
       16#274edebfe76f65fbd51ad2f14898b95b:128/big-unsigned>>,
     <<16#e28e35e25a1874908bf0958bb088b69f3d742a753c86993e9f4b1c4c21988f95:256/big-unsigned,
       16#8bd1fe0315b195aca7b061213ac2a9bd:128/big-unsigned>>,
     <<16#37b49ef3d08de53e9bd018b0630067bd43d09c427d06b05812f48531bce7d2a6:256/big-unsigned,
       16#98ee2d1ed1ffed46fd4c3b9f38a8a557:128/big-unsigned>>,
     <<16#e3e3602f4d90c935321d788f722071a8809f4f09366f2825cd85da97ccd2955e:256/big-unsigned,
       16#b6b8245974402aa64789ed45293e94ba:128/big-unsigned>>,
     <<16#1ca650f38480fa9dfb5729636bec4a935ebc1cd4c0055ee50cad2aa627e06687:256/big-unsigned,
       16#1044fd8e6fdb80edf10b85df15ba7aab:128/big-unsigned>>,
     <<16#b8261ddcd7df7b3969a516b72550de6fbf0e394a4a7bb2bbc60ec603c2ceff64:256/big-unsigned,
       16#3c5bf62bc6dcbfa5beb54b62d750b969:128/big-unsigned>>,
     <<16#548e4e9a1ff57f469ed47b023bf5279dfb4d4ca08c65051e3a5c41fab84479a2:256/big-unsigned,
       16#05496276906008b4b3c5b0970b2f5446:128/big-unsigned>>,
     <<16#c6fec3a3278dd6b5afc8c0971d32d38faf5802f1a21527c32563b32a1ac34065:256/big-unsigned,
       16#6b433b44fe2648aa2232206f4301193a:128/big-unsigned>>,
     <<16#92dca5655229b3c34796a227ff1809e273499adc2830149481224e0f54ff4483:256/big-unsigned,
       16#bd49834d4865e508ef53d4cd22b703ce:128/big-unsigned>>,
     <<16#310fbb2027bdb7042f0e09e7b092e9ada506649510a7aa029825c8e8019e9c30:256/big-unsigned,
       16#749d723f2de1bd8c043d8d89d3748c2f:128/big-unsigned>>,
     <<16#0d5e45317bc7997cb9c8a23bad9bac9170d5bc81789b51af6bcd74ace379fd64:256/big-unsigned,
       16#9a2b48cb56c4cb4ec1477e6933329e0e:128/big-unsigned>>,
     <<16#aa1e77c094e5ce6db81a1add4c095201d020b7f8885a4333218da3b799b9fc42:256/big-unsigned,
       16#f00d60cd438a1724ae03bd7b515b739b:128/big-unsigned>>,
     <<16#78cc6402a29eb984b8f8f888ab0102cabe7c06f0b9570e3d8d744c969db14397:256/big-unsigned,
       16#f58ecd14e70f324bf12d8dd4cd1ad3b2:128/big-unsigned>>,
     <<16#72ec26cc742bc5fb1ef82541c9cadcf01a15c8104650d305f24ec8b006d7428e:256/big-unsigned,
       16#8ebe2bb320a465dbdd5c6326bbd8c9ad:128/big-unsigned>>].

sha512_expected() ->
    [<<16#ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a:256/big-unsigned,
       16#2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f:256/big-unsigned>>,
     <<16#204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335:256/big-unsigned,
       16#96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445:256/big-unsigned>>,
     <<16#8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018:256/big-unsigned,
       16#501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909:256/big-unsigned>>,
     <<16#23450737795d2f6a13aa61adcca0df5eef6df8d8db2b42cd2ca8f783734217a7:256/big-unsigned,
       16#3e9cabc3c9b8a8602f8aeaeb34562b6b1286846060f9809b90286b3555751f09:256/big-unsigned>>,
     <<16#cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce:256/big-unsigned,
       16#47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e:256/big-unsigned>>,
     <<16#70aefeaa0e7ac4f8fe17532d7185a289bee3b428d950c14fa8b713ca09814a38:256/big-unsigned,
       16#7d245870e007a80ad97c369d193e41701aa07f3221d15f0e65a1ff970cedf030:256/big-unsigned>>,
     <<16#b3de4afbc516d2478fe9b518d063bda6c8dd65fc38402dd81d1eb7364e72fb6e:256/big-unsigned,
       16#6663cf6d2771c8f5a6da09601712fb3d2a36c6ffea3e28b0818b05b0a8660766:256/big-unsigned>>,
     <<16#97fb4ec472f3cb698b9c3c12a12768483e5b62bcdad934280750b4fa4701e5e0:256/big-unsigned,
       16#550a80bb0828342c19631ba55a55e1cee5de2fda91fc5d40e7bee1d4e6d415b3:256/big-unsigned>>,
     <<16#d399507bbf5f2d0da51db1ff1fc51c1c9ff1de0937e00d01693b240e84fcc340:256/big-unsigned,
       16#0601429f45c297acc6e8fcf1e4e4abe9ff21a54a0d3d88888f298971bd206cd5:256/big-unsigned>>,
     <<16#caf970d3638e21053173a638c4b94d6d1ff87bc47b58f8ee928fbe9e245c23ab:256/big-unsigned,
       16#f81019e45bf017ecc8610e5e0b95e3b025ccd611a772ca4fb3dfba26f0859725:256/big-unsigned>>,
     <<16#ee5d07460183b130687c977e9f8d43110989b0864b18fe6ee00a53dec5eda111:256/big-unsigned,
       16#f3aaa3bac7ab8dae26ed545a4de33ed45190f18fa0c327c44642ab9424265330:256/big-unsigned>>,
     <<16#73ffeb67716c3495fbc33f2d62fe08e2616706a5599881c7e67e9ef2b68f4988:256/big-unsigned,
       16#ea8b3b604ba87e50b07962692705c420fa31a00be41d6aaa9f3b11eafe9cf49b:256/big-unsigned>>,
     <<16#0e928db6207282bfb498ee871202f2337f4074f3a1f5055a24f08e912ac118f8:256/big-unsigned,
       16#101832cdb9c2f702976e629183db9bacfdd7b086c800687c3599f15de7f7b9dd:256/big-unsigned>>,
     <<16#a001636f3ff1ce34f432f8e8f7785b78be84318beb8485a406650a8b243c419f:256/big-unsigned,
       16#7db6435cf6bf3000c6524adb5b52bad01afb76b3ceff701331e18b85b0e4cbd3:256/big-unsigned>>,
     <<16#735bd6bebfe6f8070d70069105bc761f35ed1ac3742f2e372fdc14d2a51898e6:256/big-unsigned,
       16#153ccaff9073324130abdc451c730dc5dab5a0452487b1171c4dd97f92e267b7:256/big-unsigned>>,
     <<16#fae25ec70bcb3bbdef9698b9d579da49db68318dbdf18c021d1f76aaceff9628:256/big-unsigned,
       16#38873235597e7cce0c68aabc610e0deb79b13a01c302abc108e459ddfbe9bee8:256/big-unsigned>>,
     <<16#211bec83fbca249c53668802b857a9889428dc5120f34b3eac1603f13d1b4796:256/big-unsigned,
       16#5c387b39ef6af15b3a44c5e7b6bbb6c1096a677dc98fc8f472737540a332f378:256/big-unsigned>>,
     <<16#ebad464e6d9f1df7e8aadff69f52db40a001b253fbf65a018f29974dcc7fbf8e:256/big-unsigned,
       16#58b69e247975fbadb4153d7289357c9b6212752d0ab67dd3d9bbc0bb908aa98c:256/big-unsigned>>].
