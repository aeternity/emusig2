-module(musig2_tests).
-compile([export_all, nowarn_export_all]).

-include_lib("eunit/include/eunit.hrl").

compute_nonce() ->
  clamp(crypto:strong_rand_bytes(32)).

clamp(<<B0:8, B1_30:30/bytes, B31:8>>) ->
  <<(B0 band 16#f8):8, B1_30/bytes, ((B31 band 16#7f) bor 16#40):8>>.

gen_user_data() ->
  SK = crypto:strong_rand_bytes(32),
  #{public := PK} = ecu_eddsa:sign_seed_keypair(SK),
  Nonces = [compute_nonce(), compute_nonce()],
  NoncePts = [ ecu_ed25519:compress(ecu_ed25519:scalar_mul_base_noclamp(P))
               || P <- Nonces ],
  {SK, PK, Nonces, NoncePts}.

musig2_2party_test() ->
  [ begin
      A = gen_user_data(),
      B = gen_user_data(),
      Msg = crypto:strong_rand_bytes(32),
      test_sign(A, B, Msg),
      ok
    end || _ <- lists:seq(1, 10) ].

musig2_3party_test() ->
  [ begin
      A = gen_user_data(),
      B = gen_user_data(),
      C = gen_user_data(),
      Msg = crypto:strong_rand_bytes(32),
      test_sign3(A, B, C, Msg),
      ok
    end || _ <- lists:seq(1, 10) ].

test_sign({ASK, APK, ANs, ANPs}, {BSK, BPK, BNs, BNPs}, Msg) ->
  {AggPK, _} = emusig2:aggregate_pks(APK, [BPK]),

  AState1 = emusig2:sign_init(APK, AggPK, [BPK]),
  BState1 = emusig2:sign_init(BPK, AggPK, [APK]),

  {AS, AState2} = emusig2:sign_msg(AState1, ASK, Msg, ANs, [BNPs]),
  {BS, BState2} = emusig2:sign_msg(BState1, BSK, Msg, BNs, [ANPs]),

  {all, AState3} = emusig2:sign_add_sig(AState2, BS),
  {all, BState3} = emusig2:sign_add_sig(BState2, AS),

  {ESig, AState4} = emusig2:sign_finish(AState3),
  {ESig, _BState4} = emusig2:sign_finish(BState3),

  #{sig := Sig, agg_pk := AggPK} = AState4,
  true = ecu_eddsa:sign_verify_detached(Sig, Msg, AggPK),
  ok.

test_sign3({ASK, APK, ANs, ANPs}, {BSK, BPK, BNs, BNPs}, {CSK, CPK, CNs, CNPs}, Msg) ->
  {AggPK, _} = emusig2:aggregate_pks(APK, [BPK, CPK]),

  AState1 = emusig2:sign_init(APK, AggPK, [BPK, CPK]),
  BState1 = emusig2:sign_init(BPK, AggPK, [APK, CPK]),
  CState1 = emusig2:sign_init(CPK, AggPK, [APK, BPK]),

  {AS, AState2} = emusig2:sign_msg(AState1, ASK, Msg, ANs, [BNPs, CNPs]),
  {BS, BState2} = emusig2:sign_msg(BState1, BSK, Msg, BNs, [ANPs, CNPs]),
  {CS, CState2} = emusig2:sign_msg(CState1, CSK, Msg, CNs, [ANPs, BNPs]),

  {incomplete, AState3} = emusig2:sign_add_sig(AState2, BS),
  {incomplete, BState3} = emusig2:sign_add_sig(BState2, AS),
  {incomplete, CState3} = emusig2:sign_add_sig(CState2, AS),

  {all, AState4} = emusig2:sign_add_sig(AState3, CS),
  {all, BState4} = emusig2:sign_add_sig(BState3, CS),
  {all, CState4} = emusig2:sign_add_sig(CState3, BS),

  {ESig, AState5}  = emusig2:sign_finish(AState4),
  {ESig, _BState5} = emusig2:sign_finish(BState4),
  {ESig, _CState5} = emusig2:sign_finish(CState4),

  #{sig := Sig, agg_pk := AggPK} = AState5,
  true = ecu_eddsa:sign_verify_detached(Sig, Msg, AggPK),
  ok.

