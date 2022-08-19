%%% File        : emusig2.erl
%%% Author      : Hans Svensson
%%% Description : Experimental muSig2 implementation for ed25519
%%% Created     : 24 Jan 2022 by Hans Svensson
-module(emusig2).

-export([sign_init/2, sign_init/3,
         sign_msg/5,
         sign_add_sig/2,
         sign_finish/1,
         aggregated_key/1,
         nonce2nonce_pt/1]).

-ifdef(TEST).
-compile([export_all, nowarn_export_all]).
-endif.

-type binary_32() :: <<_:256>>.
-type binary_64() :: <<_:512>>.

-type sign_state() ::
  #{pk     => binary_32(),
    exp    => binary_32(),
    agg_pk => binary_32(),
    n      => non_neg_integer(),
    my_s   => binary_32(),
    agg_n  => binary_32(),
    s      => binary_32(),
    ss     => [binary_32()],
    sig    => binary_64(),
    msg    => binary()}.

%% Ed255129 points are represented by their Y-coordinates and a single (the
%% highest one!) bit for sign of X.
%% Scalars are 256 bits (or really 253 bits), and little-endian represenation
%% is used.

-spec sign_init(PubKey    :: <<_:256>>,
                OtherKeys :: [<<_:256>>]) -> sign_state().
sign_init(PubKey, OtherKeys) ->
  {AggPK, MyExp} = aggregate_pks(PubKey, OtherKeys),
  #{pk => PubKey, agg_pk => AggPK, exp => MyExp, n => length(OtherKeys) + 1}.

-spec sign_init(PubKey    :: <<_:256>>,
                AggPK     :: <<_:256>>,
                OtherKeys :: [<<_:256>>]) -> sign_state().
sign_init(PubKey, AggPK, OtherKeys) ->
  case aggregate_pks(PubKey, OtherKeys) of
    {AggPK, MyExp} ->
      #{pk => PubKey, agg_pk => AggPK, exp => MyExp, n => length(OtherKeys) + 1};
    {_WrongAggPK, _} ->
      error({bad_init_data, aggregate_pk_mismatch})
  end.

-spec sign_msg(SignState   :: sign_state(),
               SK          :: binary_32(),
               Msg         :: binary(),
               MyNonces    :: [binary_32()],
               OtherNonces :: [[binary_32()]]) -> {binary_32(), sign_state()}.
sign_msg(SignState = #{agg_pk := AggPK, exp := MyExp}, SK = <<_:256>>, Msg, MyNonces0, OtherNonces) ->
  MyNonces = [ clamp(N) || N <- MyNonces0 ],
  MyNoncePts = [ sc_mul(N) || N <- MyNonces ],

  <<Seed0:32/bytes, _/binary>> = crypto:hash(sha512, SK),
  Seed = clamp(Seed0),

  AccNonces = accumulate_nonces([MyNoncePts | OtherNonces]),
  {AggN, [Exp1, Exp2]} = aggregate_nonces(AggPK, AccNonces, Msg),

  Challenge = hash_to_scalar(<<AggN/binary, AggPK/binary, Msg/binary>>),
  [N1s, N2s] = MyNonces,

  Ns = add_sc(mul_sc(Exp1, N1s), mul_sc(Exp2, N2s)),
  S  = compress(add_sc(mul_sc(Challenge, mul_sc(MyExp, Seed)), Ns)),
  {S, SignState#{my_s => S, ss => [S], agg_n => AggN, msg => Msg}};
sign_msg(_SignState, _SK, _Msg, _MyNonces, _OtherNonces) ->
  error(bad_sign_state).

-spec sign_add_sig(SignState :: sign_state(),
                   PartSig   :: binary_32()) -> {all | incomplete, sign_state()}.
sign_add_sig(SignState = #{ss := Ss, n := N}, S) ->
  NewSs = lists:usort([S | Ss]),
  case length(NewSs) == N of
    true ->
      Stot = sum_scalars(NewSs),
      {all, SignState#{s => Stot, ss := NewSs}};
    false ->
      {incomplete, SignState#{ss := NewSs}}
  end.

-spec sign_finish(SignState :: sign_state()) -> {binary_64(), sign_state()}.
sign_finish(SignState = #{agg_n := AN, s := S}) ->
  Sig = <<AN:32/bytes, S:32/bytes>>,
  {Sig, SignState#{sig => Sig}}.

-spec aggregated_key(PKs :: [binary_32()]) -> binary_32().
aggregated_key(PKs) ->
  SortedPKs = lists:sort(PKs),

  AllPKs = << PK || PK <- SortedPKs >>,

  Factors = [ sc_mul(compute_exponent(AllPKs, PK), PK) || PK <- SortedPKs ],

  compress(sum_pts(Factors)).

-spec nonce2nonce_pt(Nonce :: binary_32()) -> binary_32().
nonce2nonce_pt(Nonce) ->
  compress(sc_mul(clamp(Nonce))).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% p_add(A, B)  -> enacl:crypto_ed25519_add(A, B).
%% sc_mul(S)    -> enacl:crypto_ed25519_scalarmult_base_noclamp(S).
%% sc_mul(S, P) -> enacl:crypto_ed25519_scalarmult_noclamp(S, P).
%% mul_sc(A, B) -> enacl:crypto_ed25519_scalar_mul(A, B).
%% add_sc(A, B) -> enacl:crypto_ed25519_scalar_add(A, B).
%% compress(P)  -> P.

p_add(A, B)  -> ecu_ed25519:p_add(A, B).
sc_mul(P)    -> ecu_ed25519:scalar_mul_base_noclamp(P).
sc_mul(S, P) -> ecu_ed25519:scalar_mul_noclamp(S, P).
mul_sc(A, B) -> ecu_ed25519:s_mul(A, B).
add_sc(A, B) -> ecu_ed25519:s_add(A, B).
compress(P)  -> ecu_ed25519:compress(P).

aggregate_pks(MyPK, PKs) ->
  SortedPKs = [ PK || PK <- lists:sort([MyPK | PKs]) ],

  AllPKs = << PK || PK <- SortedPKs >>,

  Factors = [ sc_mul(compute_exponent(AllPKs, PK), PK) || PK <- SortedPKs ],

  AggregatedPK = compress(sum_pts(Factors)),

  {AggregatedPK, compute_exponent(AllPKs, MyPK)}.

accumulate_nonces([[] | _]) -> [];
accumulate_nonces(NoncesLists) ->
  Ns = [ hd(L) || L <- NoncesLists ],
  Ts = [ tl(L) || L <- NoncesLists ],
  [ compress(sum_pts(Ns)) | accumulate_nonces(Ts)].

aggregate_nonces(AggPK, [AccN1, AccN2], Msg) ->
  Exp1 = <<1:256/little>>,
  Exp2 = hash_to_scalar(<<AggPK/binary, AccN1/binary, AccN2/binary, Msg/binary>>),

  AggN = compress(p_add(sc_mul(Exp1, AccN1), sc_mul(Exp2, AccN2))),
  {AggN, [Exp1, Exp2]}.

sum_pts([P | Ps]) ->
   lists:foldl(fun p_add/2, P, Ps).

sum_scalars([P | Ps]) ->
   lists:foldl(fun add_sc/2, P, Ps).

compute_exponent(AllPKs, PK) ->
  hash_to_scalar(<<AllPKs/binary, PK/binary>>).

hash_to_scalar(Binary) ->
  ecu_ed25519:scalar_reduce(crypto:hash(sha512, Binary)).

%% Clamp a 32-byte little-endian value - i.e clear the lowest three bits of
%% the first byte and clear the highest and set the second highest of the
%% last byte
clamp(<<B0:8, B1_30:30/bytes, B31:8>>) ->
  <<(B0 band 16#f8):8, B1_30/bytes, ((B31 band 16#7f) bor 16#40):8>>.
