//! Shapes shared across the sig-net contracts.

use minocrab::v3::{Circuit3, FieldT, Operand, Secp256k1PointT, Wire3};
use minocrab::{Alignment, AlignmentAtom, AlignmentSegment, Private, Public, Visibility};
use minocrab_ledger::{
    cell_read, cell_write_coin, counter_read, dup, emit, idx_field, kernel_claim_zswap_coin_receive,
    kernel_claim_zswap_coin_spend, kernel_claim_zswap_nullifier, kernel_mint_shielded,
    popeq, ImpactElem, LedgerValue,
};
use minocrab_std::v3::kernel;
use minocrab_std::v3::{
    CoinNonce, TokenDomainSeparator,
    b32_newtype, coin_commitment, coin_nullifier_contract, token_type, CircuitAbi, CoinRecipient,
    ContractAddress, Secp256k1Point, ShieldedCoinInfo3, Uint, B32, STRAIGHT_LINE,
};

b32_newtype! {
    /// The witnessed vault secret key (`witness …SecretKey(): Bytes<32>`) —
    /// what [`commitment_padded_tag`] and [`commitment_packed_tag`] derive
    /// an identity from, and the first preimage limb of every refund
    /// commitment. Constructed only by [`witness_sk`], so nothing but a
    /// witnessed secret key can reach those derivations: any other private
    /// `B32` in scope (a nonce, a colour, a request id) no longer
    /// type-checks there, which is newtype-survey hazard A2 closed.
    SecretKey,
    /// An identity commitment — the MPC's key-derivation PATH, i.e. the
    /// value that decides which EVM account is derived. Produced only by
    /// [`commitment_padded_tag`] and [`commitment_packed_tag`]; the stored
    /// deployer and every depositor/caller comparison carry this type, so
    /// no other 32-byte value (a nonce, a colour, a request id, a refund
    /// commitment) can be compared against or written as one —
    /// newtype-survey hazard A3, the family whose near-unification would
    /// have "silently restranded every derived account"
    /// (notes/vault-vocabulary.org §0).
    UserCommitment,
    /// A refund commitment — `withdrawRefundCommitment(sk, requestId)`,
    /// covering both the withdraw and swap variants (same derivation; the
    /// two `LedgerMap`s distinguish which route holds one). Produced only
    /// by the forks' `withdraw_refund_commitment`, stored and looked up as
    /// this type, so a [`UserCommitment`] (or any other 32-byte value) can
    /// no longer satisfy a withdrawer/swapper/claimant gate —
    /// newtype-survey hazard A4.
    RefundCommitment,
    /// The MPC's SIGNING PATH — slot 5 of the sign-bidirectional event
    /// record, the value the MPC derives its signing key from. Genuinely
    /// polymorphic (deposit signs from the depositor's [`UserCommitment`];
    /// withdraw/swap/approveRouter from the constant vault path), which is
    /// why it is ONE type with exactly two constructors —
    /// `SigningPath::from(user_commitment)` and [`SigningPath::vault_path`]
    /// — rather than four: nothing else fits the slot, so the
    /// sender/path/caip2 transposition of newtype-survey hazard A7 no
    /// longer compiles.
    SigningPath,
    /// A CAIP-2 chain id — slot 7 of the event record and the vault's
    /// `caip2Id` cell. Distinct from [`SigningPath`] so the MPC can never
    /// be asked to derive a signing key from a chain id (hazard A7's
    /// sharpest transposition).
    Caip2Id,
}

/// A depositor's identity commitment IS a signing path — deposit's event
/// signs from it. The only conversion into [`SigningPath`] besides
/// [`SigningPath::vault_path`].
impl<V: minocrab_std::v3::Vis3> From<UserCommitment<V>> for SigningPath<V> {
    fn from(commitment: UserCommitment<V>) -> Self {
        SigningPath(commitment.bytes())
    }
}

impl SigningPath<Public> {
    /// `pad(32, "vault")` — the contract-authored path the non-deposit
    /// circuits sign from.
    pub fn vault_path(c: &mut Circuit3) -> Self {
        SigningPath(B32::pad(c, super::erc20_vault::VAULT_PATH))
    }
}

/// A `Secp256k1Point`'s FAB alignment: x as b24+b8, y as b24+b8, plus a
/// native field element (notes/ledger-abi.org §3) — 5 limbs, matching
/// `encode`'s output.
///
/// The table itself lives on the ARGUMENT type (M9 phase 5), because a
/// point's alignment is one fact: the same five atoms describe the value
/// entering a circuit and the value written to a `Secp256k1Point` cell.
pub fn secp256k1_point_atoms() -> Vec<AlignmentAtom> {
    Secp256k1Point::<Public>::atoms()
}

/// The identity commitment both contracts derive:
/// `persistentHash<Vector<2, Bytes<32>>>([pad(32, prefix), sk])` — the tag
/// occupying a full 32-byte limb, so the preimage is 64 bytes and SHA-256
/// splits it into two blocks.
///
/// A DIFFERENT VALUE FROM [`commitment_packed_tag`], not a slower spelling of
/// it: the packed form hashes the tag's significant bytes alone, which is a
/// different byte string and therefore a different digest. The digest is the
/// MPC's key-derivation PATH, so the two forms derive different EVM accounts
/// and an artifact must use one of them everywhere. `_padded_tag` is the
/// compat form — what compactc's own vault emits, and what the deployed MPC
/// config expects.
///
/// The suffix names the PREIMAGE rather than the cost on purpose: M18's
/// design pass read the old name `commitment_short` as a cheaper spelling and
/// filed it for unification, which would have silently restranded every
/// derived account (notes/vault-vocabulary.org §0).
pub fn commitment_padded_tag(
    c: &mut Circuit3,
    prefix: &str,
    sk: &SecretKey<Private>,
) -> UserCommitment<Private> {
    let sk = sk.bytes();
    c.region("identity commitment", |c| {
        let pad = B32::pad(c, prefix);
        let alignment = Alignment(vec![
            AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
            AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
        ]);
        let digest = c.persistent_hash(
            alignment,
            &[
                pad.hi.private().erase(),
                pad.lo.private().erase(),
                sk.hi.erase(),
                sk.lo.erase(),
            ],
        );
        UserCommitment(B32::from_typed(c, digest))
    })
}

/// The PACKED-TAG identity commitment (M10 rung 5(i-userCommit), avenue 1):
/// `persistentHash<[Bytes<11>, Bytes<32>]>(["vault:user:", sk])`.
///
/// A DIFFERENT VALUE FROM [`commitment_padded_tag`] — see that function for
/// why the two can never be unified. Everything below is why the optimized
/// vault chooses this one.
///
/// The port hashes `[pad(32, "vault:user:"), sk]` — 64 message bytes, which
/// SHA-256 splits into TWO blocks (ceil((64+9)/64) = 2). Dropping the zero
/// padding of the domain tag to its 11 significant bytes gives 43 message
/// bytes (ceil((43+9)/64) = 1 block): −1,880 rows per use, at three uses
/// (initialize's deployer gate, deposit's request path, claim's recipient
/// re-derivation), which MUST all agree since they compare the same value.
///
/// The domain tag string is UNCHANGED ("vault:user:"), so the meaning is
/// identical; only the second SHA block of zero padding is gone. This stays
/// SHA-256 deliberately: the commitment is the MPC's key-derivation PATH
/// (Signet.compact:78-85), so a curve-independent hash is required — a
/// Poseidon variant would strand funds at the old derived EVM account
/// (notes/vault-optimization.org §"Q4"). The optimized vault's identity
/// commitments differ from the port's, which is correct: it is a separate
/// deployment whose MPC config carries this one-block layout.
///
/// | byte(s) | 0..10          | 11..42 |
/// |---------|----------------|--------|
/// | content | "vault:user:"  | sk[32] |
pub fn commitment_packed_tag(c: &mut Circuit3, sk: &SecretKey<Private>) -> UserCommitment<Private> {
    let sk = sk.bytes();
    c.region("identity commitment", |c| {
        let tag = c.constant(
            minocrab::Fr::from_le_bytes(super::erc20_vault::USER_PAD.as_bytes())
                .expect("the 11-byte domain tag fits one field limb"),
        );
        let alignment = Alignment(vec![
            AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 11 }),
            AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
        ]);
        let digest = c.persistent_hash(
            alignment,
            &[tag.private().erase(), sk.hi.erase(), sk.lo.erase()],
        );
        UserCommitment(B32::from_typed(c, digest))
    })
}

/// [`assert_deployer`] against the SHORT identity commitment
/// ([`commitment_packed_tag`]) — the optimized initialize's deployer gate.
pub fn assert_deployer_short<V: Visibility + Copy>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    deployer_field: u8,
) {
    let sk = witness_sk(c);
    let digest = commitment_packed_tag(c, &sk).bytes();
    let stored = cell_read(
        c,
        guard,
        deployer_field,
        vec![AlignmentAtom::Bytes { length: 32 }],
    );
    let eq_hi = c.test_eq(digest.hi, stored[0]);
    let eq_lo = c.test_eq(digest.lo, stored[1]);
    let both = c.mul(eq_hi, eq_lo);
    c.assert(both);
}

/// Witness a secret key (`witness …SecretKey(): Bytes<32>`), input-constrained.
/// The ONLY [`SecretKey`] constructor.
pub fn witness_sk(c: &mut Circuit3) -> SecretKey<Private> {
    let sk = B32 {
        hi: c.witness::<FieldT>(),
        lo: c.witness::<FieldT>(),
    };
    sk.constrain_input(c);
    SecretKey(sk)
}

/// `right<ZswapCoinPublicKey, ContractAddress>(kernel.self())` — a fresh
/// kernel.self read packaged as a coin recipient (`is_left` = 0, the
/// unused left arm `default<ZswapCoinPublicKey>`).
fn self_recipient(c: &mut Circuit3, guard: Wire3<FieldT, Public>) -> CoinRecipient<Public> {
    let me = kernel::self_address_under(c, guard);
    contract_recipient(c, me)
}

/// [`self_recipient`] against an address the caller already read.
fn contract_recipient(c: &mut Circuit3, me: ContractAddress<Public>) -> CoinRecipient<Public> {
    let zero = c.constant(0u64);
    CoinRecipient {
        is_left: zero,
        left: minocrab_std::v3::ZswapCoinPublicKey(B32 { hi: zero, lo: zero }),
        right: me,
    }
}

fn b32_value(b: &B32<Public>) -> LedgerValue {
    LedgerValue::bytes(32, vec![ImpactElem::Wire(b.hi), ImpactElem::Wire(b.lo)])
}

/// The stdlib's `receiveShielded(coin)` (standard-library.compact:152-156):
/// `recipient = right(kernel.self());` `createZswapOutput(coin, recipient)`
/// (a Void witness — off-circuit only, nothing emitted);
/// `kernel.claimZswapCoinReceive(coinCommitment(coin, recipient))`.
pub fn receive_shielded(
    c: &mut Circuit3,
    guard: Wire3<FieldT, Public>,
    coin: &ShieldedCoinInfo3<Public>,
) {
    c.region("coin: receive", |c| {
        let recipient = self_recipient(c, guard);
        claim_receive(c, guard, coin, &recipient);
    });
}

/// `kernel.claimZswapCoinReceive(coinCommitment(coin, recipient))`.
fn claim_receive(
    c: &mut Circuit3,
    guard: Wire3<FieldT, Public>,
    coin: &ShieldedCoinInfo3<Public>,
    recipient: &CoinRecipient<Public>,
) {
    let cm = coin_commitment(c, coin, recipient);
    emit(c, guard, &kernel_claim_zswap_coin_receive(&b32_value(&cm)));
}

/// `<field>.writeCoin(coin, right(kernel.self()))` on a top-level
/// `Cell<QualifiedShieldedCoinInfo>`: a fresh kernel.self read, the
/// runtime coin commitment (`rt-coin-commit`, the same coinCommitment
/// preimage), and the writeCoin op sequence resolving the Merkle-tree
/// index on chain.
pub fn write_coin_to_self(
    c: &mut Circuit3,
    guard: Wire3<FieldT, Public>,
    field: u8,
    coin: &ShieldedCoinInfo3<Public>,
) {
    c.region("coin: write", |c| {
        let recipient = self_recipient(c, guard);
        let cm = coin_commitment(c, coin, &recipient);
        let coin_val = LedgerValue::new(
            vec![
                AlignmentAtom::Bytes { length: 32 },
                AlignmentAtom::Bytes { length: 32 },
                AlignmentAtom::Bytes { length: 16 },
            ],
            vec![
                ImpactElem::Wire(coin.nonce.bytes().hi),
                ImpactElem::Wire(coin.nonce.bytes().lo),
                ImpactElem::Wire(coin.color.bytes().hi),
                ImpactElem::Wire(coin.color.bytes().lo),
                ImpactElem::Wire(coin.value),
            ],
        );
        emit(c, guard, &cell_write_coin(field, &b32_value(&cm), &coin_val));
    });
}

/// `Cell<Secp256k1Point>.read()` of a top-level field: the gate is a
/// single typed `public_input`, whose `encode` limbs the uncached popeq
/// embeds (claim.zkir:29-33 — the mpcResponseKey read).
pub fn cell_read_point<V: Visibility + Copy>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    index: u8,
) -> Wire3<Secp256k1PointT, Public> {
    let point = c.public_transcript_input::<Secp256k1PointT>();
    let limbs = c.encode(point);
    let value = LedgerValue::new(
        secp256k1_point_atoms(),
        limbs.iter().map(|&w| ImpactElem::Wire(w)).collect(),
    );
    emit(
        c,
        guard,
        &[dup(0), idx_field(index), popeq(false, &value)],
    );
    point
}

/// The stdlib's full `mintShieldedToken(domain_sep, value, nonce,
/// recipient)` with a DYNAMIC recipient (claim.zkir:433-495): `color =
/// tokenType(domain_sep, kernel.self())`; `kernel.mintShielded(domain_sep,
/// value)`; `cm = coinCommitment({nonce, color, value}, recipient)`;
/// `kernel.claimZswapCoinSpend(cm)`; and the auto-receive branch — a
/// kernel.self read guarded by `!recipient.is_left`, the receive claim
/// guarded by `!is_left && recipient.right == self`. (mint_tokens keeps
/// its own constant-folded copy: compactc folds the branch away when the
/// recipient is a static `left`, and a constant-false-guarded op stream
/// would break PI equality there.)
pub fn mint_shielded_token(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    domain_sep: &TokenDomainSeparator<Public>,
    value: Uint<64, Public>,
    nonce: &CoinNonce<Public>,
    recipient: &CoinRecipient<Public>,
) {
    c.region("coin: mint", |c| {
        // color = tokenType(domain_sep, kernel.self())
        let me = kernel::self_address(c).bytes();
        let color = token_type(c, domain_sep, &me);

        // kernel.mintShielded(domain_sep, value)
        let ds_val = b32_value(&domain_sep.bytes());
        let amount_val = LedgerValue::bytes(8, vec![ImpactElem::Wire(value.field())]);
        emit(c, one, &kernel_mint_shielded(&ds_val, &amount_val));

        // cm = coinCommitment({nonce, color, value}, recipient)
        let coin = ShieldedCoinInfo3 {
            nonce: *nonce,
            color,
            value: value.field(),
        };
        let cm = coin_commitment(c, &coin, recipient);
        let cm_val = b32_value(&cm);

        // kernel.claimZswapCoinSpend(cm)
        emit(c, one, &kernel_claim_zswap_coin_spend(&cm_val));

        // Auto-receive when minting to this contract itself.
        let not_left = c.not(recipient.is_left);
        let self2 = kernel::self_address_guarded(c, not_left).or_default().bytes();
        let eq_hi = c.test_eq(recipient.right.bytes().hi, self2.hi);
        let eq_lo = c.test_eq(recipient.right.bytes().lo, self2.lo);
        let eq = c.mul(eq_hi, eq_lo);
        let receive = c.mul(not_left, eq);
        emit(c, receive, &kernel_claim_zswap_coin_receive(&cm_val));
    });
}

/// A full-value burn that CLAIMS A NULLIFIER: the contract spends a coin it
/// owns, so the spend is authorised by nullifying it.
///
/// The other burn is [`burn_spend`], and the difference is protocol rather
/// than cost — it emits a spend claim without nullifying, and its
/// well-formedness had to be proved against the pinned ledger before it could
/// be used (`tests/erc20_vault_opt_burn_wellformed.rs`). Neither is a cheaper
/// spelling of the other and they are not interchangeable.
///
/// `sendImmediateShielded(coin, shieldedBurnAddress(), coin.value)` as
/// compactc folds it for a full-value burn (withdraw.zkir:185-209): the
/// change is identically zero and the burn recipient is a static
/// `left(default)`, so only the spend path remains — a kernel.self read,
/// the nullifier claim, the nonce evolution, the output commitment to the
/// zero key, and the spend claim. (`createZswapInput`/`Output` are Void
/// witness natives — off-circuit only.)
pub fn burn_coin(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    coin: &ShieldedCoinInfo3<Public>,
) {
    c.region("coin: burn", |c| {
        // const selfAddr = kernel.self(); claimZswapNullifier(coinNullifier(...))
        let me = kernel::self_address(c);
        burn_body(c, one, me, coin);
    });
}

/// Everything [`burn_coin`] does after reading `kernel.self()`.
fn burn_body(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    me: ContractAddress<Public>,
    coin: &ShieldedCoinInfo3<Public>,
) {
    {
        let nul = coin_nullifier_contract(c, coin, &me.bytes());
        emit(c, one, &kernel_claim_zswap_nullifier(&b32_value(&nul)));

        // nonce' = upgradeFromTransient(transientHash([
        //   "midnight:kernel:nonce_evolve" as Field, degradeToTransient(nonce)
        // ])) — degrade takes the low limb; upgrade is [hi: 0, lo: mod 2^248].
        let tag = c.constant(
            minocrab::Fr::from_le_bytes(b"midnight:kernel:nonce_evolve").expect("28 bytes fit"),
        );
        let evolved = c.transient_hash(&[tag, coin.nonce.bytes().lo]);
        let (_overflow, lo) = c.div_mod_power_of_two(evolved, 248);
        let zero = c.constant(0u64);
        let output = ShieldedCoinInfo3 {
            nonce: CoinNonce(B32 { hi: zero, lo }),
            color: coin.color,
            value: coin.value,
        };

        // cm = coinCommitment(output, shieldedBurnAddress()) — left(default).
        let burn = CoinRecipient {
            is_left: one,
            left: minocrab_std::v3::ZswapCoinPublicKey(B32 { hi: zero, lo: zero }),
            right: ContractAddress(B32 { hi: zero, lo: zero }),
        };
        let cm = coin_commitment(c, &output, &burn);
        emit(c, one, &kernel_claim_zswap_coin_spend(&b32_value(&cm)));
    }
}

/// The OPTIMIZED burn (M10 rung vi, avenue 6): the surrendered coin is
/// destroyed by a SINGLE claimed shielded spend of the burn-address output —
/// no `receiveShielded` custody claim and no nullifier. The user funds the
/// burn Output directly (`createZswapOutput(coin, shieldedBurnAddress())`, a
/// Void witness — off-circuit — with NO `createZswapInput` preceding it), and
/// the vault claims exactly that output's commitment as its spend. A claimed
/// shielded spend needs only "the commitment exists in this segment's offer,
/// unclaimed by another contract" (verify.rs:1559,1596-1608); the receive and
/// nullifier equalities are satisfied vacuously because `shieldedBurnAddress()`
/// is `left(default)` = `Recipient::User` (contract_address None), so the burn
/// output/input are not contract-associated. Value destruction is enforced by
/// the offer's Pedersen balance plus this circuit's colour/value constraints;
/// replay is the global `CommitmentAlreadyPresent` (the same gate as before,
/// now the only one). Well-formedness of exactly this shape against the pinned
/// ledger is proven in tests/erc20_vault_opt_burn_wellformed.rs.
///
/// A full-value burn as ONE CLAIMED SPEND, with no nullifier claim and no
/// `kernel.self()` read — the burn recipient is `left(default)` rather than
/// self, so there is no owned coin to nullify. See [`burn_coin`] for the twin
/// that does nullify, and why the two names are not a cost distinction.
///
/// The burn Output keeps the port's EVOLVED nonce (the transientHash +
/// div_mod, ~165 rows), so its commitment is byte-identical to the one the
/// compat burn already builds and the off-chain twin already constructs; only
/// the receive coinCommitment and the nullifier — two SHA-256 pair hashes,
/// ~11,280 rows — are removed. `me` is no longer read (the burn recipient is
/// `left(default)`, not `self`), so it is not a parameter.
pub fn burn_spend(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    coin: &ShieldedCoinInfo3<Public>,
) {
    c.region("coin: burn", |c| {
        // nonce' = upgradeFromTransient(transientHash([
        //   "midnight:kernel:nonce_evolve" as Field, degradeToTransient(nonce)
        // ])) — degrade takes the low limb; upgrade is [hi: 0, lo: mod 2^248].
        let tag = c.constant(
            minocrab::Fr::from_le_bytes(b"midnight:kernel:nonce_evolve").expect("28 bytes fit"),
        );
        let evolved = c.transient_hash(&[tag, coin.nonce.bytes().lo]);
        let (_overflow, lo) = c.div_mod_power_of_two(evolved, 248);
        let zero = c.constant(0u64);
        let output = ShieldedCoinInfo3 {
            nonce: CoinNonce(B32 { hi: zero, lo }),
            color: coin.color,
            value: coin.value,
        };
        // cm = coinCommitment(output, shieldedBurnAddress()) — left(default).
        let burn = CoinRecipient {
            is_left: one,
            left: minocrab_std::v3::ZswapCoinPublicKey(B32 { hi: zero, lo: zero }),
            right: ContractAddress(B32 { hi: zero, lo: zero }),
        };
        let cm = coin_commitment(c, &output, &burn);
        emit(c, one, &kernel_claim_zswap_coin_spend(&b32_value(&cm)));
    });
}

/// In-branch assert: `assert(select(guard, cond, 1))` — the condition only
/// binds when the branch is taken (completeWithdraw.zkir:300-304).
pub fn assert_if<V: minocrab_std::v3::Vis3>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    cond: Wire3<FieldT, V>,
) {
    assert_if_message(c, guard, cond, None);
}

/// [`assert_if`] with Compact's second `assert` argument (metadata — no
/// instruction; the simulator names the check when it fails).
pub fn assert_if_with<V: minocrab_std::v3::Vis3>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    cond: Wire3<FieldT, V>,
    message: &str,
) {
    assert_if_message(c, guard, cond, Some(message));
}

fn assert_if_message<V: minocrab_std::v3::Vis3>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    cond: Wire3<FieldT, V>,
    message: Option<&str>,
) {
    let one = V::from_public(c.constant(1u64));
    let gated = c.cond_select(guard, cond, one);
    c.assert_with(gated, message);
}

/// The shared body of the static-`left(pk)` mints: compactc folds the
/// recipient selects and the auto-receive branch; every effects op carries
/// `guard`.
///
/// Public as the "caller already read `kernel.self()`" form of
/// [`mint_shielded_token_to_key`]. A
/// circuit that mints twice (completeSwap) or mints on either of two
/// branches (refund) needs one read, not one per mint.
pub fn mint_shielded_token_to_key_with<G: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, G>>,
    me: ContractAddress<Public>,
    domain_sep: &TokenDomainSeparator<Public>,
    value: Uint<64, Public>,
    nonce: &CoinNonce<Public>,
    pk: &minocrab_std::v3::ZswapCoinPublicKey<Public>,
) {
    let guard = guard.into();
    c.region("coin: mint", |c| {
        let color = token_type(c, domain_sep, &me.bytes());

        let ds_val = b32_value(&domain_sep.bytes());
        let amount_val = LedgerValue::bytes(8, vec![ImpactElem::Wire(value.field())]);
        emit(c, guard, &kernel_mint_shielded(&ds_val, &amount_val));

        let one = c.constant(1u64);
        let zero = c.constant(0u64);
        let coin = ShieldedCoinInfo3 {
            nonce: *nonce,
            color,
            value: value.field(),
        };
        let left = CoinRecipient {
            is_left: one,
            left: *pk,
            right: ContractAddress(B32 { hi: zero, lo: zero }),
        };
        let cm = coin_commitment(c, &coin, &left);
        emit(c, guard, &kernel_claim_zswap_coin_spend(&b32_value(&cm)));
    });
}

/// `mintShieldedToken(domain_sep, value, nonce, left(pk))` straight-line
/// (completeSwap's two mints).
pub fn mint_shielded_token_to_key(
    c: &mut Circuit3,
    domain_sep: &TokenDomainSeparator<Public>,
    value: Uint<64, Public>,
    nonce: &CoinNonce<Public>,
    pk: &minocrab_std::v3::ZswapCoinPublicKey<Public>,
) {
    let me = kernel::self_address(c);
    mint_shielded_token_to_key_with(c, STRAIGHT_LINE, me, domain_sep, value, nonce, pk);
}

/// The one-shot gate: `assert(<counter at field> == 0)`.
pub fn assert_counter_zero<V: Visibility + Copy>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    field: u8,
) {
    let count = counter_read(c, guard, field);
    let zero = c.constant(0u64);
    let unset = c.test_eq(count, zero);
    c.assert(unset);
}

/// The deployer gate: `assert(commitment(prefix, <witnessed sk>) ==
/// <Bytes<32> cell at deployer_field>)`.
pub fn assert_deployer<V: Visibility + Copy>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    prefix: &str,
    deployer_field: u8,
) {
    let sk = witness_sk(c);
    let digest = commitment_padded_tag(c, prefix, &sk).bytes();
    let stored = cell_read(
        c,
        guard,
        deployer_field,
        vec![AlignmentAtom::Bytes { length: 32 }],
    );
    let eq_hi = c.test_eq(digest.hi, stored[0]);
    let eq_lo = c.test_eq(digest.lo, stored[1]);
    let both = c.mul(eq_hi, eq_lo);
    c.assert(both);
}
