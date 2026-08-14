//! Shapes shared across the sig-net contracts.

use minocrab::v3::{Circuit3, FieldT, Secp256k1PointT, Wire3};
use minocrab::{Alignment, AlignmentAtom, AlignmentSegment, Private, Public, Visibility};
use minocrab_ledger::{
    cell_read, cell_write_coin, counter_read, dup, emit, idx_field, kernel_claim_zswap_coin_receive,
    kernel_claim_zswap_coin_spend, kernel_claim_zswap_nullifier, kernel_mint_shielded, kernel_self,
    kernel_self_guarded, popeq, ImpactElem, LedgerValue,
};
use minocrab_std::v3::{
    coin_commitment, coin_nullifier_contract, token_type, CoinRecipient, ShieldedCoinInfo3, B32,
};

/// A `Secp256k1Point`'s FAB alignment: x as b24+b8, y as b24+b8, plus a
/// native field element (notes/ledger-abi.org §3) — 5 limbs, matching
/// `encode`'s output.
pub fn secp256k1_point_atoms() -> Vec<AlignmentAtom> {
    vec![
        AlignmentAtom::Bytes { length: 24 },
        AlignmentAtom::Bytes { length: 8 },
        AlignmentAtom::Bytes { length: 24 },
        AlignmentAtom::Bytes { length: 8 },
        AlignmentAtom::Field,
    ]
}

/// The identity commitment both contracts derive:
/// `persistentHash<Vector<2, Bytes<32>>>([pad(32, prefix), sk])`.
pub fn commitment(c: &mut Circuit3, prefix: &str, sk: &B32<Private>) -> B32<Private> {
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
    B32::from_typed(c, digest)
}

/// Witness a secret key (`witness …SecretKey(): Bytes<32>`), input-constrained.
pub fn witness_sk(c: &mut Circuit3) -> B32<Private> {
    let sk = B32 {
        hi: c.witness::<FieldT>(),
        lo: c.witness::<FieldT>(),
    };
    sk.constrain_input(c);
    sk
}

/// `right<ZswapCoinPublicKey, ContractAddress>(kernel.self())` — a fresh
/// kernel.self read packaged as a coin recipient (`is_left` = 0, the
/// unused left arm `default<ZswapCoinPublicKey>`).
fn self_recipient(c: &mut Circuit3, guard: Wire3<FieldT, Public>) -> CoinRecipient<Public> {
    let me = kernel_self(c, guard);
    let zero = c.constant(0u64);
    CoinRecipient {
        is_left: zero,
        left: B32 { hi: zero, lo: zero },
        right: B32 { hi: me[0], lo: me[1] },
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
    let recipient = self_recipient(c, guard);
    let cm = coin_commitment(c, coin, &recipient);
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
    let recipient = self_recipient(c, guard);
    let cm = coin_commitment(c, coin, &recipient);
    let coin_val = LedgerValue::new(
        vec![
            AlignmentAtom::Bytes { length: 32 },
            AlignmentAtom::Bytes { length: 32 },
            AlignmentAtom::Bytes { length: 16 },
        ],
        vec![
            ImpactElem::Wire(coin.nonce.hi),
            ImpactElem::Wire(coin.nonce.lo),
            ImpactElem::Wire(coin.color.hi),
            ImpactElem::Wire(coin.color.lo),
            ImpactElem::Wire(coin.value),
        ],
    );
    emit(c, guard, &cell_write_coin(field, &b32_value(&cm), &coin_val));
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
    domain_sep: &B32<Public>,
    value: Wire3<FieldT, Public>,
    nonce: &B32<Public>,
    recipient: &CoinRecipient<Public>,
) {
    // color = tokenType(domain_sep, kernel.self())
    let me = kernel_self(c, one);
    let me = B32 { hi: me[0], lo: me[1] };
    let color = token_type(c, domain_sep, &me);

    // kernel.mintShielded(domain_sep, value)
    let ds_val = b32_value(domain_sep);
    let amount_val = LedgerValue::bytes(8, vec![ImpactElem::Wire(value)]);
    emit(c, one, &kernel_mint_shielded(&ds_val, &amount_val));

    // cm = coinCommitment({nonce, color, value}, recipient)
    let coin = ShieldedCoinInfo3 {
        nonce: *nonce,
        color,
        value,
    };
    let cm = coin_commitment(c, &coin, recipient);
    let cm_val = b32_value(&cm);

    // kernel.claimZswapCoinSpend(cm)
    emit(c, one, &kernel_claim_zswap_coin_spend(&cm_val));

    // Auto-receive when minting to this contract itself.
    let not_left = c.not(recipient.is_left);
    let self2 = kernel_self_guarded(c, not_left);
    let eq_hi = c.test_eq(recipient.right.hi, self2[0]);
    let eq_lo = c.test_eq(recipient.right.lo, self2[1]);
    let eq = c.mul(eq_hi, eq_lo);
    let receive = c.mul(not_left, eq);
    emit(c, receive, &kernel_claim_zswap_coin_receive(&cm_val));
}

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
    // const selfAddr = kernel.self(); claimZswapNullifier(coinNullifier(...))
    let me = kernel_self(c, one);
    let me = B32 { hi: me[0], lo: me[1] };
    let nul = coin_nullifier_contract(c, coin, &me);
    emit(c, one, &kernel_claim_zswap_nullifier(&b32_value(&nul)));

    // nonce' = upgradeFromTransient(transientHash([
    //   "midnight:kernel:nonce_evolve" as Field, degradeToTransient(nonce)
    // ])) — degrade takes the low limb; upgrade is [hi: 0, lo: mod 2^248].
    let tag = c.constant(
        minocrab::Fr::from_le_bytes(b"midnight:kernel:nonce_evolve").expect("28 bytes fit"),
    );
    let evolved = c.transient_hash(&[tag, coin.nonce.lo]);
    let (_overflow, lo) = c.div_mod_power_of_two(evolved, 248);
    let zero = c.constant(0u64);
    let output = ShieldedCoinInfo3 {
        nonce: B32 { hi: zero, lo },
        color: coin.color,
        value: coin.value,
    };

    // cm = coinCommitment(output, shieldedBurnAddress()) — left(default).
    let burn = CoinRecipient {
        is_left: one,
        left: B32 { hi: zero, lo: zero },
        right: B32 { hi: zero, lo: zero },
    };
    let cm = coin_commitment(c, &output, &burn);
    emit(c, one, &kernel_claim_zswap_coin_spend(&b32_value(&cm)));
}

/// [`witness_sk`] under a branch guard.
pub fn witness_sk_guarded(
    c: &mut Circuit3,
    guard: Wire3<FieldT, Public>,
) -> B32<Private> {
    let sk = B32 {
        hi: c.witness_guarded::<FieldT, Public>(guard),
        lo: c.witness_guarded::<FieldT, Public>(guard),
    };
    sk.constrain_input(c);
    sk
}

/// In-branch assert: `assert(select(guard, cond, 1))` — the condition only
/// binds when the branch is taken (completeWithdraw.zkir:300-304).
pub fn assert_if<V: minocrab_std::v3::Vis3>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    cond: Wire3<FieldT, V>,
) {
    let one = V::from_public(c.constant(1u64));
    let gated = c.cond_select(guard, cond, one);
    c.assert(gated);
}

/// The shared body of the static-`left(pk)` mints: compactc folds the
/// recipient selects and the auto-receive branch; every effects op carries
/// `guard`.
fn mint_to_key_body(
    c: &mut Circuit3,
    guard: Wire3<FieldT, Public>,
    me: B32<Public>,
    domain_sep: &B32<Public>,
    value: Wire3<FieldT, Public>,
    nonce: &B32<Public>,
    pk: &B32<Public>,
) {
    let color = token_type(c, domain_sep, &me);

    let ds_val = b32_value(domain_sep);
    let amount_val = LedgerValue::bytes(8, vec![ImpactElem::Wire(value)]);
    emit(c, guard, &kernel_mint_shielded(&ds_val, &amount_val));

    let one = c.constant(1u64);
    let zero = c.constant(0u64);
    let coin = ShieldedCoinInfo3 {
        nonce: *nonce,
        color,
        value,
    };
    let left = CoinRecipient {
        is_left: one,
        left: *pk,
        right: B32 { hi: zero, lo: zero },
    };
    let cm = coin_commitment(c, &coin, &left);
    emit(c, guard, &kernel_claim_zswap_coin_spend(&b32_value(&cm)));
}

/// `mintShieldedToken(domain_sep, value, nonce, left(pk))` straight-line
/// (completeSwap's two mints).
pub fn mint_shielded_token_to_key(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    domain_sep: &B32<Public>,
    value: Wire3<FieldT, Public>,
    nonce: &B32<Public>,
    pk: &B32<Public>,
) {
    let me = kernel_self(c, one);
    let me = B32 { hi: me[0], lo: me[1] };
    mint_to_key_body(c, one, me, domain_sep, value, nonce, pk);
}

/// `mintShieldedToken(domain_sep, value, nonce, left(pk))` under a branch
/// guard (completeWithdraw.zkir:482-512): the kernel.self read and every
/// effects op carry the guard.
pub fn mint_shielded_token_to_key_guarded(
    c: &mut Circuit3,
    guard: Wire3<FieldT, Public>,
    domain_sep: &B32<Public>,
    value: Wire3<FieldT, Public>,
    nonce: &B32<Public>,
    pk: &B32<Public>,
) {
    let me = kernel_self_guarded(c, guard);
    let me = B32 { hi: me[0], lo: me[1] };
    mint_to_key_body(c, guard, me, domain_sep, value, nonce, pk);
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
    let digest = commitment(c, prefix, &sk);
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
