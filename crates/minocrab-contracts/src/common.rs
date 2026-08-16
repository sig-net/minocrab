//! Shapes shared across the sig-net contracts.

use minocrab::v3::{Circuit3, FieldT, Operand, Secp256k1PointT, Wire3};
use minocrab::{Alignment, AlignmentAtom, AlignmentSegment, Private, Public, Visibility};
use minocrab_ledger::{
    cell_read, cell_write_coin, counter_read, dup, emit, idx_field, kernel_claim_zswap_coin_receive,
    kernel_claim_zswap_coin_spend, kernel_claim_zswap_nullifier, kernel_mint_shielded, kernel_self,
    kernel_self_guarded, popeq, ImpactElem, LedgerValue,
};
use minocrab_std::v3::{
    coin_commitment, coin_nullifier_contract, token_type, CircuitAbi, CoinRecipient,
    Secp256k1Point, ShieldedCoinInfo3, B32, STRAIGHT_LINE,
};

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
/// `persistentHash<Vector<2, Bytes<32>>>([pad(32, prefix), sk])`.
pub fn commitment(c: &mut Circuit3, prefix: &str, sk: &B32<Private>) -> B32<Private> {
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
        B32::from_typed(c, digest)
    })
}

/// The SHORT identity commitment (M10 rung 5(i-userCommit), avenue 1):
/// `persistentHash<[Bytes<11>, Bytes<32>]>(["vault:user:", sk])`.
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
pub fn commitment_short(c: &mut Circuit3, sk: &B32<Private>) -> B32<Private> {
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
        B32::from_typed(c, digest)
    })
}

/// [`assert_deployer`] against the SHORT identity commitment
/// ([`commitment_short`]) — the optimized initialize's deployer gate.
pub fn assert_deployer_short<V: Visibility + Copy>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    deployer_field: u8,
) {
    let sk = witness_sk(c);
    let digest = commitment_short(c, &sk);
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
    contract_recipient(c, B32 { hi: me[0], lo: me[1] })
}

/// [`self_recipient`] against an address the caller already read.
fn contract_recipient(c: &mut Circuit3, me: B32<Public>) -> CoinRecipient<Public> {
    let zero = c.constant(0u64);
    CoinRecipient {
        is_left: zero,
        left: B32 { hi: zero, lo: zero },
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

/// [`receive_shielded`] against a `kernel.self()` the caller already read.
///
/// compactc emits a fresh read per stdlib call; how many times the read is
/// EMITTED is framing, not protocol (notes/vault-optimization.org §"(b)
/// COMPACTC-FRAMING-ONLY"), and the value is invariant within a
/// transaction. The M10 artifact reads it once per circuit and threads it;
/// the direct ports keep [`receive_shielded`] and their frozen rows.
pub fn receive_shielded_with(
    c: &mut Circuit3,
    guard: Wire3<FieldT, Public>,
    me: B32<Public>,
    coin: &ShieldedCoinInfo3<Public>,
) {
    c.region("coin: receive", |c| {
        let recipient = contract_recipient(c, me);
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
                ImpactElem::Wire(coin.nonce.hi),
                ImpactElem::Wire(coin.nonce.lo),
                ImpactElem::Wire(coin.color.hi),
                ImpactElem::Wire(coin.color.lo),
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
    domain_sep: &B32<Public>,
    value: Wire3<FieldT, Public>,
    nonce: &B32<Public>,
    recipient: &CoinRecipient<Public>,
) {
    c.region("coin: mint", |c| {
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
    });
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
    c.region("coin: burn", |c| {
        // const selfAddr = kernel.self(); claimZswapNullifier(coinNullifier(...))
        let me = kernel_self(c, one);
        burn_body(c, one, B32 { hi: me[0], lo: me[1] }, coin);
    });
}

/// [`burn_coin`] against a `kernel.self()` the caller already read — see
/// [`receive_shielded_with`] for why the M10 artifact wants that.
pub fn burn_coin_with(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    me: B32<Public>,
    coin: &ShieldedCoinInfo3<Public>,
) {
    c.region("coin: burn", |c| burn_body(c, one, me, coin));
}

/// Everything [`burn_coin`] does after reading `kernel.self()`.
fn burn_body(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    me: B32<Public>,
    coin: &ShieldedCoinInfo3<Public>,
) {
    {
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
    });
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
/// [`mint_shielded_token_to_key`] — see [`receive_shielded_with`]. A
/// circuit that mints twice (completeSwap) or mints on either of two
/// branches (refund) needs one read, not one per mint.
pub fn mint_shielded_token_to_key_with<G: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, G>>,
    me: B32<Public>,
    domain_sep: &B32<Public>,
    value: Wire3<FieldT, Public>,
    nonce: &B32<Public>,
    pk: &B32<Public>,
) {
    let guard = guard.into();
    c.region("coin: mint", |c| {
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
    });
}

/// `mintShieldedToken(domain_sep, value, nonce, left(pk))` straight-line
/// (completeSwap's two mints).
pub fn mint_shielded_token_to_key(
    c: &mut Circuit3,
    domain_sep: &B32<Public>,
    value: Wire3<FieldT, Public>,
    nonce: &B32<Public>,
    pk: &B32<Public>,
) {
    let me = kernel_self(c, STRAIGHT_LINE);
    let me = B32 { hi: me[0], lo: me[1] };
    mint_shielded_token_to_key_with(c, STRAIGHT_LINE, me, domain_sep, value, nonce, pk);
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
    mint_shielded_token_to_key_with(c, guard, me, domain_sep, value, nonce, pk);
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
