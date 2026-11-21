//! Compact's standard-library circuits over `kernel`
//! (`standard-library.compact:113-350`), transcribed as compactc inlines
//! them.
//!
//! WHAT IS COMPACTC'S: `!b` is `cond_select(b, 0, 1)` and `a && b` is
//! `cond_select(a, b, 0)`, never the `not` instruction or a `mul`; a guard
//! passed in explicitly is resolved against the ambient scope once PER
//! OP, not once on entering a scope; and `sendShielded` hashes the sent
//! coin's commitment twice, once per `coinCommitment` call in the Compact
//! source. THE LEAN FORM is `Circuit::not`, a `mul`, one `when` scope, and
//! one commitment reused (each repeated commitment is about 5,640 rows,
//! notes/vault-optimization.org).
//!
//! The kernel PRIMITIVES these compose (`kernel.self()`, the claims, the
//! balance reads) are the ledger's own and stay in
//! [`minocrab_std::kernel`]; only the compositions live here. Each
//! function carries the Compact it is a port of, and its body stays as
//! close to it as Rust allows, so it can be checked against the source
//! line by line.

use minocrab::{AnyWire, Circuit, FieldT, Wire};
use minocrab::{AlignmentAtom, Fr, Public};
use minocrab_ledger::{ImpactElem, LedgerValue};
use minocrab_std::kernel::{
    balance, balance_greater_than, balance_less_than, block_time_greater_than,
    block_time_less_than, claim_unshielded_coin_spend, claim_zswap_coin_receive,
    claim_zswap_coin_spend, claim_zswap_nullifier, inc_unshielded_inputs, inc_unshielded_outputs,
    mint_unshielded, self_address, unshielded, UnshieldedRecipient,
};
use minocrab_std::{
    coin_commitment_to, coin_commitment_to_contract, coin_nullifier_contract, hash, is_true,
    token_type, Assumed, Bool, CoinColor, CoinNonce, CoinRecipient, LedgerRepr, Maybe,
    QualifiedShieldedCoinInfo, ShieldedCoinInfo, ShieldedSendResult, TokenDomainSeparator,
    Uint, B32,
};

// ---- the stdlib circuits ----------------------------------------------------
//
// standard-library.compact:275-350, transcribed. Each is a composition of the
// kernel primitives and nothing else.

/// `circuit blockTimeLt(time): Boolean { return kernel.blockTimeLessThan(time); }`
///
/// The primitive itself; here so a port reads every stdlib name from one place.
pub fn block_time_lt(c: &mut Circuit, time: Uint<64, Public>) -> Assumed<Bool<Public>> {
    block_time_less_than(c, time)
}

/// `circuit blockTimeGte(time): Boolean { return !blockTimeLt(time); }`
///
/// compactc's `!` (see `not`); the lean form negates with `Circuit::not`.
pub fn block_time_gte(c: &mut Circuit, time: Uint<64, Public>) -> Assumed<Bool<Public>> {
    let lt = block_time_lt(c, time);
    Assumed::of_read(not(c, *lt))
}

/// `circuit blockTimeGt(time): Boolean { return kernel.blockTimeGreaterThan(time); }`
///
/// The primitive itself; here so a port reads every stdlib name from one place.
pub fn block_time_gt(c: &mut Circuit, time: Uint<64, Public>) -> Assumed<Bool<Public>> {
    block_time_greater_than(c, time)
}

/// `circuit blockTimeLte(time): Boolean { return !blockTimeGt(time); }`
///
/// compactc's `!` (see `not`); the lean form negates with `Circuit::not`.
pub fn block_time_lte(c: &mut Circuit, time: Uint<64, Public>) -> Assumed<Bool<Public>> {
    let gt = block_time_gt(c, time);
    Assumed::of_read(not(c, *gt))
}

/// Compact's `!b` on a Boolean, which compactc lowers to
/// `cond_select(b, 0, 1)` (one row) where the lean form is the `not`
/// instruction — the shape the fixture's `sBlockTimeGte` shows.
fn not(c: &mut Circuit, b: Bool<Public>) -> Bool<Public> {
    Bool::from_field_unchecked(c.cond_select(b.field(), 0u64, 1u64))
}

/// `circuit unshieldedBalance(color): Uint<128>`
///
/// The primitive over `left(color)`; here so a port reads every stdlib name
/// from one place.
pub fn unshielded_balance(c: &mut Circuit, color: CoinColor<Public>) -> Assumed<Uint<128, Public>> {
    let token = unshielded(c, color);
    balance(c, &token)
}

/// `circuit unshieldedBalanceLt(color, amount): Boolean`
///
/// The primitive over `left(color)`; here so a port reads every stdlib name
/// from one place.
pub fn unshielded_balance_lt(
    c: &mut Circuit,
    color: CoinColor<Public>,
    amount: Uint<128, Public>,
) -> Assumed<Bool<Public>> {
    let token = unshielded(c, color);
    balance_less_than(c, &token, amount)
}

/// `circuit unshieldedBalanceGte(color, amount): Boolean { return !…Lt(…); }`
///
/// compactc's `!` (see `not`); the lean form negates with `Circuit::not`.
pub fn unshielded_balance_gte(
    c: &mut Circuit,
    color: CoinColor<Public>,
    amount: Uint<128, Public>,
) -> Assumed<Bool<Public>> {
    let lt = unshielded_balance_lt(c, color, amount);
    Assumed::of_read(not(c, *lt))
}

/// `circuit unshieldedBalanceGt(color, amount): Boolean`
///
/// The primitive over `left(color)`; here so a port reads every stdlib name
/// from one place.
pub fn unshielded_balance_gt(
    c: &mut Circuit,
    color: CoinColor<Public>,
    amount: Uint<128, Public>,
) -> Assumed<Bool<Public>> {
    let token = unshielded(c, color);
    balance_greater_than(c, &token, amount)
}

/// `circuit unshieldedBalanceLte(color, amount): Boolean { return !…Gt(…); }`
///
/// compactc's `!` (see `not`); the lean form negates with `Circuit::not`.
pub fn unshielded_balance_lte(
    c: &mut Circuit,
    color: CoinColor<Public>,
    amount: Uint<128, Public>,
) -> Assumed<Bool<Public>> {
    let gt = unshielded_balance_gt(c, color, amount);
    Assumed::of_read(not(c, *gt))
}

/// ```text
/// circuit receiveUnshielded(color, amount): [] {
///   kernel.incUnshieldedInputs(left<Bytes<32>, Bytes<32>>(color), amount);
/// }
/// ```
///
/// One effect; here so a port reads every stdlib name from one place.
pub fn receive_unshielded(c: &mut Circuit, color: CoinColor<Public>, amount: Uint<128, Public>) {
    let token = unshielded(c, color);
    inc_unshielded_inputs(c, &token, amount);
}

/// `recipient.is_left && recipient.left.bytes == kernel.self().bytes` — the
/// AUTO-RECEIVE guard both [`send_unshielded`] and [`mint_unshielded_token`]
/// end with.
///
/// compactc's: the `kernel.self()` read is guarded by `is_left` ALONE (a
/// user recipient never needs the address, so its `public_input` gates
/// yield the default), and both `&&`s are `cond_select`s, where the lean
/// form is a `mul` for each.
fn is_self(c: &mut Circuit, recipient: &UnshieldedRecipient<Public>) -> Wire<FieldT, Public> {
    let is_left = recipient.is_left.field();
    let me = guarded_kernel_self(c, is_left);
    let me = never_stale(c, me);
    let left = recipient.left.bytes();
    let eq_hi = c.test_eq(left.hi, me[0]);
    let eq_lo = c.test_eq(left.lo, me[1]);
    let both = c.cond_select(eq_hi, eq_lo, 0u64);
    c.cond_select(is_left, both, 0u64)
}

/// The kernel's self read is a `popeq` on a value no transaction can change,
/// so it is acknowledged at the read and never wears `Assumed` (M42 B).
/// The same two lines as `minocrab_std::kernel`'s private helper.
fn never_stale(c: &mut Circuit, wires: [Wire<FieldT, Public>; 2]) -> [Wire<FieldT, Public>; 2] {
    c.acknowledge_stale(&[wires[0].val(), wires[1].val()]);
    wires
}

/// [`minocrab_ledger::kernel_self`], guarded by an EXPLICIT wire rather than
/// the ambient scope.
///
/// compactc's: the explicit guard is conjoined with the ambient one PER
/// EFFECT (once per read and once per Impact op), which is what the corpus
/// shows when these circuits are called inside another `when` (e.g.
/// `manager.compact`'s `execute`). The lean form is
/// `c.when(is_left, |c| kernel_self(c)).or_default()`, which conjoins once on
/// entry and so emits fewer rows.
fn guarded_kernel_self(c: &mut Circuit, guard: Wire<FieldT, Public>) -> [Wire<FieldT, Public>; 2] {
    let atoms = vec![AlignmentAtom::Bytes { length: 32 }];
    let limbs: usize = atoms.iter().map(minocrab_ledger::atom_limbs).sum();
    let wires: Vec<Wire<FieldT, Public>> = (0..limbs)
        .map(|_| c.public_transcript_input_guarded::<FieldT, Public>(guard))
        .collect();
    let value = LedgerValue::new(atoms, wires.iter().map(|&w| ImpactElem::Wire(w)).collect());
    for op in [
        minocrab_ledger::dup(2),
        minocrab_ledger::idx_one(true, false, 0),
        minocrab_ledger::popeq(true, &value),
    ] {
        c.impact_mixed(guard, &op.0);
    }
    [wires[0], wires[1]]
}

/// Emit `ops` under an EXPLICIT guard, resolved against the ambient scope
/// PER OP ([`Circuit::impact_mixed`] once per op) — compactc's, for the
/// reason [`guarded_kernel_self`] gives; the lean form is one `c.when`.
fn emit_guarded(c: &mut Circuit, guard: Wire<FieldT, Public>, ops: &[minocrab_ledger::ImpactOp]) {
    for op in ops {
        c.impact_mixed(guard, &op.0);
    }
}

/// ```text
/// circuit sendUnshielded(color, amount, recipient): [] {
///   kernel.incUnshieldedOutputs(left<Bytes<32>, Bytes<32>>(color), amount);
///   kernel.claimUnshieldedCoinSpend(left<Bytes<32>, Bytes<32>>(color), recipient, amount);
///   // Auto-receive when sending to self
///   if (recipient.is_left && recipient.left.bytes == kernel.self().bytes) {
///     kernel.incUnshieldedInputs(left<Bytes<32>, Bytes<32>>(color), amount);
///   }
/// }
/// ```
///
/// compactc's in the auto-receive guard (`is_self`) and its per-op
/// resolution (`emit_guarded`).
pub fn send_unshielded(
    c: &mut Circuit,
    color: CoinColor<Public>,
    amount: Uint<128, Public>,
    recipient: &UnshieldedRecipient<Public>,
) {
    let token = unshielded(c, color);
    inc_unshielded_outputs(c, &token, amount);
    claim_unshielded_coin_spend(c, &token, recipient, amount);
    let mine = is_self(c, recipient);
    let t = token.ledger_value();
    let amt = amount.ledger_value(c);
    emit_guarded(c, mine, &minocrab_ledger::kernel_inc_unshielded_inputs(&t, &amt));
}

/// ```text
/// circuit mintUnshieldedToken(domainSep, amount, recipient): Bytes<32> {
///   kernel.mintUnshielded(domainSep, amount);
///   const color = tokenType(domainSep, kernel.self());
///   kernel.claimUnshieldedCoinSpend(left<Bytes<32>, Bytes<32>>(color), recipient, amount);
///   // Auto-receive when minting to self
///   if (recipient.is_left && recipient.left.bytes == kernel.self().bytes) {
///     kernel.incUnshieldedInputs(left<Bytes<32>, Bytes<32>>(color), amount);
///   }
///   return color;
/// }
/// ```
///
/// compactc's as [`send_unshielded`] is, plus the second `kernel.self()`
/// read the source makes (the lean form reads it once). The amount is a
/// `Uint<64>` at the mint and a `Uint<128>` at the claim; Compact widens
/// it, and so does this.
pub fn mint_unshielded_token(
    c: &mut Circuit,
    domain_sep: &TokenDomainSeparator<Public>,
    amount: Uint<64, Public>,
    recipient: &UnshieldedRecipient<Public>,
) -> CoinColor<Public> {
    mint_unshielded(c, domain_sep, amount);
    let me = self_address(c);
    let color = token_type(c, domain_sep, &me.bytes());
    let token = unshielded(c, color);
    let wide = Uint::<128, Public>::from_field_unchecked(amount.field());
    claim_unshielded_coin_spend(c, &token, recipient, wide);
    let mine = is_self(c, recipient);
    let t = token.ledger_value();
    let amt = wide.ledger_value(c);
    emit_guarded(c, mine, &minocrab_ledger::kernel_inc_unshielded_inputs(&t, &amt));
    color
}

// ---- the SHIELDED half ------------------------------------------------------
//
// Two shapes recur, and both are compactc's: a coin paid to THIS contract is
// `right(kernel.self())`, a literal, so its commitment has no recipient
// select (`coin_commitment_to_contract`); and
// `upgradeFromTransient(transientHash([<tag>, degradeToTransient(nonce)]))` is
// how every derived nonce is made, the tag inline and the two `Copy`s the
// casts (`hash::degrade_to_transient`).

/// The domain a coin's successor nonce is derived under, and the `/2` variant
/// `sendShielded` gives its CHANGE coin.
const NONCE_EVOLVE: &[u8] = b"midnight:kernel:nonce_evolve";
const NONCE_EVOLVE_CHANGE: &[u8] = b"midnight:kernel:nonce_evolve/2";

/// A `bytes<n>` (n ≤ 31) literal as a single constant limb, the INLINE hash
/// operand compactc writes (the same as `minocrab_std`'s private helper).
fn short_literal_imm(bytes: &[u8]) -> Fr {
    assert!(bytes.len() <= 31);
    Fr::from_le_bytes(bytes).expect("≤31 bytes fit")
}

/// `upgradeFromTransient(transientHash<Vector<2, Field>>([<domain> as Field,
/// degradeToTransient(nonce)]))` — the nonce of a coin derived from another,
/// in the two-element form `sendShielded` and `mergeCoin` write inline.
fn derived_nonce(c: &mut Circuit, domain: &[u8], nonce: &CoinNonce<Public>) -> CoinNonce<Public> {
    let degraded = hash::degrade_to_transient(c, &nonce.bytes());
    let h = c.transient_hash(&[AnyWire::immediate(short_literal_imm(domain)), degraded.erase()]);
    CoinNonce(hash::upgrade_from_transient(c, h))
}

/// `a == b` on `Bytes<32>`, as compactc lowers it: a `test_eq` per limb and
/// a `cond_select` for the `&&`, where the lean form (`B32::eq`) is a `mul`.
fn bytes_eq(c: &mut Circuit, a: &B32<Public>, b: &B32<Public>) -> Wire<FieldT, Public> {
    let hi = c.test_eq(a.hi, b.hi);
    let lo = c.test_eq(a.lo, b.lo);
    c.cond_select(hi, lo, 0u64)
}

/// Compact's `a - b` on a `Uint<128>`: the difference, and the assertion that
/// there is one. compactc's: the underflow test negated by a `cond_select`
/// ([`not`]) before it is asserted; the lean form asserts the comparison
/// with no select.
fn checked_sub(c: &mut Circuit, a: Wire<FieldT, Public>, b: Wire<FieldT, Public>) -> Wire<FieldT, Public> {
    let underflow = c.less_than(a, b, 128);
    let ok = not(c, Bool::from_field_unchecked(underflow));
    c.assert(is_true(ok).message("subtraction would underflow"));
    let neg = c.neg(b);
    c.add(a, neg)
}

/// Compact's `x as Uint<128>` on a value just computed: the range constraint,
/// then the `Copy` the cast names its result with. The `Copy` is compactc's
/// (it costs no rows); the lean form names the checked wire itself.
fn as_uint128(c: &mut Circuit, w: Wire<FieldT, Public>) -> Wire<FieldT, Public> {
    // Inside a `when` the checked value is the selected one; that is the
    // value the cast names and everything downstream (the commitment, the
    // ledger op) consumes — compactc's branch semantics, and what keeps the
    // hash preimage provably bounded for the taint lint.
    let checked = Uint::<128, Public>::from_field_checked(c, w);
    c.copy(checked.field())
}

/// ```text
/// circuit mergeCoin(a: QualifiedShieldedCoinInfo, b: QualifiedShieldedCoinInfo): ShieldedCoinInfo {
///   const selfAddr = kernel.self();
///   createZswapInput(a);
///   kernel.claimZswapNullifier(coinNullifier(downcastQualifiedCoin(a), selfAddr));
///   createZswapInput(b);
///   kernel.claimZswapNullifier(coinNullifier(downcastQualifiedCoin(b), selfAddr));
///   assert(a.color == b.color, "Can only merge coins of the same color");
///   const newCoin = ShieldedCoinInfo{
///     nonce: upgradeFromTransient(transientHash<Vector<2, Field>>([
///              "midnight:kernel:nonce_evolve" as Field, degradeToTransient(a.nonce)])),
///     color: a.color,
///     value: (a.value + b.value) as Uint<128>
///   };
///   createZswapOutput(newCoin, right<ZswapCoinPublicKey, ContractAddress>(selfAddr));
///   const cm = coinCommitment(newCoin, right<ZswapCoinPublicKey, ContractAddress>(selfAddr));
///   kernel.claimZswapCoinSpend(cm);
///   kernel.claimZswapCoinReceive(cm);
///   return newCoin;
/// }
/// ```
///
/// compactc's in the colour test (`bytes_eq`) and the cast's `Copy`
/// (`as_uint128`). `createZswapInput` / `createZswapOutput` are Void
/// witness natives and emit nothing here.
pub fn merge_coin(
    c: &mut Circuit,
    a: &QualifiedShieldedCoinInfo<Public>,
    b: &QualifiedShieldedCoinInfo<Public>,
) -> ShieldedCoinInfo<Public> {
    merge(c, &a.downcast(), &b.downcast())
}

/// ```text
/// circuit mergeCoinImmediate(a: QualifiedShieldedCoinInfo, b: ShieldedCoinInfo): ShieldedCoinInfo {
///   return mergeCoin(a, upcastQualifiedCoin(b));
/// }
/// ```
///
/// [`merge_coin`]'s body against `b` directly: `upcastQualifiedCoin`'s
/// `mt_index: 0` is never read, and compactc's `sMergeCoinImmediate` is
/// `sMergeCoin` minus `b`'s `mt_index` constraint, instruction for
/// instruction.
pub fn merge_coin_immediate(
    c: &mut Circuit,
    a: &QualifiedShieldedCoinInfo<Public>,
    b: &ShieldedCoinInfo<Public>,
) -> ShieldedCoinInfo<Public> {
    merge(c, &a.downcast(), b)
}

/// Everything both merges do, once the coins are downcast.
fn merge(c: &mut Circuit, a: &ShieldedCoinInfo<Public>, b: &ShieldedCoinInfo<Public>) -> ShieldedCoinInfo<Public> {
    let me = self_address(c).bytes();
    let nul_a = coin_nullifier_contract(c, a, &me);
    claim_zswap_nullifier(c, &nul_a);
    let nul_b = coin_nullifier_contract(c, b, &me);
    claim_zswap_nullifier(c, &nul_b);

    let same_colour = bytes_eq(c, &a.color.bytes(), &b.color.bytes());
    c.assert(is_true(Bool::from_field_unchecked(same_colour)).message("Can only merge coins of the same color"));

    // Field order is evaluation order, and compactc's too: the derived nonce
    // before the sum.
    let nonce = derived_nonce(c, NONCE_EVOLVE, &a.nonce);
    let sum = c.add(a.value, b.value);
    let new_coin = ShieldedCoinInfo { nonce, color: a.color, value: as_uint128(c, sum) };
    let cm = coin_commitment_to_contract(c, &new_coin, &me);
    claim_zswap_coin_spend(c, &cm);
    claim_zswap_coin_receive(c, &cm);
    new_coin
}

/// ```text
/// circuit sendShielded(input: QualifiedShieldedCoinInfo,
///                      recipient: Either<ZswapCoinPublicKey, ContractAddress>,
///                      value: Uint<128>): ShieldedSendResult {
///   const selfAddr = kernel.self();
///   createZswapInput(input);
///   kernel.claimZswapNullifier(coinNullifier(downcastQualifiedCoin(input), selfAddr));
///   const change = input.value - value;
///   const output = ShieldedCoinInfo{ nonce: <derived>, color: input.color, value: value };
///   createZswapOutput(output, recipient);
///   kernel.claimZswapCoinSpend(coinCommitment(output, recipient));
///   // Auto-receive when sending to self
///   if (!recipient.is_left && recipient.right.bytes == selfAddr.bytes) {
///     kernel.claimZswapCoinReceive(coinCommitment(output, recipient));
///   }
///   if (change == 0) { return ShieldedSendResult{ change: none, sent: output }; }
///   else { <change coin, spent and received by this contract>; }
/// }
/// ```
///
/// compactc's: `output`'s commitment is hashed TWICE, once per
/// `coinCommitment` in the source (about 5,640 rows, notes/vault-optimization.org),
/// where the lean form hashes it once and reuses it; and `!`, `&&` and the
/// change test are `cond_select`s (`not`, `bytes_eq`, `checked_sub`).
/// The `if (change == 0)` is written out rather than through
/// [`Circuit::when_value`] because compactc folds the `Maybe`'s tag into the
/// guard it already has: the tag IS the guard here, named once, and only the
/// five payload slots are selected.
pub fn send_shielded(
    c: &mut Circuit,
    input: &QualifiedShieldedCoinInfo<Public>,
    recipient: &CoinRecipient<Public>,
    value: Uint<128, Public>,
) -> ShieldedSendResult<Public> {
    let me = self_address(c).bytes();
    let spent = input.downcast();
    let nul = coin_nullifier_contract(c, &spent, &me);
    claim_zswap_nullifier(c, &nul);

    let change = checked_sub(c, input.value, value.field());

    let output = ShieldedCoinInfo {
        nonce: derived_nonce(c, NONCE_EVOLVE, &input.nonce),
        color: input.color,
        value: value.field(),
    };
    let to = B32::cond_select(c, recipient.is_left, &recipient.left.bytes(), &recipient.right.bytes());
    let cm = coin_commitment_to(c, &output, recipient.is_left.erase(), &to);
    claim_zswap_coin_spend(c, &cm);

    // Auto-receive when sending to self: `!recipient.is_left && …`, which is
    // one `cond_select` with the arms the other way round from `is_self`'s.
    // The address needs no guarded read — `selfAddr` is already to hand.
    let same = bytes_eq(c, &recipient.right.bytes(), &me);
    let mine = c.cond_select(recipient.is_left, 0u64, same);
    let cm_again = coin_commitment_to(c, &output, recipient.is_left.erase(), &to);
    let cm_again_val = cm_again.ledger_value(c);
    emit_guarded(c, mine, &minocrab_ledger::kernel_claim_zswap_coin_receive(&cm_again_val));

    let spent_it_all = c.test_eq(change, 0u64);
    let has_change = not(c, Bool::from_field_unchecked(spent_it_all)).field();
    let change_coin = ShieldedCoinInfo {
        nonce: derived_nonce(c, NONCE_EVOLVE_CHANGE, &input.nonce),
        color: input.color,
        value: change,
    };
    let change_cm = coin_commitment_to_contract(c, &change_coin, &me);
    c.when(has_change, |c| {
        claim_zswap_coin_spend(c, &change_cm);
        claim_zswap_coin_receive(c, &change_cm);
    });

    // `none<ShieldedCoinInfo>()` is the default coin, so the payload is the
    // change coin selected against zero — the tag is `has_change` above.
    let none_unless = |c: &mut Circuit, w| c.cond_select(spent_it_all, 0u64, w);
    let change_value = ShieldedCoinInfo {
        nonce: CoinNonce(B32 {
            hi: none_unless(c, change_coin.nonce.bytes().hi),
            lo: none_unless(c, change_coin.nonce.bytes().lo),
        }),
        color: CoinColor(B32 {
            hi: none_unless(c, change_coin.color.bytes().hi),
            lo: none_unless(c, change_coin.color.bytes().lo),
        }),
        value: none_unless(c, change_coin.value),
    };
    ShieldedSendResult {
        change: Maybe { is_some: Bool::from_field_unchecked(has_change), value: change_value },
        sent: output,
    }
}
