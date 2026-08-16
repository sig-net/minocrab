//! Compact's `kernel` ADT, and the token stdlib circuits built on it (M17,
//! notes/kernel-tokens.org).
//!
//! TWO LAYERS wearing one name, and the split is the milestone's main
//! structural finding:
//!
//! | layer | what it is | here |
//! |---|---|---|
//! | KERNEL PRIMITIVES | `declare-ledger-adt Kernel` functions with vm-code | [`mint_unshielded`] … [`block_time_greater_than`] |
//! | STDLIB CIRCUITS | ordinary `export circuit`s written IN COMPACT, composed from those | [`send_unshielded`] … [`unshielded_balance_lte`] |
//!
//! The second layer is `standard-library.compact:113-350` transcribed. Each
//! function below carries the Compact it is a port of, and the bodies are
//! deliberately as close to it as Rust allows — these are the circuits whose
//! *composition* is the specification, and a reader should be able to check
//! them against the Compact source line by line.
//!
//! `kernel.checkpoint()` IS ABSENT. compactc's ZKIR-v3 backend cannot compile
//! it at all (`assemble1` has no `ckpt` case, so `--feature-zkir-v3` on a
//! contract calling it fails with `assert not-implemented`); the v2 backend
//! assembles it to `255`. It is a v2-only feature, so there is no artifact to
//! agree with and nothing here to agree with it — see
//! notes/kernel-tokens.org finding (a).
//!
//! THE BALANCE CAVEAT, which is Compact's own and worth repeating: the
//! balance these functions read is the contract's balance at the START of
//! execution. Unshielded sends, receives and mints inside the same circuit do
//! NOT feed back into it. `unshieldedBalance` also imposes exact-match
//! semantics at apply time, so the comparison forms are usually what a
//! contract wants.

use minocrab::v3::{Circuit3, FieldT, Operand};
use minocrab::{AlignmentAtom, Fr, Public, Visibility};
use minocrab_ledger::{
    emit, kernel_balance, kernel_block_time, kernel_claim_unshielded_coin_spend,
    kernel_inc_unshielded_inputs, kernel_inc_unshielded_outputs, kernel_mint_shielded,
    kernel_mint_unshielded, kernel_self, BalanceCmp, ImpactElem, LedgerValue,
};

use super::ledger::LedgerRepr;
use super::{Bool, ContractAddress, Either, Uint, UserAddress, B32};

/// The guard of a STRAIGHT-LINE kernel operation: the immediate `1`, inlined
/// into the Impact instruction rather than named by a `Copy` — the same
/// convention the ledger slots use.
const STRAIGHT_LINE: u64 = 1;

/// Compact's `TokenType` — `Either<Bytes<32>, Bytes<32>>`.
pub type TokenType<V = Public> = Either<B32<V>, B32<V>, V>;

/// Compact's `UnshieldedRecipient` — `Either<ContractAddress, UserAddress>`.
pub type UnshieldedRecipient<V = Public> = Either<ContractAddress<V>, UserAddress<V>, V>;

/// `left<Bytes<32>, Bytes<32>>(color)` — an unshielded token type, which is
/// the ONLY `TokenType` Compact's own stdlib ever builds.
///
/// A distinct type rather than a [`TokenType`], and the reason is the
/// instruction stream. Four of the five FAB limbs of `left(color)` are
/// CONSTANT — the `is_left` tag and the unused right arm's two — and compactc
/// inlines all four into the Impact `push`. Routing them through
/// [`LedgerRepr`](super::LedgerRepr) would name each with a `copy`, which is
/// the named-immediate gap M15 recorded for ledger VALUE positions and left
/// as dmd's call.
///
/// This closes it where it can be closed WITHOUT that API change: an
/// `UnshieldedToken` knows its own constants, so it builds its `LedgerValue`
/// with [`ImpactElem::Imm`] directly and never asks the trait for a wire that
/// does not exist. A `TokenType` whose tag is computed still goes the ordinary
/// way — the general `Either` impl is untouched.
#[derive(Clone, Copy)]
pub struct UnshieldedToken<V: super::Vis3 = Public>(pub B32<V>);

/// `left<Bytes<32>, Bytes<32>>(color)`.
pub fn unshielded(_c: &mut Circuit3, color: B32<Public>) -> UnshieldedToken<Public> {
    UnshieldedToken(color)
}

impl UnshieldedToken<Public> {
    /// The five FAB limbs, three of them inline constants: `[1, hi, lo, 0, 0]`
    /// under `[bytes<1>, bytes<32>, bytes<32>]`.
    pub fn ledger_value(&self) -> LedgerValue {
        LedgerValue::new(
            vec![
                AlignmentAtom::Bytes { length: 1 },
                AlignmentAtom::Bytes { length: 32 },
                AlignmentAtom::Bytes { length: 32 },
            ],
            vec![
                ImpactElem::Imm(Fr::from(1u64)),
                ImpactElem::Wire(self.0.hi),
                ImpactElem::Wire(self.0.lo),
                ImpactElem::Imm(Fr::from(0u64)),
                ImpactElem::Imm(Fr::from(0u64)),
            ],
        )
    }
}

// ---- the kernel primitives --------------------------------------------------

/// `kernel.self()` — the contract's own address.
pub fn self_address(c: &mut Circuit3) -> ContractAddress<Public> {
    self_address_under(c, STRAIGHT_LINE)
}

/// [`self_address`] under a branch condition.
pub fn self_address_under<G: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, G>>,
) -> ContractAddress<Public> {
    ContractAddress::from_limbs(kernel_self(c, guard))
}

/// `kernel.mintShielded(domain_sep, amount)` — effects[4].
pub fn mint_shielded(c: &mut Circuit3, domain_sep: &B32<Public>, amount: Uint<64, Public>) {
    mint_shielded_under(c, STRAIGHT_LINE, domain_sep, amount)
}

/// [`mint_shielded`] under a branch condition.
pub fn mint_shielded_under<G: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, G>>,
    domain_sep: &B32<Public>,
    amount: Uint<64, Public>,
) {
    let (ds, amt) = (domain_sep.ledger_value(c), amount.ledger_value(c));
    emit(c, guard, &kernel_mint_shielded(&ds, &amt));
}

/// `kernel.mintUnshielded(domain_sep, amount)` — effects[5], and the same
/// accumulator shape [`mint_shielded`] is.
pub fn mint_unshielded(c: &mut Circuit3, domain_sep: &B32<Public>, amount: Uint<64, Public>) {
    mint_unshielded_under(c, STRAIGHT_LINE, domain_sep, amount)
}

/// [`mint_unshielded`] under a branch condition.
pub fn mint_unshielded_under<G: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, G>>,
    domain_sep: &B32<Public>,
    amount: Uint<64, Public>,
) {
    let (ds, amt) = (domain_sep.ledger_value(c), amount.ledger_value(c));
    emit(c, guard, &kernel_mint_unshielded(&ds, &amt));
}

/// `kernel.incUnshieldedInputs(token_type, amount)` — effects[6]. Called when
/// the contract RECEIVES an unshielded token.
pub fn inc_unshielded_inputs(
    c: &mut Circuit3,
    token: &UnshieldedToken<Public>,
    amount: Uint<128, Public>,
) {
    inc_unshielded_inputs_under(c, STRAIGHT_LINE, token, amount)
}

/// [`inc_unshielded_inputs`] under a branch condition.
pub fn inc_unshielded_inputs_under<G: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, G>>,
    token: &UnshieldedToken<Public>,
    amount: Uint<128, Public>,
) {
    let (t, amt) = (token.ledger_value(), amount.ledger_value(c));
    emit(c, guard, &kernel_inc_unshielded_inputs(&t, &amt));
}

/// `kernel.incUnshieldedOutputs(token_type, amount)` — effects[7]. Called when
/// the contract SENDS one.
pub fn inc_unshielded_outputs(
    c: &mut Circuit3,
    token: &UnshieldedToken<Public>,
    amount: Uint<128, Public>,
) {
    inc_unshielded_outputs_under(c, STRAIGHT_LINE, token, amount)
}

/// [`inc_unshielded_outputs`] under a branch condition.
pub fn inc_unshielded_outputs_under<G: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, G>>,
    token: &UnshieldedToken<Public>,
    amount: Uint<128, Public>,
) {
    let (t, amt) = (token.ledger_value(), amount.ledger_value(c));
    emit(c, guard, &kernel_inc_unshielded_outputs(&t, &amt));
}

/// `kernel.claimUnshieldedCoinSpend(token_type, recipient, amount)` —
/// effects[8]. Authorizes a transfer; the key is the token type and the
/// recipient TOGETHER, so the two travel as one six-atom value.
pub fn claim_unshielded_coin_spend(
    c: &mut Circuit3,
    token: &UnshieldedToken<Public>,
    recipient: &UnshieldedRecipient<Public>,
    amount: Uint<128, Public>,
) {
    claim_unshielded_coin_spend_under(c, STRAIGHT_LINE, token, recipient, amount)
}

/// [`claim_unshielded_coin_spend`] under a branch condition.
pub fn claim_unshielded_coin_spend_under<G: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, G>>,
    token: &UnshieldedToken<Public>,
    recipient: &UnshieldedRecipient<Public>,
    amount: Uint<128, Public>,
) {
    let key = concat_values(token.ledger_value(), recipient.ledger_value(c));
    let amt = amount.ledger_value(c);
    emit(c, guard, &kernel_claim_unshielded_coin_spend(&key, &amt));
}

/// The two halves of `claimUnshieldedCoinSpend`'s key, side by side in one
/// `LedgerValue` — which is what the single `push` in its stream carries.
fn concat_values(a: LedgerValue, b: LedgerValue) -> LedgerValue {
    let mut atoms = a.atoms().to_vec();
    let mut elems = a.elems().to_vec();
    atoms.extend_from_slice(b.atoms());
    elems.extend_from_slice(b.elems());
    LedgerValue::new(atoms, elems)
}

/// `kernel.balance(token_type)` — the contract's balance of an unshielded
/// token, or ZERO if it has never held one. See the module docs for what
/// "balance" means here.
pub fn balance(c: &mut Circuit3, token: &UnshieldedToken<Public>) -> Uint<128, Public> {
    balance_under(c, STRAIGHT_LINE, token)
}

/// [`balance`] under a branch condition.
pub fn balance_under<G: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, G>>,
    token: &UnshieldedToken<Public>,
) -> Uint<128, Public> {
    let t = token.ledger_value();
    Uint::from_field(kernel_balance(c, guard, &t, BalanceCmp::Value, None))
}

/// `kernel.balanceLessThan(token_type, amount)`.
pub fn balance_less_than(
    c: &mut Circuit3,
    token: &UnshieldedToken<Public>,
    amount: Uint<128, Public>,
) -> Bool<Public> {
    balance_less_than_under(c, STRAIGHT_LINE, token, amount)
}

/// [`balance_less_than`] under a branch condition.
pub fn balance_less_than_under<G: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, G>>,
    token: &UnshieldedToken<Public>,
    amount: Uint<128, Public>,
) -> Bool<Public> {
    let (t, amt) = (token.ledger_value(), amount.ledger_value(c));
    Bool::from_field(kernel_balance(
        c,
        guard,
        &t,
        BalanceCmp::LessThan,
        Some(&amt),
    ))
}

/// `kernel.balanceGreaterThan(token_type, amount)`.
pub fn balance_greater_than(
    c: &mut Circuit3,
    token: &UnshieldedToken<Public>,
    amount: Uint<128, Public>,
) -> Bool<Public> {
    balance_greater_than_under(c, STRAIGHT_LINE, token, amount)
}

/// [`balance_greater_than`] under a branch condition.
pub fn balance_greater_than_under<G: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, G>>,
    token: &UnshieldedToken<Public>,
    amount: Uint<128, Public>,
) -> Bool<Public> {
    let (t, amt) = (token.ledger_value(), amount.ledger_value(c));
    Bool::from_field(kernel_balance(
        c,
        guard,
        &t,
        BalanceCmp::GreaterThan,
        Some(&amt),
    ))
}

/// `kernel.blockTimeLessThan(t)` — whether the block time is before `t`.
pub fn block_time_less_than(c: &mut Circuit3, time: Uint<64, Public>) -> Bool<Public> {
    block_time_less_than_under(c, STRAIGHT_LINE, time)
}

/// [`block_time_less_than`] under a branch condition.
pub fn block_time_less_than_under<G: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, G>>,
    time: Uint<64, Public>,
) -> Bool<Public> {
    let t = time.ledger_value(c);
    Bool::from_field(kernel_block_time(c, guard, &t, false))
}

/// `kernel.blockTimeGreaterThan(t)`.
pub fn block_time_greater_than(c: &mut Circuit3, time: Uint<64, Public>) -> Bool<Public> {
    block_time_greater_than_under(c, STRAIGHT_LINE, time)
}

/// [`block_time_greater_than`] under a branch condition.
pub fn block_time_greater_than_under<G: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, G>>,
    time: Uint<64, Public>,
) -> Bool<Public> {
    let t = time.ledger_value(c);
    Bool::from_field(kernel_block_time(c, guard, &t, true))
}

// ---- the stdlib circuits ----------------------------------------------------
//
// standard-library.compact:275-350, transcribed. Each is a composition of the
// primitives above and nothing else.

/// `circuit blockTimeLt(time): Boolean { return kernel.blockTimeLessThan(time); }`
pub fn block_time_lt(c: &mut Circuit3, time: Uint<64, Public>) -> Bool<Public> {
    block_time_less_than(c, time)
}

/// `circuit blockTimeGte(time): Boolean { return !blockTimeLt(time); }`
pub fn block_time_gte(c: &mut Circuit3, time: Uint<64, Public>) -> Bool<Public> {
    let lt = block_time_lt(c, time);
    not(c, lt)
}

/// `circuit blockTimeGt(time): Boolean { return kernel.blockTimeGreaterThan(time); }`
pub fn block_time_gt(c: &mut Circuit3, time: Uint<64, Public>) -> Bool<Public> {
    block_time_greater_than(c, time)
}

/// `circuit blockTimeLte(time): Boolean { return !blockTimeGt(time); }`
pub fn block_time_lte(c: &mut Circuit3, time: Uint<64, Public>) -> Bool<Public> {
    let gt = block_time_gt(c, time);
    not(c, gt)
}

/// Compact's `!b` on a Boolean, which compactc lowers to
/// `cond_select(b, 0, 1)` rather than to an arithmetic negation — the shape
/// the fixture's `sBlockTimeGte` shows.
fn not(c: &mut Circuit3, b: Bool<Public>) -> Bool<Public> {
    Bool::from_field(c.cond_select(b.field(), 0u64, 1u64))
}

/// `circuit unshieldedBalance(color): Uint<128>`
pub fn unshielded_balance(c: &mut Circuit3, color: B32<Public>) -> Uint<128, Public> {
    let token = unshielded(c, color);
    balance(c, &token)
}

/// `circuit unshieldedBalanceLt(color, amount): Boolean`
pub fn unshielded_balance_lt(
    c: &mut Circuit3,
    color: B32<Public>,
    amount: Uint<128, Public>,
) -> Bool<Public> {
    let token = unshielded(c, color);
    balance_less_than(c, &token, amount)
}

/// `circuit unshieldedBalanceGte(color, amount): Boolean { return !…Lt(…); }`
pub fn unshielded_balance_gte(
    c: &mut Circuit3,
    color: B32<Public>,
    amount: Uint<128, Public>,
) -> Bool<Public> {
    let lt = unshielded_balance_lt(c, color, amount);
    not(c, lt)
}

/// `circuit unshieldedBalanceGt(color, amount): Boolean`
pub fn unshielded_balance_gt(
    c: &mut Circuit3,
    color: B32<Public>,
    amount: Uint<128, Public>,
) -> Bool<Public> {
    let token = unshielded(c, color);
    balance_greater_than(c, &token, amount)
}

/// `circuit unshieldedBalanceLte(color, amount): Boolean { return !…Gt(…); }`
pub fn unshielded_balance_lte(
    c: &mut Circuit3,
    color: B32<Public>,
    amount: Uint<128, Public>,
) -> Bool<Public> {
    let gt = unshielded_balance_gt(c, color, amount);
    not(c, gt)
}

/// ```text
/// circuit receiveUnshielded(color, amount): [] {
///   kernel.incUnshieldedInputs(left<Bytes<32>, Bytes<32>>(color), amount);
/// }
/// ```
pub fn receive_unshielded(c: &mut Circuit3, color: B32<Public>, amount: Uint<128, Public>) {
    let token = unshielded(c, color);
    inc_unshielded_inputs(c, &token, amount);
}
