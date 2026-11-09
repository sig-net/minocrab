//! `xcall` (signet-midnight-experiments) — the cross-contract calling
//! experiment: caller contract A holds a sealed reference to target
//! contract B and calls its circuits cross-contract (M5).
//!
//! Compact original (caller):
//! ```text
//! contract Target {
//!   circuit deposit(recipient: Bytes<32>, amount: Uint<128>): [];
//!   circuit depositEmit(recipient: Bytes<32>, amount: Uint<128>): [];
//!   circuit depositBig(data: Bytes<256>): [];
//! }
//! export sealed ledger target: Target;              // field 0
//! export ledger callCount: Counter;                 // field 1
//! export ledger lastAmount: Uint<128>;              // field 2
//! export ledger balances: Map<Bytes<32>, Uint<128>>;// field 3
//!
//! localBase(recipient, amount): the baseline workload done locally
//! callOnce(recipient, amount):  increment + target.deposit(r, a)
//! callTwice(recipient, amount): increment + 2 × target.deposit(r, a)
//! callBig(data: Bytes<256>):    increment + target.depositBig(data)
//! callEmit(recipient, amount):  increment + target.depositEmit(r, a)
//! ```
//! `callEmit` and `callOnce` differ only in WHICH entry point they claim,
//! which is a constant of the circuit: their ZKIR differs in exactly the two
//! entry-point-hash limbs of the claim.
//!
//! The target contract's `deposit`/`depositEmit` are exactly the `events`
//! experiment's `base`/`emit1` circuits (same ledger layout, same
//! `DepositEvent`, same `deposit-0` event name) — see [`target_deposit`].

use minocrab::v3::{Circuit3, Compiled3, FieldT, Wire3};
use minocrab::{label, Private, Public};
use minocrab_ledger::{
    cell_write, counter_increment, emit, map_insert, ImpactElem, LedgerValue, XcallCommitment,
};
use minocrab_std::v3::{contract, entry, BytesN, CircuitArg, Disclose, Discloses, Uint, B32};

use xcall_target_interface::XcallTarget;

use crate::events;

/// Caller ledger fields, in declaration order.
pub const TARGET: u8 = 0;
pub const CALL_COUNT: u8 = 1;
pub const LAST_AMOUNT: u8 = 2;
pub const BALANCES: u8 = 3;

/// Target ledger fields (= the `events` experiment's layout).
pub const T_CALL_COUNT: u8 = 0;

/// `(recipient: Bytes<32>, amount: Uint<128>)` — the argument list four of
/// these circuits share.
#[derive(CircuitArg)]
struct DepositArgs {
    recipient: B32<Private>,
    amount: Uint<128>,
}

label! {
    Recipient = "recipient";
    Amount = "amount";
    /// `callBig`'s 256-byte argument — nine limbs, ONE logical value.
    Data = "data";
}

/// The shared disclosure of a [`DepositArgs`]: everything these circuits do
/// with the pair is public (a ledger write, or a cross-contract call).
fn disclose_args(c: &mut Circuit3, args: DepositArgs) -> (B32<Public>, Wire3<FieldT, Public>) {
    let r = args.recipient.disclose_as::<Recipient>(c);
    let a = args.amount.disclose_as::<Amount>(c).field();
    (r, a)
}

/// What every circuit in the `callOnce`/`callTwice` family discloses: the two
/// arguments, plus what `contract_call` publishes on the caller's behalf —
/// the same for one call or two, since a label names a value, not an
/// occurrence.
///
/// Named once because the family is built through [`entry`]: the entry
/// point's return type and the hand-written set-equality test below have to
/// be the SAME declaration, and an alias is what makes that a compiler fact.
type CallDisclosures = Discloses<(Recipient, Amount, XcallCommitment)>;

/// The sealed `target` reference. `at_field` means every call site does its
/// own fresh uncached read of the cell — which `callTwice` relies on.
const TARGET_CONTRACT: XcallTarget = XcallTarget::at_field(TARGET);

/// The caller contract: the local control, the two cross-contract entry
/// points that are `#[circuit]`s, and the target's own `depositBig` callee.
/// (`callOnce`/`callTwice` are built through [`entry`] over a
/// Rust-valued family and stay free functions — see [`call_n_times`].)
pub struct Xcall;

#[contract]
impl Xcall {
    /// `export circuit localBase(recipient, amount): []` — the control: the
    /// shared workload performed locally against the caller's own ledger.
    #[circuit]
    pub fn local_base(
        c: &mut Circuit3,
        recipient: B32<Private>,
        amount: Uint<128>,
    ) -> Discloses<(Recipient, Amount)> {
        let (r, a) = disclose_args(c, DepositArgs { recipient, amount });
        // Kept even though guard threading no longer uses it: dropping this
        // `Copy` would renumber every later identifier, moving the ZKIR
        // (notes/edsl-trim.org §B, the removal's zero-movement gate).
        let _ = c.constant(1u64);

        let amount_val = LedgerValue::bytes(16, vec![ImpactElem::Wire(a)]);
        let recipient_val = LedgerValue::bytes(32, vec![ImpactElem::Wire(r.hi), ImpactElem::Wire(r.lo)]);
        let mut ops = counter_increment(CALL_COUNT, 1);
        ops.extend(cell_write(LAST_AMOUNT, &amount_val));
        ops.extend(map_insert(BALANCES, &recipient_val, &amount_val));
        emit(c, &ops);
        Discloses::of(())
    }

    /// `export circuit callEmit(recipient, amount): []` — `target.depositEmit`.
    /// [`call_once`] with the other entry point: the two circuits differ only
    /// in the entry-point constant of the claim.
    #[circuit]
    pub fn call_emit(
        c: &mut Circuit3,
        recipient: B32<Private>,
        amount: Uint<128>,
    ) -> Discloses<(Recipient, Amount, XcallCommitment)> {
        let (r, a) = disclose_args(c, DepositArgs { recipient, amount });
        // Kept even though guard threading no longer uses it: dropping this
        // `Copy` would renumber every later identifier, moving the ZKIR
        // (notes/edsl-trim.org §B, the removal's zero-movement gate).
        let _ = c.constant(1u64);
        emit(c, &counter_increment(CALL_COUNT, 1));
        TARGET_CONTRACT.deposit_emit(c, r, Uint::from_field_unchecked(a));
        Discloses::of(())
    }

    /// `export circuit callBig(data: Bytes<256>): []` — one call carrying a
    /// 256-byte argument (9 FAB limbs).
    #[circuit]
    pub fn call_big(
        c: &mut Circuit3,
        data: BytesN<Private, 256>,
    ) -> Discloses<(Data, XcallCommitment)> {
        let data: BytesN<Public, 256> = data.disclose_as::<Data>(c);
        // Kept even though guard threading no longer uses it: dropping this
        // `Copy` would renumber every later identifier, moving the ZKIR
        // (notes/edsl-trim.org §B, the removal's zero-movement gate).
        let _ = c.constant(1u64);

        emit(c, &counter_increment(CALL_COUNT, 1));
        TARGET_CONTRACT.deposit_big(c, data);
        Discloses::of(())
    }

    /// Target `export circuit depositBig(data: Bytes<256>): []` — just the
    /// counter increment; isolates the cost of moving a large argument across
    /// the contract boundary.
    #[circuit]
    pub fn target_deposit_big(c: &mut Circuit3, _data: BytesN<Private, 256>) -> Discloses<()> {
        // Kept even though guard threading no longer uses it: dropping this
        // `Copy` would renumber every later identifier, moving the ZKIR
        // (notes/edsl-trim.org §B, the removal's zero-movement gate).
        let _ = c.constant(1u64);
        emit(c, &counter_increment(T_CALL_COUNT, 1));
        // The callee's own argument never leaves the private domain: it is
        // declared for the wire shape and never read. `Discloses<()>` is that
        // fact, stated positively and checked like any other declaration.
        Discloses::of(())
    }
}

/// `export circuit callOnce(recipient, amount): []` — one cross-contract
/// call carrying `(Bytes<32>, Uint<128>)`. ([`call_emit`] is the same call
/// through the interface's other method, `depositEmit`: the same circuit
/// up to the entry-point constant.)
pub fn call_once() -> Compiled3 {
    call_n_times(1)
}

/// `export circuit callTwice(recipient, amount): []` — two calls in one
/// circuit; each call site re-reads the target cell (uncached, like the
/// first).
pub fn call_twice() -> Compiled3 {
    call_n_times(2)
}

/// `callOnce`/`callTwice`, which differ by a Rust value and so are built
/// through [`entry`] rather than the attribute (see `events`'s note).
fn call_n_times(n: usize) -> Compiled3 {
    entry(|c, args: DepositArgs| -> CallDisclosures {
        let (r, a) = disclose_args(c, args);
        // Kept even though guard threading no longer uses it: dropping this
        // `Copy` would renumber every later identifier, moving the ZKIR
        // (notes/edsl-trim.org §B, the removal's zero-movement gate).
        let _ = c.constant(1u64);

        emit(c, &counter_increment(CALL_COUNT, 1));
        for _ in 0..n {
            TARGET_CONTRACT.deposit(c, r, Uint::from_field_unchecked(a));
        }
        Discloses::of(())
    })
}

/// Target `deposit` — identical to the `events` experiment's `base`.
pub fn target_deposit() -> Compiled3 {
    events::base()
}

/// Target `depositEmit` — identical to the `events` experiment's `emit1`.
pub fn target_deposit_emit() -> Compiled3 {
    events::emit_n(1)
}

/// The set-equality test `#[circuit]` would have generated for this family,
/// hand-written per instantiation — see [`crate::events`]'s twin for the
/// reasoning.
#[cfg(test)]
mod call_n_times_discloses {
    use super::*;
    use minocrab_std::v3::assert_declared_disclosures;

    #[test]
    fn the_declared_disclosures_are_the_ones_the_family_makes() {
        for n in [1, 2] {
            assert_declared_disclosures::<CallDisclosures>(
                &format!("call_n_times({n})"),
                &call_n_times(n),
            );
        }
    }
}
