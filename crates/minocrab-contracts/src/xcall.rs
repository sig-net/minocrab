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
//! `callEmit` and `callOnce` differ only in WHICH entry point the prover
//! claims (witness data), so their circuits are structurally identical.
//!
//! The target contract's `deposit`/`depositEmit` are exactly the `events`
//! experiment's `base`/`emit1` circuits (same ledger layout, same
//! `DepositEvent`, same `deposit-0` event name) — see [`target_deposit`].

use minocrab::v3::{Circuit3, Compiled3, FieldT, Wire3};
use minocrab::Public;
use minocrab_ledger::{
    cell_read, cell_write, contract_call, counter_increment, emit, map_insert, ImpactElem,
    LedgerValue,
};
use minocrab_std::v3::{BytesN, B32};

use crate::events;

/// Caller ledger fields, in declaration order.
pub const TARGET: u8 = 0;
pub const CALL_COUNT: u8 = 1;
pub const LAST_AMOUNT: u8 = 2;
pub const BALANCES: u8 = 3;

/// Target ledger fields (= the `events` experiment's layout).
pub const T_CALL_COUNT: u8 = 0;

/// `(recipient: Bytes<32>, amount: Uint<128>)` argument pair, constrained
/// and disclosed.
fn recipient_amount_args(c: &mut Circuit3) -> (B32<Public>, Wire3<FieldT, Public>) {
    let recipient = B32 {
        hi: c.arg::<FieldT>("recipient_hi"),
        lo: c.arg::<FieldT>("recipient_lo"),
    };
    let amount = c.arg::<FieldT>("amount");
    recipient.constrain_input(c);
    c.assert_bits(amount, 128);
    let r = B32 {
        hi: c.disclose(recipient.hi, "recipient (hi)"),
        lo: c.disclose(recipient.lo, "recipient (lo)"),
    };
    let a = c.disclose(amount, "amount");
    (r, a)
}

/// One `target.deposit`-shaped call site: the fresh uncached read of the
/// sealed `target` cell, then the call itself (unit return).
fn call_target(c: &mut Circuit3, one: Wire3<FieldT, Public>, args: &[Wire3<FieldT, Public>]) {
    let addr = cell_read(
        c,
        one,
        TARGET,
        vec![minocrab::AlignmentAtom::Bytes { length: 32 }],
    );
    contract_call(c, one, [addr[0], addr[1]], args, &[]);
}

/// `export circuit localBase(recipient, amount): []` — the control: the
/// shared workload performed locally against the caller's own ledger.
pub fn local_base() -> Compiled3 {
    let mut c = Circuit3::new();
    let (r, a) = recipient_amount_args(&mut c);
    let one = c.constant(1u64);

    let amount_val = LedgerValue::bytes(16, vec![ImpactElem::Wire(a)]);
    let recipient_val = LedgerValue::bytes(32, vec![ImpactElem::Wire(r.hi), ImpactElem::Wire(r.lo)]);
    let mut ops = counter_increment(CALL_COUNT, 1);
    ops.extend(cell_write(LAST_AMOUNT, &amount_val));
    ops.extend(map_insert(BALANCES, &recipient_val, &amount_val));
    emit(&mut c, one, &ops);

    c.finish(true)
}

/// `export circuit callOnce/callEmit(recipient, amount): []` — one
/// cross-contract call carrying `(Bytes<32>, Uint<128>)`. (`callEmit`
/// claims `depositEmit` instead of `deposit`, which only changes the
/// prover-supplied entry-point-hash witness, not the circuit.)
pub fn call_once() -> Compiled3 {
    call_n_times(1)
}

/// `export circuit callTwice(recipient, amount): []` — two calls in one
/// circuit; each call site re-reads the target cell (uncached, like the
/// first).
pub fn call_twice() -> Compiled3 {
    call_n_times(2)
}

fn call_n_times(n: usize) -> Compiled3 {
    let mut c = Circuit3::new();
    let (r, a) = recipient_amount_args(&mut c);
    let one = c.constant(1u64);

    emit(&mut c, one, &counter_increment(CALL_COUNT, 1));
    for _ in 0..n {
        call_target(&mut c, one, &[r.hi, r.lo, a]);
    }

    c.finish(true)
}

/// `export circuit callBig(data: Bytes<256>): []` — one call carrying a
/// 256-byte argument (9 FAB limbs).
pub fn call_big() -> Compiled3 {
    let mut c = Circuit3::new();
    let data = BytesN::<_, 256>::arg(&mut c, "data");
    data.constrain_input(&mut c);
    let data: Vec<Wire3<FieldT, Public>> = data
        .limbs()
        .iter()
        .map(|&w| c.disclose(w, "data"))
        .collect();
    let one = c.constant(1u64);

    emit(&mut c, one, &counter_increment(CALL_COUNT, 1));
    call_target(&mut c, one, &data);

    c.finish(true)
}

/// Target `deposit` — identical to the `events` experiment's `base`.
pub fn target_deposit() -> Compiled3 {
    events::base()
}

/// Target `depositEmit` — identical to the `events` experiment's `emit1`.
pub fn target_deposit_emit() -> Compiled3 {
    events::emit_n(1)
}

/// Target `export circuit depositBig(data: Bytes<256>): []` — just the
/// counter increment; isolates the cost of moving a large argument across
/// the contract boundary.
pub fn target_deposit_big() -> Compiled3 {
    let mut c = Circuit3::new();
    let data = BytesN::<_, 256>::arg(&mut c, "data");
    data.constrain_input(&mut c);
    let one = c.constant(1u64);
    emit(&mut c, one, &counter_increment(T_CALL_COUNT, 1));
    c.finish(true)
}
