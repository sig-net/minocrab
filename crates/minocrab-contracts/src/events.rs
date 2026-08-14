//! `events` (signet-midnight-experiments) — the baseline workload plus a
//! growing number of MIP-0002 `Misc` events (`emit`, the VM `log` op).
//!
//! Compact original:
//! ```text
//! export ledger callCount: Counter;                 // field 0
//! export ledger lastAmount: Uint<128>;              // field 1
//! export ledger balances: Map<Bytes<32>, Uint<128>>;// field 2
//!
//! struct DepositEvent { amount: Uint<128>; sequence: Uint<64>; recipient: Bytes<32> }
//!
//! base(recipient, amount):   the shared workload, no emit (= baseline.base)
//! emitN(recipient, amount):  workload + N × emit(Misc {
//!     name: pad(32, "deposit-<i>"),
//!     payload: serialize<DepositEvent, 256>(DepositEvent { amount, sequence, recipient })
//! })   where sequence = callCount as Uint<64> (read before the increment)
//! ```
//! `Misc` is event tag 10, version 1, serialized size 288 = name ‖ payload
//! (compiler/midnight-events.ss:71).

use minocrab::v3::{Circuit3, Compiled3, FieldT, Wire3};
use minocrab::Public;
use minocrab_ledger::{
    cell_write, counter_increment, counter_read, emit, emit_event, map_insert, ImpactElem,
    LedgerValue,
};
use minocrab_std::v3::{Serializer, B32};

/// Ledger field indices, in declaration order.
pub const CALL_COUNT: u8 = 0;
pub const LAST_AMOUNT: u8 = 1;
pub const BALANCES: u8 = 2;

/// The Misc event constants (compiler/midnight-events.ss:71).
pub const MISC_VERSION: u32 = 1;
pub const MISC_TAG: u8 = 10;
pub const MISC_SIZE: usize = 288;

/// The event name of the `i`-th emit.
pub fn event_name(i: usize) -> String {
    format!("deposit-{i}")
}

/// The shared workload: `callCount.increment(1); lastAmount = a;
/// balances.insert(r, a)`.
fn workload(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    r: &B32<Public>,
    a: Wire3<FieldT, Public>,
) {
    let amount_val = LedgerValue::bytes(16, vec![ImpactElem::Wire(a)]);
    let recipient_val = LedgerValue::bytes(32, vec![ImpactElem::Wire(r.hi), ImpactElem::Wire(r.lo)]);
    let mut ops = counter_increment(CALL_COUNT, 1);
    ops.extend(cell_write(LAST_AMOUNT, &amount_val));
    ops.extend(map_insert(BALANCES, &recipient_val, &amount_val));
    emit(c, one, &ops);
}

/// The circuit family: the workload plus `emits` Misc events.
fn base_with_emits(emits: usize) -> Compiled3 {
    let mut c = Circuit3::new();
    let recipient = B32 {
        hi: c.arg::<FieldT>("recipient_hi"),
        lo: c.arg::<FieldT>("recipient_lo"),
    };
    let amount = c.arg::<FieldT>("amount");
    recipient.constrain_input(&mut c);
    c.assert_bits(amount, 128);
    let one = c.constant(1u64);

    let a = c.disclose(amount, "amount");
    let r = B32 {
        hi: c.disclose(recipient.hi, "recipient (hi)"),
        lo: c.disclose(recipient.lo, "recipient (lo)"),
    };

    // const sequence = callCount as Uint<64> — read before the increment,
    // only when an emit needs it.
    let sequence = (emits > 0).then(|| counter_read(&mut c, one, CALL_COUNT));

    workload(&mut c, one, &r, a);

    for i in 0..emits {
        c.region("emit Misc", |c| {
            // serialize<Misc, 288> = name(32) ‖ serialize<DepositEvent, 256>.
            let mut name = [0u8; 32];
            let label = event_name(i);
            name[..label.len()].copy_from_slice(label.as_bytes());

            let mut s = Serializer::<Public>::new();
            s.push_literal(c, &name);
            s.push_uint(a, 16); // amount: Uint<128>
            s.push_uint(sequence.expect("sequence read exists"), 8); // sequence: Uint<64>
            s.push_b32(&r); // recipient: Bytes<32>
            let serialized = s.finish(c, MISC_SIZE);

            let payload = LedgerValue::bytes(
                MISC_SIZE as u32,
                serialized.limbs.iter().map(|&w| ImpactElem::Wire(w)).collect(),
            );
            emit(c, one, &emit_event(MISC_VERSION, MISC_TAG, &payload));
        });
    }

    c.finish(true)
}

/// `export circuit base(recipient, amount): []` — the control.
pub fn base() -> Compiled3 {
    base_with_emits(0)
}

/// `export circuit emit1/2/4(recipient, amount): []`.
pub fn emit_n(n: usize) -> Compiled3 {
    assert!(n >= 1);
    base_with_emits(n)
}
