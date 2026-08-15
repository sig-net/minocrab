//! `events`, THROUGH THE BORSH API (M11 stage 6) — the twin of
//! [`crate::events`].
//!
//! The original is PINNED: it is differential-green against compactc's
//! `events` artifacts and does not move. This twin emits THE SAME BYTES —
//! stage 0 proved the deployed `Misc` payloads are already canonical Borsh
//! for the fixed-width subset — but builds them out of DECLARED TYPES
//! (`#[derive(CircuitBorsh)]`, [`minocrab_std::v3::borsh::to_bytes`]) instead
//! of hand-rolled [`Serializer`] pushes. Nothing about the format changes;
//! what changes is that the layout is a type rather than a call sequence, and
//! that the same declaration also yields the offset table the TS side reads.
//!
//! # Why the envelope is one struct and not two
//!
//! Compact's `Misc` is `{ name: Bytes<32>, payload: Bytes<256> }`, and the
//! payload is `serialize<DepositEvent, 256>` — the event's 56 Borsh bytes
//! followed by 200 zero bytes. This twin declares
//! [`MiscDepositEvent`] `= { name: [u8; 32], payload: DepositEvent }`, 88
//! bytes, and writes it into the 288-byte envelope under the padding rule
//! ("bytes `0..LEN` are the Borsh encoding, bytes `LEN..N` MUST be zero").
//!
//! THE TWO DESCRIBE THE SAME 288 BYTES, because both pads are contiguous:
//! `32 + 56 + 200 (payload pad) + 0 (envelope pad)` and
//! `32 + 56 + 232 (envelope pad)` lay the same bytes at the same offsets. The
//! nested form is the one a circuit can build in a single packing pass — the
//! two-level form would materialise the intermediate `Bytes<256>` and re-pack
//! it, which costs rows for no byte. Where the payload IS materialised
//! because something hashes it, the two-level form is the right one and
//! [`crate::xcontract_events_borsh`] uses it.
//!
//! Byte-identity with the original is asserted in
//! `tests/events_differential.rs`, which hands the twin the SAME preimage —
//! the one carrying the exact 288-byte `Misc` transcript that compactc's own
//! artifact accepts.

use minocrab::v3::{Circuit3, Compiled3, FieldT, Wire3};
use minocrab::Public;
use minocrab_ledger::{
    cell_write, counter_increment, counter_read, emit, emit_event, map_insert, ImpactElem,
    LedgerValue,
};
// `CircuitBorsh` names both the trait and the derive macro (different
// namespaces, one path), as `serde::Serialize` does.
use minocrab_std::v3::borsh::{self, CircuitBorsh};
use minocrab_std::v3::{Uint, Vis3, B32};

use crate::events::{
    event_name, BALANCES, CALL_COUNT, LAST_AMOUNT, MISC_SIZE, MISC_TAG, MISC_VERSION,
};

/// `struct DepositEvent { amount: Uint<128>, sequence: Uint<64>, recipient:
/// Bytes<32> }` — 56 Borsh bytes, the payload the deployed contract logs.
#[derive(CircuitBorsh)]
pub struct DepositEvent<V: Vis3> {
    pub amount: Uint<128, V>,
    pub sequence: Uint<64, V>,
    pub recipient: B32<V>,
}

/// The logged `Misc`: the 32-byte event name and the payload — 88 Borsh
/// bytes, written into the 288-byte envelope with a zero tail (see the module
/// docs for why this is the same byte string as `{name, payload: Bytes<256>}`).
#[derive(CircuitBorsh)]
pub struct MiscDepositEvent<V: Vis3> {
    pub name: B32<V>,
    pub payload: DepositEvent<V>,
}

/// `pad(32, name)` as a constant pair, LOW LIMB DECLARED FIRST.
///
/// [`B32::pad`] would do, and emits the same two constants — but in the other
/// order, because a struct literal evaluates `hi` before `lo`. The original's
/// `Serializer::push_literal` chunks the 32 bytes into `[0..31]` then `[31]`,
/// so it declares the low limb first, and matching that is what makes the two
/// circuits BYTE-IDENTICAL ZKIR rather than merely equivalent — a much
/// stronger gate for a stage whose whole claim is "same bytes, built through
/// the API". Two constants in the other order would have cost nothing and
/// proven less.
pub(crate) fn event_name_literal(c: &mut Circuit3, name: &str) -> B32<Public> {
    assert!(name.len() <= 32, "an event name is a pad(32, ..) literal");
    let mut bytes = [0u8; 32];
    bytes[..name.len()].copy_from_slice(name.as_bytes());
    let lo = c.constant(minocrab::Fr::from_le_bytes(&bytes[..31]).expect("31 bytes fit"));
    let hi = c.constant(minocrab::Fr::from(u64::from(bytes[31])));
    B32 { hi, lo }
}

/// The shared workload: `callCount.increment(1); lastAmount = a;
/// balances.insert(r, a)` — identical to [`crate::events`]'s, which is the
/// point: this stage touches serialization and nothing else.
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
            // THE WHOLE SERIALIZATION, as one declared value. The leaves are
            // already canonical where they are produced — `amount` and
            // `recipient` by their argument constraints, `sequence` by being
            // a `Bytes<8>` cell read, the name by being a constant — so
            // `constrain_canonical` is deliberately NOT re-emitted here; it
            // would duplicate the very constraints above and move rows. The
            // precondition `to_bytes` states (leaves in range) is met by
            // those, and `tests/events_differential.rs` pins the resulting
            // bytes against compactc's own artifact.
            let misc = MiscDepositEvent {
                name: event_name_literal(c, &event_name(i)),
                payload: DepositEvent {
                    amount: Uint::from_field(a),
                    sequence: Uint::from_field(sequence.expect("sequence read exists")),
                    recipient: r,
                },
            };
            let serialized = borsh::to_bytes::<MISC_SIZE, Public, _>(c, &misc);

            let payload = LedgerValue::bytes(
                MISC_SIZE as u32,
                serialized.limbs().iter().map(|&w| ImpactElem::Wire(w)).collect(),
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
