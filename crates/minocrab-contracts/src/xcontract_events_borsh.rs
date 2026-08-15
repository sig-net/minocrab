//! `xcontract-events`, THROUGH THE BORSH API (M11 stage 6) — the twin of
//! [`crate::xcontract_events`].
//!
//! Same discipline as [`crate::events_borsh`]: the original is pinned and
//! differential-green against compactc, this twin emits THE SAME BYTES and
//! builds them out of declared types. What makes this the more interesting of
//! the two twins is that the payload is MATERIALISED — the token hashes it
//! (`persistentHash<Bytes<256>>(payload)`) and returns the digest across a
//! cross-contract call — so both halves of the padding rule are exercised on
//! one shape:
//!
//! - `payload = to_bytes::<256>(DepositEvent)` — 56 Borsh bytes then 200 zero
//!   bytes, and it is THOSE 256 bytes that are hashed, exactly as deployed;
//! - `misc = to_bytes::<288>(Misc { name, payload })` — here `LEN == 288`
//!   exactly, so there is no pad at all: the envelope IS the Borsh encoding
//!   of a `{[u8; 32], [u8; 256]}` struct.
//!
//! The caller side (`depositViaVault`) serializes nothing and is not twinned:
//! it would be a byte-for-byte copy of a circuit this stage has no opinion
//! about, and the harness would learn nothing from it.

use minocrab::v3::Circuit3;
use minocrab::{Private, Public};
use minocrab_ledger::{
    cell_write, counter_increment, counter_read, emit, emit_event, set_insert, ImpactElem,
    LedgerValue,
};
// `CircuitBorsh` names both the trait and the derive macro.
use minocrab_std::v3::borsh::{self, CircuitBorsh};
use minocrab_std::v3::{circuit, BytesN, ContractAddress, Uint, Vis3, B32};

use crate::events::{MISC_SIZE, MISC_TAG, MISC_VERSION};
use crate::events_borsh::DepositEvent;
use crate::xcontract_events::{
    DEPOSIT_COUNT, EMITTED_DEPOSITS, EVENT_NAME, LAST_AMOUNT, PAYLOAD_SIZE,
};

/// `Misc { name: Bytes<32>, payload: Bytes<256> }` — 288 Borsh bytes, the
/// deployed envelope declared exactly as it is: a name and an opaque
/// fixed-width payload slot, whose CONTENTS are `borsh(DepositEvent)`
/// followed by the payload's own zero pad.
#[derive(CircuitBorsh)]
pub struct Misc<V: Vis3> {
    pub name: B32<V>,
    pub payload: BytesN<V, PAYLOAD_SIZE>,
}

fn b32_ledger_value(b: &B32<Public>) -> LedgerValue {
    LedgerValue::bytes(32, vec![ImpactElem::Wire(b.hi), ImpactElem::Wire(b.lo)])
}

/// `export circuit deposit(amount: Uint<128>, caller: ContractAddress):
/// Bytes<32>` — the token-side callee, with both serializations built from
/// declared types.
#[circuit(output = "event hash")]
pub fn token_deposit(
    c: &mut Circuit3,
    amount: Uint<128>,
    caller: ContractAddress<Private>,
) -> B32<Public> {
    let caller = caller.bytes();
    let a = c.disclose(amount.field(), "amount");
    let cal = B32 {
        hi: c.disclose(caller.hi, "caller (hi)"),
        lo: c.disclose(caller.lo, "caller (lo)"),
    };
    let one = c.constant(1u64);

    // const sequence = depositCount as Uint<64> — read before the increment.
    let sequence = counter_read(c, one, DEPOSIT_COUNT);
    emit(c, one, &counter_increment(DEPOSIT_COUNT, 1));
    let amount_val = LedgerValue::bytes(16, vec![ImpactElem::Wire(a)]);
    emit(c, one, &cell_write(LAST_AMOUNT, &amount_val));

    // payload = serialize<DepositEvent, 256>({amount, sequence, caller}).
    // The leaves are canonical where they are produced (argument constraints,
    // a Bytes<8> cell read), so `constrain_canonical` is not re-emitted — see
    // `events_borsh`'s note; the bytes are pinned against compactc's artifact
    // in tests/xcontract_events_differential.rs.
    let event = DepositEvent {
        amount: minocrab_std::v3::Uint::from_field(a),
        sequence: minocrab_std::v3::Uint::from_field(sequence),
        recipient: cal,
    };
    let payload = borsh::to_bytes::<PAYLOAD_SIZE, Public, _>(c, &event);

    // eventHash = persistentHash<Bytes<256>>(payload) — over the WHOLE
    // envelope, Borsh bytes and zero pad alike, as deployed.
    let alignment = BytesN::<Public, PAYLOAD_SIZE>::alignment();
    let limbs: Vec<_> = payload.limbs().iter().map(|w| w.erase()).collect();
    let digest = c.persistent_hash(alignment, &limbs);
    let event_hash = B32::from_typed(c, digest);

    emit(
        c,
        one,
        &set_insert(EMITTED_DEPOSITS, &b32_ledger_value(&event_hash)),
    );

    // emit (Misc { name: pad(32, "deposit"), payload }) — LEN is exactly 288,
    // so this envelope has no pad: it is the plain Borsh encoding.
    let misc = Misc {
        name: crate::events_borsh::event_name_literal(c, EVENT_NAME),
        payload,
    };
    let misc = borsh::to_bytes::<MISC_SIZE, Public, _>(c, &misc);
    let misc_val = LedgerValue::bytes(
        MISC_SIZE as u32,
        misc.limbs().iter().map(|&w| ImpactElem::Wire(w)).collect(),
    );
    emit(c, one, &emit_event(MISC_VERSION, MISC_TAG, &misc_val));

    event_hash
}
