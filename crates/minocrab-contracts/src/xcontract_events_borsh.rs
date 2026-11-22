//! `xcontract-events`, through the Borsh API — the twin of
//! [`crate::xcontract_events`].
//!
//! Same discipline as [`crate::events_borsh`]: the original is pinned and
//! differential-green against compactc, this twin emits the same bytes and
//! builds them out of declared types. What makes this the more interesting of
//! the two twins is that the payload is materialised — the token hashes it
//! (`persistentHash<Bytes<256>>(payload)`) and returns the digest across a
//! cross-contract call — so both halves of the padding rule are exercised on
//! one shape:
//!
//! - `payload = to_bytes::<256>(DepositEvent)` — 56 Borsh bytes then 200 zero
//!   bytes, and it is those 256 bytes that are hashed, exactly as deployed;
//! - `misc = to_bytes::<288>(Misc { name, payload })` — here `LEN == 288`
//!   exactly, so there is no pad at all: the envelope is the Borsh encoding
//!   of a `{[u8; 32], [u8; 256]}` struct.
//!
//! The caller side (`depositViaVault`) serializes nothing and is not twinned:
//! it would be a byte-for-byte copy of a circuit this stage has no opinion
//! about, and the harness would learn nothing from it.

use minocrab::Circuit;
use minocrab::{Private, Public};
use minocrab_experimental::impact::raw::{
    cell_write, counter_increment, counter_read, emit, set_insert, ImpactElem,
    LedgerValue,
};
// `CircuitBorsh` names both the trait and the derive macro.
use minocrab_std::borsh::{self, CircuitBorsh};
use minocrab_std::{contract, event, BytesN, ContractAddress, Disclose, Discloses, Uint, Vis, B32};

use crate::events::{MISC_SIZE, MISC_TAG, MISC_VERSION};
use crate::events_borsh::DepositEvent;
// The labels are the original's: same callee, same two disclosed values.
use crate::xcontract_events::{
    Amount, Caller, DEPOSIT_COUNT, EMITTED_DEPOSITS, EVENT_NAME, LAST_AMOUNT, PAYLOAD_SIZE,
};

/// `Misc { name: Bytes<32>, payload: Bytes<256> }` — 288 Borsh bytes, the
/// deployed envelope declared exactly as it is: a name and an opaque
/// fixed-width payload slot, whose contents are `borsh(DepositEvent)`
/// followed by the payload's own zero pad.
#[derive(CircuitBorsh)]
pub struct Misc<V: Vis> {
    pub name: B32<V>,
    pub payload: BytesN<V, PAYLOAD_SIZE>,
}

fn b32_ledger_value(b: &B32<Public>) -> LedgerValue {
    LedgerValue::bytes(32, vec![ImpactElem::Wire(b.hi), ImpactElem::Wire(b.lo)])
}

/// `xcontract-events`, through the Borsh API — the token-side callee.
pub struct XcontractEventsBorsh;

#[contract(lowering = minocrab_compat::profile)]
impl XcontractEventsBorsh {
    /// `export circuit deposit(amount: Uint<128>, caller: ContractAddress):
    /// Bytes<32>` — the token-side callee, with both serializations built from
    /// declared types.
    #[circuit(output = "event hash")]
    pub fn token_deposit(
        c: &mut Circuit,
        amount: Uint<128>,
        caller: ContractAddress<Private>,
    ) -> Discloses<(Amount, Caller), B32<Public>> {
        let caller = caller.bytes();
        let a = amount.disclose_as::<Amount>(c).field();
        let cal = caller.disclose_as::<Caller>(c);
        // The `one` compactc threads, unused here: dropping this `Copy` would
        // renumber every later identifier, moving the ZKIR (notes/edsl-trim.org §B).
        let _ = c.constant(1u64);

        // const sequence = depositCount as Uint<64> — read before the increment.
        let sequence = counter_read(c, DEPOSIT_COUNT);
        emit(c, &counter_increment(DEPOSIT_COUNT, 1));
        let amount_val = LedgerValue::bytes(16, vec![ImpactElem::Wire(a)]);
        emit(c, &cell_write(LAST_AMOUNT, &amount_val));

        // payload = serialize<DepositEvent, 256>({amount, sequence, caller}).
        // The leaves are canonical where they are produced (argument constraints,
        // a Bytes<8> cell read), so `constrain_canonical` is not re-emitted — see
        // `events_borsh`'s note; the bytes are pinned against compactc's artifact
        // in tests/xcontract_events_differential.rs.
        let event = DepositEvent {
            amount: minocrab_std::Uint::from_field_unchecked(a),
            sequence: minocrab_std::Uint::from_field_unchecked(sequence),
            recipient: cal,
        };
        let payload = borsh::to_bytes::<PAYLOAD_SIZE, Public, _>(c, &event);

        // eventHash = persistentHash<Bytes<256>>(payload) — over the whole
        // envelope, Borsh bytes and zero pad alike, as deployed.
        let alignment = BytesN::<Public, PAYLOAD_SIZE>::alignment();
        let limbs: Vec<_> = payload.limbs().iter().map(|w| w.erase()).collect();
        let digest = c.persistent_hash(alignment, &limbs);
        let event_hash = B32::from_typed(c, digest);

        emit(
            c,
            &set_insert(EMITTED_DEPOSITS, &b32_ledger_value(&event_hash)),
        );

        // emit (Misc { name: pad(32, "deposit"), payload }) — LEN is exactly 288,
        // so this envelope has no pad: it is the plain Borsh encoding.
        let misc = Misc {
            name: crate::events_borsh::event_name_literal(c, EVENT_NAME),
            payload,
        };
        let misc = borsh::to_bytes::<MISC_SIZE, Public, _>(c, &misc);
        event::emit(c, MISC_VERSION, MISC_TAG, &misc);

        Discloses::of(event_hash)
    }
}
