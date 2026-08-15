//! `signet-contract` (signet-midnight-integration) — the Signet singleton,
//! the central Sig Network contract on Midnight that the erc20-vault calls
//! cross-contract. Three stateless, unauthenticated emit-only circuits
//! (verification is deliberately the reader's job — see the Compact
//! original's header):
//!
//! ```text
//! signBidirectional(requestId: Bytes<32>, notification: { version: Uint<8>, payload: Bytes<128> }):
//!   emit (Misc { name: pad(32, "SignBidirectionalEvent"),
//!                payload: Bytes[version, ...requestId, ...payload, ...zeros(95)] })
//! respond(requestId, { signature: { bigR: {x, y}, s, recoveryId } }):
//!   emit (Misc { name: pad(32, "SignatureRespondedEvent"),
//!                payload: Bytes[...requestId, ...x, ...y, ...s, recoveryId, ...zeros(127)] })
//! respondBidirectional(requestId, { signature }):  — identical shape,
//!   name pad(32, "RespondBidirectionalEvent")
//! ```
//!
//! No ledger fields, no witnesses; every argument is disclosed into the
//! 256-byte event payload. `Misc` is the same tag-10 event as the events
//! experiment (name(32) ‖ payload(256) = 288 serialized bytes).

use minocrab::v3::Circuit3;
use minocrab::{Private, Public};
use minocrab_ledger::{emit, emit_event, ImpactElem, LedgerValue};
use minocrab_std::v3::{circuit, Serializer, Uint, B32};
use signet_signer_interface::{AffinePoint, RequestId, SignBidirectionalEventNotification};

use crate::events::{MISC_SIZE, MISC_TAG, MISC_VERSION};

/// The three event names, `pad(32, …)`.
pub const SIGN_BIDIRECTIONAL_EVENT: &str = "SignBidirectionalEvent";
pub const SIGNATURE_RESPONDED_EVENT: &str = "SignatureRespondedEvent";
pub const RESPOND_BIDIRECTIONAL_EVENT: &str = "RespondBidirectionalEvent";

fn disclose_b32(c: &mut Circuit3, b: &B32<Private>, label: &str) -> B32<Public> {
    B32 {
        hi: c.disclose(b.hi, &format!("{label} (hi)")),
        lo: c.disclose(b.lo, &format!("{label} (lo)")),
    }
}

/// `emit (Misc { name: pad(32, name), payload })` — the serializer holds
/// name ‖ payload bytes, zero-padded to the 288-byte Misc.
fn emit_misc(c: &mut Circuit3, s: Serializer<Public>) {
    let one = c.constant(1u64);
    let serialized = s.finish::<MISC_SIZE>(c);
    let payload = LedgerValue::bytes(
        MISC_SIZE as u32,
        serialized.limbs().iter().map(|&w| ImpactElem::Wire(w)).collect(),
    );
    emit(c, one, &emit_event(MISC_VERSION, MISC_TAG, &payload));
}

fn misc_name(c: &mut Circuit3, name: &str) -> Serializer<Public> {
    let mut padded = [0u8; 32];
    padded[..name.len()].copy_from_slice(name.as_bytes());
    let mut s = Serializer::<Public>::new();
    s.push_literal(c, &padded);
    s
}

/// `export circuit signBidirectional(requestId: RequestId,
/// notification: SignBidirectionalEventNotification): []`
///
/// The notification's type comes from `signet-signer-interface` — THE
/// CRATE THIS CONTRACT'S OWN CALLERS IMPORT. There is one declaration of
/// the record, used at `Private` here (the callee witnesses its arguments)
/// and at `Public` by every caller, so the two sides of the wire cannot
/// disagree about its layout; `tests/contract_matches_its_interface.rs`
/// checks the whole signature the same way.
#[circuit]
pub fn sign_bidirectional(
    c: &mut Circuit3,
    request_id: B32<Private>,
    notification: SignBidirectionalEventNotification<Private>,
) {
    let version = notification.version.field();
    let payload = notification.payload;

    let rid = disclose_b32(c, &request_id, "requestId");
    let version = c.disclose(version, "notification.version");
    let payload = payload.map_limbs(|i, w| c.disclose(w, &format!("notification.payload ({i})")));

    // payload: version(1) ‖ requestId(32) ‖ notification.payload(128) ‖ zeros(95)
    c.region("event serialize + emit", |c| {
        let mut s = misc_name(c, SIGN_BIDIRECTIONAL_EVENT);
        s.push_uint(version, 1);
        s.push_b32(&rid);
        s.push_bytes_n(&payload);
        emit_misc(c, s);
    });
}

/// The shared body of `respond`/`respondBidirectional`: only the event
/// name differs.
///
/// The arguments are the interface crate's own types — `AffinePoint` for
/// `bigR`, `RequestId` for the id — but ONE LEVEL FLATTER than the Compact
/// signature, which wraps them in `{ signature: { bigR, s, recoveryId } }`.
/// The wrapper carries no slot and no label of its own in the hand-written
/// declarations the interface snapshot froze (`bigR_x_hi`, not
/// `signatureRespondedEvent_signature_bigR_x_hi`), and `#[arg(name)]` can
/// rename a path segment but not delete one — the same trade [`crate::erc20_vault::claim`]
/// documents. So the port keeps the fields at the head of the parameter
/// list: zero movement, and the types are still the crate's.
/// `tests/contract_matches_its_interface.rs` checks the resulting IR against
/// `SignatureRespondedEvent`'s schema slot for slot, as it did when these
/// nine slots were raw `c.arg` calls.
fn respond_like(
    c: &mut Circuit3,
    name: &str,
    request_id: RequestId<Private>,
    big_r: AffinePoint<Private>,
    s_scalar: B32<Private>,
    recovery_id: Uint<8>,
) {
    let recovery_id = recovery_id.field();

    let rid = disclose_b32(c, &request_id, "requestId");
    let x = disclose_b32(c, &big_r.x, "signature.bigR.x");
    let y = disclose_b32(c, &big_r.y, "signature.bigR.y");
    let s_scalar = disclose_b32(c, &s_scalar, "signature.s");
    let recovery_id = c.disclose(recovery_id, "signature.recoveryId");

    // payload: requestId(32) ‖ x(32) ‖ y(32) ‖ s(32) ‖ recoveryId(1) ‖ zeros(127)
    c.region("event serialize + emit", |c| {
        let mut s = misc_name(c, name);
        s.push_b32(&rid);
        s.push_b32(&x);
        s.push_b32(&y);
        s.push_b32(&s_scalar);
        s.push_uint(recovery_id, 1);
        emit_misc(c, s);
    });
}

/// `export circuit respond(requestId: RequestId, signatureRespondedEvent:
/// SignatureRespondedEvent): []` — see [`respond_like`] for why the event's
/// three fields are the parameter list.
#[circuit]
pub fn respond(
    c: &mut Circuit3,
    request_id: RequestId<Private>,
    big_r: AffinePoint<Private>,
    s: B32<Private>,
    recovery_id: Uint<8>,
) {
    respond_like(c, SIGNATURE_RESPONDED_EVENT, request_id, big_r, s, recovery_id);
}

/// `export circuit respondBidirectional(requestId: RequestId,
/// respondBidirectionalEvent: RespondBidirectionalEvent): []` — the same
/// nine slots under a different event name.
#[circuit]
pub fn respond_bidirectional(
    c: &mut Circuit3,
    request_id: RequestId<Private>,
    big_r: AffinePoint<Private>,
    s: B32<Private>,
    recovery_id: Uint<8>,
) {
    respond_like(c, RESPOND_BIDIRECTIONAL_EVENT, request_id, big_r, s, recovery_id);
}
