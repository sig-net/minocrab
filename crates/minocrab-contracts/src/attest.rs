//! `attest` (signet-midnight-experiments/experiments/attest) — MPC
//! attestation verification.
//!
//! Compact original:
//! ```text
//! export ledger callCount: Counter;                 // field 0
//! export ledger verified: Map<Bytes<32>, Boolean>;  // field 1
//!
//! mapOnly(requestId):    callCount.increment(1); verified.insert(disclose(requestId), true)
//! verifyOnly(requestId, digest, r, s, pk):
//!     callCount.increment(1);
//!     assert(secp256k1EcdsaVerify(digest, {r as Secp256k1Scalar, s as ..}, pk));
//!     verified.insert(disclose(requestId), true)
//! ```
//! (`shaVerify`/`keccakVerify` additionally hash the attested output and
//! deserialize a RespondOutput; they land once the serialize<T,N> byte
//! layout is ported.)

use minocrab::v3::{Circuit3, Compiled3, FieldT, Secp256k1PointT};
use minocrab::{Fr, Private};
use minocrab_ledger::{counter_increment, emit, map_insert, ImpactElem, LedgerValue};
use minocrab_std::v3::{secp256k1_ecdsa_verify, Secp256k1EcdsaSignature, B32};

/// Ledger field indices, in declaration order.
const CALL_COUNT: u8 = 0;
const VERIFIED: u8 = 1;

/// Declare a `Bytes<32>` circuit argument (two native slots). All
/// arguments must be declared before any instruction, so the 8/248-bit
/// input constraints are applied separately once declarations are done.
fn bytes32_arg(c: &mut Circuit3, label: &str) -> B32<Private> {
    let hi = c.arg::<FieldT>(&format!("{label}_hi"));
    let lo = c.arg::<FieldT>(&format!("{label}_lo"));
    B32 { hi, lo }
}

/// The shared tail: `verified.insert(disclose(requestId), true)` plus the
/// call-count increment, emitted in source order (increment first).
fn ledger_writes(c: &mut Circuit3, request_id: &B32<Private>) {
    let r_hi = c.disclose(request_id.hi, "attested request id (hi)");
    let r_lo = c.disclose(request_id.lo, "attested request id (lo)");
    let one = c.constant(1u64);

    let key = LedgerValue::bytes(32, vec![ImpactElem::Wire(r_hi), ImpactElem::Wire(r_lo)]);
    let true_val = LedgerValue::bytes(1, vec![ImpactElem::Imm(Fr::from(1u64))]);
    let mut ops = counter_increment(CALL_COUNT, 1);
    ops.extend(map_insert(VERIFIED, &key, &true_val));
    emit(c, one, &ops);
}

/// `export circuit mapOnly(requestId: Bytes<32>): []`
pub fn map_only() -> Compiled3 {
    let mut c = Circuit3::new();
    let request_id = bytes32_arg(&mut c, "requestId");
    request_id.constrain_input(&mut c);
    c.region("ledger writes", |c| ledger_writes(c, &request_id));
    c.finish(true)
}

/// `export circuit verifyOnly(requestId, digest, r, s, pk): []`
pub fn verify_only() -> Compiled3 {
    let mut c = Circuit3::new();
    let request_id = bytes32_arg(&mut c, "requestId");
    let digest = bytes32_arg(&mut c, "digest");
    let r = bytes32_arg(&mut c, "r");
    let s = bytes32_arg(&mut c, "s");
    let pk = c.arg::<Secp256k1PointT>("pk");
    for b in [&request_id, &digest, &r, &s] {
        b.constrain_input(&mut c);
    }

    let ok = c.region("signature verification", |c| {
        // `r as Secp256k1Scalar` / `s as ..`: Bytes<32> → typed bytes →
        // mod-n reduction (notes/builtin-lowering.org §8).
        let r_typed = r.to_typed(c);
        let s_typed = s.to_typed(c);
        let sig = Secp256k1EcdsaSignature {
            r: c.from_bytes32(r_typed),
            s: c.from_bytes32(s_typed),
        };
        secp256k1_ecdsa_verify(c, &digest, &sig, pk)
    });
    c.assert(ok); // "attestation signature invalid"

    c.region("ledger writes", |c| ledger_writes(c, &request_id));
    c.finish(true)
}

/// The ledger field indices (callCount, verified), for reference
/// transcripts in tests.
pub const FIELDS: (u8, u8) = (CALL_COUNT, VERIFIED);
