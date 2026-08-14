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
//! `shaVerify`/`keccakVerify` additionally hash the attested output —
//! `digest = persistentHash/keccak256<[Bytes<32>, Bytes<128>]>([requestId,
//! output])` — and read the packed output back with `deserialize
//! <RespondOutput, 128>` (`struct RespondOutput { success: Boolean;
//! amount: Uint<128>; recipient: Bytes<20> }`, 37 packed bytes,
//! zero-padded), asserting `out.success`.

use minocrab::v3::{Circuit3, Compiled3, FieldT, Secp256k1PointT, Wire3};
use minocrab::{Alignment, AlignmentAtom, AlignmentSegment, Fr, Private};
use minocrab_ledger::{counter_increment, emit, map_insert, ImpactElem, LedgerValue};
use minocrab_std::v3::{
    rebuild_limb, secp256k1_ecdsa_verify, BytesN, Secp256k1EcdsaSignature, Vis3, B32,
};

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

/// `struct RespondOutput { success: Boolean; amount: Uint<128>;
/// recipient: Bytes<20> }` as circuit wires.
pub struct RespondOutput<V: Vis3> {
    pub success: Wire3<FieldT, V>,
    pub amount: Wire3<FieldT, V>,
    pub recipient: Wire3<FieldT, V>,
}

/// `deserialize<RespondOutput, 128>(output)` (expand-serialize.ss
/// build-deserialize): `success = (byte 0 == 1)`, `amount = bytes 1..17`
/// (Uint<128>, LE), `recipient = bytes 17..37` (`Bytes<20>`, one limb);
/// the 91 padding bytes are ignored.
fn deserialize_respond_output<V: Vis3>(
    c: &mut Circuit3,
    output: &BytesN<V, 128>,
) -> RespondOutput<V> {
    let bytes = output.to_le_bytes(c);
    let one = V::from_public(c.constant(1u64));
    RespondOutput {
        success: c.test_eq(bytes[0], one),
        amount: rebuild_limb(c, &bytes[1..17]),
        recipient: rebuild_limb(c, &bytes[17..37]),
    }
}

/// The shared body of `shaVerify` / `keccakVerify`, parameterized by the
/// digest hash.
fn hash_verify(
    hash: impl FnOnce(
        &mut Circuit3,
        Alignment,
        &[minocrab::v3::AnyWire3<Private>],
    ) -> Wire3<minocrab::v3::Bytes32T, Private>,
) -> Compiled3 {
    let mut c = Circuit3::new();
    let request_id = bytes32_arg(&mut c, "requestId");
    let output = BytesN::<_, 128>::arg(&mut c, "output");
    let r = bytes32_arg(&mut c, "r");
    let s = bytes32_arg(&mut c, "s");
    let pk = c.arg::<Secp256k1PointT>("pk");
    request_id.constrain_input(&mut c);
    output.constrain_input(&mut c);
    r.constrain_input(&mut c);
    s.constrain_input(&mut c);

    // digest = hash<[Bytes<32>, Bytes<128>]>([requestId, output])
    let digest = c.region("digest", |c| {
        let alignment = Alignment(vec![
            AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
            AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 128 }),
        ]);
        let mut inputs = vec![request_id.hi.erase(), request_id.lo.erase()];
        inputs.extend(output.limbs().iter().map(|w| w.erase()));
        let typed = hash(c, alignment, &inputs);
        B32::from_typed(c, typed)
    });

    let ok = c.region("signature verification", |c| {
        let r_typed = r.to_typed(c);
        let s_typed = s.to_typed(c);
        let sig = Secp256k1EcdsaSignature {
            r: c.from_bytes32(r_typed),
            s: c.from_bytes32(s_typed),
        };
        secp256k1_ecdsa_verify(c, &digest, &sig, pk)
    });
    c.assert(ok); // "attestation signature invalid"

    let out = c.region("deserialize RespondOutput", |c| {
        deserialize_respond_output(c, &output)
    });
    c.assert(out.success); // "respond reported failure"

    c.region("ledger writes", |c| ledger_writes(c, &request_id));
    c.finish(true)
}

/// `export circuit shaVerify(requestId, output, r, s, pk): []`
pub fn sha_verify() -> Compiled3 {
    hash_verify(|c, alignment, inputs| c.persistent_hash(alignment, inputs))
}

/// `export circuit keccakVerify(requestId, output, r, s, pk): []`
pub fn keccak_verify() -> Compiled3 {
    hash_verify(|c, alignment, inputs| c.keccak256(alignment, inputs))
}

/// The ledger field indices (callCount, verified), for reference
/// transcripts in tests.
pub const FIELDS: (u8, u8) = (CALL_COUNT, VERIFIED);
