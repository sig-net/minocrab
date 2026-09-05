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

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{label, Alignment, AlignmentAtom, AlignmentSegment, Fr, Private};
use minocrab_ledger::{counter_increment, emit, map_insert, ImpactElem, LedgerValue};
use minocrab_std::v3::{
    contract, rebuild_limb, secp256k1_ecdsa_verify, BytesN, Disclose, Discloses,
    Secp256k1EcdsaSignature, Secp256k1Point, Vis3, B32,
};

/// Ledger field indices, in declaration order.
const CALL_COUNT: u8 = 0;
const VERIFIED: u8 = 1;

label! {
    /// The map key every circuit here makes public — one label for the whole
    /// `Bytes<32>`, where the hand-written calls said `"… (hi)"` / `"… (lo)"`.
    AttestedRequestId = "attested request id";
}

/// The shared tail: `verified.insert(disclose(requestId), true)` plus the
/// call-count increment, emitted in source order (increment first).
fn ledger_writes(c: &mut Circuit3, request_id: B32<Private>) {
    let request_id = request_id.disclose_as::<AttestedRequestId>(c);
    let one = c.constant(1u64);

    let key = LedgerValue::bytes(
        32,
        vec![ImpactElem::Wire(request_id.hi), ImpactElem::Wire(request_id.lo)],
    );
    let true_val = LedgerValue::bytes(1, vec![ImpactElem::Imm(Fr::from(1u64))]);
    let mut ops = counter_increment(CALL_COUNT, 1);
    ops.extend(map_insert(VERIFIED, &key, &true_val));
    emit(c, one, &ops);
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
/// digest hash. The two circuits differ in the hash builtin alone, so the
/// entry points are two `#[circuit]` functions over one body — an attribute
/// generates a nullary constructor, so a body shared by a Rust PARAMETER
/// cannot itself be one.
fn hash_verify(
    c: &mut Circuit3,
    hash: impl FnOnce(
        &mut Circuit3,
        Alignment,
        &[minocrab::v3::AnyWire3<Private>],
    ) -> Wire3<minocrab::v3::Bytes32T, Private>,
    request_id: B32<Private>,
    output: BytesN<Private, 128>,
    r: B32<Private>,
    s: B32<Private>,
    pk: Secp256k1Point,
) {
    let pk = pk.point();

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

    c.region("ledger writes", |c| ledger_writes(c, request_id));
}

/// MPC attestation verification.
pub struct Attest;

#[contract]
impl Attest {
    /// `export circuit mapOnly(requestId: Bytes<32>): []`
    #[circuit]
    pub fn map_only(c: &mut Circuit3, request_id: B32<Private>) -> Discloses<(AttestedRequestId,)> {
        c.region("ledger writes", |c| ledger_writes(c, request_id));
        Discloses::of(())
    }

    /// `export circuit verifyOnly(requestId, digest, r, s, pk): []`
    #[circuit]
    pub fn verify_only(
        c: &mut Circuit3,
        request_id: B32<Private>,
        digest: B32<Private>,
        r: B32<Private>,
        s: B32<Private>,
        pk: Secp256k1Point,
    ) -> Discloses<(AttestedRequestId,)> {
        let pk = pk.point();

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

        c.region("ledger writes", |c| ledger_writes(c, request_id));
        Discloses::of(())
    }

    /// `export circuit shaVerify(requestId, output, r, s, pk): []`
    #[circuit]
    pub fn sha_verify(
        c: &mut Circuit3,
        request_id: B32<Private>,
        output: BytesN<Private, 128>,
        r: B32<Private>,
        s: B32<Private>,
        pk: Secp256k1Point,
    ) -> Discloses<(AttestedRequestId,)> {
        let hash = |c: &mut Circuit3, alignment, inputs: &[_]| c.persistent_hash(alignment, inputs);
        hash_verify(c, hash, request_id, output, r, s, pk);
        Discloses::of(())
    }

    /// `export circuit keccakVerify(requestId, output, r, s, pk): []`
    #[circuit]
    pub fn keccak_verify(
        c: &mut Circuit3,
        request_id: B32<Private>,
        output: BytesN<Private, 128>,
        r: B32<Private>,
        s: B32<Private>,
        pk: Secp256k1Point,
    ) -> Discloses<(AttestedRequestId,)> {
        let hash = |c: &mut Circuit3, alignment, inputs: &[_]| c.keccak256(alignment, inputs);
        hash_verify(c, hash, request_id, output, r, s, pk);
        Discloses::of(())
    }
}

/// The ledger field indices (callCount, verified), for reference
/// transcripts in tests.
pub const FIELDS: (u8, u8) = (CALL_COUNT, VERIFIED);
