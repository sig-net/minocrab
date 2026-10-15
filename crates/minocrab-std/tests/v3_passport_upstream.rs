//! The helpers lifted from the passport account custody port (PR #184) and
//! its cost study: each is checked against the thing it replaces.
//!
//! - `hash::Preimage`'s constant fold against the in-circuit hash;
//! - `base64url_32` against a native encoder;
//! - `JubjubPoint::times_cofactor` against `ecMul(p, 8)`, and the
//!   identity / small-order predicates on the identity and the generator;
//! - `Check::implies` on its truth table;
//! - `kernel::caller` against compactc 0.35.0's lowering, byte for byte.

use std::borrow::Cow;

use midnight_curves::pairing::group::Group;
use midnight_curves::{Fr as JubjubFr, JubjubSubgroup};
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage};
use midnight_zkir_v3::ir_instructions::ec_mul::ec_mul_offcircuit;
use midnight_zkir_v3::ir_instructions::encode::encode_offcircuit;
use minocrab::v3::{Circuit3, FieldT, JubjubPointT};
use minocrab::{Alignment, AlignmentAtom, AlignmentSegment, Fr, Private};
use minocrab_sim::v3::simulate;
use minocrab_std::v3::hash::{persistent_hash_compact, Preimage};
use minocrab_std::v3::{base64url_32, is_true, kernel, Bool, JubjubPoint, B32};
use minocrab_zkir::v3::{to_zkir_string, IrValue};

fn preimage(inputs: Vec<Fr>) -> ProofPreimage {
    ProofPreimage {
        inputs,
        private_transcript: vec![],
        public_transcript_inputs: vec![],
        public_transcript_outputs: vec![],
        binding_input: 0.into(),
        communications_commitment: None,
        key_location: KeyLocation(Cow::Borrowed("minocrab-std-v3-passport-upstream")),
    }
}

fn natives(v: &IrValue) -> Vec<Fr> {
    encode_offcircuit(v)
        .into_iter()
        .map(|x| match x {
            IrValue::Native(f) => f,
            other => panic!("encode produced non-native {other:?}"),
        })
        .collect()
}

fn outputs(c: Circuit3, inputs: Vec<Fr>) -> Vec<Fr> {
    let compiled = c.finish(false);
    let run = simulate(&compiled.ir, &preimage(inputs)).expect("the circuit accepts");
    run.outputs
        .iter()
        .map(|v| match v {
            IrValue::Native(fr) => *fr,
            other => panic!("expected a native output, got {other:?}"),
        })
        .collect()
}

fn emit_b32(c: &mut Circuit3, b: B32<Private>) {
    let hi = c.disclose(b.hi, "hi");
    c.output(hi, "hi");
    let lo = c.disclose(b.lo, "lo");
    c.output(lo, "lo");
}

fn b32_limbs(bytes: &[u8; 32]) -> (Fr, Fr) {
    (
        Fr::from(u64::from(bytes[31])),
        Fr::from_le_bytes(&bytes[..31]).expect("31 bytes fit"),
    )
}

// ---- the constant fold -------------------------------------------------------

#[test]
fn constant_persistent_hash_matches_the_circuit() {
    let mut tag = [0u8; 32];
    tag[..19].copy_from_slice(b"midnight:test:tag:v");
    let body = [0x5au8; 32];

    // Folded: every slot an immediate, hashed here, two Copies emitted.
    let mut folded = Circuit3::new();
    let digest = Preimage::<Private>::tag("midnight:test:tag:v")
        .bytes_const(&body)
        .hash(&mut folded);
    emit_b32(&mut folded, digest);
    let compiled = folded.finish(false);
    assert!(
        !compiled.ir.instructions.iter().any(|i| format!("{i:?}").starts_with("PersistentHash")),
        "an all-constant preimage must not emit persistent_hash"
    );
    let folded: Vec<Fr> = simulate(&compiled.ir, &preimage(vec![]))
        .expect("accepts")
        .outputs
        .iter()
        .map(|v| match v {
            IrValue::Native(fr) => *fr,
            other => panic!("{other:?}"),
        })
        .collect();

    // In-circuit: the same limbs as wires.
    let mut live = Circuit3::new();
    let (t_hi, t_lo) = b32_limbs(&tag);
    let (b_hi, b_lo) = b32_limbs(&body);
    let slots: Vec<_> = [t_hi, t_lo, b_hi, b_lo]
        .into_iter()
        .map(|f| live.constant(f).private().erase())
        .collect();
    let alignment = Alignment(vec![
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
    ]);
    let digest = persistent_hash_compact(&mut live, alignment, &slots);
    emit_b32(&mut live, digest);
    let circuit = outputs(live, vec![]);

    assert_eq!(folded, circuit, "the fold and the chip disagree on a 2 x bytes<32> preimage");
}

#[test]
fn constant_blob_fold_matches_the_circuit() {
    let mut tag = [0u8; 64];
    let text = b"midnight:account:auth:k1:v1:withdraw_unshielded";
    tag[..text.len()].copy_from_slice(text);

    let mut folded = Circuit3::new();
    let digest = Preimage::<Private>::new().blob_const(&tag).hash(&mut folded);
    emit_b32(&mut folded, digest);
    let folded = outputs(folded, vec![]);

    let mut live = Circuit3::new();
    let blob = minocrab_std::v3::BytesN::<Private, 64>::literal(&mut live, &tag);
    let digest = Preimage::<Private>::new().blob(&blob).hash(&mut live);
    emit_b32(&mut live, digest);
    let circuit = outputs(live, vec![]);

    assert_eq!(folded, circuit, "the fold and the chip disagree on a bytes<64> preimage");
}

// ---- base64url ------------------------------------------------------------------

fn native_base64url(bytes: &[u8; 32]) -> [u8; 43] {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::with_capacity(43);
    for chunk in bytes.chunks(3) {
        let mut g = 0u32;
        for (i, b) in chunk.iter().enumerate() {
            g |= u32::from(*b) << (16 - 8 * i);
        }
        let n = chunk.len() + 1;
        for i in 0..n {
            out.push(ALPHABET[((g >> (18 - 6 * i)) & 63) as usize]);
        }
    }
    out.try_into().expect("43 characters")
}

#[test]
fn base64url_32_matches_a_native_encoder() {
    let mut cases: Vec<[u8; 32]> = vec![[0u8; 32], [0xff; 32], [0x3f; 32]];
    let mut x = 0x9e3779b97f4a7c15u64;
    for _ in 0..6 {
        let mut b = [0u8; 32];
        for byte in b.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *byte = x as u8;
        }
        cases.push(b);
    }
    // Every alphabet row and the two padding boundaries, in one value.
    let mut sweep = [0u8; 32];
    for (i, b) in sweep.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37).wrapping_add(11);
    }
    cases.push(sweep);

    for bytes in cases {
        let mut c = Circuit3::new();
        let hi = c.arg::<FieldT>("hi");
        let lo = c.arg::<FieldT>("lo");
        let value = B32 { hi, lo }.constrain_input(&mut c);
        let text = base64url_32(&mut c, &value);
        for (i, limb) in text.limbs().iter().enumerate() {
            let w = c.disclose(*limb, "limb");
            c.output(w, &format!("limb{i}"));
        }
        let (hi, lo) = b32_limbs(&bytes);
        let got = outputs(c, vec![hi, lo]);
        let want = native_base64url(&bytes);
        // Slot order: the 12-byte leftover (characters 31..43) first.
        let expect = vec![
            Fr::from_le_bytes(&want[31..43]).unwrap(),
            Fr::from_le_bytes(&want[..31]).unwrap(),
        ];
        assert_eq!(
            got,
            expect,
            "base64url of {bytes:02x?} should be {:?}",
            std::str::from_utf8(&want).unwrap()
        );
    }
}

// ---- JubJub ---------------------------------------------------------------------

fn jubjub_point(scalar: u64) -> IrValue {
    ec_mul_offcircuit(
        &IrValue::JubjubPoint(JubjubSubgroup::generator()),
        &IrValue::JubjubScalar(JubjubFr::from(scalar)),
    )
    .expect("a generator multiple")
}

#[test]
fn times_cofactor_is_ec_mul_by_eight() {
    for scalar in [1u64, 2, 7, 0xdead_beef, u64::MAX] {
        let mut c = Circuit3::new();
        let p = JubjubPoint::from_point(c.arg::<JubjubPointT>("p"));
        let doubled = p.times_cofactor(&mut c);
        let eight = c.constant(8u64).private();
        let eight = c.jubjub_scalar_from_native(eight);
        let multiplied = c.ec_mul(p.point(), eight);
        c.assert_eq(doubled.point(), multiplied);
        let compiled = c.finish(false);
        simulate(&compiled.ir, &preimage(natives(&jubjub_point(scalar))))
            .unwrap_or_else(|e| panic!("[8]p by doublings differs from ecMul(p, 8) at scalar {scalar}: {e}"));
    }
}

#[test]
fn identity_and_small_order_predicates() {
    let identity = IrValue::JubjubPoint(JubjubSubgroup::default());
    let generator = jubjub_point(1);

    let mut c = Circuit3::new();
    let p = JubjubPoint::from_point(c.arg::<JubjubPointT>("p"));
    let is_id = p.is_identity(&mut c);
    let w = c.disclose(is_id.field(), "id");
    c.output(w, "is_identity");
    let compiled = c.finish(false);
    let run = |v: &IrValue| {
        simulate(&compiled.ir, &preimage(natives(v))).expect("accepts").outputs[0].clone()
    };
    assert_eq!(run(&identity), IrValue::Native(Fr::from(1u64)), "the identity is (0, 1)");
    assert_eq!(run(&generator), IrValue::Native(Fr::from(0u64)), "the generator is not");

    let mut c = Circuit3::new();
    let p = JubjubPoint::from_point(c.arg::<JubjubPointT>("p"));
    p.assert_not_small_order(&mut c);
    let compiled = c.finish(false);
    assert!(simulate(&compiled.ir, &preimage(natives(&identity))).is_err(), "the identity is rejected");
    assert!(simulate(&compiled.ir, &preimage(natives(&generator))).is_ok(), "the generator is live");
    assert!(simulate(&compiled.ir, &preimage(natives(&jubjub_point(0xf00d)))).is_ok());
}

// ---- implies ----------------------------------------------------------------------

#[test]
fn implies_truth_table() {
    let mut c = Circuit3::new();
    let a = c.arg::<FieldT>("a");
    let b = c.arg::<FieldT>("b");
    let a = Bool::from_field_unchecked(a).constrain_input(&mut c);
    let b = Bool::from_field_unchecked(b).constrain_input(&mut c);
    c.assert(is_true(a).implies(is_true(b)).message("a implies b"));
    let compiled = c.finish(false);
    let one_select = compiled
        .ir
        .instructions
        .iter()
        .filter(|i| format!("{i:?}").starts_with("CondSelect"))
        .count();
    assert_eq!(one_select, 1, "implies is ONE select");
    for (a, b, holds) in [(0u64, 0u64, true), (0, 1, true), (1, 0, false), (1, 1, true)] {
        let ok = simulate(&compiled.ir, &preimage(vec![Fr::from(a), Fr::from(b)])).is_ok();
        assert_eq!(ok, holds, "{a} → {b}");
    }
}

// ---- kernel.caller ------------------------------------------------------------------

#[test]
fn kernel_caller_is_compactc_0_35_0_byte_for_byte() {
    let mut c = Circuit3::new();
    let _ = kernel::caller(&mut c);
    let json: serde_json::Value =
        serde_json::from_str(&to_zkir_string(&c.finish(false).ir).expect("IR serializes")).unwrap();
    let impacts: Vec<Vec<String>> = json["instructions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["op"] == "impact")
        .map(|i| i["inputs"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect())
        .collect();
    let publics = json["instructions"].as_array().unwrap().iter().filter(|i| i["op"] == "public_input").count();
    assert_eq!(publics, 6, "Maybe<Either<ContractAddress, UserAddress>> is six public inputs");

    // passport account.compact, `withdraw_unshielded_with_grant_jubjub`,
    // instructions 102-115 of the compactc 0.35.0 artifact.
    let hex = |s: &str| s.split(' ').map(str::to_string).collect::<Vec<_>>();
    let expected = [
        hex("0x32"),
        hex("0x60 0x01 0x01 0x06"),
        hex("0x30"),
        hex("0x03"),
        hex("0x10 0x01 0x01 0x01 0x01"),
        hex("0x02"),
        hex("0x12 0x04"),
        hex("0x10 0x01 0x01 0x01 0x01"),
        hex("0x40"),
        hex("0x16 0x50"),
        hex("0x13 0x02"),
        hex("0x0b"),
        hex("0x10 0x01 0x04 0x01 0x01 0x20 0x20 0x00 0x00 0x00 0x00 0x00 0x00"),
    ];
    assert_eq!(impacts.len(), expected.len() + 1, "thirteen ops and the popeq");
    for (i, (got, want)) in impacts.iter().zip(expected.iter()).enumerate() {
        assert_eq!(got, want, "impact op {i} differs from compactc's");
    }
    let popeq = &impacts[expected.len()];
    assert_eq!(&popeq[..6], &hex("0x0d 0x04 0x01 0x01 0x20 0x20")[..], "popeqc over [bool, bool, bytes<32>, bytes<32>]");
    assert_eq!(popeq.len(), 12, "six wires follow the alignment");
}
