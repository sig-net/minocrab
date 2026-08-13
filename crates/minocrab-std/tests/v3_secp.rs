//! The v3 stdlib secp256k1 circuits verify real ECDSA signatures and
//! derive real Ethereum addresses, cross-checked against upstream's
//! reference `check()` by the v3 simulator harness.
//!
//! All native-side arithmetic goes through zkir-v3's own off-circuit
//! helpers (`ir_instructions::*_offcircuit`), so the test oracle is
//! Midnight's code, not ours.

use std::borrow::Cow;

use group::Group;
use midnight_curves::k256;
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage};
use midnight_zkir_v3::ir_instructions::add::add_offcircuit;
use midnight_zkir_v3::ir_instructions::ec_mul::ec_mul_offcircuit;
use midnight_zkir_v3::ir_instructions::encode::encode_offcircuit;
use midnight_zkir_v3::ir_instructions::from_bytes32::from_bytes32_offcircuit;
use midnight_zkir_v3::ir_instructions::into_bytes32::into_bytes32_offcircuit;
use midnight_zkir_v3::ir_instructions::into_coordinates::into_coordinates_offcircuit;
use midnight_zkir_v3::ir_instructions::inv::inv_offcircuit;
use midnight_zkir_v3::ir_instructions::mul::mul_offcircuit;
use minocrab::v3::{Circuit3, FieldT, Secp256k1PointT, Secp256k1ScalarT};
use minocrab::{Fr, Private};
use minocrab_std::v3::{secp256k1_ecdsa_verify, secp256k1_ethereum_address, Secp256k1EcdsaSignature, B32};
use minocrab_zkir::v3::{IrType, IrValue};
use sha3::{Digest, Keccak256};

fn scalar(v: u64) -> IrValue {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&v.to_le_bytes());
    from_bytes32_offcircuit(&IrType::Secp256k1Scalar, &bytes).unwrap()
}

fn generator() -> IrValue {
    IrValue::Secp256k1Point(k256::K256::generator())
}

/// Sign `digest` (big-endian, per RFC 6979) with private key `d` and nonce
/// `k`, entirely through upstream's off-circuit ops.
fn sign(digest: &[u8; 32], d: &IrValue, k: &IrValue) -> (IrValue, IrValue, IrValue) {
    // z: the digest as a big-endian integer, reduced mod n.
    let mut le = *digest;
    le.reverse();
    let z = from_bytes32_offcircuit(&IrType::Secp256k1Scalar, &le).unwrap();

    let r_point = ec_mul_offcircuit(&generator(), k).unwrap();
    let (x, _y) = into_coordinates_offcircuit(&r_point).unwrap();
    let IrValue::Bytes32(x_le) = into_bytes32_offcircuit(&x).unwrap() else {
        panic!("into_bytes32 yields Bytes32");
    };
    let r = from_bytes32_offcircuit(&IrType::Secp256k1Scalar, &x_le).unwrap();

    // s = k⁻¹ · (z + r·d)
    let rd = mul_offcircuit(&r, d).unwrap();
    let z_rd = add_offcircuit(&z, &rd).unwrap();
    let k_inv = inv_offcircuit(k).unwrap();
    let s = mul_offcircuit(&k_inv, &z_rd).unwrap();

    let pk = ec_mul_offcircuit(&generator(), d).unwrap();
    (r, s, pk)
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

/// digest → the [hi, lo] Fr pair of its Compact-level Bytes<32> form.
fn digest_slots(digest: &[u8; 32]) -> (Fr, Fr) {
    let hi = Fr::from(u64::from(digest[31]));
    let lo = Fr::from_le_bytes(&digest[..31]).unwrap();
    (hi, lo)
}

fn preimage(inputs: Vec<Fr>) -> ProofPreimage {
    ProofPreimage {
        inputs,
        private_transcript: vec![],
        public_transcript_inputs: vec![],
        public_transcript_outputs: vec![],
        binding_input: 0.into(),
        communications_commitment: None,
        key_location: KeyLocation(Cow::Borrowed("minocrab-std-v3-test")),
    }
}

/// Build the verify circuit once: args msgHash [hi, lo], r, s, pk;
/// output = the boolean verdict.
fn verify_circuit() -> minocrab::v3::Compiled3 {
    let mut c = Circuit3::new();
    let hi = c.arg::<FieldT>("msgHash_hi");
    let lo = c.arg::<FieldT>("msgHash_lo");
    let r = c.arg::<Secp256k1ScalarT>("r");
    let s = c.arg::<Secp256k1ScalarT>("s");
    let pk = c.arg::<Secp256k1PointT>("pk");
    let msg_hash = B32 { hi, lo };
    msg_hash.constrain_input(&mut c);
    let sig = Secp256k1EcdsaSignature { r, s };
    let valid = secp256k1_ecdsa_verify(&mut c, &msg_hash, &sig, pk);
    let valid_pub = c.disclose(valid, "signature verdict");
    c.output(valid_pub, "valid");
    c.finish(false)
}

fn run_verify(digest: &[u8; 32], r: &IrValue, s: &IrValue, pk: &IrValue) -> IrValue {
    let compiled = verify_circuit();
    let (hi, lo) = digest_slots(digest);
    let mut inputs = vec![hi, lo];
    inputs.extend(natives(r));
    inputs.extend(natives(s));
    inputs.extend(natives(pk));
    let run = minocrab_sim::v3::simulate(&compiled.ir, &preimage(inputs))
        .expect("verify circuit simulates");
    run.outputs[0].clone()
}

#[test]
fn ecdsa_verify_accepts_valid_and_rejects_tampered() {
    let digest = Keccak256::digest(b"minocrab test message");
    let digest: [u8; 32] = digest.into();
    let d = scalar(0x1234_5678_9abc_def0);
    let k = scalar(0x0fed_cba9_8765_4321);
    let (r, s, pk) = sign(&digest, &d, &k);

    assert_eq!(run_verify(&digest, &r, &s, &pk), IrValue::Native(Fr::from(1u64)));

    // Tampered s: verdict 0.
    let bad_s = add_offcircuit(&s, &scalar(1)).unwrap();
    assert_eq!(
        run_verify(&digest, &r, &bad_s, &pk),
        IrValue::Native(Fr::from(0u64))
    );

    // Wrong message: verdict 0.
    let other = Keccak256::digest(b"a different message");
    assert_eq!(
        run_verify(&other.into(), &r, &s, &pk),
        IrValue::Native(Fr::from(0u64))
    );

    // High-s malleability twin (r, n - s) also verifies, as documented.
    let neg_s = midnight_zkir_v3::ir_instructions::neg::neg_offcircuit(&s).unwrap();
    assert_eq!(run_verify(&digest, &r, &neg_s, &pk), IrValue::Native(Fr::from(1u64)));
}

#[test]
fn ethereum_address_matches_native_keccak() {
    let d = scalar(0xc0ffee);
    let pk = ec_mul_offcircuit(&generator(), &d).unwrap();

    // Expected address natively: keccak256(X_be ++ Y_be)[12..32].
    let (x, y) = into_coordinates_offcircuit(&pk).unwrap();
    let coord_be = |v: &IrValue| -> [u8; 32] {
        let IrValue::Bytes32(mut le) = into_bytes32_offcircuit(v).unwrap() else {
            panic!("into_bytes32 yields Bytes32");
        };
        le.reverse();
        le
    };
    let mut preimage_bytes = Vec::with_capacity(64);
    preimage_bytes.extend_from_slice(&coord_be(&x));
    preimage_bytes.extend_from_slice(&coord_be(&y));
    let hash: [u8; 32] = Keccak256::digest(&preimage_bytes).into();
    // The circuit returns the Bytes<20> as one slot: bytes 12..31 of the
    // digest — but slot order is little-endian over the *digest's* byte
    // index, i.e. Fr::from_le_bytes(hash[12..32]).
    let expected = Fr::from_le_bytes(&hash[12..32]).unwrap();

    let mut c = Circuit3::new();
    let pk_wire = c.arg::<Secp256k1PointT>("pk");
    let addr = secp256k1_ethereum_address(&mut c, pk_wire);
    let addr_pub = c.disclose(addr, "ethereum address");
    c.output(addr_pub, "address");
    let compiled = c.finish(false);

    let run = minocrab_sim::v3::simulate(&compiled.ir, &preimage(natives(&pk)))
        .expect("address circuit simulates");
    assert_eq!(run.outputs[0], IrValue::Native(expected));
}
