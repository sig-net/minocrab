//! attest: call-compatibility with the corpus artifacts (mapOnly,
//! verifyOnly) per notes/ledger-abi.org §6, plus acceptance-behavior
//! agreement on bad signatures.

use std::borrow::Cow;

use midnight_base_crypto::fab::{
    Alignment, AlignmentAtom, AlignmentSegment, AlignedValue, Value, ValueAtom,
};
use midnight_curves::k256;
use midnight_onchain_state::state::StateValue;
use midnight_onchain_vm::ops::{Key, Op};
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_transient_crypto::hash::transient_commit;
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage};
use midnight_transient_crypto::repr::FieldRepr;
use midnight_zkir_v3::ir_instructions::add::add_offcircuit;
use midnight_zkir_v3::ir_instructions::ec_mul::ec_mul_offcircuit;
use midnight_zkir_v3::ir_instructions::encode::encode_offcircuit;
use midnight_zkir_v3::ir_instructions::from_bytes32::from_bytes32_offcircuit;
use midnight_zkir_v3::ir_instructions::into_bytes32::into_bytes32_offcircuit;
use midnight_zkir_v3::ir_instructions::into_coordinates::into_coordinates_offcircuit;
use midnight_zkir_v3::ir_instructions::inv::inv_offcircuit;
use midnight_zkir_v3::ir_instructions::mul::mul_offcircuit;
use minocrab::Fr;
use minocrab_contracts::attest;
use minocrab_sim::v3::{assert_call_compatible, simulate};
use minocrab_zkir::v3::{IrSource, IrType, IrValue};

type VmOp = Op<ResultModeVerify, InMemoryDB>;

fn corpus_zkir(name: &str) -> IrSource {
    let path = format!(
        "{}/../../corpus/zkir/signet-midnight-experiments/experiments/attest/contract/src/attest/zkir/{name}.zkir",
        env!("CARGO_MANIFEST_DIR")
    );
    minocrab_zkir::v3::read_zkir(&path).expect("corpus golden parses")
}

fn bytes1_value(v: u8) -> AlignedValue {
    AlignedValue::new(
        Value(vec![ValueAtom(vec![v]).normalize()]),
        Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 1 })]),
    )
    .unwrap()
}

fn bytes32_value(bytes: &[u8; 32]) -> AlignedValue {
    AlignedValue::new(
        Value(vec![ValueAtom(bytes.to_vec()).normalize()]),
        Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 })]),
    )
    .unwrap()
}

/// The Impact program both attest circuits perform:
/// callCount.increment(1); verified.insert(requestId, true).
fn attest_transcript(request_id: &[u8; 32]) -> Vec<Fr> {
    let (call_count, verified) = attest::FIELDS;
    let ops: Vec<VmOp> = vec![
        Op::Idx {
            cached: false,
            push_path: true,
            path: vec![Key::Value(bytes1_value(call_count))].into(),
        },
        Op::Addi { immediate: 1 },
        Op::Ins { cached: true, n: 1 },
        Op::Idx {
            cached: false,
            push_path: true,
            path: vec![Key::Value(bytes1_value(verified))].into(),
        },
        Op::Push {
            storage: false,
            value: StateValue::Cell(Sp::new(bytes32_value(request_id))),
        },
        Op::Push {
            storage: true,
            value: StateValue::Cell(Sp::new(bytes1_value(1))),
        },
        Op::Ins { cached: false, n: 1 },
        Op::Ins { cached: true, n: 1 },
    ];
    let mut out = Vec::new();
    for op in &ops {
        op.field_repr(&mut out);
    }
    out
}

/// [hi, lo] Fr slot pair of a Bytes<32>.
fn b32_slots(bytes: &[u8; 32]) -> (Fr, Fr) {
    (
        Fr::from(u64::from(bytes[31])),
        Fr::from_le_bytes(&bytes[..31]).unwrap(),
    )
}

fn preimage(inputs: Vec<Fr>, transcript: Vec<Fr>) -> ProofPreimage {
    let rand = Fr::from(0x5ee_du64);
    let comm = transient_commit(&inputs[..], rand);
    ProofPreimage {
        inputs,
        private_transcript: vec![],
        public_transcript_inputs: transcript,
        public_transcript_outputs: vec![],
        binding_input: 0.into(),
        communications_commitment: Some((comm, rand)),
        key_location: KeyLocation(Cow::Borrowed("minocrab-contracts-test")),
    }
}

#[test]
fn map_only_matches_corpus() {
    let theirs = corpus_zkir("mapOnly");
    let ours = attest::map_only().ir;

    let request_id = {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        b[31] = 0x7f;
        b
    };
    let (hi, lo) = b32_slots(&request_id);
    let pi = preimage(vec![hi, lo], attest_transcript(&request_id));
    assert_call_compatible(&ours, &theirs, &pi);
}

// --- verifyOnly: needs a real ECDSA signature --------------------------------

fn scalar(v: u64) -> IrValue {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&v.to_le_bytes());
    from_bytes32_offcircuit(&IrType::Secp256k1Scalar, &bytes).unwrap()
}

/// Sign `digest` (big-endian integer, RFC 6979) via upstream off-circuit
/// helpers; returns (r_bytes32_le, s_bytes32_le, pk).
fn sign(digest: &[u8; 32], d: &IrValue, k: &IrValue) -> ([u8; 32], [u8; 32], IrValue) {
    let generator = IrValue::Secp256k1Point(k256::K256::generator());
    let mut le = *digest;
    le.reverse();
    let z = from_bytes32_offcircuit(&IrType::Secp256k1Scalar, &le).unwrap();

    let r_point = ec_mul_offcircuit(&generator, k).unwrap();
    let (x, _y) = into_coordinates_offcircuit(&r_point).unwrap();
    let IrValue::Bytes32(x_le) = into_bytes32_offcircuit(&x).unwrap() else {
        panic!("into_bytes32 yields Bytes32");
    };
    let r = from_bytes32_offcircuit(&IrType::Secp256k1Scalar, &x_le).unwrap();

    let rd = mul_offcircuit(&r, d).unwrap();
    let z_rd = add_offcircuit(&z, &rd).unwrap();
    let k_inv = inv_offcircuit(k).unwrap();
    let s = mul_offcircuit(&k_inv, &z_rd).unwrap();

    let IrValue::Bytes32(r_le) = into_bytes32_offcircuit(&r).unwrap() else {
        panic!()
    };
    let IrValue::Bytes32(s_le) = into_bytes32_offcircuit(&s).unwrap() else {
        panic!()
    };
    let pk = ec_mul_offcircuit(&generator, d).unwrap();
    (r_le, s_le, pk)
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

fn verify_only_inputs(
    request_id: &[u8; 32],
    digest: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
    pk: &IrValue,
) -> Vec<Fr> {
    let mut inputs = Vec::new();
    for b in [request_id, digest, r, s] {
        let (hi, lo) = b32_slots(b);
        inputs.extend([hi, lo]);
    }
    inputs.extend(natives(pk));
    inputs
}

// --- shaVerify / keccakVerify: in-circuit digest + deserialize ---------------

/// Pack a `RespondOutput { success, amount, recipient }` as
/// midnight-serde does: byte 0 = success, bytes 1..17 = amount LE,
/// bytes 17..37 = recipient, zero-padded to 128.
fn pack_respond_output(success: u8, amount: u128, recipient: &[u8; 20]) -> [u8; 128] {
    let mut bytes = [0u8; 128];
    bytes[0] = success;
    bytes[1..17].copy_from_slice(&amount.to_le_bytes());
    bytes[17..37].copy_from_slice(recipient);
    bytes
}

/// `Bytes<128>` FAB limbs, slot order: leftover (bytes 124..128) first,
/// then 31-byte limbs down to bytes 0..31.
fn b128_limbs(bytes: &[u8; 128]) -> Vec<Fr> {
    [&bytes[124..128], &bytes[93..124], &bytes[62..93], &bytes[31..62], &bytes[0..31]]
        .iter()
        .map(|chunk| Fr::from_le_bytes(chunk).unwrap())
        .collect()
}

fn hash_verify_inputs(
    request_id: &[u8; 32],
    output: &[u8; 128],
    r: &[u8; 32],
    s: &[u8; 32],
    pk: &IrValue,
) -> Vec<Fr> {
    let mut inputs = Vec::new();
    let (hi, lo) = b32_slots(request_id);
    inputs.extend([hi, lo]);
    inputs.extend(b128_limbs(output));
    for b in [r, s] {
        let (hi, lo) = b32_slots(b);
        inputs.extend([hi, lo]);
    }
    inputs.extend(natives(pk));
    inputs
}

/// Differential + reject agreement for one hash-verify circuit. `digest`
/// is the native hash of `requestId ‖ output` (the FAB binary of
/// `[Bytes<32>, Bytes<128>]` is the concatenated bytes).
fn check_hash_verify(ours: &IrSource, theirs: &IrSource, digest_of: impl Fn(&[u8]) -> [u8; 32]) {
    let request_id = {
        let mut b = [0u8; 32];
        b[0] = 0xaa;
        b[31] = 0x55;
        b
    };
    let recipient = *b"attest-recipient-20b";
    let output = pack_respond_output(1, 1_000_000, &recipient);

    let mut preimage_bytes = Vec::new();
    preimage_bytes.extend_from_slice(&request_id);
    preimage_bytes.extend_from_slice(&output);
    let digest = digest_of(&preimage_bytes);

    let d = scalar(0x5ec_e7u64);
    let k = scalar(0x40_0ceu64);
    let (r, s, pk) = sign(&digest, &d, &k);

    let inputs = hash_verify_inputs(&request_id, &output, &r, &s, &pk);
    let pi = preimage(inputs, attest_transcript(&request_id));
    assert_call_compatible(ours, theirs, &pi);

    // Criterion 3a: a failed respond (success = 0, correctly signed) must
    // be rejected by BOTH (the signature is fine; the deserialize assert
    // fires).
    let failed = pack_respond_output(0, 1_000_000, &recipient);
    let mut preimage_bytes = Vec::new();
    preimage_bytes.extend_from_slice(&request_id);
    preimage_bytes.extend_from_slice(&failed);
    let (r, s, pk) = sign(&digest_of(&preimage_bytes), &d, &k);
    let inputs = hash_verify_inputs(&request_id, &failed, &r, &s, &pk);
    let pi = preimage(inputs, attest_transcript(&request_id));
    assert!(simulate(ours, &pi).is_err(), "ours must reject success=0");
    assert!(simulate(theirs, &pi).is_err(), "corpus must reject success=0");

    // Criterion 3b: a tampered output (digest no longer matches the
    // signature) must be rejected by BOTH.
    let mut tampered = output;
    tampered[20] ^= 1;
    let inputs = hash_verify_inputs(&request_id, &tampered, &r, &s, &pk);
    let pi = preimage(inputs, attest_transcript(&request_id));
    assert!(simulate(ours, &pi).is_err(), "ours must reject tampering");
    assert!(simulate(theirs, &pi).is_err(), "corpus must reject tampering");
}

#[test]
fn sha_verify_matches_corpus() {
    let theirs = corpus_zkir("shaVerify");
    let ours = attest::sha_verify().ir;
    check_hash_verify(&ours, &theirs, |bytes| {
        use sha2::Digest;
        sha2::Sha256::digest(bytes).into()
    });
}

#[test]
fn keccak_verify_matches_corpus() {
    let theirs = corpus_zkir("keccakVerify");
    let ours = attest::keccak_verify().ir;
    check_hash_verify(&ours, &theirs, |bytes| {
        use sha3::Digest;
        sha3::Keccak256::digest(bytes).into()
    });
}

#[test]
fn verify_only_matches_corpus() {
    let theirs = corpus_zkir("verifyOnly");
    let ours = attest::verify_only().ir;

    let request_id = {
        let mut b = [0u8; 32];
        b[0] = 0x11;
        b[31] = 0x22;
        b
    };
    let digest = {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&0x0123_4567_89ab_cdefu64.to_be_bytes());
        b
    };
    let d = scalar(0x5ec_e7u64);
    let k = scalar(0x40_0ceu64);
    let (r, s, pk) = sign(&digest, &d, &k);

    let inputs = verify_only_inputs(&request_id, &digest, &r, &s, &pk);
    let pi = preimage(inputs, attest_transcript(&request_id));
    assert_call_compatible(&ours, &theirs, &pi);

    // Criterion 3: a tampered signature must be rejected by BOTH.
    let mut bad_s = s;
    bad_s[0] ^= 1;
    let inputs = verify_only_inputs(&request_id, &digest, &r, &bad_s, &pk);
    let pi = preimage(inputs, attest_transcript(&request_id));
    assert!(simulate(&ours, &pi).is_err(), "ours must reject a bad signature");
    assert!(
        simulate(&theirs, &pi).is_err(),
        "corpus must reject a bad signature"
    );
}
