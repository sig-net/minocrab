//! hashing + keccak experiments: call-compatibility for all 19 corpus
//! circuits (controls, persistentHash, keccak256, transientHash,
//! persistentVec8) per notes/ledger-abi.org §6.

use std::borrow::Cow;

use midnight_base_crypto::fab::{
    Alignment, AlignmentAtom, AlignmentSegment, AlignedValue, Value, ValueAtom,
};
use midnight_onchain_state::state::StateValue;
use midnight_onchain_vm::ops::{Key, Op};
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_transient_crypto::hash::{transient_commit, transient_hash};
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage, Zkir};
use midnight_transient_crypto::repr::FieldRepr;
use minocrab::Fr;
use minocrab_contracts::hashing;
use minocrab_sim::v3::simulate;
use minocrab_zkir::v3::IrSource;
use sha2::Digest as _;
use sha3::Digest as _;

type VmOp = Op<ResultModeVerify, InMemoryDB>;

fn corpus_zkir(experiment: &str, name: &str) -> IrSource {
    let path = format!(
        "{}/../../corpus/zkir/signet-midnight-experiments/experiments/{experiment}/contract/src/{experiment}/zkir/{name}.zkir",
        env!("CARGO_MANIFEST_DIR")
    );
    minocrab_zkir::v3::read_zkir(&path).expect("corpus golden parses")
}

fn bytesn_value(n: u32, bytes: &[u8]) -> AlignedValue {
    AlignedValue::new(
        Value(vec![ValueAtom(bytes.to_vec()).normalize()]),
        Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes {
            length: n,
        })]),
    )
    .unwrap()
}

fn field_value(f: Fr) -> AlignedValue {
    AlignedValue::new(
        Value(vec![ValueAtom::from(f)]),
        Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Field)]),
    )
    .unwrap()
}

/// FAB limbs of a `Bytes<len>` in slot order (leftover MSB chunk first).
fn bytes_limbs(bytes: &[u8]) -> Vec<Fr> {
    let mut chunks: Vec<&[u8]> = bytes.chunks(31).collect();
    chunks.reverse();
    chunks
        .into_iter()
        .map(|c| Fr::from_le_bytes(c).unwrap())
        .collect()
}

/// The test input: `len` deterministic bytes.
fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + 3) as u8).collect()
}

/// Differential for one circuit: workload = increment + optionally a cell
/// write of the expected digest at `write`.
fn check(ours: IrSource, experiment: &str, name: &str, len: usize, write: Option<(u8, AlignedValue)>) {
    check_with_inputs(ours, experiment, name, bytes_limbs(&data(len)), write)
}

fn check_with_inputs(
    ours: IrSource,
    experiment: &str,
    name: &str,
    inputs: Vec<Fr>,
    write: Option<(u8, AlignedValue)>,
) {
    let theirs = corpus_zkir(experiment, name);

    let mut ops: Vec<VmOp> = vec![
        Op::Idx {
            cached: false,
            push_path: true,
            path: vec![Key::Value(bytesn_value(1, &[hashing::CALL_COUNT]))].into(),
        },
        Op::Addi { immediate: 1 },
        Op::Ins { cached: true, n: 1 },
    ];
    if let Some((field, av)) = write {
        ops.extend([
            Op::Push {
                storage: false,
                value: StateValue::Cell(Sp::new(bytesn_value(1, &[field]))),
            },
            Op::Push {
                storage: true,
                value: StateValue::Cell(Sp::new(av)),
            },
            Op::Ins {
                cached: false,
                n: 1,
            },
        ]);
    }
    let mut transcript = Vec::new();
    for op in &ops {
        op.field_repr(&mut transcript);
    }

    let rand = Fr::from(0xa5_a5u64);
    let comm = transient_commit(&inputs[..], rand);
    let pi = ProofPreimage {
        inputs,
        private_transcript: vec![],
        public_transcript_inputs: transcript,
        public_transcript_outputs: vec![],
        binding_input: 0.into(),
        communications_commitment: Some((comm, rand)),
        key_location: KeyLocation(Cow::Borrowed("minocrab-contracts-test")),
    };

    let types = |ir: &IrSource| {
        serde_json::to_value(&ir.inputs)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|ti| ti["type"].clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(types(&ours), types(&theirs), "{name}: input schemas differ");
    assert_eq!(ours.outputs, theirs.outputs, "{name}: output schemas differ");

    let our_run = simulate(&ours, &pi).unwrap_or_else(|e| panic!("{name}: ours rejects: {e:?}"));
    let their_run =
        simulate(&theirs, &pi).unwrap_or_else(|e| panic!("{name}: corpus rejects: {e:?}"));
    assert_eq!(our_run.pi_skips, their_run.pi_skips, "{name}: pi_skips differ");
    assert_eq!(our_run.pis, their_run.pis, "{name}: PI vectors differ");
    assert_eq!(ours.check(&pi).expect("upstream accepts ours"), our_run.pi_skips);
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(bytes).into()
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    sha3::Keccak256::digest(bytes).into()
}

#[test]
fn hashing_controls_match_corpus() {
    for len in [32, 256, 1024] {
        check(hashing::control(len).ir, "hashing", &format!("control{len}"), len, None);
    }
}

#[test]
fn hashing_persistent_matches_corpus() {
    for len in [32, 256, 1024] {
        let digest = sha(&data(len));
        check(
            hashing::persistent(len).ir,
            "hashing",
            &format!("persistent{len}"),
            len,
            Some((hashing::DIGEST, bytesn_value(32, &digest))),
        );
    }
}

#[test]
fn hashing_persistent_vec8_matches_corpus() {
    // The same 256 bytes, hashed as 8 × Bytes<32> — the FAB binary is the
    // concatenated bytes, so the digest equals the flat sha256; but the
    // ARGUMENTS are 16 limbs ([hi, lo] per Bytes<32>), not 9.
    let digest = sha(&data(256));
    check_with_inputs(
        hashing::persistent_vec8().ir,
        "hashing",
        "persistentVec8",
        data(256)
            .chunks(32)
            .flat_map(|part| {
                let part: &[u8; 32] = part.try_into().unwrap();
                [
                    Fr::from(u64::from(part[31])),
                    Fr::from_le_bytes(&part[..31]).unwrap(),
                ]
            })
            .collect(),
        Some((hashing::DIGEST, bytesn_value(32, &digest))),
    );
}

#[test]
fn hashing_transient_matches_corpus() {
    for len in [32, 256, 1024] {
        let f = transient_hash(&bytes_limbs(&data(len)));
        check(
            hashing::transient(len).ir,
            "hashing",
            &format!("transient{len}"),
            len,
            Some((hashing::FDIGEST, field_value(f))),
        );
    }
}

#[test]
fn keccak_controls_match_corpus() {
    for len in [64, 128, 256] {
        check(hashing::control(len).ir, "keccak", &format!("c{len}"), len, None);
    }
}

#[test]
fn keccak_persistent_matches_corpus() {
    for len in [64, 128, 256] {
        let digest = sha(&data(len));
        check(
            hashing::persistent(len).ir,
            "keccak",
            &format!("p{len}"),
            len,
            Some((hashing::DIGEST, bytesn_value(32, &digest))),
        );
    }
}

#[test]
fn keccak_keccak_matches_corpus() {
    for len in [64, 128, 256] {
        let digest = keccak(&data(len));
        check(
            hashing::keccak(len).ir,
            "keccak",
            &format!("k{len}"),
            len,
            Some((hashing::DIGEST, bytesn_value(32, &digest))),
        );
    }
}
