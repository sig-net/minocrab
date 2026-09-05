//! serde-builtin `checkRoundtrip`: call-compatibility with the corpus
//! artifact per notes/ledger-abi.org §6, plus rejection agreement on
//! non-canonical encodings.

use std::borrow::Cow;

use midnight_base_crypto::fab::{
    Alignment, AlignmentAtom, AlignmentSegment, AlignedValue, Value, ValueAtom,
};
use midnight_onchain_vm::ops::{Key, Op};
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::db::InMemoryDB;
use midnight_transient_crypto::hash::transient_commit;
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage, Zkir};
use midnight_transient_crypto::repr::FieldRepr;
use minocrab::Fr;
use minocrab_contracts::serde_builtin;
use minocrab_sim::v3::simulate;
use minocrab_zkir::v3::IrSource;

type VmOp = Op<ResultModeVerify, InMemoryDB>;

fn corpus_zkir() -> IrSource {
    let path = format!(
        "{}/../../corpus/zkir/signet-midnight-experiments/experiments/serde-builtin/contract/src/serde-builtin/zkir/checkRoundtrip.zkir",
        env!("CARGO_MANIFEST_DIR")
    );
    minocrab_zkir::v3::read_zkir(&path).expect("corpus golden parses")
}

/// A canonical Mixed encoding: flag=1, amount, small, tag, zero padding.
fn mixed_bytes(amount: u128, small: u8, tag: &[u8; 32]) -> [u8; 128] {
    let mut bytes = [0u8; 128];
    bytes[0] = 1;
    bytes[1..17].copy_from_slice(&amount.to_le_bytes());
    bytes[17] = small;
    bytes[18..50].copy_from_slice(tag);
    bytes
}

fn b128_limbs(bytes: &[u8; 128]) -> Vec<Fr> {
    let mut chunks: Vec<&[u8]> = bytes.chunks(31).collect();
    chunks.reverse();
    chunks
        .into_iter()
        .map(|c| Fr::from_le_bytes(c).unwrap())
        .collect()
}

fn preimage(bytes: &[u8; 128]) -> ProofPreimage {
    let key = Key::Value(
        AlignedValue::new(
            Value(vec![ValueAtom(vec![serde_builtin::CHECKS]).normalize()]),
            Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes {
                length: 1,
            })]),
        )
        .unwrap(),
    );
    let ops: Vec<VmOp> = vec![
        Op::Idx {
            cached: false,
            push_path: true,
            path: vec![key].into(),
        },
        Op::Addi { immediate: 1 },
        Op::Ins { cached: true, n: 1 },
    ];
    let mut transcript = Vec::new();
    for op in &ops {
        op.field_repr(&mut transcript);
    }

    let inputs = b128_limbs(bytes);
    let rand = Fr::from(0x5e12_deu64);
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
fn check_roundtrip_matches_corpus() {
    let theirs = corpus_zkir();
    let ours = serde_builtin::SerdeBuiltin::check_roundtrip().ir;

    let bytes = mixed_bytes(0xdead_beef_0123, 0x2a, b"mixed-tag-32-bytes-for-the-test!");
    let pi = preimage(&bytes);

    let types = |ir: &IrSource| {
        serde_json::to_value(&ir.inputs)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|ti| ti["type"].clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(types(&ours), types(&theirs), "input schemas differ");
    assert_eq!(ours.outputs, theirs.outputs, "output schemas differ");

    let our_run = simulate(&ours, &pi).expect("our artifact accepts");
    let their_run = simulate(&theirs, &pi).expect("corpus artifact accepts");
    assert_eq!(our_run.pi_skips, their_run.pi_skips, "pi_skips differ");
    assert_eq!(our_run.pis, their_run.pis, "PI vectors differ");
    assert_eq!(ours.check(&pi).expect("upstream accepts ours"), our_run.pi_skips);

    // Criterion 3: non-canonical encodings must be rejected by BOTH —
    // a flag byte of 2 (deserializes to false, re-serializes to 0)…
    let mut bad_flag = bytes;
    bad_flag[0] = 2;
    let pi = preimage(&bad_flag);
    assert!(simulate(&ours, &pi).is_err(), "ours must reject flag=2");
    assert!(simulate(&theirs, &pi).is_err(), "corpus must reject flag=2");

    // …and nonzero padding (dropped by the re-serialize).
    let mut bad_pad = bytes;
    bad_pad[100] = 0xff;
    let pi = preimage(&bad_pad);
    assert!(simulate(&ours, &pi).is_err(), "ours must reject padding");
    assert!(simulate(&theirs, &pi).is_err(), "corpus must reject padding");
}
