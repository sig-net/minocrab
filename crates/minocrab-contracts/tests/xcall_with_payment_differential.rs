//! xcall-with-payment caller (callOnce/request) and target
//! (confirmRequest): call-compatibility with the corpus artifacts per
//! notes/ledger-abi.org §6. The target's notify/pay (receiveShielded coin
//! custody, no cross-contract machinery) are out of M5 scope.

use std::borrow::Cow;

use midnight_base_crypto::fab::{
    Alignment, AlignmentAtom, AlignmentSegment, AlignedValue, Value, ValueAtom,
};
use midnight_onchain_state::state::StateValue;
use midnight_onchain_vm::ops::{Key, Op};
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_transient_crypto::fab::ValueReprAlignedValue;
use midnight_transient_crypto::hash::transient_commit;
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage, Zkir};
use midnight_transient_crypto::repr::FieldRepr;
use minocrab::Fr;
use minocrab_contracts::xcall_with_payment as xwp;
use minocrab_sim::v3::simulate;
use minocrab_zkir::v3::IrSource;

type VmOp = Op<ResultModeVerify, InMemoryDB>;

fn corpus_zkir(side: &str, name: &str) -> IrSource {
    let path = format!(
        "{}/../../corpus/zkir/signet-midnight-experiments/experiments/xcall-with-payment/contract/src/{side}/zkir/{name}.zkir",
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

fn cell(av: AlignedValue) -> StateValue {
    StateValue::Cell(Sp::new(av))
}

fn key(i: u8) -> Key {
    Key::Value(bytesn_value(1, &[i]))
}

fn b32_slots(bytes: &[u8; 32]) -> (Fr, Fr) {
    (
        Fr::from(u64::from(bytes[31])),
        Fr::from_le_bytes(&bytes[..31]).unwrap(),
    )
}

fn addr_ep_comm_value(addr: &[u8; 32], ep: &[u8; 32], comm: Fr) -> AlignedValue {
    let mut comm_bytes = comm.as_le_bytes();
    while comm_bytes.last() == Some(&0) {
        comm_bytes.pop();
    }
    AlignedValue::new(
        Value(vec![
            ValueAtom(addr.to_vec()).normalize(),
            ValueAtom(ep.to_vec()).normalize(),
            ValueAtom(comm_bytes).normalize(),
        ]),
        Alignment(vec![
            AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
            AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
            AlignmentSegment::Atom(AlignmentAtom::Field),
        ]),
    )
    .unwrap()
}

/// The caller's single call site: target read + claim.
fn call_ops(target: &[u8; 32], ep: &[u8; 32], comm: Fr) -> Vec<VmOp> {
    vec![
        Op::Dup { n: 0 },
        Op::Idx {
            cached: false,
            push_path: false,
            path: vec![key(xwp::TARGET)].into(),
        },
        Op::Popeq {
            cached: false,
            result: bytesn_value(32, target),
        },
        Op::Swap { n: 0 },
        Op::Idx {
            cached: true,
            push_path: true,
            path: vec![key(3)].into(),
        },
        Op::Dup { n: 0 },
        Op::Size,
        Op::Push {
            storage: false,
            value: cell(addr_ep_comm_value(target, ep, comm)),
        },
        Op::Concat {
            cached: true,
            n: 160,
        },
        Op::Push {
            storage: false,
            value: StateValue::Null,
        },
        Op::Ins { cached: true, n: 2 },
        Op::Swap { n: 0 },
    ]
}

fn preimage(inputs: Vec<Fr>, ops: Vec<VmOp>, read_results: &[AlignedValue], witnesses: Vec<Fr>) -> ProofPreimage {
    let mut transcript = Vec::new();
    for op in ops {
        op.field_repr(&mut transcript);
    }
    let mut outputs = Vec::new();
    for av in read_results {
        ValueReprAlignedValue(av.clone()).field_repr(&mut outputs);
    }
    let rand = Fr::from(0x9a9_0123u64);
    let comm = transient_commit(&inputs[..], rand);
    ProofPreimage {
        inputs,
        private_transcript: witnesses,
        public_transcript_inputs: transcript,
        public_transcript_outputs: outputs,
        binding_input: 0.into(),
        communications_commitment: Some((comm, rand)),
        key_location: KeyLocation(Cow::Borrowed("minocrab-contracts-test")),
    }
}

fn assert_call_compatible(ours: &IrSource, theirs: &IrSource, pi: &ProofPreimage) {
    let types = |ir: &IrSource| {
        serde_json::to_value(&ir.inputs)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|ti| ti["type"].clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(types(ours), types(theirs), "input schemas differ");
    assert_eq!(ours.outputs, theirs.outputs, "output schemas differ");

    let our_run = simulate(ours, pi).expect("our artifact accepts");
    let their_run = simulate(theirs, pi).expect("corpus artifact accepts");
    assert_eq!(our_run.pi_skips, their_run.pi_skips, "pi_skips differ");
    assert_eq!(our_run.pis, their_run.pis, "PI vectors differ");

    assert_eq!(ours.check(pi).expect("upstream accepts ours"), our_run.pi_skips);
    assert_eq!(
        theirs.check(pi).expect("upstream accepts theirs"),
        their_run.pi_skips
    );
}

fn target_addr() -> [u8; 32] {
    let mut t = [0u8; 32];
    t[..10].copy_from_slice(b"pay-target");
    t[31] = 0x77;
    t
}

fn ep(name: &[u8]) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[..name.len()].copy_from_slice(name);
    e[31] = 0x88;
    e
}

#[test]
fn call_once_matches_corpus() {
    let theirs = corpus_zkir("caller", "callOnce");
    let ours = xwp::call_once().ir;

    // ShieldedCoinInfo { nonce, color, value }.
    let mut nonce = [0u8; 32];
    nonce[..8].copy_from_slice(b"pay-nonc");
    nonce[31] = 0x41;
    let mut color = [0u8; 32];
    color[..8].copy_from_slice(b"pay-colr");
    color[31] = 0x42;
    let (n_hi, n_lo) = b32_slots(&nonce);
    let (c_hi, c_lo) = b32_slots(&color);
    let args = vec![n_hi, n_lo, c_hi, c_lo, Fr::from(31_337u64)];

    let target = target_addr();
    let e = ep(b"ep:notify");
    let cc_rand = Fr::from(0xc0117u64);
    let comm = transient_commit(&args[..], cc_rand);
    let (ep_hi, ep_lo) = b32_slots(&e);
    let pi = preimage(
        args,
        call_ops(&target, &e, comm),
        &[bytesn_value(32, &target)],
        vec![cc_rand, ep_hi, ep_lo],
    );
    assert_call_compatible(&ours, &theirs, &pi);
}

#[test]
fn request_matches_corpus() {
    let theirs = corpus_zkir("caller", "request");
    let ours = xwp::request().ir;

    let mut request_id = [0u8; 32];
    request_id[..7].copy_from_slice(b"req-id-");
    request_id[31] = 0x51;
    let (r_hi, r_lo) = b32_slots(&request_id);
    let args = vec![r_hi, r_lo];

    let target = target_addr();
    let e = ep(b"ep:confirmRequest");
    let cc_rand = Fr::from(0x4e9_0e57u64);
    let comm = transient_commit(&args[..], cc_rand);
    let (ep_hi, ep_lo) = b32_slots(&e);
    let pi = preimage(
        args,
        call_ops(&target, &e, comm),
        &[bytesn_value(32, &target)],
        vec![cc_rand, ep_hi, ep_lo],
    );
    assert_call_compatible(&ours, &theirs, &pi);
}

#[test]
fn confirm_request_matches_corpus() {
    let theirs = corpus_zkir("target", "confirmRequest");
    let ours = xwp::confirm_request().ir;

    let mut request_id = [0u8; 32];
    request_id[..7].copy_from_slice(b"req-id-");
    request_id[31] = 0x51;
    let (r_hi, r_lo) = b32_slots(&request_id);

    let ops = vec![
        Op::Idx {
            cached: false,
            push_path: true,
            path: vec![key(xwp::REQUESTS)].into(),
        },
        Op::Push {
            storage: false,
            value: cell(bytesn_value(32, &request_id)),
        },
        Op::Push {
            storage: true,
            value: StateValue::Null,
        },
        Op::Ins {
            cached: false,
            n: 1,
        },
        Op::Ins { cached: true, n: 1 },
    ];
    let pi = preimage(vec![r_hi, r_lo], ops, &[], vec![]);
    assert_call_compatible(&ours, &theirs, &pi);
}
