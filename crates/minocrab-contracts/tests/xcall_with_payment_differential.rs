//! xcall-with-payment caller (callOnce/request) and target
//! (confirmRequest, plus the root-call coin-custody circuits notify/pay —
//! receiveShielded + treasury.writeCoin): call-compatibility with the
//! corpus artifacts per notes/ledger-abi.org §6.

use std::borrow::Cow;

use midnight_base_crypto::fab::{
    Alignment, AlignmentAtom, AlignmentSegment, AlignedValue, Value, ValueAtom,
};
use midnight_base_crypto::repr::BinaryHashRepr;
use midnight_transient_crypto::fab::AlignmentExt;
use sha2::{Digest, Sha256};
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
use minocrab_ledger::ep_hash;
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

/// The entry-point hash, DERIVED from the callee circuit's name (M12
/// stage 1). Preimage-only: the ep limbs are prover-supplied witnesses.
fn ep(name: &str) -> [u8; 32] {
    ep_hash(name)
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
    let e = ep("notify");
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
    let e = ep("confirmRequest");
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

// --- notify / pay: root-call coin custody ------------------------------------

fn atom(n: u32) -> AlignmentSegment {
    AlignmentSegment::Atom(AlignmentAtom::Bytes { length: n })
}

/// SHA-256 over the FAB binary of `limbs` laid out per `segments` — the
/// off-circuit persistent_hash (zkir-v3 ir_vm.rs:478-505).
fn fab_sha256(segments: Vec<AlignmentSegment>, limbs: &[Fr]) -> [u8; 32] {
    let value = Alignment(segments)
        .parse_field_repr(limbs)
        .expect("limbs match the alignment");
    let mut repr = Vec::new();
    ValueReprAlignedValue(value).binary_repr(&mut repr);
    Sha256::digest(&repr).into()
}

/// A coin custody scenario: the coin argument plus the contract's address
/// (what both kernel.self() reads return).
struct CoinScenario {
    nonce: [u8; 32],
    color: [u8; 32],
    value: u64,
    address: [u8; 32],
}

impl CoinScenario {
    fn new() -> CoinScenario {
        let mut nonce = [0u8; 32];
        nonce[..9].copy_from_slice(b"pay-nonce");
        nonce[31] = 0x61;
        let mut color = [0u8; 32];
        color[..9].copy_from_slice(b"pay-color");
        color[31] = 0x62;
        let mut address = [0u8; 32];
        address[..11].copy_from_slice(b"pay-address");
        address[31] = 0x63;
        CoinScenario {
            nonce,
            color,
            value: 1_000_000,
            address,
        }
    }

    /// `coinCommitment(coin, right(kernel.self()))` — is_left = 0.
    fn commitment(&self) -> [u8; 32] {
        let prefix = Fr::from_le_bytes(b"midnight:zswap-cc[v1]").unwrap();
        let (n_hi, n_lo) = b32_slots(&self.nonce);
        let (c_hi, c_lo) = b32_slots(&self.color);
        let (a_hi, a_lo) = b32_slots(&self.address);
        fab_sha256(
            vec![atom(21), atom(32), atom(32), atom(16), atom(1), atom(32)],
            &[
                prefix,
                n_hi,
                n_lo,
                c_hi,
                c_lo,
                Fr::from(self.value),
                Fr::from(0u64), // is_left: right(self)
                a_hi,
                a_lo,
            ],
        )
    }

    /// The 3-atom ShieldedCoinInfo cell value `[nonce, color, value]`.
    fn coin_cell(&self) -> AlignedValue {
        AlignedValue::new(
            Value(vec![
                ValueAtom(self.nonce.to_vec()).normalize(),
                ValueAtom(self.color.to_vec()).normalize(),
                ValueAtom(self.value.to_le_bytes().to_vec()).normalize(),
            ]),
            Alignment(vec![
                AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
                AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
                AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 16 }),
            ]),
        )
        .unwrap()
    }

    /// One kernel.self() read (dup 2; idxc [0]; popeqc).
    fn self_read_ops(&self) -> Vec<VmOp> {
        vec![
            Op::Dup { n: 2 },
            Op::Idx {
                cached: true,
                push_path: false,
                path: vec![key(0)].into(),
            },
            Op::Popeq {
                cached: true,
                result: bytesn_value(32, &self.address),
            },
        ]
    }

    /// The shared custody body: `receiveShielded(coin)` +
    /// `treasury.writeCoin(coin, right(kernel.self()))`.
    fn custody_ops(&self) -> Vec<VmOp> {
        let cm = self.commitment();
        let mut ops = self.self_read_ops();
        ops.extend([
            // kernel.claimZswapCoinReceive(cm) — effects[1]
            Op::Swap { n: 0 },
            Op::Idx {
                cached: true,
                push_path: true,
                path: vec![key(1)].into(),
            },
            Op::Push {
                storage: false,
                value: cell(bytesn_value(32, &cm)),
            },
            Op::Push {
                storage: false,
                value: StateValue::Null,
            },
            Op::Ins { cached: true, n: 2 },
            Op::Swap { n: 0 },
        ]);
        // treasury.writeCoin: a second kernel.self() read, then the write.
        ops.extend(self.self_read_ops());
        ops.extend([
            Op::Push {
                storage: false,
                value: cell(bytesn_value(1, &[xwp::TREASURY])),
            },
            Op::Dup { n: 3 },
            Op::Push {
                storage: false,
                value: cell(bytesn_value(32, &cm)),
            },
            Op::Idx {
                cached: true,
                push_path: false,
                path: vec![key(1), Key::Stack].into(),
            },
            Op::Push {
                storage: false,
                value: cell(self.coin_cell()),
            },
            Op::Swap { n: 0 },
            Op::Concat {
                cached: true,
                n: 91,
            },
            Op::Ins {
                cached: false,
                n: 1,
            },
        ]);
        ops
    }

    /// The coin argument's five input limbs.
    fn coin_inputs(&self) -> Vec<Fr> {
        let (n_hi, n_lo) = b32_slots(&self.nonce);
        let (c_hi, c_lo) = b32_slots(&self.color);
        vec![n_hi, n_lo, c_hi, c_lo, Fr::from(self.value)]
    }

    /// Both kernel.self() reads' results, in read order.
    fn read_results(&self) -> Vec<AlignedValue> {
        vec![
            bytesn_value(32, &self.address),
            bytesn_value(32, &self.address),
        ]
    }

    fn notify_preimage(&self) -> ProofPreimage {
        preimage(self.coin_inputs(), self.custody_ops(), &self.read_results(), vec![])
    }

    fn pay_preimage(&self, request_id: &[u8; 32]) -> ProofPreimage {
        let (r_hi, r_lo) = b32_slots(request_id);
        let mut inputs = vec![r_hi, r_lo];
        inputs.extend(self.coin_inputs());
        let mut ops = self.custody_ops();
        ops.extend([
            // paidRequests.insert(requestId)
            Op::Idx {
                cached: false,
                push_path: true,
                path: vec![key(xwp::PAID_REQUESTS)].into(),
            },
            Op::Push {
                storage: false,
                value: cell(bytesn_value(32, request_id)),
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
        ]);
        preimage(inputs, ops, &self.read_results(), vec![])
    }
}

#[test]
fn notify_matches_corpus() {
    let theirs = corpus_zkir("target", "notify");
    let ours = xwp::notify().ir;
    let s = CoinScenario::new();
    assert_call_compatible(&ours, &theirs, &s.notify_preimage());
}

#[test]
fn pay_matches_corpus() {
    let theirs = corpus_zkir("target", "pay");
    let ours = xwp::pay().ir;
    let s = CoinScenario::new();
    let mut request_id = [0u8; 32];
    request_id[..7].copy_from_slice(b"req-id-");
    request_id[31] = 0x51;
    assert_call_compatible(&ours, &theirs, &s.pay_preimage(&request_id));
}

/// Criterion 3: tampering with ANY transcript element of the custody body
/// (the claimed commitment, the written coin, the self address…) must be
/// rejected by both artifacts, with zero acceptance disagreements.
#[test]
fn notify_rejects_tampering() {
    let theirs = corpus_zkir("target", "notify");
    let ours = xwp::notify().ir;
    let s = CoinScenario::new();

    let pi = s.notify_preimage();
    let mut disagreements = 0;
    for i in 0..pi.public_transcript_inputs.len() {
        let mut t = pi.clone();
        t.public_transcript_inputs[i] = t.public_transcript_inputs[i] + Fr::from(1u64);
        let ours_rejects = simulate(&ours, &t).is_err();
        assert!(ours_rejects, "ours accepts tampered transcript element {i}");
        if ours_rejects != simulate(&theirs, &t).is_err() {
            disagreements += 1;
        }
    }
    assert_eq!(disagreements, 0, "acceptance disagreement on tampering");
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
