//! xcall caller (localBase/callOnce/callTwice/callBig/callEmit) and target
//! (deposit/depositEmit/depositBig): call-compatibility with the corpus
//! artifacts per notes/ledger-abi.org §6 — the M5 cross-contract layer
//! (caller-side commitment + kernel.claimContractCall) against real
//! compactc artifacts, plus rejection agreement on tampering.

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
use minocrab_contracts::{events, xcall};
use minocrab_sim::v3::simulate;
use minocrab_zkir::v3::IrSource;

type VmOp = Op<ResultModeVerify, InMemoryDB>;

fn corpus_zkir(side: &str, name: &str) -> IrSource {
    let path = format!(
        "{}/../../corpus/zkir/signet-midnight-experiments/experiments/xcall/contract/src/{side}/zkir/{name}.zkir",
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

/// Value-only FAB limbs of a `Bytes<n>` in slot order: the leftover (most
/// significant) bytes first, then 31-byte chunks down to the least
/// significant.
fn fab_limbs(bytes: &[u8]) -> Vec<Fr> {
    let n = bytes.len();
    let count = n.div_ceil(31);
    let rem = n - 31 * (count - 1);
    let mut limbs = vec![Fr::from_le_bytes(&bytes[n - rem..]).unwrap()];
    for k in 1..count {
        let end = n - rem - 31 * (k - 1);
        limbs.push(Fr::from_le_bytes(&bytes[end - 31..end]).unwrap());
    }
    limbs
}

/// The `rt-aligned-concat addr ‖ entry_point ‖ comm` 3-atom cell value the
/// claim pushes.
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

/// `Counter.increment(1)` on `field`.
fn counter_inc_ops(field: u8) -> Vec<VmOp> {
    vec![
        Op::Idx {
            cached: false,
            push_path: true,
            path: vec![key(field)].into(),
        },
        Op::Addi { immediate: 1 },
        Op::Ins { cached: true, n: 1 },
    ]
}

/// The uncached read of a `Bytes<32>` cell at `field`.
fn cell_read_ops(field: u8, result: &[u8; 32]) -> Vec<VmOp> {
    vec![
        Op::Dup { n: 0 },
        Op::Idx {
            cached: false,
            push_path: false,
            path: vec![key(field)].into(),
        },
        Op::Popeq {
            cached: false,
            result: bytesn_value(32, result),
        },
    ]
}

/// `kernel.claimContractCall(addr, ep, comm)`.
fn claim_call_ops(addr: &[u8; 32], ep: &[u8; 32], comm: Fr) -> Vec<VmOp> {
    vec![
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
            value: cell(addr_ep_comm_value(addr, ep, comm)),
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

fn preimage(
    inputs: Vec<Fr>,
    ops: Vec<VmOp>,
    read_results: &[AlignedValue],
    witnesses: Vec<Fr>,
) -> ProofPreimage {
    let mut transcript = Vec::new();
    for op in ops {
        op.field_repr(&mut transcript);
    }
    let mut outputs = Vec::new();
    for av in read_results {
        ValueReprAlignedValue(av.clone()).field_repr(&mut outputs);
    }
    let rand = Fr::from(0xca11_0123u64);
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

struct Scenario {
    recipient: [u8; 32],
    amount: u128,
    target: [u8; 32],
    ep: [u8; 32],
}

impl Scenario {
    fn new() -> Scenario {
        let mut recipient = [0u8; 32];
        recipient[..7].copy_from_slice(b"xcall-r");
        recipient[31] = 0x55;
        let mut target = [0u8; 32];
        target[..12].copy_from_slice(b"target-contr");
        target[31] = 0x21;
        // The entry-point hash: any Bytes<32>; the hi slot is a byte, so
        // any value fits the 8-bit constraint.
        let mut ep = [0u8; 32];
        ep[..10].copy_from_slice(b"ep:deposit");
        ep[31] = 0x99;
        Scenario {
            recipient,
            amount: 987_654_321,
            target,
            ep,
        }
    }

    fn args(&self) -> Vec<Fr> {
        let (r_hi, r_lo) = b32_slots(&self.recipient);
        vec![r_hi, r_lo, Fr::from(self.amount)]
    }

    /// One call site: the target read + the claim; returns (ops, witnesses).
    fn call_site(&self, call_args: &[Fr], cc_rand: Fr) -> (Vec<VmOp>, Vec<Fr>) {
        let comm = transient_commit(call_args, cc_rand);
        let mut ops = cell_read_ops(xcall::TARGET, &self.target);
        ops.extend(claim_call_ops(&self.target, &self.ep, comm));
        let (ep_hi, ep_lo) = b32_slots(&self.ep);
        (ops, vec![cc_rand, ep_hi, ep_lo])
    }

    /// callOnce/callEmit (`n` = 1) and callTwice (`n` = 2).
    fn preimage_call_n(&self, n: usize) -> ProofPreimage {
        let mut ops = counter_inc_ops(xcall::CALL_COUNT);
        let mut witnesses = Vec::new();
        for i in 0..n {
            let cc_rand = Fr::from(0x5eed_0000u64 + i as u64);
            let (site_ops, site_wits) = self.call_site(&self.args(), cc_rand);
            ops.extend(site_ops);
            witnesses.extend(site_wits);
        }
        let reads: Vec<AlignedValue> = (0..n).map(|_| bytesn_value(32, &self.target)).collect();
        preimage(self.args(), ops, &reads, witnesses)
    }

    /// The shared workload ops against the given field indices (the caller
    /// uses fields 1/2/3, the target — like the events experiment — 0/1/2).
    fn workload_ops(&self, call_count: u8, last_amount: u8, balances: u8) -> Vec<VmOp> {
        let amount_av = bytesn_value(16, &self.amount.to_le_bytes());
        let mut ops = counter_inc_ops(call_count);
        ops.extend([
            // lastAmount = a
            Op::Push {
                storage: false,
                value: cell(bytesn_value(1, &[last_amount])),
            },
            Op::Push {
                storage: true,
                value: cell(amount_av.clone()),
            },
            Op::Ins {
                cached: false,
                n: 1,
            },
            // balances.insert(r, a)
            Op::Idx {
                cached: false,
                push_path: true,
                path: vec![key(balances)].into(),
            },
            Op::Push {
                storage: false,
                value: cell(bytesn_value(32, &self.recipient)),
            },
            Op::Push {
                storage: true,
                value: cell(amount_av),
            },
            Op::Ins {
                cached: false,
                n: 1,
            },
            Op::Ins { cached: true, n: 1 },
        ]);
        ops
    }

    fn preimage_local_base(&self) -> ProofPreimage {
        let ops = self.workload_ops(xcall::CALL_COUNT, xcall::LAST_AMOUNT, xcall::BALANCES);
        preimage(self.args(), ops, &[], vec![])
    }

    /// The target's deposit — the workload against fields 0/1/2.
    fn preimage_target_deposit(&self) -> ProofPreimage {
        let ops = self.workload_ops(0, 1, 2);
        preimage(self.args(), ops, &[], vec![])
    }

    /// The target's depositEmit — sequence read, workload, one Misc event
    /// named `deposit-0` carrying the serialized DepositEvent.
    fn preimage_target_deposit_emit(&self, sequence: u64) -> ProofPreimage {
        let mut misc = vec![0u8; events::MISC_SIZE];
        let name = events::event_name(0);
        misc[..name.len()].copy_from_slice(name.as_bytes());
        misc[32..48].copy_from_slice(&self.amount.to_le_bytes());
        misc[48..56].copy_from_slice(&sequence.to_le_bytes());
        misc[56..88].copy_from_slice(&self.recipient);

        let seq_av = bytesn_value(8, &sequence.to_le_bytes());
        let mut ops = vec![
            Op::Dup { n: 0 },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![key(0)].into(),
            },
            Op::Popeq {
                cached: true,
                result: seq_av.clone(),
            },
        ];
        ops.extend(self.workload_ops(0, 1, 2));
        ops.extend([
            Op::Push {
                storage: false,
                value: StateValue::Array(
                    vec![
                        cell(bytesn_value(4, &events::MISC_VERSION.to_le_bytes())),
                        cell(bytesn_value(1, &[events::MISC_TAG])),
                        cell(bytesn_value(events::MISC_SIZE as u32, &misc)),
                    ]
                    .into(),
                ),
            },
            Op::Log,
        ]);
        preimage(self.args(), ops, &[seq_av], vec![])
    }

    fn preimage_call_big(&self, data: &[u8; 256]) -> ProofPreimage {
        let args = fab_limbs(data);
        let mut ops = counter_inc_ops(xcall::CALL_COUNT);
        let (site_ops, witnesses) = self.call_site(&args, Fr::from(0xb16_5eedu64));
        ops.extend(site_ops);
        preimage(args, ops, &[bytesn_value(32, &self.target)], witnesses)
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

#[test]
fn local_base_matches_corpus() {
    let theirs = corpus_zkir("caller", "localBase");
    let ours = xcall::local_base().ir;
    let s = Scenario::new();
    assert_call_compatible(&ours, &theirs, &s.preimage_local_base());
}

#[test]
fn call_once_matches_corpus() {
    let theirs = corpus_zkir("caller", "callOnce");
    let ours = xcall::call_once().ir;
    let s = Scenario::new();
    assert_call_compatible(&ours, &theirs, &s.preimage_call_n(1));
}

/// callEmit is the same circuit claiming a different entry point — only
/// the prover-supplied ep witness changes.
#[test]
fn call_emit_matches_corpus() {
    let theirs = corpus_zkir("caller", "callEmit");
    let ours = xcall::call_once().ir;
    let mut s = Scenario::new();
    s.ep[..14].copy_from_slice(b"ep:depositEmit");
    assert_call_compatible(&ours, &theirs, &s.preimage_call_n(1));
}

#[test]
fn call_twice_matches_corpus() {
    let theirs = corpus_zkir("caller", "callTwice");
    let ours = xcall::call_twice().ir;
    let s = Scenario::new();
    assert_call_compatible(&ours, &theirs, &s.preimage_call_n(2));
}

#[test]
fn call_big_matches_corpus() {
    let theirs = corpus_zkir("caller", "callBig");
    let ours = xcall::call_big().ir;
    let s = Scenario::new();
    let mut data = [0u8; 256];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    assert_call_compatible(&ours, &theirs, &s.preimage_call_big(&data));
}

/// The target's deposit/depositEmit are the events experiment's base/emit1
/// circuits; their differentials against the XCALL corpus artifacts verify
/// that equivalence. depositBig is its own minimal circuit.
#[test]
fn target_deposit_big_matches_corpus() {
    let theirs = corpus_zkir("target", "depositBig");
    let ours = xcall::target_deposit_big().ir;
    let mut data = [0u8; 256];
    data[0] = 0x42;
    data[255] = 0x24;
    let pi = preimage(
        fab_limbs(&data),
        counter_inc_ops(xcall::T_CALL_COUNT),
        &[],
        vec![],
    );
    assert_call_compatible(&ours, &theirs, &pi);
}

#[test]
fn target_deposit_matches_corpus() {
    let theirs = corpus_zkir("target", "deposit");
    let ours = xcall::target_deposit().ir;
    let s = Scenario::new();
    assert_call_compatible(&ours, &theirs, &s.preimage_target_deposit());
}

#[test]
fn target_deposit_emit_matches_corpus() {
    let theirs = corpus_zkir("target", "depositEmit");
    let ours = xcall::target_deposit_emit().ir;
    let s = Scenario::new();
    assert_call_compatible(&ours, &theirs, &s.preimage_target_deposit_emit(3));
}

/// Criterion 3: tampering with ANY element of the callOnce transcript or
/// its private witnesses (cc-rand, ep limbs) must be rejected by both
/// artifacts, with zero acceptance disagreements.
#[test]
fn call_once_rejects_tampering() {
    let theirs = corpus_zkir("caller", "callOnce");
    let ours = xcall::call_once().ir;
    let s = Scenario::new();

    let pi = s.preimage_call_n(1);
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
    // Flipping any private witness breaks the in-circuit comm (cc-rand)
    // or the claimed entry point (ep limbs) against the transcript.
    for i in 0..pi.private_transcript.len() {
        let mut t = pi.clone();
        t.private_transcript[i] = t.private_transcript[i] + Fr::from(1u64);
        let ours_rejects = simulate(&ours, &t).is_err();
        assert!(ours_rejects, "ours accepts tampered witness {i}");
        if ours_rejects != simulate(&theirs, &t).is_err() {
            disagreements += 1;
        }
    }
    assert_eq!(disagreements, 0, "acceptance disagreement on tampering");
}
