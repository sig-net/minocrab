//! xcontract-events depositViaVault (caller with a returned value) and
//! token deposit (callee): call-compatibility with the corpus artifacts per
//! notes/ledger-abi.org §6 — the M5 return-value path (result witnesses
//! bound by the communication commitment) plus Set.insert, against real
//! compactc artifacts, with rejection agreement on tampering.

use std::borrow::Cow;

use midnight_base_crypto::fab::{
    Alignment, AlignmentAtom, AlignmentSegment, AlignedValue, Value, ValueAtom,
};
use midnight_base_crypto::repr::BinaryHashRepr;
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
use minocrab_contracts::events;
use minocrab_contracts::xcontract_events as xce;
use minocrab_sim::v3::simulate;
use minocrab_zkir::v3::IrSource;
use sha2::{Digest, Sha256};

type VmOp = Op<ResultModeVerify, InMemoryDB>;

fn corpus_zkir(side: &str, name: &str) -> IrSource {
    let path = format!(
        "{}/../../corpus/zkir/signet-midnight-experiments/experiments/xcontract-events/contract/src/{side}/zkir/{name}.zkir",
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

/// The `rt-aligned-concat addr ‖ entry_point ‖ comm` 3-atom cell value.
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

fn set_insert_ops(field: u8, elem: AlignedValue) -> Vec<VmOp> {
    vec![
        Op::Idx {
            cached: false,
            push_path: true,
            path: vec![key(field)].into(),
        },
        Op::Push {
            storage: false,
            value: cell(elem),
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
    ]
}

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

/// `comm_vals` is the circuit's own commitment preimage: arguments then
/// output values (value-only FAB order).
fn preimage(
    inputs: Vec<Fr>,
    comm_vals: Vec<Fr>,
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
    let rand = Fr::from(0xe0e0_0123u64);
    let comm = transient_commit(&comm_vals[..], rand);
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
    amount: u128,
    sequence: u64,
    vault_addr: [u8; 32],
    token_addr: [u8; 32],
    ep: [u8; 32],
}

impl Scenario {
    fn new() -> Scenario {
        let mut vault_addr = [0u8; 32];
        vault_addr[..9].copy_from_slice(b"vault-adr");
        vault_addr[31] = 0x11;
        let mut token_addr = [0u8; 32];
        token_addr[..9].copy_from_slice(b"token-adr");
        token_addr[31] = 0x22;
        let mut ep = [0u8; 32];
        ep[..10].copy_from_slice(b"ep:deposit");
        ep[31] = 0x33;
        Scenario {
            amount: 555_000_111,
            sequence: 9,
            vault_addr,
            token_addr,
            ep,
        }
    }

    /// The serialized DepositEvent payload the token builds:
    /// amount(16) ‖ sequence(8) ‖ caller(32), zero-padded to 256.
    fn payload(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; xce::PAYLOAD_SIZE];
        bytes[..16].copy_from_slice(&self.amount.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.sequence.to_le_bytes());
        bytes[24..56].copy_from_slice(&self.vault_addr);
        bytes
    }

    /// The event hash: off-circuit persistentHash<Bytes<256>>(payload) =
    /// SHA-256 over the FAB binary repr.
    fn event_hash(&self) -> [u8; 32] {
        let av = bytesn_value(xce::PAYLOAD_SIZE as u32, &self.payload());
        let mut repr = Vec::new();
        ValueReprAlignedValue(av).binary_repr(&mut repr);
        Sha256::digest(&repr).into()
    }

    /// The vault's preimage; the witnessed call result is the exact hash
    /// the token's circuit computes for this scenario.
    fn preimage_vault(&self) -> ProofPreimage {
        let (eh_hi, eh_lo) = b32_slots(&self.event_hash());
        let (me_hi, me_lo) = b32_slots(&self.vault_addr);
        let amount = Fr::from(self.amount);
        let cc_rand = Fr::from(0x5eed_1111u64);
        let call_comm = transient_commit(&[amount, me_hi, me_lo, eh_hi, eh_lo], cc_rand);

        let mut ops = counter_inc_ops(xce::VAULT_CALL_COUNT);
        // kernel.self()
        ops.extend([
            Op::Dup { n: 2 },
            Op::Idx {
                cached: true,
                push_path: false,
                path: vec![key(0)].into(),
            },
            Op::Popeq {
                cached: true,
                result: bytesn_value(32, &self.vault_addr),
            },
        ]);
        // token cell read
        ops.extend([
            Op::Dup { n: 0 },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![key(xce::TOKEN)].into(),
            },
            Op::Popeq {
                cached: false,
                result: bytesn_value(32, &self.token_addr),
            },
        ]);
        ops.extend(claim_call_ops(&self.token_addr, &self.ep, call_comm));
        ops.extend(set_insert_ops(
            xce::VAULT_DEPOSITS,
            bytesn_value(32, &self.event_hash()),
        ));

        let (ep_hi, ep_lo) = b32_slots(&self.ep);
        preimage(
            vec![amount],
            vec![amount, eh_hi, eh_lo],
            ops,
            &[
                bytesn_value(32, &self.vault_addr),
                bytesn_value(32, &self.token_addr),
            ],
            vec![eh_hi, eh_lo, cc_rand, ep_hi, ep_lo],
        )
    }

    /// The token's preimage for the same call.
    fn preimage_token(&self) -> ProofPreimage {
        let (cal_hi, cal_lo) = b32_slots(&self.vault_addr);
        let (eh_hi, eh_lo) = b32_slots(&self.event_hash());
        let amount = Fr::from(self.amount);
        let seq_av = bytesn_value(8, &self.sequence.to_le_bytes());

        // sequence read
        let mut ops = vec![
            Op::Dup { n: 0 },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![key(xce::DEPOSIT_COUNT)].into(),
            },
            Op::Popeq {
                cached: true,
                result: seq_av.clone(),
            },
        ];
        ops.extend(counter_inc_ops(xce::DEPOSIT_COUNT));
        // lastAmount = amount
        ops.extend([
            Op::Push {
                storage: false,
                value: cell(bytesn_value(1, &[xce::LAST_AMOUNT])),
            },
            Op::Push {
                storage: true,
                value: cell(bytesn_value(16, &self.amount.to_le_bytes())),
            },
            Op::Ins {
                cached: false,
                n: 1,
            },
        ]);
        ops.extend(set_insert_ops(
            xce::EMITTED_DEPOSITS,
            bytesn_value(32, &self.event_hash()),
        ));
        // emit (Misc { name: pad(32, "deposit"), payload })
        let mut misc = vec![0u8; events::MISC_SIZE];
        misc[..xce::EVENT_NAME.len()].copy_from_slice(xce::EVENT_NAME.as_bytes());
        misc[32..].copy_from_slice(&self.payload());
        ops.extend([
            Op::Push {
                storage: false,
                value: StateValue::Array(
                    vec![
                        cell(bytesn_value(4, &1u32.to_le_bytes())),
                        cell(bytesn_value(1, &[10])),
                        cell(bytesn_value(events::MISC_SIZE as u32, &misc)),
                    ]
                    .into(),
                ),
            },
            Op::Log,
        ]);

        preimage(
            vec![amount, cal_hi, cal_lo],
            vec![amount, cal_hi, cal_lo, eh_hi, eh_lo],
            ops,
            &[seq_av],
            vec![],
        )
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
fn deposit_via_vault_matches_corpus() {
    let theirs = corpus_zkir("vault", "depositViaVault");
    let ours = xce::deposit_via_vault().ir;
    let s = Scenario::new();
    assert_call_compatible(&ours, &theirs, &s.preimage_vault());
}

#[test]
fn token_deposit_matches_corpus() {
    let theirs = corpus_zkir("token", "deposit");
    let ours = xce::token_deposit().ir;
    let s = Scenario::new();
    assert_call_compatible(&ours, &theirs, &s.preimage_token());
}

/// Criterion 3 on the return-value path: tampering with any transcript
/// element or any private witness (the returned hash limbs, cc-rand, ep)
/// must be rejected by both vault artifacts, with zero disagreements.
#[test]
fn deposit_via_vault_rejects_tampering() {
    let theirs = corpus_zkir("vault", "depositViaVault");
    let ours = xce::deposit_via_vault().ir;
    let s = Scenario::new();

    let pi = s.preimage_vault();
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
