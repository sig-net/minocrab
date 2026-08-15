//! events base/emit1/emit2/emit4: call-compatibility with the corpus
//! artifacts per notes/ledger-abi.org §6 — the `log` (emit) op and the
//! serialize<T,N> layout against real compactc artifacts.

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
use minocrab_contracts::events;
use minocrab_sim::v3::simulate;
use minocrab_zkir::v3::IrSource;

type VmOp = Op<ResultModeVerify, InMemoryDB>;

fn corpus_zkir(name: &str) -> IrSource {
    let path = format!(
        "{}/../../corpus/zkir/signet-midnight-experiments/experiments/events/contract/src/events/zkir/{name}.zkir",
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

fn b32_slots(bytes: &[u8; 32]) -> (Fr, Fr) {
    (
        Fr::from(u64::from(bytes[31])),
        Fr::from_le_bytes(&bytes[..31]).unwrap(),
    )
}

struct Scenario {
    recipient: [u8; 32],
    amount: u128,
    sequence: u64,
}

impl Scenario {
    fn new() -> Scenario {
        let mut recipient = [0u8; 32];
        recipient[..8].copy_from_slice(b"events-r");
        recipient[31] = 0x66;
        Scenario {
            recipient,
            amount: 424_242,
            sequence: 7,
        }
    }

    /// The serialized `Misc { name: pad(32, "deposit-<i>"), payload:
    /// serialize<DepositEvent, 256>({amount, sequence, recipient}) }`.
    fn misc_bytes(&self, i: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; events::MISC_SIZE];
        let name = events::event_name(i);
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        bytes[32..48].copy_from_slice(&self.amount.to_le_bytes());
        bytes[48..56].copy_from_slice(&self.sequence.to_le_bytes());
        bytes[56..88].copy_from_slice(&self.recipient);
        bytes
    }

    /// The reference Impact program with `emits` events.
    fn ops(&self, emits: usize) -> Vec<VmOp> {
        let key = |i: u8| Key::Value(bytesn_value(1, &[i]));
        let amount_av = bytesn_value(16, &self.amount.to_le_bytes());
        let mut ops: Vec<VmOp> = Vec::new();
        if emits > 0 {
            // const sequence = callCount as Uint<64>
            ops.extend([
                Op::Dup { n: 0 },
                Op::Idx {
                    cached: false,
                    push_path: false,
                    path: vec![key(events::CALL_COUNT)].into(),
                },
                Op::Popeq {
                    cached: true,
                    result: bytesn_value(8, &self.sequence.to_le_bytes()),
                },
            ]);
        }
        // The shared workload.
        ops.extend([
            Op::Idx {
                cached: false,
                push_path: true,
                path: vec![key(events::CALL_COUNT)].into(),
            },
            Op::Addi { immediate: 1 },
            Op::Ins { cached: true, n: 1 },
            Op::Push {
                storage: false,
                value: cell(bytesn_value(1, &[events::LAST_AMOUNT])),
            },
            Op::Push {
                storage: true,
                value: cell(amount_av.clone()),
            },
            Op::Ins {
                cached: false,
                n: 1,
            },
            Op::Idx {
                cached: false,
                push_path: true,
                path: vec![key(events::BALANCES)].into(),
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
        // The emits.
        for i in 0..emits {
            ops.extend([
                Op::Push {
                    storage: false,
                    value: StateValue::Array(
                        vec![
                            cell(bytesn_value(4, &events::MISC_VERSION.to_le_bytes())),
                            cell(bytesn_value(1, &[events::MISC_TAG])),
                            cell(bytesn_value(
                                events::MISC_SIZE as u32,
                                &self.misc_bytes(i),
                            )),
                        ]
                        .into(),
                    ),
                },
                Op::Log,
            ]);
        }
        ops
    }

    fn preimage(&self, emits: usize) -> ProofPreimage {
        let (r_hi, r_lo) = b32_slots(&self.recipient);
        let inputs = vec![r_hi, r_lo, Fr::from(self.amount)];

        let mut transcript = Vec::new();
        for op in self.ops(emits) {
            op.field_repr(&mut transcript);
        }
        let mut outputs = Vec::new();
        if emits > 0 {
            ValueReprAlignedValue(bytesn_value(8, &self.sequence.to_le_bytes()))
                .field_repr(&mut outputs);
        }

        let rand = Fr::from(0xeee_e7u64);
        let comm = transient_commit(&inputs[..], rand);
        ProofPreimage {
            inputs,
            private_transcript: vec![],
            public_transcript_inputs: transcript,
            public_transcript_outputs: outputs,
            binding_input: 0.into(),
            communications_commitment: Some((comm, rand)),
            key_location: KeyLocation(Cow::Borrowed("minocrab-contracts-test")),
        }
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
fn base_matches_corpus() {
    let theirs = corpus_zkir("base");
    let ours = events::base().ir;
    let s = Scenario::new();
    assert_call_compatible(&ours, &theirs, &s.preimage(0));
}

#[test]
fn emit1_matches_corpus() {
    let theirs = corpus_zkir("emit1");
    let ours = events::emit_n(1).ir;
    let s = Scenario::new();
    assert_call_compatible(&ours, &theirs, &s.preimage(1));
}

#[test]
fn emit2_matches_corpus() {
    let theirs = corpus_zkir("emit2");
    let ours = events::emit_n(2).ir;
    let s = Scenario::new();
    assert_call_compatible(&ours, &theirs, &s.preimage(2));
}

#[test]
fn emit4_matches_corpus() {
    let theirs = corpus_zkir("emit4");
    let ours = events::emit_n(4).ir;
    let s = Scenario::new();
    assert_call_compatible(&ours, &theirs, &s.preimage(4));
}

/// Criterion 3: a transcript whose event payload disagrees with the
/// circuit's emit (tampered amount inside the logged bytes) must be
/// rejected by BOTH artifacts.
#[test]
fn emit1_rejects_tampered_event_payload() {
    let theirs = corpus_zkir("emit1");
    let ours = events::emit_n(1).ir;
    let s = Scenario::new();

    let mut pi = s.preimage(1);
    let honest = pi.public_transcript_inputs.clone();
    // Rebuild the transcript with a different amount inside the event only.
    let tampered_scenario = Scenario {
        amount: s.amount + 1,
        ..Scenario::new()
    };
    let mut tampered = Vec::new();
    for op in tampered_scenario.ops(1) {
        op.field_repr(&mut tampered);
    }
    // Splice: keep the honest workload prefix, take the tampered event
    // block (the trailing Push+Log elements).
    let event_len = {
        let mut b = Vec::new();
        for op in &s.ops(1)[s.ops(1).len() - 2..] {
            op.field_repr(&mut b);
        }
        b.len()
    };
    let n = honest.len();
    pi.public_transcript_inputs[..n - event_len].copy_from_slice(&honest[..n - event_len]);
    pi.public_transcript_inputs[n - event_len..]
        .copy_from_slice(&tampered[tampered.len() - event_len..]);

    assert!(simulate(&ours, &pi).is_err(), "ours must reject");
    assert!(simulate(&theirs, &pi).is_err(), "corpus must reject");
}

// ---- M11 stage 6: the Borsh twin ---------------------------------------------

/// `events_borsh` emits THE SAME BYTES as `events`, built out of declared
/// [`minocrab_std::v3::borsh`] types instead of hand-rolled `Serializer`
/// pushes — and the equality is BYTE-IDENTICAL ZKIR, not merely equal
/// payloads.
///
/// That is the strongest form the claim can take: identical ZKIR means the
/// twin is the same circuit, so the same rows, the same interface, the same
/// PI vector and the same 288-byte `Misc` transcript, and compactc's own
/// differential below covers it verbatim. Stage 0 had already proved the
/// deployed payload IS canonical Borsh; this proves the API PRODUCES it, on a
/// real event shape, for nothing.
#[test]
fn borsh_twins_are_byte_identical_to_the_originals() {
    use minocrab_contracts::events_borsh;
    use minocrab_zkir::v3::to_zkir_string;
    for (name, original, twin) in [
        ("base", events::base(), events_borsh::base()),
        ("emit1", events::emit_n(1), events_borsh::emit_n(1)),
        ("emit2", events::emit_n(2), events_borsh::emit_n(2)),
        ("emit4", events::emit_n(4), events_borsh::emit_n(4)),
    ] {
        assert_eq!(
            to_zkir_string(&original.ir).expect("the original serializes"),
            to_zkir_string(&twin.ir).expect("the twin serializes"),
            "{name}: the Borsh twin is not byte-identical to the pinned original"
        );
    }
}

/// ...and the twin is run against compactc's golden ITSELF, on the preimage
/// whose transcript carries the exact 288-byte `Misc` bytes. Redundant while
/// the ZKIR is identical, and deliberately kept: the day the twin diverges,
/// this is the test that says whether the BYTES still agree with the deployed
/// artifact, which is the property stage 6 is actually about.
#[test]
fn borsh_twins_match_the_corpus() {
    use minocrab_contracts::events_borsh;
    let s = Scenario::new();
    assert_call_compatible(&events_borsh::base().ir, &corpus_zkir("base"), &s.preimage(0));
    for n in [1usize, 2, 4] {
        assert_call_compatible(
            &events_borsh::emit_n(n).ir,
            &corpus_zkir(&format!("emit{n}")),
            &s.preimage(n),
        );
    }
}
