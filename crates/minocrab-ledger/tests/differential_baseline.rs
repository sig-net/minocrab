//! THE acceptance test for the ledger-op layer (notes/ledger-abi.org §6):
//! rebuild corpus baseline circuits with minocrab-ledger + Circuit3 and
//! prove call-compatibility with compactc's artifacts — identical typed
//! inputs/outputs schemas, and identical `pis` + `pi_skips` from the v3
//! simulator on the same ProofPreimage, with upstream `check()` agreeing.
//!
//! Corpus source (annotated in notes/ledger-abi.org §5):
//!   export ledger callCount: Counter;                  // field 0
//!   export ledger lastAmount: Uint<128>;               // field 1
//!   export ledger balances: Map<Bytes<32>, Uint<128>>; // field 2
//!   noop(): callCount.increment(1)
//!   base(recipient: Bytes<32>, amount: Uint<128>):
//!     callCount.increment(1); lastAmount = a; balances.insert(r, a)

use std::borrow::Cow;

use midnight_base_crypto::fab::{
    Alignment, AlignmentAtom, AlignmentSegment, AlignedValue, Value, ValueAtom,
};
use midnight_onchain_vm::ops::{Key, Op};
use midnight_onchain_state::state::StateValue;
use midnight_storage::arena::Sp;
use midnight_transient_crypto::hash::transient_commit;
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage, Zkir};
use midnight_transient_crypto::repr::FieldRepr;
use minocrab::v3::{Circuit3, FieldT};
use minocrab::Fr;
use minocrab_ledger::{cell_write, counter_increment, emit, map_insert, ImpactElem, LedgerValue, VmOp};
use minocrab_sim::v3::simulate;

fn corpus_zkir(rel: &str) -> minocrab_zkir::v3::IrSource {
    let path = format!("{}/../../corpus/zkir/{rel}", env!("CARGO_MANIFEST_DIR"));
    minocrab_zkir::v3::read_zkir(&path).expect("corpus golden parses")
}

fn transcript(ops: &[VmOp]) -> Vec<Fr> {
    let mut out = Vec::new();
    for op in ops {
        op.field_repr(&mut out);
    }
    out
}

fn bytes1_value(v: u8) -> AlignedValue {
    AlignedValue::new(
        Value(vec![ValueAtom(vec![v]).normalize()]),
        Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 1 })]),
    )
    .unwrap()
}

fn bytesn_value(n: u32, bytes: &[u8]) -> AlignedValue {
    AlignedValue::new(
        Value(vec![ValueAtom(bytes.to_vec()).normalize()]),
        Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes { length: n })]),
    )
    .unwrap()
}

fn cell(av: AlignedValue) -> StateValue {
    StateValue::Cell(Sp::new(av))
}

fn preimage(inputs: Vec<Fr>, transcript: Vec<Fr>, rand: Fr) -> ProofPreimage {
    let comm = transient_commit(&inputs[..], rand);
    ProofPreimage {
        inputs,
        private_transcript: vec![],
        public_transcript_inputs: transcript,
        public_transcript_outputs: vec![],
        binding_input: 0.into(),
        communications_commitment: Some((comm, rand)),
        key_location: KeyLocation(Cow::Borrowed("minocrab-ledger-test")),
    }
}

/// Simulate both artifacts on the same preimage; assert full §6
/// call-compatibility.
fn assert_call_compatible(
    ours: &minocrab_zkir::v3::IrSource,
    theirs: &minocrab_zkir::v3::IrSource,
    pi: &ProofPreimage,
) {
    // 1. Typed interface: same input/output types in the same order.
    let types = |ir: &minocrab_zkir::v3::IrSource| {
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

    // 2. PI stream: identical pis and pi_skips.
    let our_run = simulate(ours, pi).expect("our artifact accepts");
    let their_run = simulate(theirs, pi).expect("corpus artifact accepts");
    assert_eq!(our_run.pi_skips, their_run.pi_skips, "pi_skips differ");
    assert_eq!(our_run.pis, their_run.pis, "PI vectors differ");

    // 3. Upstream check() agrees with both.
    assert_eq!(ours.check(pi).expect("upstream accepts ours"), our_run.pi_skips);
    assert_eq!(
        theirs.check(pi).expect("upstream accepts theirs"),
        their_run.pi_skips
    );
}

const IDX_FIELD0: fn() -> VmOp = || Op::Idx {
    cached: false,
    push_path: true,
    path: vec![Key::Value(bytes1_value(0))].into(),
};

#[test]
fn noop_matches_corpus() {
    let theirs = corpus_zkir(
        "signet-midnight-experiments/experiments/baseline/contract/src/baseline/zkir/noop.zkir",
    );

    let mut c = Circuit3::new();
    let one = c.constant(1u64);
    emit(&mut c, one, &counter_increment(0, 1));
    let ours = c.finish(true).ir;

    let real_ops = [
        IDX_FIELD0(),
        Op::Addi { immediate: 1 },
        Op::Ins { cached: true, n: 1 },
    ];
    let pi = preimage(vec![], transcript(&real_ops), Fr::from(0xbeefu64));
    assert_call_compatible(&ours, &theirs, &pi);
}

#[test]
fn base_matches_corpus() {
    let theirs = corpus_zkir(
        "signet-midnight-experiments/experiments/baseline/contract/src/baseline/zkir/base.zkir",
    );

    // Concrete arguments: recipient = Bytes<32> {hi = 0xab, lo = 12345},
    // amount = 777.
    let (r_hi, r_lo, amount) = (0xabu8, 12345u64, 777u64);
    let mut r_bytes = [0u8; 32];
    r_bytes[..8].copy_from_slice(&r_lo.to_le_bytes());
    r_bytes[31] = r_hi;

    // Our circuit, mirroring base(): args in compactc's flattened order.
    let mut c = Circuit3::new();
    let rec_hi = c.arg::<FieldT>("recipient_hi");
    let rec_lo = c.arg::<FieldT>("recipient_lo");
    let amt = c.arg::<FieldT>("amount");
    c.assert_bits(rec_hi, 8);
    c.assert_bits(rec_lo, 248);
    c.assert_bits(amt, 128);
    let a = c.disclose(amt, "amount");
    let r0 = c.disclose(rec_hi, "recipient hi");
    let r1 = c.disclose(rec_lo, "recipient lo");
    let one = c.constant(1u64);

    let amount_val = LedgerValue::bytes(16, vec![ImpactElem::Wire(a)]);
    let recipient_val = LedgerValue::bytes(32, vec![ImpactElem::Wire(r0), ImpactElem::Wire(r1)]);
    let mut ops = counter_increment(0, 1);
    ops.extend(cell_write(1, &amount_val));
    ops.extend(map_insert(2, &recipient_val, &amount_val));
    emit(&mut c, one, &ops);
    let ours = c.finish(true).ir;

    // The reference transcript from real Impact-VM ops.
    let amount_av = bytesn_value(16, &amount.to_le_bytes());
    let real_ops = [
        IDX_FIELD0(),
        Op::Addi { immediate: 1 },
        Op::Ins { cached: true, n: 1 },
        // lastAmount = a
        Op::Push {
            storage: false,
            value: cell(bytes1_value(1)),
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
            path: vec![Key::Value(bytes1_value(2))].into(),
        },
        Op::Push {
            storage: false,
            value: cell(bytesn_value(32, &r_bytes)),
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
    ];

    let inputs = vec![
        Fr::from(u64::from(r_hi)),
        Fr::from(r_lo),
        Fr::from(amount),
    ];
    let pi = preimage(inputs, transcript(&real_ops), Fr::from(0xf00du64));
    assert_call_compatible(&ours, &theirs, &pi);
}
