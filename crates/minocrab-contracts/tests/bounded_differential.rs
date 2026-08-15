//! `bounded.compact` — the M14 differential: [`minocrab_std::v3::BoundedUint`]
//! against compactc's own artifacts, for every shape a `Uint<0..n>` bound
//! can take.
//!
//! WHY THE FIXTURE IS OURS. No compiled corpus artifact carries a
//! non-power-of-two bound. The scan: 788 `.zkir` files under `corpus/zkir`,
//! 66 of them v3 (only the three sig-net sources are compiled with
//! `--feature-zkir-v3`, and our IR is v3) — and none of the 66 has one. The
//! corpus contracts that DO use such a bound are
//! `compact/examples/multiconst` (whose `test5.zkir` really does contain
//! `less_than x 0x0a bits=4` for an `x as Uint<0..10>`, but is v2 output) and
//! midnight-serde's `serde-fixtures.compact` (`Uint<0..300>`, `<0..1000>`,
//! `<0..70000>` — every circuit `pure`, and a pure exported circuit gets no
//! `.zkir` at all). So this is the established tiny.compact-style fallback:
//! `tests/fixtures/bounded/bounded.compact`, compiled with the PINNED
//! compactc, with the exact invocation in its header.
//!
//! THREE CLAIMS, in increasing strength:
//!
//! 1. [`assert_call_compatible`] — the notes/ledger-abi.org §6 criterion
//!    every other differential in this crate uses: same typed input/output
//!    schemas, same `pis` and `pi_skips` from the v3 simulator on one
//!    preimage, and upstream `check()` agreeing with both.
//! 2. `identical_instruction_streams` — the artifacts are the SAME CIRCUIT,
//!    compared as serialized ZKIR up to identifier RENAMING (our
//!    temporaries are `%lt.N` where compactc's are `%tmp.N`, and a derived
//!    struct's argument labels are the informative `%order_kind.0` where
//!    compactc repeats `%order.0` — notes/contract-api.org §ArgPath). Every
//!    op, every immediate, every width and every operand position is pinned.
//!    That is what says the LOWERING of a bound is compactc's, not ours.
//! 3. `both_reject_the_first_illegal_value` / `both_accept_the_last_legal_value`
//!    — the bound is exactly where the source says, and it is load-bearing.
//!    Claims 1 and 2 are satisfied by honest preimages whatever the
//!    constraint says; these two are the pair that an off-by-one in either
//!    direction fails.

use std::borrow::Cow;

use midnight_base_crypto::fab::{
    AlignedValue, Alignment, AlignmentAtom, AlignmentSegment, Value, ValueAtom,
};
use midnight_onchain_vm::ops::{Key, Op};
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::db::InMemoryDB;
use midnight_transient_crypto::hash::transient_commit;
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage, Zkir};
use midnight_transient_crypto::repr::FieldRepr;
use minocrab::v3::Compiled3;
use minocrab::Fr;
use minocrab_contracts::bounded;
use minocrab_sim::v3::simulate;
use minocrab_zkir::v3::{to_zkir_string, IrSource};

type VmOp = Op<ResultModeVerify, InMemoryDB>;

/// compactc's artifact for one fixture circuit.
fn theirs(name: &str) -> IrSource {
    let path = format!(
        "{}/tests/fixtures/bounded/out/zkir/{name}.zkir",
        env!("CARGO_MANIFEST_DIR")
    );
    minocrab_zkir::v3::read_zkir(&path).expect("the pinned compactc's artifact parses")
}

fn bytes1_value(v: u8) -> AlignedValue {
    AlignedValue::new(
        Value(vec![ValueAtom(vec![v]).normalize()]),
        Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes {
            length: 1,
        })]),
    )
    .unwrap()
}

fn transcript(ops: &[VmOp]) -> Vec<Fr> {
    let mut out = Vec::new();
    for op in ops {
        op.field_repr(&mut out);
    }
    out
}

fn preimage(inputs: Vec<Fr>, transcript: Vec<Fr>) -> ProofPreimage {
    let rand = Fr::from(0xb0_u64);
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

/// `dummy.increment(1)` on ledger field 0 — the whole transcript of every
/// single-argument circuit in the fixture.
fn increment_transcript() -> Vec<Fr> {
    transcript(&[
        Op::Idx {
            cached: false,
            push_path: true,
            path: vec![Key::Value(bytes1_value(0))].into(),
        },
        Op::Addi { immediate: 1 },
        Op::Ins { cached: true, n: 1 },
    ])
}

/// `flag = less` on ledger field 1 — `push key; pushs value; ins 1`.
fn flag_write_transcript(less: bool) -> Vec<Fr> {
    transcript(&[
        Op::Push {
            storage: false,
            value: bytes1_value(1).into(),
        },
        Op::Push {
            storage: true,
            value: bytes1_value(u8::from(less)).into(),
        },
        Op::Ins {
            cached: false,
            n: 1,
        },
    ])
}

/// The notes/ledger-abi.org §6 criterion, verbatim from the crate's other
/// differentials.
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
    let their_run = simulate(theirs, pi).expect("compactc's artifact accepts");
    assert_eq!(our_run.pi_skips, their_run.pi_skips, "pi_skips differ");
    assert_eq!(our_run.pis, their_run.pis, "PI vectors differ");

    assert_eq!(
        ours.check(pi).expect("upstream accepts ours"),
        our_run.pi_skips
    );
    assert_eq!(
        theirs.check(pi).expect("upstream accepts compactc's"),
        their_run.pi_skips
    );
}

/// Serialized ZKIR with every `%name.index` identifier replaced by
/// `%<order of first appearance>`.
///
/// Names are the ONLY thing the two artifacts are allowed to differ in, and
/// they are cosmetic to the ledger ABI (order and type are the contract —
/// notes/contract-api.org §ArgPath). Everything else — the op sequence, the
/// immediates, the widths, which operand sits where — survives this and is
/// therefore asserted.
fn canonical(ir: &IrSource) -> String {
    let text = to_zkir_string(ir).expect("serializes");
    let mut renames: Vec<(String, String)> = Vec::new();
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(at) = rest.find('%') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let end = rest[1..]
            .find(|ch: char| !(ch.is_alphanumeric() || ch == '_' || ch == '.'))
            .map(|i| i + 1)
            .unwrap_or(rest.len());
        let name = &rest[..end];
        let next = renames.len();
        let canon = match renames.iter().find(|(from, _)| from == name) {
            Some((_, to)) => to.clone(),
            None => {
                let to = format!("%{next}");
                renames.push((name.to_string(), to.clone()));
                to
            }
        };
        out.push_str(&canon);
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// Every single-argument circuit of the fixture: our builder, compactc's
/// artifact name, and a LARGEST-LEGAL witness.
fn cases() -> Vec<(&'static str, fn() -> Compiled3, Vec<u128>)> {
    vec![
        ("b10", bounded::b10 as fn() -> Compiled3, vec![9]),
        ("b300", bounded::b300, vec![299]),
        ("b1000", bounded::b1000, vec![999]),
        ("b70000", bounded::b70000, vec![69_999]),
        ("b1", bounded::b1, vec![0]),
        ("b2", bounded::b2, vec![1]),
        ("b256", bounded::b256, vec![255]),
        ("b255", bounded::b255, vec![254]),
        ("bEnum", bounded::b_enum, vec![2]),
        // kind, quantity, price, tag — field order is the slot order.
        (
            "bStruct",
            bounded::b_struct,
            vec![2, 999, u64::MAX as u128, 0xdead_beef],
        ),
    ]
}

fn fr(v: u128) -> Fr {
    Fr::from_le_bytes(&v.to_le_bytes()).expect("16 bytes fit the native field")
}

/// Claim 2, and the headline: for every bound, our circuit IS compactc's,
/// op for op and immediate for immediate.
#[test]
fn identical_instruction_streams() {
    for (name, build, _) in cases() {
        assert_eq!(
            canonical(&build().ir),
            canonical(&theirs(name)),
            "{name}: our lowering of the bound differs from compactc's"
        );
    }
    assert_eq!(
        canonical(&bounded::b_compare().ir),
        canonical(&theirs("bCompare")),
        "bCompare: the constraint width, the comparison width or the write differs"
    );
}

/// Claim 1: call-compatibility on a legal witness, per circuit.
#[test]
fn every_bound_is_call_compatible() {
    for (name, build, args) in cases() {
        let ours = build().ir;
        let pi = preimage(
            args.iter().copied().map(fr).collect(),
            increment_transcript(),
        );
        assert_call_compatible(&ours, &theirs(name), &pi);
    }
}

/// Claim 1 for the comparing circuit, whose transcript carries the
/// comparison's RESULT — so a comparison running at the wrong width would
/// show up as a differing `pis`, not merely as a differing stream.
#[test]
fn the_comparison_is_call_compatible_both_ways() {
    for (a, b, less) in [(0u128, 69_999u128, true), (69_999, 0, false), (5, 5, false)] {
        let pi = preimage(vec![fr(a), fr(b)], flag_write_transcript(less));
        assert_call_compatible(&bounded::b_compare().ir, &theirs("bCompare"), &pi);
    }
}

/// Claim 3: the bound is real. One value past the range end is rejected by
/// both artifacts, at every shape the table produces — the `less_than` arm
/// (`b10`/`b300`/`b1000`/`b70000`/`b255`/`bEnum`), the `constrain_bits` arm
/// (`b256`), the `constrain_to_boolean` arm (`b2`) and the `constrain_eq 0`
/// arm (`b1`).
#[test]
fn both_reject_the_first_illegal_value() {
    let over: Vec<(&str, fn() -> Compiled3, u128)> = vec![
        ("b10", bounded::b10 as fn() -> Compiled3, 10),
        ("b300", bounded::b300, 300),
        ("b1000", bounded::b1000, 1000),
        ("b70000", bounded::b70000, 70_000),
        ("b1", bounded::b1, 1),
        ("b2", bounded::b2, 2),
        ("b256", bounded::b256, 256),
        ("b255", bounded::b255, 255),
        ("bEnum", bounded::b_enum, 3),
    ];
    for (name, build, first_illegal) in over {
        let pi = preimage(vec![fr(first_illegal)], increment_transcript());
        let ours = build().ir;
        let theirs = theirs(name);
        assert!(
            simulate(&ours, &pi).is_err(),
            "{name}: ours accepted {first_illegal}, which is one past the range end"
        );
        assert!(
            simulate(&theirs, &pi).is_err(),
            "{name}: compactc's accepted {first_illegal}"
        );
        assert!(ours.check(&pi).is_err(), "{name}: upstream accepted ours");
        assert!(
            theirs.check(&pi).is_err(),
            "{name}: upstream accepted compactc's"
        );
    }
}

/// THE ABI ROUND-TRIP, closing the loop the interface generator opens:
/// compactc's own `contract-info.json` for this fixture, flattened by
/// `minocrab_abi::info`, must agree slot for slot with the `CircuitAbi` of
/// the Rust types the generator would emit for it — atoms AND primitive
/// types. Those two lists agreeing IS the agreement check every interface
/// crate rests on (crates/minocrab-abi/src/check.rs).
///
/// It also pins the EXCLUSIVE range end from the artifact side: compactc
/// publishes `maxval: 69999` for the source's `Uint<0..70000>`, and the type
/// that agrees with it is `BoundedUint<70000>`.
#[test]
fn compactc_s_abi_agrees_with_the_leafs() {
    use minocrab_abi::info::ContractInfo;
    use minocrab::v3::CircuitAbi;
    use minocrab::Public;
    use minocrab_std::v3::{BoundedUint, Bytes, Uint};

    let text = std::fs::read_to_string(format!(
        "{}/tests/fixtures/bounded/out/compiler/contract-info.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("the pinned compactc's contract-info is committed");
    let info = ContractInfo::parse(&text).expect("contract-info parses");

    /// The Rust type each fixture circuit's ONE argument has.
    fn ours(name: &str) -> (Vec<minocrab::AlignmentAtom>, Vec<minocrab::v3::Prim>) {
        macro_rules! abi {
            ($ty:ty) => {
                (<$ty as CircuitAbi>::atoms(), <$ty as CircuitAbi>::prims())
            };
        }
        match name {
            "b10" => abi!(BoundedUint<10, Public>),
            "b300" => abi!(BoundedUint<300, Public>),
            "b1000" => abi!(BoundedUint<1000, Public>),
            "b70000" => abi!(BoundedUint<70_000, Public>),
            "b1" => abi!(BoundedUint<1, Public>),
            "b2" => abi!(BoundedUint<2, Public>),
            // A power-of-two bound is a bit width, and the generator emits
            // the SIZED leaf for it — which must agree with the artifact
            // just as the bounded one does.
            "b256" => abi!(Uint<8, Public>),
            "b255" => abi!(BoundedUint<255, Public>),
            // A fieldless enum of k names is `Uint<0..k>`.
            "bEnum" => abi!(BoundedUint<3, Public>),
            other => panic!("no Rust type declared for `{other}`"),
        }
    }

    for name in [
        "b10", "b300", "b1000", "b70000", "b1", "b2", "b256", "b255", "bEnum",
    ] {
        let circuit = info.circuit(name).expect("the artifact exports it");
        let flat = circuit.arguments[0]
            .ty
            .flatten()
            .expect("a bounded uint flattens");
        let (atoms, prims) = ours(name);
        assert_eq!(flat.atoms, atoms, "{name}: FAB atoms disagree");
        assert_eq!(flat.prims, prims, "{name}: primitive types disagree");
    }

    // …and the struct, field by field, in declaration order.
    let order = info.circuit("bStruct").expect("bStruct is exported");
    let flat = order.arguments[0].ty.flatten().expect("Order flattens");
    let mut atoms = Vec::new();
    let mut prims = Vec::new();
    for (a, p) in [
        ours("bEnum"),
        (
            <BoundedUint<1000, Public> as CircuitAbi>::atoms(),
            <BoundedUint<1000, Public> as CircuitAbi>::prims(),
        ),
        (
            <Uint<64, Public> as CircuitAbi>::atoms(),
            <Uint<64, Public> as CircuitAbi>::prims(),
        ),
        (
            <Bytes<4, Public> as CircuitAbi>::atoms(),
            <Bytes<4, Public> as CircuitAbi>::prims(),
        ),
    ] {
        atoms.extend(a);
        prims.extend(p);
    }
    assert_eq!(flat.atoms, atoms, "Order: FAB atoms disagree");
    assert_eq!(flat.prims, prims, "Order: primitive types disagree");
}

/// ...and the LAST legal value is accepted by both, which is the other half
/// of "the bound is exactly where the source says".
#[test]
fn both_accept_the_last_legal_value() {
    for (name, build, args) in cases() {
        let pi = preimage(
            args.iter().copied().map(fr).collect(),
            increment_transcript(),
        );
        assert!(
            simulate(&build().ir, &pi).is_ok(),
            "{name}: ours rejected the largest legal value"
        );
        assert!(
            simulate(&theirs(name), &pi).is_ok(),
            "{name}: compactc's rejected the largest legal value"
        );
    }
}
