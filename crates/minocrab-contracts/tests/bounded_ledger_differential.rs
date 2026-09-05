//! `bounded_ledger.compact` — the M31 differential: a `Uint<0..1>` in LEDGER
//! position, against compactc 0.34.0's own artifact.
//!
//! WHY THIS FIXTURE EXISTS, and why it is separate from `bounded.compact`.
//! compactc issue #588 (fixed 0.33.108, CHANGELOG.md at compactc-v0.34.0)
//! gives a `Uint<0..1>` a ONE-byte alignment on the Impact op when it sits
//! in LEDGER position; `bounded.compact`'s own `b1` takes it as a circuit
//! ARGUMENT, and compactc's compiled `b1.zkir` is byte-identical under both
//! 0.33.0-rc.2 and 0.34.0 — argument position never moved
//! (notes/version-bump.org "Bump 1 — 2026-09-05" §"Family E"). Only ledger
//! position did, and no compiled corpus artifact and no existing fixture
//! puts one there, so this fixture is what pins it.
//!
//! THE POINT of comparing against a COMPILED ARTIFACT rather than computing
//! the byte ourselves: `bounded_differential`'s own ABI check
//! (`compactc_s_abi_agrees_with_the_leafs`) reads compactc's own `maxval`
//! out of `contract-info.json` and reconstructs the FAB alignment with
//! `minocrab::v3::uint_atom_bytes` — the SAME formula this crate's
//! lowering uses to build the circuit in the first place — so a wrong
//! formula agrees with itself and that check can never see it
//! (notes/version-bump.org, decision list item 3). This differential
//! instead compares our lowering's actual instruction stream, alignment
//! byte included, against compactc's compiled `.zkir` — so a wrong
//! `uint_atom_bytes` fails it regardless of what our own formula believes.
//!
//! VERIFIED (recorded here since the check itself cannot re-run the old
//! code): reverting `uint_atom_bytes(0)` to the old `0` and re-running
//! `identical_instruction_streams` fails both cases, each on the
//! alignment literal moving from `0x01` (compactc 0.34.0's artifact) to
//! `0x00` (what the reverted formula emits) inside the `impact`
//! instruction's operands — restoring the fix makes both pass again.

use std::borrow::Cow;

use midnight_base_crypto::fab::{AlignedValue, Alignment, AlignmentAtom, AlignmentSegment, Value, ValueAtom};
use midnight_onchain_vm::ops::Op;
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::db::InMemoryDB;
use midnight_transient_crypto::hash::transient_commit;
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage};
use midnight_transient_crypto::repr::FieldRepr;
use minocrab::Fr;
use minocrab_contracts::bounded_ledger::BoundedLedger;
use minocrab_sim::v3::assert_call_compatible;
use minocrab_zkir::v3::{to_zkir_string, IrSource};

type VmOp = Op<ResultModeVerify, InMemoryDB>;

/// compactc's artifact for one fixture circuit.
fn theirs(name: &str) -> IrSource {
    let path = format!(
        "{}/tests/fixtures/bounded_ledger/out/zkir/{name}.zkir",
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

/// `cell = disclose(x)` on ledger field 0 — `push key (field 0); pushs
/// value; ins 1`, the same shape `bounded_differential.rs`'s
/// `flag_write_transcript` and `opaque_differential.rs`'s
/// `cell_write_transcript` use for a plain `Cell` write. The VALUE's own
/// `AlignmentAtom::Bytes { length: 1 }` is the fix under test: under the
/// OLD `uint_atom_bytes(0) == 0`, our circuit's own `impact` instruction
/// declares a zero-byte value and this one-byte transcript entry no
/// longer matches it.
fn write_transcript(v: u8) -> Vec<Fr> {
    transcript(&[
        Op::Push {
            storage: false,
            value: bytes1_value(0).into(),
        },
        Op::Push {
            storage: true,
            value: bytes1_value(v).into(),
        },
        Op::Ins {
            cached: false,
            n: 1,
        },
    ])
}

fn fr(v: u128) -> Fr {
    Fr::from_le_bytes(&v.to_le_bytes()).expect("16 bytes fit the native field")
}

/// Serialized ZKIR with every `%name.index` identifier replaced by
/// `%<order of first appearance>` — the same canonicalization
/// `bounded_differential.rs` and `opaque_differential.rs` use. Names are the
/// only thing the two artifacts may differ in; the `impact` instruction's
/// OWN OPERANDS — including the alignment byte this fixture is about — are
/// not identifiers and survive untouched, so this comparison pins them
/// exactly.
fn canonical(ir: &IrSource) -> String {
    let ir = &minocrab_ir::v3::passes::folded(ir);
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

/// THE HEADLINE CLAIM: our lowering of a `Uint<0..1>` LEDGER cell is
/// compactc's, op for op and immediate for immediate — the alignment byte
/// included. This is strictly stronger than call-compatibility (identical
/// streams cannot produce differing `pis`), and it is what actually pins
/// the fix: `uint_atom_bytes(0) == 0` (the old value) makes both `blWrite`
/// and `blRead` differ from compactc's artifact by exactly one operand
/// (`0x00` where compactc says `0x01`); `uint_atom_bytes(0) == 1` (the
/// fix) makes them equal.
#[test]
fn identical_instruction_streams() {
    assert_eq!(
        canonical(&BoundedLedger::bl_write().ir),
        canonical(&theirs("blWrite")),
        "blWrite: our lowering of the Uint<0..1> ledger write differs from compactc's \
         (check the impact instruction's alignment operand)"
    );
    assert_eq!(
        canonical(&BoundedLedger::bl_read().ir),
        canonical(&theirs("blRead")),
        "blRead: our lowering of the Uint<0..1> ledger read differs from compactc's \
         (check the impact instruction's alignment operand)"
    );
}

/// CALL-COMPATIBILITY on a real write transcript, so the fix is checked
/// against upstream's own `check()` and not only against a raw text diff.
/// The write's VALUE carries an explicit one-byte `AlignmentAtom`
/// (`bytes1_value`); under the old zero-byte formula our circuit's own
/// `impact` instruction disagrees with that transcript entry and this
/// preimage is REJECTED by our artifact (verified by temporarily reverting
/// the fix — see this file's header).
#[test]
fn the_write_is_call_compatible() {
    let pi = preimage(vec![fr(0)], write_transcript(0));
    assert_call_compatible(&BoundedLedger::bl_write().ir, &theirs("blWrite"), &pi);
}

/// THE ABI ROUND-TRIP, same criterion `bounded_differential.rs` and
/// `opaque_differential.rs` use: compactc's own `contract-info.json`,
/// flattened, against the `CircuitAbi` of the Rust leaf. This is
/// deliberately NOT the instrument that would catch the alignment bug
/// (notes/version-bump.org, decision list item 3 explains why: both sides
/// of this equality go through the SAME `uint_atom_bytes` formula) — it is
/// here to pin everything else about the type (the `maxval` and the
/// `Prim`), so `identical_instruction_streams` above is doing the one job
/// this check structurally cannot.
#[test]
fn compactc_s_abi_agrees_with_the_leaf() {
    use minocrab::v3::CircuitAbi;
    use minocrab::Public;
    use minocrab_abi::info::ContractInfo;
    use minocrab_std::v3::BoundedUint;

    let text = std::fs::read_to_string(format!(
        "{}/tests/fixtures/bounded_ledger/out/compiler/contract-info.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("the pinned compactc's contract-info is committed");
    let info = ContractInfo::parse(&text).expect("contract-info parses");

    let circuit = info.circuit("blWrite").expect("blWrite is exported");
    let flat = circuit.arguments[0]
        .ty
        .flatten()
        .expect("a Uint<0..1> flattens");
    assert_eq!(flat.atoms, <BoundedUint<1, Public> as CircuitAbi>::atoms());
    assert_eq!(flat.prims, <BoundedUint<1, Public> as CircuitAbi>::prims());
}
