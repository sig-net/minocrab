//! `adts.compact` — the M16 differential: every ledger-ADT operation Compact
//! exposes, against compactc's own artifacts (notes/ledger-adts.org).
//!
//! WHY THE FIXTURE IS OURS. The corpus declares 25 `List`, 15 `MerkleTree`, 7
//! `HistoricMerkleTree` and 41 `Set` fields, but our IR is v3 and only the
//! three sig-net sources carry `--feature-zkir-v3`. Their v3 artifacts between
//! them exercise three of the thirty-one operations here: `Set.insert`,
//! `Set.member` and `List.pushFront`. So this is the M14/M15 fallback again —
//! our source, compiled with the PINNED compactc, the invocation in the
//! fixture's header.
//!
//! FOUR CLAIMS:
//!
//! 1. `identical_instruction_streams` — for all thirty-one circuits, our
//!    serialized ZKIR IS compactc's up to identifier renaming. Every opcode,
//!    every immediate, every `ins` depth, every `branch`/`jmp` skip.
//! 2. `push_front_matches_the_corpus` — the corpus provenance the fixture
//!    route costs, recovered where the corpus does have coverage: the Impact
//!    block `test-caller-contract`'s `submitSignatureRequest` emits for
//!    `requestLog.pushFront(requestId)`, against ours for the same operation
//!    on a different field.
//! 3. `compactc_s_abi_agrees_with_the_leaves` — the artifact's
//!    `contract-info.json`, flattened by `minocrab_abi::info`, against the
//!    `CircuitAbi` of the Rust types. This is where the new
//!    [`MerkleTreeDigest`] leaf's "one `field` atom, `Prim::Field`, no
//!    constraint" is checked rather than asserted.
//! 4. `the_tree_reads_are_accepted_by_upstream` — a preimage for the four
//!    tree-read circuits accepted by both artifacts and by upstream's
//!    `check()`, which is what says the `root`/`member`/`neg` opcodes mean
//!    here what they mean in the VM.

use std::borrow::Cow;

use midnight_base_crypto::fab::{
    AlignedValue, Alignment, AlignmentAtom, AlignmentSegment, Value, ValueAtom,
};
use midnight_onchain_state::state::StateValue;
use midnight_onchain_vm::ops::{Key, Op};
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_transient_crypto::hash::transient_commit;
use midnight_transient_crypto::repr::FieldRepr;
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage, Zkir};
use minocrab::v3::Compiled3;
use minocrab::Fr;
use minocrab_contracts::adts;
use minocrab_zkir::v3::{to_zkir_string, IrSource};

type VmOp = Op<ResultModeVerify, InMemoryDB>;

/// compactc's artifact for one fixture circuit.
fn theirs(name: &str) -> IrSource {
    let path = format!(
        "{}/tests/fixtures/adts/out/zkir/{name}.zkir",
        env!("CARGO_MANIFEST_DIR")
    );
    minocrab_zkir::v3::read_zkir(&path).expect("the pinned compactc's artifact parses")
}

/// The corpus's own `test-caller-contract` artifact.
fn corpus(name: &str) -> IrSource {
    let path = format!(
        "{}/../../corpus/zkir/signet-midnight-integration/packages/test-caller-contract/\
         src/test-caller-contract/zkir/{name}.zkir",
        env!("CARGO_MANIFEST_DIR")
    );
    minocrab_zkir::v3::read_zkir(&path).expect("the corpus artifact parses")
}

/// Serialized ZKIR with every `%name.index` identifier replaced by
/// `%<order of first appearance>` — the canonicalization every differential
/// here uses: names are the only thing the two artifacts may differ in, and
/// they are cosmetic to the ABI.
fn canonical(ir: &IrSource) -> String {
    // BOTH SIDES are folded first (notes/ir-passes.org §2 ii): our builder
    // inlines a `Copy` of an immediate at `finish`, and compactc names some of
    // the constants it inlines elsewhere, so the comparison is instruction for
    // instruction MODULO the naming of constants — a rename with no rows, no
    // public input and no semantics. Everything else still compares exactly.
    let ir = &minocrab_ir::v3::passes::folded(ir);
    canonicalize(&to_zkir_string(ir).expect("serializes"))
}

fn canonicalize(text: &str) -> String {
    let mut renames: Vec<(String, String)> = Vec::new();
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
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

/// Every circuit of the fixture: compactc's artifact name and our builder.
fn cases() -> Vec<(&'static str, fn() -> Compiled3)> {
    vec![
        // Set
        ("setInsert", adts::Adts::set_insert as fn() -> Compiled3),
        ("setMember", adts::Adts::set_member),
        ("setRemove", adts::Adts::set_remove),
        ("setSize", adts::Adts::set_size),
        ("setIsEmpty", adts::Adts::set_is_empty),
        ("setReset", adts::Adts::set_reset),
        // List
        ("listPushFront", adts::Adts::list_push_front),
        ("listPopFront", adts::Adts::list_pop_front),
        ("listHead", adts::Adts::list_head),
        ("listLength", adts::Adts::list_length),
        ("listIsEmpty", adts::Adts::list_is_empty),
        ("listReset", adts::Adts::list_reset),
        // Map — the two operations LedgerMap was missing
        ("mapInsertDefault", adts::Adts::map_insert_default),
        ("mapReset", adts::Adts::map_reset),
        // MerkleTree
        ("mtInsert", adts::Adts::mt_insert),
        ("mtInsertIndex", adts::Adts::mt_insert_index),
        ("mtInsertHash", adts::Adts::mt_insert_hash),
        ("mtInsertHashIndex", adts::Adts::mt_insert_hash_index),
        ("mtInsertIndexDefault", adts::Adts::mt_insert_index_default),
        ("mtCheckRoot", adts::Adts::mt_check_root),
        ("mtIsFull", adts::Adts::mt_is_full),
        ("mtReset", adts::Adts::mt_reset),
        // HistoricMerkleTree
        ("hmtInsert", adts::Adts::hmt_insert),
        ("hmtInsertIndex", adts::Adts::hmt_insert_index),
        ("hmtInsertHash", adts::Adts::hmt_insert_hash),
        ("hmtInsertHashIndex", adts::Adts::hmt_insert_hash_index),
        ("hmtInsertIndexDefault", adts::Adts::hmt_insert_index_default),
        ("hmtCheckRoot", adts::Adts::hmt_check_root),
        ("hmtIsFull", adts::Adts::hmt_is_full),
        ("hmtResetHistory", adts::Adts::hmt_reset_history),
        ("hmtReset", adts::Adts::hmt_reset),
    ]
}

/// CLAIM 1, and the headline: for every ledger-ADT operation Compact has, our
/// circuit IS compactc's — op for op, immediate for immediate.
///
/// What that pins, and what nothing weaker would: the `Array` positions each
/// ADT descends through, the `3 | len << 4` / `4 | h << 4` state-value tags in
/// the pushed constants, the `Op::Type` numbering `List.isEmpty` compares
/// against, the `branch`/`jmp` skip counts, the `concat` operand
/// `rt-max-sizeof` produces, and the `"mdn:lh"` leaf-hash preimage.
#[test]
fn identical_instruction_streams() {
    for (name, build) in cases() {
        let ours = build().ir;
        assert_eq!(
            canonical(&ours),
            canonical(&theirs(name)),
            "{name}: our lowering differs from compactc's"
        );
    }
}

/// The fixture covers every operation, and the list above is not allowed to
/// quietly shrink: one case per `.zkir` compactc produced.
#[test]
fn every_fixture_circuit_is_covered() {
    let dir = format!("{}/tests/fixtures/adts/out/zkir", env!("CARGO_MANIFEST_DIR"));
    let mut compiled: Vec<String> = std::fs::read_dir(&dir)
        .expect("the fixture is compiled")
        .map(|entry| {
            entry
                .expect("a readable entry")
                .file_name()
                .to_string_lossy()
                .trim_end_matches(".zkir")
                .to_string()
        })
        .collect();
    compiled.sort();
    let mut covered: Vec<String> = cases().iter().map(|(n, _)| n.to_string()).collect();
    covered.sort();
    assert_eq!(compiled, covered);
}

/// CLAIM 2 — corpus provenance for the one operation the corpus has in a v3
/// artifact.
///
/// `test-caller-contract`'s `submitSignatureRequest` ends with
/// `requestLog.pushFront(requestId as Bytes<32>)` on field 0; our
/// `listPushFront` does the same on field 2. So the thirteen Impact
/// instructions must agree once the field key is accounted for — which says
/// the fixture route is measuring the shape production code actually uses, not
/// a narrower one.
#[test]
fn push_front_matches_the_corpus() {
    let ours = impact_ops(&adts::Adts::list_push_front().ir);
    let theirs = impact_ops(&corpus("submitSignatureRequest"));

    // The corpus circuit does much else; find its pushFront by the idxp of
    // field 0 that starts a thirteen-instruction block ending in `insc 2`.
    let block = theirs
        .windows(ours.len())
        .find(|w| w[0] == vec!["0x70", "0x01", "0x01", "0x00"])
        .expect("submitSignatureRequest contains an idxp of field 0");

    assert_eq!(block.len(), 13, "pushFront is thirteen instructions");
    for (i, (mine, yours)) in ours.iter().zip(block).enumerate() {
        if i == 0 {
            // The idxp of the list's own field — 2 here, 0 there.
            assert_eq!(mine[..3], yours[..3]);
            assert_eq!(mine[3], "0x02");
            assert_eq!(yours[3], "0x00");
            continue;
        }
        // The pushed element differs only in which wire carries the value.
        let strip = |op: &Vec<String>| -> Vec<String> {
            op.iter()
                .map(|e| if e.starts_with('%') { "%".into() } else { e.clone() })
                .collect()
        };
        assert_eq!(strip(mine), strip(yours), "pushFront instruction {i}");
    }
}

/// Every `impact` instruction's operand list, in order.
fn impact_ops(ir: &IrSource) -> Vec<Vec<String>> {
    let value: serde_json::Value =
        serde_json::from_str(&to_zkir_string(ir).expect("serializes")).expect("valid JSON");
    value["instructions"]
        .as_array()
        .expect("an array")
        .iter()
        .filter(|i| i["op"] == "impact")
        .map(|i| {
            i["inputs"]
                .as_array()
                .expect("an array")
                .iter()
                .map(|e| e.as_str().expect("a string").to_string())
                .collect()
        })
        .collect()
}

/// CLAIM 3 — compactc's own ABI agrees with the leaves, including the new one.
///
/// `MerkleTreeDigest` is published as a `Struct` of one `Field`, and
/// `List.head`'s result as a `Struct` named `Maybe` of a `Boolean` and the
/// element — so this test is where "our `MerkleTreeDigest` is `Prim::Field`,
/// one `field` atom" and "our `Maybe<T>` result layout is compactc's" stop
/// being assertions in a doc comment. It is the M15 test that would have
/// caught the curve-point bug, pointed at M16's leaf.
#[test]
fn compactc_s_abi_agrees_with_the_leaves() {
    use minocrab::v3::CircuitAbi;
    use minocrab::Public;
    use minocrab_abi::info::ContractInfo;
    use minocrab_std::v3::{Bool, Maybe, MerkleTreeDigest, Uint, B32};

    let text = std::fs::read_to_string(format!(
        "{}/tests/fixtures/adts/out/compiler/contract-info.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("the pinned compactc's contract-info is committed");
    let info = ContractInfo::parse(&text).expect("contract-info parses");

    macro_rules! abi {
        ($($ty:ty),*) => {{
            let mut atoms = Vec::new();
            let mut prims = Vec::new();
            $(
                atoms.extend(<$ty as CircuitAbi>::atoms());
                prims.extend(<$ty as CircuitAbi>::prims());
            )*
            (atoms, prims)
        }};
    }

    // One entry per circuit that HAS arguments, in declaration order.
    let expected: Vec<(&str, (Vec<_>, Vec<_>))> = vec![
        ("setInsert", abi!(B32<Public>)),
        ("setMember", abi!(B32<Public>)),
        ("setRemove", abi!(B32<Public>)),
        ("listPushFront", abi!(B32<Public>)),
        ("mapInsertDefault", abi!(B32<Public>)),
        ("mtInsert", abi!(B32<Public>)),
        ("mtInsertIndex", abi!(B32<Public>, Uint<64, Public>)),
        ("mtInsertHash", abi!(B32<Public>)),
        ("mtInsertHashIndex", abi!(B32<Public>, Uint<64, Public>)),
        ("mtInsertIndexDefault", abi!(Uint<64, Public>)),
        // The new leaf: one `field` atom, `Prim::Field`, no constraint.
        ("mtCheckRoot", abi!(MerkleTreeDigest<Public>)),
        ("hmtInsert", abi!(B32<Public>)),
        ("hmtInsertIndex", abi!(B32<Public>, Uint<64, Public>)),
        ("hmtInsertHash", abi!(B32<Public>)),
        ("hmtInsertHashIndex", abi!(B32<Public>, Uint<64, Public>)),
        ("hmtInsertIndexDefault", abi!(Uint<64, Public>)),
        ("hmtCheckRoot", abi!(MerkleTreeDigest<Public>)),
    ];

    for (name, (atoms, prims)) in expected {
        let circuit = info.circuit(name).unwrap_or_else(|| panic!("{name} is exported"));
        let flat = minocrab_abi::info::flatten_all(circuit.arguments.iter().map(|a| &a.ty))
            .unwrap_or_else(|e| panic!("{name}: compactc's ABI does not flatten: {e}"));
        assert_eq!(flat.atoms, atoms, "{name}: FAB atoms differ");
        assert_eq!(flat.prims, prims, "{name}: primitive types differ");
    }

    // `List.head`'s RESULT: compactc's `Maybe` struct against ours.
    let head = info.circuit("listHead").expect("listHead is exported");
    let flat = minocrab_abi::info::flatten_all([&head.result_type])
        .expect("compactc's Maybe<Bytes<32>> flattens");
    let (atoms, prims) = abi!(Maybe<B32<Public>, Public>);
    assert_eq!(flat.atoms, atoms, "listHead: Maybe's FAB atoms differ");
    assert_eq!(flat.prims, prims, "listHead: Maybe's primitive types differ");
    // …and the tag really is a Boolean, not a byte.
    assert_eq!(flat.prims[0], <Bool<Public> as CircuitAbi>::prims()[0]);
}

/// CLAIM 4 — the tree READS mean what the VM says they mean.
///
/// The three read circuits between them carry every opcode M16 adds that is
/// not exercised by a write: `lt`+`neg` (`isFull`), `root`+`eq`
/// (`MerkleTree.checkRoot`) and `member` on the history map
/// (`HistoricMerkleTree.checkRoot`). A preimage built from the REFERENCE
/// Impact program — the ops written out by hand here, not read back off either
/// artifact — has to satisfy both artifacts and upstream's `check()`. That is
/// the statement stream equality cannot make on its own: it says the transcript
/// our circuit expects is the one the VM produces, element for element and in
/// the right slots.
#[test]
fn the_tree_reads_are_accepted_by_upstream() {
    // `mt` is field 4 and `hmt` field 5 (the fixture's declaration order); a
    // tree's own `Array` positions are 0 = tree, 1 = next index, 2 = history.
    let root = Fr::from(0x5eed_u64);

    let is_full = |field: u8, answer: u8| {
        (
            vec![
                Op::Dup { n: 0 },
                idx(field),
                idx(1),
                Op::Push {
                    storage: false,
                    value: cell(bytesn_value(8, &(1u64 << adts::DEPTH).to_le_bytes())),
                },
                Op::Lt,
                Op::Neg,
                Op::Popeq {
                    cached: true,
                    result: bytesn_value(1, &[answer]),
                },
            ],
            vec![],
            answer,
        )
    };

    let cases: Vec<(&str, fn() -> Compiled3, (Vec<VmOp>, Vec<Fr>, u8))> = vec![
        ("mtIsFull", adts::Adts::mt_is_full as fn() -> Compiled3, is_full(4, 0)),
        ("hmtIsFull", adts::Adts::hmt_is_full, is_full(5, 1)),
        (
            "mtCheckRoot",
            adts::Adts::mt_check_root,
            (
                vec![
                    Op::Dup { n: 0 },
                    idx(4),
                    idx(0),
                    Op::Root,
                    Op::Push {
                        storage: false,
                        value: cell(field_value(root)),
                    },
                    Op::Eq,
                    Op::Popeq {
                        cached: true,
                        result: bytesn_value(1, &[1]),
                    },
                ],
                vec![root],
                1,
            ),
        ),
        (
            "hmtCheckRoot",
            adts::Adts::hmt_check_root,
            (
                vec![
                    Op::Dup { n: 0 },
                    idx(5),
                    idx(2),
                    Op::Push {
                        storage: false,
                        value: cell(field_value(root)),
                    },
                    Op::Member,
                    Op::Popeq {
                        cached: true,
                        result: bytesn_value(1, &[1]),
                    },
                ],
                vec![root],
                1,
            ),
        ),
    ];

    for (name, build, (ops, inputs, answer)) in cases {
        let answer = Fr::from(u64::from(answer));
        let pre = preimage_out(inputs, transcript(&ops), &[answer], &[answer]);
        for (whose, ir) in [("ours", build().ir), ("compactc's", theirs(name))] {
            ir.check(&pre).unwrap_or_else(|e| {
                panic!("{name}: {whose} artifact rejected the reference transcript: {e:?}")
            });
        }
    }
}

/// `idx [k]` by one constant `bytes<1>` key — a top-level field or an `Array`
/// position, which are the same instruction.
fn idx(k: u8) -> VmOp {
    Op::Idx {
        cached: false,
        push_path: false,
        path: vec![Key::Value(bytesn_value(1, &[k]))].into(),
    }
}

fn bytesn_value(n: u32, bytes: &[u8]) -> AlignedValue {
    AlignedValue::new(
        Value(vec![ValueAtom(bytes.to_vec()).normalize()]),
        Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes {
            length: n,
        })]),
    )
    .expect("the bytes fit the atom")
}

/// A `MerkleTreeDigest`: one `field` atom.
fn field_value(f: Fr) -> AlignedValue {
    let mut bytes = Vec::new();
    f.field_repr(&mut bytes);
    AlignedValue::new(
        Value(vec![ValueAtom(field_le_bytes(f)).normalize()]),
        Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Field)]),
    )
    .expect("a field atom fits a field element")
}

fn field_le_bytes(f: Fr) -> Vec<u8> {
    let mut out = f.as_le_bytes().to_vec();
    out.truncate(32);
    out
}

fn cell(av: AlignedValue) -> StateValue {
    StateValue::Cell(Sp::new(av))
}

fn transcript(ops: &[VmOp]) -> Vec<Fr> {
    let mut out = Vec::new();
    for op in ops {
        op.field_repr(&mut out);
    }
    out
}

/// The preimage of a circuit that READS: the op stream is
/// `public_transcript_inputs`, and what the ledger hands back — every `popeq`
/// result, value-only, in read order — is `public_transcript_outputs`, which
/// is what a `public_input` gate consumes (`zkir-v3/src/ir_vm.rs:347-365`).
///
/// The communications commitment covers the circuit's INPUTS and its declared
/// OUTPUTS (`onchain-runtime-wasm/src/primitives.rs`), which for these
/// circuits is the Boolean each returns.
fn preimage_out(
    inputs: Vec<Fr>,
    transcript: Vec<Fr>,
    reads: &[Fr],
    outputs: &[Fr],
) -> ProofPreimage {
    let rand = Fr::from(0xb0_u64);
    let mut comm_vals = inputs.clone();
    comm_vals.extend_from_slice(outputs);
    let comm = transient_commit(&comm_vals[..], rand);
    ProofPreimage {
        inputs,
        private_transcript: vec![],
        public_transcript_inputs: transcript,
        public_transcript_outputs: reads.to_vec(),
        binding_input: 0.into(),
        communications_commitment: Some((comm, rand)),
        key_location: KeyLocation(Cow::Borrowed("minocrab-contracts-test")),
    }
}
