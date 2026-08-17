//! `nested.compact` — the M22 stage B1 differential: NESTED LEDGER ADTs
//! against compactc's own artifacts (notes/coin-arms-nested-adts.org §2).
//!
//! WHY THE FIXTURE IS OURS, for the sixth milestone running. Nested
//! declarations have real third-party demand — OpenZeppelin's
//! `ShieldedMultiSig` declares `Map<Uint<64>, Map<Either<..>, Boolean>>` and
//! writes through it — and compactc's own test suite compiles two more
//! (`map_boolean_map_field_counter`, `map_field_list_field`). Every one of
//! those artifacts is ZKIR **v2**, and across the three
//! `--feature-zkir-v3` corpus sources nested declarations are used ZERO
//! times. So they are corroboration for the SHAPE and not a differential
//! target (notes/ledger-adts.org finding (e)), and the target is our source,
//! compiled with the PINNED compactc — the invocation is in the fixture's
//! header.
//!
//! WHAT THE HEADLINE PINS, and what nothing weaker would. A nested access is
//! ONE `idx` with a longer path and ONE `insc` with a bigger `n`, so the only
//! thing that can be wrong is the ARITHMETIC, and there are five distinct
//! answers:
//!
//! | closing `insc` | who |
//! |---|---|
//! | `len(f)` | `insert`, `insertDefault`, `remove`, `increment`, `popFront`, `insertIndex` |
//! | `len(f) + 1` | `List.pushFront`, `MerkleTree.insert`, `HistoricMerkleTree.insert` |
//! | `len(f) + 2` | `HistoricMerkleTree.resetHistory` — alone |
//! | `len(f) − 1`, SUPPRESSED at zero | the nine whole-field-replace ops |
//! | a literal 1 or 2 | the `insc` in the MIDDLE of a tree insert, at every depth |
//!
//! plus the leading `idxp`, which for those nine takes `f` minus its last
//! element and disappears entirely at depth 1. Every one of those five is a
//! circuit below, at depth 2, and `deepInsert` / `deepLookup` add depth 3 so
//! that "tracks `len(f)`" is pinned as a relation rather than a constant.
//!
//! AND ONE FINDING THE DIFFERENTIAL EXISTS TO CATCH: `outerInsertDefault`.
//! An `insertDefault` whose value type is an ADT pushes the ADT's own
//! `(initial-value …)` — the empty map — and not a cell of zeros, because
//! `assemble-operand-acc`'s `VMstate-value-ADT` case discards the value
//! whenever the type is an ADT. The crate's pre-existing `map_insert_default`
//! would have pushed zeros.

use minocrab::v3::Compiled3;
use minocrab_contracts::nested::Nested;
use minocrab_zkir::v3::{to_zkir_string, IrSource};

/// compactc's artifact for one fixture circuit.
fn theirs(name: &str) -> IrSource {
    let path = format!(
        "{}/tests/fixtures/nested/out/zkir/{name}.zkir",
        env!("CARGO_MANIFEST_DIR")
    );
    minocrab_zkir::v3::read_zkir(&path).expect("the pinned compactc's artifact parses")
}

/// Serialized ZKIR with every `%name.index` identifier replaced by
/// `%<order of first appearance>` — the same canonicalization every
/// differential here uses.
fn canonical(ir: &IrSource) -> String {
    // BOTH SIDES are folded first (notes/ir-passes.org §2 ii): our builder
    // inlines a `Copy` of an immediate at `finish`, and compactc names some of
    // the constants it inlines elsewhere, so the comparison is instruction for
    // instruction MODULO the naming of constants — a rename with no rows, no
    // public input and no semantics. Everything else still compares exactly.
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

/// Every circuit of the fixture: compactc's artifact name and our builder.
fn cases() -> Vec<(&'static str, fn() -> Compiled3)> {
    vec![
        ("mapInsert", Nested::map_insert as fn() -> Compiled3),
        ("mapInsertDefault", Nested::map_insert_default),
        ("mapLookup", Nested::map_lookup),
        ("mapMember", Nested::map_member),
        ("mapRemove", Nested::map_remove),
        ("mapSize", Nested::map_size),
        ("mapIsEmpty", Nested::map_is_empty),
        ("mapReset", Nested::map_reset),
        ("outerInsertDefault", Nested::outer_insert_default),
        ("listPushFront", Nested::list_push_front),
        ("listPopFront", Nested::list_pop_front),
        ("listLength", Nested::list_length),
        ("listHead", Nested::list_head),
        ("listIsEmpty", Nested::list_is_empty),
        ("listReset", Nested::list_reset),
        ("setInsert", Nested::set_insert),
        ("setRemove", Nested::set_remove),
        ("setMember", Nested::set_member),
        ("counterIncrement", Nested::counter_increment),
        ("counterRead", Nested::counter_read),
        ("counterReset", Nested::counter_reset),
        ("mtInsert", Nested::mt_insert),
        ("mtCheckRoot", Nested::mt_check_root),
        ("hmtInsert", Nested::hmt_insert),
        ("hmtResetHistory", Nested::hmt_reset_history),
        ("hmtReset", Nested::hmt_reset),
        ("deepInsert", Nested::deep_insert),
        ("deepLookup", Nested::deep_lookup),
    ]
}

/// THE HEADLINE: for every nested operation, our serialized ZKIR IS
/// compactc's up to identifier renaming.
#[test]
fn identical_instruction_streams() {
    for (name, build) in cases() {
        assert_eq!(
            canonical(&build().ir),
            canonical(&theirs(name)),
            "{name}: our lowering differs from compactc's"
        );
    }
}

/// EVERY CIRCUIT THE CONTRACT EXPORTS IS IN THE DIFFERENTIAL, compared by
/// FUNCTION POINTER rather than by count — the two lists name circuits
/// differently (`mapInsert` against `map_insert`), and a count would pass
/// while two entries silently swapped.
#[test]
fn every_exported_circuit_is_in_the_differential() {
    let ported: std::collections::HashSet<usize> =
        cases().iter().map(|(_, build)| *build as usize).collect();
    let missing: Vec<&str> = Nested::CIRCUITS
        .iter()
        .filter(|(_, build)| !ported.contains(&(*build as usize)))
        .map(|(name, _)| *name)
        .collect();
    assert!(
        missing.is_empty(),
        "these circuits are exported by the contract and compared against \
         nothing: {missing:?}"
    );
}

/// …and the fixture is not allowed to grow a circuit nothing compares: one
/// case per `.zkir` compactc produced.
#[test]
fn every_fixture_circuit_is_covered() {
    let dir = format!(
        "{}/tests/fixtures/nested/out/zkir",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut compiled: Vec<String> = std::fs::read_dir(&dir)
        .expect("the fixture is compiled")
        .map(|e| {
            e.expect("a readable entry")
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

/// CLAIM 2 — the DEPTH is visible in the bytes, and it is the only thing that
/// moved.
///
/// The headline compares whole streams and would pass if every depth were
/// uniformly wrong in the same direction as the fixture. This reads the
/// opcode nibbles out of compactc's own artifacts and asserts the relation
/// the note derived from the scheme sources, so a future change that made
/// depth a no-op could not hide behind a matching fixture.
#[test]
fn the_depth_is_the_opcode_nibble_and_the_ins_operand() {
    /// The leading `idx` opcode and every `ins`/`insc` opcode of a circuit,
    /// read straight out of compactc's artifact — an Impact instruction's
    /// first operand is its opcode byte.
    fn opcodes(name: &str) -> (i64, Vec<i64>) {
        let text = std::fs::read_to_string(format!(
            "{}/tests/fixtures/nested/out/zkir/{name}.zkir",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("the fixture is compiled");
        let json: serde_json::Value = serde_json::from_str(&text).expect("the artifact is JSON");
        let mut lead = None;
        let mut ins = Vec::new();
        for instr in json["instructions"].as_array().expect("instructions") {
            if instr["op"] != "impact" {
                continue;
            }
            let first = instr["inputs"][0].as_str().expect("an opcode operand");
            let op = i64::from_str_radix(first.trim_start_matches("0x"), 16).expect("hex");
            if (0x50..0x90).contains(&op) && lead.is_none() {
                lead = Some(op);
            }
            if (0x90..0xb0).contains(&op) {
                ins.push(op);
            }
        }
        (lead.expect("every circuit here starts with an idx"), ins)
    }

    // Depth 2: the leading idx is `hi | 1`, and the closing insc `0xa2`.
    let (lead, ins) = opcodes("mapInsert");
    assert_eq!(lead, 0x71, "idxp over a two-element path");
    assert_eq!(*ins.last().unwrap(), 0xa2, "insc len(f)");

    // Depth 3: both nibbles step by exactly one.
    let (lead, ins) = opcodes("deepInsert");
    assert_eq!(lead, 0x72);
    assert_eq!(*ins.last().unwrap(), 0xa3);

    // A read at depth 2 and at depth 3 — `idx`, not `idxp`.
    assert_eq!(opcodes("mapLookup").0, 0x51);
    assert_eq!(opcodes("deepLookup").0, 0x52);

    // `len(f) + 1` and `len(f) + 2`, the two closings that are not `len(f)`.
    assert_eq!(*opcodes("listPushFront").1.last().unwrap(), 0xa3);
    assert_eq!(*opcodes("mtInsert").1.last().unwrap(), 0xa3);
    assert_eq!(*opcodes("hmtInsert").1.last().unwrap(), 0xa3);
    assert_eq!(*opcodes("hmtResetHistory").1.last().unwrap(), 0xa4);

    // SUPPRESSION, come alive: a nested `resetToDefault` leads with `idxp`
    // over the path MINUS its last element — one element, so `0x70` — and
    // closes with the `insc 1` that a top-level reset suppresses away.
    let (lead, ins) = opcodes("mapReset");
    assert_eq!(lead, 0x70, "the CONTAINER's path, not the field's");
    assert_eq!(ins, vec![0x91, 0xa1]);
    assert_eq!(opcodes("listReset").0, 0x70);
    assert_eq!(opcodes("counterReset").0, 0x70);
    assert_eq!(opcodes("hmtReset").1, vec![0xa2, 0x91, 0xa1]);
}

/// CLAIM 3 — compactc's own ABI agrees with the argument types.
///
/// The fixture's `contract-info.json`, flattened by `minocrab_abi::info`,
/// against the `CircuitAbi` of the Rust types. Here it also pins that a
/// nested declaration does not change a circuit's SIGNATURE at all — the
/// keys are ordinary arguments and the nesting is invisible above the
/// transcript.
#[test]
fn compactc_s_abi_agrees_with_the_arguments() {
    use minocrab::v3::CircuitAbi;
    use minocrab::Public;
    use minocrab_abi::info::ContractInfo;
    use minocrab_std::v3::{MerkleTreeDigest, Uint, B32};

    let text = std::fs::read_to_string(format!(
        "{}/tests/fixtures/nested/out/compiler/contract-info.json",
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

    type Key = B32<Public>;
    let expected: Vec<(&str, (Vec<_>, Vec<_>))> = vec![
        ("mapInsert", abi!(Key, Key, Uint<64, Public>)),
        ("mapLookup", abi!(Key, Key)),
        ("mapSize", abi!(Key)),
        ("listPushFront", abi!(Key, Key)),
        ("mtCheckRoot", abi!(Key, MerkleTreeDigest<Public>)),
        ("deepInsert", abi!(Key, Key, Key, Uint<64, Public>)),
    ];

    for (name, (atoms, prims)) in expected {
        let circuit = info.circuit(name).unwrap_or_else(|| panic!("{name} is exported"));
        let flat = minocrab_abi::info::flatten_all(circuit.arguments.iter().map(|a| &a.ty))
            .unwrap_or_else(|e| panic!("{name}: compactc's ABI does not flatten: {e}"));
        assert_eq!(flat.atoms, atoms, "{name}: FAB atoms differ");
        assert_eq!(flat.prims, prims, "{name}: primitive types differ");
    }
}
