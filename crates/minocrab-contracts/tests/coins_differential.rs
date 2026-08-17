//! `coins.compact` — the M22 stage A differential: the three COIN ARMS of the
//! collection ADTs, against compactc's own artifacts
//! (notes/coin-arms-nested-adts.org).
//!
//! WHY THE FIXTURE IS OURS, for the fifth milestone running and with a
//! sharper reason than usual. The three arms have REAL third-party demand —
//! OpenZeppelin's `ShieldedTreasury` keeps its coins in a
//! `Map<Bytes<32>, QualifiedShieldedCoinInfo>` and calls `Map.insertCoin`
//! three times — and compactc's own test suite compiles all three
//! (`adt/exports/set_qualified_coin_info`, `list_qualified_coin_info`). But
//! every one of those artifacts is ZKIR **v2**, and across the three
//! `--feature-zkir-v3` corpus sources the three arms are used ZERO times. So
//! they are corroboration for the SHAPE and not a differential target
//! (notes/ledger-adts.org finding (e)), and the target is our source,
//! compiled with the PINNED compactc — the invocation is in the fixture's
//! header.
//!
//! WHAT THE HEADLINE PINS, and what nothing weaker would: the three `dup`
//! reaches (4, 5 and 7 — three different constants, none of them the `3` the
//! crate already had), the `idxc [(align 1 1), stack]` two-element path that
//! resolves the Merkle-tree index, the `concatc 91` literal, the fact that
//! `Set`'s dance runs BEFORE its `pushs null` because the qualified coin is
//! the KEY, and `List.pushFrontCoin`'s eight extra instructions around a
//! BLANK `[null, null, null]` node.

use minocrab::v3::Compiled3;
use minocrab_contracts::coins::Coins;
use minocrab_zkir::v3::{to_zkir_string, IrSource};

/// compactc's artifact for one fixture circuit.
fn theirs(name: &str) -> IrSource {
    let path = format!(
        "{}/tests/fixtures/coins/out/zkir/{name}.zkir",
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
        ("setInsertCoin", Coins::set_insert_coin as fn() -> Compiled3),
        ("mapInsertCoin", Coins::map_insert_coin),
        ("listPushFrontCoin", Coins::list_push_front_coin),
    ]
}

/// THE HEADLINE: for all three coin arms, our serialized ZKIR IS compactc's
/// up to identifier renaming.
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
/// differently (`setInsertCoin` against `set_insert_coin`), and a count would
/// pass while two entries silently swapped.
#[test]
fn every_exported_circuit_is_in_the_differential() {
    let ported: std::collections::HashSet<usize> =
        cases().iter().map(|(_, build)| *build as usize).collect();
    let missing: Vec<&str> = Coins::CIRCUITS
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
        "{}/tests/fixtures/coins/out/zkir",
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

/// CLAIM 2 — compactc's own ABI agrees with the argument types.
///
/// The fixture's `contract-info.json`, flattened by `minocrab_abi::info`,
/// against the `CircuitAbi` of the Rust types. This is where "our
/// `ShieldedCoinInfo` is `[Bytes<32>, Bytes<32>, Uint<128>]` and our
/// `Either<ZswapCoinPublicKey, ContractAddress>` is a tag plus two
/// `Bytes<32>`" stops being an assertion in a doc comment — and the three
/// atoms are exactly what the qualify dance's `push coin` embeds.
#[test]
fn compactc_s_abi_agrees_with_the_arguments() {
    use minocrab::v3::CircuitAbi;
    use minocrab::Public;
    use minocrab_abi::info::ContractInfo;
    use minocrab_std::v3::{
        ContractAddress, Either, ShieldedCoinInfo3, ZswapCoinPublicKey, B32,
    };

    let text = std::fs::read_to_string(format!(
        "{}/tests/fixtures/coins/out/compiler/contract-info.json",
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

    type Recipient = Either<ZswapCoinPublicKey<Public>, ContractAddress<Public>, Public>;
    let expected: Vec<(&str, (Vec<_>, Vec<_>))> = vec![
        ("setInsertCoin", abi!(ShieldedCoinInfo3<Public>, Recipient)),
        ("mapInsertCoin", abi!(B32<Public>, ShieldedCoinInfo3<Public>, Recipient)),
        ("listPushFrontCoin", abi!(ShieldedCoinInfo3<Public>, Recipient)),
    ];

    for (name, (atoms, prims)) in expected {
        let circuit = info.circuit(name).unwrap_or_else(|| panic!("{name} is exported"));
        let flat = minocrab_abi::info::flatten_all(circuit.arguments.iter().map(|a| &a.ty))
            .unwrap_or_else(|e| panic!("{name}: compactc's ABI does not flatten: {e}"));
        assert_eq!(flat.atoms, atoms, "{name}: FAB atoms differ");
        assert_eq!(flat.prims, prims, "{name}: primitive types differ");
    }
}
