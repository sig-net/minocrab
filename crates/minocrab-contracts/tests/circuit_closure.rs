//! Closure of the circuit list: every `#[circuit]` in this crate's source
//! appears in `support::circuits()`.
//!
//! `circuits()` is the only statement of which circuits exist — it feeds both
//! snapshots, the ZKIR dump, the adversarial suite and the taint lint. Until
//! now nothing checked it was complete: the snapshots guard the opposite
//! direction (a listed circuit that moved), so a circuit added and not listed
//! was covered by nothing. Verification.md §5 admitted this; the external
//! review's §7.4 asked for the check. The `#[contract]` migration derives the
//! set for its adopters; this test closes the gap for everything else, and it
//! found `xcall::Xcall::call_emit` on its first run.
//!
//! Textual on purpose, like the escape-hatch greps: the source is the
//! authority on what carries the attribute, and a Rust-level registry would
//! be one more list to keep complete. Family builders (`hashing::keccak(64)`,
//! `events::emit_n(2)`) are not attributes and are outside this test's
//! direction; the attribute → listed direction is the one that was open.

use std::collections::BTreeSet;
use std::path::Path;

mod support;

/// `(module path, fn name)` for every `#[circuit …]` attribute under `src/`,
/// where the module path is the file's path relative to `src/` (`a/b.rs` →
/// `a::b`, `a/mod.rs` → `a`) — the naming `circuits()` keys by.
fn circuit_attributes(src: &Path) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let mut stack = vec![src.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("readable src dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let module = path
                .strip_prefix(src)
                .expect("under src")
                .with_extension("")
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .filter(|c| c != "mod")
                .collect::<Vec<_>>()
                .join("::");
            let text = std::fs::read_to_string(&path).expect("readable source");
            let lines: Vec<&str> = text.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let t = line.trim_start();
                if !t.starts_with("#[circuit") {
                    continue;
                }
                // The attribute's item: the next line that is neither another
                // attribute nor a doc comment, and declares a fn.
                let decl = lines[i + 1..]
                    .iter()
                    .find(|l| {
                        let l = l.trim_start();
                        !l.starts_with("#[") && !l.starts_with("///") && !l.is_empty()
                    })
                    .unwrap_or_else(|| panic!("{}:{}: `#[circuit]` with no item", path.display(), i + 1));
                let name = decl
                    .split_whitespace()
                    .skip_while(|w| *w != "fn")
                    .nth(1)
                    .unwrap_or_else(|| panic!("{}:{}: `#[circuit]` on a non-fn", path.display(), i + 1))
                    .split(|ch: char| !(ch.is_alphanumeric() || ch == '_'))
                    .next()
                    .expect("an identifier");
                found.push((module.clone(), name.to_string()));
            }
        }
    }
    found
}

#[test]
fn every_circuit_attribute_is_listed() {
    let listed: BTreeSet<String> = support::circuits()
        .iter()
        .map(|(name, _)| name.to_string())
        .collect();
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let attributes = circuit_attributes(&src);
    assert!(
        attributes.len() > 100,
        "only {} `#[circuit]` attributes found under {} — the walk is broken",
        attributes.len(),
        src.display()
    );
    let missing: Vec<String> = attributes
        .iter()
        .map(|(module, name)| format!("{module}::{name}"))
        .filter(|full| !listed.contains(full))
        .collect();
    assert!(
        missing.is_empty(),
        "{} circuit(s) carry `#[circuit]` but are not in `support::circuits()`, so no \
         snapshot, dump, adversarial suite or lint sees them:\n  {}\n\
         fix: add each to `circuits()` in tests/support/mod.rs (or move its contract \
         to `#[contract]`, which derives the list), then regenerate the snapshots and \
         the taint baseline for the new entries.",
        missing.len(),
        missing.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// the compactc lowering on every port. A circuit with a Compact
// twin, and every circuit of the deployed signer, is built under
// `minocrab_compat::profile`. For a `#[contract]` block that is one attribute,
// `#[contract(lowering = minocrab_compat::profile)]`, which the macro applies
// to each of its circuits; the few circuits built by hand outside a block
// call it themselves. Forgetting either is invisible in the ZKIR while the
// profile equals the defaults, so it is checked here.

use minocrab::Circuit;
use minocrab_contracts::{
    adts, attest, bounded, bounded_ledger, coins, erc20_vault, hashing, kernel_tokens, manager,
    mint_tokens, nested, opaque, serde_builtin, signet_contract, test_caller, xcall,
    xcall_with_payment, xcontract_events, xcontract_events_borsh,
};

/// The modules whose contracts have a Compact twin, from where the tests
/// already say so: every `tests/<module>_differential.rs` whose stem is a
/// module under `src/` compares that module against compactc's output.
/// `lean` and `wide` are differential suites with no module of their own. The
/// deployed signer (`signet_contract`) is added by name: its corpus check is
/// `signet_construction.rs`, not a `_differential` file. A `<module>_borsh`
/// twin of a port emits the port's bytes through the Borsh API and is held to
/// them by the port's own differential file (`events_differential.rs`
/// compares `events_borsh` too), so it is a port as well: the default flip of
/// M48 C step 3 moved both until they said so.
fn ported_modules() -> BTreeSet<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut ported = BTreeSet::from(["signet_contract".to_string()]);
    for entry in std::fs::read_dir(root.join("tests")).expect("readable tests dir") {
        let name = entry.expect("dir entry").file_name().to_string_lossy().into_owned();
        let Some(module) = name.strip_suffix("_differential.rs") else {
            continue;
        };
        for module in [module.to_string(), format!("{module}_borsh")] {
            if root.join("src").join(format!("{module}.rs")).exists() {
                ported.insert(module);
            }
        }
    }
    ported
}

/// The modules with no Compact twin, the only ones whose circuits take the
/// lean defaults (owner's ruling, 2026-11-21).
const MINOCRAB_ONLY: [&str; 3] = ["disclosure", "erc20_vault_pending", "treasury"];

/// Every module that builds a listed circuit is either a port or one of
/// [`MINOCRAB_ONLY`], so no circuit takes the lean defaults by omission.
#[test]
fn every_listed_module_is_a_port_or_minocrab_only() {
    let ported = ported_modules();
    let modules: BTreeSet<String> = support::circuits()
        .iter()
        .map(|(name, _)| name.split("::").next().expect("a module").to_string())
        .collect();
    for module in &modules {
        assert!(
            ported.contains(module) != MINOCRAB_ONLY.contains(&module.as_str()),
            "`{module}` builds listed circuits but is {}. fix: a port gets \
             `#[contract(lowering = minocrab_compat::profile)]` (and a differential test); a \
             contract with no Compact twin is added to MINOCRAB_ONLY",
            if ported.contains(module) { "both a port and MinoCrab-only" } else { "neither a port nor MinoCrab-only" }
        );
    }
}

/// Every `#[contract]` block of a ported module, with what it says its
/// lowering is. This list is the one place Rust names the ported contracts;
/// [`every_ported_contract_is_listed`] checks it against the source, so a
/// new port's block cannot be left out of it.
const PORTED_CONTRACTS: [(&str, Option<fn(&mut Circuit)>); 20] = [
    ("adts", adts::Adts::LOWERING),
    ("attest", attest::Attest::LOWERING),
    ("bounded", bounded::Bounded::LOWERING),
    ("bounded_ledger", bounded_ledger::BoundedLedger::LOWERING),
    ("coins", coins::Coins::LOWERING),
    ("erc20_vault", erc20_vault::Vault::LOWERING),
    ("hashing", hashing::Hashing::LOWERING),
    ("kernel_tokens", kernel_tokens::KernelTokens::LOWERING),
    ("manager", manager::Manager::LOWERING),
    ("mint_tokens", mint_tokens::MintTokens::LOWERING),
    ("nested", nested::Nested::LOWERING),
    ("opaque", opaque::OpaqueLedger::LOWERING),
    ("serde_builtin", serde_builtin::SerdeBuiltin::LOWERING),
    ("signet_contract", signet_contract::Signer::LOWERING),
    ("signet_contract", signet_contract::Responder::LOWERING),
    ("test_caller", test_caller::TestCaller::LOWERING),
    ("xcall", xcall::Xcall::LOWERING),
    ("xcall_with_payment", xcall_with_payment::XcallWithPayment::LOWERING),
    // `events` has no `#[contract]` block, only hand-built circuits (checked
    // below).
    ("xcontract_events", xcontract_events::XcontractEvents::LOWERING),
    ("xcontract_events_borsh", xcontract_events_borsh::XcontractEventsBorsh::LOWERING),
];

fn source_of(module: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(format!("{module}.rs"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The list above is complete: each ported module has exactly as many
/// entries as it has `#[contract` attributes, and no entry names a module
/// that is not a port.
#[test]
fn every_ported_contract_is_listed() {
    let ported = ported_modules();
    assert!(ported.len() >= 19, "only {} ported modules found: the walk is broken", ported.len());
    for module in &ported {
        let blocks = source_of(module)
            .lines()
            .filter(|l| l.trim_start().starts_with("#[contract"))
            .count();
        let listed = PORTED_CONTRACTS.iter().filter(|(m, _)| m == module).count();
        assert_eq!(
            blocks, listed,
            "src/{module}.rs has a Compact twin and {blocks} `#[contract]` block(s), but \
             PORTED_CONTRACTS lists {listed}. fix: add each block as \
             (\"{module}\", Type::LOWERING), and give the block \
             `#[contract(lowering = minocrab_compat::profile)]`"
        );
    }
    for (module, _) in PORTED_CONTRACTS {
        assert!(ported.contains(module), "PORTED_CONTRACTS lists `{module}`, which has no Compact twin");
    }
}

/// Every ported `#[contract]` block chose compactc's lowering: applying its
/// `LOWERING` to a fresh circuit gives exactly what `minocrab_compat::profile`
/// gives. (The macro applies it to every `#[circuit]` in the block, before the
/// body; `contract_lowering.rs` shows that ordering.)
#[test]
fn every_ported_contract_is_lowered_as_compactc_does() {
    let mut reference = Circuit::new();
    minocrab_compat::profile(&mut reference);
    for (module, lowering) in PORTED_CONTRACTS {
        let lowering = lowering.unwrap_or_else(|| {
            panic!(
                "src/{module}.rs has a Compact twin but its `#[contract]` chose no lowering, so \
                 its circuits are lowered by the defaults rather than compactc's. fix: \
                 `#[contract(lowering = minocrab_compat::profile)]`"
            )
        });
        let mut c = Circuit::new();
        lowering(&mut c);
        assert!(c.lowering_chosen(), "{module}: its lowering function sets nothing");
        assert_eq!(c.lowering(), reference.lowering(), "{module}: not compactc's lowering");
    }
}

/// A ported module's circuits built by hand (through `entry`, or
/// `Circuit::new()`) are outside every `#[contract]` block, so the attribute
/// does not reach them: each must call `minocrab_compat::profile` as the
/// first statement of what it builds. Textual, like the closure check above.
#[test]
fn every_hand_built_port_circuit_calls_the_profile_first() {
    let mut found = 0;
    for module in ported_modules() {
        let text = source_of(&module);
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim_start();
            if t.starts_with("//") {
                continue;
            }
            let builds = t.contains("Circuit::new()")
                || t.starts_with("entry(")
                || t.starts_with("entry_out(");
            if !builds {
                continue;
            }
            found += 1;
            let next = lines[i + 1..]
                .iter()
                .map(|l| l.trim_start())
                .find(|l| !l.is_empty() && !l.starts_with("//"))
                .unwrap_or("");
            assert!(
                next.starts_with("minocrab_compat::profile("),
                "src/{module}.rs:{}: a circuit of a port is built by hand here, outside its \
                 `#[contract]` block, and its next statement is `{next}`. fix: make \
                 `minocrab_compat::profile(..)` its first statement",
                i + 1
            );
        }
    }
    assert_eq!(found, 4, "expected the four hand-built port circuits (events, events_borsh, hashing, xcall)");
}
