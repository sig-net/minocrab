//! The trusted-computing-base inventory, generated not typed.
//!
//! `TRUST.md` at the repository root carries a table, one row per source
//! file of the eight eDSL crates: what warrants it (which test, proof or
//! gate would catch a wrong line), and the failure that would hide there if
//! it were wrong. The rows whose warrant is reading are the trusted
//! computing base — the part a human reviewer has to read.
//!
//! The classification is data in this file ([`ROWS`]); the table carries no
//! line counts, so editing a source file does not make it stale — only
//! adding, removing or reclassifying a file does. The table in `TRUST.md`
//! is regenerated between its markers by
//! `MINOCRAB_TRUST_BASE=1 cargo test -p minocrab-contracts --test trust_base`
//! (the same reviewable-diff rule as the snapshots). The test fails when:
//! a classified file does not exist, a source file of those crates is not
//! classified (closure, so a new file cannot slip in unwarranted), or the
//! table in `TRUST.md` is stale.
//!
//! The one error the table must not contain is a warrant claimed that is not
//! there: where unsure, a row says reading and a reviewer downgrades it,
//! never the reverse.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// A source file of the eDSL: path under `crates/`, its warrant, the
/// failure that would hide in it.
struct Row {
    path: &'static str,
    warrant: &'static str,
    hides: &'static str,
}

const READING: &str = "READING";

/// The classification. Order is the read order of `TRUST.md` §2 (bottom of
/// the stack first). Warrant names are test files, proof modules or gates
/// a reviewer can run; "READING" means nothing but a human's eyes.
const ROWS: &[Row] = &[
    // ---- L0: bindings -------------------------------------------------------------------
    Row { path: "minocrab-zkir/src/lib.rs", warrant: "corpus_roundtrip (855 v3 artifacts, count asserted); lean_roundtrip (byte-exact Lean syntax, M27 rung 1)", hides: "a `.zkir` envelope or version read wrongly — every differential reads compactc's artifacts through here" },
    Row { path: "minocrab-zkir/src/io.rs", warrant: "corpus_roundtrip; lean_roundtrip; every differential (reads compactc's artifact through this pair)", hides: "an IR re-emitted differently from what was parsed" },
    // ---- L1: the builder -----------------------------------------------------------------
    Row { path: "minocrab-ir/src/lib.rs", warrant: READING, hides: "nothing beyond re-exports" },
    Row { path: "minocrab-ir/src/builder.rs", warrant: "every instruction-level differential (the emitted stream equals compactc's); builder. The operand-type TABLES themselves: READING against midnight-zkir's src/ir_vm.rs", hides: "an instruction emitted with an operand type the VM rejects, on a path no fixture takes" },
    Row { path: "minocrab-ir/src/passes.rs", warrant: "Lean (crates/minocrab-ir/lean, the pass theorems, M25/M27); passes; the zkir dump + row snapshot (every pass is zero-movement on the shipped artifacts)", hides: "a pass that changes a circuit's statement while preserving its rows" },
    Row { path: "minocrab-ir/src/passes/kept.rs", warrant: "its unit tests (each pass's map on a fixed stream and on 100,000 random streams per pass, composition, the panics); the debug-build checks in Builder::finish_kept and Circuit::finish, run on every circuit metadata_indices builds; metadata (5,000 random Circuit programs)", hides: "an assert message or region moved onto the wrong instruction of the finished stream" },
    Row { path: "minocrab-taint/src/lib.rs", warrant: "Kani harnesses (./kani.sh, M23 R4) + unit tests for the Max arithmetic; 23 unit tests over the marking rules, the three subtraction warrants' near-miss refusals and the observability walk's refused sinks; the MARKING RULES' warrants are cited in-file per rule and are READING. The observability walk (M23 R3 Class A) reads operands through passes::operands / defined_identifiers, which the Lean dataflow gate diffs", hides: "a limb marked bounded that is not, or a guarded read discharged as unobservable whose digest in fact reaches an effect the walk's sink classification waves through — a false negative in the one lint that sees what honest inputs cannot" },
    // ---- L2: the eDSL --------------------------------------------------------------------
    Row { path: "minocrab/src/lib.rs", warrant: "compile_fail doctests (a private wire cannot reach an output); READING for the lattice itself", hides: "a Meet impl that lets private meet public as public" },
    Row { path: "minocrab/src/circuit.rs", warrant: "every differential (the streams Circuit emits); guard_scope (guard scopes); the generated disclosure set-equality tests + compile_fail (the disclose gate). The instruction methods' operand/immediate handling and public_input minting: READING against reduce-to-zkir.ss", hides: "a guard dropped on one effect inside `when`; a public input minted in the wrong order" },
    Row { path: "minocrab/src/abi.rs", warrant: "entry / leaves / bounded (the constraint table pinned to compactc's, notes/builtin-lowering.org §9); interface_snapshot", hides: "an argument type constrained to the wrong width" },
    Row { path: "minocrab/src/disclose.rs", warrant: "the generated set-equality test on every circuit; disclosure_report; disclose", hides: "a disclosure recorded under a label the signature does not name" },
    Row { path: "minocrab/src/effects.rs", warrant: "guard_scope; every differential with a branch", hides: "an effect escaping its guard" },
    Row { path: "minocrab/src/lowering.rs", warrant: "minocrab-compat tests/profile.rs (the profile's settings and both refusals); kernel_cache (OncePerCircuit, and never keeping a guarded read); the zkir dump (every parity port byte-identical under the profile)", hides: "a setting the profile leaves at a non-compactc value, moving a parity port or a deployed key" },
    // ---- L2.5: Impact ledger ops ----------------------------------------------------------
    // Split from one 3724-line lib.rs into modules by concern (zero
    // behavioural movement) — the warrant below is the whole op layer's and
    // applies unchanged to every file it was split across.
    Row { path: "minocrab-ledger/src/lib.rs", warrant: READING, hides: "nothing beyond the crate doc and mod/pub-use plumbing" },
    Row { path: "minocrab-ledger/src/impact.rs", warrant: "differential_baseline (call-compatibility with compactc's artifacts); every contract differential; nested_differential + nested_typed (nested paths); entry_point (325 contracts). Ops no fixture reaches (VERIFICATION.md §5 'unported constructs'): READING against midnight-ledger.ss vm-code", hides: "an Impact op encoded so the ledger applies a different state change than the circuit claims" },
    Row { path: "minocrab-ledger/src/ops.rs", warrant: "differential_baseline (call-compatibility with compactc's artifacts); every contract differential; nested_differential + nested_typed (nested paths); entry_point (325 contracts). Ops no fixture reaches (VERIFICATION.md §5 'unported constructs'): READING against midnight-ledger.ss vm-code", hides: "an Impact op encoded so the ledger applies a different state change than the circuit claims" },
    Row { path: "minocrab-ledger/src/reads.rs", warrant: "differential_baseline (call-compatibility with compactc's artifacts); every contract differential; nested_differential + nested_typed (nested paths); entry_point (325 contracts); stale (emit's stale-read check: raw and typed writes refused alike, keys and leaves not checked, no instruction added). Ops no fixture reaches (VERIFICATION.md §5 'unported constructs'): READING against midnight-ledger.ss vm-code", hides: "an Impact op encoded so the ledger applies a different state change than the circuit claims; a stored value emitted without the stale-read check" },
    Row { path: "minocrab-ledger/src/kernel.rs", warrant: "differential_baseline (call-compatibility with compactc's artifacts); every contract differential; nested_differential + nested_typed (nested paths); entry_point (325 contracts). Ops no fixture reaches (VERIFICATION.md §5 'unported constructs'): READING against midnight-ledger.ss vm-code", hides: "an Impact op encoded so the ledger applies a different state change than the circuit claims" },
    Row { path: "minocrab-ledger/src/calls.rs", warrant: "differential_baseline (call-compatibility with compactc's artifacts); every contract differential; nested_differential + nested_typed (nested paths); entry_point (325 contracts). Ops no fixture reaches (VERIFICATION.md §5 'unported constructs'): READING against midnight-ledger.ss vm-code", hides: "an Impact op encoded so the ledger applies a different state change than the circuit claims" },
    Row { path: "minocrab-ledger/src/tests.rs", warrant: READING, hides: "a unit test that pins the wrong constant or asserts a weaker property than intended, unnoticed because it still passes" },
    // ---- L3: the standard library ---------------------------------------------------------
    Row { path: "minocrab-std/src/lib.rs", warrant: READING, hides: "nothing beyond re-exports" },
    Row { path: "minocrab-std/src/leaves.rs", warrant: "every differential; leaves / bounded / literals / secp; lean_claims (the typed-leaf claims, crates/minocrab-std/lean). `from_field_unchecked` sites: READING (the grep in TRUST.md §3)", hides: "a leaf whose type promises a bound its constructor did not constrain" },
    Row { path: "minocrab-std/src/ledger.rs", warrant: "every contract differential; ledger; nested_typed; the derive's layout pinned against compactc's `batch` for all 256 block sizes and the sixteen-field probe", hides: "a typed slot reading the wrong field, or a segmented path computed differently from compactc" },
    Row { path: "minocrab-std/src/borsh.rs", warrant: "serialization_conformance (vectors shared with the published TypeScript decoder, spec/ts); borsh; the borsh differentials", hides: "a non-canonical encoding accepted, breaking the digest's injectivity (api-safety-survey §B3)" },
    Row { path: "minocrab-std/src/borsh/schema.rs", warrant: "the generated schema cross-check test per #[derive(CircuitBorsh)] (layout ≡ borsh's schema of the spec type)", hides: "a layout table disagreeing with the published spec" },
    Row { path: "minocrab-std/src/kernel.rs", warrant: "kernel_tokens_differential (24 circuits, byte-identical); kernel_cache", hides: "a kernel effect claimed at the wrong effects index" },
    Row { path: "minocrab-std/src/blind.rs", warrant: "blind (every blind op run on Midnight's on-chain VM against a seeded state, zero reads asserted; the typed spellings byte-identical to the explicit op lists); stream; evm_outbox", hides: "a blind combine or snapshot that lands a different value than the step defines, or one that embeds a read" },
    Row { path: "minocrab-std/src/hook.rs", warrant: "hook (every builder method on the on-chain VM, each failure row of the design table, attachment order, guard capture, the after-the-body rule; a composite hook byte-identical to the explicit op lists); the two compile-fail doctests", hides: "a hook lowered to ops that read, or emitted under the wrong guard or before an inline effect" },
    Row { path: "minocrab-std/src/assumed.rs", warrant: "ledger and every contract differential (the wrapper is erased in the ZKIR: byte-identical artifacts); the compile-fail doctest; the backstop's refusals in the contract suites named every read-modify-write in the corpus", hides: "a read result re-entering the ledger with nothing naming the assumption — a contended write nobody sees as one" },
    Row { path: "minocrab-std/src/stream.rs", warrant: "stream (insert / take / combine / sequence on the on-chain VM, both layouts); evm_outbox (the contention audit); fee_ema (flushes of one to four); the two compile-fail doctests", hides: "a stream operation reading the shared accumulator where the design says it must not" },
    Row { path: "minocrab-std/src/vector.rs", warrant: "vector (fold and for_each on the VM: live slots only, the guard and the select; the all-dead case unexpressible); bounded", hides: "a fold applying its step, or a ledger op, on a dead slot" },
    Row { path: "minocrab-std/src/entry.rs", warrant: "interface_snapshot (every circuit's argument schema frozen); entry; every differential", hides: "an argument declared in a different slot order than the wire" },
    Row { path: "minocrab-std/src/predicate.rs", warrant: "predicates; every differential with a comparison", hides: "a comparison at the wrong width, or a message-carrying assert that binds outside its branch" },
    Row { path: "minocrab-std/src/slots.rs", warrant: "xcall_differential / xcall_with_payment_differential / xcontract_events_differential; interface_macro; contract_matches_its_interface", hides: "a leaf's slots (call limbs, ledger limbs, argument constraints) in the wrong order" },
    Row { path: "minocrab-std/src/disclose.rs", warrant: "disclose; the generated set-equality tests", hides: "a leaf disclosed under fewer wires than it has" },
    Row { path: "minocrab-std/src/event.rs", warrant: "event (ZKIR and disclosure record identical to the raw `emit_event` form, straight-line and under `when`, one to ten limbs; refused inside `when_private`); events_differential and xcontract_events_differential (the Borsh twins included) / signet_construction (the five emitting contracts byte-identical); the compile-fail doctest", hides: "an event wrapper with a version, tag or payload width compactc would not emit" },
    Row { path: "minocrab-std/src/hash.rs", warrant: "hashing_differential; every differential that hashes", hides: "a preimage aligned differently from compactc's" },
    // ---- the decorators ------------------------------------------------------------------
    Row { path: "minocrab-macros/src/lib.rs", warrant: READING, hides: "nothing beyond wrappers (the expansions are the modules below)" },
    Row { path: "minocrab-macros/src/circuit.rs", warrant: "circuit (the expansion lowers to ZKIR byte-identical to the hand-written twin); the generated per-circuit tests run on every circuit. The GENERATED TESTS' own bodies: READING", hides: "an expansion that declares an argument the twin would not, or a generated test that passes vacuously" },
    Row { path: "minocrab-macros/src/circuit_arg.rs", warrant: "derive (twin); every derived struct's slots in interface_snapshot", hides: "a field's slots declared out of order" },
    Row { path: "minocrab-macros/src/circuit_borsh.rs", warrant: "borsh_derive (twin) + the generated schema cross-check", hides: "a Borsh field encoded at the wrong width" },
    Row { path: "minocrab-macros/src/interface.rs", warrant: "interface_macro (twin, byte-identical ZKIR); contract_matches_its_interface", hides: "a call handle passing limbs in an order the callee does not expect" },
    Row { path: "minocrab-macros/src/ledger.rs", warrant: "the derive's unit tests; in_block pinned against `batch` for every block size (minocrab-std); the sixteen-field compactc probe", hides: "a ledger field laid out at a path compactc would not use" },
    Row { path: "minocrab-macros/src/ledger_repr.rs", warrant: READING, hides: "nothing beyond the check it adds to `value.rs`" },
    Row { path: "minocrab-macros/src/value.rs", warrant: "ledger `derived_repr` (atoms and limb round trip); derive (twin); the erc20_vault_pending lineage's slots; the 227-circuit dump", hides: "an environment's limbs split at the wrong boundaries on read-back, or an impl that holds where a field's does not" },
    Row { path: "minocrab-macros/src/contract.rs", warrant: "circuit_closure (every #[circuit] is listed) + the derived sets feeding both snapshots", hides: "a circuit missing from its contract's set" },
    // ---- L5: the simulator ---------------------------------------------------------------
    Row { path: "minocrab-sim/src/lib.rs", warrant: READING, hides: "nothing beyond the Profile types" },
    Row { path: "minocrab-sim/src/vm.rs", warrant: "cross-checked against Midnight's reference VM (`IrSource::check`) on every accepted run — link 2 of erc20_vault_pending_spec, link 3 of executor_vault, and every differential; end_to_end. It is never trusted alone", hides: "a simulator accepting what the reference VM rejects (caught) — or both agreeing on a wrong statement (out of scope here; the differentials' job)" },
    Row { path: "minocrab-sim/src/exec.rs", warrant: "executor_vault (the transcript it derives from state equals the vault harness's hand model, op for op, on seventeen circuits) + IrSource::check on every preimage it produces; impact_roundtrip (the decoder is the exact inverse of minocrab-ledger's encoder, one fixture per Op::field_repr branch). Test-side only: nothing a deployed circuit links", hides: "a mis-decoded Impact op — a transcript that gathers a read from the wrong slot, agreeing with nothing (caught by the harness) unless the hand model is wrong the same way" },
    Row { path: "minocrab-sim/src/rowcost.rs", warrant: "calibrated against real proving (BENCHMARK.md); a MEASUREMENT model, not a correctness claim", hides: "a mis-priced primitive — a wrong k estimate, never a wrong circuit" },
    Row { path: "minocrab-sim/src/bin/minocrab.rs", warrant: READING, hides: "nothing a proof depends on (the CLI)" },
];

const CRATES: &[&str] = &["minocrab-zkir", "minocrab-ir", "minocrab-taint", "minocrab", "minocrab-ledger", "minocrab-std", "minocrab-macros", "minocrab-sim"];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("repo root")
}

fn source_files(crates_dir: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for krate in CRATES {
        let src = crates_dir.join(krate).join("src");
        let mut stack = vec![src.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("readable src dir") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let rel = path.strip_prefix(crates_dir).expect("under crates/").to_string_lossy().replace('\\', "/");
                    out.insert(rel);
                }
            }
        }
    }
    out
}

/// The table body, from the classification alone. The closing sentence
/// counts files, which move only when a file is added, removed or
/// reclassified.
fn table() -> String {
    let mut body = String::from("| file | what warrants it | the failure that would hide there |\n|---|---|---|\n");
    let mut reading = 0usize;
    for row in ROWS {
        if row.warrant == READING || row.warrant.contains(": READING") {
            reading += 1;
        }
        let warrant = if row.warrant == READING { "**READING**".to_string() } else { row.warrant.replace(": READING", ": **READING**") };
        body.push_str(&format!("| `{}` | {} | {} |\n", row.path, warrant, row.hides));
    }
    let total = ROWS.len();
    body.push_str(&format!("\n{total} files in the eight crates; {reading} of them have a warrant that is READING in whole or in part (the rows in bold).\n"));
    body
}

const BEGIN: &str = "<!-- GENERATED BEGIN: trust_base.rs -->";
const END: &str = "<!-- GENERATED END -->";

fn generated_region(text: &str) -> (usize, usize) {
    let a = text.find(BEGIN).expect("TRUST.md has the BEGIN marker") + BEGIN.len();
    let b = text.find(END).expect("TRUST.md has the END marker");
    assert!(a < b, "markers out of order");
    (a, b)
}

#[test]
fn the_classification_is_closed_over_the_edsl_sources() {
    let files = source_files(&repo_root().join("crates"));
    let classified: Vec<&str> = ROWS.iter().map(|r| r.path).collect();
    for row in ROWS {
        assert!(files.contains(row.path), "classified file no longer exists: {}", row.path);
    }
    let unclassified: Vec<&String> = files.iter().filter(|f| !classified.contains(&f.as_str())).collect();
    assert!(
        unclassified.is_empty(),
        "source files of the eDSL crates with no row in trust_base.rs (add a row; say READING if unsure): {unclassified:?}"
    );
    let mut seen = BTreeSet::new();
    for row in ROWS {
        assert!(seen.insert(row.path), "duplicate row: {}", row.path);
        assert!(!row.hides.is_empty(), "{}: every row names the failure it would hide", row.path);
    }
}

#[test]
fn trust_md_table_is_current() {
    let root = repo_root();
    let expected = format!("\n{}", table());
    let path = root.join("TRUST.md");
    let text = std::fs::read_to_string(&path).expect("TRUST.md exists");
    let (a, b) = generated_region(&text);
    if std::env::var_os("MINOCRAB_TRUST_BASE").is_some() {
        let mut out = String::new();
        out.push_str(&text[..a]);
        out.push_str(&expected);
        out.push_str(&text[b..]);
        std::fs::write(&path, out).expect("TRUST.md writes");
        return;
    }
    assert_eq!(
        &text[a..b],
        expected,
        "TRUST.md's generated table is stale — regenerate with \
         `MINOCRAB_TRUST_BASE=1 cargo test -p minocrab-contracts --test trust_base` and review the diff"
    );
}
