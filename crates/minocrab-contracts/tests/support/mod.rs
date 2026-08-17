//! Shared test support. Not a test target (lives in a subdirectory).
//!
//! Compiled into every test binary that declares `mod support`, each of
//! which uses only the part it needs — hence the blanket `dead_code`
//! allowance.
#![allow(dead_code)]

use midnight_transient_crypto::proofs::ProofPreimage;

use minocrab::v3::Compiled3;
use minocrab_zkir::v3::{to_zkir_string, IrSource};
use minocrab_contracts::{
    adts, attest, bounded, coins, kernel_tokens, erc20_vault, erc20_vault_borsh,
    erc20_vault_modern, erc20_vault_opt, events, events_borsh, hashing, mint_tokens, nested,
    opaque,
    serde_builtin, signet_contract, test_caller, xcall, xcall_with_payment, xcontract_events,
    xcontract_events_borsh,
};

/// A circuit under snapshot: its name and how to build it.
pub type Circuit = (&'static str, fn() -> Compiled3);

/// A file under `crates/minocrab-contracts/tests/`.
pub fn test_source(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join(name)
}

/// Replace a snapshot table's generated region, in place.
///
/// The snapshot regenerators WRITE their table back into their own source
/// file instead of printing it for a human to paste. A toolchain bump moves
/// several snapshots at once (M8, notes/version-bump.org), and `./bump.sh
/// accept` runs every regenerator in one step — a step that has to end with
/// a reviewable `git diff`, not with paste instructions.
///
/// `body` replaces every line strictly between the two marker lines, whose
/// own indentation is preserved. Each marker must appear exactly once.
pub fn rewrite_generated_region(path: &std::path::Path, body: &str) {
    // Assembled rather than written literally, so that the markers occur
    // exactly once in a file this function rewrites.
    let begin = format!("// {} BEGIN", "GENERATED");
    let end = format!("// {} END", "GENERATED");
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{} is not readable: {e}", path.display()));
    let at = |marker: &str| {
        let first = text
            .find(marker)
            .unwrap_or_else(|| panic!("{} has no `{marker}` marker", path.display()));
        assert!(
            text[first + marker.len()..].find(marker).is_none(),
            "{} has more than one `{marker}` marker",
            path.display()
        );
        first
    };
    let (begin_at, end_at) = (at(&begin), at(&end));
    assert!(begin_at < end_at, "{}: the markers are the wrong way round", path.display());
    // From just past the BEGIN marker's newline to the start of the line
    // carrying the END marker.
    let from = begin_at + text[begin_at..].find('\n').expect("the begin marker ends its line") + 1;
    let to = text[..end_at].rfind('\n').expect("the end marker is not on line 1") + 1;

    let mut out = String::with_capacity(text.len());
    out.push_str(&text[..from]);
    out.push_str(body);
    out.push_str(&text[to..]);
    std::fs::write(path, out).unwrap_or_else(|e| panic!("{} is not writable: {e}", path.display()));
    println!("wrote {}", path.display());
}

// ---- the ZKIR dump, and the diff that reads it ------------------------------

/// A circuit's serialized ZKIR, ONE INSTRUCTION PER LINE.
///
/// Exactly [`to_zkir_string`]'s JSON, split: the first line is the object
/// without its `instructions` (version, input schema, output types, the
/// communications-commitment flag), then one line per instruction in order.
/// Nothing is dropped, so equality of these lines is equality of the IR —
/// which is what lets the same rendering serve the byte-comparison instrument
/// (`zkir_dump`) and the line diff a snapshot failure prints.
pub fn zkir_lines(ir: &IrSource) -> Vec<String> {
    let text = to_zkir_string(ir).expect("the IR serializes");
    let mut value: serde_json::Value =
        serde_json::from_str(&text).expect("its own output parses back");
    let object = value
        .as_object_mut()
        .expect("a serialized IrSource is a JSON object");
    let instructions = object
        .remove("instructions")
        .expect("a serialized IrSource carries its instructions");
    let mut lines = vec![serde_json::to_string(&value).expect("the header re-serializes")];
    lines.extend(
        instructions
            .as_array()
            .expect("`instructions` is an array")
            .iter()
            .map(|i| serde_json::to_string(i).expect("an instruction re-serializes")),
    );
    lines
}

/// A circuit's file name in a dump directory: the name with `::` as `__`, so
/// a `diff -rq` names the circuit directly.
pub fn zkir_dump_name(circuit: &str) -> String {
    format!("{}.zkir", circuit.replace("::", "__"))
}

/// Write every circuit's [`zkir_lines`] into `dir`, one file each.
pub fn write_zkir_dump(dir: &std::path::Path) -> usize {
    std::fs::create_dir_all(dir).unwrap_or_else(|e| panic!("creating {}: {e}", dir.display()));
    let circuits = circuits();
    for (name, build) in &circuits {
        let mut text = zkir_lines(&build().ir).join("\n");
        text.push('\n');
        let path = dir.join(zkir_dump_name(name));
        std::fs::write(&path, text).unwrap_or_else(|e| panic!("writing {}: {e}", path.display()));
    }
    circuits.len()
}

/// Where `row_snapshot` looks for the previous run's dump: `$MINOCRAB_ZKIR_
/// BASELINE` if it is set (a directory `zkir_dump` produced at a chosen
/// commit), otherwise the copy the row snapshot keeps for itself under the
/// target directory.
pub fn zkir_baseline_dir() -> std::path::PathBuf {
    match std::env::var_os("MINOCRAB_ZKIR_BASELINE") {
        Some(dir) => std::path::PathBuf::from(dir),
        None => std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("zkir-baseline"),
    }
}

/// The longest-common-subsequence table of two line lists.
fn lcs_table(a: &[&str], b: &[&str]) -> Vec<Vec<usize>> {
    let mut lcs = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    lcs
}

/// A unified-style diff: `-` expected, `+` actual, ` ` unchanged.
///
/// One definition, used by `interface_snapshot`'s failure path (over
/// interface lines) and `row_snapshot`'s (over [`zkir_lines`]).
pub fn diff(expected: &[&str], actual: &[&str]) -> String {
    let lcs = lcs_table(expected, actual);
    let (mut i, mut j) = (0, 0);
    let mut out = String::new();
    while i < expected.len() && j < actual.len() {
        if expected[i] == actual[j] {
            out.push_str(&format!("      {}\n", expected[i]));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            out.push_str(&format!("    - {}\n", expected[i]));
            i += 1;
        } else {
            out.push_str(&format!("    + {}\n", actual[j]));
            j += 1;
        }
    }
    for line in &expected[i..] {
        out.push_str(&format!("    - {line}\n"));
    }
    for line in &actual[j..] {
        out.push_str(&format!("    + {line}\n"));
    }
    out
}

/// Beyond this many lines on either side, [`changed_lines`] stops using
/// [`diff`]: the LCS table is `(n+1)·(m+1)` `usize`s, which is nothing at the
/// ~300-instruction streams this workspace builds and gigabytes at a stream a
/// hundred times longer. A failing instrument must not exhaust memory, so the
/// fallback is a positional comparison — cruder (an insertion misaligns
/// everything after it) but bounded.
const LCS_LIMIT: usize = 5_000;

/// [`diff`] with the unchanged lines dropped and the result capped.
///
/// An instruction-level diff is mostly unchanged lines; what a failure needs
/// is the movement, so only the `-`/`+` lines survive and only the first
/// `max` of them are printed.
pub fn changed_lines(expected: &[&str], actual: &[&str], max: usize) -> String {
    let full = if expected.len().max(actual.len()) > LCS_LIMIT {
        positional_diff(expected, actual)
    } else {
        diff(expected, actual)
    };
    let changed: Vec<&str> = full
        .lines()
        .filter(|l| l.starts_with("    -") || l.starts_with("    +"))
        .collect();
    let mut out = String::new();
    for line in changed.iter().take(max) {
        out.push_str(line);
        out.push('\n');
    }
    if changed.len() > max {
        out.push_str(&format!(
            "    … {} more changed lines\n",
            changed.len() - max
        ));
    }
    out
}

/// [`diff`]'s shape without its table: index against index.
fn positional_diff(expected: &[&str], actual: &[&str]) -> String {
    let mut out = String::new();
    for i in 0..expected.len().max(actual.len()) {
        match (expected.get(i), actual.get(i)) {
            (Some(a), Some(b)) if a == b => out.push_str(&format!("      {a}\n")),
            (a, b) => {
                if let Some(a) = a {
                    out.push_str(&format!("    - {a}\n"));
                }
                if let Some(b) = b {
                    out.push_str(&format!("    + {b}\n"));
                }
            }
        }
    }
    out
}

/// Every circuit the workspace builds, in snapshot order. Shared by the
/// snapshot guards (`row_snapshot`, `interface_snapshot`) so both cover
/// exactly the same set; their frozen tables stay independent.
pub fn circuits() -> Vec<Circuit> {
    macro_rules! c {
        ($name:literal, $f:expr) => {
            ($name, { $f } as fn() -> Compiled3)
        };
    }
    let mut listed: Vec<Circuit> = vec![
        c!("erc20_vault::initialize", || erc20_vault::initialize()),
        c!("erc20_vault::deposit", || erc20_vault::deposit()),
        c!("erc20_vault::claim", || erc20_vault::claim()),
        c!("erc20_vault::approve_router", || erc20_vault::approve_router()),
        c!("erc20_vault::withdraw", || erc20_vault::withdraw()),
        c!("erc20_vault::complete_withdraw", || erc20_vault::complete_withdraw()),
        c!("erc20_vault::refund", || erc20_vault::refund()),
        c!("erc20_vault::swap", || erc20_vault::swap()),
        c!("erc20_vault::complete_swap", || erc20_vault::complete_swap()),
        // erc20-vault, OPTIMIZED (M10 step 4): the same nine circuits from the
        // forked artifact. At the forking commit every row and every interface
        // line below is identical to the port's; later M10 rungs move the rows
        // of this block ONLY — a moved port row means an optimization leaked
        // into the compatibility reference.
        c!("erc20_vault_opt::initialize", || erc20_vault_opt::initialize()),
        c!("erc20_vault_opt::deposit", || erc20_vault_opt::deposit()),
        c!("erc20_vault_opt::claim", || erc20_vault_opt::claim()),
        c!("erc20_vault_opt::approve_router", || erc20_vault_opt::approve_router()),
        c!("erc20_vault_opt::withdraw", || erc20_vault_opt::withdraw()),
        c!("erc20_vault_opt::complete_withdraw", || erc20_vault_opt::complete_withdraw()),
        c!("erc20_vault_opt::refund", || erc20_vault_opt::refund()),
        c!("erc20_vault_opt::swap", || erc20_vault_opt::swap()),
        c!("erc20_vault_opt::complete_swap", || erc20_vault_opt::complete_swap()),
        // erc20-vault, BORSH (M11 stage 4): the same nine circuits again, forked
        // from the OPTIMIZED artifact. At the forking commit every row and every
        // interface line below is identical to the opt block's; M11's format
        // changes move the rows of this block ONLY.
        c!("erc20_vault_borsh::initialize", || erc20_vault_borsh::initialize()),
        c!("erc20_vault_borsh::deposit", || erc20_vault_borsh::deposit()),
        c!("erc20_vault_borsh::claim", || erc20_vault_borsh::claim()),
        c!("erc20_vault_borsh::approve_router", || erc20_vault_borsh::approve_router()),
        c!("erc20_vault_borsh::withdraw", || erc20_vault_borsh::withdraw()),
        c!("erc20_vault_borsh::complete_withdraw", || erc20_vault_borsh::complete_withdraw()),
        c!("erc20_vault_borsh::refund", || erc20_vault_borsh::refund()),
        c!("erc20_vault_borsh::swap", || erc20_vault_borsh::swap()),
        c!("erc20_vault_borsh::complete_swap", || erc20_vault_borsh::complete_swap()),
        // erc20-vault, THE SHOWCASE TWIN (M9 phase 8): the same nine circuits
        // once more, rewritten through the whole M9 API from the BORSH fork.
        // These rows are the phase's deliverable and are EXPECTED to differ
        // from the borsh block's — by construction, since the modern spelling
        // drops the `Copy`s that named the Impact guards. What may not move is
        // the (k, rows) of the three blocks above.
        c!("erc20_vault_modern::initialize", || erc20_vault_modern::initialize()),
        c!("erc20_vault_modern::deposit", || erc20_vault_modern::deposit()),
        c!("erc20_vault_modern::claim", || erc20_vault_modern::claim()),
        c!("erc20_vault_modern::approve_router", || erc20_vault_modern::approve_router()),
        c!("erc20_vault_modern::withdraw", || erc20_vault_modern::withdraw()),
        c!("erc20_vault_modern::complete_withdraw", || erc20_vault_modern::complete_withdraw()),
        c!("erc20_vault_modern::refund", || erc20_vault_modern::refund()),
        c!("erc20_vault_modern::swap", || erc20_vault_modern::swap()),
        c!("erc20_vault_modern::complete_swap", || erc20_vault_modern::complete_swap()),
        c!("signet_contract::sign_bidirectional", || signet_contract::sign_bidirectional()),
        c!("signet_contract::respond", || signet_contract::respond()),
        c!("signet_contract::respond_bidirectional", || {
            signet_contract::respond_bidirectional()
        }),
        c!("attest::map_only", || attest::map_only()),
        c!("attest::verify_only", || attest::verify_only()),
        c!("attest::sha_verify", || attest::sha_verify()),
        c!("attest::keccak_verify", || attest::keccak_verify()),
        c!("events::base", || events::base()),
        c!("events::emit_n(1)", || events::emit_n(1)),
        c!("events::emit_n(2)", || events::emit_n(2)),
        c!("events::emit_n(4)", || events::emit_n(4)),
        // events, THROUGH THE BORSH API (M11 stage 6): byte-identical ZKIR to
        // the four above, so these rows must match them line for line.
        c!("events_borsh::base", || events_borsh::base()),
        c!("events_borsh::emit_n(1)", || events_borsh::emit_n(1)),
        c!("events_borsh::emit_n(2)", || events_borsh::emit_n(2)),
        c!("events_borsh::emit_n(4)", || events_borsh::emit_n(4)),
        c!("hashing::control(32)", || hashing::control(32)),
        c!("hashing::control(64)", || hashing::control(64)),
        c!("hashing::control(128)", || hashing::control(128)),
        c!("hashing::control(256)", || hashing::control(256)),
        c!("hashing::control(1024)", || hashing::control(1024)),
        c!("hashing::persistent(32)", || hashing::persistent(32)),
        c!("hashing::persistent(64)", || hashing::persistent(64)),
        c!("hashing::persistent(128)", || hashing::persistent(128)),
        c!("hashing::persistent(256)", || hashing::persistent(256)),
        c!("hashing::persistent(1024)", || hashing::persistent(1024)),
        c!("hashing::keccak(64)", || hashing::keccak(64)),
        c!("hashing::keccak(128)", || hashing::keccak(128)),
        c!("hashing::keccak(256)", || hashing::keccak(256)),
        c!("hashing::transient(32)", || hashing::transient(32)),
        c!("hashing::transient(256)", || hashing::transient(256)),
        c!("hashing::transient(1024)", || hashing::transient(1024)),
        c!("hashing::persistent_vec8", || hashing::persistent_vec8()),
        c!("xcall::local_base", || xcall::local_base()),
        c!("xcall::call_once", || xcall::call_once()),
        c!("xcall::call_twice", || xcall::call_twice()),
        c!("xcall::call_big", || xcall::call_big()),
        c!("xcall::target_deposit", || xcall::target_deposit()),
        c!("xcall::target_deposit_emit", || xcall::target_deposit_emit()),
        c!("xcall::target_deposit_big", || xcall::target_deposit_big()),
        c!("xcall_with_payment::call_once", || xcall_with_payment::call_once()),
        c!("xcall_with_payment::request", || xcall_with_payment::request()),
        c!("xcall_with_payment::notify", || xcall_with_payment::notify()),
        c!("xcall_with_payment::pay", || xcall_with_payment::pay()),
        c!("xcall_with_payment::confirm_request", || xcall_with_payment::confirm_request()),
        c!("xcontract_events::deposit_via_vault", || xcontract_events::deposit_via_vault()),
        c!("xcontract_events::token_deposit", || xcontract_events::token_deposit()),
        c!("xcontract_events_borsh::token_deposit", || {
            xcontract_events_borsh::token_deposit()
        }),
        c!("mint_tokens::mint_with_recipient_argument", || {
            mint_tokens::mint_with_recipient_argument()
        }),
        c!("mint_tokens::mint_with_recipient_own_public_key", || {
            mint_tokens::mint_with_recipient_own_public_key()
        }),
        c!("serde_builtin::check_roundtrip", || serde_builtin::check_roundtrip()),
        c!("test_caller::initialise", || test_caller::initialise()),
        // `bounded.compact` (M14): Compact's `Uint<0..n>` at every shape the
        // bound can take, one circuit each. The only block here whose Compact
        // source is OURS rather than the corpus's — no compiled corpus
        // artifact carries a non-power-of-two bound
        // (tests/bounded_differential.rs has the scan).
        c!("bounded::b10", || bounded::b10()),
        c!("bounded::b300", || bounded::b300()),
        c!("bounded::b1000", || bounded::b1000()),
        c!("bounded::b70000", || bounded::b70000()),
        c!("bounded::b1", || bounded::b1()),
        c!("bounded::b2", || bounded::b2()),
        c!("bounded::b256", || bounded::b256()),
        c!("bounded::b255", || bounded::b255()),
        c!("bounded::b_enum", || bounded::b_enum()),
        c!("bounded::b_struct", || bounded::b_struct()),
        c!("bounded::b_compare", || bounded::b_compare()),
        // `opaque.compact` (M15): Compact's `Opaque<'ts-type'>` in every
        // position it can occupy, plus the two CURVE POINT types, which
        // compactc's ABI also spells `Opaque`. Ours rather than the corpus's
        // for the same reason as `bounded` above: the corpus's 74 `Opaque`
        // nodes are all in v2 artifacts except four `Secp256k1Point`s
        // (tests/opaque_differential.rs has the scan).
        c!("opaque::op_arg", || opaque::op_arg()),
        c!("opaque::op_ret", || opaque::op_ret()),
        c!("opaque::op_eq", || opaque::op_eq()),
        c!("opaque::op_default", || opaque::op_default()),
        c!("opaque::op_cell", || opaque::op_cell()),
        c!("opaque::op_witness", || opaque::op_witness()),
        c!("opaque::op_map_value", || opaque::op_map_value()),
        c!("opaque::op_map_key", || opaque::op_map_key()),
        c!("opaque::op_set", || opaque::op_set()),
        c!("opaque::op_maybe", || opaque::op_maybe()),
        c!("opaque::op_bytes", || opaque::op_bytes()),
        c!("opaque::op_struct", || opaque::op_struct()),
        c!("opaque::op_point", || opaque::op_point()),
        c!("opaque::op_jubjub", || opaque::op_jubjub()),
        // `adts.compact` (M16): every ledger-ADT operation Compact exposes.
        // Ours rather than the corpus's for the third time and the same
        // reason — the corpus's `List`/`MerkleTree`/`HistoricMerkleTree`
        // declarations are in v2 artifacts, and its v3 ones exercise three of
        // these thirty-one (tests/adts_differential.rs has the scan).
        c!("adts::set_insert", || adts::set_insert()),
        c!("adts::set_member", || adts::set_member()),
        c!("adts::set_remove", || adts::set_remove()),
        c!("adts::set_size", || adts::set_size()),
        c!("adts::set_is_empty", || adts::set_is_empty()),
        c!("adts::set_reset", || adts::set_reset()),
        c!("adts::list_push_front", || adts::list_push_front()),
        c!("adts::list_pop_front", || adts::list_pop_front()),
        c!("adts::list_head", || adts::list_head()),
        c!("adts::list_length", || adts::list_length()),
        c!("adts::list_is_empty", || adts::list_is_empty()),
        c!("adts::list_reset", || adts::list_reset()),
        c!("adts::map_insert_default", || adts::map_insert_default()),
        c!("adts::map_reset", || adts::map_reset()),
        c!("adts::mt_insert", || adts::mt_insert()),
        c!("adts::mt_insert_index", || adts::mt_insert_index()),
        c!("adts::mt_insert_hash", || adts::mt_insert_hash()),
        c!("adts::mt_insert_hash_index", || adts::mt_insert_hash_index()),
        c!("adts::mt_insert_index_default", || {
            adts::mt_insert_index_default()
        }),
        c!("adts::mt_check_root", || adts::mt_check_root()),
        c!("adts::mt_is_full", || adts::mt_is_full()),
        c!("adts::mt_reset", || adts::mt_reset()),
        c!("adts::hmt_insert", || adts::hmt_insert()),
        c!("adts::hmt_insert_index", || adts::hmt_insert_index()),
        c!("adts::hmt_insert_hash", || adts::hmt_insert_hash()),
        c!("adts::hmt_insert_hash_index", || {
            adts::hmt_insert_hash_index()
        }),
        c!("adts::hmt_insert_index_default", || {
            adts::hmt_insert_index_default()
        }),
        c!("adts::hmt_check_root", || adts::hmt_check_root()),
        c!("adts::hmt_is_full", || adts::hmt_is_full()),
        c!("adts::hmt_reset_history", || adts::hmt_reset_history()),
        c!("adts::hmt_reset", || adts::hmt_reset()),
        // `kernel.compact` (M17): the kernel primitives and the token-stdlib
        // circuits built on them. Ours rather than the corpus's for the fourth
        // time and the same measured reason — the v3 corpus's kernel/token
        // surface is entirely SHIELDED (tests/kernel_tokens_differential.rs
        // has the scan). `kernel.checkpoint()` is absent because compactc's
        // v3 backend cannot compile it at all.
    ];
    // DERIVED, not listed (the `#[contract]` block): every circuit
    // `KernelTokens` exports, named the way this list names things. A circuit
    // added to that contract appears here without anyone editing this file,
    // which is the completeness the hand-written entries never had.
    listed.extend(of(
        "kernel_tokens",
        &kernel_tokens::KernelTokens::CIRCUITS,
    ));
    // `coins.compact` (M22 stage A): the three COIN ARMS of the collection
    // ADTs — `Set.insertCoin`, `Map.insertCoin`, `List.pushFrontCoin`. Ours
    // rather than the corpus's for the fifth time, and here because the
    // demand is OpenZeppelin's and OZ's artifacts are ZKIR v2
    // (tests/coins_differential.rs has the scan). Derived, like
    // `kernel_tokens` above.
    listed.extend(of("coins", &coins::Coins::CIRCUITS));
    // `nested.compact` (M22 stage B1): NESTED ledger ADTs — `Map<K, Map>`,
    // `Map<K, List>`, `Map<K, Set>`, `Map<K, Counter>`, the two trees, and a
    // three-level `Map`. Built at the RAW op layer (`&[LedgerKey]` by hand),
    // because the typed surface is stage B2 and the encoding had to be
    // proven first. Derived, like `coins` above.
    listed.extend(of("nested", &nested::Nested::CIRCUITS));
    listed
}

/// A contract's derived circuit set, named `module::circuit` the way the
/// snapshots key their tables.
fn of(module: &str, circuits: &[(&'static str, fn() -> Compiled3)]) -> Vec<Circuit> {
    circuits
        .iter()
        .map(|(name, build)| {
            let name: &'static str = Box::leak(format!("{module}::{name}").into_boxed_str());
            (name, *build)
        })
        .collect()
}

/// Dump a differential test's honest, corpus-verified preimage for the
/// benchmark harness (crates/minocrab-bench): no-op unless
/// `MINOCRAB_DUMP_PREIMAGES=<dir>` is set. Both toolchains' artifacts are
/// PI-equal on these preimages, so the benchmark proves the SAME statement
/// under both.
pub fn dump_preimage(circuit: &str, pi: &ProofPreimage) {
    dump_preimage_in(None, circuit, pi)
}

/// [`dump_preimage`] into a per-side subdirectory. The optimized artifact
/// cannot share the port's preimage — it proves its own statement for the
/// same logical operation — so the benchmark reads its preimages from
/// `preimages/opt/` (crates/minocrab-bench: `Preimages::PerSide`).
pub fn dump_preimage_in(side: Option<&str>, circuit: &str, pi: &ProofPreimage) {
    let Some(dir) = std::env::var_os("MINOCRAB_DUMP_PREIMAGES") else {
        return;
    };
    let mut dir = std::path::PathBuf::from(dir);
    if let Some(side) = side {
        dir.push(side);
    }
    std::fs::create_dir_all(&dir).expect("create preimage dump dir");
    let mut buf = Vec::new();
    midnight_serialize::tagged_serialize(pi, &mut buf).expect("preimage serializes");
    std::fs::write(dir.join(format!("{circuit}.preimage")), buf).expect("preimage writes");
}
