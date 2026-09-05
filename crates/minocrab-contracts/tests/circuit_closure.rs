//! CLOSURE of the circuit list: every `#[circuit]` in this crate's source
//! appears in `support::circuits()`.
//!
//! `circuits()` is the only statement of which circuits exist — it feeds both
//! snapshots, the ZKIR dump, the adversarial suite and the taint lint. Until
//! now nothing checked it was complete: the snapshots guard the opposite
//! direction (a listed circuit that moved), so a circuit added and not listed
//! was covered by nothing. VERIFICATION.md §5 admitted this; the external
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
