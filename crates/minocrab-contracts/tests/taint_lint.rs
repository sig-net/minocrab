//! The taint lint over every circuit the workspace builds (M23 R3).
//!
//! `minocrab_ir::v3::taint::audit` proves each byte-atom hash-preimage limb
//! bounded to its own byte width or constant — the api-safety-survey §B3
//! class no test on honest preimages can see. Running it over
//! `support::circuits()` audits all present circuits AND every future one,
//! since the snapshot registry is the one list every new circuit joins.
//!
//! # The recorded findings, and why they are frozen rather than fixed
//!
//! The first run (2026-08-27, notes/taint-lint.org) classified every firing:
//! ZERO findings on free-witness wires (`%w.*`, `private_input`) — every
//! prover-controlled limb that reaches a hash is constrained in-circuit —
//! and every finding rooted in PUBLIC-TRANSCRIPT wires (`%pi.*`, the popeq
//! ledger reads and cross-contract results, plus `sel`/`add`/`div` wires
//! derived from them). Those carry an EXTERNAL warrant: the wire must equal
//! a value the ledger itself stored normalized, so an out-of-range value
//! can never verify against a real transcript — but that warrant is the
//! ledger's, not an in-circuit constraint, and compactc's own artifacts
//! have the identical property (27 of the 84 v3 corpus artifacts fire the
//! same way; `cargo run -p minocrab-ir --example taint_corpus`). Whether the
//! lint should encode that warrant (and how guarded reads — whose wires are
//! genuinely FREE when the guard is false — are treated) is dmd's call, per
//! the M23 R3 spec: findings go to dmd; no allowlist without a ruling.
//!
//! Until that ruling, the recorded findings are FROZEN as a baseline, the
//! way the row snapshot freezes rows: any NEW finding fails this test, so
//! the instrument still audits every change and every future circuit.

mod support;

use std::collections::HashSet;

use minocrab_ir::v3::taint;

const BASELINE: &str = include_str!("taint_baseline.txt");

#[test]
fn every_hash_limb_is_bounded_or_recorded() {
    let mut lines = Vec::new();
    for (name, build) in support::circuits() {
        for finding in taint::audit(&build().ir.instructions) {
            lines.push(format!("{name}: {finding}"));
        }
    }
    let mut current = lines.join("\n");
    if !current.is_empty() {
        current.push('\n');
    }

    // `MINOCRAB_TAINT_BASELINE=1 cargo test …` rewrites the frozen file —
    // for REMOVALS (a finding resolved is pure progress) and for findings
    // dmd has ruled on. A NEW finding must never be accepted this way
    // without that ruling; the failure message below is the instrument.
    if std::env::var_os("MINOCRAB_TAINT_BASELINE").is_some() {
        let path = support::test_source("taint_baseline.txt");
        std::fs::write(&path, &current).expect("baseline writes");
        println!("wrote {}", path.display());
        return;
    }

    if current == BASELINE {
        return;
    }
    let old: HashSet<&str> = BASELINE.lines().collect();
    let new: HashSet<&str> = current.lines().collect();
    let added: Vec<&&str> = {
        let mut a: Vec<_> = new.difference(&old).collect();
        a.sort();
        a
    };
    let removed: Vec<&&str> = {
        let mut r: Vec<_> = old.difference(&new).collect();
        r.sort();
        r
    };
    let render = |items: &[&&str]| {
        items.iter().map(|l| format!("  {l}")).collect::<Vec<_>>().join("\n")
    };
    assert!(
        added.is_empty(),
        "NEW taint finding(s) — a hash-preimage limb that is not provably \
         bounded to its atom's byte width:\n{}\n\
         Do NOT accept these into the baseline: either extend the taint \
         rules in minocrab-ir/src/v3/taint.rs with a cited in-circuit \
         warrant for the bounded source, or take the finding to dmd \
         (milestones.org M23 R3, notes/taint-lint.org).",
        render(&added),
    );
    assert!(
        removed.is_empty(),
        "taint finding(s) RESOLVED — the stream no longer fires here:\n{}\n\
         That is progress; accept it with \
         `MINOCRAB_TAINT_BASELINE=1 cargo test -p minocrab-contracts --test taint_lint`.",
        render(&removed),
    );
    // Same set, different order/rendering: the baseline is stale in shape.
    panic!(
        "taint baseline is out of date in ordering only; regenerate with \
         `MINOCRAB_TAINT_BASELINE=1 cargo test -p minocrab-contracts --test taint_lint`"
    );
}
