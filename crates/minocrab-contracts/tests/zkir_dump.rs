//! ZERO-MOVEMENT INSTRUMENT: dump every workspace circuit's serialized ZKIR,
//! one file per circuit, for byte-comparison across a change.
//!
//! The frozen snapshots are the standing gates — `row_snapshot` freezes
//! `(k, rows)` and `interface_snapshot` the ordered `(label, type)` of every
//! input/output/witness — but neither sees an instruction REORDER at equal row
//! count, and `row_snapshot` is blind to a removed `Copy` (M9 phase 7 learned
//! that the hard way, and its literals commit is the one item in
//! notes/review-queue.org whose gate was a hand-review). Several sessions have
//! therefore dumped all N circuits' ZKIR by hand and diffed; this is that
//! procedure, committed, so the next one does not reinvent it.
//!
//! IGNORED by default: it writes files, and it is an instrument rather than a
//! check. To compare a change against a baseline:
//!
//! ```text
//! MINOCRAB_ZKIR_DUMP=/tmp/after  cargo test -p minocrab-contracts \
//!     --test zkir_dump -- --ignored dump_every_circuits_zkir
//! git checkout <baseline>
//! MINOCRAB_ZKIR_DUMP=/tmp/before cargo test -p minocrab-contracts \
//!     --test zkir_dump -- --ignored dump_every_circuits_zkir
//! diff -rq /tmp/before /tmp/after      # only the intended circuits may differ
//! ```
//!
//! Files are named after the circuit with `::` as `__`, so a diff names the
//! circuit directly, and each holds `support::zkir_lines` — the same JSON
//! `to_zkir_string` produces, split one instruction per line, so `diff -u` on
//! a pair is legible and `diff -rq` is exactly as strong as before.
//!
//! A dump directory produced here is also what `row_snapshot` will read as
//! `MINOCRAB_ZKIR_BASELINE` when its own failure path prints an
//! instruction-level diff.

mod support;

/// Write `<circuit>.zkir` per circuit into `$MINOCRAB_ZKIR_DUMP`.
#[test]
#[ignore = "instrument: writes ZKIR dumps for cross-change byte comparison"]
fn dump_every_circuits_zkir() {
    let dir = std::env::var("MINOCRAB_ZKIR_DUMP")
        .expect("set MINOCRAB_ZKIR_DUMP=<dir> — see this file's docs");
    let dir = std::path::PathBuf::from(dir);
    let n = support::write_zkir_dump(&dir);
    println!("dumped {n} circuits to {}", dir.display());
}
