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
//! circuit directly.

mod support;

/// Write `<circuit>.zkir` per circuit into `$MINOCRAB_ZKIR_DUMP`.
#[test]
#[ignore = "instrument: writes ZKIR dumps for cross-change byte comparison"]
fn dump_every_circuits_zkir() {
    let dir = std::env::var("MINOCRAB_ZKIR_DUMP")
        .expect("set MINOCRAB_ZKIR_DUMP=<dir> — see this file's docs");
    std::fs::create_dir_all(&dir).expect("the dump directory is creatable");

    let circuits = support::circuits();
    for (name, build) in &circuits {
        let text = minocrab_zkir::v3::to_zkir_string(&build().ir).expect("serializes");
        let path = format!("{dir}/{}.zkir", name.replace("::", "__"));
        std::fs::write(&path, text).unwrap_or_else(|e| panic!("writing {path}: {e}"));
    }
    println!("dumped {} circuits to {dir}", circuits.len());
}
