//! M1 exit criterion: round-trip every compactc-compiled ZKIR v3 `.zkir` in
//! the corpus — parse, re-emit, re-parse, assert equality. The corpus's v2
//! artifacts are counted and skipped (nothing targets them). Skips when the
//! corpus hasn't been compiled yet (corpus/compile.sh).

use std::path::{Path, PathBuf};

fn collect_zkir(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_zkir(&path, out);
        } else if path.extension().is_some_and(|e| e == "zkir") {
            out.push(path);
        }
    }
}

#[test]
fn round_trips_entire_corpus() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/zkir");
    let mut files = Vec::new();
    collect_zkir(&corpus, &mut files);
    if files.is_empty() {
        eprintln!("skipping: no corpus at {} (run corpus/compile.sh)", corpus.display());
        return;
    }

    let mut failures = Vec::new();
    let mut v3_count = 0usize;
    for path in &files {
        let name = path.display().to_string();
        let result = (|| -> Result<bool, String> {
            // The corpus keeps compactc's ZKIR v2 artifacts for the record;
            // nothing here targets them, so they are counted and skipped.
            if minocrab_zkir::major_version(path).map_err(|e| format!("version: {e}"))? != 3 {
                return Ok(false);
            }
            let ir = minocrab_zkir::v3::read_zkir(path).map_err(|e| format!("parse: {e}"))?;
            let emitted = minocrab_zkir::v3::to_zkir_string(&ir).map_err(|e| format!("emit: {e}"))?;
            let reparsed = minocrab_zkir::v3::parse_zkir(emitted.as_bytes(), &name)
                .map_err(|e| format!("reparse: {e}"))?;
            if reparsed != ir {
                return Err("re-emitted v3 IR differs from original".into());
            }
            Ok(true)
        })();
        match result {
            Ok(true) => v3_count += 1,
            Ok(false) => {}
            Err(e) => failures.push(format!("{name}: {e}")),
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} corpus files failed round-trip:\n{}",
        failures.len(),
        files.len(),
        failures.join("\n"),
    );
    println!(
        "round-tripped {} v3 corpus .zkir files ({} v2 files skipped)",
        v3_count,
        files.len() - v3_count,
    );
    // THE COUNT IS ASSERTED. Without it this test is green on a partial or
    // empty checkout, which is silence, not evidence. The number moves only
    // when the corpus does (corpus/compile.sh after a source is added or the
    // compactc pin bumps — notes/version-bump.org); update it in the same
    // commit, with the source that moved it named.
    assert_eq!(
        (files.len(), v3_count),
        (814, 92),
        "corpus size moved: {} files ({} v3). If the corpus was deliberately \
         recompiled or extended, update this assertion in the same commit and say \
         which source moved it; otherwise the checkout is incomplete.",
        files.len(),
        v3_count
    );
}
