//! M1 exit criterion: round-trip every compactc-compiled `.zkir` in the
//! corpus — parse, re-emit, re-parse, assert equality. Skips when the corpus
//! hasn't been compiled yet (corpus/compile.sh).

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
            match minocrab_zkir::read_any(path).map_err(|e| format!("parse: {e}"))? {
                minocrab_zkir::AnyIr::V2(ir) => {
                    let emitted =
                        minocrab_zkir::to_zkir_string(&ir).map_err(|e| format!("emit: {e}"))?;
                    let reparsed = minocrab_zkir::parse_zkir(emitted.as_bytes(), &name)
                        .map_err(|e| format!("reparse: {e}"))?;
                    if reparsed != ir {
                        return Err("re-emitted v2 IR differs from original".into());
                    }
                    Ok(false)
                }
                minocrab_zkir::AnyIr::V3(ir) => {
                    let emitted = minocrab_zkir::v3::to_zkir_string(&ir)
                        .map_err(|e| format!("emit: {e}"))?;
                    let reparsed = minocrab_zkir::v3::parse_zkir(emitted.as_bytes(), &name)
                        .map_err(|e| format!("reparse: {e}"))?;
                    if reparsed != ir {
                        return Err("re-emitted v3 IR differs from original".into());
                    }
                    Ok(true)
                }
            }
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
        "round-tripped {} corpus .zkir files ({} v2, {} v3)",
        files.len(),
        files.len() - v3_count,
        v3_count
    );
}
