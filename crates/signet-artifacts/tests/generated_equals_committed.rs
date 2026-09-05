//! M29 rung A's generated-equals-committed gate, the `spec/ts` pattern:
//! regenerate the whole managed directory into a temp dir and assert the
//! COMMITTED `.zkir`/`.verifier` files and `MANIFEST.sha256`/
//! `expectedVk.json` are byte-identical to a fresh run. Drift in the
//! uncommitted `.prover`/`.bzkir` files shows up as a manifest mismatch
//! (their hashes are IN the manifest even though the files are not
//! committed — that is the whole point of the manifest).
//!
//! Skips loudly, like `corpus_roundtrip`, if `zkir-v3` is not on `PATH`
//! (`$ZKIR_V3` overrides) — but it IS present in this workspace's devshell,
//! so the ordinary run exercises the real binary, not a mock.

use std::path::Path;

fn managed_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("managed")
}

/// Read a committed file, or panic with its path (there is nothing sensible
/// to skip to — the committed side of this gate is checked into git).
fn read_committed(rel: &str) -> Vec<u8> {
    let path = managed_dir().join(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{} (committed) is not readable: {e}", path.display()))
}

#[test]
fn generated_equals_committed() {
    let Some(zkir_v3) = signet_artifacts::zkir_v3_available() else {
        eprintln!(
            "skipping: `zkir-v3` not on PATH and $ZKIR_V3 not set (enter the nix devshell)"
        );
        return;
    };

    let out_dir = std::env::temp_dir().join(format!(
        "signet-artifacts-regen-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time moves forward")
            .as_nanos()
    ));
    let start = std::time::Instant::now();
    signet_artifacts::generate(&out_dir, &zkir_v3)
        .unwrap_or_else(|e| panic!("regenerating into {}: {e}", out_dir.display()));
    let elapsed = start.elapsed();
    println!("regenerated the managed dir (keygen for 3 circuits) in {elapsed:.2?}");

    let circuits = signet_artifacts::circuits();
    let mut mismatches = Vec::new();

    // The two committed kinds: `.zkir` and `.verifier`, byte-identical.
    for (name, _) in &circuits {
        for (dir, ext) in [("zkir", "zkir"), ("keys", "verifier")] {
            let rel = format!("{dir}/{name}.{ext}");
            let committed = read_committed(&rel);
            let fresh = std::fs::read(out_dir.join(&rel))
                .unwrap_or_else(|e| panic!("{}: fresh copy not readable: {e}", rel));
            if committed != fresh {
                mismatches.push(rel);
            }
        }
    }

    // The manifest and the expectedVk table: both fully regenerated, so
    // they must match byte for byte too (the manifest additionally pins the
    // NON-committed `.prover`/`.bzkir` hashes — any drift in keygen's output
    // shows up here even though those files never enter git).
    for rel in ["MANIFEST.sha256", "expectedVk.json"] {
        let committed = read_committed(rel);
        let fresh = std::fs::read(out_dir.join(rel))
            .unwrap_or_else(|e| panic!("{rel}: fresh copy not readable: {e}"));
        if committed != fresh {
            mismatches.push(rel.to_string());
        }
    }

    std::fs::remove_dir_all(&out_dir).ok();

    assert!(
        mismatches.is_empty(),
        "regenerated artifacts differ from crates/signet-artifacts/managed/: {mismatches:?}\n\
         (run `cargo run -p signet-artifacts -- crates/signet-artifacts/managed` and review the diff)"
    );
}
