//! Shared test support. Not a test target (lives in a subdirectory).

use midnight_transient_crypto::proofs::ProofPreimage;

/// Dump a differential test's honest, corpus-verified preimage for the
/// benchmark harness (crates/minocrab-bench): no-op unless
/// `MINOCRAB_DUMP_PREIMAGES=<dir>` is set. Both toolchains' artifacts are
/// PI-equal on these preimages, so the benchmark proves the SAME statement
/// under both.
pub fn dump_preimage(circuit: &str, pi: &ProofPreimage) {
    let Some(dir) = std::env::var_os("MINOCRAB_DUMP_PREIMAGES") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    std::fs::create_dir_all(&dir).expect("create preimage dump dir");
    let mut buf = Vec::new();
    midnight_serialize::tagged_serialize(pi, &mut buf).expect("preimage serializes");
    std::fs::write(dir.join(format!("{circuit}.preimage")), buf).expect("preimage writes");
}
