//! M29 rung B: pin `signet_artifacts::hash_verifier_key` to
//! `@midnight-ntwrk/compact-js`'s `hashVerifierKey`
//! (`ContractKeyLocation.js`: `createHash('sha256').update(bytes).digest
//! ('hex')`, read directly — see notes/mpc-publisher.org §8).
//!
//! NO fixture pair (a `.verifier` file plus its published hash) was found
//! anywhere reachable: `@sig-net/midnight-contract` (the package that
//! carries `expectedVk`) is not vendored in `~/mpc` — nothing there has
//! `node_modules` installed — and the signet contract is not deployed yet,
//! so no `expectedVk` table with real values exists. So the pin is made
//! real the other way the milestone allows: actually RUN the TypeScript
//! implementation, via node, on one of our own committed `.verifier` files,
//! and assert the Rust function agrees.
//!
//! Skips loudly (not a hard failure) if `node` is not on `PATH` or the
//! compact-js checkout is not where `$MIDNIGHT_EXAMPLES_NODE_MODULES` (or
//! its default, `~/midnight-examples/node_modules`) says — both ARE present
//! in this workspace's environment, so the ordinary run exercises the real
//! TypeScript source, not a re-implementation of it.

use std::path::{Path, PathBuf};
use std::process::Command;

/// `$MIDNIGHT_EXAMPLES_NODE_MODULES`, else `~/midnight-examples/node_modules`
/// — a checkout of sig-net's examples with `@midnight-ntwrk/compact-js`
/// installed as a real dependency (not part of this repo).
fn node_modules_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("MIDNIGHT_EXAMPLES_NODE_MODULES") {
        return Some(PathBuf::from(dir));
    }
    let home = std::env::var_os("HOME")?;
    Some(Path::new(&home).join("midnight-examples/node_modules"))
}

#[test]
fn hash_verifier_key_matches_compact_js_source() {
    let Some(node_modules) = node_modules_dir() else {
        eprintln!("skipping: no $HOME and $MIDNIGHT_EXAMPLES_NODE_MODULES not set");
        return;
    };
    let contract_key_location = node_modules
        .join("@midnight-ntwrk/compact-js/dist/cjs/ContractKeyLocation.js");
    if !contract_key_location.is_file() {
        eprintln!(
            "skipping: no {} (set $MIDNIGHT_EXAMPLES_NODE_MODULES to a checkout with \
             @midnight-ntwrk/compact-js installed)",
            contract_key_location.display()
        );
        return;
    }
    let node = std::env::var("NODE").unwrap_or_else(|_| "node".to_string());
    if Command::new(&node).arg("--version").output().is_err() {
        eprintln!("skipping: `{node}` not on PATH ($NODE overrides)");
        return;
    }

    // The verifier key: our own committed artifact, real key bytes (not a
    // synthetic string) — the same file `expectedVk.json` was hashed from.
    let verifier_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("managed/keys/respond.verifier");
    let bytes = std::fs::read(&verifier_path)
        .unwrap_or_else(|e| panic!("{} is not readable: {e}", verifier_path.display()));

    let script = format!(
        "const {{ hashVerifierKey }} = require({module:?});\n\
         const fs = require('fs');\n\
         process.stdout.write(hashVerifierKey(fs.readFileSync({file:?})));\n",
        module = contract_key_location.display().to_string(),
        file = verifier_path.display().to_string(),
    );
    let output = Command::new(&node)
        .arg("-e")
        .arg(&script)
        .output()
        .unwrap_or_else(|e| panic!("running `{node} -e ...`: {e}"));
    assert!(
        output.status.success(),
        "node exited {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let ts_hash = String::from_utf8(output.stdout).expect("hashVerifierKey prints hex");

    let rust_hash = signet_artifacts::hash_verifier_key(&bytes);
    assert_eq!(
        rust_hash, ts_hash,
        "signet_artifacts::hash_verifier_key disagrees with compact-js's hashVerifierKey \
         on {}",
        verifier_path.display()
    );

    // The committed expectedVk.json is this same function on this same
    // file — check it does not silently drift from either oracle.
    let vk_json_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("managed/expectedVk.json");
    let vk_json = std::fs::read_to_string(&vk_json_path)
        .unwrap_or_else(|e| panic!("{} is not readable: {e}", vk_json_path.display()));
    let vk: serde_json::Value = serde_json::from_str(&vk_json).expect("expectedVk.json parses");
    assert_eq!(
        vk["respond"].as_str(),
        Some(rust_hash.as_str()),
        "managed/expectedVk.json's \"respond\" entry does not match hash_verifier_key of \
         managed/keys/respond.verifier"
    );
}
