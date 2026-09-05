//! The managed artifact pipeline for the three Signet signer circuits
//! (M29 rungs A+B — notes/mpc-publisher.org §3, §8).
//!
//! `sig-net/mpc`'s TypeScript sidecar never interprets the IR: compactc's JS
//! executor makes the proof preimage and whatever sits at
//! `zkir/<circuit>.bzkir` proves it (mpc-publisher.org §3). So the whole
//! swap to MinoCrab's optimised artifact is a directory of files — no
//! sidecar change. This crate builds that directory:
//!
//! ```text
//! <out-dir>/zkir/<circuit>.zkir        - minocrab_zkir::v3::write_zkir's
//!                                         on-disk form, COMMITTED (small,
//!                                         reviewable)
//! <out-dir>/zkir/<circuit>.bzkir       - the pinned `zkir-v3` binary's
//!                                         binary IR, regenerates
//!                                         deterministically from the .zkir
//! <out-dir>/keys/<circuit>.prover      - ditto, regenerates
//! <out-dir>/keys/<circuit>.verifier    - ditto, COMMITTED (small)
//! <out-dir>/MANIFEST.sha256            - sha256 of every file above,
//!                                         including the two that are not
//!                                         committed, so drift is visible
//! <out-dir>/expectedVk.json            - circuit name -> hashVerifierKey
//!                                         (compact-js's sha256-hex over the
//!                                         raw .verifier bytes; §8 has the
//!                                         provenance), COMMITTED
//! ```
//!
//! Circuit names on disk are the Compact names compactc's own artifacts use
//! (`signBidirectional`, `respond`, `respondBidirectional`), NOT the Rust
//! function names — the sidecar looks them up by the Compact name
//! (`@sig-net/midnight-contract`'s `expectedVk` keys, `RESPOND_CIRCUITS`).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use minocrab::v3::Compiled3;
use sha2::{Digest, Sha256};

/// A signer circuit: its on-disk (Compact) name and how to build it.
pub type Circuit = (&'static str, fn() -> Compiled3);

/// The three Signet signer circuits, named the way compactc's artifacts and
/// the sidecar's `expectedVk`/`RESPOND_CIRCUITS` name them — see
/// `crates/minocrab-contracts/src/signet_contract.rs`.
pub fn circuits() -> Vec<Circuit> {
    use minocrab_contracts::signet_contract;
    vec![
        ("signBidirectional", signet_contract::sign_bidirectional as fn() -> Compiled3),
        ("respond", signet_contract::respond as fn() -> Compiled3),
        ("respondBidirectional", signet_contract::respond_bidirectional as fn() -> Compiled3),
    ]
}

/// Where the pinned `zkir-v3` binary is: `$ZKIR_V3` if set, else `zkir-v3`
/// on `PATH` (a bare name with no `/` makes `Command` search `PATH` itself,
/// so no separate `which`-style lookup is needed).
pub fn zkir_v3_binary() -> PathBuf {
    std::env::var_os("ZKIR_V3")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("zkir-v3"))
}

/// `zkir_v3_binary()`, but `None` if it cannot be run at all (not found) —
/// for a test that wants to skip loudly rather than fail when the binary
/// is not on `PATH`, the way `corpus_roundtrip` skips without a corpus.
pub fn zkir_v3_available() -> Option<PathBuf> {
    let bin = zkir_v3_binary();
    let ok = Command::new(&bin)
        .arg("--help")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    ok.then_some(bin)
}

/// sha256(bytes) as lowercase hex. Shared by [`hash_verifier_key`] and the
/// manifest, which are the same computation on different files.
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// EXACTLY `@midnight-ntwrk/compact-js`'s `hashVerifierKey`
/// (`ContractKeyLocation.js`: `createHash('sha256').update(bytes).digest
/// ('hex')`, read on the raw file bytes `prover.ts`'s `keyMaterial` reads
/// with `readFile` — no framing, no prefix). See notes/mpc-publisher.org §8
/// for the file/line and the pin.
pub fn hash_verifier_key(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

/// One line of `MANIFEST.sha256`: `<hex>  <path relative to out-dir>`, the
/// same shape `sha256sum` emits (two spaces, path last) so `sha256sum -c`
/// can check it directly.
fn manifest_line(out_dir: &Path, file: &Path) -> anyhow::Result<String> {
    let bytes = std::fs::read(file)
        .map_err(|e| anyhow::anyhow!("reading {} for the manifest: {e}", file.display()))?;
    let hash = sha256_hex(&bytes);
    let rel = file.strip_prefix(out_dir).unwrap_or(file);
    Ok(format!("{hash}  {}", rel.display()))
}

/// Every file the manifest covers, `zkir/` before `keys/`, circuits in
/// [`circuits`]'s order, `.zkir`/`.bzkir` before `.prover`/`.verifier` — a
/// fixed order so `MANIFEST.sha256` is stable across regenerations.
fn manifest_files(out_dir: &Path, names: &[&str]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for name in names {
        files.push(out_dir.join("zkir").join(format!("{name}.zkir")));
    }
    for name in names {
        files.push(out_dir.join("zkir").join(format!("{name}.bzkir")));
    }
    for name in names {
        files.push(out_dir.join("keys").join(format!("{name}.prover")));
    }
    for name in names {
        files.push(out_dir.join("keys").join(format!("{name}.verifier")));
    }
    files
}

/// The generated `expectedVk` table: circuit name -> [`hash_verifier_key`]
/// of its `.verifier` file, as compact JSON with a trailing newline (one
/// object, keys in [`circuits`]'s order — `serde_json`'s `Map` preserves
/// insertion order with the default feature set this workspace already
/// carries).
fn expected_vk_json(out_dir: &Path, names: &[&str]) -> anyhow::Result<String> {
    let mut map = serde_json::Map::new();
    for name in names {
        let verifier = out_dir.join("keys").join(format!("{name}.verifier"));
        let bytes = std::fs::read(&verifier)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", verifier.display()))?;
        map.insert(name.to_string(), serde_json::Value::String(hash_verifier_key(&bytes)));
    }
    let mut text = serde_json::to_string_pretty(&serde_json::Value::Object(map))?;
    text.push('\n');
    Ok(text)
}

/// Build the whole managed directory at `out_dir`: write each circuit's
/// `.zkir`, run `zkir-v3 compile-many` for the `.bzkir`/keys, then
/// `MANIFEST.sha256` and `expectedVk.json`.
///
/// Fails loudly (rather than silently skip) if `zkir-v3` cannot be run — the
/// caller (the binary, or the regeneration test) decides whether that is
/// fatal or a loud, logged skip.
pub fn generate(out_dir: &Path, zkir_v3: &Path) -> anyhow::Result<()> {
    let circuits = circuits();
    let names: Vec<&str> = circuits.iter().map(|(name, _)| *name).collect();
    let zkir_dir = out_dir.join("zkir");
    let key_dir = out_dir.join("keys");
    std::fs::create_dir_all(&zkir_dir)?;
    std::fs::create_dir_all(&key_dir)?;

    // 1. `.zkir`, compactc's on-disk JSON form, one per circuit.
    for (name, build) in &circuits {
        let compiled = build();
        let path = zkir_dir.join(format!("{name}.zkir"));
        let file = std::fs::File::create(&path)
            .map_err(|e| anyhow::anyhow!("creating {}: {e}", path.display()))?;
        minocrab_zkir::v3::write_zkir(&compiled.ir, std::io::BufWriter::new(file), name)
            .map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))?;
    }

    // 2. `zkir-v3 compile-many <zkir_dir> <key_dir>`: keygen for every
    // `.zkir`/`.bzkir` found in `zkir_dir`, AND (as a side effect of the
    // binary's own `maybe_bzkir`, which writes a `.bzkir` sibling the first
    // time it loads a bare `.zkir`) the `.bzkir` files land in `zkir_dir`
    // too. This is the exact invocation — see notes/mpc-publisher.org §8.
    let status = Command::new(zkir_v3)
        .arg("compile-many")
        .arg(&zkir_dir)
        .arg(&key_dir)
        .status()
        .map_err(|e| anyhow::anyhow!("running `{} compile-many`: {e}", zkir_v3.display()))?;
    if !status.success() {
        anyhow::bail!("`{} compile-many {} {}` exited {status}", zkir_v3.display(), zkir_dir.display(), key_dir.display());
    }

    // 3. The manifest: every generated file's sha256, committed and
    // uncommitted alike, so drift in either is visible.
    let files = manifest_files(out_dir, &names);
    let mut lines = Vec::with_capacity(files.len());
    for file in &files {
        lines.push(manifest_line(out_dir, file)?);
    }
    let mut manifest = lines.join("\n");
    manifest.push('\n');
    let manifest_path = out_dir.join("MANIFEST.sha256");
    std::fs::write(&manifest_path, manifest)
        .map_err(|e| anyhow::anyhow!("writing {}: {e}", manifest_path.display()))?;

    // 4. `expectedVk.json`: the sidecar's build/prove gate table.
    let vk_json = expected_vk_json(out_dir, &names)?;
    let vk_path = out_dir.join("expectedVk.json");
    let mut f = std::fs::File::create(&vk_path)
        .map_err(|e| anyhow::anyhow!("creating {}: {e}", vk_path.display()))?;
    f.write_all(vk_json.as_bytes())
        .map_err(|e| anyhow::anyhow!("writing {}: {e}", vk_path.display()))?;

    Ok(())
}
