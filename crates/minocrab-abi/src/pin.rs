//! `pin.json` — the DISTILLED artifact an interface crate publishes.
//!
//! An interface crate commits the callee's `contract-info.json` (small,
//! reviewable, the typed schema) but NOT its `.zkir` files, which are
//! megabytes of instruction stream. `pin.json` is what survives the
//! distillation: the digests of both, the per-circuit facts the agreement
//! check needs (input count, `do_communications_commitment`, the constraint
//! prefix) and the compiler versions that produced them.
//!
//! It is a HASH PIN, not a fetch instruction. Nothing here downloads
//! anything: an offline `cargo test` checks the interface against the
//! committed `contract-info.json` and the distilled facts, and the full
//! `.zkir` check runs additionally when the artifact tree is at hand
//! (`MINOCRAB_ARTIFACT_DIR`, or [`Pin::source`] resolved against the
//! workspace root — in this workspace it always is).
//!
//! It is also REGENERABLE: [`Pin::distill`] builds one from an artifact
//! directory, and `signet-signer-interface`'s agreement test asserts the
//! committed file equals the distillation, so a re-pin is a diff rather
//! than a hand edit.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::info::ContractInfo;
use crate::zkir::ZkirFacts;

/// The distilled pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pin {
    /// Where the artifact came from, relative to the workspace root.
    /// PROVENANCE, and the fallback location of the `.zkir` tree; a
    /// published crate whose source is not in-tree simply finds nothing
    /// there and runs the offline half of the check.
    pub source: String,
    #[serde(rename = "compiler-version")]
    pub compiler_version: String,
    #[serde(rename = "language-version")]
    pub language_version: String,
    #[serde(rename = "runtime-version")]
    pub runtime_version: String,
    /// SHA-256 of the committed `contract-info.json`, byte for byte.
    #[serde(rename = "contract-info-sha256")]
    pub contract_info_sha256: String,
    /// One entry per circuit that has a compiled `.zkir`, by name.
    pub circuits: BTreeMap<String, PinnedCircuit>,
}

/// The distilled facts of one circuit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedCircuit {
    /// `proof: true` in `contract-info.json`.
    pub proof: bool,
    /// SHA-256 of the `.zkir` file.
    #[serde(rename = "zkir-sha256")]
    pub zkir_sha256: String,
    /// Declared native slots.
    pub inputs: usize,
    #[serde(rename = "do-communications-commitment")]
    pub do_communications_commitment: bool,
    /// The opening constraint run, [`crate::zkir::constraint_key`]-encoded
    /// in slot order. Unconstrained slots emit nothing and so appear on
    /// neither side.
    pub constraints: Vec<String>,
}

impl Pin {
    /// Parse `pin.json`.
    pub fn parse(text: &str) -> Result<Pin, serde_json::Error> {
        serde_json::from_str(text)
    }

    /// The committed on-disk form: pretty JSON with a trailing newline, so
    /// a re-pin is a readable diff.
    pub fn to_json(&self) -> String {
        let mut text = serde_json::to_string_pretty(self).expect("pin serializes");
        text.push('\n');
        text
    }

    /// Distil a pin from a compactc artifact directory (the one holding
    /// `compiler/contract-info.json` and `zkir/`).
    pub fn distill(artifact_dir: &Path, source: &str) -> Result<Pin, crate::Error> {
        let info_path = artifact_dir.join("compiler/contract-info.json");
        let info_text = read(&info_path)?;
        let info = ContractInfo::parse(&info_text)
            .map_err(|source| crate::Error::Parse { path: display(&info_path), source })?;

        let mut circuits = BTreeMap::new();
        for circuit in &info.circuits {
            let zkir_path = artifact_dir.join("zkir").join(format!("{}.zkir", circuit.name));
            if !zkir_path.exists() {
                continue;
            }
            let facts = ZkirFacts::read(&zkir_path).map_err(crate::Error::Zkir)?;
            circuits.insert(
                circuit.name.clone(),
                PinnedCircuit {
                    proof: circuit.proof,
                    zkir_sha256: sha256(std::fs::read(&zkir_path).map_err(|source| {
                        crate::Error::Io { path: display(&zkir_path), source }
                    })?),
                    inputs: facts.inputs.len(),
                    do_communications_commitment: facts.do_communications_commitment,
                    constraints: facts.prefix.into_iter().map(|c| c.key).collect(),
                },
            );
        }

        Ok(Pin {
            source: source.to_string(),
            compiler_version: info.compiler_version.clone(),
            language_version: info.language_version.clone(),
            runtime_version: info.runtime_version.clone(),
            contract_info_sha256: sha256(info_text.into_bytes()),
            circuits,
        })
    }
}

/// Lowercase hex SHA-256.
pub fn sha256(bytes: impl AsRef<[u8]>) -> String {
    let digest = Sha256::digest(bytes.as_ref());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn read(path: &Path) -> Result<String, crate::Error> {
    std::fs::read_to_string(path).map_err(|source| crate::Error::Io { path: display(path), source })
}

fn display(path: &Path) -> String {
    path.display().to_string()
}
