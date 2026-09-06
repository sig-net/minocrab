//! The managed key directory, and the disk [`Resolver`] over it.
//!
//! This is the layout `sig-net/mpc`'s sidecar reads out of
//! `@sig-net/midnight-contract` and `crates/signet-artifacts` writes (M29 A):
//!
//! ```text
//! <root>/keys/<circuit>.prover     the proving key
//! <root>/keys/<circuit>.verifier   the verifier key (COMMITTED in this repo)
//! <root>/zkir/<circuit>.bzkir      the binary IR the prover interprets
//! <root>/expectedVk.json           circuit -> hashVerifierKey (COMMITTED)
//! ```
//!
//! # Where a [`Deployment`]'s table comes from (M30 C2)
//!
//! [`ManagedDir::deployment`] builds the table from the package's OWN
//! `expectedVk.json` — the same file the sidecar's build/prove gate reads —
//! and CHECKS every entry it uses against the hash of the `.verifier` file
//! this directory actually carries, failing loudly and by name if they
//! disagree. Deriving the table from the `.verifier` files directly, the way
//! an earlier version of this function did, cannot catch this: a directory
//! can only ever agree with itself. The JSON and the keys are two artifacts
//! `signet-artifacts::generate` writes from the SAME bytes in the SAME run,
//! but nothing stops one of them from going stale independently afterward
//! (a hand-edited JSON, a key regenerated without re-running the pipeline,
//! a stale file surviving a partial copy) — this is the check that notices.
//!
//! `midnight_ledger::test_utilities::test_resolver`'s external resolver reads
//! exactly these three files under exactly these two subdirectories; this is
//! that closure, given a name and an error type, so a publisher does not need
//! the ledger's `test-utilities` feature to resolve its own keys.
//!
//! # Two spellings of a key location
//!
//! `resolve_key` accepts either the BARE circuit id (what
//! [`crate::call::call_prototype`] writes into a prototype, and what the files
//! are named) or a full encoded [`ContractKeyLocation`]
//! (`contract:<address>/<circuit>?vk=<hash>`, what compact-js's proof-server
//! client sends). Accepting both is what lets this resolver stand in for the
//! sidecar's without re-spelling every preimage.

use std::path::{Path, PathBuf};

use midnight_coin_structure::contract::ContractAddress;
use midnight_transient_crypto::proofs::{
    KeyLocation, ProvingKeyMaterial, Resolver, VerifierKey,
};

use crate::call::{ContractKeyLocation, Deployment};
use crate::error::PublishError;

/// A managed artifact directory on disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedDir {
    root: PathBuf,
}

impl ManagedDir {
    pub fn new(root: impl Into<PathBuf>) -> ManagedDir {
        ManagedDir { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `<root>/keys/<circuit>.prover`.
    pub fn prover_key_path(&self, circuit: &str) -> PathBuf {
        self.root.join("keys").join(format!("{circuit}.prover"))
    }

    /// `<root>/keys/<circuit>.verifier`.
    pub fn verifier_key_path(&self, circuit: &str) -> PathBuf {
        self.root.join("keys").join(format!("{circuit}.verifier"))
    }

    /// `<root>/zkir/<circuit>.bzkir`.
    pub fn ir_path(&self, circuit: &str) -> PathBuf {
        self.root.join("zkir").join(format!("{circuit}.bzkir"))
    }

    /// `<root>/expectedVk.json` — the package's own copy of the hash table,
    /// written by `signet-artifacts::generate` and read by the sidecar's
    /// build/prove gate.
    pub fn expected_vk_path(&self) -> PathBuf {
        self.root.join("expectedVk.json")
    }

    /// `expectedVk.json`, parsed: circuit -> 64-hex `hashVerifierKey`.
    fn expected_vk_table(
        &self,
    ) -> Result<std::collections::BTreeMap<String, String>, PublishError> {
        let path = self.expected_vk_path();
        let text = std::fs::read_to_string(&path)
            .map_err(|e| PublishError::Io { path: path.display().to_string(), source: e })?;
        serde_json::from_str(&text).map_err(|e| PublishError::Decode {
            path: path.display().to_string(),
            what: "expectedVk.json",
            message: e.to_string(),
        })
    }

    /// The verifier key's raw bytes — what `hashVerifierKey` hashes, before
    /// any deserialization.
    pub fn verifier_key_bytes(&self, circuit: &str) -> Result<Vec<u8>, PublishError> {
        let path = self.verifier_key_path(circuit);
        std::fs::read(&path)
            .map_err(|e| PublishError::Io { path: path.display().to_string(), source: e })
    }

    pub fn verifier_key(&self, circuit: &str) -> Result<VerifierKey, PublishError> {
        let path = self.verifier_key_path(circuit);
        let bytes = self.verifier_key_bytes(circuit)?;
        midnight_serialize::tagged_deserialize(&mut &bytes[..]).map_err(|e| PublishError::Decode {
            path: path.display().to_string(),
            what: "VerifierKey",
            message: e.to_string(),
        })
    }

    /// `hashVerifierKey(<circuit>.verifier)` — sha256 of the raw file bytes as
    /// lowercase hex, via `signet_protocol::hash_verifier_key`, which M29 B
    /// pinned against compact-js's own function under node.
    pub fn verifier_key_hash(&self, circuit: &str) -> Result<String, PublishError> {
        Ok(signet_protocol::hash_verifier_key(&self.verifier_key_bytes(circuit)?))
    }

    /// The [`Deployment`] a contract at `address` would have if it carried
    /// THESE verifier keys — the `expectedVk` table, taken from the
    /// package's OWN `expectedVk.json` and CHECKED against the `.verifier`
    /// files this directory carries, per circuit requested.
    ///
    /// A circuit `expectedVk.json` does not name is
    /// [`PublishError::UnknownCircuit`] (same as a `Deployment` built any
    /// other way asking for a circuit not in its table); a circuit the JSON
    /// and the key file DISAGREE on is
    /// [`PublishError::ExpectedVkOutOfSync`], naming the circuit, the path
    /// and both hashes — the mismatch this rung exists to catch (M30 C2,
    /// notes/mpc-publisher.org §11).
    pub fn deployment(
        &self,
        address: ContractAddress,
        circuits: &[&str],
    ) -> Result<Deployment, PublishError> {
        let shipped = self.expected_vk_table()?;
        let mut table = std::collections::BTreeMap::new();
        for circuit in circuits {
            let json_hash = shipped
                .get(*circuit)
                .ok_or_else(|| PublishError::UnknownCircuit((*circuit).to_string()))?
                .clone();
            let file_hash = self.verifier_key_hash(circuit)?;
            if file_hash != json_hash {
                return Err(PublishError::ExpectedVkOutOfSync {
                    circuit: (*circuit).to_string(),
                    json_path: self.expected_vk_path().display().to_string(),
                    json_hash,
                    file_hash,
                });
            }
            table.insert((*circuit).to_string(), json_hash);
        }
        Ok(Deployment { address, expected_vk: table })
    }

    /// All three files for one circuit, or `None` if any of them is missing.
    ///
    /// ALL OR NOTHING is the point: this repo commits the `.verifier` but not
    /// the `.prover` or the `.bzkir` (M29 A — they regenerate deterministically
    /// and the prover key is 56 MB), so a directory with only the verifier key
    /// must read as "cannot prove this circuit", not as a half-resolved key
    /// that fails somewhere deeper.
    pub fn key_material(&self, circuit: &str) -> std::io::Result<Option<ProvingKeyMaterial>> {
        fn read(path: PathBuf) -> std::io::Result<Option<Vec<u8>>> {
            match std::fs::read(&path) {
                Ok(bytes) => Ok(Some(bytes)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        }
        let (Some(prover_key), Some(verifier_key), Some(ir_source)) = (
            read(self.prover_key_path(circuit))?,
            read(self.verifier_key_path(circuit))?,
            read(self.ir_path(circuit))?,
        ) else {
            return Ok(None);
        };
        Ok(Some(ProvingKeyMaterial { prover_key, verifier_key, ir_source }))
    }

    /// The circuit a `KeyLocation` names: the bare circuit id, or the
    /// `circuitId` of an encoded [`ContractKeyLocation`].
    pub fn circuit_of(location: &KeyLocation) -> String {
        let raw = location.0.as_ref();
        match ContractKeyLocation::parse(raw) {
            Ok(parsed) => parsed.circuit_id,
            Err(_) => raw.to_string(),
        }
    }
}

impl Resolver for ManagedDir {
    async fn resolve_key(&self, key: KeyLocation) -> std::io::Result<Option<ProvingKeyMaterial>> {
        // Blocking reads inside an async fn, exactly as the ledger's own
        // `test_resolver` does it: these are three local files read once per
        // proof, next to a proving call that runs for a tenth of a second.
        self.key_material(&ManagedDir::circuit_of(&key))
    }
}
