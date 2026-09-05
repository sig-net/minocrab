//! L0 — ZKIR bindings.
//!
//! The ZKIR "spec" is Midnight's own `midnight-zkir-v3` crate; we re-export
//! its types instead of redefining them, and add the file-level I/O MinoCrab
//! needs. Nothing above this layer touches serialization or the zkir
//! toolchain directly (see notes/architecture.org).
//!
//! On-disk `.zkir` JSON (compactc's output) wraps the version as
//! `{"major": 3, "minor": n}`; [`v3::read_zkir`] handles the inward rewrite
//! and [`v3::write_zkir`] is its exact inverse. The corpus also holds
//! compactc's ZKIR v2 artifacts, which nothing in this workspace targets;
//! [`major_version`] is how a corpus walk tells them apart before parsing.
//!
//! # Where this sits
//!
//! The bottom of the MinoCrab stack (repository README, "Layout").
//! `minocrab-ir` builds typed instruction streams over the types re-exported
//! here, `minocrab` is the eDSL above that, and `minocrab-sim` executes the
//! result; `minocrab-abi` reads compactc's own `.zkir` through this crate to
//! check an interface against its artifact. This layer knows about files
//! and JSON so that no layer above it has to.
//!
//! # Start here
//!
//! - [`v3::read_zkir`] and [`v3::write_zkir`] — the on-disk pair, exact
//!   inverses; [`v3::parse_zkir`] / [`v3::to_zkir_string`] the in-memory pair
//! - [`v3::IrSource`] — Midnight's own IR type, re-exported not redefined
//! - [`major_version`] — which ZKIR a `.zkir` file is, without parsing it
//! - [`Error`] — the one error type, always carrying the path it failed on

use std::path::Path;

pub use midnight_transient_crypto::curve::Fr;

pub mod v3;

/// The one error type: what failed, and on which path.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("serializing {path}: {source}")]
    Json {
        path: String,
        source: serde_json::Error,
    },
}

/// The `version.major` of a `.zkir` file, read without parsing the
/// instructions — `3` for everything this workspace targets, `2` for the
/// compactc artifacts the corpus keeps for the record.
pub fn major_version(path: impl AsRef<Path>) -> Result<u64, Error> {
    let path = path.as_ref();
    let name = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
        path: name.clone(),
        source,
    })?;
    let value: serde_json::Value = serde_json::from_str(&text).map_err(|source| Error::Json {
        path: name.clone(),
        source,
    })?;
    Ok(value["version"]["major"].as_u64().unwrap_or(2))
}
