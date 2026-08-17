//! L0 — ZKIR bindings.
//!
//! The ZKIR "spec" is Midnight's own `midnight-zkir` crate; we re-export its
//! types instead of redefining them, and add the file-level I/O MinoCrab
//! needs. Nothing above this layer touches serialization or the zkir
//! toolchain directly (see notes/architecture.org).
//!
//! On-disk `.zkir` JSON (compactc's output) wraps the version as
//! `{"major": 2, "minor": n}`; `IrSource`'s own serde form uses the flat
//! minor number. `IrSource::load` handles the inward rewrite; [`write_zkir`]
//! is its exact inverse (the crate has no JSON writer of its own — compactc
//! produces these files, `zkir` only consumes them).
//!
//! # Where this sits
//!
//! The bottom of the MinoCrab stack (repository README, "Layout"). `minocrab-ir`
//! builds typed instruction streams over the types re-exported here,
//! `minocrab` is the eDSL above that, and `minocrab-sim` executes the result;
//! `minocrab-abi` reads compactc's own `.zkir` through this crate to check an
//! interface against its artifact. This layer knows about files and JSON so
//! that no layer above it has to.
//!
//! # Start here
//!
//! - [`read_any`] / [`AnyIr`] — parse a `.zkir` of either major version
//! - [`read_zkir`] and [`write_zkir`] — the v2 pair, exact inverses
//! - [`v3::read_zkir`] and [`v3::write_zkir`] — the v3 pair (what the sig-net
//!   contracts and anything built with `--feature-zkir-v3` emit)
//! - [`IrSource`] — Midnight's own v2 IR type, re-exported not redefined
//! - [`Error`] — the one error type, always carrying the path it failed on

use std::io::{Read, Write};
use std::path::Path;

pub use midnight_transient_crypto::curve::Fr;
pub use midnight_zkir::{Instruction, IrSource, Preprocessed};

pub mod v3;

/// A parsed `.zkir` file of either major version.
#[derive(Debug, Clone, PartialEq)]
pub enum AnyIr {
    V2(IrSource),
    V3(midnight_zkir_v3::IrSource),
}

/// Parse a `.zkir` file of either major version, dispatching on its
/// `version.major` envelope field.
pub fn read_any(path: impl AsRef<std::path::Path>) -> Result<AnyIr, Error> {
    let path = path.as_ref();
    let name = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
        path: name.clone(),
        source,
    })?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|source| Error::Json {
            path: name.clone(),
            source,
        })?;
    match value["version"]["major"].as_u64() {
        Some(3) => Ok(AnyIr::V3(v3::parse_zkir(text.as_bytes(), &name)?)),
        _ => Ok(AnyIr::V2(parse_zkir(text.as_bytes(), &name)?)),
    }
}

/// The ZKIR major version this crate speaks. Bump alongside the pinned
/// toolchain (see flake.nix / notes/zkir.org).
pub const ZKIR_MAJOR_VERSION: u8 = 2;

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

/// Parse a `.zkir` file (compactc's JSON output for one circuit).
pub fn read_zkir(path: impl AsRef<Path>) -> Result<IrSource, Error> {
    let path = path.as_ref();
    let file = std::fs::File::open(path).map_err(|source| Error::Io {
        path: path.display().to_string(),
        source,
    })?;
    parse_zkir(std::io::BufReader::new(file), &path.display().to_string())
}

/// Parse `.zkir` JSON from any reader; `name` is used in error messages.
pub fn parse_zkir(reader: impl Read, name: &str) -> Result<IrSource, Error> {
    IrSource::load(reader).map_err(|source| Error::Io {
        path: name.to_string(),
        source,
    })
}

/// Serialize an [`IrSource`] to `.zkir` JSON in compactc's on-disk form.
pub fn write_zkir(ir: &IrSource, writer: impl Write, name: &str) -> Result<(), Error> {
    let value = to_disk_form(ir, name)?;
    serde_json::to_writer(writer, &value).map_err(|source| Error::Json {
        path: name.to_string(),
        source,
    })
}

/// Serialize an [`IrSource`] to a `.zkir` JSON string in compactc's on-disk form.
pub fn to_zkir_string(ir: &IrSource) -> Result<String, Error> {
    let value = to_disk_form(ir, "<string>")?;
    serde_json::to_string(&value).map_err(|source| Error::Json {
        path: "<string>".to_string(),
        source,
    })
}

/// Inverse of `IrSource::load`'s version rewrite: flat minor number →
/// `{"major": 2, "minor": n}` envelope.
fn to_disk_form(ir: &IrSource, name: &str) -> Result<serde_json::Value, Error> {
    let mut value = serde_json::to_value(ir).map_err(|source| Error::Json {
        path: name.to_string(),
        source,
    })?;
    let obj = value
        .as_object_mut()
        .expect("IrSource serializes to a JSON object");
    let minor = obj
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .expect("IrSource.version serializes to a number");
    obj.insert(
        "version".into(),
        serde_json::json!({ "major": ZKIR_MAJOR_VERSION, "minor": minor }),
    );
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_compactc_output() {
        let src = include_str!("../tests/fixtures/counter_increment.zkir");
        let ir = parse_zkir(src.as_bytes(), "counter_increment.zkir").unwrap();

        let emitted = to_zkir_string(&ir).unwrap();
        let reparsed = parse_zkir(emitted.as_bytes(), "re-emitted").unwrap();
        assert_eq!(ir, reparsed);

        // The version envelope must match compactc's on-disk form.
        let value: serde_json::Value = serde_json::from_str(&emitted).unwrap();
        assert_eq!(value["version"], serde_json::json!({"major": 2, "minor": 0}));
    }
}
