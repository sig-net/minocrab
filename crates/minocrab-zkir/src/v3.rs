//! ZKIR v3 bindings — same shape as the v2 module in `lib.rs`, over the
//! typed IR (`midnight-zkir-v3`, pinned to the same midnight-ledger tag as
//! the bundled `zkir-v3` binary). The sig-net contracts (and anything built
//! with `--feature-zkir-v3`) emit this format.

use std::io::{Read, Write};
use std::path::Path;

pub use midnight_zkir_v3::{Identifier, Instruction, IrSource, Preprocessed};

use crate::Error;

/// The ZKIR major version this module speaks.
pub const ZKIR_MAJOR_VERSION: u8 = 3;

/// Parse a v3 `.zkir` file.
pub fn read_zkir(path: impl AsRef<Path>) -> Result<IrSource, Error> {
    let path = path.as_ref();
    let file = std::fs::File::open(path).map_err(|source| Error::Io {
        path: path.display().to_string(),
        source,
    })?;
    parse_zkir(std::io::BufReader::new(file), &path.display().to_string())
}

/// Parse v3 `.zkir` JSON from any reader; `name` is used in error messages.
pub fn parse_zkir(reader: impl Read, name: &str) -> Result<IrSource, Error> {
    IrSource::load(reader).map_err(|source| Error::Io {
        path: name.to_string(),
        source,
    })
}

/// Serialize a v3 [`IrSource`] to `.zkir` JSON in compactc's on-disk form.
pub fn write_zkir(ir: &IrSource, writer: impl Write, name: &str) -> Result<(), Error> {
    let value = to_disk_form(ir, name)?;
    serde_json::to_writer(writer, &value).map_err(|source| Error::Json {
        path: name.to_string(),
        source,
    })
}

/// Serialize a v3 [`IrSource`] to a `.zkir` JSON string in compactc's on-disk form.
pub fn to_zkir_string(ir: &IrSource) -> Result<String, Error> {
    let value = to_disk_form(ir, "<string>")?;
    serde_json::to_string(&value).map_err(|source| Error::Json {
        path: "<string>".to_string(),
        source,
    })
}

/// Inverse of `IrSource::load`'s version rewrite (see the v2 twin in lib.rs).
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
