//! The serialization-format conformance harness (M11 stage 0,
//! notes/borsh-format.org).
//!
//! Layering, outermost first:
//!
//! - [`spec_types`] — the DECLARATIONS: plain Rust structs for the payloads
//!   the deployed protocol already puts on the wire, deriving borsh's traits
//!   and serde's.
//! - [`oracle`] — the two independent encoders (borsh, serde+bincode-fixint)
//!   and the Borsh-schema walk that turns a spec type into `(path, kind,
//!   offset, width)` rows.
//! - [`deployed`] — the deployed bytes, built with the protocol's own code:
//!   FAB `binary_repr` for the hash preimages, the `Misc` envelope for the
//!   singleton's logs, and the proof preimage that lets the CORPUS ARTIFACT
//!   be asked whether it accepts them.
//! - [`records`] — the bridge from the reference model's scenarios to the
//!   spec types.
//!
//! Not a test target (subdirectory of `tests/`). Requires `mod vault;` in
//! the same binary: the deployed side reuses M10's reference model and
//! generation strategies rather than growing a second one.
#![allow(dead_code)]

pub mod deployed;
pub mod oracle;
pub mod records;
pub mod spec_types;
