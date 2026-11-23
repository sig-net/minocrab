//! The serialization-format conformance harness
//! (notes/borsh-format.org).
//!
//! Layering, outermost first:
//!
//! - [`spec_types`] — the declarations: plain Rust structs for the payloads
//!   the deployed protocol already puts on the wire, deriving borsh's traits
//!   and serde's.
//! - [`oracle`] — the two independent encoders (borsh, serde+bincode-fixint)
//!   and the Borsh-schema walk that turns a spec type into `(path, kind,
//!   offset, width)` rows.
//! - [`deployed`] — the deployed bytes, built with the protocol's own code:
//!   FAB `binary_repr` for the hash preimages, the `Misc` envelope for the
//!   signet signer's logs, and the proof preimage that lets the corpus artifact
//!   be asked whether it accepts them.
//! - [`records`] — the bridge from the reference model's scenarios to the
//!   spec types.
//! - [`spec_doc`] — the published artifact: `spec/borsh-subset.md`'s
//!   offset tables and `spec/vectors/*.json`, generated from the same schema
//!   walk, so the document a TS or MPC implementer reads cannot drift from
//!   the format the suite checks.
//! - [`ts_codegen`] — the published decoder: `spec/ts/`, the
//!   dependency-free TypeScript reader/writer for those same types, generated
//!   from the same walk so the code cannot drift from the document either.
//!
//! Not a test target (subdirectory of `tests/`). Requires `mod vault;` in
//! the same binary: the deployed side reuses the vault reference model and
//! generation strategies rather than growing a second one.
#![allow(dead_code)]

pub mod deployed;
pub mod oracle;
pub mod records;
pub mod spec_doc;
pub mod spec_types;
pub mod ts_codegen;
