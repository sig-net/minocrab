//! The `erc20_vault_pending` verification harness (M35 rung C's spec-harness
//! extension): the same shape as `tests/vault` — a reference model, an
//! executor and a spec — retargeted at the `Pending`-based lineage's
//! seventeen circuits.
//!
//! `prims` and `tamper` are the COMPAT lineage's, unchanged: the FAB
//! encodings, hash constructions and signature helpers they hold are
//! protocol-level (Poseidon commitments, ECDSA, coin commitments), not
//! specific to the 21-field block, so they are declared here by path
//! rather than copied. `ops` IS copied (`tests/vault_pending/ops.rs`)
//! because its one field-count constant differs (22, not 21); every
//! builder in it is otherwise identical, byte for byte.
#![allow(dead_code)]

#[path = "../vault/prims.rs"]
pub mod prims;
#[path = "../vault/tamper.rs"]
pub mod tamper;

pub mod exec;
pub mod gen;
pub mod model;
pub mod ops;
pub mod spec;
