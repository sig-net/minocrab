//! The `erc20_vault_pending` verification harness (the spec-harness
//! extension): the same shape as `tests/vault` — a reference model, an
//! executor and a spec — retargeted at the `Pending`-based lineage's
//! seventeen circuits.
//!
//! `prims` and `tamper` are the compat lineage's, unchanged: the FAB
//! encodings, hash constructions and signature helpers they hold are
//! protocol-level (Poseidon commitments, ECDSA, coin commitments), not
//! specific to the 21-field block, so they are declared here by path
//! rather than copied. `ops` sets the block's field count (21, where the
//! flush vault's is 35) over the builders all the harnesses share,
//! `tests/support/ledger_ops.rs`.
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
