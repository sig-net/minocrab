//! The erc20-vault verification harness (M10 step 1).
//!
//! Layering, outermost first:
//!
//! - [`artifact`] — WHICH vault is under test: the compat ports, the M10
//!   optimized fork, the M11 Borsh fork or the M9 phase-8 showcase twin
//!   (`Art`), the nine circuits by name, and the three divergence ledgers
//!   saying what each forked circuit still inherits from the artifact it was
//!   forked from. The first two ledgers are about byte-identity; the twin's
//!   is about PI-equality, because the twin rewrites every circuit on
//!   purpose and byte-identity is not what it claims.
//! - [`spec`] — the symbolic effect algebra and the nine per-circuit total
//!   functions `spec_initialize` .. `spec_complete_swap`. Artifact-agnostic:
//!   it says WHICH commitment a circuit writes, never how that commitment is
//!   hashed.
//! - [`prims`] — the compat artifact's CONCRETIZATION: SHA-256/keccak/ECDSA
//!   realisations of the spec's terms, plus the FAB encodings.
//! - [`model`] — the reference model: a scenario per circuit that owns a
//!   pre-state and one call's arguments/witnesses, and emits the Impact op
//!   stream, popeq results and `ProofPreimage`.
//! - [`exec`] — the reference executor: the op stream run through the real
//!   Impact VM, so the model is checked against ledger semantics rather than
//!   against itself.
//! - [`gen`] — branch-aware generation strategies (see
//!   notes/vault-optimization.org §"Generation strategies").
//! - [`tamper`] — the perturbation sweeps, shared by the differential
//!   suite and the adversarial one.
//!
//! Not a test target (subdirectory of `tests/`); each binary that wants it
//! declares `mod vault;`. Deliberately NOT under `src/`: every layer here
//! needs midnight-onchain-vm / base-crypto / sha2 / sha3, which are
//! dev-dependencies — promoting them to real dependencies of a contracts
//! crate to host test infrastructure would be the wrong trade.
#![allow(dead_code)]

pub mod artifact;
pub mod exec;
pub mod gen;
pub mod model;
pub mod prims;
pub mod spec;
pub mod tamper;
