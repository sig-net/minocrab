//! The sig-net corpus contracts, rewritten in the MinoCrab eDSL.
//!
//! Milestone 4: each contract here is a mechanical rewrite of its Compact
//! original (corpus/src/signet-*), and each circuit carries a differential
//! test against compactc's compiled artifact — call-compatibility per
//! notes/ledger-abi.org §6 (same typed I/O schema, same pis/pi_skips on a
//! shared preimage).

pub mod adts;
pub mod attest;
pub mod bounded;
pub mod bounded_ledger;
pub mod coins;
pub mod common;
/// Per-recipient disclosure (notes/disclosure-model.org) — the one module here
/// with no Compact original to be a rewrite OF. An exploration, not corpus.
pub mod disclosure;
pub mod erc20_vault;
pub mod erc20_vault_pending;
pub mod evm;
pub mod events;
pub mod events_borsh;
pub mod hashing;
pub mod interfaces;
pub mod kernel_tokens;
pub mod manager;
pub mod mint_tokens;
pub mod nested;
pub mod opaque;
pub mod serde_builtin;
pub mod signet;
pub mod signet_contract;
/// FROZEN 0.24.1 record and attestation for the `375071b` vault port only.
#[doc(hidden)]
pub mod signet_v1_0241;
pub mod test_caller;
pub mod treasury;
pub mod xcall;
pub mod xcall_with_payment;
pub mod xcontract_events;
pub mod xcontract_events_borsh;

// The Signet library, at the paths it had when it lived here.
pub use minocrab_signet::{evm_flow, output_schema, signet_flow, signet_v1};
