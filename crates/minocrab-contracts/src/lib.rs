//! The sig-net corpus contracts, rewritten in the MinoCrab eDSL.
//!
//! Milestone 4: each contract here is a mechanical rewrite of its Compact
//! original (corpus/src/signet-*), and each circuit carries a differential
//! test against compactc's compiled artifact — call-compatibility per
//! notes/ledger-abi.org §6 (same typed I/O schema, same pis/pi_skips on a
//! shared preimage).

pub mod attest;
pub mod common;
pub mod erc20_vault;
pub mod events;
pub mod hashing;
pub mod mint_tokens;
pub mod serde_builtin;
pub mod signet;
pub mod signet_contract;
pub mod test_caller;
pub mod xcall;
pub mod xcall_with_payment;
pub mod xcontract_events;
