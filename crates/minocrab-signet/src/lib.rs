//! Sig Network's Signet protocol for MinoCrab circuits.
//!
//! A Midnight contract asks the Sig Network MPC to sign and execute an EVM
//! transaction in two transactions: a REQUEST circuit files a signing record
//! and notifies the signet signer; a SETTLE circuit, later, verifies the
//! MPC's attestation over the result and consumes the record. This crate is
//! that round trip, built on the typed EVM calls of [`minocrab_evm`].
//!
//! The wire vocabulary is V1, `@sig-net/midnight` 0.26.0-rc.15 ([`signet_v1`]):
//! a request notifies the signet signer, and the MPC posts the attestation a
//! settle verifies to the signet responder.
//!
//! - [`signet_v1`]: the V1 request record, request id, attestation digest
//!   and verification, as a mechanical port of `Signet.compact` at that pin;
//!   the output schemas ([`output_schema!`]).
//! - [`signet_flow`]: the block's [`signet_flow::Signet`] configuration, the
//!   record a request files and the attested output a settle verifies.
//! - [`evm_flow`]: the typed call as a ledger slot, [`evm_flow::Pending`],
//!   its tickets, and the [`evm_flow::Outbox`].
//! - [`filing`]: how a slot files a call ([`filing::Filing`],
//!   [`filing::Filed`]) and the transaction it builds (`build_tx*`, the fee
//!   [`filing::Envelope`]).
//! - [`common`]: the 32-byte protocol values (signing path, CAIP-2 id,
//!   secret key, commitments) as distinct types.
//! - [`record_v2`]: the stage-7 request record the pending vault's slots
//!   write, and the `fff3421c` layout it is written over.

pub mod common;
pub mod evm_flow;
pub mod filing;
pub mod record_v2;
pub mod signet_flow;
pub mod signet_v1;
