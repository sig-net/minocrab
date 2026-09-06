//! The MPC's Midnight publisher, pure core (M30).
//!
//! `sig-net/mpc` publishes an MPC signature to Midnight by building a
//! `respond` call, proving it, paying its DUST fee and submitting it. Today a
//! Node 22 sidecar (`midnight-publisher-ts`) does the first three, for one
//! stated reason — "the compiled contract's bindings and executor are
//! JavaScript" (`intent.ts`'s header). This crate is the claim that this is
//! no longer true, in a form mpc's `chain-midnight` can link.
//!
//! Rung A, which is what this crate holds so far:
//!
//! ```text
//!  (request id, signature)                        M30 A — call.rs
//!            │                       arguments as an AlignedValue,
//!            ▼                       the Impact program, the key location
//!      SignerCall  ──prototype(state, parameters, rand)──▶ ContractCallPrototype
//! ```
//!
//! # Pure
//!
//! Nothing here talks to a node. Every input a chain would supply is an
//! argument: the contract's state and the chain's `LedgerParameters` (see
//! [`call`]'s header for why the parameters are not a constant of this
//! crate).
//!
//! # Not here yet
//!
//! Intent, proving, signing and sealing (M30 B); the DUST wallet (M30 C);
//! and — for the mpc repo, not this one — submission, event ingestion, the
//! `IntentClient` swap-in and the four retry classes.

pub mod call;
pub mod error;
pub mod fab;

pub use call::{
    respond, respond_bidirectional, sign_bidirectional, ContractKeyLocation, Deployment,
    EcdsaSignature, Notification, SignerCall, SIGNER_CIRCUITS,
};
pub use error::PublishError;
