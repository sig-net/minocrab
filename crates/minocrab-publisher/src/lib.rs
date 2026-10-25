//! The MPC's Midnight publisher, pure core (M30).
//!
//! `sig-net/mpc` publishes an MPC signature to Midnight by building a
//! `respond` call, proving it, paying its DUST fee and submitting it. mpc's
//! `chain-midnight` links this crate to build and prove the call in process,
//! where a Node 22 sidecar once did, because the compiled contract's bindings
//! and executor were JavaScript:
//!
//! ```text
//!  (request id, signature)                        M30 A — call.rs
//!            │                       arguments as an AlignedValue,
//!            ▼                       the Impact program, the key location
//!      SignerCall  ──prototype(state, parameters, rand)──▶ ContractCallPrototype
//!            │
//!            ▼                                            M30 B — intent.rs
//!      build ─▶ Intent (with TTL) ─▶ Transaction           prove.rs, keys.rs
//!            │                                             publish.rs
//!            ├─ prove   in process: no proof server, no child process, and
//!            │          no network once the KZG parameters are on disk
//!            ├─ balance THE DUST SEAM — [`dust::DustBalancer`]
//!            ├─ sign    Intent::sign
//!            └─ seal    PedersenRandomness ─▶ PureGeneratorPedersen
//! ```
//!
//! # Pure
//!
//! Nothing here talks to a node. Every input a chain would supply is an
//! argument, gathered in [`publish::ChainContext`]: the contract's state, the
//! chain's `LedgerParameters` (see [`call`]'s header for why that is not a
//! constant of this crate), its cost model, the network id, the segment and
//! the block time. The funding keys are [`publish::FundingKeys`] and the dust
//! state lives behind [`dust::DustBalancer`]. The only files read are the
//! managed key directory ([`keys::ManagedDir`]) and the KZG parameter cache
//! `MidnightDataProvider` expects under `$MIDNIGHT_PP` /
//! `$XDG_CACHE_HOME/midnight/zk-params` / `~/.cache/midnight/zk-params`. Ship
//! those in the image and a publish makes no network request at all.
//!
//! # Not here
//!
//! - The DUST wallet, which lives in `sig-net/mpc`'s `chain-midnight`. It
//!   does not go through [`dust::DustBalancer`]: mpc takes
//!   [`call::respond`] / [`call::respond_bidirectional`],
//!   `SignerCall::prototype`, [`intent::build_intent`] /
//!   [`intent::preimage_tx`] and [`InProcessProver`] from here, then pays
//!   with a separately proven (ZKIR v2) fee intent merged into the sealed
//!   respond. [`dust::NoDust`] is what this crate's tests run, and it leaves
//!   the transaction unbalanced — `well_formed` must have
//!   `enforce_balancing` off.
//! - Submission, event ingestion and the retry classes. Those are mpc's
//!   (its `doc/midnight-publisher.md`).

pub mod call;
pub mod dust;
pub mod error;
pub mod fab;
pub mod intent;
pub mod keys;
pub mod prove;
pub mod publish;

pub use call::{
    respond, respond_bidirectional, sign_bidirectional, Attestation, ContractKeyLocation,
    Deployment, EcdsaSignature, Notification, SignerCall, SIGNER_CIRCUITS,
};
pub use dust::{DustBalancer, NoDust};
pub use error::PublishError;
pub use intent::{PreimageIntent, PreimageTx, ProvenTx, SealedTx};
pub use keys::ManagedDir;
pub use prove::{params_provider, InProcessProver, SignerResolver};
pub use publish::{publish, ChainContext, FundingKeys};
