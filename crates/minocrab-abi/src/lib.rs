//! ARTIFACT AGREEMENT: an interface crate, checked against the callee's
//! compiled artifact.
//!
//! This is what a package manager for contract interfaces can do that
//! NEAR's `ext_contract` cannot. An `#[interface]` trait is a claim about
//! somebody else's deployed contract, and compactc publishes enough to
//! settle the claim: `contract-info.json` carries every circuit's fully
//! typed signature, and the `.zkir` carries the constraint run the prover
//! will actually execute. So drift between an interface crate and the
//! contract it describes is a TEST FAILURE in the interface crate's own
//! suite, not a runtime surprise at a call site.
//!
//! ```ignore
//! // signet-signer-interface/tests/artifact_agreement.rs
//! let artifact = Artifact::open(env!("CARGO_MANIFEST_DIR")).unwrap();
//! artifact.verify_pin().unwrap();
//! artifact.assert_interface_matches::<
//!     (RequestId<Public>, SignBidirectionalEventNotification<Public>), ()>(
//!     SignetSigner::SIGN_BIDIRECTIONAL,
//! );
//! ```
//!
//! The types named there are the ones the `#[interface]` trait declares and
//! the ones a caller passes, so nothing is written down twice: agreement
//! about the artifact IS agreement about every call site.
//!
//! Three pieces:
//! - [`info`] — `contract-info.json` and the FLATTENING of Compact's typed
//!   tree into native slots, which is the same rule the `minocrab_std`
//!   leaves implement;
//! - [`pin`] — `pin.json`, the distilled hash-pinned artifact an interface
//!   crate commits instead of megabytes of `.zkir`;
//! - [`check`] — the six checks, and [`schema`] — the frozen published-ABI
//!   rendering whose diff is the semver decision.
//!
//! WHAT IT DOES NOT DO: bind an artifact to a deployed ADDRESS. That needs
//! the verifier key (keygen), which is out of M12's scope — see
//! notes/interface-crates.org §"Honest limits" #3.
//!
//! # Where this sits
//!
//! Off to the side of the stack, at the top: a dev-dependency of an interface
//! crate, never something a contract links. It reads compactc's artifacts
//! through `minocrab-zkir` (L0) and speaks the ABI vocabulary of [`minocrab`]
//! (L2) and [`minocrab_ledger`] (L2.5), so the types it checks against are
//! exactly the ones the call sites use. `minocrab-interface-gen` reads the
//! same parse to *write* interface crates, which is why the generator and the
//! test that validates its output cannot disagree.
//!
//! # Start here
//!
//! - [`Artifact`] — open a crate's pinned artifact; the entry point for every
//!   check
//! - [`Artifact::verify_pin`] and [`Pin`] — the hash-pinned distillation an
//!   interface crate commits instead of megabytes of `.zkir`
//! - [`Artifact::assert_interface_matches`] — the declared Rust types against
//!   the artifact's typed signature
//! - [`ContractInfo`] and [`Flattened`] — `contract-info.json`, and the
//!   flattening of Compact's typed tree into native slots
//! - [`circuit_schema`] — the frozen published-ABI rendering whose diff is
//!   the semver decision
//! - [`Problems`] and [`Error`] — what a disagreement reads like

pub mod check;
pub mod info;
pub mod pin;
pub mod schema;
pub mod zkir;

pub use check::{assert_ir_matches_interface, check_ir, Artifact, Error, Problems};
pub use info::{ContractInfo, CompactType, Flattened, TypeError};
pub use pin::{Pin, PinnedCircuit};
pub use schema::circuit_schema;
pub use zkir::ZkirFacts;
