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

pub mod check;
pub mod info;
pub mod pin;
pub mod schema;
pub mod zkir;

pub use check::{Artifact, Error, Problems};
pub use info::{ContractInfo, CompactType, Flattened, TypeError};
pub use pin::{Pin, PinnedCircuit};
pub use schema::circuit_schema;
pub use zkir::ZkirFacts;
