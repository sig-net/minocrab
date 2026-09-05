//! L3 — the MinoCrab standard library.
//!
//! Ports of Compact's `standard-library.compact` and `zkir-v3-library.compact`,
//! expressed against the L2 eDSL. Translation is mechanical from Midnight's
//! sources (corpus/src/compact/compiler/), with the lowering recipes pinned
//! in notes/builtin-lowering.org; each ported item is differential-tested
//! against compactc's compilation of the original.
//!
//! Everything lives under [`v3`] (ZKIR v3, the only target): the typed
//! leaves ([`v3::Uint`], [`v3::Bytes`], [`v3::B32`]), the ledger block, the
//! kernel ADT, Borsh, and the `secp256k1`/keccak circuits. Values above a
//! single field element are typed leaves whose slots flatten in declaration
//! order beside the type's FAB alignment atoms — compactc's own
//! flatten-datatypes view of Compact values.
//!
//! # Where this sits
//!
//! The top of the library stack: [`minocrab`] (L2) supplies the eDSL and
//! [`minocrab_ledger`] (L2.5) the Impact op emission that [`v3::LedgerMap`]
//! and [`v3::kernel`] wrap, and with the default `macros` feature the
//! `minocrab-macros` decorators are re-exported from here beside the traits
//! they implement. A contract crate normally depends on this crate alone, and
//! on `minocrab-sim` as a dev-dependency to run its circuits under
//! `cargo test`.
//!
//! # Start here
//!
//! - [`v3::Uint`], [`v3::Bytes`], [`v3::B32`], [`v3::Bool`] — the typed
//!   leaves; an argument's type *is* its range constraint
//! - [`v3::hash`] — the two hash flavors, always called module-qualified
//!   because which bytes get hashed is a decision
//! - [`v3::borsh`] — canonical Borsh over the fixed-width subset a circuit
//!   can emit
//! - [`v3::LedgerMap`], [`v3::LedgerCell`], [`v3::LedgerCounter`] — the
//!   ledger block as types, carrying Compact's own method names
//! - [`v3::kernel`] — mint/send/receive/claim, `blockTime*`,
//!   `unshieldedBalance*`
//! - [`macro@v3::circuit`] and [`macro@v3::CircuitArg`] — the decorators
//!   (default `macros` feature)
//!
//! # Stability (M24 tier boundary)
//!
//! STABLE TIER (semver commitment): the typed v3 leaves — `Uint`, `Bool`,
//! `Bytes<N>`, `B32`, the curve leaves — per notes/library-api.org §1's
//! minimal set. The wider contract-authoring surface (ledger declarations,
//! kernel, Borsh, disclosure vocabulary) is not yet under a stability
//! promise: the tier line inside this crate is drawn deliberately small
//! while users are few, and widens by decision.

pub mod v3;

