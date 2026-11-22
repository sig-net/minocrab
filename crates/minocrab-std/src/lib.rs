//! L3 — the MinoCrab standard library.
//!
//! Ports of Compact's `standard-library.compact` and `zkir-v3-library.compact`,
//! expressed against the L2 eDSL. Translation is mechanical from Midnight's
//! sources (corpus/src/compact/compiler/, pinned before compactc 0.36; the
//! 0.36 library changes ported here are in notes/version-bump.org Bump 2),
//! with the lowering recipes pinned
//! in notes/builtin-lowering.org; each ported item is differential-tested
//! against compactc's compilation of the original.
//!
//! Everything is at the crate root (ZKIR v3 is the only target): the typed
//! leaves ([`Uint`], [`Bytes`], [`B32`]), the ledger block, the
//! kernel ADT, Borsh, and the `secp256k1`/keccak circuits. Values above a
//! single field element are typed leaves whose slots flatten in declaration
//! order beside the type's FAB alignment atoms — compactc's own
//! flatten-datatypes view of Compact values.
//!
//! # Where this sits
//!
//! The top of the library stack: [`minocrab`] (L2) supplies the eDSL and
//! [`minocrab_ledger`] (L2.5) the Impact op emission that [`LedgerMap`]
//! and [`kernel`] wrap, and with the default `macros` feature the
//! `minocrab-macros` decorators are re-exported from here beside the traits
//! they implement. A contract crate normally depends on this crate alone, and
//! on `minocrab-sim` as a dev-dependency to run its circuits under
//! `cargo test`.
//!
//! # Start here
//!
//! - [`Uint`], [`Bytes`], [`B32`], [`Bool`] — the typed
//!   leaves; an argument's type *is* its range constraint
//! - [`hash`] — the two hash flavors, always called module-qualified
//!   because which bytes get hashed is a decision
//! - [`borsh`] — canonical Borsh over the fixed-width subset a circuit
//!   can emit
//! - [`LedgerMap`], [`LedgerCell`], [`LedgerCounter`] — the
//!   ledger block as types, carrying Compact's own method names
//! - [`kernel`] — mint/send/receive/claim, `blockTime*`,
//!   `unshieldedBalance*`
//! - [`macro@circuit`] and [`macro@Value`] — the decorators
//!   (default `macros` feature)
//!
//! # Stability
//!
//! Stable tier (semver commitment): the typed v3 leaves — `Uint`, `Bool`,
//! `Bytes<N>`, `B32`, the curve leaves — per notes/library-api.org §1's
//! minimal set. The wider contract-authoring surface (ledger declarations,
//! kernel, Borsh, disclosure vocabulary) is not yet under a stability
//! promise: the tier line inside this crate is drawn deliberately small
//! while users are few, and widens by decision.

mod leaves;
mod slots;
mod disclose;
mod entry;
mod ledger;

/// Blind accumulators: the steps the ledger applies itself — `Add`,
/// `Max`, `Min`, `And`, `Or`, `Last`, `First` and tuples of them — with a
/// blind snapshot into a per-key map. Written module-qualified
/// (`blind::Max`) except for the two traits.
mod assumed;
pub mod blind;
mod hook;
mod stream;
mod vector;

/// Compact's `kernel` ADT and the token stdlib built on it — always
/// written module-qualified (`kernel::balance(c, &t)`), because a kernel
/// operation is an effect on the transaction and the call site should say so.
pub mod kernel;
mod predicate;

/// Compact's `emit <event>` — always written module-qualified
/// (`event::emit(c, version, tag, &payload)`): an event is public output
/// appended to the transaction's log, and the call site should say so.
pub mod event;

/// Canonical Borsh, restricted to the fixed-width subset a circuit can emit
/// — the serialization layer (notes/borsh-format.org). Read its module
/// docs first: **this is Borsh, not a format of ours**, and the subset exists
/// because a circuit cannot have data-dependent layout.
pub mod borsh;

/// The two hash flavors — `persistent_hash`/`transient_hash` over a value's
/// Borsh encoding (the default) and the `_compact` pair over Compact's FAB
/// representation (Compact-interop digest agreement only). Always written
/// module-qualified (`hash::persistent_hash(c, &v)`), never re-exported bare:
/// which bytes get hashed is a decision, and it should be visible at the call
/// site.
pub mod hash;
pub use leaves::*;

// rename-v3: begin shim (tools/rename-v3.sh never rewrites this block)
/// The pre-rename path: everything that was `minocrab_std::v3::X` is `minocrab_std::X`.
/// Kept for the downstream pins only; nothing in this workspace uses it.
#[doc(hidden)]
#[deprecated(note = "`minocrab_std::v3` is gone: the items are at the crate root \
                     (`minocrab_std::X`) and lose the `3` suffix; this module is removed in the next release")]
pub mod v3 {
    pub use crate::*;
    pub use crate::Vis as Vis3;
    #[deprecated(note = "renamed to `minocrab_std::ShieldedCoinInfo`")]
    pub type ShieldedCoinInfo3<V> = crate::ShieldedCoinInfo<V>;
    #[deprecated(note = "renamed to `minocrab_std::QualifiedShieldedCoinInfo`")]
    pub type QualifiedShieldedCoinInfo3<V> = crate::QualifiedShieldedCoinInfo<V>;
}
// rename-v3: end shim

