//! L1 — typed circuit builder over ZKIR v3 instructions.
//!
//! [`v3::Builder3`] emits a ZKIR v3 instruction stream over *named, typed*
//! values with inline immediates, checking every operand's [`v3::IrType`]
//! against the instruction's supported-type list as it goes, so an emitted
//! stream is well-formed by construction. The passes (L4) operate on this
//! layer. Semantics reference: midnight-zkir's `src/ir_vm.rs`.
//!
//! # Where this sits
//!
//! Directly above [`minocrab_zkir`] (L0), whose types it re-exports, and
//! directly below the `minocrab` eDSL (L2), which is what contract code is
//! written against. Nothing here knows about wires, visibility or disclosure
//! — this layer's whole job is that an emitted instruction stream is
//! well-formed. Most users want L2; reach for this crate to build ZKIR
//! directly, or to run a pass over it.
//!
//! # Start here
//!
//! - [`v3::Builder3`] and [`v3::Arg`] — the builder, over *named, typed*
//!   values with inline immediates
//! - [`v3::IrType`] — the v3 value types the builder checks operands against
//! - [`v3::passes`] — the normalisation passes both sides of a differential
//!   are run through
//! - [`minocrab_zkir::v3::IrSource`] — what a finished build hands to L0 for
//!   writing
//!
//! # Stability
//!
//! [`v3::passes`] (the [`v3::passes::Pass`] trait and the reference passes)
//! and the re-exported ZKIR types are the surface a pass crate builds on. The raw [`v3::Builder3`] layer is the eDSL's implementation detail,
//! wrapped by `minocrab`'s `Circuit3`, and carries no stability promise.

pub use midnight_base_crypto::fab::{Alignment, AlignmentAtom, AlignmentSegment};
pub use minocrab_zkir::Fr;

pub mod v3;
