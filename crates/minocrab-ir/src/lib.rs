//! L1 — typed circuit builder over ZKIR v3 instructions.
//!
//! [`Builder`] emits a ZKIR v3 instruction stream over *named, typed*
//! values with inline immediates, checking every operand's [`IrType`]
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
//! - [`Builder`] and [`Arg`] — the builder, over *named, typed*
//!   values with inline immediates
//! - [`IrType`] — the v3 value types the builder checks operands against
//! - [`passes`] — the normalisation passes both sides of a differential
//!   are run through
//! - [`minocrab_zkir::IrSource`] — what a finished build hands to L0 for
//!   writing
//!
//! # Stability
//!
//! [`passes`] (the [`passes::Pass`] trait and the reference passes)
//! and the re-exported ZKIR types are the surface a pass crate builds on. The raw [`Builder`] layer is the eDSL's implementation detail,
//! wrapped by `minocrab`'s `Circuit`, and carries no stability promise.

pub use midnight_base_crypto::fab::{Alignment, AlignmentAtom, AlignmentSegment};
pub use minocrab_zkir::Fr;

mod builder;
pub mod passes;
pub use builder::*;

// rename-v3: begin shim (tools/rename-v3.sh never rewrites this block)
/// The pre-rename path: everything that was `minocrab_ir::v3::X` is `minocrab_ir::X`.
/// Kept for the downstream pins only; nothing in this workspace uses it.
#[doc(hidden)]
#[deprecated(note = "`minocrab_ir::v3` is gone: the items are at the crate root \
                     (`minocrab_ir::X`) and lose the `3` suffix; this module is removed in the next release")]
pub mod v3 {
    pub use crate::*;
    #[deprecated(note = "renamed to `minocrab_ir::Builder`")]
    pub type Builder3 = crate::Builder;
}
// rename-v3: end shim
