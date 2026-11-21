//! The normaliser the instruction-level differentials apply to BOTH
//! streams, compactc's artifact and the port's, before comparing them.
//!
//! WHAT IS COMPACTC'S: compactc names some constants with a `Copy` of an
//! immediate where the builder inlines them. The rename has no rows, no
//! public-input effect and no semantic content, so the comparison is made
//! modulo it. THE LEAN FORM needs no normaliser: it is what
//! `Builder::finish` already emits.

use minocrab_ir::passes::fold_immediate_copies;
use minocrab_zkir::IrSource;

/// [`fold_immediate_copies`] over a whole [`IrSource`] — the form the
/// instruction-for-instruction differentials need, because they must run the
/// SAME normalisation over compactc's artifact as our builder runs over ours.
///
/// Why that is not a weakening of those tests: the pass only ever removes a
/// `Copy` of an immediate, which is a rename with no rows (measured), no
/// public-input effect and no semantic content. Everything else — every
/// instruction, every operand, every order — is still compared exactly, and a
/// constant that either side NAMES for an output slot is still named on both.
///
/// THE COPY FOLD ONLY, deliberately: `drop_true_asserts` also runs in
/// `Builder::finish`, and is NOT part of this normalisation. It deletes an
/// instruction rather than renaming one, and no compactc artifact we hold
/// contains an `assert` on an immediate (measured 2026-09-06: all 332 asserts
/// in the 211 workspace dumps, and all 251 in the 209 v3 `.zkir` files under
/// `corpus/` and `crates/`, name a WIRE). Adding it here would only ever hide
/// a divergence — a compactc artifact that DID carry one is something we want
/// a differential to say out loud, not something to normalise away.
pub fn folded(ir: &IrSource) -> IrSource {
    IrSource { instructions: std::sync::Arc::new(fold_immediate_copies(ir.instructions.to_vec())), ..ir.clone() }
}
