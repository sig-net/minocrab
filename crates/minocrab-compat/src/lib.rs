//! # minocrab-compat: compactc's lowerings, for circuits ported from Compact
//!
//! WHY THIS CRATE EXISTS. A circuit ported from a Compact contract has to
//! emit compactc's instruction stream byte for byte. That equality is how a
//! port is checked against the compiler's own output (the instruction-level
//! differentials compare the two streams), and it is what keeps an artifact
//! whose verifier key is already deployed from moving. The items here are
//! the compactc-shaped lowerings that equality needs.
//!
//! NOTHING IN IT IS THE CHEAPEST CORRECT LOWERING. Each module and item says
//! what about its shape is compactc's and what the lean form is. A contract
//! with no Compact twin and no deployed key should not use this crate; it
//! uses `minocrab_std`, whose gadgets are free to get cheaper.
//!
//! | module | what |
//! |---|---|
//! | [`kernel`] | the Compact standard-library circuits over `kernel` |
//! | [`merkle`] | `insertIndexDefault` with the default leaf hashed in circuit |
//! | [`secp`] | `secp256k1EcdsaVerify` |
//! | [`normalise`] | the copy fold the differentials apply to both streams |
//! | [`profile`] | compactc's lowering settings, one attribute on a ported contract |
//!
//! Nothing in the core depends on this crate (`cargo tree -i
//! minocrab-compat` lists only the corpus of ports), so nothing compactc
//! needs can reach a contract that did not ask for it.

pub mod kernel;
pub mod merkle;
pub mod normalise;
pub mod secp;

use minocrab::v3::{Circuit3, Lowering, SelfAddressReads};

/// Set this circuit's lowering to compactc's, for every circuit ported from
/// Compact and every circuit of the deployed signer.
///
/// A ported contract says it ONCE, on its block:
/// `#[contract(lowering = minocrab_compat::profile)]`, and `#[contract]`
/// calls this on each of its circuits before the body. A circuit built by
/// hand outside a `#[contract]` block (through `entry`, or `Circuit3::new()`)
/// calls it itself, as the first statement of what it builds.
///
/// The settings no gadget can carry, because shared helpers reach them
/// through core ([`Circuit3::set_lowering`]):
///
/// - `kernel.self()` is read at EVERY call ([`SelfAddressReads::EveryCall`]):
///   compactc never caches it. The lean form reads it once per circuit. With
///   the profile set, `kernel::cache_self_address` is refused at build time.
/// - repeated range constraints are KEPT (`dedup_range_constraints: false`):
///   compactc re-emits them. The lean form drops the implied ones (two rows
///   each).
///
/// The struct literal is exhaustive on purpose: a setting added to
/// [`Lowering`] stops this compiling until it says what compactc does.
///
/// Refused (a build-time panic, from `set_lowering`) once a gadget has
/// lowered under the circuit's previous settings: the circuit would be half
/// one lowering and half the other.
#[track_caller]
pub fn profile(c: &mut Circuit3) {
    c.set_lowering(Lowering {
        self_address: SelfAddressReads::EveryCall,
        dedup_range_constraints: false,
        // compactc emits the dead and repeated computations the simplification deletes.
        simplify: false,
    });
}
