//! M25's construct-loop reflection for this crate (notes/lean-port.org §3,
//! rows 1-3): the numeric and visibility Lean warrants under
//! `lean/MinocrabStdProofs/` are EMBEDDED here at compile time — a deleted
//! proof file is a build error — and this test asserts each still declares
//! every theorem the crate claims, so a renamed theorem is a test failure,
//! not a silently stale claim (the same instrument as minocrab-ir's
//! `the_builtin_proofs_declare_every_claimed_theorem`).
//!
//! What each proof warrants is written in the proof files' headers; the
//! Rust-side enforcement the theorems back is the inline-const asserts on
//! `Uint`/`BoundedUint` (`add`/`mul`/`sub`/`widen`/`to_uint`/`narrow`) and
//! the `Meet`/`disclose` visibility system.

use minocrab_ir::lean_proof;
use minocrab_ir::v3::passes::ProofRef;

/// The numeric leaves' warrant: `BoundedUint`'s bound arithmetic (the
/// `add`/`mul` const asserts sound AND minimal), the subtraction guard
/// (field-sub equals integer-sub exactly under the guard; the underflow
/// shape without it), the guard's comparison width, and the free retypes
/// (`widen`, `to_uint`).
static NUMERIC_PROOF: ProofRef = lean_proof! {
    file: "../lean/MinocrabStdProofs/Numeric.lean",
    theorems: [
        "sum_bound_sound",
        "sum_bound_minimal",
        "product_bound_sound",
        "product_bound_minimal",
        "field_sub_eq_nat_sub",
        "field_sub_underflow",
        "sub_result_bound",
        "lt_two_pow_log2_succ",
        "guard_width_sound",
        "widen_sound",
        "uint_widen_sound",
        "to_uint_sound",
    ],
};

/// The visibility system's warrant: `Meet`'s table is a lattice meet
/// (commutative, associative, idempotent, `Public` identity, `Private`
/// absorbing, greatest lower bound), and the taint theorem — an
/// expression types `Public` iff every private leaf sits under a
/// `disclose`.
static VISIBILITY_PROOF: ProofRef = lean_proof! {
    file: "../lean/MinocrabStdProofs/Visibility.lean",
    theorems: [
        "meet_comm",
        "meet_assoc",
        "meet_idem",
        "meet_pub",
        "meet_priv",
        "meet_eq_pub_iff",
        "le_refl",
        "meet_le_left",
        "meet_le_right",
        "le_meet",
        "vis_pub_iff_no_undisclosed_priv",
        "undisclosed_priv_is_private",
    ],
};

#[test]
fn the_std_proofs_declare_every_claimed_theorem() {
    for proof in [&NUMERIC_PROOF, &VISIBILITY_PROOF] {
        assert_eq!(
            proof.missing_theorems(),
            Vec::<&str>::new(),
            "{} no longer declares every claimed theorem",
            proof.file(),
        );
    }
}
