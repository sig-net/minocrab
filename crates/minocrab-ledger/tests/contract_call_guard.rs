//! `contract_call` under a guard (external review §4.3): its witnesses —
//! the callee's results, cc-rand and the entry-point limbs — are read under
//! the same guard the claim op is emitted under, so a call inside a branch
//! consumes the private transcript only where the branch runs.
//!
//! `contract_call` no longer takes a guard parameter at all
//! (notes/edsl-trim.org §B): its witness reads are `c.witness()`, which
//! resolves the AMBIENT scope, so the one way to guard a call is
//! `c.when(g, |c| contract_call(c, ..))`.

use minocrab::v3::{Circuit3, FieldT, LimbConstraint};
use minocrab_ledger::contract_call;
use minocrab_zkir::v3::to_zkir_string;

fn zkir(build: impl FnOnce(&mut Circuit3)) -> String {
    let mut c = Circuit3::new();
    build(&mut c);
    to_zkir_string(&c.finish(true).ir).expect("serializes")
}

#[test]
fn a_call_inside_a_scope_reads_its_witnesses_under_the_scope() {
    let scoped = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let g = c.disclose(g, "g");
        let hi = c.arg::<FieldT>("addr_hi");
        let hi = c.disclose(hi, "addr hi");
        let lo = c.arg::<FieldT>("addr_lo");
        let lo = c.disclose(lo, "addr lo");
        c.when(g, |c| {
            contract_call(c, [hi, lo], &[], &[LimbConstraint::Bits(64)]);
        });
    });
    // The witnesses really are guarded: every private_input names `g`.
    let reads = scoped.matches("private_input").count();
    assert_eq!(reads, 4, "results + cc-rand + two entry-point limbs");
    assert!(!scoped.contains(r#""guard":null"#), "{scoped}");
}

/// Straight-line: no ambient scope, so every read lowers to compactc's
/// `guard: null` and the op carries the immediate `0x01`.
#[test]
fn a_straight_line_call_reads_its_witnesses_unguarded() {
    let stream = zkir(|c| {
        let hi = c.arg::<FieldT>("addr_hi");
        let hi = c.disclose(hi, "addr hi");
        let lo = c.arg::<FieldT>("addr_lo");
        let lo = c.disclose(lo, "addr lo");
        contract_call(c, [hi, lo], &[], &[]);
    });
    assert_eq!(stream.matches(r#""guard":null"#).count(), 3, "{stream}");
}
