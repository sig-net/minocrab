//! `contract_call` under a guard (external review §4.3): its witnesses —
//! the callee's results, cc-rand and the entry-point limbs — are read under
//! the same guard the claim op is emitted under, so a call inside a branch
//! consumes the private transcript only where the branch runs. The claim,
//! as everywhere in the guard-scope suite: the scoped spelling and the
//! explicit-guard spelling lower byte for byte to the same stream.

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
        let one = c.constant(1u64);
        c.when(g, |c| {
            contract_call(c, one, [hi, lo], &[], &[LimbConstraint::Bits(64)]);
        });
    });
    let explicit = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let g = c.disclose(g, "g");
        let hi = c.arg::<FieldT>("addr_hi");
        let hi = c.disclose(hi, "addr hi");
        let lo = c.arg::<FieldT>("addr_lo");
        let lo = c.disclose(lo, "addr lo");
        // Same identifier budget as the scoped side (its `one` numbers a wire
        // even though the fold inlines it).
        let _one = c.constant(1u64);
        contract_call(c, g, [hi, lo], &[], &[LimbConstraint::Bits(64)]);
    });
    assert_eq!(scoped, explicit);
    // And the witnesses really are guarded: every private_input names `g`.
    let reads = explicit.matches("private_input").count();
    assert_eq!(reads, 4, "results + cc-rand + two entry-point limbs");
    assert!(!explicit.contains(r#""guard":null"#), "{explicit}");
}

/// Straight-line: the constant-true guard lowers to compactc's `guard:
/// null` on every read, and the immediate `0x01` on the op.
#[test]
fn a_straight_line_call_reads_its_witnesses_unguarded() {
    let stream = zkir(|c| {
        let hi = c.arg::<FieldT>("addr_hi");
        let hi = c.disclose(hi, "addr hi");
        let lo = c.arg::<FieldT>("addr_lo");
        let lo = c.disclose(lo, "addr lo");
        let one = c.constant(1u64);
        contract_call(c, one, [hi, lo], &[], &[]);
    });
    assert_eq!(stream.matches(r#""guard":null"#).count(), 3, "{stream}");
}
