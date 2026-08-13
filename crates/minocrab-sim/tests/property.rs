//! M3: spec ≡ circuit property testing.
//!
//! The spec is ordinary Rust; proptest drives random inputs through both the
//! spec and the simulated circuit and asserts they agree — the strongest
//! practical defense against proving-the-wrong-statement. Every accepted run
//! is additionally validated by Midnight's reference VM (`IrSource::check`),
//! so a simulator bug can't hide a circuit bug.
//!
//! Case count is a CI knob: `PROPTEST_CASES=1000000 cargo test` scales it up
//! without code changes (default 256).

use midnight_transient_crypto::proofs::Zkir;
use minocrab::{Circuit, Compiled, Fr};
use proptest::prelude::*;

/// Simulate + cross-check against the reference VM. Returns None if the
/// circuit rejected the witness.
fn run_checked(compiled: &Compiled, witness: &[Fr]) -> Option<minocrab_sim::Run> {
    let run = minocrab_sim::simulate(&compiled.ir, &[], witness, &[]).ok()?;
    compiled
        .ir
        .check(&run.preimage(witness, &[]))
        .expect("simulator accepted but reference VM rejected");
    Some(run)
}

// --- age gate: private age, public >= 18 verdict ------------------------------

fn age_gate() -> Compiled {
    let (mut c, _) = Circuit::new(0);
    let age = c.witness();
    let threshold = c.constant(18u64);
    let too_young = c.less_than(age, threshold, 8);
    let old_enough = c.not(too_young);
    c.assert(old_enough);
    let verdict = c.disclose(old_enough, "age >= 18 verdict");
    c.declare_public(verdict, "verdict");
    c.finish()
}

fn age_gate_spec(age: u8) -> bool {
    age >= 18
}

proptest! {
    #[test]
    fn age_gate_matches_spec(age: u8) {
        let compiled = age_gate();
        let accepted = run_checked(&compiled, &[Fr::from(age as u64)]);
        prop_assert_eq!(accepted.is_some(), age_gate_spec(age));
        if let Some(run) = accepted {
            prop_assert_eq!(&run.public_transcript_inputs, &vec![Fr::from(1u64)]);
        }
    }
}

// --- linear arithmetic: (a + b) * c disclosed --------------------------------

fn linear() -> Compiled {
    let (mut c, _) = Circuit::new(0);
    let a = c.witness();
    let b = c.witness();
    let k = c.witness();
    let sum = c.add(a, b);
    let product = c.mul(sum, k);
    let result = c.disclose(product, "(a+b)*c");
    c.declare_public(result, "result");
    c.finish()
}

fn linear_spec(a: u64, b: u64, k: u64) -> u128 {
    (a as u128 + b as u128) * k as u128
}

proptest! {
    #[test]
    fn linear_matches_spec(a: u32, b: u32, k: u32) {
        let compiled = linear();
        let witness = [Fr::from(a as u64), Fr::from(b as u64), Fr::from(k as u64)];
        let run = run_checked(&compiled, &witness).expect("linear circuit never rejects");
        // u32 inputs can't overflow the ~255-bit field, so field arithmetic
        // must equal integer arithmetic.
        let expected = linear_spec(a as u64, b as u64, k as u64);
        prop_assert_eq!(
            &run.public_transcript_inputs,
            &vec![Fr::from(expected)]
        );
    }
}

// --- conditional: |a - b| via cond_select -------------------------------------

fn abs_diff() -> Compiled {
    let (mut c, _) = Circuit::new(0);
    let a = c.witness();
    let b = c.witness();
    let a_lt_b = c.less_than(a, b, 32);
    let neg_a = c.neg(a);
    let neg_b = c.neg(b);
    let b_minus_a = c.add(b, neg_a);
    let a_minus_b = c.add(a, neg_b);
    let diff = c.cond_select(a_lt_b, b_minus_a, a_minus_b);
    let result = c.disclose(diff, "|a-b|");
    c.declare_public(result, "abs diff");
    c.finish()
}

proptest! {
    #[test]
    fn abs_diff_matches_spec(a: u32, b: u32) {
        let compiled = abs_diff();
        let witness = [Fr::from(a as u64), Fr::from(b as u64)];
        let run = run_checked(&compiled, &witness).expect("abs_diff never rejects");
        let expected = (a as i64 - b as i64).unsigned_abs();
        prop_assert_eq!(&run.public_transcript_inputs, &vec![Fr::from(expected)]);
    }
}
