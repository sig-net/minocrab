//! Inline immediates: a native Rust value in an operand position must cost
//! NOTHING, and must cost strictly less than naming the same constant first.
//!
//! v3 has no `LoadImm` — an immediate is an operand — so
//! `c.less_than(0u64, x, 64)` is one instruction where
//! `c.less_than(c.constant(0u64), x, 64)` is two, and the second one exists
//! only to give the constant a name. This is the property the row snapshot
//! CANNOT see (a `Copy` is zero rows), so it is asserted here on the
//! instruction stream itself.

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Private, Public};
use minocrab_zkir::v3::to_zkir_string;

/// Each operand-taking builder method, with a literal and with a named
/// constant: the literal form is one instruction, the named form is two.
#[test]
fn a_literal_operand_costs_one_instruction_less_than_naming_it() {
    fn count(build: impl FnOnce(&mut Circuit3)) -> usize {
        let mut c = Circuit3::new();
        let _ = c.arg::<FieldT>("x");
        build(&mut c);
        c.instruction_count()
    }

    let x = |c: &mut Circuit3| c.arg::<FieldT>("x");

    // less_than
    assert_eq!(
        count(|c| {
            let x = x(c);
            c.less_than(0u64, x, 64);
        }),
        1
    );
    assert_eq!(
        count(|c| {
            let x = x(c);
            let zero = c.constant(0u64);
            c.less_than(zero, x, 64);
        }),
        2
    );

    // test_eq / add / mul / cond_select / assert_eq / not / neg
    assert_eq!(
        count(|c| {
            let x = x(c);
            c.test_eq(x, 7u64);
        }),
        1
    );
    assert_eq!(
        count(|c| {
            let x = x(c);
            c.add(x, 7u64);
        }),
        1
    );
    assert_eq!(
        count(|c| {
            let x = x(c);
            c.mul(x, 7u64);
        }),
        1
    );
    assert_eq!(
        count(|c| {
            let x = x(c);
            c.cond_select(x, x, 0u64);
        }),
        1
    );
    assert_eq!(
        count(|c| {
            let x = x(c);
            c.assert_eq(x, 0u64);
        }),
        1
    );
    assert_eq!(
        count(|c| {
            let x = x(c);
            c.neg(x);
            c.not(x);
        }),
        2
    );
}

/// The immediate is INLINE in the stream — the operand is the value, and
/// there is no `copy` naming it.
#[test]
fn the_immediate_appears_as_the_operand() {
    let mut c = Circuit3::new();
    let x = c.arg::<FieldT>("x");
    let lt = c.less_than(5u64, x, 64);
    c.assert(lt);
    let zkir = to_zkir_string(&c.finish(false).ir).expect("IR serializes");

    assert!(zkir.contains(r#""a":"0x05""#), "immediate not inline: {zkir}");
    assert!(!zkir.contains(r#""op":"copy""#), "a copy survived: {zkir}");
}

/// An immediate is public, and `V ⊓ Public = V`: comparing a private wire
/// against a literal keeps the result private. The assertion is the type
/// annotation — this test passing is a compile-time statement.
#[test]
fn a_literal_does_not_launder_visibility() {
    let mut c = Circuit3::new();
    let secret: Wire3<FieldT, Private> = c.arg::<FieldT>("secret");
    let public: Wire3<FieldT, Public> = c.public_transcript_input::<FieldT>();

    let _private_result: Wire3<FieldT, Private> = c.less_than(0u64, secret, 64);
    let _also_private: Wire3<FieldT, Private> = c.test_eq(secret, 1u64);
    let _public_result: Wire3<FieldT, Public> = c.test_eq(public, 1u64);
}
