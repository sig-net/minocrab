//! Assertion predicates are lowering, not magic: `c.assert(less_than(a, b))`
//! must produce the BYTE-IDENTICAL ZKIR of the hand-written
//! `let p = c.less_than(a, b, BITS); c.assert(p);` — with the width read off
//! the operand type instead of typed at the call site.
//!
//! Everything else this file pins is the scope boundary: a predicate that is
//! never asserted emits nothing, a message is metadata (no instruction), the
//! combinators lower to exactly the ops they name, and the checks that make
//! the width sound reject at BUILD time — two of them as compile errors (see
//! `_COMPILE_ERRORS_NOT_PANICS`), the third as a panic, because the value of
//! a runtime integer is not in the type system.

use minocrab::v3::{Circuit3, Compiled3, FieldT};
use minocrab::{Private, Public};
use minocrab_std::v3::{
    eq, ge, greater_than, is_true, le, less_than, ne, not, Bool, Bytes, Uint,
};
use minocrab_zkir::v3::to_zkir_string;

fn zkir(compiled: Compiled3) -> String {
    to_zkir_string(&compiled.ir).expect("IR serializes")
}

/// Two circuits over the same arguments: one written with predicates, one by
/// hand.
fn same_zkir(
    predicates: impl FnOnce(&mut Circuit3, Uint<128, Private>, Uint<128, Private>),
    by_hand: impl FnOnce(&mut Circuit3, Uint<128, Private>, Uint<128, Private>),
) {
    fn build(
        f: impl FnOnce(&mut Circuit3, Uint<128, Private>, Uint<128, Private>),
    ) -> String {
        let mut c = Circuit3::new();
        let a = Uint::<128, Private>::from_field(c.arg::<FieldT>("a"));
        let b = Uint::<128, Private>::from_field(c.arg::<FieldT>("b"));
        f(&mut c, a, b);
        zkir(c.finish(false))
    }
    assert_eq!(build(predicates), build(by_hand));
}

/// Each comparison, against the hand-written lowering it replaces.
#[test]
fn every_comparison_lowers_to_the_hand_written_form() {
    // a < b
    same_zkir(
        |c, a, b| c.assert(less_than(a, b)),
        |c, a, b| {
            let p = c.less_than(a.field(), b.field(), 128);
            c.assert(p);
        },
    );
    // a > b is the same instruction with the operands swapped
    same_zkir(
        |c, a, b| c.assert(greater_than(a, b)),
        |c, a, b| {
            let p = c.less_than(b.field(), a.field(), 128);
            c.assert(p);
        },
    );
    // a <= b is !(b < a)
    same_zkir(
        |c, a, b| c.assert(le(a, b)),
        |c, a, b| {
            let lt = c.less_than(b.field(), a.field(), 128);
            let p = c.not(lt);
            c.assert(p);
        },
    );
    // a >= b is !(a < b)
    same_zkir(
        |c, a, b| c.assert(ge(a, b)),
        |c, a, b| {
            let lt = c.less_than(a.field(), b.field(), 128);
            let p = c.not(lt);
            c.assert(p);
        },
    );
    // a == b
    same_zkir(
        |c, a, b| c.assert(eq(a, b)),
        |c, a, b| {
            let p = c.test_eq(a.field(), b.field());
            c.assert(p);
        },
    );
    // a != b
    same_zkir(
        |c, a, b| c.assert(ne(a, b)),
        |c, a, b| {
            let e = c.test_eq(a.field(), b.field());
            let p = c.not(e);
            c.assert(p);
        },
    );
}

/// A literal operand is the inline immediate of the literals piece — the
/// width still comes from the typed side.
#[test]
fn a_literal_operand_is_the_inline_immediate() {
    same_zkir(
        |c, a, _| c.assert(greater_than(a, 0u64)),
        |c, a, _| {
            let p = c.less_than(0u64, a.field(), 128);
            c.assert(p);
        },
    );
    same_zkir(
        |c, a, _| c.assert(le(a, u64::MAX)),
        |c, a, _| {
            let too_big = c.less_than(u64::MAX, a.field(), 128);
            let p = c.not(too_big);
            c.assert(p);
        },
    );
}

/// not / and / or, each exactly the ops it names.
#[test]
fn the_combinators_lower_to_the_ops_they_name() {
    same_zkir(
        |c, a, b| c.assert(not(less_than(a, b))),
        |c, a, b| {
            let lt = c.less_than(a.field(), b.field(), 128);
            let p = c.not(lt);
            c.assert(p);
        },
    );
    same_zkir(
        |c, a, b| c.assert(less_than(a, b).and(greater_than(a, 0u64))),
        |c, a, b| {
            let lt = c.less_than(a.field(), b.field(), 128);
            let gt = c.less_than(0u64, a.field(), 128);
            let p = c.mul(lt, gt);
            c.assert(p);
        },
    );
    // or is De Morgan, written out: !(!x && !y)
    same_zkir(
        |c, a, b| c.assert(less_than(a, b).or(eq(a, b))),
        |c, a, b| {
            let lt = c.less_than(a.field(), b.field(), 128);
            let not_lt = c.not(lt);
            let e = c.test_eq(a.field(), b.field());
            let not_e = c.not(e);
            let neither = c.mul(not_lt, not_e);
            let p = c.not(neither);
            c.assert(p);
        },
    );
}

/// The escape hatch: `eval` hands back the wire, and emits the comparison
/// and nothing else.
#[test]
fn eval_is_the_comparison_without_the_assert() {
    same_zkir(
        |c, a, b| {
            let flag: Bool<Private> = less_than(a, b).eval(c);
            c.assert(flag);
        },
        |c, a, b| {
            let p = c.less_than(a.field(), b.field(), 128);
            c.assert(p);
        },
    );
}

/// An unasserted predicate emits NOTHING — strictly safer than an unasserted
/// `c.less_than(..)`, which emits cost and constrains nothing.
#[test]
fn an_unasserted_predicate_emits_nothing() {
    let mut c = Circuit3::new();
    let a = Uint::<128, Private>::from_field(c.arg::<FieldT>("a"));
    let before = c.instruction_count();
    let _dropped = less_than(0u64, a).and(le(a, u64::MAX)).message("unused");
    assert_eq!(c.instruction_count(), before);
}

/// The message is metadata: the stream is identical with and without it, and
/// the compiled circuit can name the assert that failed.
#[test]
fn a_message_costs_nothing_and_is_recorded() {
    let build = |message: bool| {
        let mut c = Circuit3::new();
        let a = Uint::<64, Private>::from_field(c.arg::<FieldT>("a"));
        let check = greater_than(a, 0u64);
        c.assert(if message {
            check.message("Chain ID must be positive")
        } else {
            check
        });
        c.finish(false)
    };

    let with = build(true);
    let without = build(false);
    assert_eq!(
        to_zkir_string(&with.ir).unwrap(),
        to_zkir_string(&without.ir).unwrap()
    );
    assert!(without.assert_messages.is_empty());
    assert_eq!(with.assert_messages.len(), 1);
    let at = with.assert_messages[0].instruction;
    assert_eq!(with.assert_message(at), Some("Chain ID must be positive"));
}

/// The methods on the typed leaves are the free constructors.
#[test]
fn the_method_surface_is_the_free_constructors() {
    same_zkir(
        |c, a, b| c.assert(a.gt(0u64).and(a.lt(b))),
        |c, a, b| c.assert(greater_than(a, 0u64).and(less_than(a, b))),
    );
}

/// Widths come from the types, so two typed operands must agree — and an
/// ORDERING needs at least one width to run at. Neither is a test here,
/// because neither is a runtime failure any more (M9 phase 8): both are
/// inline-`const` asserts in the constructors, so
///
/// ```compile_fail
/// # use minocrab::v3::{Circuit3, FieldT};
/// # use minocrab::Private;
/// # use minocrab_std::v3::{less_than, Uint};
/// let mut c = Circuit3::new();
/// let a = Uint::<128, Private>::from_field(c.arg::<FieldT>("a"));
/// let b = Uint::<64, Private>::from_field(c.arg::<FieldT>("b"));
/// c.assert(less_than(a, b));  // error[E0080]: … different widths …
/// ```
///
/// and
///
/// ```compile_fail
/// # use minocrab::v3::{Circuit3, FieldT};
/// # use minocrab_std::v3::less_than;
/// let mut c = Circuit3::new();
/// let a = c.arg::<FieldT>("a");
/// let b = c.arg::<FieldT>("b");
/// c.assert(less_than(a, b));  // error[E0080]: … needs a width …
/// ```
///
/// are BUILD errors at the call site, not panics when the circuit is built.
/// (Both messages are checked by hand; there is no trybuild in the lock file,
/// and `compile_fail` doc-tests do not run for a test target — this block is
/// the record of the two spellings that must not compile.)
const _COMPILE_ERRORS_NOT_PANICS: () = ();

/// Equality needs no width, so raw wires are fine there.
#[test]
fn equality_of_raw_wires_is_allowed() {
    let mut c = Circuit3::new();
    let a = c.arg::<FieldT>("a");
    let b = c.arg::<FieldT>("b");
    c.assert(eq(a, b));
    assert_eq!(c.instruction_count(), 2);
}

/// The constant side is a CHECKED immediate.
#[test]
#[should_panic(expected = "does not fit the 8 bits")]
fn a_literal_wider_than_the_comparison_is_rejected() {
    let mut c = Circuit3::new();
    let byte = Bytes::<1, Private>::from_field(c.arg::<FieldT>("byte"));
    c.assert(less_than(byte, 300u64));
}

/// A public comparison stays public; a private operand makes it private.
#[test]
fn visibility_follows_the_meet() {
    let mut c = Circuit3::new();
    let secret = Uint::<64, Private>::from_field(c.arg::<FieldT>("secret"));
    let public = Uint::<64, Public>::from_field(c.public_transcript_input::<FieldT>());

    let _private: Bool<Private> = less_than(0u64, secret).eval(&mut c);
    let _public: Bool<Public> = less_than(0u64, public).eval(&mut c);
    let _mixed: Bool<Private> = less_than(secret, public).eval(&mut c);
}

/// The boolean LEAF (M9 phase 8, candidate 5) costs nothing: `is_true(b)` and
/// the bare wire are the same stream, so `.message(..)` and the combinators
/// reach a computed boolean (a map `member` result) for free.
#[test]
fn is_true_is_the_wire_itself() {
    let build = |leaf: bool| {
        let mut c = Circuit3::new();
        let b = Bool::<Private>::from_field(c.arg::<FieldT>("b"));
        if leaf {
            c.assert(is_true(b).message("Request already exists"));
        } else {
            c.assert_with(b.field(), Some("Request already exists"));
        }
        c.finish(false)
    };
    let with = build(true);
    let without = build(false);
    assert_eq!(
        to_zkir_string(&with.ir).unwrap(),
        to_zkir_string(&without.ir).unwrap()
    );
    assert_eq!(with.assert_messages, without.assert_messages);
}

/// ...and it composes: a leaf inside the combinators is the hand-written
/// boolean algebra.
#[test]
fn is_true_composes_with_the_combinators() {
    let build = |predicates: bool| {
        let mut c = Circuit3::new();
        let b = Bool::<Private>::from_field(c.arg::<FieldT>("b"));
        let a = Uint::<64, Private>::from_field(c.arg::<FieldT>("a"));
        if predicates {
            c.assert(is_true(b).and(a.gt(0u64)));
        } else {
            let gt = c.less_than(0u64, a.field(), 64);
            let both = c.mul(b.field(), gt);
            c.assert(both);
        }
        zkir(c.finish(false))
    };
    assert_eq!(build(true), build(false));
}

/// `.when(guard)` (M9 phase 8, candidate 6) is the in-branch assert:
/// `assert(select(guard, cond, 1))`, with the `1` inline.
#[test]
fn when_is_the_in_branch_assert() {
    let build = |predicates: bool| {
        let mut c = Circuit3::new();
        let a = Uint::<64, Private>::from_field(c.arg::<FieldT>("a"));
        let b = Uint::<64, Private>::from_field(c.arg::<FieldT>("b"));
        let guard = c.public_transcript_input::<FieldT>();
        if predicates {
            c.assert(less_than(a, b).when(guard).message("Not the withdrawer"));
        } else {
            let lt = c.less_than(a.field(), b.field(), 64);
            let gated = c.cond_select(guard, lt, 1u64);
            c.assert_with(gated, Some("Not the withdrawer"));
        }
        c.finish(false)
    };
    let with = build(true);
    let without = build(false);
    assert_eq!(
        to_zkir_string(&with.ir).unwrap(),
        to_zkir_string(&without.ir).unwrap()
    );
    assert_eq!(with.assert_messages.len(), 1);
}

/// A guard may be PUBLIC over a private check — the common case, a public
/// branch condition gating a secret comparison.
#[test]
fn a_public_guard_gates_a_private_check() {
    let mut c = Circuit3::new();
    let secret = Uint::<64, Private>::from_field(c.arg::<FieldT>("secret"));
    let guard = c.public_transcript_input::<FieldT>();
    let _: Bool<Private> = less_than(0u64, secret).when(guard).eval(&mut c);
}

/// `.widen::<W>()` (dmd's decision A) is free: the same wire, no instruction,
/// and no second range constraint — so a widened comparison is the
/// hand-written comparison at the wider width.
#[test]
fn widen_is_free_and_compares_at_the_wider_width() {
    let build = |widened: bool| {
        let mut c = Circuit3::new();
        let narrow = Uint::<64, Private>::from_field(c.arg::<FieldT>("narrow"));
        let wide = Uint::<128, Private>::from_field(c.arg::<FieldT>("wide"));
        if widened {
            c.assert(less_than(narrow.widen::<128>(), wide));
        } else {
            let lt = c.less_than(narrow.field(), wide.field(), 128);
            c.assert(lt);
        }
        zkir(c.finish(false))
    };
    assert_eq!(build(true), build(false));

    // …and it really is zero instructions on its own.
    let mut c = Circuit3::new();
    let narrow = Uint::<64, Private>::from_field(c.arg::<FieldT>("narrow"));
    let before = c.instruction_count();
    let _wide: Uint<128, Private> = narrow.widen();
    assert_eq!(c.instruction_count(), before);
}
