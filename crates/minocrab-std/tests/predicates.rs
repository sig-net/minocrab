//! Assertion predicates are lowering, not magic: `c.assert(less_than(a, b))`
//! must produce the byte-identical ZKIR of the hand-written
//! `let p = c.less_than(a, b, BITS); c.assert(p);` — with the width read off
//! the operand type instead of typed at the call site.
//!
//! Everything else this file pins is the scope boundary: a predicate that is
//! never asserted emits nothing, a message is metadata (no instruction), the
//! combinators lower to exactly the ops they name, and the checks that make
//! the width sound reject at build time — two of them as compile errors (see
//! `_COMPILE_ERRORS_NOT_PANICS`), the third as a panic, because the value of
//! a runtime integer is not in the type system.

use minocrab::{Circuit, Compiled, FieldT, Wire};
use minocrab::{Private, Public};
use minocrab_std::{
    eq, ge, greater_than, is_true, le, less_than, ne, not, Bool, BoundedUint, Bytes, Uint,
};
use minocrab_zkir::to_zkir_string;

fn zkir(compiled: Compiled) -> String {
    to_zkir_string(&compiled.ir).expect("IR serializes")
}

/// Two circuits over the same arguments: one written with predicates, one by
/// hand.
fn same_zkir(
    predicates: impl FnOnce(&mut Circuit, Uint<128, Private>, Uint<128, Private>),
    by_hand: impl FnOnce(&mut Circuit, Uint<128, Private>, Uint<128, Private>),
) {
    fn build(
        f: impl FnOnce(&mut Circuit, Uint<128, Private>, Uint<128, Private>),
    ) -> String {
        let mut c = Circuit::new();
        let a = Uint::<128, Private>::from_field_unchecked(c.arg::<FieldT>("a"));
        let b = Uint::<128, Private>::from_field_unchecked(c.arg::<FieldT>("b"));
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
    // or over two comparisons (bits by construction) is one select
    same_zkir(
        |c, a, b| c.assert(less_than(a, b).or(eq(a, b))),
        |c, a, b| {
            let lt = c.less_than(a.field(), b.field(), 128);
            let e = c.test_eq(a.field(), b.field());
            let p = c.cond_select(lt, 1u64, e);
            c.assert(p);
        },
    );
    // …with the operand that is a bit as the arm whichever side it is on…
    same_zkir(
        |c, a, b| c.assert(is_true(Bool::from_field_unchecked(a.field())).or(eq(a, b))),
        |c, a, b| {
            let e = c.test_eq(a.field(), b.field());
            let p = c.cond_select(a.field(), 1u64, e);
            c.assert(p);
        },
    );
    same_zkir(
        |c, a, b| c.assert(eq(a, b).or(is_true(Bool::from_field_unchecked(a.field())))),
        |c, a, b| {
            let e = c.test_eq(a.field(), b.field());
            let p = c.cond_select(a.field(), 1u64, e);
            c.assert(p);
        },
    );
    // …and De Morgan, written out, !(!x && !y), when neither is
    same_zkir(
        |c, a, b| {
            c.assert(is_true(Bool::from_field_unchecked(a.field())).or(is_true(Bool::from_field_unchecked(b.field()))))
        },
        |c, a, b| {
            let not_a = c.not(a.field());
            let not_b = c.not(b.field());
            let neither = c.mul(not_a, not_b);
            let p = c.not(neither);
            c.assert(p);
        },
    );
}

/// `or`'s lowering accepts exactly what the De Morgan form accepted and
/// computes the same value, for every shape of operand on either side,
/// including leaves whose wires are not bits (an unchecked `Bool` of 2 or of
/// p − 1). Run through the executor on every assignment of
/// `{0, 1, 2, p − 1}` to the two wires, the result asserted equal to a third
/// argument of 0 or 1 so that the verdict reads the value too.
#[test]
fn or_accepts_exactly_what_de_morgan_accepts() {
    use midnight_onchain_state::state::StateValue;
    use minocrab::Fr;
    use minocrab_sim::exec::{self, Call, ExecError};
    use minocrab_std::Check;

    // The four operand shapes, each over the wires (x, y): the check, and
    // its lowering by hand as the old `or` saw it.
    type Shape = (fn(Wire<FieldT, Private>, Wire<FieldT, Private>) -> Check<Private>, fn(&mut Circuit, Wire<FieldT, Private>, Wire<FieldT, Private>) -> Wire<FieldT, Private>);
    let shapes: [(&str, Shape); 4] = [
        ("leaf", (|x, _| is_true(Bool::from_field_unchecked(x)), |_, x, _| x)),
        ("compare", (|x, y| eq(x, y), |c, x, y| c.test_eq(x, y))),
        ("not", (|x, _| not(is_true(Bool::from_field_unchecked(x))), |c, x, _| c.not(x))),
        ("and", (|x, y| is_true(Bool::from_field_unchecked(x)).and(is_true(Bool::from_field_unchecked(y))), |c, x, y| c.mul(x, y))),
    ];
    let minus_one = Fr::from(0u64) - Fr::from(1u64);
    let values = [Fr::from(0u64), Fr::from(1u64), Fr::from(2u64), minus_one];
    let (mut accepted, mut refused) = (0, 0);
    for (left_name, (left, left_by_hand)) in shapes {
        for (right_name, (right, right_by_hand)) in shapes {
            let build = |lean: bool| {
                let mut c = Circuit::new();
                let x = c.arg::<FieldT>("x");
                let y = c.arg::<FieldT>("y");
                let z = c.arg::<FieldT>("z");
                let value = if lean {
                    left(x, y).or(right(y, x)).eval(&mut c).field()
                } else {
                    let l = left_by_hand(&mut c, x, y);
                    let l = c.not(l);
                    let r = right_by_hand(&mut c, y, x);
                    let r = c.not(r);
                    let both = c.mul(l, r);
                    c.not(both)
                };
                let same = c.test_eq(value, z);
                c.assert(same);
                c.finish(false)
            };
            let (lean, de_morgan) = (build(true), build(false));
            for x in values {
                for y in values {
                    for z in [Fr::from(0u64), Fr::from(1u64)] {
                        let args = [x, y, z];
                        let run = |compiled: &Compiled| {
                            let ctx = exec::context(StateValue::Null, [0u8; 32]);
                            exec::execute(&compiled.ir, &Call::new(&args, &[]), &ctx)
                        };
                        let (a, b) = (run(&lean), run(&de_morgan));
                        let refused_by_circuit = |r: &Result<_, ExecError>| match r {
                            Ok(_) => false,
                            Err(ExecError::Rejected { .. } | ExecError::Circuit(_)) => true,
                            Err(other) => panic!("not a circuit verdict: {other}"),
                        };
                        assert_eq!(
                            refused_by_circuit(&a),
                            refused_by_circuit(&b),
                            "{left_name} || {right_name} on {args:?}: lean {:?}, De Morgan {:?}",
                            a.as_ref().err(),
                            b.as_ref().err()
                        );
                        if a.is_ok() { accepted += 1 } else { refused += 1 }
                    }
                }
            }
        }
    }
    // Both verdicts were reached: every bit pair accepts once (z its value)
    // and every non-bit operand the old form saw refuses.
    assert!(accepted > 0 && refused > accepted, "accepted {accepted}, refused {refused}");
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

/// An unasserted predicate emits nothing — strictly safer than an unasserted
/// `c.less_than(..)`, which emits cost and constrains nothing.
#[test]
fn an_unasserted_predicate_emits_nothing() {
    let mut c = Circuit::new();
    let a = Uint::<128, Private>::from_field_unchecked(c.arg::<FieldT>("a"));
    let before = c.instruction_count();
    let _dropped = less_than(0u64, a).and(le(a, u64::MAX)).message("unused");
    assert_eq!(c.instruction_count(), before);
}

/// The message is metadata: the stream is identical with and without it, and
/// the compiled circuit can name the assert that failed.
#[test]
fn a_message_costs_nothing_and_is_recorded() {
    let build = |message: bool| {
        let mut c = Circuit::new();
        let a = Uint::<64, Private>::from_field_unchecked(c.arg::<FieldT>("a"));
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
/// ordering needs at least one width to run at. Neither is a test here,
/// because neither is a runtime failure any more: both are
/// inline-`const` asserts in the constructors, so
///
/// ```compile_fail
/// # use minocrab::{Circuit, FieldT};
/// # use minocrab::Private;
/// # use minocrab_std::{less_than, Uint};
/// let mut c = Circuit::new();
/// let a = Uint::<128, Private>::from_field_unchecked(c.arg::<FieldT>("a"));
/// let b = Uint::<64, Private>::from_field_unchecked(c.arg::<FieldT>("b"));
/// c.assert(less_than(a, b));  // error[E0080]: … different widths …
/// ```
///
/// and
///
/// ```compile_fail
/// # use minocrab::{Circuit, FieldT};
/// # use minocrab_std::less_than;
/// let mut c = Circuit::new();
/// let a = c.arg::<FieldT>("a");
/// let b = c.arg::<FieldT>("b");
/// c.assert(less_than(a, b));  // error[E0080]: … needs a width …
/// ```
///
/// are build errors at the call site, not panics when the circuit is built.
/// (Both messages are checked by hand; there is no trybuild in the lock file,
/// and `compile_fail` doc-tests do not run for a test target — this block is
/// the record of the two spellings that must not compile.)
const _COMPILE_ERRORS_NOT_PANICS: () = ();

/// Equality needs no width, so raw wires are fine there.
#[test]
fn equality_of_raw_wires_is_allowed() {
    let mut c = Circuit::new();
    let a = c.arg::<FieldT>("a");
    let b = c.arg::<FieldT>("b");
    c.assert(eq(a, b));
    assert_eq!(c.instruction_count(), 2);
}

/// The constant side is a checked immediate.
#[test]
#[should_panic(expected = "does not fit the 8 bits")]
fn a_literal_wider_than_the_comparison_is_rejected() {
    let mut c = Circuit::new();
    let byte = Bytes::<1, Private>::from_field_unchecked(c.arg::<FieldT>("byte"));
    c.assert(less_than(byte, 300u64));
}

/// A public comparison stays public; a private operand makes it private.
#[test]
fn visibility_follows_the_meet() {
    let mut c = Circuit::new();
    let secret = Uint::<64, Private>::from_field_unchecked(c.arg::<FieldT>("secret"));
    let public = Uint::<64, Public>::from_field_unchecked(c.public_transcript_input::<FieldT>());

    let _private: Bool<Private> = less_than(0u64, secret).eval(&mut c);
    let _public: Bool<Public> = less_than(0u64, public).eval(&mut c);
    let _mixed: Bool<Private> = less_than(secret, public).eval(&mut c);
}

/// The boolean leaf (candidate 5) costs nothing: `is_true(b)` and
/// the bare wire are the same stream, so `.message(..)` and the combinators
/// reach a computed boolean (a map `member` result) for free.
#[test]
fn is_true_is_the_wire_itself() {
    let build = |leaf: bool| {
        let mut c = Circuit::new();
        let b = Bool::<Private>::from_field_unchecked(c.arg::<FieldT>("b"));
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
        let mut c = Circuit::new();
        let b = Bool::<Private>::from_field_unchecked(c.arg::<FieldT>("b"));
        let a = Uint::<64, Private>::from_field_unchecked(c.arg::<FieldT>("a"));
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

/// The in-branch assert (candidate 6; notes/edsl-trim.org §B) is
/// the scope, not a `Check` method: `c.when(g, |c| c.assert(p))` lowers to
/// `assert(select(guard, cond, 1))`, with the `1` inline — the same
/// instruction `Check::when` used to build by hand.
#[test]
fn when_is_the_in_branch_assert() {
    let build = |predicates: bool| {
        let mut c = Circuit::new();
        let a = Uint::<64, Private>::from_field_unchecked(c.arg::<FieldT>("a"));
        let b = Uint::<64, Private>::from_field_unchecked(c.arg::<FieldT>("b"));
        let guard = c.public_transcript_input::<FieldT>();
        if predicates {
            c.when(guard, |c| {
                c.assert(less_than(a, b).message("Not the withdrawer"));
            });
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

/// A guard may be public over a private check — the common case, a public
/// branch condition gating a secret comparison.
#[test]
fn a_public_guard_gates_a_private_check() {
    let mut c = Circuit::new();
    let secret = Uint::<64, Private>::from_field_unchecked(c.arg::<FieldT>("secret"));
    let guard = c.public_transcript_input::<FieldT>();
    c.when(guard, |c| {
        c.assert(less_than(0u64, secret));
    });
}

/// `.widen::<W>()` (dmd's decision A) is free: the same wire, no instruction,
/// and no second range constraint — so a widened comparison is the
/// hand-written comparison at the wider width.
#[test]
fn widen_is_free_and_compares_at_the_wider_width() {
    let build = |widened: bool| {
        let mut c = Circuit::new();
        let narrow = Uint::<64, Private>::from_field_unchecked(c.arg::<FieldT>("narrow"));
        let wide = Uint::<128, Private>::from_field_unchecked(c.arg::<FieldT>("wide"));
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
    let mut c = Circuit::new();
    let narrow = Uint::<64, Private>::from_field_unchecked(c.arg::<FieldT>("narrow"));
    let before = c.instruction_count();
    let _wide: Uint<128, Private> = narrow.widen();
    assert_eq!(c.instruction_count(), before);
}

// --- a literal outside the operand's bound (dmd, 2026-08-16) ---------------
//
// The width check above is not enough once bounded integers are in play: a
// `BoundedUint<300>` compares at 9 bits, so `500` fits the width and is still
// a value the operand can never take. The comparison is then a constant, which
// is a bug in every case we can construct.

/// dmd's own example: `b.lt(500u64)` on a `BoundedUint<300>` used to compile
/// and be always true.
#[test]
#[should_panic(expected = "is larger than the largest value the operand it is compared with can hold (299)")]
fn a_literal_above_the_bound_is_rejected() {
    let mut c = Circuit::new();
    let b = BoundedUint::<300, Private>::from_field_unchecked(c.arg::<FieldT>("b"));
    c.assert(less_than(b, 500u64));
}

/// The bound is exclusive, so the largest legal value is `BOUND - 1` and a
/// literal at it is fine: `b < 299` is a real question.
#[test]
fn a_literal_at_the_bound_is_accepted() {
    let mut c = Circuit::new();
    let b = BoundedUint::<300, Private>::from_field_unchecked(c.arg::<FieldT>("b"));
    c.assert(less_than(b, 299u64));
}

/// The check reads the other operand's type, so it fires with the literal on
/// either side.
#[test]
#[should_panic(expected = "is larger than the largest value the operand it is compared with can hold (299)")]
fn a_literal_above_the_bound_is_rejected_on_the_left() {
    let mut c = Circuit::new();
    let b = BoundedUint::<300, Private>::from_field_unchecked(c.arg::<FieldT>("b"));
    c.assert(greater_than(500u64, b));
}

/// It applies to plain widths too, where it agrees with the width check
/// rather than replacing it: 300 is not a value a `Uint<8>` can take.
#[test]
#[should_panic(expected = "does not fit the 8 bits")]
fn a_literal_above_a_plain_width_is_still_rejected() {
    let mut c = Circuit::new();
    let byte = Uint::<8, Private>::from_field_unchecked(c.arg::<FieldT>("byte"));
    c.assert(less_than(byte, 300u64));
}

// --- subtraction carries Compact's guard (notes/api-safety-survey.org §B1) --
//
// compactc inserts `assert(a >= b, "result of subtraction would be negative")`
// before every subtraction and then lowers it as neg + add. `Uint::sub` is
// that, in that order, at that width — so these tests are the claim, not a
// smoke check.

/// `a.sub(c, b)` is byte-identical to the hand-written guard-then-subtract,
/// which is compactc's own lowering.
#[test]
fn sub_is_compactcs_guarded_lowering() {
    let by_hand = zkir({
        let mut c = Circuit::new();
        let a = Uint::<64, Private>::from_field_unchecked(c.arg::<FieldT>("a"));
        let b = Uint::<64, Private>::from_field_unchecked(c.arg::<FieldT>("b"));
        // the guard compactc emits, at compactc's width (64 = intlen(max))
        c.assert(ge(a, b).message("result of subtraction would be negative"));
        let negated = c.neg(b.field());
        let _ = c.add(a.field(), negated);
        c.finish(true)
    });
    let typed = zkir({
        let mut c = Circuit::new();
        let a = Uint::<64, Private>::from_field_unchecked(c.arg::<FieldT>("a"));
        let b = Uint::<64, Private>::from_field_unchecked(c.arg::<FieldT>("b"));
        let _ = a.sub(&mut c, b);
        c.finish(true)
    });
    assert_eq!(by_hand, typed);
}

/// The guard is not optional and not elidable: a subtraction emits an
/// `assert`, where the raw `c.add(a, c.neg(b))` emits none. This is the
/// difference the survey is about, pinned so a future "optimisation" that
/// drops it fails here.
#[test]
fn the_raw_spelling_has_no_guard_and_the_typed_one_does() {
    let raw = zkir({
        let mut c = Circuit::new();
        let a = c.arg::<FieldT>("a");
        let b = c.arg::<FieldT>("b");
        let negated = c.neg(b);
        let _ = c.add(a, negated);
        c.finish(true)
    });
    let typed = zkir({
        let mut c = Circuit::new();
        let a = Uint::<64, Private>::from_field_unchecked(c.arg::<FieldT>("a"));
        let b = Uint::<64, Private>::from_field_unchecked(c.arg::<FieldT>("b"));
        let _ = a.sub(&mut c, b);
        c.finish(true)
    });
    assert!(!raw.contains("\"assert\""), "the raw spelling emits no guard: {raw}");
    assert!(typed.contains("\"assert\""), "the typed one must: {typed}");
    assert!(
        typed.contains("\"less_than\"") && typed.contains("\"bits\":64"),
        "and the guard compares at the TYPE's width, not a number typed here: {typed}"
    );
}

/// The result keeps `BITS` — compactc's rule (result type `Uint<maxa>`),
/// sound because `a - b <= a < 2^BITS`. Checked by using the result where a
/// `Uint<64>` is required.
#[test]
fn sub_keeps_the_left_operands_width() {
    let mut c = Circuit::new();
    let a = Uint::<64, Private>::from_field_unchecked(c.arg::<FieldT>("a"));
    let b = Uint::<64, Private>::from_field_unchecked(c.arg::<FieldT>("b"));
    let d: Uint<64, Private> = a.sub(&mut c, b);
    // and it composes: the difference compares at 64 bits like any Uint<64>
    c.assert(ge(d, b));
}
