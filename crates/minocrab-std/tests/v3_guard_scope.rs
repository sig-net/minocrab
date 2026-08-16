//! `Circuit3::guarded` — the scoped guard, against the hand-threaded form.
//!
//! THE CLAIM that makes it safe to adopt: for every shape a guard can apply
//! to, `guarded(g, |c| plain(c, ..))` emits the SAME instructions as
//! `plain_under(c, g, ..)` — byte for byte, in the same order. The scope is
//! a way of writing the guard down, not a different lowering, so the
//! differentials cannot tell the two apart and existing call sites can move
//! across one at a time.
//!
//! Plus the two things the scoped form does that the threaded form leaves to
//! the caller: it guards transcript READS without a `_guarded` variant, and
//! it guards ASSERTIONS — which by hand is a rule in a doc comment that
//! nothing checks.

use minocrab::v3::{Circuit3, FieldT, ImpactElem};
use minocrab::Fr;
use minocrab_zkir::v3::to_zkir_string;

fn zkir(build: impl FnOnce(&mut Circuit3)) -> String {
    let mut c = Circuit3::new();
    build(&mut c);
    to_zkir_string(&c.finish(true).ir).expect("serializes")
}

/// Three Impact elements standing in for any ledger operation.
fn op() -> [ImpactElem; 2] {
    [
        ImpactElem::Imm(Fr::from(0x70u64)),
        ImpactElem::Imm(Fr::from(0x01u64)),
    ]
}

#[test]
fn a_scoped_guard_is_the_threaded_guard() {
    let threaded = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        c.impact_mixed(g, &op());
        c.impact_mixed(g, &op());
    });
    let scoped = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        c.when(g, |c| {
            c.impact_mixed(1u64, &op());
            c.impact_mixed(1u64, &op());
        });
    });
    assert_eq!(scoped, threaded);
}

#[test]
fn a_scoped_guard_reaches_transcript_reads() {
    let threaded = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let w = c.public_transcript_input_guarded::<FieldT, _>(g);
        c.impact_mixed(g, &[ImpactElem::Wire(w)]);
    });
    let scoped = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        c.when(g, |c| {
            let w = c.public_transcript_input::<FieldT>();
            c.impact_mixed(1u64, &[ImpactElem::Wire(w)]);
        });
    });
    assert_eq!(scoped, threaded);
}

/// THE ONE THAT IS NOT JUST ERGONOMICS. Written by hand, an assertion inside
/// a conditional has to be wrapped in `select(guard, cond, 1)` by the caller
/// — and if it is not, it fires on the branch that was not taken, which no
/// differential test on an honest preimage can see.
#[test]
fn a_scoped_guard_reaches_assertions() {
    let by_hand = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let cond = c.arg::<FieldT>("cond");
        let held = c.cond_select(g, cond, 1u64);
        c.assert(held);
    });
    let scoped = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let cond = c.arg::<FieldT>("cond");
        c.when(g, |c| c.assert(cond));
    });
    assert_eq!(scoped, by_hand);
}

/// Nesting IS Compact's `&&`, and the conjunction is computed once on entry
/// rather than per operation — so two operations under `a && b` cost one
/// `cond_select`, not two.
#[test]
fn nesting_is_a_single_conjunction() {
    let by_hand = zkir(|c| {
        let a = c.arg::<FieldT>("a");
        let b = c.arg::<FieldT>("b");
        let both = c.cond_select(a, b, 0u64);
        c.impact_mixed(both, &op());
        c.impact_mixed(both, &op());
    });
    let scoped = zkir(|c| {
        let a = c.arg::<FieldT>("a");
        let b = c.arg::<FieldT>("b");
        c.when(a, |c| {
            c.when(b, |c| {
                c.impact_mixed(1u64, &op());
                c.impact_mixed(1u64, &op());
            });
        });
    });
    assert_eq!(scoped, by_hand);
}

/// The shape M17's `send_unshielded` needed and had to build by hand: a read
/// under the OUTER guard alone, then the effect under the conjunction. It
/// falls out of the nesting rather than having to be discovered in an
/// artifact.
#[test]
fn a_read_between_two_scopes_is_guarded_by_the_outer_one() {
    let by_hand = zkir(|c| {
        let a = c.arg::<FieldT>("a");
        let w = c.public_transcript_input_guarded::<FieldT, _>(a);
        let both = c.cond_select(a, w, 0u64);
        c.impact_mixed(both, &op());
    });
    let scoped = zkir(|c| {
        let a = c.arg::<FieldT>("a");
        c.when(a, |c| {
            let w = c.public_transcript_input::<FieldT>();
            c.when(w, |c| c.impact_mixed(1u64, &op()));
        });
    });
    assert_eq!(scoped, by_hand);
}

/// `otherwise` runs under the negation, computed once.
#[test]
fn a_chain_negates_once() {
    let by_hand = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        c.impact_mixed(g, &op());
        let not_g = c.cond_select(g, 0u64, 1u64);
        c.impact_mixed(not_g, &op());
        c.impact_mixed(not_g, &op());
    });
    let scoped = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        c.when(g, |c| c.impact_mixed(1u64, &op())).otherwise(|c| {
            c.impact_mixed(1u64, &op());
            c.impact_mixed(1u64, &op());
        });
    });
    assert_eq!(scoped, by_hand);
}

// ---- the predicate vocabulary as guards -------------------------------------

/// A guard written as a `Check` is the same guard: the predicate layer and
/// the guard layer are one language.
#[test]
fn a_check_guards_exactly_as_its_wire_does() {
    use minocrab_std::v3::{eq, Uint};

    let by_wire = zkir(|c| {
        let x = c.arg::<FieldT>("x");
        let y = c.arg::<FieldT>("y");
        let same = c.test_eq(x, y);
        c.when(same, |c| c.impact_mixed(1u64, &op()));
    });
    let by_check = zkir(|c| {
        let x: Uint<64> = Uint::from_field(c.arg::<FieldT>("x"));
        let y: Uint<64> = Uint::from_field(c.arg::<FieldT>("y"));
        c.when(eq(x, y), |c| c.impact_mixed(1u64, &op()));
    });
    assert_eq!(by_check, by_wire);
}

// ---- if / else-if / else chains ---------------------------------------------

/// A bare `when` — a plain `if` with no `else` — emits NOTHING beyond the
/// arm. The accumulator is only computed when another arm arrives, which
/// matters because an unused instruction is a real row (backend_folding.rs).
#[test]
fn a_bare_when_emits_no_accumulator() {
    let threaded = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        c.impact_mixed(g, &op());
    });
    let bare = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        c.when(g, |c| c.impact_mixed(1u64, &op()));
    });
    assert_eq!(bare, threaded);
}

/// THE CLAIM that makes a chain a chain: arm two runs where its own condition
/// holds AND arm one did not match, and the final arm where NEITHER did.
#[test]
fn chain_arms_are_exclusive() {
    let by_hand = zkir(|c| {
        let a = c.arg::<FieldT>("a");
        let b = c.arg::<FieldT>("b");
        // arm 1: a
        c.impact_mixed(a, &op());
        // arm 2: !a && b
        let not_a = c.cond_select(a, 0u64, 1u64);
        let arm2 = c.cond_select(not_a, b, 0u64);
        c.impact_mixed(arm2, &op());
        // otherwise: !a && !b
        let rest = c.cond_select(b, 0u64, not_a);
        c.impact_mixed(rest, &op());
    });
    let by_chain = zkir(|c| {
        let a = c.arg::<FieldT>("a");
        let b = c.arg::<FieldT>("b");
        c.when(a, |c| c.impact_mixed(1u64, &op()))
            .else_when(b, |c| c.impact_mixed(1u64, &op()))
            .otherwise(|c| c.impact_mixed(1u64, &op()));
    });
    assert_eq!(by_chain, by_hand);
}

/// A chain arm can be written in the predicate vocabulary too.
#[test]
fn chain_arms_take_checks() {
    use minocrab_std::v3::{eq, Uint};

    let by_wire = zkir(|c| {
        let x = c.arg::<FieldT>("x");
        let y = c.arg::<FieldT>("y");
        let same = c.test_eq(x, y);
        c.when(same, |c| c.impact_mixed(1u64, &op()))
            .otherwise(|c| c.impact_mixed(1u64, &op()));
    });
    let by_check = zkir(|c| {
        let x: Uint<64> = Uint::from_field(c.arg::<FieldT>("x"));
        let y: Uint<64> = Uint::from_field(c.arg::<FieldT>("y"));
        c.when(eq(x, y), |c| c.impact_mixed(1u64, &op()))
            .otherwise(|c| c.impact_mixed(1u64, &op()));
    });
    assert_eq!(by_check, by_wire);
}

/// A chain nests inside a guard, and its arms pick that up — so an
/// if/else-if inside a branch needs no threading either.
#[test]
fn a_chain_inside_a_guard_is_conjoined_with_it() {
    let by_hand = zkir(|c| {
        let outer = c.arg::<FieldT>("outer");
        let a = c.arg::<FieldT>("a");
        let arm1 = c.cond_select(outer, a, 0u64);
        c.impact_mixed(arm1, &op());
        let not_a = c.cond_select(a, 0u64, 1u64);
        let arm2 = c.cond_select(outer, not_a, 0u64);
        c.impact_mixed(arm2, &op());
    });
    let scoped = zkir(|c| {
        let outer = c.arg::<FieldT>("outer");
        let a = c.arg::<FieldT>("a");
        c.when(outer, |c| {
            c.when(a, |c| c.impact_mixed(1u64, &op()))
                .otherwise(|c| c.impact_mixed(1u64, &op()));
        });
    });
    assert_eq!(scoped, by_hand);
}

// ---- the value form ----------------------------------------------------------

/// A two-arm VALUE chain is the hand-written form: both arms emitted, one
/// `cond_select` to choose. The abstraction costs nothing over doing it by
/// hand — what it removes is the chance of selecting on the wrong guard.
#[test]
fn a_value_chain_is_the_hand_written_select() {
    let by_hand = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let x = c.arg::<FieldT>("x");
        let y = c.arg::<FieldT>("y");
        let a = c.mul(x, y); // "then" arm
        let not_g = c.cond_select(g, 0u64, 1u64);
        let b = c.add(x, y); // "else" arm — emitted regardless
        let chosen = c.cond_select(not_g, b, a);
        c.assert(chosen);
    });
    let by_chain = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let x = c.arg::<FieldT>("x");
        let y = c.arg::<FieldT>("y");
        let chosen = c
            .when_value(g, |c| c.mul(x, y))
            .otherwise(|c| c.add(x, y));
        c.assert(chosen);
    });
    assert_eq!(by_chain, by_hand);
}

/// The value form selects EVERY slot of a multi-slot leaf — a `Bytes<32>`
/// costs two selects per arm, not one.
#[test]
fn a_value_chain_selects_every_slot() {
    use minocrab_std::v3::B32;

    let by_hand = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let a = B32 {
            hi: c.arg::<FieldT>("ahi"),
            lo: c.arg::<FieldT>("alo"),
        };
        let b = B32 {
            hi: c.arg::<FieldT>("bhi"),
            lo: c.arg::<FieldT>("blo"),
        };
        let not_g = c.cond_select(g, 0u64, 1u64);
        let hi = c.cond_select(not_g, b.hi, a.hi);
        let lo = c.cond_select(not_g, b.lo, a.lo);
        c.assert(hi);
        c.assert(lo);
    });
    let by_chain = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let a = B32 {
            hi: c.arg::<FieldT>("ahi"),
            lo: c.arg::<FieldT>("alo"),
        };
        let b = B32 {
            hi: c.arg::<FieldT>("bhi"),
            lo: c.arg::<FieldT>("blo"),
        };
        let chosen = c.when_value(g, |_c| a).otherwise(|_c| b);
        c.assert(chosen.hi);
        c.assert(chosen.lo);
    });
    assert_eq!(by_chain, by_hand);
}

/// A value chain still GUARDS its arms' effects — the value is selected and
/// the effects are suppressed, by the same mechanism.
#[test]
fn a_value_chain_still_guards_effects() {
    let by_hand = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let x = c.arg::<FieldT>("x");
        c.impact_mixed(g, &op());
        let not_g = c.cond_select(g, 0u64, 1u64);
        c.impact_mixed(not_g, &op());
        let chosen = c.cond_select(not_g, x, x);
        c.assert(chosen);
    });
    let by_chain = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let x = c.arg::<FieldT>("x");
        let chosen = c
            .when_value(g, |c| {
                c.impact_mixed(1u64, &op());
                x
            })
            .otherwise(|c| {
                c.impact_mixed(1u64, &op());
                x
            });
        c.assert(chosen);
    });
    assert_eq!(by_chain, by_hand);
}
