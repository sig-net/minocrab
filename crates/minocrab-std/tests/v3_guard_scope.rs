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
use minocrab::{Fr, Public};
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
        let g = c.disclose(g, "g");
        c.impact_mixed(g, &op());
        c.impact_mixed(g, &op());
    });
    let scoped = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let g = c.disclose(g, "g");
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
        let g = c.disclose(g, "g");
        let w = c.public_transcript_input_guarded::<FieldT, _>(g);
        c.impact_mixed(g, &[ImpactElem::Wire(w)]);
    });
    let scoped = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let g = c.disclose(g, "g");
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
        let g = c.disclose(g, "g");
        let cond = c.arg::<FieldT>("cond");
        let cond = c.disclose(cond, "cond");
        let held = c.cond_select(g, cond, 1u64);
        c.assert(held);
    });
    let scoped = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let g = c.disclose(g, "g");
        let cond = c.arg::<FieldT>("cond");
        let cond = c.disclose(cond, "cond");
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
        let a = c.disclose(a, "a");
        let b = c.arg::<FieldT>("b");
        let b = c.disclose(b, "b");
        let both = c.cond_select(a, b, 0u64);
        c.impact_mixed(both, &op());
        c.impact_mixed(both, &op());
    });
    let scoped = zkir(|c| {
        let a = c.arg::<FieldT>("a");
        let a = c.disclose(a, "a");
        let b = c.arg::<FieldT>("b");
        let b = c.disclose(b, "b");
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
        let a = c.disclose(a, "a");
        let w = c.public_transcript_input_guarded::<FieldT, _>(a);
        let both = c.cond_select(a, w, 0u64);
        c.impact_mixed(both, &op());
    });
    let scoped = zkir(|c| {
        let a = c.arg::<FieldT>("a");
        let a = c.disclose(a, "a");
        c.when(a, |c| {
            let w = c.public_transcript_input::<FieldT>();
            c.when(w, |c| c.impact_mixed(1u64, &op()));
        });
    });
    assert_eq!(scoped, by_hand);
}

/// A `_guarded` transcript read called INSIDE a DIFFERENT ambient scope must
/// conjoin the two guards — gate on `a && b`, not on the explicit `b` alone.
///
/// REGRESSION for the bug the AA-manager port exposed (2026-08-27,
/// `sendUnshielded`'s auto-receive `kernel.self` read inside
/// `custodyDispatch`'s `isWithdrawUnshielded` arm): before the fix,
/// `public_transcript_input_guarded` used its explicit guard directly and did
/// NOT resolve against the ambient scope, so the read's PI gates fired on `b`
/// while its op embed (which always resolves through `resolve_guard`) stayed
/// skipped under `a && b` — shifting every later read's public inputs. The two
/// builds below must be byte-identical: a plain read nested one scope deeper
/// gates on `a && b`, and so must `input_guarded(b)` under `when(a)`.
#[test]
fn a_guarded_read_inside_a_scope_conjoins_both_guards() {
    let nested = zkir(|c| {
        let a = c.arg::<FieldT>("a");
        let a = c.disclose(a, "a");
        let b = c.arg::<FieldT>("b");
        let b = c.disclose(b, "b");
        c.when(a, |c| {
            c.when(b, |c| {
                let _w = c.public_transcript_input::<FieldT>();
            });
        });
    });
    let guarded = zkir(|c| {
        let a = c.arg::<FieldT>("a");
        let a = c.disclose(a, "a");
        let b = c.arg::<FieldT>("b");
        let b = c.disclose(b, "b");
        c.when(a, |c| {
            let _w = c.public_transcript_input_guarded::<FieldT, _>(b);
        });
    });
    assert_eq!(nested, guarded);
}

/// `otherwise` runs under the negation, computed once.
#[test]
fn a_chain_negates_once() {
    let by_hand = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let g = c.disclose(g, "g");
        c.impact_mixed(g, &op());
        let not_g = c.cond_select(g, 0u64, 1u64);
        c.impact_mixed(not_g, &op());
        c.impact_mixed(not_g, &op());
    });
    let scoped = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let g = c.disclose(g, "g");
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
        let x = c.disclose(x, "x");
        let y = c.arg::<FieldT>("y");
        let y = c.disclose(y, "y");
        let same = c.test_eq(x, y);
        c.when(same, |c| c.impact_mixed(1u64, &op()));
    });
    let by_check = zkir(|c| {
        let x = c.arg::<FieldT>("x");
        let x = c.disclose(x, "x");
        let y = c.arg::<FieldT>("y");
        let y = c.disclose(y, "y");
        let x: Uint<64, Public> = Uint::from_field_unchecked(x);
        let y: Uint<64, Public> = Uint::from_field_unchecked(y);
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
        let g = c.disclose(g, "g");
        c.impact_mixed(g, &op());
    });
    let bare = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let g = c.disclose(g, "g");
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
        let a = c.disclose(a, "a");
        let b = c.arg::<FieldT>("b");
        let b = c.disclose(b, "b");
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
        let a = c.disclose(a, "a");
        let b = c.arg::<FieldT>("b");
        let b = c.disclose(b, "b");
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
        let x = c.disclose(x, "x");
        let y = c.arg::<FieldT>("y");
        let y = c.disclose(y, "y");
        let same = c.test_eq(x, y);
        c.when(same, |c| c.impact_mixed(1u64, &op()))
            .otherwise(|c| c.impact_mixed(1u64, &op()));
    });
    let by_check = zkir(|c| {
        let x = c.arg::<FieldT>("x");
        let x = c.disclose(x, "x");
        let y = c.arg::<FieldT>("y");
        let y = c.disclose(y, "y");
        let x: Uint<64, Public> = Uint::from_field_unchecked(x);
        let y: Uint<64, Public> = Uint::from_field_unchecked(y);
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
        let outer = c.disclose(outer, "outer");
        let a = c.arg::<FieldT>("a");
        let a = c.disclose(a, "a");
        let arm1 = c.cond_select(outer, a, 0u64);
        c.impact_mixed(arm1, &op());
        let not_a = c.cond_select(a, 0u64, 1u64);
        let arm2 = c.cond_select(outer, not_a, 0u64);
        c.impact_mixed(arm2, &op());
    });
    let scoped = zkir(|c| {
        let outer = c.arg::<FieldT>("outer");
        let outer = c.disclose(outer, "outer");
        let a = c.arg::<FieldT>("a");
        let a = c.disclose(a, "a");
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
        let g = c.disclose(g, "g");
        let x = c.arg::<FieldT>("x");
        let x = c.disclose(x, "x");
        let y = c.arg::<FieldT>("y");
        let y = c.disclose(y, "y");
        let a = c.mul(x, y); // "then" arm
        let not_g = c.cond_select(g, 0u64, 1u64);
        let b = c.add(x, y); // "else" arm — emitted regardless
        let chosen = c.cond_select(not_g, b, a);
        c.assert(chosen);
    });
    let by_chain = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let g = c.disclose(g, "g");
        let x = c.arg::<FieldT>("x");
        let x = c.disclose(x, "x");
        let y = c.arg::<FieldT>("y");
        let y = c.disclose(y, "y");
        let chosen = c
            .when_value(g, |c| c.mul(x, y))
            .otherwise(|c| c.add(x, y));
        c.assert(chosen.into_inner());
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
        let g = c.disclose(g, "g");
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
        let g = c.disclose(g, "g");
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
        let g = c.disclose(g, "g");
        let x = c.arg::<FieldT>("x");
        let x = c.disclose(x, "x");
        c.impact_mixed(g, &op());
        let not_g = c.cond_select(g, 0u64, 1u64);
        c.impact_mixed(not_g, &op());
        let chosen = c.cond_select(not_g, x, x);
        c.assert(chosen);
    });
    let by_chain = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let g = c.disclose(g, "g");
        let x = c.arg::<FieldT>("x");
        let x = c.disclose(x, "x");
        let chosen = c
            .when_value(g, |c| {
                c.impact_mixed(1u64, &op());
                x
            })
            .otherwise(|c| {
                c.impact_mixed(1u64, &op());
                x
            });
        c.assert(chosen.into_inner());
    });
    assert_eq!(by_chain, by_hand);
}

/// THE COST OF A VALUE CHAIN, as a number rather than a description — so the
/// figure quoted in `when_value`'s docs cannot rot.
///
/// Three arms returning a `Bytes<32>` (two native slots), over a baseline
/// that runs the same three bodies unconditionally.
#[test]
fn a_three_arm_value_chain_costs_what_the_docs_say() {
    use minocrab_std::v3::B32;

    fn instrs(build: impl FnOnce(&mut Circuit3)) -> usize {
        let mut c = Circuit3::new();
        build(&mut c);
        c.finish(true).ir.instructions.len()
    }

    let bodies_only = instrs(|c| {
        let a = B32 { hi: c.arg::<FieldT>("a0"), lo: c.arg::<FieldT>("a1") };
        c.assert(a.hi);
        c.assert(a.lo);
    });
    let chained = instrs(|c| {
        let p = c.arg::<FieldT>("p");
        let p = c.disclose(p, "p");
        let q = c.arg::<FieldT>("q");
        let q = c.disclose(q, "q");
        let a = B32 { hi: c.arg::<FieldT>("a0"), lo: c.arg::<FieldT>("a1") };
        let chosen = c
            .when_value(p, |_c| a)
            .else_when(q, |_c| a)
            .otherwise(|_c| a);
        c.assert(chosen.hi);
        c.assert(chosen.lo);
    });

    // 3 selects to thread the guards (none for the first arm, two for the
    // middle, one for the fallback) + 4 to choose the value (two slots for
    // each arm after the first).
    assert_eq!(chained - bodies_only, 7);
}

/// ...and it reaches WITNESSES, which is the fourth shape and the one with a
/// semantic rather than a framing difference.
///
/// A guarded private input yields the default and does NOT consume the
/// private transcript when its guard is false. So a witness read unguarded
/// inside a branch consumes a value on the path that was not taken — the
/// witness STREAM moves, which no differential on an honest preimage can see.
/// The scope closes that the same way it closes the assertion case.
#[test]
fn a_scoped_guard_reaches_witnesses() {
    let threaded = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let g = c.disclose(g, "g");
        let _ = c.witness_guarded::<FieldT, _>(g);
    });
    let scoped = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let g = c.disclose(g, "g");
        c.when(g, |c| {
            let _ = c.witness::<FieldT>();
        });
    });
    assert_eq!(threaded, scoped);
}

/// Outside every scope a witness is unguarded, which is what the 167
/// pre-existing circuits emit — the ambient guard adds a gate, it does not
/// impose one.
#[test]
fn an_unscoped_witness_carries_no_guard() {
    let ir = zkir(|c| {
        let _ = c.witness::<FieldT>();
    });
    assert!(
        ir.contains("\"guard\":null"),
        "an unscoped witness must have no guard: {ir}"
    );
}

// --- `Guarded<T>`: the guarded read's value, and what naming it costs -------
//
// A guarded-off gate yields the type's DEFAULT and skips the transcript
// (upstream `ir_vm.rs:348-366`). `Guarded<T>` makes the caller say which they
// mean instead of handing back a value that is silently zero on a path they
// were not thinking about. These three tests are its price list.

/// `or_default()` is FREE — the whole point. The gate already produced the
/// default; naming that fact must not emit an instruction, or the type would
/// be a tax on the honest case.
#[test]
fn or_default_emits_nothing() {
    let bare = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let g = c.disclose(g, "g");
        let _ = c.witness_guarded::<FieldT, _>(g);
    });
    let named = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let g = c.disclose(g, "g");
        let _ = minocrab::v3::Guarded::new(c.witness_guarded::<FieldT, _>(g), g).or_default();
    });
    assert_eq!(bare, named);
}

/// `or(fallback)` costs exactly the `cond_select` a careful author writes by
/// hand, on the same guard and in the same order.
#[test]
fn or_is_the_hand_written_select() {
    let by_hand = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let g = c.disclose(g, "g");
        let alt = c.arg::<FieldT>("alt");
        let read = c.witness_guarded::<FieldT, _>(g);
        let _ = c.cond_select(g, read, alt);
    });
    let wrapped = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let g = c.disclose(g, "g");
        let alt = c.arg::<FieldT>("alt");
        let read = minocrab::v3::Guarded::new(c.witness_guarded::<FieldT, _>(g), g);
        let _ = read.or(c, alt);
    });
    assert_eq!(by_hand, wrapped);
}

/// `assert_read()` is one `Assert` on the guard — the caller stating that the
/// branch must have been taken, which makes the circuit unsatisfiable where
/// it was not.
#[test]
fn assert_read_is_one_assert_on_the_guard() {
    let by_hand = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let g = c.disclose(g, "g");
        let _ = c.witness_guarded::<FieldT, _>(g);
        c.assert(g);
    });
    let wrapped = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let g = c.disclose(g, "g");
        let _ = minocrab::v3::Guarded::new(c.witness_guarded::<FieldT, _>(g), g).assert_read(c);
    });
    assert_eq!(by_hand, wrapped);
}

// --- the effect choke point (review §4.2, §4.3) ----------------------------------------
//
// Every check entry point and every `_guarded` read resolves its guard
// through one private function (minocrab/src/v3/effects.rs). These pin the
// three cells of the old method-by-method table that were wrong, each
// against the hand-threaded lowering it must equal byte for byte.

/// §4.2: `assert_eq` inside a scope is compactc's `assert(a == b)` in a
/// branch — `test_eq`, then `assert(select(guard, eq, 1))`.
#[test]
fn a_scoped_guard_reaches_assert_eq() {
    let by_hand = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let g = c.disclose(g, "g");
        let a = c.arg::<FieldT>("a");
        let a = c.disclose(a, "a");
        let b = c.arg::<FieldT>("b");
        let b = c.disclose(b, "b");
        let eq = c.test_eq(a, b);
        let held = c.cond_select(g, eq, 1u64);
        c.assert(held);
    });
    let scoped = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let g = c.disclose(g, "g");
        let a = c.arg::<FieldT>("a");
        let a = c.disclose(a, "a");
        let b = c.arg::<FieldT>("b");
        let b = c.disclose(b, "b");
        c.when(g, |c| c.assert_eq(a, b));
    });
    assert_eq!(by_hand, scoped);
}

/// §4.2: `assert_bits` and `assert_boolean` inside a scope check
/// `select(guard, w, 0)` — zero satisfies both, so the constraint holds
/// wherever the guard is off.
#[test]
fn a_scoped_guard_reaches_range_checks() {
    let by_hand = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let g = c.disclose(g, "g");
        let w = c.arg::<FieldT>("w");
        let w = c.disclose(w, "w");
        let b = c.arg::<FieldT>("b");
        let b = c.disclose(b, "b");
        let w_or_zero = c.cond_select(g, w, 0u64);
        c.assert_bits(w_or_zero, 8);
        let b_or_zero = c.cond_select(g, b, 0u64);
        c.assert_boolean(b_or_zero);
    });
    let scoped = zkir(|c| {
        let g = c.arg::<FieldT>("g");
        let g = c.disclose(g, "g");
        let w = c.arg::<FieldT>("w");
        let w = c.disclose(w, "w");
        let b = c.arg::<FieldT>("b");
        let b = c.disclose(b, "b");
        c.when(g, |c| {
            c.assert_bits(w, 8);
            c.assert_boolean(b);
        });
    });
    assert_eq!(by_hand, scoped);
}

/// Straight-line checks are untouched: outside a scope each is the direct
/// instruction, no select — the zero-movement half of the claim.
#[test]
fn unscoped_checks_emit_no_select() {
    let stream = zkir(|c| {
        let a = c.arg::<FieldT>("a");
        let a = c.disclose(a, "a");
        let b = c.arg::<FieldT>("b");
        let b = c.disclose(b, "b");
        c.assert_eq(a, b);
        c.assert_bits(a, 8);
        c.assert_boolean(b);
    });
    assert!(!stream.contains("cond_select"), "{stream}");
    assert!(stream.contains("constrain_eq"), "{stream}");
}

/// §4.3: the witness twin of `a_guarded_read_inside_a_scope_conjoins_both_guards`
/// — a `_guarded` witness inside a scope consumes the private transcript
/// only where BOTH guards hold.
#[test]
fn a_guarded_witness_inside_a_scope_conjoins_both_guards() {
    let nested = zkir(|c| {
        let a = c.arg::<FieldT>("a");
        let a = c.disclose(a, "a");
        let b = c.arg::<FieldT>("b");
        let b = c.disclose(b, "b");
        c.when(a, |c| {
            c.when(b, |c| {
                let _w = c.witness::<FieldT>();
            });
        });
    });
    let guarded = zkir(|c| {
        let a = c.arg::<FieldT>("a");
        let a = c.disclose(a, "a");
        let b = c.arg::<FieldT>("b");
        let b = c.disclose(b, "b");
        c.when(a, |c| {
            let _w = c.witness_guarded::<FieldT, _>(b);
        });
    });
    assert_eq!(nested, guarded);
}

/// An assert message inside a scope is recorded against the `Assert`
/// itself, not the `cond_select` the scope emits in front of it — the index
/// the simulator looks a failed assertion up by.
#[test]
fn an_assert_message_inside_a_scope_names_the_assert() {
    let mut c = Circuit3::new();
    let g = c.arg::<FieldT>("g");
    let g = c.disclose(g, "g");
    let x = c.arg::<FieldT>("x");
    let x = c.disclose(x, "x");
    c.when(g, |c| c.assert_with(x, Some("x must hold")));
    let compiled = c.finish(true);
    let last = compiled.ir.instructions.len() - 1;
    assert_eq!(compiled.assert_message(last), Some("x must hold"));
    assert_eq!(
        compiled.assert_message(last - 1),
        None,
        "the select carries no message"
    );
}
