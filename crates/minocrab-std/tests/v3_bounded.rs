//! `BoundedUint<BOUND>` — Compact's `Uint<0..BOUND>` for an arbitrary bound
//! (M14, notes/bounded-integers.org).
//!
//! The claims, in the order the note makes them:
//!
//! - the LOWERING is compactc's table, not the leaf's — every arm of it,
//!   compared as byte-identical ZKIR against the hand-written form;
//! - the THREE WIDTHS a bound carries (range constraint, comparison, FAB
//!   atom) are the three different numbers they should be;
//! - the two conversions (`widen`, `to_uint`) are free: no instruction, and
//!   no second range constraint;
//! - the BORSH width is the next Borsh primitive up, and `constrain_canonical`
//!   is exactly `constrain_input` — which no other range-checked leaf can say
//!   (`Tag<K>` adds a bound Compact does not emit).
//!
//! The real end-to-end gate is
//! `crates/minocrab-contracts/tests/bounded_differential.rs`, which compares
//! against the pinned compactc's own artifacts.

use std::borrow::Cow;

use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage};
use minocrab::v3::{Circuit3, CircuitAbi, FieldT, Prim, Wire3};
use minocrab::{AlignmentAtom, Fr, Private, Public};
use minocrab_std::v3::borsh::{limbs_of, CircuitBorsh};
use minocrab_std::v3::{less_than, BoundedUint, CircuitArg, Uint};
use minocrab_zkir::v3::{to_zkir_string, IrValue};

/// The ZKIR a circuit body lowers to.
fn ir_of(build: impl FnOnce(&mut Circuit3)) -> String {
    let mut c = Circuit3::new();
    build(&mut c);
    to_zkir_string(&c.finish(false).ir).expect("IR serializes")
}

fn instructions(build: impl FnOnce(&mut Circuit3)) -> usize {
    let mut c = Circuit3::new();
    build(&mut c);
    c.finish(false).ir.instructions.len()
}

/// Build and RUN a circuit over `inputs` (the argument slots `c.arg` reads),
/// returning its native outputs — the arithmetic checked as arithmetic, not
/// only as an instruction stream.
fn run(build: impl FnOnce(&mut Circuit3), inputs: Vec<Fr>) -> Vec<Fr> {
    run_result(build, inputs).expect("the circuit accepts the preimage")
}

/// [`run`], but keeping the rejection: an unsatisfied assert is an `Err`, and
/// the underflow guard's whole job is to produce one.
fn run_result(build: impl FnOnce(&mut Circuit3), inputs: Vec<Fr>) -> Result<Vec<Fr>, String> {
    let mut c = Circuit3::new();
    build(&mut c);
    let compiled = c.finish(false);
    let preimage = ProofPreimage {
        inputs,
        private_transcript: vec![],
        public_transcript_inputs: vec![],
        public_transcript_outputs: vec![],
        binding_input: 0.into(),
        communications_commitment: None,
        key_location: KeyLocation(Cow::Borrowed("minocrab-std-v3-bounded")),
    };
    let run = minocrab_sim::v3::simulate(&compiled.ir, &preimage).map_err(|e| format!("{e:?}"))?;
    Ok(run
        .outputs
        .iter()
        .map(|v| match v {
            IrValue::Native(fr) => *fr,
            other => panic!("expected a native output, got {other:?}"),
        })
        .collect())
}

/// EVERY ARM of compactc's table, reached through the bound alone. The
/// hand-written side spells out what compactc emits for that `Uint<0..n>`
/// (verified against the pinned compiler's artifacts —
/// `minocrab-contracts/tests/fixtures/bounded/`); the typed side only names
/// the bound.
#[test]
fn each_bound_lowers_to_compactc_s_own_constraint() {
    // `Uint<0..1>` holds only zero.
    assert_eq!(
        ir_of(|c| {
            let x: Wire3<FieldT, Private> = c.arg("x");
            c.assert_eq(x, 0u64);
        }),
        ir_of(|c| { BoundedUint::<1>::from_field_unchecked(c.arg("x")).constrain_input(c); }),
    );
    // `Uint<0..2>` is `Boolean`.
    assert_eq!(
        ir_of(|c| {
            let x: Wire3<FieldT, Private> = c.arg("x");
            c.assert_boolean(x);
        }),
        ir_of(|c| { BoundedUint::<2>::from_field_unchecked(c.arg("x")).constrain_input(c); }),
    );
    // A bound that IS a power of two is a BIT WIDTH, not a `less_than` —
    // so `BoundedUint<256>` and `Uint<8>` are the same instruction.
    assert_eq!(
        ir_of(|c| {
            let x: Wire3<FieldT, Private> = c.arg("x");
            c.assert_bits(x, 8);
        }),
        ir_of(|c| { BoundedUint::<256>::from_field_unchecked(c.arg("x")).constrain_input(c); }),
    );
    assert_eq!(
        ir_of(|c| { Uint::<8>::from_field_unchecked(c.arg("x")).constrain_input(c); }),
        ir_of(|c| { BoundedUint::<256>::from_field_unchecked(c.arg("x")).constrain_input(c); }),
    );
    // Everything else is `less_than v BOUND bits` + `assert`, with
    // compactc's EVEN-ROUNDED width and the bound as an inline immediate.
    for (bound, bits) in [(10u128, 4u32), (255, 8), (300, 10), (1000, 10)] {
        assert_eq!(
            ir_of(|c| {
                let x: Wire3<FieldT, Private> = c.arg("x");
                let ok = c.less_than(x, minocrab::Fr::from(bound as u64), bits);
                c.assert(ok);
            }),
            match bound {
                10 => ir_of(|c| { BoundedUint::<10>::from_field_unchecked(c.arg("x")).constrain_input(c); }),
                255 => ir_of(|c| { BoundedUint::<255>::from_field_unchecked(c.arg("x")).constrain_input(c); }),
                300 => ir_of(|c| { BoundedUint::<300>::from_field_unchecked(c.arg("x")).constrain_input(c); }),
                _ => ir_of(|c| { BoundedUint::<1000>::from_field_unchecked(c.arg("x")).constrain_input(c); }),
            },
            "Uint<0..{bound}>"
        );
    }
}

/// `CircuitArg::constrain` — the PROVIDED method, which runs the same table
/// over `push_prims` — must agree with `constrain_input` for every bound.
/// That is the whole point of the leaf saying only what its slots are.
#[test]
fn the_derived_constraint_is_the_leafs_own() {
    fn both<const BOUND: u128>() {
        assert_eq!(
            ir_of(|c| { BoundedUint::<BOUND>::from_field_unchecked(c.arg("x")).constrain_input(c); }),
            ir_of(|c| {
                let x = <BoundedUint<BOUND, Private> as CircuitArg>::declare(
                    c,
                    &minocrab_std::v3::ArgPath::root("x"),
                );
                x.constrain(c);
            }),
        );
    }
    both::<1>();
    both::<2>();
    both::<10>();
    both::<256>();
    both::<300>();
    both::<70_000>();
}

/// `from_field_checked` is DEFINED as `from_field_unchecked` immediately
/// followed by `constrain_input` (notes/api-safety-survey.org §A1's fix), so
/// the two spellings must lower to byte-identical ZKIR — every arm of the
/// bound table, same as [`each_bound_lowers_to_compactc_s_own_constraint`].
#[test]
fn from_field_checked_matches_unchecked_plus_constrain_input() {
    fn both<const BOUND: u128>() {
        assert_eq!(
            ir_of(|c| {
                let w = c.arg("x");
                BoundedUint::<BOUND>::from_field_checked(c, w);
            }),
            ir_of(|c| {
                let x = BoundedUint::<BOUND>::from_field_unchecked(c.arg("x"));
                x.constrain_input(c);
            }),
        );
    }
    both::<1>();
    both::<2>();
    both::<10>();
    both::<256>();
    both::<300>();
    both::<70_000>();
}

/// THREE WIDTHS, three different numbers — the table in
/// notes/bounded-integers.org §2, asserted through the leaf's own surfaces.
#[test]
fn the_three_widths_are_three_numbers() {
    // The FAB atom: `⌈bitlen(maxval)/8⌉` bytes, so ZERO for `Uint<0..1>`
    // and THREE for `Uint<0..70000>` — neither of which is a Borsh width.
    let atom = |atoms: Vec<AlignmentAtom>| match atoms[..] {
        [AlignmentAtom::Bytes { length }] => length,
        _ => panic!("a bounded uint is one bytes atom"),
    };
    assert_eq!(atom(BoundedUint::<1, Private>::atoms()), 0);
    assert_eq!(atom(BoundedUint::<10, Private>::atoms()), 1);
    assert_eq!(atom(BoundedUint::<300, Private>::atoms()), 2);
    assert_eq!(atom(BoundedUint::<70_000, Private>::atoms()), 3);
    // The range CONSTRAINT of `Uint<0..70000>` runs at 18 bits (even, as
    // Plonk's gadget wants) …
    assert_eq!(
        BoundedUint::<70_000, Private>::prims(),
        vec![Prim::UintMax { maxval: 69_999 }]
    );
    assert!(ir_of(|c| { BoundedUint::<70_000>::from_field_unchecked(c.arg("x")).constrain_input(c); })
        .contains("\"bits\":18"));
    // … while a COMPARISON of two of them runs at 17.
    assert!(ir_of(|c| {
        let a = BoundedUint::<70_000>::from_field_unchecked(c.arg("a"));
        let b = BoundedUint::<70_000>::from_field_unchecked(c.arg("b"));
        c.assert(less_than(a, b));
    })
    .contains("\"bits\":17"));
}

/// A comparison against a bounded value is the hand-written one at the
/// type's comparison width, and nothing else.
#[test]
fn a_comparison_is_the_hand_written_one() {
    assert_eq!(
        ir_of(|c| {
            let a: Wire3<FieldT, Private> = c.arg("a");
            let b: Wire3<FieldT, Private> = c.arg("b");
            let lt = c.less_than(a, b, 10);
            c.assert(lt);
        }),
        ir_of(|c| {
            let a = BoundedUint::<1000>::from_field_unchecked(c.arg("a"));
            let b = BoundedUint::<1000>::from_field_unchecked(c.arg("b"));
            c.assert(a.lt(b));
        }),
    );
    // …and a `BoundedUint<1000>` (10) and a `Uint<10>` (10) agree on a
    // width, so they compare directly. A pair that does NOT agree is a
    // compile error — see `_COMPILE_ERRORS_NOT_PANICS`.
    assert_eq!(
        instructions(|c| {
            let a = BoundedUint::<1000>::from_field_unchecked(c.arg("a"));
            let b = Uint::<10>::from_field_unchecked(c.arg("b"));
            c.assert(a.lt(b));
        }),
        2
    );
}

/// Both conversions are FREE: no instruction, and no second range
/// constraint. A widened value's constraint is the SOURCE's, emitted once.
#[test]
fn widening_and_retyping_cost_nothing() {
    assert_eq!(
        instructions(|c| {
            let x = BoundedUint::<1000>::from_field_unchecked(c.arg("x"));
            let _wider: BoundedUint<70_000, Private> = x.widen::<70_000>();
            let _sized: Uint<10, Private> = x.to_uint::<10>();
        }),
        0
    );
    // The widened value carries the SOURCE's obligation, so the comparison
    // it enables costs one instruction and no range check.
    assert_eq!(
        ir_of(|c| {
            let a: Wire3<FieldT, Private> = c.arg("a");
            let b: Wire3<FieldT, Private> = c.arg("b");
            let lt = c.less_than(a, b, 17);
            c.assert(lt);
        }),
        ir_of(|c| {
            let a = BoundedUint::<1000>::from_field_unchecked(c.arg("a")).widen::<70_000>();
            let b = BoundedUint::<70_000>::from_field_unchecked(c.arg("b"));
            c.assert(a.lt(b));
        }),
    );
}

/// BORSH: the next primitive width up, and a `constrain_canonical` that IS
/// the argument constraint.
#[test]
fn borsh_serializes_at_the_next_primitive_width() {
    assert_eq!(<BoundedUint<1, Private> as CircuitBorsh<Private>>::LEN, 1);
    assert_eq!(<BoundedUint<10, Private> as CircuitBorsh<Private>>::LEN, 1);
    assert_eq!(<BoundedUint<256, Private> as CircuitBorsh<Private>>::LEN, 1);
    assert_eq!(<BoundedUint<300, Private> as CircuitBorsh<Private>>::LEN, 2);
    assert_eq!(<BoundedUint<1000, Private> as CircuitBorsh<Private>>::LEN, 2);
    // THREE FAB bytes, FOUR Borsh bytes: Borsh has no `u24`.
    assert_eq!(
        <BoundedUint<70_000, Private> as CircuitBorsh<Private>>::LEN,
        4
    );

    let layout = <BoundedUint<70_000, Private> as CircuitBorsh<Private>>::layout();
    assert_eq!(layout.len(), 1);
    assert_eq!(layout[0].kind, "u32");
    assert_eq!(layout[0].width, 4);
    assert_eq!(<BoundedUint<300, Private> as CircuitBorsh<Private>>::layout()[0].kind, "u16");

    // Describing the preimage emits nothing, and the hash atom is the
    // BORSH width (4), not the FAB one (3).
    let mut c = Circuit3::new();
    let x = BoundedUint::<70_000, Private>::from_field_unchecked(c.arg("x"));
    let before = c.instruction_count();
    let limbs = limbs_of::<Private, _>(&x);
    assert_eq!(c.instruction_count(), before);
    assert_eq!(
        limbs.alignment().0,
        vec![minocrab::AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 4 })]
    );

    // `constrain_canonical` is `constrain_input` — no extra bound, unlike
    // `Tag<K>`. So a value that entered as an argument is already canonical.
    assert_eq!(
        ir_of(|c| { BoundedUint::<70_000>::from_field_unchecked(c.arg("x")).constrain_input(c); }),
        ir_of(|c| {
            let x = BoundedUint::<70_000, Private>::from_field_unchecked(c.arg("x"));
            <BoundedUint<70_000, Private> as CircuitBorsh<Private>>::constrain_canonical(&x, c);
        }),
    );
}

// ---- TRACKED ARITHMETIC (M19 fix 1, notes/api-safety-survey.org §B2) ------------
//
// Compact's rule, verbatim (notes/builtin-lowering.org §9): `+` and `*` are a
// plain field `add` / `mul` with the max carried in the TYPE and no check at
// the op; `-` inserts the underflow guard first. The claims below are all the
// same claim — the instruction stream is compactc's, byte for byte, and the
// only thing our const generics add is the bookkeeping compactc does in its
// inference table.

/// `+` is ONE `add` and nothing else — no range check, exactly as compactc
/// emits none, because the result's bound is in the type.
#[test]
fn add_is_one_field_add_and_no_check() {
    assert_eq!(
        ir_of(|c| {
            let a: Wire3<FieldT, Private> = c.arg("a");
            let b: Wire3<FieldT, Private> = c.arg("b");
            let sum = c.add(a, b);
            let sum = c.disclose(sum, "sum");
            c.output(sum, "sum");
        }),
        ir_of(|c| {
            let a = BoundedUint::<300>::from_field_unchecked(c.arg("a"));
            let b = BoundedUint::<200>::from_field_unchecked(c.arg("b"));
            let sum: BoundedUint<499, Private> = a.add::<499, 200>(c, b);
            let sum = c.disclose(sum.field(), "sum");
            c.output(sum, "sum");
        }),
    );
    assert_eq!(
        instructions(|c| {
            let a = BoundedUint::<300>::from_field_unchecked(c.arg("a"));
            let b = BoundedUint::<200>::from_field_unchecked(c.arg("b"));
            let _ = a.add::<499, 200>(c, b);
        }),
        1
    );
}

/// `*` likewise: ONE `mul`, and the bound is `(BOUND-1)·(BOUND2-1) + 1`.
#[test]
fn mul_is_one_field_mul_and_no_check() {
    assert_eq!(
        ir_of(|c| {
            let a: Wire3<FieldT, Private> = c.arg("a");
            let b: Wire3<FieldT, Private> = c.arg("b");
            let product = c.mul(a, b);
            let product = c.disclose(product, "p");
            c.output(product, "p");
        }),
        ir_of(|c| {
            let a = BoundedUint::<300>::from_field_unchecked(c.arg("a"));
            let b = BoundedUint::<200>::from_field_unchecked(c.arg("b"));
            // 299 * 199 = 59_501, so 59_502 is the narrowest legal OUT.
            let product: BoundedUint<59_502, Private> = a.mul::<59_502, 200>(c, b);
            let product = c.disclose(product.field(), "p");
            c.output(product, "p");
        }),
    );
    assert_eq!(
        instructions(|c| {
            let a = BoundedUint::<300>::from_field_unchecked(c.arg("a"));
            let b = BoundedUint::<200>::from_field_unchecked(c.arg("b"));
            let _ = a.mul::<59_502, 200>(c, b);
        }),
        1
    );
}

/// `-` is compactc's GUARDED lowering — `assert(a >= b)`, `neg`, `add`, in
/// that order — at the BOUND's comparison width (10 for `Uint<0..1000>`,
/// not the 10-bit-even range-constraint width by coincidence; the point is
/// that no number is typed at the call site).
#[test]
fn sub_is_compactcs_guarded_lowering() {
    assert_eq!(
        ir_of(|c| {
            let a: Wire3<FieldT, Private> = c.arg("a");
            let b: Wire3<FieldT, Private> = c.arg("b");
            // the guard compactc emits, spelled out: !(a < b), then assert
            let lt = c.less_than(a, b, 10);
            let ge = c.not(lt);
            c.assert(ge);
            let negated = c.neg(b);
            let diff = c.add(a, negated);
            let diff = c.disclose(diff, "d");
            c.output(diff, "d");
        }),
        ir_of(|c| {
            let a = BoundedUint::<1000>::from_field_unchecked(c.arg("a"));
            let b = BoundedUint::<1000>::from_field_unchecked(c.arg("b"));
            let diff: BoundedUint<1000, Private> = a.sub(c, b);
            let diff = c.disclose(diff.field(), "d");
            c.output(diff, "d");
        }),
    );
    // The message is metadata: `sub_with` is the SAME lowering.
    assert_eq!(
        ir_of(|c| {
            let a = BoundedUint::<1000>::from_field_unchecked(c.arg("a"));
            let b = BoundedUint::<1000>::from_field_unchecked(c.arg("b"));
            let _ = a.sub(c, b);
        }),
        ir_of(|c| {
            let a = BoundedUint::<1000>::from_field_unchecked(c.arg("a"));
            let b = BoundedUint::<1000>::from_field_unchecked(c.arg("b"));
            let _ = a.sub_with(c, b, "the vault's own words");
        }),
    );
    // And the guard is not optional: the raw spelling emits no `assert`.
    let raw = ir_of(|c| {
        let a: Wire3<FieldT, Private> = c.arg("a");
        let b: Wire3<FieldT, Private> = c.arg("b");
        let negated = c.neg(b);
        let diff = c.add(a, negated);
        let diff = c.disclose(diff, "d");
        c.output(diff, "d");
    });
    assert!(!raw.contains("\"assert\""), "the raw spelling has no guard: {raw}");
}

/// `narrow` emits THE RANGE CHECK COMPACTC OMITS (§B4's correction:
/// `amount as Uint<64>` in argument position emits nothing at all), and
/// nothing else — the same instruction `Uint<BITS>`'s own argument
/// constraint emits, from the same table.
#[test]
fn narrow_emits_the_check_compactc_omits() {
    assert_eq!(
        ir_of(|c| {
            let x: Wire3<FieldT, Private> = c.arg("x");
            c.assert_bits(x, 8);
        }),
        ir_of(|c| {
            let x = BoundedUint::<300>::from_field_unchecked(c.arg("x"));
            let _: Uint<8, Private> = x.narrow::<8>(c);
        }),
    );
    // …and it is the SAME instruction `Uint<8>` constrains an argument with.
    assert_eq!(
        ir_of(|c| { Uint::<8>::from_field_unchecked(c.arg("x")).constrain_input(c); }),
        ir_of(|c| {
            let _ = BoundedUint::<300>::from_field_unchecked(c.arg("x")).narrow::<8>(c);
        }),
    );
    assert_eq!(
        instructions(|c| {
            let _ = BoundedUint::<300>::from_field_unchecked(c.arg("x")).narrow::<8>(c);
        }),
        1
    );
    // The free direction is `to_uint`, and it stays free (zero instructions).
    assert_eq!(
        instructions(|c| {
            let _ = BoundedUint::<300>::from_field_unchecked(c.arg("x")).to_uint::<9>();
        }),
        0
    );
}

/// THE BOUND IS TRACKED, and the value is right: `Uint<0..300> +
/// Uint<0..200>` types as `Uint<0..499>` (`299 + 199 = 498`, bound
/// exclusive), and the arithmetic the type describes is the arithmetic the
/// simulator performs.
#[test]
fn bounds_track_and_the_values_round_trip() {
    fn sum(a: u64, b: u64) -> Fr {
        run(
            |c| {
                let x = BoundedUint::<300, Private>::from_field_unchecked(c.arg("a"));
                let y = BoundedUint::<200, Private>::from_field_unchecked(c.arg("b"));
                x.constrain_input(c);
                y.constrain_input(c);
                let out: BoundedUint<499, Private> = x.add::<499, 200>(c, y);
                let out = c.disclose(out.field(), "sum");
                c.output(out, "sum");
            },
            vec![Fr::from(a), Fr::from(b)],
        )[0]
    }
    assert_eq!(sum(0, 0), Fr::from(0u64));
    assert_eq!(sum(150, 100), Fr::from(250u64));
    // The extremes, which are exactly what `BoundedUint<499>::MAX` claims.
    assert_eq!(sum(299, 199), Fr::from(498u64));
    assert_eq!(BoundedUint::<499, Private>::MAX, 498);

    // The product, at its own bound.
    let product = run(
        |c| {
            let x = BoundedUint::<300, Private>::from_field_unchecked(c.arg("a"));
            let y = BoundedUint::<200, Private>::from_field_unchecked(c.arg("b"));
            x.constrain_input(c);
            y.constrain_input(c);
            let out: BoundedUint<59_502, Private> = x.mul::<59_502, 200>(c, y);
            let out = c.disclose(out.field(), "product");
            c.output(out, "product");
        },
        vec![Fr::from(299u64), Fr::from(199u64)],
    );
    assert_eq!(product[0], Fr::from(59_501u64));
    assert_eq!(BoundedUint::<59_502, Private>::MAX, 59_501);

    // The guarded subtraction: honest preimage passes with the right answer,
    // and the underflowing one is REJECTED rather than yielding `a - b + p`.
    let difference = |a: u64, b: u64| {
        run_result(
            |c| {
                let x = BoundedUint::<1000, Private>::from_field_unchecked(c.arg("a"));
                let y = BoundedUint::<1000, Private>::from_field_unchecked(c.arg("b"));
                x.constrain_input(c);
                y.constrain_input(c);
                let out = x.sub(c, y);
                let out = c.disclose(out.field(), "difference");
                c.output(out, "difference");
            },
            vec![Fr::from(a), Fr::from(b)],
        )
    };
    assert_eq!(difference(999, 1).expect("999 - 1 is honest")[0], Fr::from(998u64));
    assert_eq!(difference(7, 7).expect("7 - 7 is honest")[0], Fr::from(0u64));
    assert!(
        difference(1, 7).is_err(),
        "the underflow guard must reject 1 - 7, not produce 1 - 7 + p"
    );
}

/// A public constant, and the one panic this leaf keeps: the magnitude of a
/// runtime integer is not in the type system, so `BOUND` cannot check it at
/// compile time (notes/contract-api.org §"Panics that could NOT become
/// compile errors", item 5).
#[test]
#[should_panic(expected = "300 is not a value of Uint<0..300>")]
fn a_constant_past_the_bound_panics() {
    let mut c = Circuit3::new();
    let _ = BoundedUint::<300, Public>::constant(&mut c, 300);
}

#[test]
fn the_largest_legal_constant_is_fine() {
    let mut c = Circuit3::new();
    let _ = BoundedUint::<300, Public>::constant(&mut c, 299);
    assert_eq!(BoundedUint::<300, Public>::MAX, 299);
}

/// The rejections that are COMPILE errors, not panics (the standing rule).
/// Each block is a spelling that must not compile:
///
/// a bound of zero — compactc's own rule, in compactc's own words,
///
/// ```compile_fail
/// # use minocrab::v3::{Circuit3, FieldT};
/// # use minocrab_std::v3::BoundedUint;
/// let mut c = Circuit3::new();
/// // error[E0080]: range end for Uint type is 0 but must be at least 1 …
/// let _ = BoundedUint::<0>::from_field_unchecked(c.arg::<FieldT>("x"));
/// ```
///
/// a `widen` that narrows,
///
/// ```compile_fail
/// # use minocrab::v3::{Circuit3, FieldT};
/// # use minocrab_std::v3::BoundedUint;
/// let mut c = Circuit3::new();
/// let x = BoundedUint::<1000>::from_field_unchecked(c.arg::<FieldT>("x"));
/// let _ = x.widen::<300>();   // error[E0080]: `.widen::<B>()` only widens …
/// ```
///
/// a `to_uint` into a width the bound does not fit,
///
/// ```compile_fail
/// # use minocrab::v3::{Circuit3, FieldT};
/// # use minocrab_std::v3::BoundedUint;
/// let mut c = Circuit3::new();
/// let x = BoundedUint::<1000>::from_field_unchecked(c.arg::<FieldT>("x"));
/// let _ = x.to_uint::<9>();   // error[E0080]: needs 2^BITS >= BOUND …
/// ```
///
/// and a comparison whose two operands disagree about the width (the
/// predicate module's rule, inherited — `BoundedUint<70000>` is 17 bits and
/// `Uint<32>` is 32):
///
/// ```compile_fail
/// # use minocrab::v3::{Circuit3, FieldT};
/// # use minocrab_std::v3::{BoundedUint, Uint};
/// let mut c = Circuit3::new();
/// let a = BoundedUint::<70_000>::from_field_unchecked(c.arg::<FieldT>("a"));
/// let b = Uint::<32>::from_field_unchecked(c.arg::<FieldT>("b"));
/// c.assert(a.lt(b));          // error[E0080]: … different widths …
/// ```
///
/// (Checked by hand, as the predicate module's pair is: there is no
/// trybuild in the lock file and `compile_fail` doc-tests do not run for a
/// test target. This block is the record of the four spellings.)
///
/// The TRACKED ARITHMETIC's rejections — a too-small `OUT` on `add` and on
/// `mul`, an `OUT` whose computation overflows a `u128`, and a `narrow` in
/// the free direction — are `compile_fail` doc-tests on the methods
/// themselves in `minocrab-std/src/v3.rs`, where doc-tests DO run, so those
/// four are checked by `cargo test` rather than by hand.
const _COMPILE_ERRORS_NOT_PANICS: () = ();
