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

use minocrab::v3::{Circuit3, CircuitAbi, FieldT, Prim, Wire3};
use minocrab::{AlignmentAtom, Private, Public};
use minocrab_std::v3::borsh::{limbs_of, CircuitBorsh};
use minocrab_std::v3::{less_than, BoundedUint, CircuitArg, Uint};
use minocrab_zkir::v3::to_zkir_string;

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
        ir_of(|c| BoundedUint::<1>::from_field(c.arg("x")).constrain_input(c)),
    );
    // `Uint<0..2>` is `Boolean`.
    assert_eq!(
        ir_of(|c| {
            let x: Wire3<FieldT, Private> = c.arg("x");
            c.assert_boolean(x);
        }),
        ir_of(|c| BoundedUint::<2>::from_field(c.arg("x")).constrain_input(c)),
    );
    // A bound that IS a power of two is a BIT WIDTH, not a `less_than` —
    // so `BoundedUint<256>` and `Uint<8>` are the same instruction.
    assert_eq!(
        ir_of(|c| {
            let x: Wire3<FieldT, Private> = c.arg("x");
            c.assert_bits(x, 8);
        }),
        ir_of(|c| BoundedUint::<256>::from_field(c.arg("x")).constrain_input(c)),
    );
    assert_eq!(
        ir_of(|c| Uint::<8>::from_field(c.arg("x")).constrain_input(c)),
        ir_of(|c| BoundedUint::<256>::from_field(c.arg("x")).constrain_input(c)),
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
                10 => ir_of(|c| BoundedUint::<10>::from_field(c.arg("x")).constrain_input(c)),
                255 => ir_of(|c| BoundedUint::<255>::from_field(c.arg("x")).constrain_input(c)),
                300 => ir_of(|c| BoundedUint::<300>::from_field(c.arg("x")).constrain_input(c)),
                _ => ir_of(|c| BoundedUint::<1000>::from_field(c.arg("x")).constrain_input(c)),
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
            ir_of(|c| BoundedUint::<BOUND>::from_field(c.arg("x")).constrain_input(c)),
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
    assert!(ir_of(|c| BoundedUint::<70_000>::from_field(c.arg("x")).constrain_input(c))
        .contains("\"bits\":18"));
    // … while a COMPARISON of two of them runs at 17.
    assert!(ir_of(|c| {
        let a = BoundedUint::<70_000>::from_field(c.arg("a"));
        let b = BoundedUint::<70_000>::from_field(c.arg("b"));
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
            let a = BoundedUint::<1000>::from_field(c.arg("a"));
            let b = BoundedUint::<1000>::from_field(c.arg("b"));
            c.assert(a.lt(b));
        }),
    );
    // …and a `BoundedUint<1000>` (10) and a `Uint<10>` (10) agree on a
    // width, so they compare directly. A pair that does NOT agree is a
    // compile error — see `_COMPILE_ERRORS_NOT_PANICS`.
    assert_eq!(
        instructions(|c| {
            let a = BoundedUint::<1000>::from_field(c.arg("a"));
            let b = Uint::<10>::from_field(c.arg("b"));
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
            let x = BoundedUint::<1000>::from_field(c.arg("x"));
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
            let a = BoundedUint::<1000>::from_field(c.arg("a")).widen::<70_000>();
            let b = BoundedUint::<70_000>::from_field(c.arg("b"));
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
    let x = BoundedUint::<70_000, Private>::from_field(c.arg("x"));
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
        ir_of(|c| BoundedUint::<70_000>::from_field(c.arg("x")).constrain_input(c)),
        ir_of(|c| {
            let x = BoundedUint::<70_000, Private>::from_field(c.arg("x"));
            <BoundedUint<70_000, Private> as CircuitBorsh<Private>>::constrain_canonical(&x, c);
        }),
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
/// let _ = BoundedUint::<0>::from_field(c.arg::<FieldT>("x"));
/// ```
///
/// a `widen` that narrows,
///
/// ```compile_fail
/// # use minocrab::v3::{Circuit3, FieldT};
/// # use minocrab_std::v3::BoundedUint;
/// let mut c = Circuit3::new();
/// let x = BoundedUint::<1000>::from_field(c.arg::<FieldT>("x"));
/// let _ = x.widen::<300>();   // error[E0080]: `.widen::<B>()` only widens …
/// ```
///
/// a `to_uint` into a width the bound does not fit,
///
/// ```compile_fail
/// # use minocrab::v3::{Circuit3, FieldT};
/// # use minocrab_std::v3::BoundedUint;
/// let mut c = Circuit3::new();
/// let x = BoundedUint::<1000>::from_field(c.arg::<FieldT>("x"));
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
/// let a = BoundedUint::<70_000>::from_field(c.arg::<FieldT>("a"));
/// let b = Uint::<32>::from_field(c.arg::<FieldT>("b"));
/// c.assert(a.lt(b));          // error[E0080]: … different widths …
/// ```
///
/// (Checked by hand, as the predicate module's pair is: there is no
/// trybuild in the lock file and `compile_fail` doc-tests do not run for a
/// test target. This block is the record of the four spellings.)
const _COMPILE_ERRORS_NOT_PANICS: () = ();
