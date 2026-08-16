//! The typed v3 leaves (`Uint<BITS>`, `Bool`, `Bytes<N>`) must be pure
//! type-level structure: a circuit written with them has to lower to the
//! byte-identical instruction stream of the same circuit written against
//! raw wires. Each test below builds both and compares the serialized ZKIR.

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Fr, Private};
use minocrab_std::v3::{Bool, Bytes, Uint};
use minocrab_zkir::v3::to_zkir_string;

/// The ZKIR a circuit body lowers to.
fn ir_of(build: impl FnOnce(&mut Circuit3)) -> String {
    let mut c = Circuit3::new();
    build(&mut c);
    to_zkir_string(&c.finish(false).ir).expect("IR serializes")
}

/// How many instructions a circuit body emits.
fn instructions(build: impl FnOnce(&mut Circuit3)) -> usize {
    let mut c = Circuit3::new();
    build(&mut c);
    c.finish(false).ir.instructions.len()
}

#[test]
fn uint_lowers_like_the_hand_written_argument() {
    let hand = ir_of(|c| {
        let x: Wire3<FieldT, Private> = c.arg("evmNonce");
        c.assert_bits(x, 64);
        let k = c.constant(5u64);
        let sum = c.add(x, k);
        c.assert_bits(sum, 65);
    });
    let typed = ir_of(|c| {
        let x = Uint::<64>::from_field_unchecked(c.arg("evmNonce"));
        x.constrain_input(c);
        let k = Uint::<64, _>::constant(c, 5);
        let sum = c.add(x.field(), k.field());
        c.assert_bits(sum, 65);
    });
    assert_eq!(hand, typed);
}

#[test]
fn bool_lowers_like_the_hand_written_argument() {
    let hand = ir_of(|c| {
        let b: Wire3<FieldT, Private> = c.arg("isSome");
        c.assert_boolean(b);
        let t = c.constant(1u64);
        let and = c.mul(b, t);
        c.assert_boolean(and);
    });
    let typed = ir_of(|c| {
        let b = Bool::from_field_unchecked(c.arg("isSome"));
        b.constrain_input(c);
        let t = Bool::constant(c, true);
        let and = c.mul(b.field(), t.field());
        c.assert_boolean(and);
    });
    assert_eq!(hand, typed);
}

#[test]
fn bytes_lowers_like_the_hand_written_argument() {
    let address = [0xabu8; 20];
    let hand = ir_of(|c| {
        let a: Wire3<FieldT, Private> = c.arg("erc20Address");
        c.assert_bits(a, 160);
        let k = c.constant(Fr::from_le_bytes(&address).expect("20 bytes fit"));
        c.assert_eq(a, k);
    });
    let typed = ir_of(|c| {
        let a = Bytes::<20>::from_field_unchecked(c.arg("erc20Address"));
        a.constrain_input(c);
        let k = Bytes::<20, _>::constant(c, &address);
        c.assert_eq(a.field(), k.field());
    });
    assert_eq!(hand, typed);
}

#[test]
fn field_unwrap_emits_no_instruction() {
    assert_eq!(
        instructions(|c| {
            let u = Uint::<64>::from_field_unchecked(c.arg("a"));
            let b = Bool::from_field_unchecked(c.arg("b"));
            let s = Bytes::<20>::from_field_unchecked(c.arg("c"));
            let _ = (u.field(), b.field(), s.field());
        }),
        0
    );
}

#[test]
fn uint_constant_accepts_every_u64_at_64_bits_and_wider() {
    // The range check must not trip — nor shift-overflow — once BITS >= 64.
    let mut c = Circuit3::new();
    Uint::<64, _>::constant(&mut c, u64::MAX);
    Uint::<128, _>::constant(&mut c, u64::MAX);
    Uint::<254, _>::constant(&mut c, u64::MAX);
    Uint::<8, _>::constant(&mut c, 255);
}

#[test]
#[should_panic(expected = "256 does not fit in Uint<8>")]
fn uint_constant_rejects_an_out_of_range_value() {
    Uint::<8, _>::constant(&mut Circuit3::new(), 256);
}

/// `from_field_checked` is DEFINED as `from_field_unchecked` immediately
/// followed by `constrain_input` (notes/api-safety-survey.org §A1's fix) —
/// so the two spellings must lower to byte-identical ZKIR, for every typed
/// leaf that has a `constrain_input` to delegate to.
#[test]
fn uint_from_field_checked_matches_unchecked_plus_constrain_input() {
    let checked = ir_of(|c| {
        let w = c.arg("evmNonce");
        Uint::<64>::from_field_checked(c, w);
    });
    let unchecked_then_constrained = ir_of(|c| {
        let x = Uint::<64>::from_field_unchecked(c.arg("evmNonce"));
        x.constrain_input(c);
    });
    assert_eq!(checked, unchecked_then_constrained);
}

#[test]
fn bool_from_field_checked_matches_unchecked_plus_constrain_input() {
    let checked = ir_of(|c| {
        let w = c.arg("isSome");
        Bool::from_field_checked(c, w);
    });
    let unchecked_then_constrained = ir_of(|c| {
        let b = Bool::from_field_unchecked(c.arg("isSome"));
        b.constrain_input(c);
    });
    assert_eq!(checked, unchecked_then_constrained);
}

#[test]
fn bytes_from_field_checked_matches_unchecked_plus_constrain_input() {
    let checked = ir_of(|c| {
        let w = c.arg("erc20Address");
        Bytes::<20>::from_field_checked(c, w);
    });
    let unchecked_then_constrained = ir_of(|c| {
        let a = Bytes::<20>::from_field_unchecked(c.arg("erc20Address"));
        a.constrain_input(c);
    });
    assert_eq!(checked, unchecked_then_constrained);
}

#[test]
fn constants_are_the_values_they_name() {
    // One `Copy` of an immediate each, and the immediate is the native
    // encoding of the Rust value.
    let ir = ir_of(|c| {
        Uint::<64, _>::constant(c, 7);
        Bool::constant(c, true);
        Bytes::<4, _>::constant(c, &[1, 0, 0, 0]);
    });
    let hand = ir_of(|c| {
        c.constant(7u64);
        c.constant(1u64);
        c.constant(1u64);
    });
    assert_eq!(ir, hand);
}
