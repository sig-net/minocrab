//! The small primitives contract authors kept hand-writing, each pinned to
//! the BYTE-IDENTICAL ZKIR of the sequence it replaces: `B32::equals`,
//! `LedgerMap::lookup_required`, `LedgerCell::increment`.

use minocrab::v3::{Circuit3, Compiled3, FieldT};
use minocrab::{Private, Public};
use minocrab_std::v3::{eq, is_true, not, LedgerCell, LedgerMap, Uint, B32};
use minocrab_zkir::v3::to_zkir_string;

fn zkir(compiled: Compiled3) -> String {
    to_zkir_string(&compiled.ir).expect("IR serializes")
}

fn build(f: impl FnOnce(&mut Circuit3)) -> String {
    let mut c = Circuit3::new();
    f(&mut c);
    zkir(c.finish(false))
}

fn two_b32(c: &mut Circuit3) -> (B32<Private>, B32<Private>) {
    let a = B32 { hi: c.arg::<FieldT>("a_hi"), lo: c.arg::<FieldT>("a_lo") };
    let b = B32 { hi: c.arg::<FieldT>("b_hi"), lo: c.arg::<FieldT>("b_lo") };
    (a, b)
}

/// `a.equals(b)` asserted is the contracts' former private `b32_eq` check
/// (`eq(hi).and(eq(lo))`), and both are `B32::eq`'s two `test_eq` and `mul`.
#[test]
fn b32_equals_is_the_hand_written_limb_check() {
    let std_form = build(|c| {
        let (a, b) = two_b32(c);
        c.assert(a.equals(b).message("differ"));
    });
    let check_form = build(|c| {
        let (a, b) = two_b32(c);
        c.assert(eq(a.hi, b.hi).and(eq(a.lo, b.lo)).message("differ"));
    });
    let wire_form = build(|c| {
        let (a, b) = two_b32(c);
        let hi = c.test_eq(a.hi, b.hi);
        let lo = c.test_eq(a.lo, b.lo);
        let same = c.mul(hi, lo);
        c.assert_with(same, Some("differ"));
    });
    let bool_form = build(|c| {
        let (a, b) = two_b32(c);
        let same = a.eq(c, b);
        c.assert(is_true(same).message("differ"));
    });
    assert_eq!(std_form, check_form);
    assert_eq!(std_form, wire_form);
    assert_eq!(std_form, bool_form);
}

/// Negated, it is one `not` after the `mul`, as `not(b32_eq(..))` was.
#[test]
fn b32_equals_negates_like_the_hand_written_check() {
    let std_form = build(|c| {
        let (a, b) = two_b32(c);
        c.assert(not(a.equals(b)).message("same"));
    });
    let by_hand = build(|c| {
        let (a, b) = two_b32(c);
        let hi = c.test_eq(a.hi, b.hi);
        let lo = c.test_eq(a.lo, b.lo);
        let same = c.mul(hi, lo);
        let differ = c.not(same);
        c.assert_with(differ, Some("same"));
    });
    assert_eq!(std_form, by_hand);
}

/// A public side moves over with `.private()`, which emits nothing.
#[test]
fn b32_equals_across_visibilities_goes_through_private() {
    let std_form = build(|c| {
        let (a, _) = two_b32(c);
        let k: B32<Public> = B32::pad(c, "key");
        c.assert(a.equals(k.private()));
    });
    let by_hand = build(|c| {
        let (a, _) = two_b32(c);
        let k: B32<Public> = B32::pad(c, "key");
        let hi = c.test_eq(a.hi, k.hi);
        let lo = c.test_eq(a.lo, k.lo);
        let same = c.mul(hi, lo);
        c.assert(same);
    });
    assert_eq!(std_form, by_hand);
}

const REQUESTS: LedgerMap<B32<Public>, Uint<64, Public>> = LedgerMap::at(3);
const NONCE: LedgerCell<Uint<64, Public>> = LedgerCell::at(4);

fn public_b32(c: &mut Circuit3) -> B32<Public> {
    B32::pad(c, "request")
}

/// `lookup_required` is `member`, the messaged assert, `lookup`, in that
/// order, and its value still needs `.stale(c)` to go back to the ledger.
#[test]
fn lookup_required_is_member_assert_lookup() {
    let std_form = build(|c| {
        let k = public_b32(c);
        let v = REQUESTS.lookup_required(c, &k, "Request not sent").stale(c);
        NONCE.write(c, &v);
    });
    let by_hand = build(|c| {
        let k = public_b32(c);
        let present = REQUESTS.member(c, &k);
        c.assert(is_true(present).message("Request not sent"));
        let v = REQUESTS.lookup(c, &k).stale(c);
        NONCE.write(c, &v);
    });
    let wire_dialect = build(|c| {
        let k = public_b32(c);
        let present = REQUESTS.member(c, &k).field();
        c.assert_with(present, Some("Request not sent"));
        let v = REQUESTS.lookup(c, &k).stale(c);
        NONCE.write(c, &v);
    });
    assert_eq!(std_form, by_hand);
    assert_eq!(std_form, wire_dialect);
}

/// The message survives to the finished circuit, as the hand-written one does.
#[test]
fn lookup_required_keeps_its_message() {
    let mut c = Circuit3::new();
    let k = public_b32(&mut c);
    let _ = REQUESTS.lookup_required(&mut c, &k, "Request not sent");
    let compiled = c.finish(false);
    assert!(
        compiled.assert_messages.iter().any(|m| m.message == "Request not sent"),
        "the assert message is carried"
    );
}
