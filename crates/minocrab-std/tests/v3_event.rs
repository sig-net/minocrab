//! `event::emit` is the raw `emit(c, &emit_event(version, tag, &payload))`
//! with the payload typed: the same ZKIR and the same disclosure record, in
//! straight-line code and inside a `when`, for payloads of one and of
//! several limbs.

use minocrab::v3::{Circuit3, Compiled3, FieldT};
use minocrab::Public;
use minocrab_ledger::{emit, emit_event, ImpactElem, LedgerValue};
use minocrab_std::v3::{event, BytesN, Serializer};
use minocrab_zkir::v3::to_zkir_string;

const VERSION: u32 = 1;
const TAG: u8 = 10;

/// A payload of `N` bytes: a name literal, two disclosed arguments, then
/// the zero pad `finish` adds.
fn payload<const N: usize>(c: &mut Circuit3) -> BytesN<Public, N> {
    let a = c.arg::<FieldT>("a");
    let b = c.arg::<FieldT>("b");
    let [a, b] = c.disclose_all("ab", [a, b]);
    let mut s = Serializer::<Public>::new();
    s.push_literal(c, b"deposit");
    s.push_uint(a, 16);
    s.push_uint(b, 8);
    s.finish::<N>(c)
}

fn raw<const N: usize>(c: &mut Circuit3, payload: &BytesN<Public, N>) {
    let value = LedgerValue::bytes(
        N as u32,
        payload.limbs().iter().map(|&w| ImpactElem::Wire(w)).collect(),
    );
    emit(c, &emit_event(VERSION, TAG, &value));
}

fn typed<const N: usize>(c: &mut Circuit3, payload: &BytesN<Public, N>) {
    event::emit(c, VERSION, TAG, payload);
}

/// The circuit, with the emission straight-line or under a disclosed guard.
fn build<const N: usize>(guarded: bool, emit: fn(&mut Circuit3, &BytesN<Public, N>)) -> Compiled3 {
    let mut c = Circuit3::new();
    let g = guarded.then(|| c.arg::<FieldT>("g"));
    let p = payload::<N>(&mut c);
    if let Some(g) = g {
        let g = c.disclose(g, "g");
        c.when(g, |c| emit(c, &p));
    } else {
        emit(&mut c, &p);
    }
    c.finish(true)
}

fn same<const N: usize>(guarded: bool) {
    let r = build::<N>(guarded, raw::<N>);
    let t = build::<N>(guarded, typed::<N>);
    assert_eq!(r.disclosures, t.disclosures, "disclosures, N = {N}, guarded = {guarded}");
    assert_eq!(
        to_zkir_string(&r.ir).expect("serializes"),
        to_zkir_string(&t.ir).expect("serializes"),
        "ZKIR, N = {N}, guarded = {guarded}"
    );
}

#[test]
fn one_and_two_limbs_straight_line() {
    same::<32>(false);
    same::<62>(false);
}

#[test]
fn the_misc_size_straight_line() {
    same::<288>(false);
}

#[test]
fn inside_a_when() {
    same::<32>(true);
    same::<288>(true);
}

#[test]
#[should_panic(expected = "inside `when_private`")]
fn inside_a_private_scope_is_refused_as_the_raw_form_is() {
    let mut c = Circuit3::new();
    let g = c.arg::<FieldT>("g");
    let p = payload::<64>(&mut c);
    c.when_private(g, |c| typed(c, &p));
}
