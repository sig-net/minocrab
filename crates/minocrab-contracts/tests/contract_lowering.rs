//! `#[contract(lowering = path)]` applies the path to every circuit of the
//! block BEFORE the body, after the arguments are declared and constrained.
//!
//! Ordering is the point: `Circuit3::set_lowering` refuses to run once a
//! gadget has consulted the settings, so a lowering applied after the body's
//! first `kernel.self()` read would panic, and one applied after the body
//! would be no lowering at all. Here the lowering is a non-default one so its
//! effect on the stream is visible: under `OncePerCircuit` two self reads
//! emit one.

use minocrab::v3::{Circuit3, Lowering, SelfAddressReads};
use minocrab_std::v3::{contract, kernel, Uint};

fn read_once(c: &mut Circuit3) {
    c.set_lowering(Lowering { self_address: SelfAddressReads::OncePerCircuit, ..Lowering::default() });
}

pub struct Lean;

#[contract(lowering = read_once)]
impl Lean {
    /// An argument, so its declaration and range constraint come first, then
    /// the lowering (which would panic had they consulted it), then the body.
    #[circuit]
    pub fn two_reads(c: &mut Circuit3, _amount: Uint<64>) {
        assert!(c.lowering_chosen(), "the body runs under the contract's lowering");
        assert_eq!(c.lowering().self_address, SelfAddressReads::OncePerCircuit);
        kernel::self_address(c);
        kernel::self_address(c);
    }

    #[circuit]
    pub fn one_read(c: &mut Circuit3, _amount: Uint<64>) {
        kernel::self_address(c);
    }
}

pub struct Plain;

#[contract]
impl Plain {
    #[circuit]
    pub fn two_plain_reads(c: &mut Circuit3, _amount: Uint<64>) {
        assert!(!c.lowering_chosen(), "no attribute, no lowering");
        kernel::self_address(c);
        kernel::self_address(c);
    }
}

fn len(c: &minocrab::v3::Compiled3) -> usize {
    c.ir.instructions.len()
}

#[test]
fn the_lowering_is_in_effect_from_the_bodys_first_gadget() {
    let lean = Lean::two_reads();
    assert_eq!(len(&lean), len(&Lean::one_read()), "under OncePerCircuit the second read emits nothing");
    assert!(len(&lean) < len(&Plain::two_plain_reads()), "the default reads at every call");
}

#[test]
fn the_contract_records_its_lowering() {
    let lowering = Lean::LOWERING.expect("the attribute was given");
    let mut c = Circuit3::new();
    lowering(&mut c);
    assert_eq!(c.lowering().self_address, SelfAddressReads::OncePerCircuit);
    assert!(Plain::LOWERING.is_none());
}

/// What the attribute's ordering avoids: the same lowering applied after a
/// gadget has consulted the settings is refused.
#[test]
#[should_panic(expected = "called after a gadget already lowered")]
fn a_lowering_after_the_first_read_is_refused() {
    let mut c = Circuit3::new();
    kernel::self_address(&mut c);
    read_once(&mut c);
}
