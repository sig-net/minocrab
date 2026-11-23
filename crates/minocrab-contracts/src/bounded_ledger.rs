//! `bounded_ledger.compact` — a `Uint<0..1>` in ledger position, through
//! [`minocrab_std::BoundedUint`] (notes/bounded-integers.org §3).
//!
//! Why this is a second fixture beside `bounded.compact`. compactc issue
//! #588 (fixed 0.33.108, "\[skip-changelog\] Fix alignment width for bounded
//! integers with maxval=0") gives a `Uint<0..1>` a one-byte alignment on the
//! Impact op when it sits in ledger position, where our prior pin
//! (0.33.0-rc.2) gave it zero — still writing one (always-zero) value in the
//! transcript either way. `bounded.compact`'s own `b1` circuit takes
//! `Uint<0..1>` as an argument, and compactc's compiled `b1.zkir` is
//! byte-identical under both compilers: argument position never moved. Only
//! ledger position did, and no corpus artifact and no existing fixture puts
//! a `Uint<0..1>` there — hence this fixture, compiled fresh under the
//! pinned (0.36.0) compactc.
//!
//! What it pins, and against what. `bounded_differential`'s own ABI check
//! (`compactc_s_abi_agrees_with_the_leafs`) reads compactc's own `maxval`
//! out of `contract-info.json` and reconstructs the FAB alignment with
//! `uint_atom_bytes` — the same formula this crate's lowering uses — so a
//! wrong formula agrees with itself and that check can never see it. This
//! fixture's differential instead compares the actual Impact operand bytes
//! our lowering emits against the ones in the compiled `.zkir`, so a wrong
//! `uint_atom_bytes` fails it regardless of what our own formula believes.

use minocrab::Circuit;
use minocrab::Public;
use minocrab_std::{Assumed, contract, label, BoundedUint, Disclose, Discloses, Ledger, LedgerCell};

label! {
    /// The one value this fixture ever discloses.
    X = "x";
}

/// `export ledger cell: Uint<0..1>;` — the whole ledger block.
#[derive(Ledger)]
pub struct BoundedLedger {
    pub cell: LedgerCell<BoundedUint<1, Public>>,
}

/// The contract's ledger block.
pub const BOUNDED_LEDGER: BoundedLedger = BoundedLedger::new();

#[contract(lowering = minocrab_compat::profile)]
impl BoundedLedger {
    /// `export circuit blWrite(x: Uint<0..1>): [] { cell = disclose(x); }` —
    /// the write whose Impact op carries the one-byte alignment (`0x01`).
    #[circuit]
    pub fn bl_write(c: &mut Circuit, x: BoundedUint<1>) -> Discloses<X> {
        let x = x.disclose_as::<X>(c);
        BOUNDED_LEDGER.cell.write(c, &x);
        Discloses::of(())
    }

    /// `export circuit blRead(): Uint<0..1> { return cell; }` — the mirror
    /// check a write-only fixture would miss: the read side carries the
    /// same alignment byte in its own Impact op.
    #[circuit(output = "cell")]
    pub fn bl_read(c: &mut Circuit) -> Assumed<BoundedUint<1, Public>> {
        BOUNDED_LEDGER.cell.read(c)
    }
}
