//! `bounded.compact` — Compact's `Uint<0..n>` at every shape the bound can
//! take, through [`minocrab_std::v3::BoundedUint`] (M14,
//! notes/bounded-integers.org).
//!
//! Not a corpus contract: no compiled corpus artifact carries a
//! non-power-of-two bound (the scan is in the fixture's header and in the
//! note's §5), so the source is ours and lives beside its differential at
//! `tests/fixtures/bounded/`, compiled with the PINNED compactc. Everything
//! else is the established route — one module per contract, one `#[circuit]`
//! per exported circuit, and a differential asserting call-compatibility
//! with compactc's own artifact.
//!
//! **THE RANGE END IS EXCLUSIVE.** compactc rejects `Uint<0..0>` with "range
//! end for Uint type is 0 but must be at least 1 (the range end is
//! exclusive)", and `contract-info.json` publishes `maxval: 9` for
//! `Uint<0..10>`. So `BoundedUint<10>` IS `Uint<0..10>`, digit for digit,
//! and holds `0..=9`.
//!
//! What the nine argument shapes below cover, and why each is here:
//!
//! | circuit | Compact | what compactc emits |
//! |---|---|---|
//! | `b10` / `b300` / `b1000` / `b70000` | the README fairness bullet's four bounds | `less_than x n bits` + `assert` |
//! | `b1` | `Uint<0..1>` — holds only zero | `constrain_eq x 0` |
//! | `b2` | `Uint<0..2>` — Boolean | `constrain_to_boolean x` |
//! | `b256` | a bound that IS a power of two | `constrain_bits x 8`, no `less_than` |
//! | `b255` | the bound that LOOKS sized and is not (0..=254) | `less_than x 255 8` + `assert` |
//! | `bEnum` | a 3-name fieldless enum = `Uint<0..3>` | `less_than x 3 2` + `assert` |
//! | `bStruct` | a bounded field beside sized ones | the four constraints, in field order |
//! | `bCompare` | two bounded arguments, compared | constraints at 18 bits, the COMPARISON at 17 |
//!
//! Which of the four constraints a bound gets is never this file's decision
//! and never the leaf's: [`BoundedUint::constrain_input`] hands the maxval to
//! compactc's own ported table (`minocrab::v3::Prim::constraint`). That is
//! the whole claim the differential checks.

use minocrab::v3::Circuit3;
use minocrab::Public;
use minocrab_std::v3::{
    circuit, label, Bool, BoundedUint, Bytes, CircuitArg, Disclose, Discloses, Ledger,
    LedgerCell, LedgerCounter, Uint,
};

label! {
    LeftOperand = "left operand";
    RightOperand = "right operand";
}

/// THE LEDGER BLOCK — `export ledger dummy: Counter;` and
/// `export ledger flag: Boolean;`, declaration order being the field index.
///
/// `dummy` exists for one reason: a PURE exported Compact circuit produces no
/// `.zkir` at all, so a circuit that is only an argument constraint has to
/// touch the ledger to be compiled into an artifact worth comparing against.
#[derive(Ledger)]
pub struct Bounded {
    pub dummy: LedgerCounter,
    pub flag: LedgerCell<Bool<Public>>,
}

/// The contract's ledger block.
pub const BOUNDED: Bounded = Bounded::new();

/// `export circuit b10(x: Uint<0..10>): [] { dummy.increment(1); }`.
#[circuit]
pub fn b10(c: &mut Circuit3, x: BoundedUint<10>) -> Discloses<()> {
    let _ = x;
    BOUNDED.dummy.increment(c, 1);
    Discloses::of(())
}

/// `export circuit b300(x: Uint<0..300>): []`.
#[circuit]
pub fn b300(c: &mut Circuit3, x: BoundedUint<300>) -> Discloses<()> {
    let _ = x;
    BOUNDED.dummy.increment(c, 1);
    Discloses::of(())
}

/// `export circuit b1000(x: Uint<0..1000>): []`.
#[circuit]
pub fn b1000(c: &mut Circuit3, x: BoundedUint<1000>) -> Discloses<()> {
    let _ = x;
    BOUNDED.dummy.increment(c, 1);
    Discloses::of(())
}

/// `export circuit b70000(x: Uint<0..70000>): []` — the widest bound in the
/// fairness bullet, and the one whose three widths all differ (constraint
/// 18, comparison 17, FAB atom 3 bytes).
#[circuit]
pub fn b70000(c: &mut Circuit3, x: BoundedUint<70000>) -> Discloses<()> {
    let _ = x;
    BOUNDED.dummy.increment(c, 1);
    Discloses::of(())
}

/// `export circuit b1(x: Uint<0..1>): []` — the type holding only zero, so
/// the table's `constrain_eq 0` arm. Its FAB atom is ZERO bytes wide.
#[circuit]
pub fn b1(c: &mut Circuit3, x: BoundedUint<1>) -> Discloses<()> {
    let _ = x;
    BOUNDED.dummy.increment(c, 1);
    Discloses::of(())
}

/// `export circuit b2(x: Uint<0..2>): []` — Compact's `Boolean` by another
/// name, so `constrain_to_boolean`.
#[circuit]
pub fn b2(c: &mut Circuit3, x: BoundedUint<2>) -> Discloses<()> {
    let _ = x;
    BOUNDED.dummy.increment(c, 1);
    Discloses::of(())
}

/// `export circuit b256(x: Uint<0..256>): []` — a bound that IS a power of
/// two, which compactc lowers as a BIT WIDTH (`constrain_bits 8`), not a
/// `less_than`. The leaf does not reject it and does not special-case it:
/// `Prim::unsigned(255)` normalizes to `Prim::Uint { bits: 8 }` and the
/// table does the rest, so `BoundedUint<256>` and `Uint<8>` emit the same
/// instruction.
#[circuit]
pub fn b256(c: &mut Circuit3, x: BoundedUint<256>) -> Discloses<()> {
    let _ = x;
    BOUNDED.dummy.increment(c, 1);
    Discloses::of(())
}

/// `export circuit b255(x: Uint<0..255>): []` — the bound that looks like a
/// byte and is not: it admits `0..=254`, so it is a `less_than 255` at 8
/// bits. The one-off-a-power-of-two case is why the leaf takes the bound and
/// not a width.
#[circuit]
pub fn b255(c: &mut Circuit3, x: BoundedUint<255>) -> Discloses<()> {
    let _ = x;
    BOUNDED.dummy.increment(c, 1);
    Discloses::of(())
}

/// `enum Status { pending, live, closed }` as an argument: Compact's
/// `Uint<0..3>`, so `less_than 3` at 2 bits. A fieldless enum has no Rust
/// representation beyond its index — the VARIANT INDEX is the whole value —
/// which is why the interface generator maps it to this same leaf.
#[circuit]
pub fn b_enum(c: &mut Circuit3, x: BoundedUint<3>) -> Discloses<()> {
    let _ = x;
    BOUNDED.dummy.increment(c, 1);
    Discloses::of(())
}

/// `struct Order { kind: Status, quantity: Uint<0..1000>, price: Uint<64>,
/// tag: Bytes<4> }` — a bounded leaf inside `#[derive(CircuitArg)]`, whose
/// generated `constrain` runs the table over the four slots in field order.
#[derive(CircuitArg)]
pub struct Order {
    pub kind: BoundedUint<3>,
    pub quantity: BoundedUint<1000>,
    pub price: Uint<64>,
    pub tag: Bytes<4>,
}

/// `export circuit bStruct(order: Order): []`.
#[circuit]
pub fn b_struct(c: &mut Circuit3, order: Order) -> Discloses<()> {
    let _ = order;
    BOUNDED.dummy.increment(c, 1);
    Discloses::of(())
}

/// `export circuit bCompare(a: Uint<0..70000>, b: Uint<0..70000>): []
/// { flag = disclose(a) < disclose(b); }` — the circuit that shows the two
/// widths apart: each argument is range-constrained at compactc's
/// even-rounded 18 bits, and the ORDERING between them runs at 17, the bit
/// length of the largest legal value. Both numbers come from the type, so
/// neither is hand-written here.
#[circuit]
pub fn b_compare(
    c: &mut Circuit3,
    a: BoundedUint<70000>,
    b: BoundedUint<70000>,
) -> Discloses<(LeftOperand, RightOperand)> {
    let a = a.disclose_as::<LeftOperand>(c);
    let b = b.disclose_as::<RightOperand>(c);
    let less = a.lt(b).eval(c);
    BOUNDED.flag.write(c, &less);
    Discloses::of(())
}
