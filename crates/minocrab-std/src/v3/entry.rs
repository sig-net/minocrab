//! The circuit entry-point core: one trait per argument type that is at
//! once its schema, its declaration and its input constraints, and an
//! [`entry`] that owns the fixed build order every v3 circuit follows.
//!
//! The problem it solves (notes/contract-api.org §Survey): a hand-written
//! circuit declares its arguments in one block and range-constrains them in
//! a second, parallel block, and nothing but the author's eye ties the two
//! together — a missing `assert_bits` is invisible to the differential
//! tests, because an honest preimage satisfies the circuit either way. Here
//! both blocks are generated from the argument's type, so they cannot
//! disagree.
//!
//! The three laws every [`CircuitArg`] impl must satisfy:
//!
//! 1. `declare` touches exactly [`CircuitArg::SLOTS`] argument slots and
//!    calls nothing but [`Circuit3::arg`] — ZKIR requires every input to
//!    precede every instruction, so declaration cannot compute.
//! 2. `push_atoms` describes exactly those slots, in the same order (the
//!    FAB atoms of the Compact type the argument stands for).
//! 3. `constrain` emits exactly the input constraints compactc emits for
//!    that Compact type, in slot order.
//!
//! [`entry`] enforces the parts of law 1 that are checkable — the slot
//! count and the emptiness of the instruction stream after declaration —
//! and orders the two phases so law 3's "in slot order" is all an impl has
//! to get right.

use minocrab::v3::{Circuit3, Compiled3, FieldT};
use minocrab::{AlignmentAtom, Private, Public};

use super::{Bool, Bytes, BytesN, Either, Maybe, Uint, B32};

// ---- argument paths ---------------------------------------------------------

/// The label of one argument slot, built from the argument's name and the
/// path to the slot inside it: segments joined with `_`.
///
/// The rule, stated once for every impl below:
/// - a struct field appends its Compact field name ([`ArgPath::field`]) —
///   `depositRequest` + `erc20Address` = `depositRequest_erc20Address`;
/// - an element of a vector or a limb of a multi-slot leaf appends its
///   index ([`ArgPath::index`]) — `notification_payload_0`;
/// - a structural slot appends the suffix its shape owns
///   ([`ArgPath::suffix`]): `_hi`/`_lo` for a `Bytes<32>` pair, `_is_some`
///   for a `Maybe` tag, `_is_left` for an `Either` tag.
///
/// compactc itself does not flatten struct arguments this way (it repeats
/// the base name: `%depositRequest.5`, `%depositRequest.6`); the joined
/// path is ours and is strictly more informative. Argument names are
/// cosmetic to the ledger ABI — order and type are the contract — so this
/// is a free improvement (notes/contract-api.org §Survey).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArgPath(String);

impl ArgPath {
    /// The argument itself: the Compact parameter name, verbatim.
    pub fn root(name: &str) -> ArgPath {
        ArgPath(name.to_string())
    }

    /// A struct field of this value.
    pub fn field(&self, name: &str) -> ArgPath {
        self.join(name)
    }

    /// Element / limb `i` of this value.
    pub fn index(&self, i: usize) -> ArgPath {
        self.join(&i.to_string())
    }

    /// A structural slot of this value (`hi`, `lo`, `is_some`, `is_left`).
    pub fn suffix(&self, suffix: &str) -> ArgPath {
        self.join(suffix)
    }

    /// The label as `Circuit3::arg` takes it.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn join(&self, segment: &str) -> ArgPath {
        ArgPath(format!("{}_{segment}", self.0))
    }
}

impl std::fmt::Display for ArgPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ---- CircuitArg -------------------------------------------------------------

/// A type usable as (part of) a circuit argument: its slot count, its FAB
/// atoms, how it is declared, and how it is constrained on entry — one
/// trait, so a schema and its materialization cannot drift apart (the
/// `CandidType` lesson, notes/contract-api.org §Survey).
///
/// Implemented for [`Private`] leaves only: circuit arguments are witness
/// data, so [`Circuit3::arg`] can only hand back private wires.
///
/// See the module docs for the three laws an impl must satisfy.
pub trait CircuitArg: Sized {
    /// Argument slots this type occupies.
    const SLOTS: usize;

    /// The FAB atoms of these slots, in slot order.
    fn push_atoms(atoms: &mut Vec<AlignmentAtom>);

    /// Declare the slots — `Circuit3::arg` calls and nothing else.
    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self;

    /// Emit compactc's input constraints for this type, in slot order.
    fn constrain(&self, c: &mut Circuit3);

    /// The FAB atoms of these slots, in slot order.
    fn atoms() -> Vec<AlignmentAtom> {
        let mut atoms = Vec::new();
        Self::push_atoms(&mut atoms);
        atoms
    }
}

impl<const BITS: u32> CircuitArg for Uint<BITS, Private> {
    const SLOTS: usize = 1;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        atoms.push(AlignmentAtom::Bytes { length: BITS.div_ceil(8) });
    }

    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        Uint::from_field(c.arg::<FieldT>(path.as_str()))
    }

    fn constrain(&self, c: &mut Circuit3) {
        self.constrain_input(c);
    }
}

impl CircuitArg for Bool<Private> {
    const SLOTS: usize = 1;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        atoms.push(AlignmentAtom::Bytes { length: 1 });
    }

    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        Bool::from_field(c.arg::<FieldT>(path.as_str()))
    }

    fn constrain(&self, c: &mut Circuit3) {
        self.constrain_input(c);
    }
}

impl<const N: usize> CircuitArg for Bytes<N, Private> {
    const SLOTS: usize = 1;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        atoms.push(AlignmentAtom::Bytes { length: N as u32 });
    }

    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        Bytes::from_field(c.arg::<FieldT>(path.as_str()))
    }

    fn constrain(&self, c: &mut Circuit3) {
        self.constrain_input(c);
    }
}

impl CircuitArg for B32<Private> {
    const SLOTS: usize = 2;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        atoms.push(AlignmentAtom::Bytes { length: 32 });
    }

    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        B32 {
            hi: c.arg::<FieldT>(path.suffix("hi").as_str()),
            lo: c.arg::<FieldT>(path.suffix("lo").as_str()),
        }
    }

    fn constrain(&self, c: &mut Circuit3) {
        self.constrain_input(c);
    }
}

impl<const N: usize> CircuitArg for BytesN<Private, N> {
    const SLOTS: usize = Self::LIMBS;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        atoms.extend(Self::atoms());
    }

    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        BytesN::from_limbs(
            (0..Self::LIMBS)
                .map(|i| c.arg::<FieldT>(path.index(i).as_str()))
                .collect(),
        )
    }

    fn constrain(&self, c: &mut Circuit3) {
        self.constrain_input(c);
    }
}

/// Compact's `Vector<N, T>`: `N` copies of `T` back to back, each element
/// labelled with its index (`words_0`, `words_1`, ...).
impl<T: CircuitArg, const N: usize> CircuitArg for [T; N] {
    const SLOTS: usize = T::SLOTS * N;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        for _ in 0..N {
            T::push_atoms(atoms);
        }
    }

    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        // Built through a Vec rather than `array::from_fn`, whose call order
        // is not part of its contract: here the order IS the wire layout.
        let mut elements = Vec::with_capacity(N);
        for i in 0..N {
            elements.push(T::declare(c, &path.index(i)));
        }
        match <[T; N]>::try_from(elements) {
            Ok(array) => array,
            Err(_) => unreachable!("N elements were pushed"),
        }
    }

    fn constrain(&self, c: &mut Circuit3) {
        for element in self {
            element.constrain(c);
        }
    }
}

/// Compact's `Maybe<T>`: the `is_some` tag followed by the value, which
/// occupies its slots whether or not the tag is set.
///
/// The tag takes the `_is_some` suffix and the value keeps the parent's
/// path — a `Maybe` adds a slot, not a level (`recipient_is_some` then
/// `recipient_...`), which is how the hand-written `claim` labels its
/// `Maybe<Either<..>>` recipient.
impl<T: CircuitArg> CircuitArg for Maybe<T, Private> {
    const SLOTS: usize = <Bool<Private> as CircuitArg>::SLOTS + T::SLOTS;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        <Bool<Private> as CircuitArg>::push_atoms(atoms);
        T::push_atoms(atoms);
    }

    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        Maybe {
            is_some: CircuitArg::declare(c, &path.suffix("is_some")),
            value: T::declare(c, path),
        }
    }

    fn constrain(&self, c: &mut Circuit3) {
        self.is_some.constrain(c);
        self.value.constrain(c);
    }
}

/// Compact's `Either<A, B>`: the `is_left` tag followed by both arms, each
/// of which occupies its slots whichever way the tag points
/// (`recipient_is_left`, `recipient_left_...`, `recipient_right_...`).
impl<A: CircuitArg, B: CircuitArg> CircuitArg for Either<A, B, Private> {
    const SLOTS: usize = <Bool<Private> as CircuitArg>::SLOTS + A::SLOTS + B::SLOTS;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        <Bool<Private> as CircuitArg>::push_atoms(atoms);
        A::push_atoms(atoms);
        B::push_atoms(atoms);
    }

    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        Either {
            is_left: CircuitArg::declare(c, &path.suffix("is_left")),
            left: A::declare(c, &path.field("left")),
            right: B::declare(c, &path.field("right")),
        }
    }

    fn constrain(&self, c: &mut Circuit3) {
        self.is_left.constrain(c);
        self.left.constrain(c);
        self.right.constrain(c);
    }
}

// ---- CircuitArgs ------------------------------------------------------------

/// A circuit's whole argument list: the per-circuit struct whose fields are
/// the Compact parameters, in declaration order.
///
/// Field order IS the wire contract — it feeds the input schema, the
/// communications commitment and the preimage layout — so an impl declares
/// and constrains its fields in exactly the order the Compact signature
/// lists them (the rule is precedented in `signet.rs`'s record layouts, and
/// backstopped by the interface snapshot and PI equality).
///
/// Written by hand for now; phase 3's `#[derive(CircuitArg)]` /
/// `#[circuit]` generate exactly these impls.
pub trait CircuitArgs: Sized {
    /// Total argument slots — the sum of the fields' [`CircuitArg::SLOTS`].
    const SLOTS: usize;

    /// Declare every field, in declaration order.
    fn declare(c: &mut Circuit3) -> Self;

    /// Constrain every field, in declaration order.
    fn constrain(&self, c: &mut Circuit3);

    /// The FAB atoms of the argument list, in slot order.
    fn atoms() -> Vec<AlignmentAtom>;
}

/// The empty argument list.
impl CircuitArgs for () {
    const SLOTS: usize = 0;

    fn declare(_c: &mut Circuit3) -> Self {}

    fn constrain(&self, _c: &mut Circuit3) {}

    fn atoms() -> Vec<AlignmentAtom> {
        Vec::new()
    }
}

// ---- CircuitOut -------------------------------------------------------------

/// A value a circuit may return: queued as circuit outputs by [`entry_out`].
///
/// Implemented only for [`Public`] values — returning a value discloses it,
/// so a private one has to pass through `Circuit3::disclose` before it can
/// be returned, and forgetting to is a compile error rather than a leak.
///
/// `label` names the logical value; a multi-slot impl suffixes each slot
/// the way the hand-written circuits do (`"event hash (hi)"` /
/// `"(lo)"`). Output labels live only in the disclosure record — ZKIR's
/// output signature is types only — and phase 6 replaces the string with a
/// declared label type.
pub trait CircuitOut {
    /// Output slots this value occupies.
    const SLOTS: usize;

    /// Queue the slots as circuit outputs, in wire order.
    fn emit(self, c: &mut Circuit3, label: &str);
}

/// `[]` — a circuit that returns nothing.
impl CircuitOut for () {
    const SLOTS: usize = 0;

    fn emit(self, _c: &mut Circuit3, _label: &str) {}
}

impl<const BITS: u32> CircuitOut for Uint<BITS, Public> {
    const SLOTS: usize = 1;

    fn emit(self, c: &mut Circuit3, label: &str) {
        c.output(self.field(), label);
    }
}

impl CircuitOut for Bool<Public> {
    const SLOTS: usize = 1;

    fn emit(self, c: &mut Circuit3, label: &str) {
        c.output(self.field(), label);
    }
}

impl<const N: usize> CircuitOut for Bytes<N, Public> {
    const SLOTS: usize = 1;

    fn emit(self, c: &mut Circuit3, label: &str) {
        c.output(self.field(), label);
    }
}

impl CircuitOut for B32<Public> {
    const SLOTS: usize = 2;

    fn emit(self, c: &mut Circuit3, label: &str) {
        c.output(self.hi, &format!("{label} (hi)"));
        c.output(self.lo, &format!("{label} (lo)"));
    }
}

// ---- entry ------------------------------------------------------------------

/// Build a circuit that returns `[]`: the fixed order every v3 entry point
/// follows — declare every argument, check the declaration, constrain every
/// argument, run the body, finish.
///
/// ```ignore
/// pub fn deposit() -> Compiled3 {
///     entry(|c, args: DepositArgs| { .. })
/// }
/// ```
pub fn entry<A: CircuitArgs>(body: impl FnOnce(&mut Circuit3, A)) -> Compiled3 {
    entry_out("", |c, args| body(c, args))
}

/// [`entry`] for a circuit that returns a value: `label` names the returned
/// value in the disclosure record (see [`CircuitOut`]).
pub fn entry_out<A: CircuitArgs, O: CircuitOut>(
    label: &str,
    body: impl FnOnce(&mut Circuit3, A) -> O,
) -> Compiled3 {
    let mut c = Circuit3::new();

    // Phase 1: declaration only. ZKIR requires every input to precede
    // every instruction, which is why this is separate from constraining
    // at all — and why both halves of law 1 are worth checking.
    let args = A::declare(&mut c);
    assert_eq!(
        c.arg_count(),
        A::SLOTS,
        "CircuitArgs::declare touched {} argument slots, but SLOTS says {}",
        c.arg_count(),
        A::SLOTS
    );
    assert_eq!(
        c.instruction_count(),
        0,
        "CircuitArgs::declare emitted instructions; declaration may only call Circuit3::arg"
    );

    // Phase 2: compactc's input constraints, derived from the types.
    args.constrain(&mut c);

    let out = body(&mut c, args);
    out.emit(&mut c, label);

    // Every ported circuit is an exported entry point, and every exported
    // entry point commits to its cross-contract communications; the
    // hand-written circuits all end in `finish(true)`.
    c.finish(true)
}
