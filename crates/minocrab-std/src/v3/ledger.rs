//! The ledger block as TYPES: `#[derive(Ledger)]`, [`LedgerMap`],
//! [`LedgerCell`], [`LedgerCounter`].
//!
//! Below this module, `minocrab_ledger` emits compactc's vm-code for one
//! ledger operation at a time and takes two things a caller has to get right
//! by hand: the FIELD INDEX (a `u8`) and the value's FAB ATOMS (a
//! `Vec<AlignmentAtom>` written out at the call site). Both are silent
//! hazards — an index off by one reads another field, an atom list that does
//! not match the stored value's changes the PI stream — and neither is
//! visible to a type checker.
//!
//! This module removes both, and nothing else:
//!
//! - the index comes from the DECLARATION ORDER of a `#[derive(Ledger)]`
//!   struct that mirrors the Compact `export ledger` block, so the mapping
//!   lives once, where the fields are declared;
//! - the atoms come from the key/value TYPE through [`LedgerRepr`], so
//!   `Map<RequestId, Bytes<32>>` is `LedgerMap<B32<Public>, B32<Public>>` and
//!   nobody writes `vec![AlignmentAtom::Bytes { length: 32 }]` again.
//!
//! THE INVARIANT (notes/contract-api.org §The design): no method here issues
//! more Impact ops than the one Compact operation it names. Every method is a
//! one-line call into `minocrab_ledger`, and `c` and the guard stay VISIBLE
//! in the signature — a ledger operation is a cost, and the call site says so.
//! `map[k]` sugar, `Deref`, `entry()` and iterators are REJECTED for the same
//! reason.

use std::marker::PhantomData;

use minocrab::v3::{CallArg, CallResult, Circuit3, CircuitAbi, FieldT, Wire3};
use minocrab::{AlignmentAtom, Public, Visibility};
use minocrab_ledger::{
    cell_read, cell_read_guarded, cell_write, counter_increment, counter_less_than, counter_read,
    counter_read_guarded, emit, map_insert, map_is_empty, map_lookup, map_lookup_guarded,
    map_member, map_member_guarded, map_remove, map_size, ImpactElem, LedgerValue,
};

use super::{Bool, Bytes, BytesN, ContractAddress, Uint, B32};

/// What a ledger slot's key or value type must be able to do: name its FAB
/// atoms, hand over its limbs, and be rebuilt from the limbs a read witnesses.
///
/// The three facts are exactly [`CircuitAbi::atoms`],
/// [`CallArg::push_call_slots`] and [`CallResult::from_call_slots`] — a
/// ledger write and a cross-contract argument are the same crossing (a
/// public, FAB-aligned value leaving the circuit), so the leaf impls below
/// DELEGATE rather than restate. `LedgerRepr` exists as its own trait, and
/// does NOT require `CircuitAbi`, because a stored record is not an argument:
/// a ledger read is checked by the op's `popeq`, never range-constrained, so
/// requiring [`CircuitAbi::prims`] would make every record type declare
/// constraints that nothing emits.
///
/// Implemented at [`Public`] only, and that is the same soundness statement
/// `CallArg` makes: what the ledger holds is public, so a private value has
/// to pass `disclose` before it can be written — forgetting is a compile
/// error rather than a leak.
pub trait LedgerRepr: Sized {
    /// This type's FAB atoms, in slot order.
    fn atoms() -> Vec<AlignmentAtom>;

    /// This value's limbs, in slot order.
    fn push_limbs(&self, limbs: &mut Vec<Wire3<FieldT, Public>>);

    /// Rebuild from a read's limbs, in slot order.
    fn from_limbs(limbs: Vec<Wire3<FieldT, Public>>) -> Self;

    /// This value's limbs, in slot order.
    fn limbs(&self) -> Vec<Wire3<FieldT, Public>> {
        let mut limbs = Vec::new();
        self.push_limbs(&mut limbs);
        limbs
    }

    /// The value as `minocrab_ledger` takes it: atoms from the TYPE, limbs
    /// from the value. This is the method that kills hand-written atom lists.
    fn ledger_value(&self) -> LedgerValue {
        LedgerValue::new(
            Self::atoms(),
            self.limbs().into_iter().map(ImpactElem::Wire).collect(),
        )
    }
}

/// The leaf impls: pure delegation to the ABI traits, so a leaf's atoms and
/// limb order are stated in exactly one place (`entry.rs` / `call.rs`).
macro_rules! ledger_repr_via_abi {
    ($( $(#[$m:meta])* [$($gen:tt)*] $ty:ty ),* $(,)?) => {$(
        $(#[$m])*
        impl<$($gen)*> LedgerRepr for $ty {
            fn atoms() -> Vec<AlignmentAtom> {
                <$ty as CircuitAbi>::atoms()
            }

            fn push_limbs(&self, limbs: &mut Vec<Wire3<FieldT, Public>>) {
                <$ty as CallArg>::push_call_slots(self, limbs)
            }

            fn from_limbs(limbs: Vec<Wire3<FieldT, Public>>) -> Self {
                debug_assert_eq!(
                    limbs.len(),
                    <$ty as CircuitAbi>::SLOTS,
                    "ledger read handed back the wrong number of limbs"
                );
                <$ty as CallResult>::from_call_slots(&limbs)
            }
        }
    )*};
}

ledger_repr_via_abi! {
    [const BITS: u32] Uint<BITS, Public>,
    [] Bool<Public>,
    [const N: usize] Bytes<N, Public>,
    [] B32<Public>,
    [const N: usize] BytesN<Public, N>,
    [] ContractAddress<Public>,
}

// ---- the ledger slots -------------------------------------------------------
//
// Each is a `u8` index and the phantom types of what it holds, constructed by
// the `at(index)` the derive calls. They are `const`-constructible so a
// contract's ledger block is a `const` item and costs nothing at run time.

/// `export ledger m: Map<K, V>` — Compact's `Map` methods, one Impact
/// operation each.
///
/// Every method takes `c` and the guard, because every one of them costs: a
/// read mints one `public_input` gate per FAB limb of what it reads and then
/// emits the op's Impact instructions; a write emits the op's instructions.
/// The `_guarded` variants are the reads inside a conditional branch (the
/// guard rides the transcript gates as well as the instructions), matching
/// `minocrab_ledger`'s own pairing.
pub struct LedgerMap<K, V> {
    index: u8,
    _kv: PhantomData<fn() -> (K, V)>,
}

impl<K, V> LedgerMap<K, V> {
    /// The map held in ledger field `index` (the derive supplies it).
    pub const fn at(index: u8) -> Self {
        LedgerMap {
            index,
            _kv: PhantomData,
        }
    }

    /// The ledger field index.
    pub const fn index(&self) -> u8 {
        self.index
    }
}

impl<K: LedgerRepr, V: LedgerRepr> LedgerMap<K, V> {
    /// `map.member(key)` — `dup 0; idx [field]; push key; member; popeqc`.
    pub fn member<G: Visibility + Copy>(
        &self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, G>,
        key: &K,
    ) -> Bool<Public> {
        Bool::from_field(map_member(c, guard, self.index, &key.ledger_value()))
    }

    /// [`LedgerMap::member`] inside a conditional branch.
    pub fn member_guarded<G: Visibility + Copy>(
        &self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, G>,
        key: &K,
    ) -> Bool<Public> {
        Bool::from_field(map_member_guarded(c, guard, self.index, &key.ledger_value()))
    }

    /// `map.lookup(key)` — `dup 0; idx [field]; idx {key}; popeq`. The value
    /// atoms come from `V`.
    pub fn lookup<G: Visibility + Copy>(
        &self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, G>,
        key: &K,
    ) -> V {
        V::from_limbs(map_lookup(
            c,
            guard,
            self.index,
            &key.ledger_value(),
            V::atoms(),
        ))
    }

    /// [`LedgerMap::lookup`] inside a conditional branch.
    pub fn lookup_guarded<G: Visibility + Copy>(
        &self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, G>,
        key: &K,
    ) -> V {
        V::from_limbs(map_lookup_guarded(
            c,
            guard,
            self.index,
            &key.ledger_value(),
            V::atoms(),
        ))
    }

    /// `map.insert(key, value)` — `idxp [field]; push key; pushs value;
    /// ins 1; insc 1`.
    pub fn insert<G: Visibility + Copy>(
        &self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, G>,
        key: &K,
        value: &V,
    ) {
        emit(
            c,
            guard,
            &map_insert(self.index, &key.ledger_value(), &value.ledger_value()),
        );
    }

    /// `map.remove(key)` — `idxp [field]; push key; rem; insc 1`.
    pub fn remove<G: Visibility + Copy>(
        &self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, G>,
        key: &K,
    ) {
        emit(c, guard, &map_remove(self.index, &key.ledger_value()));
    }

    /// `map.size()` — `dup 0; idx [field]; size; popeqc`.
    pub fn size<G: Visibility + Copy>(
        &self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, G>,
    ) -> Uint<64, Public> {
        Uint::from_field(map_size(c, guard, self.index))
    }

    /// `map.isEmpty()` — `dup 0; idx [field]; size; push 0; eq; popeqc`.
    pub fn is_empty<G: Visibility + Copy>(
        &self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, G>,
    ) -> Bool<Public> {
        Bool::from_field(map_is_empty(c, guard, self.index))
    }
}

/// `export ledger x: T` — a Cell.
pub struct LedgerCell<T> {
    index: u8,
    _t: PhantomData<fn() -> T>,
}

impl<T> LedgerCell<T> {
    /// The cell held in ledger field `index`.
    pub const fn at(index: u8) -> Self {
        LedgerCell {
            index,
            _t: PhantomData,
        }
    }

    /// The ledger field index.
    pub const fn index(&self) -> u8 {
        self.index
    }
}

impl<T: LedgerRepr> LedgerCell<T> {
    /// `x` (a Cell read) — `dup 0; idx [field]; popeq`.
    pub fn read<G: Visibility + Copy>(&self, c: &mut Circuit3, guard: Wire3<FieldT, G>) -> T {
        T::from_limbs(cell_read(c, guard, self.index, T::atoms()))
    }

    /// [`LedgerCell::read`] inside a conditional branch.
    pub fn read_guarded<G: Visibility + Copy>(
        &self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, G>,
    ) -> T {
        T::from_limbs(cell_read_guarded(c, guard, self.index, T::atoms()))
    }

    /// `x = value` — `push key; pushs value; ins 1`.
    pub fn write<G: Visibility + Copy>(
        &self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, G>,
        value: &T,
    ) {
        emit(c, guard, &cell_write(self.index, &value.ledger_value()));
    }
}

/// `export ledger n: Counter`.
pub struct LedgerCounter {
    index: u8,
}

impl LedgerCounter {
    /// The counter held in ledger field `index`.
    pub const fn at(index: u8) -> Self {
        LedgerCounter { index }
    }

    /// The ledger field index.
    pub const fn index(&self) -> u8 {
        self.index
    }

    /// `n` (a Counter read) — `dup 0; idx [field]; popeqc`.
    pub fn read<G: Visibility + Copy>(
        &self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, G>,
    ) -> Uint<64, Public> {
        Uint::from_field(counter_read(c, guard, self.index))
    }

    /// [`LedgerCounter::read`] inside a conditional branch.
    pub fn read_guarded<G: Visibility + Copy>(
        &self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, G>,
    ) -> Uint<64, Public> {
        Uint::from_field(counter_read_guarded(c, guard, self.index))
    }

    /// `n.increment(amount)` — `idxp [field]; addi amount; insc 1`.
    pub fn increment<G: Visibility + Copy>(
        &self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, G>,
        amount: u32,
    ) {
        emit(c, guard, &counter_increment(self.index, amount));
    }

    /// `n.lessThan(threshold)` — `dup 0; idx [field]; push threshold; lt;
    /// popeqc`.
    pub fn less_than<G: Visibility + Copy>(
        &self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, G>,
        threshold: u64,
    ) -> Bool<Public> {
        let threshold = LedgerValue::bytes(
            8,
            vec![ImpactElem::Imm(minocrab::Fr::from(threshold))],
        );
        Bool::from_field(counter_less_than(c, guard, self.index, &threshold))
    }
}

/// A ledger field this layer does not model yet — a `Set`, a coin cell, a
/// curve-point cell — declared so that the fields AFTER it keep their
/// indices, and so that the struct is a faithful transcription of the
/// `export ledger` block. It carries its index and nothing else; the
/// operations stay explicit `minocrab_ledger` calls at the call site.
pub struct LedgerField {
    index: u8,
}

impl LedgerField {
    /// The field at ledger index `index`.
    pub const fn at(index: u8) -> Self {
        LedgerField { index }
    }

    /// The ledger field index.
    pub const fn index(&self) -> u8 {
        self.index
    }
}
