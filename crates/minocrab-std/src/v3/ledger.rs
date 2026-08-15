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

use minocrab::v3::{
    CallArg, CallResult, Circuit3, CircuitAbi, FieldT, Operand, Secp256k1PointT, Wire3,
};
use minocrab::{AlignmentAtom, Public, Visibility};
use minocrab_ledger::{
    cell_read_embedded, cell_write, counter_increment, counter_less_than, counter_read,
    counter_read_guarded, emit, map_insert, map_is_empty, map_lookup, map_lookup_guarded,
    map_member, map_member_guarded, map_remove, map_size, mint_read_with, ImpactElem, LedgerValue,
};

use super::{Bool, BoundedUint, Bytes, BytesN, ContractAddress, Secp256k1Point, Uint, B32};

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
    ///
    /// Takes `c` (M9 phase 8, candidate 2): a value whose limbs are COMPUTED
    /// rather than stored — a `Secp256k1Point`, whose five limbs come out of
    /// an `encode` INSTRUCTION — cannot hand them over without emitting, and
    /// before this it had to stay a [`LedgerField`] with the ops spelled out
    /// at the call site. THE PRICE, recorded because it was worth stating: a
    /// repr may now emit, so "building a `LedgerValue` is free" is no longer
    /// true by construction. What replaces it is narrower and still checkable:
    /// a repr emits exactly the instructions the call site would have emitted
    /// itself, immediately before the op, which is what
    /// `tests/v3_ledger.rs`'s byte-equality against the explicit form says.
    fn push_limbs(&self, c: &mut Circuit3, limbs: &mut Vec<Wire3<FieldT, Public>>);

    /// Rebuild from a read's limbs, in slot order.
    fn from_limbs(limbs: Vec<Wire3<FieldT, Public>>) -> Self;

    /// This value's limbs, in slot order.
    fn limbs(&self, c: &mut Circuit3) -> Vec<Wire3<FieldT, Public>> {
        let mut limbs = Vec::new();
        self.push_limbs(c, &mut limbs);
        limbs
    }

    /// The value as `minocrab_ledger` takes it: atoms from the TYPE, limbs
    /// from the value. This is the method that kills hand-written atom lists.
    fn ledger_value(&self, c: &mut Circuit3) -> LedgerValue {
        LedgerValue::new(
            Self::atoms(),
            self.limbs(c).into_iter().map(ImpactElem::Wire).collect(),
        )
    }

    /// Witness a READ of this type: the gates it mints, and the value the
    /// op's `popeq` embeds.
    ///
    /// The default is the native-limb shape — one `public_input` gate per FAB
    /// limb, rebuilt with [`LedgerRepr::from_limbs`] — which is what every
    /// FAB-aligned record does. The one type that overrides it is
    /// [`Secp256k1Point`]: a point cell mints ONE TYPED gate and DERIVES its
    /// five limbs with `encode`, so its read is not a limb read at all.
    fn witness_read<V: Visibility + Copy>(
        c: &mut Circuit3,
        guard: Option<Wire3<FieldT, V>>,
    ) -> (Self, LedgerValue) {
        let (wires, value) = mint_read_with(c, guard, Self::atoms());
        (Self::from_limbs(wires), value)
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

            fn push_limbs(&self, _c: &mut Circuit3, limbs: &mut Vec<Wire3<FieldT, Public>>) {
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
    [const BOUND: u128] BoundedUint<BOUND, Public>,
    [] Bool<Public>,
    [const N: usize] Bytes<N, Public>,
    [] B32<Public>,
    [const N: usize] BytesN<Public, N>,
    [] ContractAddress<Public>,
}

/// `export ledger k: Secp256k1Point` — the one stored type whose limbs are
/// COMPUTED, in both directions (M9 phase 8, candidate 2).
///
/// A point occupies one slot whose wire is not a field element, and its five
/// FAB limbs (x as b24+b8, y as b24+b8, the infinity field —
/// notes/ledger-abi.org §3) come out of an `encode` instruction. So both
/// halves of the crossing are overridden: [`LedgerRepr::push_limbs`] emits
/// the `encode` a write needs, and [`LedgerRepr::witness_read`] mints the
/// TYPED gate a read witnesses and encodes THAT (claim.zkir:29-33). Before
/// this the field had to be a [`LedgerField`] with `cell_read_point` and a
/// hand-written `cell_write` at the call sites.
impl LedgerRepr for Secp256k1Point<Public> {
    fn atoms() -> Vec<AlignmentAtom> {
        <Secp256k1Point<Public> as CircuitAbi>::atoms()
    }

    fn push_limbs(&self, c: &mut Circuit3, limbs: &mut Vec<Wire3<FieldT, Public>>) {
        limbs.extend(c.encode(self.point()));
    }

    /// UNREACHABLE by construction: [`LedgerRepr::witness_read`] is
    /// overridden below, and it is the only caller of `from_limbs` in this
    /// module. A point cannot be rebuilt from its encoding — ZKIR has
    /// `encode` and no inverse — so a `LedgerMap<_, Secp256k1Point>`, whose
    /// lookup does go through `from_limbs`, is not supported: store the
    /// point in a CELL (which is the only shape Compact's `Secp256k1Point`
    /// ledger fields take) or store the encoded limbs as a record type.
    fn from_limbs(_limbs: Vec<Wire3<FieldT, Public>>) -> Self {
        unreachable!(
            "a Secp256k1Point is read through its typed gate, not rebuilt from \
             its `encode` limbs — see the impl's docs for the supported shapes"
        )
    }

    fn witness_read<V: Visibility + Copy>(
        c: &mut Circuit3,
        guard: Option<Wire3<FieldT, V>>,
    ) -> (Self, LedgerValue) {
        let point = match guard {
            Some(g) => c.public_transcript_input_guarded::<Secp256k1PointT, V>(g),
            None => c.public_transcript_input::<Secp256k1PointT>(),
        };
        let point = Secp256k1Point::from_point(point);
        let mut limbs = Vec::new();
        point.push_limbs(c, &mut limbs);
        let value = LedgerValue::new(
            <Self as LedgerRepr>::atoms(),
            limbs.into_iter().map(ImpactElem::Wire).collect(),
        );
        (point, value)
    }
}

// ---- the ledger slots -------------------------------------------------------
//
// Each is a `u8` index and the phantom types of what it holds, constructed by
// the `at(index)` the derive calls. They are `const`-constructible so a
// contract's ledger block is a `const` item and costs nothing at run time.

/// `export ledger m: Map<K, V>` — Compact's `Map` methods, one Impact
/// operation each.
///
/// Every method takes `c`, because every one of them costs: a read mints one
/// `public_input` gate per FAB limb of what it reads and then emits the op's
/// Impact instructions; a write emits the op's instructions.
///
/// THREE FORMS, because an Impact operation carries a guard and there are
/// three things that guard can be (M9 phase 8, candidate 1):
///
/// | form | guard | when |
/// |------|-------|------|
/// | `member(c, &k)` | the immediate `1` | straight-line code |
/// | `member_under(c, g, &k)` | the wire `g` | an EFFECT under a branch condition |
/// | `member_guarded(c, g, &k)` | the wire `g`, on the gates too | a READ inside a branch |
///
/// The plain name is the straight-line one because that is what Compact
/// itself writes (`map.member(key)` — Compact has no guard argument at all),
/// and a straight-line circuit no longer threads a `one` wire through every
/// call site and every helper signature. It costs zero rows and REMOVES an
/// instruction (the `Copy` that named the `1`), and it is therefore no longer
/// byte-identical to compactc's stream, whose guard operand is that named
/// wire — which is why the three direct-port forks use `_under` throughout
/// and only the showcase twin uses the plain names.
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
    pub fn member(&self, c: &mut Circuit3, key: &K) -> Bool<Public> {
        self.member_under(c, STRAIGHT_LINE, key)
    }

    /// [`LedgerMap::member`] under a branch condition.
    pub fn member_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
        key: &K,
    ) -> Bool<Public> {
        let key = key.ledger_value(c);
        Bool::from_field(map_member(c, guard, self.index, &key))
    }

    /// [`LedgerMap::member`] inside a conditional branch.
    pub fn member_guarded<G: Visibility + Copy>(
        &self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, G>,
        key: &K,
    ) -> Bool<Public> {
        let key = key.ledger_value(c);
        Bool::from_field(map_member_guarded(c, guard, self.index, &key))
    }

    /// `map.lookup(key)` — `dup 0; idx [field]; idx {key}; popeq`. The value
    /// atoms come from `V`.
    pub fn lookup(&self, c: &mut Circuit3, key: &K) -> V {
        self.lookup_under(c, STRAIGHT_LINE, key)
    }

    /// [`LedgerMap::lookup`] under a branch condition.
    pub fn lookup_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
        key: &K,
    ) -> V {
        let key = key.ledger_value(c);
        V::from_limbs(map_lookup(c, guard, self.index, &key, V::atoms()))
    }

    /// [`LedgerMap::lookup`] inside a conditional branch.
    pub fn lookup_guarded<G: Visibility + Copy>(
        &self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, G>,
        key: &K,
    ) -> V {
        let key = key.ledger_value(c);
        V::from_limbs(map_lookup_guarded(
            c,
            guard,
            self.index,
            &key,
            V::atoms(),
        ))
    }

    /// `map.insert(key, value)` — `idxp [field]; push key; pushs value;
    /// ins 1; insc 1`.
    pub fn insert(&self, c: &mut Circuit3, key: &K, value: &V) {
        self.insert_under(c, STRAIGHT_LINE, key, value)
    }

    /// [`LedgerMap::insert`] under a branch condition.
    pub fn insert_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
        key: &K,
        value: &V,
    ) {
        let key = key.ledger_value(c);
        let value = value.ledger_value(c);
        emit(c, guard, &map_insert(self.index, &key, &value));
    }

    /// `map.remove(key)` — `idxp [field]; push key; rem; insc 1`.
    pub fn remove(&self, c: &mut Circuit3, key: &K) {
        self.remove_under(c, STRAIGHT_LINE, key)
    }

    /// [`LedgerMap::remove`] under a branch condition.
    pub fn remove_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
        key: &K,
    ) {
        let key = key.ledger_value(c);
        emit(c, guard, &map_remove(self.index, &key));
    }

    /// `map.size()` — `dup 0; idx [field]; size; popeqc`.
    pub fn size(&self, c: &mut Circuit3) -> Uint<64, Public> {
        self.size_under(c, STRAIGHT_LINE)
    }

    /// [`LedgerMap::size`] under a branch condition.
    pub fn size_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
    ) -> Uint<64, Public> {
        Uint::from_field(map_size(c, guard, self.index))
    }

    /// `map.isEmpty()` — `dup 0; idx [field]; size; push 0; eq; popeqc`.
    pub fn is_empty(&self, c: &mut Circuit3) -> Bool<Public> {
        self.is_empty_under(c, STRAIGHT_LINE)
    }

    /// [`LedgerMap::is_empty`] under a branch condition.
    pub fn is_empty_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
    ) -> Bool<Public> {
        Bool::from_field(map_is_empty(c, guard, self.index))
    }
}

/// The guard of a STRAIGHT-LINE ledger operation: the immediate `1`, inlined
/// into the Impact instruction rather than named by a `Copy` (see
/// [`LedgerMap`]).
const STRAIGHT_LINE: u64 = 1;

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
    pub fn read(&self, c: &mut Circuit3) -> T {
        self.read_under(c, STRAIGHT_LINE)
    }

    /// [`LedgerCell::read`] under a branch condition.
    pub fn read_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
    ) -> T {
        let (value, embed) = T::witness_read::<Public>(c, None);
        cell_read_embedded(c, guard, self.index, &embed);
        value
    }

    /// [`LedgerCell::read`] inside a conditional branch.
    pub fn read_guarded<G: Visibility + Copy>(
        &self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, G>,
    ) -> T {
        let (value, embed) = T::witness_read(c, Some(guard));
        cell_read_embedded(c, guard, self.index, &embed);
        value
    }

    /// `x = value` — `push key; pushs value; ins 1`.
    pub fn write(&self, c: &mut Circuit3, value: &T) {
        self.write_under(c, STRAIGHT_LINE, value)
    }

    /// [`LedgerCell::write`] under a branch condition.
    pub fn write_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
        value: &T,
    ) {
        let value = value.ledger_value(c);
        emit(c, guard, &cell_write(self.index, &value));
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
    pub fn read(&self, c: &mut Circuit3) -> Uint<64, Public> {
        self.read_under(c, STRAIGHT_LINE)
    }

    /// [`LedgerCounter::read`] under a branch condition.
    pub fn read_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
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
    pub fn increment(&self, c: &mut Circuit3, amount: u32) {
        self.increment_under(c, STRAIGHT_LINE, amount)
    }

    /// [`LedgerCounter::increment`] under a branch condition.
    pub fn increment_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
        amount: u32,
    ) {
        emit(c, guard, &counter_increment(self.index, amount));
    }

    /// `n.lessThan(threshold)` — `dup 0; idx [field]; push threshold; lt;
    /// popeqc`.
    pub fn less_than(&self, c: &mut Circuit3, threshold: u64) -> Bool<Public> {
        self.less_than_under(c, STRAIGHT_LINE, threshold)
    }

    /// [`LedgerCounter::less_than`] under a branch condition.
    pub fn less_than_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
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
