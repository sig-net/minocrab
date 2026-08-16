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
    AnyWire3, CallArg, CallResult, Circuit3, CircuitAbi, FieldT, JubjubPointT, Operand,
    Secp256k1PointT, Wire3,
};
use minocrab::{Alignment, AlignmentAtom, AlignmentSegment, Fr, Public, Visibility};
use minocrab_ledger::{
    atom_limbs, cell_read_embedded, cell_write, counter_increment, counter_less_than, counter_read,
    counter_read_guarded, emit, historic_merkle_tree_check_root, historic_merkle_tree_insert,
    historic_merkle_tree_insert_index, historic_merkle_tree_reset,
    historic_merkle_tree_reset_history, list_head, list_is_empty, list_length, list_pop_front,
    list_push_front, list_reset, map_insert, map_insert_default, map_is_empty, map_lookup,
    map_lookup_guarded, map_member, map_member_guarded, map_remove, map_reset, map_size,
    merkle_tree_check_root, merkle_tree_insert, merkle_tree_insert_index, merkle_tree_is_full,
    merkle_tree_reset, mint_read_with, set_insert, set_is_empty, set_remove, set_reset, set_size,
    ImpactElem, LedgerValue,
};

use super::{
    hash, Bool, BoundedUint, Bytes, BytesN, ContractAddress, JubjubPoint, Maybe, MerkleTreeDigest,
    Opaque, Secp256k1Point, TsType, Uint, B32,
};

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
    /// `MerkleTreeDigest` in a ledger slot — one limb under a `field` atom.
    /// A tree's roots are not STORED as digests (the tree holds them), but a
    /// `checkRoot` argument is pushed through this path, and a contract may
    /// keep one in a `Cell`.
    [] MerkleTreeDigest<Public>,
    [const BOUND: u128] BoundedUint<BOUND, Public>,
    [] Bool<Public>,
    [const N: usize] Bytes<N, Public>,
    [] B32<Public>,
    [const N: usize] BytesN<Public, N>,
    [] ContractAddress<Public>,
    /// `Opaque<'ts-type'>` in a ledger slot — one limb under a `compress`
    /// atom, which is the ordinary delegation. It is a `Cell` type, a `Map`
    /// KEY type, a `Map` VALUE type and a `Set` element type, all four of
    /// which the fixture exercises; unlike [`Secp256k1Point`] there is no
    /// shape it cannot take, because the commitment is a plain field limb
    /// that a read can hand straight back.
    [T: TsType] Opaque<T, Public>,
    /// `export ledger m: Maybe<T>` — Compact's `Maybe` is an ordinary struct
    /// (`{ is_some: Boolean, value: T }`), so a stored one is its tag's limb
    /// followed by the payload's, which is what the ABI delegation already
    /// says. The payload occupies its slots whether or not the tag is set;
    /// that is the format, not a choice made here.
    [T: CircuitAbi + CallArg + CallResult] Maybe<T, Public>,
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

/// `export ledger k: JubjubPoint` — the same computed-limb story as
/// [`Secp256k1Point`] above, over two `field` limbs instead of five mixed ones.
///
/// Both halves are overridden for the same reason: `encode` produces the limbs
/// and ZKIR has no inverse, so a write emits the `encode` and a read mints the
/// TYPED gate and encodes that. A `LedgerMap<_, JubjubPoint>` is therefore not
/// supported either — store it in a `Cell`, which is the only shape Compact's
/// own `JubjubPoint` ledger fields take (`test-center/compact/test`'s `x15`).
impl LedgerRepr for JubjubPoint<Public> {
    fn atoms() -> Vec<AlignmentAtom> {
        <JubjubPoint<Public> as CircuitAbi>::atoms()
    }

    fn push_limbs(&self, c: &mut Circuit3, limbs: &mut Vec<Wire3<FieldT, Public>>) {
        limbs.extend(c.encode(self.point()));
    }

    /// UNREACHABLE by construction — see [`Secp256k1Point`]'s impl, which
    /// carries the argument in full.
    fn from_limbs(_limbs: Vec<Wire3<FieldT, Public>>) -> Self {
        unreachable!(
            "a JubjubPoint is read through its typed gate, not rebuilt from \
             its `encode` limbs — see the impl's docs for the supported shapes"
        )
    }

    fn witness_read<V: Visibility + Copy>(
        c: &mut Circuit3,
        guard: Option<Wire3<FieldT, V>>,
    ) -> (Self, LedgerValue) {
        let point = match guard {
            Some(g) => c.public_transcript_input_guarded::<JubjubPointT, V>(g),
            None => c.public_transcript_input::<JubjubPointT>(),
        };
        let point = JubjubPoint::from_point(point);
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

    /// `map.insertDefault(key)` — `idxp [field]; push key; pushs default;
    /// ins 1; insc 1`. The stored value is `V`'s default, which is zeros in
    /// every one of its limbs (notes/ledger-adts.org finding (c)).
    pub fn insert_default(&self, c: &mut Circuit3, key: &K) {
        self.insert_default_under(c, STRAIGHT_LINE, key)
    }

    /// [`LedgerMap::insert_default`] under a branch condition.
    pub fn insert_default_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
        key: &K,
    ) {
        let key = key.ledger_value(c);
        emit(c, guard, &map_insert_default(self.index, &key, V::atoms()));
    }
}

impl<K, V> LedgerMap<K, V> {
    /// `map.resetToDefault()` — `push key; pushs (empty map); ins 1`. Needs
    /// no bound on `K`/`V`: an empty map is empty whatever it held.
    pub fn reset_to_default(&self, c: &mut Circuit3) {
        self.reset_to_default_under(c, STRAIGHT_LINE)
    }

    /// [`LedgerMap::reset_to_default`] under a branch condition.
    pub fn reset_to_default_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
    ) {
        emit(c, guard, &map_reset(self.index));
    }
}

/// The guard of a STRAIGHT-LINE ledger operation: the immediate `1`, inlined
/// into the Impact instruction rather than named by a `Copy` (see
/// [`LedgerMap`]).
const STRAIGHT_LINE: u64 = 1;

/// `export ledger s: Set<T>` — a `Map` with `Null` values, which is what
/// Compact's `Set` IS.
///
/// Every method here delegates to the `Map` one, and that is a fact about the
/// vm-code rather than a shortcut: compactc's `Set` and `Map` declarations
/// give `member`, `remove`, `size`, `isEmpty` and `resetToDefault` character
/// for character the same instruction sequences, and the M16 fixture's
/// `setRemove` / `setSize` / `setIsEmpty` / `setReset` are byte-identical to
/// `map_remove` / `map_size` / `map_is_empty` / `map_reset`
/// (notes/ledger-adts.org §1). Only [`insert`](LedgerSet::insert) differs, and
/// only in what it stores: a `Null` where a map stores a value.
///
/// Landed at M15 with `insert` and `member` (M15's fixture stores an
/// [`Opaque`] in a `Set`); M16 completed it rather than adding a second `Set`.
pub struct LedgerSet<T> {
    index: u8,
    _t: PhantomData<fn() -> T>,
}

impl<T> LedgerSet<T> {
    /// The set held in ledger field `index` (the derive supplies it).
    pub const fn at(index: u8) -> Self {
        LedgerSet {
            index,
            _t: PhantomData,
        }
    }

    /// The ledger field index.
    pub const fn index(&self) -> u8 {
        self.index
    }
}

impl<T: LedgerRepr> LedgerSet<T> {
    /// `set.insert(elem)` — `idxp [field]; push elem; pushs null; ins 1; insc 1`.
    pub fn insert(&self, c: &mut Circuit3, elem: &T) {
        self.insert_under(c, STRAIGHT_LINE, elem)
    }

    /// [`LedgerSet::insert`] under a branch condition.
    pub fn insert_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
        elem: &T,
    ) {
        let elem = elem.ledger_value(c);
        emit(c, guard.into(), &set_insert(self.index, &elem));
    }

    /// `set.member(elem)` — `dup 0; idx [field]; push elem; member; popeqc`.
    ///
    /// The same op a map's `member` is, which is why it delegates to
    /// `map_member` rather than to a `set_member` that would be its duplicate.
    pub fn member(&self, c: &mut Circuit3, elem: &T) -> Bool<Public> {
        self.member_under(c, STRAIGHT_LINE, elem)
    }

    /// [`LedgerSet::member`] under a branch condition.
    pub fn member_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
        elem: &T,
    ) -> Bool<Public> {
        let elem = elem.ledger_value(c);
        Bool::from_field(map_member(c, guard, self.index, &elem))
    }

    /// `set.remove(elem)` — `idxp [field]; push elem; rem; insc 1`.
    pub fn remove(&self, c: &mut Circuit3, elem: &T) {
        self.remove_under(c, STRAIGHT_LINE, elem)
    }

    /// [`LedgerSet::remove`] under a branch condition.
    pub fn remove_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
        elem: &T,
    ) {
        let elem = elem.ledger_value(c);
        emit(c, guard, &set_remove(self.index, &elem));
    }
}

impl<T> LedgerSet<T> {
    /// `set.size()` — `dup 0; idx [field]; size; popeqc`.
    pub fn size(&self, c: &mut Circuit3) -> Uint<64, Public> {
        self.size_under(c, STRAIGHT_LINE)
    }

    /// [`LedgerSet::size`] under a branch condition.
    pub fn size_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
    ) -> Uint<64, Public> {
        Uint::from_field(set_size(c, guard, self.index))
    }

    /// `set.isEmpty()` — `dup 0; idx [field]; size; push 0; eq; popeqc`.
    pub fn is_empty(&self, c: &mut Circuit3) -> Bool<Public> {
        self.is_empty_under(c, STRAIGHT_LINE)
    }

    /// [`LedgerSet::is_empty`] under a branch condition.
    pub fn is_empty_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
    ) -> Bool<Public> {
        Bool::from_field(set_is_empty(c, guard, self.index))
    }

    /// `set.resetToDefault()` — `push key; pushs (empty map); ins 1`.
    pub fn reset_to_default(&self, c: &mut Circuit3) {
        self.reset_to_default_under(c, STRAIGHT_LINE)
    }

    /// [`LedgerSet::reset_to_default`] under a branch condition.
    pub fn reset_to_default_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
    ) {
        emit(c, guard, &set_reset(self.index));
    }
}

// ---- List -------------------------------------------------------------------

/// `export ledger l: List<T>` — an unbounded singly-linked list, stored as an
/// `Array[3]` of `{head cell, tail list, length}` (notes/ledger-adts.org §1).
///
/// Compact's own method names, and the same one-op-per-method invariant as
/// every slot here. [`head`](LedgerList::head) is the one worth reading twice:
/// it returns a [`Maybe<T>`](Maybe) — so it is safe on the empty list — and it
/// does that with Impact-level `branch`/`jmp`, which the CIRCUIT does not see.
/// Its cost is fifteen constant instructions and a `Maybe<T>`'s worth of
/// witnessed limbs, whether the list is empty or not.
pub struct LedgerList<T> {
    index: u8,
    _t: PhantomData<fn() -> T>,
}

impl<T> LedgerList<T> {
    /// The list held in ledger field `index` (the derive supplies it).
    pub const fn at(index: u8) -> Self {
        LedgerList {
            index,
            _t: PhantomData,
        }
    }

    /// The ledger field index.
    pub const fn index(&self) -> u8 {
        self.index
    }

    /// `list.popFront()` — `idxp [field]; idx [1]; insc 1`. Needs no bound on
    /// `T`: the list becomes its own tail, and nothing is read or written.
    pub fn pop_front(&self, c: &mut Circuit3) {
        self.pop_front_under(c, STRAIGHT_LINE)
    }

    /// [`LedgerList::pop_front`] under a branch condition.
    pub fn pop_front_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
    ) {
        emit(c, guard, &list_pop_front(self.index));
    }

    /// `list.length()` — `dup 0; idx [field]; idx [2]; popeqc`. A stored
    /// count, not a computed `size`.
    pub fn length(&self, c: &mut Circuit3) -> Uint<64, Public> {
        self.length_under(c, STRAIGHT_LINE)
    }

    /// [`LedgerList::length`] under a branch condition.
    pub fn length_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
    ) -> Uint<64, Public> {
        Uint::from_field(list_length(c, guard, self.index))
    }

    /// `list.isEmpty()` — `dup 0; idx [field]; idx [1]; type; push 1; eq;
    /// popeqc`, i.e. "the tail is null".
    pub fn is_empty(&self, c: &mut Circuit3) -> Bool<Public> {
        self.is_empty_under(c, STRAIGHT_LINE)
    }

    /// [`LedgerList::is_empty`] under a branch condition.
    pub fn is_empty_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
    ) -> Bool<Public> {
        Bool::from_field(list_is_empty(c, guard, self.index))
    }

    /// `list.resetToDefault()` — `push key; pushs [null, null, 0]; ins 1`.
    pub fn reset_to_default(&self, c: &mut Circuit3) {
        self.reset_to_default_under(c, STRAIGHT_LINE)
    }

    /// [`LedgerList::reset_to_default`] under a branch condition.
    pub fn reset_to_default_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
    ) {
        emit(c, guard, &list_reset(self.index));
    }
}

impl<T: LedgerRepr> LedgerList<T> {
    /// `list.pushFront(value)` — thirteen instructions building a new
    /// `[value, old list, len + 1]` node (notes/ledger-adts.org §1).
    ///
    /// The one M16 operation with corpus provenance: it is
    /// `test-caller-contract`'s `requestLog.pushFront(requestId)`.
    pub fn push_front(&self, c: &mut Circuit3, value: &T) {
        self.push_front_under(c, STRAIGHT_LINE, value)
    }

    /// [`LedgerList::push_front`] under a branch condition.
    pub fn push_front_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
        value: &T,
    ) {
        let value = value.ledger_value(c);
        emit(c, guard, &list_push_front(self.index, &value));
    }

    /// `list.head()` — the first element, or `None` on the empty list.
    pub fn head(&self, c: &mut Circuit3) -> Maybe<T, Public> {
        self.head_under(c, STRAIGHT_LINE)
    }

    /// [`LedgerList::head`] under a branch condition.
    pub fn head_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
    ) -> Maybe<T, Public> {
        let mut limbs = list_head(c, guard, self.index, T::atoms());
        let value = T::from_limbs(limbs.split_off(1));
        Maybe {
            is_some: Bool::from_field(limbs[0]),
            value,
        }
    }
}

// ---- MerkleTree and HistoricMerkleTree --------------------------------------

/// `export ledger t: MerkleTree<DEPTH, T>` — a bounded Merkle tree stored as
/// an `Array[2]` of `{tree, next free index}`.
///
/// `DEPTH` is Compact's `nat`, and Compact's rule is `2 <= nat <= 32`: the
/// height is part of the tree's `field_repr` tag, so a wrong depth is a wrong
/// TRANSCRIPT rather than a runtime error. It is checked by an inline-const
/// assert, per the project's compile-errors-over-panics rule — so a depth
/// outside the range is E0080 at the `at()` that names it:
///
/// ```compile_fail
/// use minocrab::Public;
/// use minocrab_std::v3::{LedgerMerkleTree, B32};
///
/// const T: LedgerMerkleTree<1, B32<Public>> = LedgerMerkleTree::at(0);
/// ```
///
/// while the same line at a legal depth compiles:
///
/// ```
/// use minocrab::Public;
/// use minocrab_std::v3::{LedgerMerkleTree, B32};
///
/// const T: LedgerMerkleTree<2, B32<Public>> = LedgerMerkleTree::at(0);
/// ```
///
/// The five `insert*` methods are TWO instruction streams: `insert` /
/// `insert_hash` share one, and `insert_index` / `insert_hash_index` /
/// `insert_index_default` share the other. What differs between the members of
/// a pair is only where the 32-byte leaf came from — hashed from the item
/// ([`leaf_hash`]), handed over directly, or hashed from `T`'s default.
pub struct LedgerMerkleTree<const DEPTH: u8, T> {
    index: u8,
    _t: PhantomData<fn() -> T>,
}

/// The `2 <= DEPTH <= 32` check, shared by both tree types.
const fn check_depth(depth: u8) {
    assert!(
        depth >= 2 && depth <= 32,
        "a Merkle tree's depth must satisfy 2 <= DEPTH <= 32 — Compact's own \
         bound, and upstream's BoundedMerkleTree carries the height in its \
         field_repr tag, so a wrong depth is a wrong transcript"
    );
}

impl<const DEPTH: u8, T> LedgerMerkleTree<DEPTH, T> {
    /// The tree held in ledger field `index` (the derive supplies it).
    pub const fn at(index: u8) -> Self {
        const { check_depth(DEPTH) };
        LedgerMerkleTree {
            index,
            _t: PhantomData,
        }
    }

    /// The ledger field index.
    pub const fn index(&self) -> u8 {
        self.index
    }

    /// `t.isFull()` — `!(next < 2^DEPTH)`.
    pub fn is_full(&self, c: &mut Circuit3) -> Bool<Public> {
        self.is_full_under(c, STRAIGHT_LINE)
    }

    /// [`LedgerMerkleTree::is_full`] under a branch condition.
    pub fn is_full_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
    ) -> Bool<Public> {
        Bool::from_field(merkle_tree_is_full(c, guard, self.index, DEPTH))
    }

    /// `t.checkRoot(rt)` — whether `rt` is the tree's CURRENT root.
    pub fn check_root(&self, c: &mut Circuit3, root: MerkleTreeDigest<Public>) -> Bool<Public> {
        self.check_root_under(c, STRAIGHT_LINE, root)
    }

    /// [`LedgerMerkleTree::check_root`] under a branch condition.
    pub fn check_root_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
        root: MerkleTreeDigest<Public>,
    ) -> Bool<Public> {
        let root = root.ledger_value(c);
        Bool::from_field(merkle_tree_check_root(c, guard, self.index, &root))
    }

    /// `t.insertHash(hash)` — insert a leaf whose digest is already known, at
    /// the first free index.
    pub fn insert_hash(&self, c: &mut Circuit3, hash: &B32<Public>) {
        self.insert_hash_under(c, STRAIGHT_LINE, hash)
    }

    /// [`LedgerMerkleTree::insert_hash`] under a branch condition.
    pub fn insert_hash_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
        hash: &B32<Public>,
    ) {
        let leaf = hash.ledger_value(c);
        emit(c, guard, &merkle_tree_insert(self.index, &leaf));
    }

    /// `t.insertHashIndex(hash, at)` — insert a known digest at a specific
    /// index, bumping the next-free index to `max(next, at + 1)`.
    pub fn insert_hash_index(
        &self,
        c: &mut Circuit3,
        hash: &B32<Public>,
        at: Uint<64, Public>,
    ) {
        self.insert_hash_index_under(c, STRAIGHT_LINE, hash, at)
    }

    /// [`LedgerMerkleTree::insert_hash_index`] under a branch condition.
    pub fn insert_hash_index_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
        hash: &B32<Public>,
        at: Uint<64, Public>,
    ) {
        let leaf = hash.ledger_value(c);
        let at = at.ledger_value(c);
        emit(
            c,
            guard,
            &merkle_tree_insert_index(self.index, &leaf, &at),
        );
    }

    /// `t.resetToDefault()` — the blank tree of this depth, and index 0.
    pub fn reset_to_default(&self, c: &mut Circuit3) {
        self.reset_to_default_under(c, STRAIGHT_LINE)
    }

    /// [`LedgerMerkleTree::reset_to_default`] under a branch condition.
    pub fn reset_to_default_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
    ) {
        emit(c, guard, &merkle_tree_reset(self.index, DEPTH));
    }
}

impl<const DEPTH: u8, T: LedgerRepr> LedgerMerkleTree<DEPTH, T> {
    /// `t.insert(item)` — hash the item into a leaf and insert it at the
    /// first free index.
    pub fn insert(&self, c: &mut Circuit3, item: &T) {
        self.insert_under(c, STRAIGHT_LINE, item)
    }

    /// [`LedgerMerkleTree::insert`] under a branch condition.
    pub fn insert_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
        item: &T,
    ) {
        let hash = leaf_hash(c, item);
        self.insert_hash_under(c, guard, &hash);
    }

    /// `t.insertIndex(item, at)` — hash the item and insert it at `at`.
    pub fn insert_index(&self, c: &mut Circuit3, item: &T, at: Uint<64, Public>) {
        self.insert_index_under(c, STRAIGHT_LINE, item, at)
    }

    /// [`LedgerMerkleTree::insert_index`] under a branch condition.
    pub fn insert_index_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
        item: &T,
        at: Uint<64, Public>,
    ) {
        let hash = leaf_hash(c, item);
        self.insert_hash_index_under(c, guard, &hash, at);
    }

    /// `t.insertIndexDefault(at)` — insert `T`'s DEFAULT value at `at`,
    /// which is Compact's way of emulating a removal.
    pub fn insert_index_default(&self, c: &mut Circuit3, at: Uint<64, Public>) {
        self.insert_index_default_under(c, STRAIGHT_LINE, at)
    }

    /// [`LedgerMerkleTree::insert_index_default`] under a branch condition.
    pub fn insert_index_default_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
        at: Uint<64, Public>,
    ) {
        let hash = default_leaf_hash::<T>(c);
        self.insert_hash_index_under(c, guard, &hash, at);
    }
}

/// `export ledger t: HistoricMerkleTree<DEPTH, T>` — [`LedgerMerkleTree`]
/// plus a history: an `Array[3]` whose third slot is a `Map` of every root the
/// tree has ever had.
///
/// Every mutation appends the new root to that map, and
/// [`check_root`](LedgerHistoricMerkleTree::check_root) is a `member` on it
/// rather than an equality against the current root — which is the whole
/// difference between the two tree types, and the reason a contract picks this
/// one: a proof against a root that was current when the prover built it stays
/// valid.
pub struct LedgerHistoricMerkleTree<const DEPTH: u8, T> {
    index: u8,
    _t: PhantomData<fn() -> T>,
}

impl<const DEPTH: u8, T> LedgerHistoricMerkleTree<DEPTH, T> {
    /// The tree held in ledger field `index` (the derive supplies it).
    pub const fn at(index: u8) -> Self {
        const { check_depth(DEPTH) };
        LedgerHistoricMerkleTree {
            index,
            _t: PhantomData,
        }
    }

    /// The ledger field index.
    pub const fn index(&self) -> u8 {
        self.index
    }

    /// `t.isFull()` — the same stream [`LedgerMerkleTree::is_full`] emits;
    /// the history does not affect capacity.
    pub fn is_full(&self, c: &mut Circuit3) -> Bool<Public> {
        self.is_full_under(c, STRAIGHT_LINE)
    }

    /// [`LedgerHistoricMerkleTree::is_full`] under a branch condition.
    pub fn is_full_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
    ) -> Bool<Public> {
        Bool::from_field(merkle_tree_is_full(c, guard, self.index, DEPTH))
    }

    /// `t.checkRoot(rt)` — whether `rt` is one of the tree's PAST roots.
    pub fn check_root(&self, c: &mut Circuit3, root: MerkleTreeDigest<Public>) -> Bool<Public> {
        self.check_root_under(c, STRAIGHT_LINE, root)
    }

    /// [`LedgerHistoricMerkleTree::check_root`] under a branch condition.
    pub fn check_root_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
        root: MerkleTreeDigest<Public>,
    ) -> Bool<Public> {
        let root = root.ledger_value(c);
        Bool::from_field(historic_merkle_tree_check_root(
            c, guard, self.index, &root,
        ))
    }

    /// `t.insertHash(hash)` — insert a known digest at the first free index,
    /// and append the resulting root to the history.
    pub fn insert_hash(&self, c: &mut Circuit3, hash: &B32<Public>) {
        self.insert_hash_under(c, STRAIGHT_LINE, hash)
    }

    /// [`LedgerHistoricMerkleTree::insert_hash`] under a branch condition.
    pub fn insert_hash_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
        hash: &B32<Public>,
    ) {
        let leaf = hash.ledger_value(c);
        emit(c, guard, &historic_merkle_tree_insert(self.index, &leaf));
    }

    /// `t.insertHashIndex(hash, at)`.
    pub fn insert_hash_index(
        &self,
        c: &mut Circuit3,
        hash: &B32<Public>,
        at: Uint<64, Public>,
    ) {
        self.insert_hash_index_under(c, STRAIGHT_LINE, hash, at)
    }

    /// [`LedgerHistoricMerkleTree::insert_hash_index`] under a branch
    /// condition.
    pub fn insert_hash_index_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
        hash: &B32<Public>,
        at: Uint<64, Public>,
    ) {
        let leaf = hash.ledger_value(c);
        let at = at.ledger_value(c);
        emit(
            c,
            guard,
            &historic_merkle_tree_insert_index(self.index, &leaf, &at),
        );
    }

    /// `t.resetHistory()` — forget every past root but the current one.
    pub fn reset_history(&self, c: &mut Circuit3) {
        self.reset_history_under(c, STRAIGHT_LINE)
    }

    /// [`LedgerHistoricMerkleTree::reset_history`] under a branch condition.
    pub fn reset_history_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
    ) {
        emit(c, guard, &historic_merkle_tree_reset_history(self.index));
    }

    /// `t.resetToDefault()` — the blank tree of this depth, index 0, and a
    /// history holding just the blank tree's root.
    pub fn reset_to_default(&self, c: &mut Circuit3) {
        self.reset_to_default_under(c, STRAIGHT_LINE)
    }

    /// [`LedgerHistoricMerkleTree::reset_to_default`] under a branch
    /// condition.
    pub fn reset_to_default_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
    ) {
        emit(c, guard, &historic_merkle_tree_reset(self.index, DEPTH));
    }
}

impl<const DEPTH: u8, T: LedgerRepr> LedgerHistoricMerkleTree<DEPTH, T> {
    /// `t.insert(item)`.
    pub fn insert(&self, c: &mut Circuit3, item: &T) {
        self.insert_under(c, STRAIGHT_LINE, item)
    }

    /// [`LedgerHistoricMerkleTree::insert`] under a branch condition.
    pub fn insert_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
        item: &T,
    ) {
        let hash = leaf_hash(c, item);
        self.insert_hash_under(c, guard, &hash);
    }

    /// `t.insertIndex(item, at)`.
    pub fn insert_index(&self, c: &mut Circuit3, item: &T, at: Uint<64, Public>) {
        self.insert_index_under(c, STRAIGHT_LINE, item, at)
    }

    /// [`LedgerHistoricMerkleTree::insert_index`] under a branch condition.
    pub fn insert_index_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
        item: &T,
        at: Uint<64, Public>,
    ) {
        let hash = leaf_hash(c, item);
        self.insert_hash_index_under(c, guard, &hash, at);
    }

    /// `t.insertIndexDefault(at)`.
    pub fn insert_index_default(&self, c: &mut Circuit3, at: Uint<64, Public>) {
        self.insert_index_default_under(c, STRAIGHT_LINE, at)
    }

    /// [`LedgerHistoricMerkleTree::insert_index_default`] under a branch
    /// condition.
    pub fn insert_index_default_under<G: Visibility>(
        &self,
        c: &mut Circuit3,
        guard: impl Into<Operand<FieldT, G>>,
        at: Uint<64, Public>,
    ) {
        let hash = default_leaf_hash::<T>(c);
        self.insert_hash_index_under(c, guard, &hash, at);
    }
}

/// compactc's `rt-leaf-hash`: `persistentHash` of the value's FAB
/// representation behind the domain separator `"mdn:lh"`.
///
/// The SAME preimage [`crate::merkle`]'s path circuits hash — a Merkle leaf's
/// digest is one thing whether the tree is in the ledger or the proof — so
/// this is a fourth caller of an existing gadget rather than a new one.
/// Interop flavor by necessity: the digest is one compactc also computes.
pub fn leaf_hash<T: LedgerRepr>(c: &mut Circuit3, item: &T) -> B32<Public> {
    let limbs: Vec<_> = item.limbs(c).into_iter().map(Wire3::erase).collect();
    leaf_hash_of(c, T::atoms(), &limbs)
}

/// [`leaf_hash`] of `T`'s DEFAULT value — all-zero limbs
/// (notes/ledger-adts.org finding (c)), which is what
/// `insertIndexDefault` hashes.
fn default_leaf_hash<T: LedgerRepr>(c: &mut Circuit3) -> B32<Public> {
    let atoms = T::atoms();
    let zeros = atoms.iter().map(atom_limbs).sum::<usize>();
    // Inline immediates, like the separator: compactc's `insertIndexDefault`
    // hashes `["0x6d646e3a6c68", "0x00", "0x00"]` with no `copy` in sight.
    let limbs = vec![AnyWire3::immediate(0u64); zeros];
    leaf_hash_of(c, atoms, &limbs)
}

fn leaf_hash_of(
    c: &mut Circuit3,
    atoms: Vec<AlignmentAtom>,
    limbs: &[AnyWire3<Public>],
) -> B32<Public> {
    let mut segments = vec![AlignmentSegment::Atom(AlignmentAtom::Bytes {
        length: LEAF_HASH_SEP_LEN as u32,
    })];
    segments.extend(atoms.into_iter().map(AlignmentSegment::Atom));
    // Inlined, not named by a `copy`: compactc puts the separator straight
    // into the `persistent_hash` operand list.
    let mut slots = vec![AnyWire3::immediate(
        Fr::from_le_bytes(LEAF_HASH_DOMAIN_SEP).expect("6 bytes fit"),
    )];
    slots.extend(limbs.iter().copied());
    hash::persistent_hash_compact(c, Alignment(segments), &slots)
}

/// The domain separator of every Merkle leaf digest, in compactc and here.
const LEAF_HASH_DOMAIN_SEP: &[u8; LEAF_HASH_SEP_LEN] = b"mdn:lh";
const LEAF_HASH_SEP_LEN: usize = 6;


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
