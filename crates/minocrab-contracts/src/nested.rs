//! `nested.compact` — NESTED LEDGER ADTs at the RAW op layer (M22 stage B1,
//! notes/coin-arms-nested-adts.org §2).
//!
//! DELIBERATELY UNTYPED. Stage B1 builds the LOWERING — [`LedgerKey`], the
//! general-path encoder, and the `_at` twin of every op builder — and stage
//! B2 builds the surface that makes it pleasant (`at_key` handles, the
//! `LedgerSlot` split, the method ripple). So every circuit here reaches into
//! `minocrab_ledger` and hands it a `&[LedgerKey]` by hand. That is the
//! point: it proves the encoding is right BEFORE any API is committed to,
//! and it is the harness B2's typed differential will be compared against.
//!
//! WHAT A NESTED ACCESS ACTUALLY IS. compactc's `propagate-ledger-paths.ss`
//! walks the accessor chain `mm.lookup(k).insert(k2, v)`, folds every
//! INTERMEDIATE `lookup` into the path `f` at compile time, and runs only the
//! LAST accessor's vm-code. So the nested form emits the same five
//! instructions the flat form does, with `f = [field, k]` instead of
//! `f = [field]`: the `idxp` gains a low nibble and the closing `insc` a
//! bigger `n`. There is no new opcode, no new instruction, and no branch.
//!
//! MAP IS THE ONLY NESTABLE ADT, and that is compactc's kind-checker rather
//! than our choice — `Set<List<T>>` is "expected non-ADT type but received
//! ledger ADT type". The fixture declares every shape the checker accepts.

use minocrab::v3::Circuit3;
use minocrab::{Private, Public};
use minocrab_ledger::{
    counter_increment_at, counter_read_at, counter_reset_at, emit, empty_map,
    historic_merkle_tree_insert_at,
    historic_merkle_tree_reset_at, historic_merkle_tree_reset_history_at, list_head_at,
    list_is_empty_at, list_length_at, list_pop_front_at, list_push_front_at, list_reset_at,
    map_insert_adt_default_at, map_insert_at, map_insert_default_at, map_is_empty_at,
    map_lookup_at, map_member_at, map_remove_at, map_reset_at, map_size_at,
    merkle_tree_check_root_at, merkle_tree_insert_at, set_insert_at, set_remove_at, LedgerKey,
};
use minocrab_std::v3::{
    contract, label, leaf_hash, Bool, Disclose, Discloses, LedgerRepr, Maybe,
    MerkleTreeDigest, Uint, B32, STRAIGHT_LINE,
};

label! {
    Key = "key";
    Key2 = "inner key";
    Key3 = "innermost key";
    Elem = "element";
    Val = "value";
    Root = "root";
}

// THE LEDGER BLOCK — declaration order is the field index, matching the
// fixture's `export ledger` block one for one. Plain `u8` constants rather
// than a `#[derive(Ledger)]` struct, because the handle types that could name
// a nested field are stage B2's and inventing them here would pre-empt the
// design of record.
const MM: u8 = 0; // Map<Bytes<32>, Map<Bytes<32>, Uint<64>>>
const ML: u8 = 1; // Map<Bytes<32>, List<Bytes<32>>>
const MS: u8 = 2; // Map<Bytes<32>, Set<Bytes<32>>>
const MC: u8 = 3; // Map<Bytes<32>, Counter>
const MT: u8 = 4; // Map<Bytes<32>, MerkleTree<8, Bytes<32>>>
const MH: u8 = 5; // Map<Bytes<32>, HistoricMerkleTree<8, Bytes<32>>>
const MMM: u8 = 6; // Map<Bytes<32>, Map<Bytes<32>, Map<Bytes<32>, Uint<64>>>>

/// The tree depth both nested trees are declared at.
const DEPTH: u8 = 8;

/// The path `[field, k]` — one `Map.lookup` deep. THIS IS THE WHOLE OF THE
/// NESTED API at the raw layer: build the list, hand it to the op.
fn under(c: &mut Circuit3, field: u8, k: &B32<Public>) -> [LedgerKey; 2] {
    [LedgerKey::Field(field), LedgerKey::Value(k.ledger_value(c))]
}

/// The path `[field, k, k2]` — two `Map.lookup`s deep.
fn under2(c: &mut Circuit3, field: u8, k: &B32<Public>, k2: &B32<Public>) -> [LedgerKey; 3] {
    [
        LedgerKey::Field(field),
        LedgerKey::Value(k.ledger_value(c)),
        LedgerKey::Value(k2.ledger_value(c)),
    ]
}

/// A contract with no state of its own — the ledger block above is `const`
/// field indices, so this type exists only to carry `#[contract]`'s derived
/// [`Nested::CIRCUITS`], which is what the snapshots enumerate.
pub struct Nested;

#[contract]
impl Nested {
    // ---- Map<K, Map<K2, V>> -------------------------------------------------

    /// `mm.lookup(disclose(k)).insert(disclose(k2), disclose(v));`
    ///
    /// `idxp [field, k]; push k2; pushs v; ins 1; insc 2` — `0x71 … 0x91
    /// 0xa2`, the pair the note read off OpenZeppelin's `ShieldedMultiSig`.
    #[circuit]
    pub fn map_insert(
        c: &mut Circuit3,
        k: B32<Private>,
        k2: B32<Private>,
        v: Uint<64, Private>,
    ) -> Discloses<(Key, Key2, Val)> {
        let k = k.disclose_as::<Key>(c);
        let k2 = k2.disclose_as::<Key2>(c);
        let v = v.disclose_as::<Val>(c);
        let path = under(c, MM, &k);
        let (k2, v) = (k2.ledger_value(c), v.ledger_value(c));
        emit(c, STRAIGHT_LINE, &map_insert_at(&path, &k2, &v));
        Discloses::of(())
    }

    /// `mm.lookup(disclose(k)).insertDefault(disclose(k2));`
    ///
    /// The INNER value type is `Uint<64>`, not an ADT, so the pushed default
    /// is a cell of zeros — contrast [`Nested::outer_insert_default`].
    #[circuit]
    pub fn map_insert_default(
        c: &mut Circuit3,
        k: B32<Private>,
        k2: B32<Private>,
    ) -> Discloses<(Key, Key2)> {
        let k = k.disclose_as::<Key>(c);
        let k2 = k2.disclose_as::<Key2>(c);
        let path = under(c, MM, &k);
        let k2 = k2.ledger_value(c);
        emit(
            c,
            STRAIGHT_LINE,
            &map_insert_default_at(&path, &k2, <Uint<64, Public>>::atoms()),
        );
        Discloses::of(())
    }

    /// `return mm.lookup(disclose(k)).lookup(disclose(k2));`
    ///
    /// TWO `idx` instructions, and the second is not part of `f`: the path
    /// reaches the inner map (`0x51`) and the leaf key descends with its own
    /// one-element `idx` (`0x50`). Only an INTERMEDIATE `lookup` folds into
    /// the path.
    #[circuit(output = "value")]
    pub fn map_lookup(
        c: &mut Circuit3,
        k: B32<Private>,
        k2: B32<Private>,
    ) -> Discloses<(Key, Key2), Uint<64, Public>> {
        let k = k.disclose_as::<Key>(c);
        let k2 = k2.disclose_as::<Key2>(c);
        let path = under(c, MM, &k);
        let k2 = k2.ledger_value(c);
        let wires = map_lookup_at(
            c,
            STRAIGHT_LINE,
            &path,
            &k2,
            <Uint<64, Public>>::atoms(),
        );
        Discloses::of(Uint::from_field_unchecked(wires[0]))
    }

    /// `return mm.lookup(disclose(k)).member(disclose(k2));`
    #[circuit(output = "member")]
    pub fn map_member(
        c: &mut Circuit3,
        k: B32<Private>,
        k2: B32<Private>,
    ) -> Discloses<(Key, Key2), Bool<Public>> {
        let k = k.disclose_as::<Key>(c);
        let k2 = k2.disclose_as::<Key2>(c);
        let path = under(c, MM, &k);
        let k2 = k2.ledger_value(c);
        Discloses::of(Bool::from_field_unchecked(map_member_at(
            c,
            STRAIGHT_LINE,
            &path,
            &k2,
        )))
    }

    /// `mm.lookup(disclose(k)).remove(disclose(k2));`
    #[circuit]
    pub fn map_remove(
        c: &mut Circuit3,
        k: B32<Private>,
        k2: B32<Private>,
    ) -> Discloses<(Key, Key2)> {
        let k = k.disclose_as::<Key>(c);
        let k2 = k2.disclose_as::<Key2>(c);
        let path = under(c, MM, &k);
        let k2 = k2.ledger_value(c);
        emit(c, STRAIGHT_LINE, &map_remove_at(&path, &k2));
        Discloses::of(())
    }

    /// `return mm.lookup(disclose(k)).size();`
    #[circuit(output = "size")]
    pub fn map_size(c: &mut Circuit3, k: B32<Private>) -> Discloses<(Key,), Uint<64, Public>> {
        let k = k.disclose_as::<Key>(c);
        let path = under(c, MM, &k);
        Discloses::of(Uint::from_field_unchecked(map_size_at(
            c,
            STRAIGHT_LINE,
            &path,
        )))
    }

    /// `return mm.lookup(disclose(k)).isEmpty();`
    #[circuit(output = "empty")]
    pub fn map_is_empty(c: &mut Circuit3, k: B32<Private>) -> Discloses<(Key,), Bool<Public>> {
        let k = k.disclose_as::<Key>(c);
        let path = under(c, MM, &k);
        Discloses::of(Bool::from_field_unchecked(map_is_empty_at(
            c,
            STRAIGHT_LINE,
            &path,
        )))
    }

    /// `mm.lookup(disclose(k)).resetToDefault();`
    ///
    /// PATH SUPPRESSION COMES ALIVE. At depth 1 the leading `idxp` and the
    /// closing `insc` are both suppressed and a reset is three instructions;
    /// at depth 2 both reappear — `idxp [field]; push k; pushs (empty map);
    /// ins 1; insc 1` — and what gets PUSHED is the last path element, the
    /// key, not the field index.
    #[circuit]
    pub fn map_reset(c: &mut Circuit3, k: B32<Private>) -> Discloses<(Key,)> {
        let k = k.disclose_as::<Key>(c);
        let path = under(c, MM, &k);
        emit(c, STRAIGHT_LINE, &map_reset_at(&path));
        Discloses::of(())
    }

    /// `mm.insertDefault(disclose(k));` — the OUTER map, at depth 1.
    ///
    /// The value type IS an ADT here, and `VMstate-value-ADT` discards the
    /// value and pushes the ADT's own `(initial-value …)`: `0x11 0x02`, the
    /// empty map, where the flat `insertDefault` would push a cell of zeros.
    /// The one place stage B1 found the crate would have been WRONG rather
    /// than merely unable.
    #[circuit]
    pub fn outer_insert_default(c: &mut Circuit3, k: B32<Private>) -> Discloses<(Key,)> {
        let k = k.disclose_as::<Key>(c);
        let k = k.ledger_value(c);
        emit(
            c,
            STRAIGHT_LINE,
            &map_insert_adt_default_at(&[LedgerKey::Field(MM)], &k, empty_map()),
        );
        Discloses::of(())
    }

    // ---- Map<K, List<V>> ----------------------------------------------------

    /// `ml.lookup(disclose(k)).pushFront(disclose(v));`
    ///
    /// The closing `insc` is `len(f) + 1`, so `0xa3` where every other write
    /// here is `0xa2`; the `insc 1` in the middle stays a literal 1.
    #[circuit]
    pub fn list_push_front(
        c: &mut Circuit3,
        k: B32<Private>,
        v: B32<Private>,
    ) -> Discloses<(Key, Val)> {
        let k = k.disclose_as::<Key>(c);
        let v = v.disclose_as::<Val>(c);
        let path = under(c, ML, &k);
        let v = v.ledger_value(c);
        emit(c, STRAIGHT_LINE, &list_push_front_at(&path, &v));
        Discloses::of(())
    }

    /// `ml.lookup(disclose(k)).popFront();`
    #[circuit]
    pub fn list_pop_front(c: &mut Circuit3, k: B32<Private>) -> Discloses<(Key,)> {
        let k = k.disclose_as::<Key>(c);
        let path = under(c, ML, &k);
        emit(c, STRAIGHT_LINE, &list_pop_front_at(&path));
        Discloses::of(())
    }

    /// `return ml.lookup(disclose(k)).length();`
    #[circuit(output = "length")]
    pub fn list_length(c: &mut Circuit3, k: B32<Private>) -> Discloses<(Key,), Uint<64, Public>> {
        let k = k.disclose_as::<Key>(c);
        let path = under(c, ML, &k);
        Discloses::of(Uint::from_field_unchecked(list_length_at(
            c,
            STRAIGHT_LINE,
            &path,
        )))
    }

    /// `return ml.lookup(disclose(k)).head();`
    ///
    /// The one operation with Impact-level `branch`/`jmp` in its middle,
    /// unchanged by nesting: only its leading `idx` grew.
    #[circuit(output = "head")]
    pub fn list_head(
        c: &mut Circuit3,
        k: B32<Private>,
    ) -> Discloses<(Key,), Maybe<B32<Public>, Public>> {
        let k = k.disclose_as::<Key>(c);
        let path = under(c, ML, &k);
        let mut limbs = list_head_at(c, STRAIGHT_LINE, &path, <B32<Public>>::atoms());
        let value = <B32<Public>>::from_limbs(limbs.split_off(1));
        Discloses::of(Maybe {
            is_some: Bool::from_field_unchecked(limbs[0]),
            value,
        })
    }

    /// `return ml.lookup(disclose(k)).isEmpty();`
    #[circuit(output = "empty")]
    pub fn list_is_empty(c: &mut Circuit3, k: B32<Private>) -> Discloses<(Key,), Bool<Public>> {
        let k = k.disclose_as::<Key>(c);
        let path = under(c, ML, &k);
        Discloses::of(Bool::from_field_unchecked(list_is_empty_at(
            c,
            STRAIGHT_LINE,
            &path,
        )))
    }

    /// `ml.lookup(disclose(k)).resetToDefault();`
    #[circuit]
    pub fn list_reset(c: &mut Circuit3, k: B32<Private>) -> Discloses<(Key,)> {
        let k = k.disclose_as::<Key>(c);
        let path = under(c, ML, &k);
        emit(c, STRAIGHT_LINE, &list_reset_at(&path));
        Discloses::of(())
    }

    // ---- Map<K, Set<T>> -----------------------------------------------------

    /// `ms.lookup(disclose(k)).insert(disclose(e));`
    #[circuit]
    pub fn set_insert(
        c: &mut Circuit3,
        k: B32<Private>,
        e: B32<Private>,
    ) -> Discloses<(Key, Elem)> {
        let k = k.disclose_as::<Key>(c);
        let e = e.disclose_as::<Elem>(c);
        let path = under(c, MS, &k);
        let e = e.ledger_value(c);
        emit(c, STRAIGHT_LINE, &set_insert_at(&path, &e));
        Discloses::of(())
    }

    /// `ms.lookup(disclose(k)).remove(disclose(e));`
    #[circuit]
    pub fn set_remove(
        c: &mut Circuit3,
        k: B32<Private>,
        e: B32<Private>,
    ) -> Discloses<(Key, Elem)> {
        let k = k.disclose_as::<Key>(c);
        let e = e.disclose_as::<Elem>(c);
        let path = under(c, MS, &k);
        let e = e.ledger_value(c);
        emit(c, STRAIGHT_LINE, &set_remove_at(&path, &e));
        Discloses::of(())
    }

    /// `return ms.lookup(disclose(k)).member(disclose(e));`
    ///
    /// `map_member_at`, because a Compact `Set` IS a `Map` with `Null` values
    /// and `member` does not touch the value — the same sharing
    /// `minocrab_ledger::set_remove` documents.
    #[circuit(output = "member")]
    pub fn set_member(
        c: &mut Circuit3,
        k: B32<Private>,
        e: B32<Private>,
    ) -> Discloses<(Key, Elem), Bool<Public>> {
        let k = k.disclose_as::<Key>(c);
        let e = e.disclose_as::<Elem>(c);
        let path = under(c, MS, &k);
        let e = e.ledger_value(c);
        Discloses::of(Bool::from_field_unchecked(map_member_at(
            c,
            STRAIGHT_LINE,
            &path,
            &e,
        )))
    }

    // ---- Map<K, Counter> ----------------------------------------------------

    /// `mc.lookup(disclose(k)).increment(1);`
    #[circuit]
    pub fn counter_increment(c: &mut Circuit3, k: B32<Private>) -> Discloses<(Key,)> {
        let k = k.disclose_as::<Key>(c);
        let path = under(c, MC, &k);
        emit(c, STRAIGHT_LINE, &counter_increment_at(&path, 1));
        Discloses::of(())
    }

    /// `return mc.lookup(disclose(k)).read();`
    #[circuit(output = "count")]
    pub fn counter_read(c: &mut Circuit3, k: B32<Private>) -> Discloses<(Key,), Uint<64, Public>> {
        let k = k.disclose_as::<Key>(c);
        let path = under(c, MC, &k);
        Discloses::of(Uint::from_field_unchecked(counter_read_at(
            c,
            STRAIGHT_LINE,
            &path,
        )))
    }

    /// `mc.lookup(disclose(k)).resetToDefault();`
    ///
    /// A `Counter`'s initial value is `cell 0u64`, so this is [`map_reset`]'s
    /// shape with a different constant pushed.
    #[circuit]
    pub fn counter_reset(c: &mut Circuit3, k: B32<Private>) -> Discloses<(Key,)> {
        let k = k.disclose_as::<Key>(c);
        let path = under(c, MC, &k);
        emit(c, STRAIGHT_LINE, &counter_reset_at(&path));
        Discloses::of(())
    }

    // ---- Map<K, MerkleTree> / Map<K, HistoricMerkleTree> --------------------

    /// `mt.lookup(disclose(k)).insert(disclose(item));`
    ///
    /// Closes at `len(f) + 1` — `0xa3` — while the two `insc` in its middle
    /// are literal 1s at every depth.
    #[circuit]
    pub fn mt_insert(
        c: &mut Circuit3,
        k: B32<Private>,
        item: B32<Private>,
    ) -> Discloses<(Key, Elem)> {
        let k = k.disclose_as::<Key>(c);
        let item = item.disclose_as::<Elem>(c);
        let hash = leaf_hash(c, &item);
        let path = under(c, MT, &k);
        let hash = hash.ledger_value(c);
        emit(c, STRAIGHT_LINE, &merkle_tree_insert_at(&path, &hash));
        Discloses::of(())
    }

    /// `return mt.lookup(disclose(k)).checkRoot(disclose(rt));`
    #[circuit(output = "ok")]
    pub fn mt_check_root(
        c: &mut Circuit3,
        k: B32<Private>,
        rt: MerkleTreeDigest<Private>,
    ) -> Discloses<(Key, Root), Bool<Public>> {
        let k = k.disclose_as::<Key>(c);
        let rt = rt.disclose_as::<Root>(c);
        let path = under(c, MT, &k);
        let rt = rt.ledger_value(c);
        Discloses::of(Bool::from_field_unchecked(merkle_tree_check_root_at(
            c,
            STRAIGHT_LINE,
            &path,
            &rt,
        )))
    }

    /// `mh.lookup(disclose(k)).insert(disclose(item));`
    #[circuit]
    pub fn hmt_insert(
        c: &mut Circuit3,
        k: B32<Private>,
        item: B32<Private>,
    ) -> Discloses<(Key, Elem)> {
        let k = k.disclose_as::<Key>(c);
        let item = item.disclose_as::<Elem>(c);
        let hash = leaf_hash(c, &item);
        let path = under(c, MH, &k);
        let hash = hash.ledger_value(c);
        emit(
            c,
            STRAIGHT_LINE,
            &historic_merkle_tree_insert_at(&path, &hash),
        );
        Discloses::of(())
    }

    /// `mh.lookup(disclose(k)).resetHistory();`
    ///
    /// THE ONE OPERATION whose closing depth is `len(f) + 2` — `0xa4` at
    /// depth 2, where `0xa3` was the deepest anything else reached.
    #[circuit]
    pub fn hmt_reset_history(c: &mut Circuit3, k: B32<Private>) -> Discloses<(Key,)> {
        let k = k.disclose_as::<Key>(c);
        let path = under(c, MH, &k);
        emit(
            c,
            STRAIGHT_LINE,
            &historic_merkle_tree_reset_history_at(&path),
        );
        Discloses::of(())
    }

    /// `mh.lookup(disclose(k)).resetToDefault();`
    ///
    /// The ninth whole-field-replace op, and the only one that open-codes its
    /// suppression: its closing pair is `insc 2; ins 1` where every other
    /// reset's is `ins 1; insc len(f)-1`.
    #[circuit]
    pub fn hmt_reset(c: &mut Circuit3, k: B32<Private>) -> Discloses<(Key,)> {
        let k = k.disclose_as::<Key>(c);
        let path = under(c, MH, &k);
        emit(
            c,
            STRAIGHT_LINE,
            &historic_merkle_tree_reset_at(&path, DEPTH),
        );
        Discloses::of(())
    }

    // ---- three levels -------------------------------------------------------

    /// `mmm.lookup(disclose(k)).lookup(disclose(k2)).insert(disclose(k3), disclose(v));`
    ///
    /// `0x72 … 0xa3` — the opcode's low nibble and the closing `insc` both
    /// track `len(f)`, and nothing else about the stream changed.
    #[circuit]
    pub fn deep_insert(
        c: &mut Circuit3,
        k: B32<Private>,
        k2: B32<Private>,
        k3: B32<Private>,
        v: Uint<64, Private>,
    ) -> Discloses<(Key, Key2, Key3, Val)> {
        let k = k.disclose_as::<Key>(c);
        let k2 = k2.disclose_as::<Key2>(c);
        let k3 = k3.disclose_as::<Key3>(c);
        let v = v.disclose_as::<Val>(c);
        let path = under2(c, MMM, &k, &k2);
        let (k3, v) = (k3.ledger_value(c), v.ledger_value(c));
        emit(c, STRAIGHT_LINE, &map_insert_at(&path, &k3, &v));
        Discloses::of(())
    }

    /// `return mmm.lookup(disclose(k)).lookup(disclose(k2)).lookup(disclose(k3));`
    #[circuit(output = "value")]
    pub fn deep_lookup(
        c: &mut Circuit3,
        k: B32<Private>,
        k2: B32<Private>,
        k3: B32<Private>,
    ) -> Discloses<(Key, Key2, Key3), Uint<64, Public>> {
        let k = k.disclose_as::<Key>(c);
        let k2 = k2.disclose_as::<Key2>(c);
        let k3 = k3.disclose_as::<Key3>(c);
        let path = under2(c, MMM, &k, &k2);
        let k3 = k3.ledger_value(c);
        let wires = map_lookup_at(
            c,
            STRAIGHT_LINE,
            &path,
            &k3,
            <Uint<64, Public>>::atoms(),
        );
        Discloses::of(Uint::from_field_unchecked(wires[0]))
    }
}
