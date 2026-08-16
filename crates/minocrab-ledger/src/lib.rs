//! L2.5 — ledger-op emission.
//!
//! A circuit's ledger operations surface as Impact instructions whose
//! elements are exactly `Op::field_repr` (midnight-onchain-vm
//! `src/ops.rs:460-525`) of the corresponding Impact-VM op — see
//! notes/ledger-abi.org §2. This crate builds those element streams:
//! fully-constant ops go through the real [`Op`] type and its
//! `field_repr` (never hand-encoded); ops embedding circuit-computed
//! values reproduce the same layout with wires spliced into the value
//! positions, and the constant header layout is unit-tested against
//! `field_repr` of real ops.
//!
//! Op sequences per ledger operation are compactc's vm-code
//! (corpus/src/compact/compiler/midnight-ledger.ss, assembled by
//! zkir-v3-passes/reduce-to-zkir.ss:484-633), with its suppression rules:
//! top-level Cell writes lose their idxp/insc wrapper; the first fetch of
//! a field is always the *uncached* idx variant.

use midnight_base_crypto::fab::{
    Alignment, AlignmentAtom, AlignmentSegment, AlignedValue, Value, ValueAtom,
};
use midnight_onchain_state::state::{EntryPointBuf, StateValue};
use midnight_onchain_vm::ops::{Key, Op};
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::HashMap as StorageHashMap;
use midnight_transient_crypto::merkle_tree::MerkleTree as VmMerkleTree;
use midnight_transient_crypto::repr::FieldRepr;
use minocrab::v3::{
    CallArgs, CallResult, Circuit3, Disclose, DisclosureLabel, FieldT, Operand, Prim, Wire3,
};
use minocrab::{Fr, Public, Visibility};

pub use minocrab::v3::LimbConstraint;

pub use minocrab::v3::ImpactElem;

// What a cross-contract call itself discloses. A CALLER declares these in
// its own `Discloses<..>` — a call is a disclosure the caller makes, so the
// labels are part of this crate's public vocabulary rather than strings
// buried in `contract_call`.
minocrab::label! {
    pub XcallEntryPointHash = "xcall entry-point hash";
    pub XcallCommitment = "xcall communications commitment";
    pub XcallResult = "xcall result";
}

/// The concrete op type whose `field_repr` defines the PI encoding.
pub type VmOp = Op<ResultModeVerify, InMemoryDB>;

/// One Impact instruction: the element stream of a single Impact-VM op.
#[derive(Clone)]
pub struct ImpactOp(pub Vec<ImpactElem>);

impl ImpactOp {
    /// A fully-constant op, encoded by the real `Op::field_repr`.
    pub fn constant(op: &VmOp) -> ImpactOp {
        let mut elems = Vec::new();
        op.field_repr(&mut elems);
        ImpactOp(elems.into_iter().map(ImpactElem::Imm).collect())
    }
}

/// A FAB-aligned value whose limbs may be circuit-computed: the alignment
/// atoms plus one element per FAB limb, in slot order (`Bytes<32>` =
/// `[hi, lo]` — notes/builtin-lowering.org §1).
#[derive(Clone)]
pub struct LedgerValue {
    atoms: Vec<AlignmentAtom>,
    elems: Vec<ImpactElem>,
}

/// How many FAB limbs one alignment atom occupies: a `bytes<n>` is limbed in
/// 31-byte chunks (at least one, so `bytes<0>` is one zero limb), a `field`
/// and a `compress` are one each.
///
/// Public because it is the FAB rule and it should be stated once — the
/// stdlib needs it to build a default value's zeros
/// (notes/ledger-adts.org finding (c)).
pub fn atom_limbs(atom: &AlignmentAtom) -> usize {
    match atom {
        AlignmentAtom::Bytes { length } => (*length as usize).div_ceil(31).max(1),
        AlignmentAtom::Field | AlignmentAtom::Compress => 1,
    }
}

impl LedgerValue {
    /// A value of one or more atoms; `elems` are the concatenated limbs.
    pub fn new(atoms: Vec<AlignmentAtom>, elems: Vec<ImpactElem>) -> LedgerValue {
        let expected: usize = atoms.iter().map(atom_limbs).sum();
        assert_eq!(
            elems.len(),
            expected,
            "LedgerValue: {} limbs for atoms {atoms:?}",
            elems.len()
        );
        LedgerValue { atoms, elems }
    }

    /// A single `bytes<n>` atom.
    pub fn bytes(n: u32, elems: Vec<ImpactElem>) -> LedgerValue {
        Self::new(vec![AlignmentAtom::Bytes { length: n }], elems)
    }
}

/// `Fr` for an alignment atom, per `AlignmentAtom::field_repr`
/// (transient-crypto fab.rs:596-608): `bytes n` → n, compress → −1,
/// field → −2.
fn atom_elem(atom: &AlignmentAtom) -> Fr {
    match atom {
        AlignmentAtom::Bytes { length } => Fr::from(u64::from(*length)),
        AlignmentAtom::Compress => Fr::from(0u64) - Fr::from(1u64),
        AlignmentAtom::Field => Fr::from(0u64) - Fr::from(2u64),
    }
}

/// The alignment header of an `AlignedValue::field_repr`: atom count, then
/// one element per atom (fab.rs:364-374).
fn alignment_header(atoms: &[AlignmentAtom]) -> Vec<ImpactElem> {
    let mut out = vec![ImpactElem::Imm(Fr::from(atoms.len() as u64))];
    out.extend(atoms.iter().map(|a| ImpactElem::Imm(atom_elem(a))));
    out
}

/// `push` / `pushs` of a `Cell` holding `value`:
/// `[0x10 + storage, 1 (Cell tag), alignment header…, limbs…]`
/// (ops.rs:488-491 + StateValue::field_repr state.rs:171-179 +
/// AlignedValue::field_repr).
pub fn push_cell(storage: bool, value: &LedgerValue) -> ImpactOp {
    let mut elems = vec![
        ImpactElem::Imm(Fr::from(0x10u64 + u64::from(storage))),
        ImpactElem::Imm(Fr::from(1u64)), // StateValue::Cell tag
    ];
    elems.extend(alignment_header(&value.atoms));
    elems.extend(value.elems.iter().copied());
    ImpactOp(elems)
}

/// One element of a pushed `StateValue::Array` whose cells may be
/// circuit-computed — see [`push_array`].
#[derive(Clone)]
pub enum LedgerElem {
    /// `StateValue::Null`.
    Null,
    /// `StateValue::Cell(..)`, possibly carrying wires.
    Cell(LedgerValue),
}

/// `push` / `pushs` of a `StateValue::Array`:
/// `[0x10 + storage, 3 | len << 4, element reprs…]` (`StateValue::field_repr`,
/// onchain-state state.rs:171-205).
///
/// The ONE mixed push in the ADT layer: `List.pushFront` pushes
/// `[Cell(value), Null, Null]` whose first element carries the pushed value's
/// wires (notes/ledger-adts.org §2). Every other ADT constant — the empty
/// map, the blank tree, a `List`'s initial value — is fully constant and goes
/// through [`ImpactOp::constant`] with a real `StateValue`, per the crate's
/// standing rule; `push_array_matches_field_repr` pins that the two agree on
/// the constant case.
pub fn push_array(storage: bool, elems: &[LedgerElem]) -> ImpactOp {
    let mut out = vec![
        ImpactElem::Imm(Fr::from(0x10u64 + u64::from(storage))),
        ImpactElem::Imm(Fr::from(3u64 | ((elems.len() as u64) << 4))),
    ];
    for elem in elems {
        match elem {
            LedgerElem::Null => out.push(ImpactElem::Imm(Fr::from(0u64))),
            LedgerElem::Cell(value) => {
                out.push(ImpactElem::Imm(Fr::from(1u64)));
                out.extend(alignment_header(&value.atoms));
                out.extend(value.elems.iter().copied());
            }
        }
    }
    ImpactOp(out)
}

/// The DEFAULT value of a type with these atoms: one zero limb per FAB limb.
///
/// True for every Compact type, not just the scalar ones — compactc's `VMnull`
/// reduction is `(make-list count 0)` over the limb count
/// (reduce-to-zkir.ss:350-355, notes/ledger-adts.org finding (c)) — which is
/// why no per-type default table exists anywhere below this line.
pub fn default_value(atoms: Vec<AlignmentAtom>) -> LedgerValue {
    let limbs: usize = atoms.iter().map(atom_limbs).sum();
    LedgerValue::new(atoms, vec![ImpactElem::Imm(Fr::from(0u64)); limbs])
}

/// `popeq` / `popeqc` expecting `result`:
/// `[0x0c + cached, alignment header…, limbs…]` (ops.rs:477-480). The limb
/// wires must be the same `public_input` outputs that witnessed the read.
pub fn popeq(cached: bool, result: &LedgerValue) -> ImpactOp {
    let mut elems = vec![ImpactElem::Imm(Fr::from(0x0cu64 + u64::from(cached)))];
    elems.extend(alignment_header(&result.atoms));
    elems.extend(result.elems.iter().copied());
    ImpactOp(elems)
}

/// The `AlignedValue` key of ledger field `index`: one `bytes<1>` atom.
pub fn field_key(index: u8) -> AlignedValue {
    AlignedValue::new(
        Value(vec![ValueAtom(vec![index]).normalize()]),
        Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes {
            length: 1,
        })]),
    )
    .expect("a byte fits a bytes<1> atom")
}

/// A `Uint<64>` as an `AlignedValue`: one `bytes<8>` atom. The initial-value
/// constants of `List` (its length) and both trees (their next index) are
/// this, and nothing else in the crate needs it.
fn u64_aligned(value: u64) -> AlignedValue {
    AlignedValue::new(
        Value(vec![ValueAtom(value.to_le_bytes().to_vec()).normalize()]),
        Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes {
            length: 8,
        })]),
    )
    .expect("a u64 fits a bytes<8> atom")
}

/// `idx` by ONE constant `bytes<1>` key.
///
/// Two things are spelled this way, and they are the same instruction: a
/// top-level ledger FIELD ([`idx_field`] / [`idxp_field`]) and a POSITION
/// inside an ADT's `Array` — `List` is `[head, tail, length]`, `MerkleTree`
/// is `[tree, next-index]`, `HistoricMerkleTree` adds `[.., history]`, and
/// every descent into one is `(align i 1)` in compactc's vm-code
/// (notes/ledger-adts.org §1).
pub fn idx_one(cached: bool, push_path: bool, index: u8) -> ImpactOp {
    ImpactOp::constant(&Op::Idx {
        cached,
        push_path,
        path: vec![Key::Value(field_key(index))].into(),
    })
}

/// `idxp [field]`: uncached path-remembering fetch of a top-level field
/// (the shape compactc emits to reach any field it will write back).
pub fn idxp_field(index: u8) -> ImpactOp {
    idx_one(false, true, index)
}

/// `idx [field]`: uncached fetch of a top-level field WITHOUT remembering
/// the path — the read shape (nothing is written back).
pub fn idx_field(index: u8) -> ImpactOp {
    idx_one(false, false, index)
}

/// `dup n`.
pub fn dup(n: u8) -> ImpactOp {
    ImpactOp::constant(&Op::Dup { n })
}

/// `idx` by a single dynamic (possibly circuit-computed) key, uncached,
/// path not remembered — the Map.lookup descent step:
/// `[0x50, key alignment header…, key limbs…]` (`Key::Value(av)` is encoded
/// as `AlignedValue::field_repr`, ops.rs:67-73).
pub fn idx_key(key: &LedgerValue) -> ImpactOp {
    let mut elems = vec![ImpactElem::Imm(Fr::from(0x50u64))];
    elems.extend(alignment_header(&key.atoms));
    elems.extend(key.elems.iter().copied());
    ImpactOp(elems)
}

// --- compactc's vm-code per ledger operation (midnight-ledger.ss) -----------

/// `Counter.increment(amount)` on ledger field `index`
/// (midnight-ledger.ss:605-609): `idxp [field]; addi amount; insc 1`.
pub fn counter_increment(index: u8, amount: u32) -> Vec<ImpactOp> {
    vec![
        idxp_field(index),
        ImpactOp::constant(&Op::Addi { immediate: amount }),
        ImpactOp::constant(&Op::Ins { cached: true, n: 1 }),
    ]
}

/// `field = value` — Cell write to a top-level field
/// (midnight-ledger.ss:552-558 with the idxp/insc pair suppressed for
/// top-level fields, reduce-to-zkir.ss:595-608): `push key; pushs value;
/// ins 1`.
pub fn cell_write(index: u8, value: &LedgerValue) -> Vec<ImpactOp> {
    let key = LedgerValue::bytes(1, vec![ImpactElem::Imm(Fr::from(u64::from(index)))]);
    vec![
        push_cell(false, &key),
        push_cell(true, value),
        ImpactOp::constant(&Op::Ins {
            cached: false,
            n: 1,
        }),
    ]
}

/// `Cell<QualifiedShieldedCoinInfo>.writeCoin(coin, recipient)` on the
/// top-level field `index` (midnight-ledger.ss:567-583): the coin's
/// Merkle-tree index is resolved by indexing the context's
/// commitment-index map (context[1]) with the coin's commitment (from the
/// stack) and concatenated onto the coin, writing the resulting
/// QualifiedShieldedCoinInfo. `push key; dup 3; push cm; idxc [1, stack];
/// push coin; swap 0; concatc 91; ins 1` — the leading idx (empty path)
/// and trailing insc 0 are compactc's depth-1 suppressions; the `dup 3`
/// reaches the context past the key push, the result slot, and effects.
/// `cm` is the runtime coin commitment (`rt-coin-commit`, a `bytes<32>`);
/// `coin` the 3-atom `[bytes<32>, bytes<32>, bytes<16>]` ShieldedCoinInfo.
pub fn cell_write_coin(index: u8, cm: &LedgerValue, coin: &LedgerValue) -> Vec<ImpactOp> {
    let key = LedgerValue::bytes(1, vec![ImpactElem::Imm(Fr::from(u64::from(index)))]);
    vec![
        push_cell(false, &key),
        dup(3),
        push_cell(false, cm),
        ImpactOp::constant(&Op::Idx {
            cached: true,
            push_path: false,
            path: vec![Key::Value(field_key(1)), Key::Stack].into(),
        }),
        push_cell(false, coin),
        ImpactOp::constant(&Op::Swap { n: 0 }),
        ImpactOp::constant(&Op::Concat { cached: true, n: 91 }),
        ImpactOp::constant(&Op::Ins {
            cached: false,
            n: 1,
        }),
    ]
}

/// `map.insert(key, value)` on ledger field `index`:
/// `idxp [field]; push key; pushs value; ins 1; insc 1`.
pub fn map_insert(index: u8, key: &LedgerValue, value: &LedgerValue) -> Vec<ImpactOp> {
    vec![
        idxp_field(index),
        push_cell(false, key),
        push_cell(true, value),
        ImpactOp::constant(&Op::Ins {
            cached: false,
            n: 1,
        }),
        ImpactOp::constant(&Op::Ins { cached: true, n: 1 }),
    ]
}

/// `map.remove(key)` on ledger field `index` (midnight-ledger.ss Map
/// `remove`; claim.zkir:287-291): `idxp [field]; push key; rem; insc 1`.
pub fn map_remove(index: u8, key: &LedgerValue) -> Vec<ImpactOp> {
    vec![
        idxp_field(index),
        push_cell(false, key),
        ImpactOp::constant(&Op::Rem { cached: false }),
        ImpactOp::constant(&Op::Ins { cached: true, n: 1 }),
    ]
}

/// `set.insert(elem)` on ledger field `index` — `map_insert` with a `Null`
/// value (midnight-ledger.ss's Set vm-code; xcontract-events
/// depositViaVault): `idxp [field]; push elem; pushs null; ins 1; insc 1`.
pub fn set_insert(index: u8, elem: &LedgerValue) -> Vec<ImpactOp> {
    vec![
        idxp_field(index),
        push_cell(false, elem),
        ImpactOp::constant(&Op::Push {
            storage: true,
            value: midnight_onchain_state::state::StateValue::Null,
        }),
        ImpactOp::constant(&Op::Ins {
            cached: false,
            n: 1,
        }),
        ImpactOp::constant(&Op::Ins { cached: true, n: 1 }),
    ]
}

/// `set.remove(elem)` on ledger field `index` — the SAME instruction stream
/// `map.remove(key)` is, because a Compact `Set` is a `Map` with `Null`
/// values and `remove` does not touch the value (fixture `setRemove` is
/// `map_remove`'s stream, notes/ledger-adts.org §1). Named for the caller's
/// sake; it emits nothing of its own.
pub fn set_remove(index: u8, elem: &LedgerValue) -> Vec<ImpactOp> {
    map_remove(index, elem)
}

/// `map.insertDefault(key)` / a `Map` whose value type's default is written
/// (midnight-ledger.ss Map `insertDefault`): `idxp [field]; push key;
/// pushs default; ins 1; insc 1`. `value_atoms` is the VALUE type's
/// alignment; the limbs are zeros ([`default_value`]).
pub fn map_insert_default(index: u8, key: &LedgerValue, value_atoms: Vec<AlignmentAtom>) -> Vec<ImpactOp> {
    map_insert(index, key, &default_value(value_atoms))
}

/// The shared shape of every `resetToDefault` on a TOP-LEVEL field:
/// `push key; pushs initial; ins 1`.
///
/// compactc's vm-code wraps this in `idx [pushPath] (all but the last path
/// element)` and a trailing `insc (len(path) - 1)`, both of which are
/// SUPPRESSED for a one-element path and so emit no instruction at all
/// (notes/ledger-adts.org finding (d)) — the same suppression a top-level
/// `Cell` write already gets.
fn reset_to(index: u8, initial: StateValue<InMemoryDB>) -> Vec<ImpactOp> {
    vec![
        push_cell(false, &field_index_value(index)),
        ImpactOp::constant(&Op::Push {
            storage: true,
            value: initial,
        }),
        ImpactOp::constant(&Op::Ins {
            cached: false,
            n: 1,
        }),
    ]
}

/// The field index as a pushable `bytes<1>` value — the key half of
/// [`field_key`], for the ops that push it rather than index by it.
fn field_index_value(index: u8) -> LedgerValue {
    LedgerValue::bytes(1, vec![ImpactElem::Imm(Fr::from(u64::from(index)))])
}

/// `map.resetToDefault()` on field `index`: `push key; pushs (empty map);
/// ins 1`.
pub fn map_reset(index: u8) -> Vec<ImpactOp> {
    reset_to(index, StateValue::Map(StorageHashMap::new()))
}

/// `set.resetToDefault()` — [`map_reset`], since a `Set`'s initial value is
/// the empty map a `Map`'s is.
pub fn set_reset(index: u8) -> Vec<ImpactOp> {
    map_reset(index)
}

// --- List: an `Array[3]` of `{head cell, tail list, length}` ----------------

/// A `List`'s initial value: `[null, null, cell 0u64]`.
fn empty_list() -> StateValue<InMemoryDB> {
    StateValue::Array(
        [
            StateValue::Null,
            StateValue::Null,
            StateValue::Cell(Sp::new(u64_aligned(0))),
        ]
        .into(),
    )
}

/// `list.resetToDefault()` on field `index`.
pub fn list_reset(index: u8) -> Vec<ImpactOp> {
    reset_to(index, empty_list())
}

/// `list.pushFront(value)` on field `index` (midnight-ledger.ss List
/// `pushFront`; the corpus's own shape is test-caller-contract
/// submitSignatureRequest.zkir:43-55):
///
/// ```text
/// idxp [field]; dup 0; idx [2]; addi 1        // len + 1
/// pushs [cell value, null, null]              // the new node
/// swap 0; push 2u8; swap 0; insc 1            // node[2] = len + 1
/// swap 0; push 1u8; swap 0; insc 2            // node[1] = the old list
/// ```
pub fn list_push_front(index: u8, value: &LedgerValue) -> Vec<ImpactOp> {
    vec![
        idxp_field(index),
        dup(0),
        idx_one(false, false, LIST_LENGTH),
        ImpactOp::constant(&Op::Addi { immediate: 1 }),
        push_array(
            true,
            &[
                LedgerElem::Cell(value.clone()),
                LedgerElem::Null,
                LedgerElem::Null,
            ],
        ),
        swap(0),
        push_cell(false, &field_index_value(LIST_LENGTH)),
        swap(0),
        ImpactOp::constant(&Op::Ins { cached: true, n: 1 }),
        swap(0),
        push_cell(false, &field_index_value(LIST_TAIL)),
        swap(0),
        ImpactOp::constant(&Op::Ins { cached: true, n: 2 }),
    ]
}

/// `list.popFront()` on field `index`: `idxp [field]; idx [1]; insc 1` — the
/// list becomes its own tail.
pub fn list_pop_front(index: u8) -> Vec<ImpactOp> {
    vec![
        idxp_field(index),
        idx_one(false, false, LIST_TAIL),
        ImpactOp::constant(&Op::Ins { cached: true, n: 1 }),
    ]
}

/// Array positions inside a `List` node.
const LIST_HEAD: u8 = 0;
const LIST_TAIL: u8 = 1;
const LIST_LENGTH: u8 = 2;

/// Array positions inside a `MerkleTree` / `HistoricMerkleTree` node.
const TREE: u8 = 0;
const TREE_NEXT: u8 = 1;
const TREE_HISTORY: u8 = 2;

// --- MerkleTree: an `Array[2]` of `{tree, next index}` ----------------------

/// A `MerkleTree`'s initial value: `[blank tree of height DEPTH, cell 0u64]`.
fn empty_merkle_tree(depth: u8) -> [StateValue<InMemoryDB>; 2] {
    [
        StateValue::BoundedMerkleTree(VmMerkleTree::blank(depth)),
        StateValue::Cell(Sp::new(u64_aligned(0))),
    ]
}

/// `mt.resetToDefault()` on field `index`.
pub fn merkle_tree_reset(index: u8, depth: u8) -> Vec<ImpactOp> {
    reset_to(
        index,
        StateValue::Array(empty_merkle_tree(depth).into_iter().collect()),
    )
}

/// `mt.insert(item)` / `mt.insertHash(hash)` on field `index`
/// (midnight-ledger.ss MerkleTree `insert`): ONE stream for both, because the
/// two differ only in where the 32-byte leaf came from — `insert` hashes the
/// item (`rt-leaf-hash`, computed above this layer) and `insertHash` is
/// handed it. The fixture's `mtInsert` and `mtInsertHash` are identical
/// instruction for instruction.
///
/// ```text
/// idxp [field]; idxp [0]; dup 2; idx [1]      // the tree, then the next index
/// pushs (cell leaf); ins 1; insc 1            // tree[next] = leaf
/// idxp [1]; addi 1; insc 2                    // next += 1
/// ```
pub fn merkle_tree_insert(index: u8, leaf: &LedgerValue) -> Vec<ImpactOp> {
    vec![
        idxp_field(index),
        idx_one(false, true, TREE),
        dup(2),
        idx_one(false, false, TREE_NEXT),
        push_cell(true, leaf),
        ImpactOp::constant(&Op::Ins {
            cached: false,
            n: 1,
        }),
        ImpactOp::constant(&Op::Ins { cached: true, n: 1 }),
        idx_one(false, true, TREE_NEXT),
        ImpactOp::constant(&Op::Addi { immediate: 1 }),
        ImpactOp::constant(&Op::Ins { cached: true, n: 2 }),
    ]
}

/// `mt.insertIndex(item, i)` / `insertHashIndex(hash, i)` /
/// `insertIndexDefault(i)` on field `index` — again ONE stream for all three,
/// which differ only in the leaf (the item's hash, the given hash, or the
/// DEFAULT value's hash).
///
/// The tail is `next = max(next, i + 1)`, and it is where the Impact-level
/// `branch`/`jmp` lives — transcript control flow, not circuit control flow
/// (notes/ledger-adts.org finding (b)):
///
/// ```text
/// idxp [field]; idxp [0]; push i; pushs (cell leaf); ins 2
/// idxp [1]; push i; addi 1; dup 1; dup 1; lt
/// branch 2; pop; jmp 2; swap 0; pop           // max(next, i + 1)
/// ins 1; insc 1
/// ```
pub fn merkle_tree_insert_index(
    index: u8,
    leaf: &LedgerValue,
    at: &LedgerValue,
) -> Vec<ImpactOp> {
    vec![
        idxp_field(index),
        idx_one(false, true, TREE),
        push_cell(false, at),
        push_cell(true, leaf),
        ImpactOp::constant(&Op::Ins {
            cached: false,
            n: 2,
        }),
        idx_one(false, true, TREE_NEXT),
        push_cell(false, at),
        ImpactOp::constant(&Op::Addi { immediate: 1 }),
        dup(1),
        dup(1),
        ImpactOp::constant(&Op::Lt),
        ImpactOp::constant(&Op::Branch { skip: 2 }),
        ImpactOp::constant(&Op::Pop),
        ImpactOp::constant(&Op::Jmp { skip: 2 }),
        swap(0),
        ImpactOp::constant(&Op::Pop),
        ImpactOp::constant(&Op::Ins {
            cached: false,
            n: 1,
        }),
        ImpactOp::constant(&Op::Ins { cached: true, n: 1 }),
    ]
}

// --- HistoricMerkleTree: the same, plus an `Array[2]` history map -----------

/// The history append every `HistoricMerkleTree` mutation ends with: descend
/// to position 2 and insert the tree's NEW root as a key with a `Null` value.
///
/// The two closing `ins` are the caller's, because the mutations and
/// `resetToDefault` close in OPPOSITE ORDERS: an insert ends `ins 1; insc 2`,
/// a reset `insc 2; ins 1` (midnight-ledger.ss:1183-1190 against :1211-1228).
/// A shared "closing" argument would have hidden that.
fn history_append() -> Vec<ImpactOp> {
    vec![
        idx_one(false, true, TREE_HISTORY),
        dup(2),
        idx_one(false, false, TREE),
        ImpactOp::constant(&Op::Root),
        ImpactOp::constant(&Op::Push {
            storage: true,
            value: StateValue::Null,
        }),
    ]
}

/// `hmt.insert(item)` / `hmt.insertHash(hash)` — [`merkle_tree_insert`] with
/// the history append spliced in, and the `insc 2` that closed it demoted to
/// `insc 1` because the append now closes the operation.
pub fn historic_merkle_tree_insert(index: u8, leaf: &LedgerValue) -> Vec<ImpactOp> {
    let mut ops = merkle_tree_insert(index, leaf);
    let last = ops.len() - 1;
    ops[last] = ImpactOp::constant(&Op::Ins { cached: true, n: 1 });
    ops.extend(history_append());
    ops.push(ImpactOp::constant(&Op::Ins {
        cached: false,
        n: 1,
    }));
    ops.push(ImpactOp::constant(&Op::Ins { cached: true, n: 2 }));
    ops
}

/// `hmt.insertIndex(..)` / `insertHashIndex(..)` / `insertIndexDefault(i)` —
/// [`merkle_tree_insert_index`] with the history append replacing its closing
/// `insc 1`.
pub fn historic_merkle_tree_insert_index(
    index: u8,
    leaf: &LedgerValue,
    at: &LedgerValue,
) -> Vec<ImpactOp> {
    let mut ops = merkle_tree_insert_index(index, leaf, at);
    ops.pop();
    ops.extend(history_append());
    ops.push(ImpactOp::constant(&Op::Ins {
        cached: false,
        n: 1,
    }));
    ops.push(ImpactOp::constant(&Op::Ins { cached: true, n: 2 }));
    ops
}

/// `hmt.resetHistory()` on field `index` (midnight-ledger.ss
/// HistoricMerkleTree `resetHistory`): replace the history with a one-entry
/// map holding the CURRENT root.
pub fn historic_merkle_tree_reset_history(index: u8) -> Vec<ImpactOp> {
    vec![
        idxp_field(index),
        push_cell(false, &field_index_value(TREE_HISTORY)),
        ImpactOp::constant(&Op::Push {
            storage: true,
            value: StateValue::Map(StorageHashMap::new()),
        }),
        dup(2),
        idx_one(false, false, TREE),
        ImpactOp::constant(&Op::Root),
        ImpactOp::constant(&Op::Push {
            storage: true,
            value: StateValue::Null,
        }),
        ImpactOp::constant(&Op::Ins { cached: true, n: 3 }),
    ]
}

/// `hmt.resetToDefault()` on field `index` — the ONE `resetToDefault` that is
/// not three instructions, because the fresh history has to be seeded with
/// the blank tree's root.
pub fn historic_merkle_tree_reset(index: u8, depth: u8) -> Vec<ImpactOp> {
    let [tree, next] = empty_merkle_tree(depth);
    let initial = StateValue::Array(
        [tree, next, StateValue::Map(StorageHashMap::new())]
            .into_iter()
            .collect(),
    );
    let mut ops = vec![
        push_cell(false, &field_index_value(index)),
        ImpactOp::constant(&Op::Push {
            storage: true,
            value: initial,
        }),
    ];
    ops.extend(history_append());
    ops.push(ImpactOp::constant(&Op::Ins { cached: true, n: 2 }));
    ops.push(ImpactOp::constant(&Op::Ins {
        cached: false,
        n: 1,
    }));
    ops
}

/// `swap n`.
pub fn swap(n: u8) -> ImpactOp {
    ImpactOp::constant(&Op::Swap { n })
}

/// Emit `ops` as Impact instructions (one per op) under `guard`.
///
/// The guard is an OPERAND (M9 phase 8): a branch condition's wire, or the
/// native `1u64` for a straight-line operation, which inlines as an
/// immediate rather than naming a `Copy` — see [`Circuit3::impact_mixed`].
pub fn emit<V: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    ops: &[ImpactOp],
) {
    let guard = guard.into();
    for op in ops {
        c.impact_mixed(guard, &op.0);
    }
}

// --- reads ------------------------------------------------------------------
//
// A ledger read = `public_input` gates witnessing the read value from
// `public_transcript_outputs` (one per FAB limb, minted BEFORE the op's
// impact instructions — reduce-to-zkir.ss:620-633), then the op's impact
// stream whose trailing `popeq[c]` embeds those same wires as the expected
// result. Reads therefore emit directly into the circuit and return the
// witnessed wires. All shapes are compactc's vm-code (midnight-ledger.ss;
// line refs per function).

/// Mint one `public_input` gate per FAB limb of `atoms`; returns the wires
/// plus the same wires packaged for a `popeq[c]` embed. `guard` is the
/// branch condition for reads inside a conditional (compactc puts the SAME
/// guard on the gates and the op's impact instructions — completeWithdraw
/// .zkir:292-297); `None` for straight-line reads (guard printed as null).
pub fn mint_read_with<V: Visibility + Copy>(
    c: &mut Circuit3,
    guard: Option<Wire3<FieldT, V>>,
    atoms: Vec<AlignmentAtom>,
) -> (Vec<Wire3<FieldT, Public>>, LedgerValue) {
    let limbs: usize = atoms.iter().map(atom_limbs).sum();
    let wires: Vec<Wire3<FieldT, Public>> = (0..limbs)
        .map(|_| match guard {
            Some(g) => c.public_transcript_input_guarded::<FieldT, V>(g),
            None => c.public_transcript_input::<FieldT>(),
        })
        .collect();
    let value = LedgerValue::new(atoms, wires.iter().map(|&w| ImpactElem::Wire(w)).collect());
    (wires, value)
}

fn mint_read(c: &mut Circuit3, atoms: Vec<AlignmentAtom>) -> (Vec<Wire3<FieldT, Public>>, LedgerValue) {
    mint_read_with::<Public>(c, None, atoms)
}

const U64_ATOM: AlignmentAtom = AlignmentAtom::Bytes { length: 8 };
const BOOL_ATOM: AlignmentAtom = AlignmentAtom::Bytes { length: 1 };

/// `Cell.read()` of the top-level field `index`
/// (midnight-ledger.ss:547-551): `dup 0; idx [field]; popeq` — both the idx
/// and the popeq uncached (`f-cached` = #f). `atoms` is the cell type's FAB
/// alignment; returns one wire per limb, in slot order.
pub fn cell_read<V: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
    atoms: Vec<AlignmentAtom>,
) -> Vec<Wire3<FieldT, Public>> {
    let guard = guard.into();
    let (wires, value) = mint_read(c, atoms);
    cell_read_embedded(c, guard, index, &value);
    wires
}

/// [`cell_read`] against gates the caller has already minted.
///
/// The read shape — `dup 0; idx [field]; popeq` with the witnessed value
/// embedded in the `popeq` — is the same whatever minted the value; what
/// differs is HOW the value was witnessed. A `Bytes<32>` cell mints one
/// native gate per limb ([`mint_read_with`], which is what [`cell_read`]
/// does). A `Secp256k1Point` cell mints ONE TYPED gate and derives its five
/// limbs with an `encode` instruction (claim.zkir:29-33), so the limbs are
/// computed rather than read and the caller has to build the value itself.
/// Both end here.
pub fn cell_read_embedded<V: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
    value: &LedgerValue,
) {
    emit(c, guard, &[dup(0), idx_field(index), popeq(false, value)]);
}

/// `Counter.read()` on field `index` (midnight-ledger.ss:590-594):
/// `dup 0; idx [field]; popeqc` — the popeq is cached even on the first
/// access (unlike Cell.read). Returns the u64 counter value.
pub fn counter_read<V: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
) -> Wire3<FieldT, Public> {
    let guard = guard.into();
    let (wires, value) = mint_read(c, vec![U64_ATOM]);
    emit(c, guard, &[dup(0), idx_field(index), popeq(true, &value)]);
    wires[0]
}

/// `Counter.lessThan(threshold)` (midnight-ledger.ss:595-600):
/// `dup 0; idx [field]; push threshold (u64 cell); lt; popeqc` → Boolean.
pub fn counter_less_than<V: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
    threshold: &LedgerValue,
) -> Wire3<FieldT, Public> {
    let guard = guard.into();
    let (wires, value) = mint_read(c, vec![BOOL_ATOM]);
    emit(
        c,
        guard,
        &[
            dup(0),
            idx_field(index),
            push_cell(false, threshold),
            ImpactOp::constant(&Op::Lt),
            popeq(true, &value),
        ],
    );
    wires[0]
}

/// `Map.member(key)` on field `index` (midnight-ledger.ss:649-655):
/// `dup 0; idx [field]; push key; member; popeqc` → Boolean.
pub fn map_member<V: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
    key: &LedgerValue,
) -> Wire3<FieldT, Public> {
    let guard = guard.into();
    let (wires, value) = mint_read(c, vec![BOOL_ATOM]);
    emit(
        c,
        guard,
        &[
            dup(0),
            idx_field(index),
            push_cell(false, key),
            ImpactOp::constant(&Op::Member),
            popeq(true, &value),
        ],
    );
    wires[0]
}

/// `Map.lookup(key)` on field `index`, for flat (Cell) value types
/// (midnight-ledger.ss:741-747): `dup 0; idx [field]; idx {key}; popeq` —
/// the key descent and the popeq both uncached. `value_atoms` is the value
/// type's FAB alignment.
pub fn map_lookup<V: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
    key: &LedgerValue,
    value_atoms: Vec<AlignmentAtom>,
) -> Vec<Wire3<FieldT, Public>> {
    let guard = guard.into();
    let (wires, value) = mint_read(c, value_atoms);
    emit(
        c,
        guard,
        &[dup(0), idx_field(index), idx_key(key), popeq(false, &value)],
    );
    wires
}

/// `Map.size()` on field `index` (midnight-ledger.ss:728-733):
/// `dup 0; idx [field]; size; popeqc` → Uint64.
pub fn map_size<V: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
) -> Wire3<FieldT, Public> {
    let guard = guard.into();
    let (wires, value) = mint_read(c, vec![U64_ATOM]);
    emit(
        c,
        guard,
        &[
            dup(0),
            idx_field(index),
            ImpactOp::constant(&Op::Size),
            popeq(true, &value),
        ],
    );
    wires[0]
}

/// `Map.isEmpty()` on field `index` (midnight-ledger.ss:720-727):
/// `dup 0; idx [field]; size; push 0 (u64 cell); eq; popeqc` → Boolean.
pub fn map_is_empty<V: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
) -> Wire3<FieldT, Public> {
    let guard = guard.into();
    let zero = LedgerValue::bytes(8, vec![ImpactElem::Imm(Fr::from(0u64))]);
    let (wires, value) = mint_read(c, vec![BOOL_ATOM]);
    emit(
        c,
        guard,
        &[
            dup(0),
            idx_field(index),
            ImpactOp::constant(&Op::Size),
            push_cell(false, &zero),
            ImpactOp::constant(&Op::Eq),
            popeq(true, &value),
        ],
    );
    wires[0]
}

/// `set.size()` / `set.isEmpty()` — the `Map` streams, exactly
/// ([`set_remove`] carries the argument).
pub fn set_size<V: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
) -> Wire3<FieldT, Public> {
    map_size(c, guard, index)
}

/// See [`set_size`].
pub fn set_is_empty<V: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
) -> Wire3<FieldT, Public> {
    map_is_empty(c, guard, index)
}

// --- List reads --------------------------------------------------------------

/// `list.length()` on field `index`: `dup 0; idx [field]; idx [2]; popeqc`
/// → Uint64. The length is a stored cell, not a computed `size`.
pub fn list_length<V: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
) -> Wire3<FieldT, Public> {
    let guard = guard.into();
    let (wires, value) = mint_read(c, vec![U64_ATOM]);
    emit(
        c,
        guard,
        &[
            dup(0),
            idx_field(index),
            idx_one(false, false, LIST_LENGTH),
            popeq(true, &value),
        ],
    );
    wires[0]
}

/// `list.isEmpty()` on field `index`: `dup 0; idx [field]; idx [1]; type;
/// push 1u8; eq; popeqc` → Boolean.
///
/// The `1` is `Op::Type`'s code for `Null` (vm.rs:414-425 — a DIFFERENT
/// numbering from `StateValue::field_repr`'s, where `Null` is `0`), so this
/// reads as "the tail is null", which is what an empty list's tail is. See
/// notes/ledger-adts.org §1, which also disposes of the upstream comment
/// claiming `1` encodes a cell.
pub fn list_is_empty<V: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
) -> Wire3<FieldT, Public> {
    let guard = guard.into();
    let (wires, value) = mint_read(c, vec![BOOL_ATOM]);
    emit(
        c,
        guard,
        &[
            dup(0),
            idx_field(index),
            idx_one(false, false, LIST_TAIL),
            ImpactOp::constant(&Op::Type),
            push_cell(false, &field_index_value(TYPE_NULL)),
            ImpactOp::constant(&Op::Eq),
            popeq(true, &value),
        ],
    );
    wires[0]
}

/// `Op::Type`'s result for `StateValue::Null` (vm.rs:414-425).
const TYPE_NULL: u8 = 1;

/// `list.head()` on field `index` → `Maybe<T>`, whose limbs are the returned
/// wires: the tag's, then `elem_atoms`'.
///
/// The one ledger operation with Impact-level control flow in its middle. The
/// `branch` is taken when the head IS null (`Op::Branch` jumps on a truthy
/// cell, vm.rs:1015-1021), landing on the `None` path; the fall-through
/// builds `(1, head)` with a `concat`. Both are constant instructions under
/// the same guard, so the CIRCUIT does not branch — see
/// notes/ledger-adts.org finding (b).
///
/// ```text
/// dup 0; idx [field]; idx [0]; dup 0; type; push 1u8; eq
/// branch 4;  push 1u8; swap 0; concat (2 + max_sizeof(T));  jmp 2
///            pop; push (cell [0u8, default T])
/// popeqc <Maybe<T>>
/// ```
pub fn list_head<V: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
    elem_atoms: Vec<AlignmentAtom>,
) -> Vec<Wire3<FieldT, Public>> {
    let guard = guard.into();
    let mut maybe_atoms = vec![BOOL_ATOM];
    maybe_atoms.extend(elem_atoms.iter().copied());
    let none = default_value(maybe_atoms.clone());
    let (wires, value) = mint_read(c, maybe_atoms);
    emit(
        c,
        guard,
        &[
            dup(0),
            idx_field(index),
            idx_one(false, false, LIST_HEAD),
            dup(0),
            ImpactOp::constant(&Op::Type),
            push_cell(false, &field_index_value(TYPE_NULL)),
            ImpactOp::constant(&Op::Eq),
            ImpactOp::constant(&Op::Branch { skip: 4 }),
            push_cell(false, &field_index_value(1)),
            swap(0),
            ImpactOp::constant(&Op::Concat {
                cached: false,
                n: 2 + max_sizeof(&elem_atoms),
            }),
            ImpactOp::constant(&Op::Jmp { skip: 2 }),
            ImpactOp::constant(&Op::Pop),
            push_cell(false, &none),
            popeq(true, &value),
        ],
    );
    wires
}

/// compactc's `rt-max-sizeof` — an upper bound on a type's serialized size,
/// and the operand of `List.head`'s `concat`
/// (reduce-to-zkir.ss:356-375, transcribed).
fn max_sizeof(atoms: &[AlignmentAtom]) -> u32 {
    /// `(ceiling (/ (integer-length n) 8))`.
    fn sep(n: u32) -> u32 {
        (32 - n.leading_zeros()).div_ceil(8)
    }
    if atoms.is_empty() {
        return 2;
    }
    atoms.iter().fold(1 + sep(atoms.len() as u32), |sum, atom| {
        sum + match atom {
            AlignmentAtom::Bytes { length: 0 } => 3,
            AlignmentAtom::Bytes { length: n } => 2 + n + sep(*n),
            AlignmentAtom::Field | AlignmentAtom::Compress => 34,
        }
    })
}

// --- MerkleTree reads --------------------------------------------------------

/// `mt.isFull()` / `hmt.isFull()` on field `index`: `dup 0; idx [field];
/// idx [1]; push 2^depth (u64 cell); lt; neg; popeqc` → Boolean, i.e.
/// `!(next < 2^depth)`.
pub fn merkle_tree_is_full<V: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
    depth: u8,
) -> Wire3<FieldT, Public> {
    let guard = guard.into();
    let capacity = LedgerValue::bytes(8, vec![ImpactElem::Imm(Fr::from(1u64 << depth))]);
    let (wires, value) = mint_read(c, vec![BOOL_ATOM]);
    emit(
        c,
        guard,
        &[
            dup(0),
            idx_field(index),
            idx_one(false, false, TREE_NEXT),
            push_cell(false, &capacity),
            ImpactOp::constant(&Op::Lt),
            ImpactOp::constant(&Op::Neg),
            popeq(true, &value),
        ],
    );
    wires[0]
}

/// `mt.checkRoot(rt)` on field `index`: `dup 0; idx [field]; idx [0]; root;
/// push rt (field cell); eq; popeqc` → Boolean. `root` is the CURRENT root,
/// so this is an equality — the historic twin is [`historic_merkle_tree_check_root`].
pub fn merkle_tree_check_root<V: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
    root: &LedgerValue,
) -> Wire3<FieldT, Public> {
    let guard = guard.into();
    let (wires, value) = mint_read(c, vec![BOOL_ATOM]);
    emit(
        c,
        guard,
        &[
            dup(0),
            idx_field(index),
            idx_one(false, false, TREE),
            ImpactOp::constant(&Op::Root),
            push_cell(false, root),
            ImpactOp::constant(&Op::Eq),
            popeq(true, &value),
        ],
    );
    wires[0]
}

/// `hmt.checkRoot(rt)` on field `index`: `dup 0; idx [field]; idx [2];
/// push rt; member; popeqc` → Boolean. A `member` on the HISTORY map, not an
/// `eq` on the current root — which is the whole difference between the two
/// tree ADTs at read time.
pub fn historic_merkle_tree_check_root<V: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
    root: &LedgerValue,
) -> Wire3<FieldT, Public> {
    let guard = guard.into();
    let (wires, value) = mint_read(c, vec![BOOL_ATOM]);
    emit(
        c,
        guard,
        &[
            dup(0),
            idx_field(index),
            idx_one(false, false, TREE_HISTORY),
            push_cell(false, root),
            ImpactOp::constant(&Op::Member),
            popeq(true, &value),
        ],
    );
    wires[0]
}

/// `kernel.self()` (midnight-ledger.ss:256-260): `dup 2` to reach the
/// context array, `idxc [0]` (cached, path not remembered), `popeqc` →
/// the contract's own address as `Bytes<32>` `[hi, lo]` wires.
pub fn kernel_self<V: Visibility>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
) -> [Wire3<FieldT, Public>; 2] {
    let guard = guard.into();
    let (wires, value) = mint_read(c, vec![AlignmentAtom::Bytes { length: 32 }]);
    let idx_context = ImpactOp::constant(&Op::Idx {
        cached: true,
        push_path: false,
        path: vec![Key::Value(field_key(0))].into(),
    });
    emit(c, guard, &[dup(2), idx_context, popeq(true, &value)]);
    [wires[0], wires[1]]
}

// --- guarded reads ----------------------------------------------------------
//
// A read inside a conditional carries the branch condition as the guard on
// BOTH its public_input gates and its impact instructions
// (completeWithdraw.zkir:292-297 — refundCommitment.lookup under the
// !succeeded branch). A guarded-off read yields the value type's default
// and does not consume the transcript (ir_vm.rs:348-366); asserts inside
// the branch are the caller's job (`assert(select(guard, cond, 1))`).
// Shapes are identical to the unguarded variants above; the first fetch of
// a field is still the uncached idx even when it happens inside a branch
// (completeWithdraw reads field 9 first at :295, `0x50` under the guard).

/// Guarded [`cell_read`].
pub fn cell_read_guarded<V: Visibility + Copy>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    index: u8,
    atoms: Vec<AlignmentAtom>,
) -> Vec<Wire3<FieldT, Public>> {
    let (wires, value) = mint_read_with(c, Some(guard), atoms);
    emit(c, guard, &[dup(0), idx_field(index), popeq(false, &value)]);
    wires
}

/// Guarded [`counter_read`].
pub fn counter_read_guarded<V: Visibility + Copy>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    index: u8,
) -> Wire3<FieldT, Public> {
    let (wires, value) = mint_read_with(c, Some(guard), vec![U64_ATOM]);
    emit(c, guard, &[dup(0), idx_field(index), popeq(true, &value)]);
    wires[0]
}

/// Guarded [`map_member`].
pub fn map_member_guarded<V: Visibility + Copy>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    index: u8,
    key: &LedgerValue,
) -> Wire3<FieldT, Public> {
    let (wires, value) = mint_read_with(c, Some(guard), vec![BOOL_ATOM]);
    emit(
        c,
        guard,
        &[
            dup(0),
            idx_field(index),
            push_cell(false, key),
            ImpactOp::constant(&Op::Member),
            popeq(true, &value),
        ],
    );
    wires[0]
}

/// Guarded [`map_lookup`].
pub fn map_lookup_guarded<V: Visibility + Copy>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    index: u8,
    key: &LedgerValue,
    value_atoms: Vec<AlignmentAtom>,
) -> Vec<Wire3<FieldT, Public>> {
    let (wires, value) = mint_read_with(c, Some(guard), value_atoms);
    emit(
        c,
        guard,
        &[dup(0), idx_field(index), idx_key(key), popeq(false, &value)],
    );
    wires
}

/// Guarded [`kernel_self`].
pub fn kernel_self_guarded<V: Visibility + Copy>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
) -> [Wire3<FieldT, Public>; 2] {
    let (wires, value) = mint_read_with(c, Some(guard), vec![AlignmentAtom::Bytes { length: 32 }]);
    let idx_context = ImpactOp::constant(&Op::Idx {
        cached: true,
        push_path: false,
        path: vec![Key::Value(field_key(0))].into(),
    });
    emit(c, guard, &[dup(2), idx_context, popeq(true, &value)]);
    [wires[0], wires[1]]
}

// --- kernel effects ops -----------------------------------------------------
//
// The zswap/kernel update ops operate on the EFFECTS array (not contract
// state): each sequence starts `swap 0` to bring effects to the top and
// ends `swap 0` to restore [context, effects, state]. Sequences are
// midnight-ledger.ss's Kernel vm-code verbatim; these ops write no popeq,
// so they return nothing.

/// `push` of `StateValue::Null` (the claim maps hold `Null` values).
fn push_null() -> ImpactOp {
    ImpactOp::constant(&Op::Push {
        storage: false,
        value: midnight_onchain_state::state::StateValue::Null,
    })
}

/// `kernel.mintShielded(domain_sep, amount)` (midnight-ledger.ss:216-254):
/// upsert into the effects' shielded-mints map (effects[4]) — member test,
/// then either insert `amount` or add it to the existing entry via a
/// VM-side `branch` (the PI stream is identical on both paths; the branch
/// is resolved on chain).
pub fn kernel_mint_shielded(domain_sep: &LedgerValue, amount: &LedgerValue) -> Vec<ImpactOp> {
    vec![
        ImpactOp::constant(&Op::Swap { n: 0 }),
        ImpactOp::constant(&Op::Idx {
            cached: true,
            push_path: true,
            path: vec![Key::Value(field_key(4))].into(),
        }),
        push_cell(false, domain_sep),
        ImpactOp::constant(&Op::Dup { n: 1 }),
        ImpactOp::constant(&Op::Dup { n: 1 }),
        ImpactOp::constant(&Op::Member),
        push_cell(false, amount),
        ImpactOp::constant(&Op::Swap { n: 0 }),
        ImpactOp::constant(&Op::Neg),
        ImpactOp::constant(&Op::Branch { skip: 4 }),
        ImpactOp::constant(&Op::Dup { n: 2 }),
        ImpactOp::constant(&Op::Dup { n: 2 }),
        ImpactOp::constant(&Op::Idx {
            cached: true,
            push_path: false,
            path: vec![Key::Stack].into(),
        }),
        ImpactOp::constant(&Op::Add),
        ImpactOp::constant(&Op::Ins { cached: true, n: 2 }),
        ImpactOp::constant(&Op::Swap { n: 0 }),
    ]
}

/// The shared claim shape (claimZswapNullifier :162 / claimZswapCoinSpend
/// :173 / claimZswapCoinReceive :184): insert `note → Null` into the
/// claim map at `effects[index]`.
fn kernel_claim(effect_index: u8, note: &LedgerValue) -> Vec<ImpactOp> {
    vec![
        ImpactOp::constant(&Op::Swap { n: 0 }),
        ImpactOp::constant(&Op::Idx {
            cached: true,
            push_path: true,
            path: vec![Key::Value(field_key(effect_index))].into(),
        }),
        push_cell(false, note),
        push_null(),
        ImpactOp::constant(&Op::Ins { cached: true, n: 2 }),
        ImpactOp::constant(&Op::Swap { n: 0 }),
    ]
}

/// `kernel.claimZswapNullifier(nul)` — effects[0].
pub fn kernel_claim_zswap_nullifier(nul: &LedgerValue) -> Vec<ImpactOp> {
    kernel_claim(0, nul)
}

/// `kernel.claimZswapCoinReceive(note)` — effects[1].
pub fn kernel_claim_zswap_coin_receive(note: &LedgerValue) -> Vec<ImpactOp> {
    kernel_claim(1, note)
}

/// `kernel.claimZswapCoinSpend(note)` — effects[2].
pub fn kernel_claim_zswap_coin_spend(note: &LedgerValue) -> Vec<ImpactOp> {
    kernel_claim(2, note)
}

/// `kernel.claimContractCall(addr, entry_point, comm)`
/// (midnight-ledger.ss:195-215): insert `size(claims) ‖ addr ‖ ep ‖ comm →
/// Null` into the claimed-contract-calls map at effects[3]. `addr_ep_comm`
/// is the single 3-atom `[bytes<32>, bytes<32>, field]` concatenation
/// (`rt-aligned-concat`); the size prefix (via `dup 0; size; concatc 160`)
/// keys repeated identical calls apart.
pub fn kernel_claim_contract_call(addr_ep_comm: &LedgerValue) -> Vec<ImpactOp> {
    vec![
        ImpactOp::constant(&Op::Swap { n: 0 }),
        ImpactOp::constant(&Op::Idx {
            cached: true,
            push_path: true,
            path: vec![Key::Value(field_key(3))].into(),
        }),
        dup(0),
        ImpactOp::constant(&Op::Size),
        push_cell(false, addr_ep_comm),
        ImpactOp::constant(&Op::Concat {
            cached: true,
            n: 160,
        }),
        push_null(),
        ImpactOp::constant(&Op::Ins { cached: true, n: 2 }),
        ImpactOp::constant(&Op::Swap { n: 0 }),
    ]
}

// --- cross-contract calls ---------------------------------------------------

/// One cross-contract call `target.circ(args…) → results`, exactly as
/// compactc desugars it (circuit-passes/desugar-contract-calls.ss:116-137;
/// notes/ledger-abi.org §Implementation): witness the callee's return
/// limbs, the communication randomness and the entry-point-hash limbs;
/// recompute `comm = transientHash([rand] ++ args ++ results)` in-circuit;
/// claim `(addr, entry_point, comm)` via [`kernel_claim_contract_call`].
///
/// `addr` is the callee's address (`Bytes<32>` `[hi, lo]`, from a
/// [`cell_read`] of the target field — one fresh uncached read per call
/// site — or [`kernel_self`]). `args` are the call arguments' FAB limbs in
/// order, already disclosed. `results` has one entry per FAB limb of the
/// callee's declared return type: the constraint compactc places right
/// after that limb's witness (`Bytes<32>` →
/// `[Bits(8), Bits(248)]`, `Uint<128>` → `[Bits(128)]`, a `Field` limb →
/// `None`).
///
/// The result constraints and a circuit's own ARGUMENT constraints are the
/// same table — compactc runs `emit-constraints-for` over both — so a
/// caller derives this list from the callee's return type via
/// `CircuitAbi::prims`, and [`LimbConstraint`] is that table's output type
/// rather than anything local to this function.
///
/// Returns the callee's result wires. They are disclosed: the claim binds
/// them publicly (under cc-rand hiding) via `comm`, and Compact treats
/// them as public downstream.
pub fn contract_call<V: Visibility + Copy>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    addr: [Wire3<FieldT, Public>; 2],
    args: &[Wire3<FieldT, Public>],
    results: &[LimbConstraint],
) -> Vec<Wire3<FieldT, Public>> {
    let results: Vec<_> = results
        .iter()
        .map(|&constraint| {
            let w = c.witness::<FieldT>();
            constraint.emit(c, w);
            w
        })
        .collect();
    let cc_rand = c.witness::<FieldT>();
    let ep_hi = c.witness::<FieldT>();
    c.assert_bits(ep_hi, 8);
    let ep_lo = c.witness::<FieldT>();
    c.assert_bits(ep_lo, 248);

    let mut preimage = vec![cc_rand];
    preimage.extend(args.iter().map(|w| w.private()));
    preimage.extend(results.iter().copied());
    let comm = c.transient_hash(&preimage);

    let [ep_hi, ep_lo] = c.disclose_all(XcallEntryPointHash::LABEL, [ep_hi, ep_lo]);
    let comm = comm.disclose_as::<XcallCommitment>(c);

    let addr_ep_comm = LedgerValue::new(
        vec![
            AlignmentAtom::Bytes { length: 32 },
            AlignmentAtom::Bytes { length: 32 },
            AlignmentAtom::Field,
        ],
        vec![
            ImpactElem::Wire(addr[0]),
            ImpactElem::Wire(addr[1]),
            ImpactElem::Wire(ep_hi),
            ImpactElem::Wire(ep_lo),
            ImpactElem::Wire(comm),
        ],
    );
    emit(c, guard, &kernel_claim_contract_call(&addr_ep_comm));

    results.disclose_as::<XcallResult>(c)
}

/// WHERE a cross-contract call's target address comes from.
///
/// The two variants are the two things a Compact receiver expression can
/// be, and they lower differently:
///
/// - [`Callee::Field`] is a sealed ledger cell holding the address
///   (`export sealed ledger target: Target`). EVERY call site does its own
///   FRESH UNCACHED read: `xcall`'s `callTwice` calls the same target twice
///   in one circuit and compactc reads the cell twice, so caching the first
///   read would be a row-count difference, not an optimization.
/// - [`Callee::Pinned`] is an address the caller already holds as data
///   (`kernel.self()`, an argument, a constant, or a `Field` callee resolved
///   early with [`Callee::pin`]).
///
/// An interface crate NEVER contains an address: a deployment pins one via
/// a sealed cell or passes it as data. That is why this type has no
/// constant-address variant.
#[derive(Clone, Copy)]
pub enum Callee {
    /// The ledger field whose cell holds the callee's address.
    Field(u8),
    /// The callee's address as FAB limbs `[hi, lo]`.
    Pinned([Wire3<FieldT, Public>; 2]),
}

impl Callee {
    /// Resolve the address NOW, returning a [`Callee::Pinned`].
    ///
    /// WHY THIS EXISTS: compactc evaluates a call's RECEIVER before its
    /// argument expressions; Rust evaluates the arguments before the call.
    /// Where an argument expression emits instructions — erc20-vault's
    /// `constructSignBidirectionalEventNotificationV1(kernel.self(), …)` —
    /// the two orders differ, and the public transcript is ordered, so the
    /// difference is real. A port with such an argument pins its callee at
    /// the point compactc reads it and the streams agree. Where the
    /// arguments emit nothing (every other call site in the corpus),
    /// `Field` resolved inside [`call`] gives the same stream and is the
    /// simpler spelling.
    pub fn pin<V: Visibility + Copy>(self, c: &mut Circuit3, guard: Wire3<FieldT, V>) -> Callee {
        Callee::Pinned(self.address(c, guard))
    }

    /// The address limbs — for [`Callee::Field`], the fresh uncached read.
    fn address<V: Visibility + Copy>(
        self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, V>,
    ) -> [Wire3<FieldT, Public>; 2] {
        match self {
            Callee::Field(index) => {
                let limbs = cell_read(c, guard, index, vec![AlignmentAtom::Bytes { length: 32 }]);
                [limbs[0], limbs[1]]
            }
            Callee::Pinned(limbs) => limbs,
        }
    }
}

/// ONE TYPED CROSS-CONTRACT CALL: `callee.entry_point(args…) -> R`.
///
/// The whole of M12 above the desugar. [`contract_call`] takes flat limb
/// vectors and a hand-written result-constraint list; this takes the
/// callee's declared argument and result TYPES and derives both — the limb
/// order from [`CallArgs::push_call_slots`], the result constraints from
/// [`CircuitAbi::prims`] run through compactc's own table. A caller can no
/// longer flatten a struct in the wrong order or forget a result's range
/// check, because it never writes either down.
///
/// `entry_point` is the callee circuit's name. THE CIRCUIT DOES NOT BIND IT
/// (notes/interface-crates.org §Honest limits #1): the entry-point hash is
/// a prover-supplied witness, which is exactly why `xcall`'s `callOnce` and
/// `callEmit` compile to the same circuit. What binds it is the LEDGER's
/// `(address, entry_point, comm)` match against the callee's own
/// transaction. Naming it here types the developer's call and tells the
/// transaction builder which circuit to run; it is not a proof obligation.
pub fn call<A: CallArgs, R: CallResult, V: Visibility + Copy>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    callee: Callee,
    entry_point: EntryPoint,
    args: A,
) -> R {
    let _ = entry_point;
    let addr = callee.address(c, guard);
    let arg_slots = args.call_slots();
    let constraints: Vec<LimbConstraint> = R::prims()
        .into_iter()
        .map(Prim::constraint)
        .collect();
    let results = contract_call(c, guard, addr, &arg_slots, &constraints);
    debug_assert_eq!(results.len(), R::SLOTS, "contract_call returned {} slots", results.len());
    R::from_call_slots(&results)
}

/// A callee circuit's ENTRY POINT: its Compact name, and the `Bytes<32>`
/// hash the ledger matches a `claimContractCall` against.
///
/// The hash is not ours to define. `EntryPointBuf::ep_hash`
/// (midnight-onchain-state `state.rs`) is the definition —
/// `persistent_commit(name, "midnight:entry-point" ‖ 12 zero bytes)` — and
/// [`EntryPoint::hash`] CALLS it. Nothing here re-derives a SHA: a
/// reimplementation that agreed today would be a silent chain-split the
/// day upstream changed the domain separator.
///
/// This is what "derive keys, don't type them" means for M12: an interface
/// declares circuit NAMES, and the 32-byte keys the claim carries fall out
/// of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryPoint(&'static str);

impl EntryPoint {
    /// The entry point of the circuit called `name` (the Compact circuit
    /// name, e.g. `"signBidirectional"`).
    pub const fn new(name: &'static str) -> EntryPoint {
        EntryPoint(name)
    }

    /// The Compact circuit name.
    pub const fn name(self) -> &'static str {
        self.0
    }

    /// The 32-byte entry-point hash.
    pub fn hash(self) -> [u8; 32] {
        ep_hash(self.0)
    }

    /// The hash's two FAB limbs, `[hi, lo]` — the witness values a
    /// [`contract_call`] site's prover supplies.
    pub fn limbs(self) -> [Fr; 2] {
        ep_limbs(self.0)
    }
}

/// [`EntryPoint::hash`] for a name known only at run time (an artifact
/// walker, a generator): upstream's own `EntryPointBuf::ep_hash`.
pub fn ep_hash(name: &str) -> [u8; 32] {
    EntryPointBuf::from(name.as_bytes()).ep_hash().0
}

/// [`EntryPoint::limbs`] for a name known only at run time.
///
/// The split is the standard `Bytes<32>` one (notes/builtin-lowering.org
/// §1): `hi` is byte 31 alone, `lo` bytes 0..30 little-endian.
pub fn ep_limbs(name: &str) -> [Fr; 2] {
    let hash = ep_hash(name);
    [
        Fr::from(u64::from(hash[31])),
        Fr::from_le_bytes(&hash[..31]).expect("31 bytes fit the native field"),
    ]
}

// --- events -----------------------------------------------------------------

/// `emit <event>` (compiler/analysis-passes/lower-emit.ss:20-27): push the
/// MIP-0002 wrapper `Array[Cell(version: u32 as bytes<4>), Cell(tag:
/// bytes<1>), Cell(payload)]`, then the VM `log` op. `payload` is the
/// serialized event value (a single `bytes<n>` atom for the declared
/// event size).
pub fn emit_event(version: u32, tag: u8, payload: &LedgerValue) -> Vec<ImpactOp> {
    let mut elems = vec![
        ImpactElem::Imm(Fr::from(0x10u64)), // push, storage = false
        ImpactElem::Imm(Fr::from(3u64 | (3 << 4))), // StateValue::Array(3) tag
        // Cell(version as bytes<4>)
        ImpactElem::Imm(Fr::from(1u64)),
        ImpactElem::Imm(Fr::from(1u64)),
        ImpactElem::Imm(Fr::from(4u64)),
        ImpactElem::Imm(Fr::from(u64::from(version))),
        // Cell(tag as bytes<1>)
        ImpactElem::Imm(Fr::from(1u64)),
        ImpactElem::Imm(Fr::from(1u64)),
        ImpactElem::Imm(Fr::from(1u64)),
        ImpactElem::Imm(Fr::from(u64::from(tag))),
        // Cell(payload)
        ImpactElem::Imm(Fr::from(1u64)),
    ];
    elems.extend(alignment_header(&payload.atoms));
    elems.extend(payload.elems.iter().copied());
    vec![ImpactOp(elems), ImpactOp::constant(&Op::Log)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use midnight_storage::arena::Sp;

    fn imms(op: &ImpactOp) -> Vec<Fr> {
        op.0.iter()
            .map(|e| match e {
                ImpactElem::Imm(f) => *f,
                ImpactElem::Wire(_) => panic!("expected constant"),
            })
            .collect()
    }

    fn repr(op: &VmOp) -> Vec<Fr> {
        let mut out = Vec::new();
        op.field_repr(&mut out);
        out
    }

    /// Our hand-laid push/popeq headers must match the real Op encodings.
    #[test]
    fn mixed_op_layout_matches_field_repr() {
        // push Cell{bytes<16>, 5}:
        let av = AlignedValue::new(
            Value(vec![ValueAtom(5u128.to_le_bytes().to_vec()).normalize()]),
            Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes {
                length: 16,
            })]),
        )
        .unwrap();
        let real = repr(&Op::Push {
            storage: true,
            value: midnight_onchain_state::state::StateValue::Cell(Sp::new(av.clone())),
        });
        let ours = imms(&push_cell(
            true,
            &LedgerValue::bytes(16, vec![ImpactElem::Imm(Fr::from(5u64))]),
        ));
        assert_eq!(ours, real);

        // popeqc expecting a bytes<32> value [hi=1, lo=2]:
        let mut bytes = [0u8; 32];
        bytes[0] = 2; // lo limb LE
        bytes[31] = 1; // hi byte
        let av = AlignedValue::new(
            Value(vec![ValueAtom(bytes.to_vec()).normalize()]),
            Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes {
                length: 32,
            })]),
        )
        .unwrap();
        let real = repr(&Op::Popeq {
            cached: true,
            result: av,
        });
        let ours = imms(&popeq(
            true,
            &LedgerValue::bytes(
                32,
                vec![
                    ImpactElem::Imm(Fr::from(1u64)), // hi
                    ImpactElem::Imm(Fr::from(2u64)), // lo
                ],
            ),
        ));
        assert_eq!(ours, real);
    }

    /// [`push_array`] is the one hand-laid `StateValue` encoder (the mixed
    /// push `List.pushFront` needs), so its constant case must agree with
    /// `StateValue::field_repr` element for element — tags, nesting and the
    /// `3 | len << 4` packing.
    #[test]
    fn push_array_matches_field_repr() {
        let cell = u64_aligned(7);
        let real = repr(&Op::Push {
            storage: true,
            value: StateValue::Array(
                [
                    StateValue::Cell(Sp::new(cell.clone())),
                    StateValue::Null,
                    StateValue::Null,
                ]
                .into(),
            ),
        });
        let ours = imms(&push_array(
            true,
            &[
                LedgerElem::Cell(LedgerValue::bytes(
                    8,
                    vec![ImpactElem::Imm(Fr::from(7u64))],
                )),
                LedgerElem::Null,
                LedgerElem::Null,
            ],
        ));
        assert_eq!(ours, real);
    }

    /// `rt-max-sizeof` against the value compactc actually emitted: the
    /// fixture's `listHead` over a `Bytes<32>` element is `concat 0x27`, and
    /// that immediate is `2 + max_sizeof`.
    #[test]
    fn max_sizeof_matches_compactc() {
        assert_eq!(2 + max_sizeof(&[AlignmentAtom::Bytes { length: 32 }]), 0x27);
        assert_eq!(max_sizeof(&[]), 2);
    }

    /// The worked example's constant streams (notes/ledger-abi.org §5).
    #[test]
    fn counter_increment_matches_annotated_golden() {
        let ops = counter_increment(0, 1);
        assert_eq!(imms(&ops[0]), vec![Fr::from(0x70u64), 1u64.into(), 1u64.into(), 0u64.into()]);
        assert_eq!(imms(&ops[1]), vec![Fr::from(0x0eu64), 1u64.into()]);
        assert_eq!(imms(&ops[2]), vec![Fr::from(0xa1u64)]);
    }

    /// `idx_key` with constant limbs must match the real Op encoding of the
    /// same single-value-key idx.
    #[test]
    fn idx_key_matches_field_repr() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x2a;
        bytes[31] = 0x01;
        let av = AlignedValue::new(
            Value(vec![ValueAtom(bytes.to_vec()).normalize()]),
            Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes {
                length: 32,
            })]),
        )
        .unwrap();
        let real = repr(&Op::Idx {
            cached: false,
            push_path: false,
            path: vec![Key::Value(av)].into(),
        });
        let ours = imms(&idx_key(&LedgerValue::bytes(
            32,
            vec![
                ImpactElem::Imm(Fr::from(1u64)),                  // hi = byte 31
                ImpactElem::Imm(Fr::from(0x2au64)),               // lo = bytes 0..30
            ],
        )));
        assert_eq!(ours, real);
    }

    /// `emit_event` with a constant payload must match the real
    /// `Op::Push` of the MIP-0002 wrapper Array followed by `Op::Log`.
    #[test]
    fn emit_event_matches_field_repr() {
        use midnight_onchain_state::state::StateValue;

        let payload_bytes: Vec<u8> = (1u8..=40).collect();
        let payload_av = AlignedValue::new(
            Value(vec![ValueAtom(payload_bytes.clone()).normalize()]),
            Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes {
                length: 40,
            })]),
        )
        .unwrap();
        let version_av = AlignedValue::new(
            Value(vec![ValueAtom(1u32.to_le_bytes().to_vec()).normalize()]),
            Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes {
                length: 4,
            })]),
        )
        .unwrap();
        let real_push = Op::Push {
            storage: false,
            value: StateValue::Array(
                vec![
                    StateValue::Cell(Sp::new(version_av)),
                    StateValue::Cell(Sp::new(field_key(10))),
                    StateValue::Cell(Sp::new(payload_av)),
                ]
                .into(),
            ),
        };

        // 40 bytes = 2 limbs: [leftover 9 bytes = bytes 31..39, bytes 0..30].
        let hi = Fr::from_le_bytes(&(32u8..=40).collect::<Vec<_>>()).unwrap();
        let lo = Fr::from_le_bytes(&(1u8..=31).collect::<Vec<_>>()).unwrap();
        let payload = LedgerValue::bytes(40, vec![ImpactElem::Imm(hi), ImpactElem::Imm(lo)]);
        let ours = emit_event(1, 10, &payload);
        assert_eq!(imms(&ours[0]), repr(&real_push));
        assert_eq!(imms(&ours[1]), repr(&Op::Log));
    }

    /// `kernel_claim_contract_call`'s constant ops and mixed push header
    /// against real Op encodings and the callOnce.zkir annotated stream:
    /// swap = 0x40, idxpc effects[3] = [0x80,1,1,3], dup 0 = 0x30,
    /// size = 0x04, push cell = [0x10, 1, 3, 0x20, 0x20, −2, limbs…],
    /// concatc 160 = [0x17, 0xa0], push null = [0x10, 0x00], insc 2 = 0xa2.
    #[test]
    fn claim_contract_call_matches_field_repr() {
        use midnight_onchain_state::state::StateValue;

        let mut addr = [0u8; 32];
        addr[0] = 0xaa;
        addr[31] = 0x01;
        let mut ep = [0u8; 32];
        ep[0] = 0xbb;
        ep[31] = 0x02;
        let comm = Fr::from(0x1234u64);

        // The real rt-aligned-concat'd 3-atom cell.
        let comm_bytes: Vec<u8> = {
            let mut le = comm.as_le_bytes();
            while le.last() == Some(&0) {
                le.pop();
            }
            le
        };
        let av = AlignedValue::new(
            Value(vec![
                ValueAtom(addr.to_vec()).normalize(),
                ValueAtom(ep.to_vec()).normalize(),
                ValueAtom(comm_bytes).normalize(),
            ]),
            Alignment(vec![
                AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
                AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
                AlignmentSegment::Atom(AlignmentAtom::Field),
            ]),
        )
        .unwrap();

        let value = LedgerValue::new(
            vec![
                AlignmentAtom::Bytes { length: 32 },
                AlignmentAtom::Bytes { length: 32 },
                AlignmentAtom::Field,
            ],
            vec![
                ImpactElem::Imm(Fr::from(u64::from(addr[31]))),
                ImpactElem::Imm(Fr::from_le_bytes(&addr[..31]).unwrap()),
                ImpactElem::Imm(Fr::from(u64::from(ep[31]))),
                ImpactElem::Imm(Fr::from_le_bytes(&ep[..31]).unwrap()),
                ImpactElem::Imm(comm),
            ],
        );
        let ours = kernel_claim_contract_call(&value);

        let real: Vec<VmOp> = vec![
            Op::Swap { n: 0 },
            Op::Idx {
                cached: true,
                push_path: true,
                path: vec![Key::Value(field_key(3))].into(),
            },
            Op::Dup { n: 0 },
            Op::Size,
            Op::Push {
                storage: false,
                value: midnight_onchain_state::state::StateValue::Cell(Sp::new(av)),
            },
            Op::Concat {
                cached: true,
                n: 160,
            },
            Op::Push {
                storage: false,
                value: StateValue::Null,
            },
            Op::Ins { cached: true, n: 2 },
            Op::Swap { n: 0 },
        ];
        assert_eq!(ours.len(), real.len());
        for (op, real_op) in ours.iter().zip(&real) {
            assert_eq!(imms(op), repr(real_op));
        }
        // The annotated corpus bytes for the constant ops.
        assert_eq!(imms(&ours[1]), vec![Fr::from(0x80u64), 1u64.into(), 1u64.into(), 3u64.into()]);
        assert_eq!(imms(&ours[3]), vec![Fr::from(0x04u64)]);
        assert_eq!(imms(&ours[5]), vec![Fr::from(0x17u64), Fr::from(0xa0u64)]);
        assert_eq!(imms(&ours[6]), vec![Fr::from(0x10u64), Fr::from(0u64)]);
        assert_eq!(imms(&ours[7]), vec![Fr::from(0xa2u64)]);
    }

    /// `map_remove` against real Op encodings and the claim.zkir annotated
    /// stream (:287-291): idxp = [0x70, 1, 1, 0], rem = 0x19, insc 1 = 0xa1.
    #[test]
    fn map_remove_matches_field_repr() {
        let key = LedgerValue::bytes(
            32,
            vec![ImpactElem::Imm(Fr::from(1u64)), ImpactElem::Imm(Fr::from(2u64))],
        );
        let ops = map_remove(0, &key);
        assert_eq!(ops.len(), 4);
        assert_eq!(
            imms(&ops[0]),
            vec![Fr::from(0x70u64), 1u64.into(), 1u64.into(), 0u64.into()]
        );
        assert_eq!(imms(&ops[2]), repr(&Op::Rem { cached: false }));
        assert_eq!(imms(&ops[2]), vec![Fr::from(0x19u64)]);
        assert_eq!(imms(&ops[3]), vec![Fr::from(0xa1u64)]);
    }

    /// `cell_write_coin` against real Op encodings and the notify.zkir
    /// annotated stream: push field key = [0x10, 1, 1, 1, 0], dup 3 =
    /// 0x33, idxc [1, stack] = [0x61, 1, 1, 1, −1] (opcode = 0x60 |
    /// (path_len − 1), Key::Stack = −1), concatc 91 = [0x17, 0x5b],
    /// ins 1 = 0x91.
    #[test]
    fn cell_write_coin_matches_field_repr() {
        let cm = LedgerValue::bytes(
            32,
            vec![ImpactElem::Imm(Fr::from(3u64)), ImpactElem::Imm(Fr::from(4u64))],
        );
        let coin = LedgerValue::new(
            vec![
                AlignmentAtom::Bytes { length: 32 },
                AlignmentAtom::Bytes { length: 32 },
                AlignmentAtom::Bytes { length: 16 },
            ],
            vec![
                ImpactElem::Imm(Fr::from(5u64)),
                ImpactElem::Imm(Fr::from(6u64)),
                ImpactElem::Imm(Fr::from(7u64)),
                ImpactElem::Imm(Fr::from(8u64)),
                ImpactElem::Imm(Fr::from(9u64)),
            ],
        );
        let ops = cell_write_coin(0, &cm, &coin);
        assert_eq!(ops.len(), 8);
        assert_eq!(
            imms(&ops[0]),
            vec![Fr::from(0x10u64), 1u64.into(), 1u64.into(), 1u64.into(), 0u64.into()]
        );
        assert_eq!(imms(&ops[1]), vec![Fr::from(0x33u64)]);
        assert_eq!(
            imms(&ops[3]),
            repr(&Op::Idx {
                cached: true,
                push_path: false,
                path: vec![Key::Value(field_key(1)), Key::Stack].into(),
            })
        );
        assert_eq!(
            imms(&ops[3]),
            vec![
                Fr::from(0x61u64),
                1u64.into(),
                1u64.into(),
                1u64.into(),
                Fr::from(0u64) - Fr::from(1u64),
            ]
        );
        // push coin: [0x10, Cell tag, 3 atoms, 0x20, 0x20, 0x10, limbs…]
        assert_eq!(
            imms(&ops[4])[..6],
            [
                Fr::from(0x10u64),
                1u64.into(),
                3u64.into(),
                0x20u64.into(),
                0x20u64.into(),
                0x10u64.into(),
            ]
        );
        assert_eq!(imms(&ops[5]), repr(&Op::Swap { n: 0 }));
        assert_eq!(imms(&ops[6]), vec![Fr::from(0x17u64), Fr::from(0x5bu64)]);
        assert_eq!(imms(&ops[7]), vec![Fr::from(0x91u64)]);
    }

    /// `set_insert` against real Op encodings (depositViaVault.zkir:
    /// pushs null = [0x11, 0x00], ins = 0x91, insc = 0xa1).
    #[test]
    fn set_insert_matches_field_repr() {
        use midnight_onchain_state::state::StateValue;

        let ops = set_insert(2, &LedgerValue::bytes(1, vec![ImpactElem::Imm(Fr::from(7u64))]));
        assert_eq!(
            imms(&ops[2]),
            repr(&Op::Push {
                storage: true,
                value: StateValue::Null,
            })
        );
        assert_eq!(imms(&ops[2]), vec![Fr::from(0x11u64), Fr::from(0u64)]);
        assert_eq!(
            imms(&ops[3]),
            repr(&Op::Ins {
                cached: false,
                n: 1,
            })
        );
        assert_eq!(imms(&ops[3]), vec![Fr::from(0x91u64)]);
    }

    /// The read shapes' constant ops, against initialise.zkir's annotated
    /// stream (test-caller-contract): dup 0 = 0x30, read idx of field 6 =
    /// [0x50, 1, 1, 6], kernel-self reach = dup 2 + idxc [0].
    #[test]
    fn read_shape_constants_match_corpus_golden() {
        assert_eq!(imms(&dup(0)), vec![Fr::from(0x30u64)]);
        assert_eq!(imms(&dup(2)), vec![Fr::from(0x32u64)]);
        assert_eq!(
            imms(&idx_field(6)),
            vec![Fr::from(0x50u64), 1u64.into(), 1u64.into(), 6u64.into()]
        );
        assert_eq!(
            imms(&ImpactOp::constant(&Op::Idx {
                cached: true,
                push_path: false,
                path: vec![Key::Value(field_key(0))].into(),
            })),
            vec![Fr::from(0x60u64), 1u64.into(), 1u64.into(), 0u64.into()]
        );
    }
}
