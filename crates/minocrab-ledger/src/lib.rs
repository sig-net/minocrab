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
//!
//! # Where this sits
//!
//! L2.5: above the [`minocrab`] eDSL (L2), whose wires it splices into op
//! element streams, and below `minocrab-std` (L3), whose `v3::ledger` and
//! `v3::kernel` types are one-line wrappers over the functions here. That
//! layering is deliberate — the ADTs sit *above* the ops, so this crate stays
//! the pure op layer and gains no dependency of its own. Contract code should
//! use the typed slots in `minocrab-std`; reach for this crate to emit an
//! operation those do not cover, or to read what the encoding actually is.
//!
//! # Start here
//!
//! - [`ImpactOp`] and [`ImpactElem`] — one Impact instruction, as the element
//!   stream `Op::field_repr` would produce
//! - [`LedgerValue`] — a FAB-aligned value whose limbs may be
//!   circuit-computed
//! - [`cell_write`], [`map_insert`], [`counter_increment`] — writes, as
//!   compactc's vm-code sequences them
//! - [`cell_read`], [`map_lookup`], [`counter_read`] — reads, which return
//!   wires and record their disclosure
//! - [`contract_call`] — a cross-contract call, and the labels it discloses
//!   ([`XcallEntryPointHash`], [`XcallCommitment`], [`XcallResult`])
//!
//! # Stability (M24 tier boundary)
//!
//! INTERNAL TIER, whole crate: the Impact op layer is the eDSL's
//! implementation detail (reached through `minocrab-std`'s typed ledger
//! surface) and carries no stability promise.

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

    /// The alignment atoms, in slot order.
    pub fn atoms(&self) -> &[AlignmentAtom] {
        &self.atoms
    }

    /// The limbs, in slot order.
    pub fn elems(&self) -> &[ImpactElem] {
        &self.elems
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
    assert!(
        n <= 15,
        "dup {n}: the reach does not fit the opcode's low nibble — a coin arm \
         at this path depth would miscompile in compactc too \
         (midnight-ledger.ss:576-577)"
    );
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

// --- the ledger PATH (`f`) --------------------------------------------------
//
// Every ledger operation's vm-code is written against `f`, "the path to the
// field being operated on" (midnight-ledger.ss:133-138), and `f` is "a list of
// either aligned value instances, or the symbol 'stack". For a top-level
// field it is one `bytes<1>` key; nesting appends map keys.
//
// A NESTED ACCESS IS NOT A NEW INSTRUCTION. compactc's
// `propagate-ledger-paths.ss` walks a chain of accessors, folds every
// intermediate `Map.lookup(k)` into `f` as one more path element, and emits
// nothing for it; only the LAST accessor's vm-code runs, with a longer `f`.
// So `m.lookup(k).insert(k2, v)` is `map_insert`'s five instructions with a
// two-element path — `idxp` gains a low nibble and the closing `insc` a
// bigger `n`. See notes/coin-arms-nested-adts.org "AS BUILT — STAGE B1".

/// One element of a ledger path — compactc's `f` entry.
///
/// [`LedgerKey::Field`] and [`LedgerKey::Value`] are the two halves of
/// upstream's `Key::Value(AlignedValue)`, split because a field index is
/// const-known and a map key generally is not; [`LedgerKey::Stack`] is
/// upstream's `Key::Stack` (`'stack` in the vm-code). All three encode
/// exactly as `Key::field_repr` does — `key_encoding_matches_field_repr`
/// pins it.
#[derive(Clone)]
pub enum LedgerKey {
    /// A constant `bytes<1>` key — a ledger field index, or a position inside
    /// an ADT's `Array` (compactc's `(align i 1)`). Encodes as `[1, 1, i]`.
    Field(u8),
    /// A FAB-aligned key whose limbs may be circuit-computed: a `Map` key.
    /// Encodes as its alignment header followed by its limbs.
    Value(LedgerValue),
    /// The top of the Impact stack, `-1` — the coin arms' `idxc [(1), stack]`
    /// and nothing else.
    Stack,
}

impl LedgerKey {
    /// This element's `Key::field_repr` elements, appended to `out`.
    fn push_elems(&self, out: &mut Vec<ImpactElem>) {
        match self {
            LedgerKey::Field(index) => {
                out.extend(alignment_header(&[AlignmentAtom::Bytes { length: 1 }]));
                out.push(ImpactElem::Imm(Fr::from(u64::from(*index))));
            }
            LedgerKey::Value(value) => {
                out.extend(alignment_header(&value.atoms));
                out.extend(value.elems.iter().copied());
            }
            LedgerKey::Stack => out.push(ImpactElem::Imm(Fr::from(0u64) - Fr::from(1u64))),
        }
    }

    /// This element pushed as a `Cell` — compactc's
    /// `(push [storage #f] [value (state-value 'cell (car (reverse f)))])`,
    /// the key the whole-field-replace ops write the new value under.
    fn push_as_cell(&self) -> ImpactOp {
        match self {
            LedgerKey::Field(index) => push_cell(false, &field_index_value(*index)),
            LedgerKey::Value(value) => push_cell(false, value),
            LedgerKey::Stack => panic!("a whole-field replace cannot write under a stack key"),
        }
    }
}

/// The ONE new encoder of stage B1: `idx` over a whole path.
///
/// `[0x50 | hi | (path.len() − 1)]` then each element's encoding, which is
/// `assemble1`'s `idx` case (reduce-to-zkir.ss:586-601) and upstream's
/// `Op::Idx` field_repr (ops.rs:510-524) at once. The low nibble is the
/// ONLY thing depth changes.
pub fn idx_path(cached: bool, push_path: bool, path: &[LedgerKey]) -> ImpactOp {
    assert!(
        !path.is_empty(),
        "idx_path: an empty path emits no instruction — the callers that can \
         produce one go through the suppression helpers"
    );
    assert!(
        path.len() <= 16,
        "idx_path: a {}-element path does not fit the opcode's low nibble \
         (compactc has the same bound, unchecked)",
        path.len()
    );
    let hi = match (cached, push_path) {
        (false, false) => 0x50u8,
        (true, false) => 0x60,
        (false, true) => 0x70,
        (true, true) => 0x80,
    };
    let mut elems = vec![ImpactElem::Imm(Fr::from(u64::from(
        hi | (path.len() as u8 - 1),
    )))];
    for key in path {
        key.push_elems(&mut elems);
    }
    ImpactOp(elems)
}

/// The one-element path of a top-level ledger field — what every `u8`
/// builder widens into, and the reason the widening is purely ADDITIVE.
fn field_path(index: u8) -> [LedgerKey; 1] {
    [LedgerKey::Field(index)]
}

/// `insc n`, with compactc's own nibble bound stated.
fn insc(n: usize) -> ImpactOp {
    assert!(
        n <= 15,
        "insc {n}: the depth does not fit the opcode's low nibble"
    );
    ImpactOp::constant(&Op::Ins {
        cached: true,
        n: n as u8,
    })
}

/// `ins 1` — the uncached insert every write closes its inner slot with.
fn ins1() -> ImpactOp {
    ImpactOp::constant(&Op::Ins {
        cached: false,
        n: 1,
    })
}

// --- PATH SUPPRESSION -------------------------------------------------------
//
// Nine operations REPLACE a whole field rather than reach inside it —
// `Cell.write`, `Cell.writeCoin`, `Cell.resetToDefault`,
// `Counter.resetToDefault`, and the five collections' `resetToDefault`
// (midnight-ledger.ss:554, 561, 573, 616, 627, 715, 821, 1015, 1178). They
// alone split `f` into "the path to the container" and "the key to write":
//
//   (idx [pushPath #t] [path (suppress-null (reverse (cdr (reverse f))))])
//   (push [storage #f] [value (state-value 'cell (car (reverse f)))])
//   …
//   (ins [cached #t] [n (suppress-zero (sub1 (length f)))])
//
// `suppress-null` / `suppress-zero` (vm.ss:192-194) turn the degenerate
// operand into `VMsuppress`, which `assemble1` maps to the EMPTY operand list
// and `assemble` then drops — the instruction disappears. At depth 1 both
// vanish, which is why a top-level `Cell` write is three instructions. At
// depth 2 BOTH become live: `idxp [field]` and `insc 1` reappear, exactly as
// the probe of `a.lookup(k).resetToDefault()` shows.
//
// This is the one place our encoding must diverge from `Op::field_repr`:
// upstream's `Op::Ins { n: 0 }` writes `0xa0` rather than nothing, so the
// suppressed `insc` has to be OMITTED here and not encoded as zero.
// (`Op::Idx` with an empty path already writes nothing, so that half agrees.)

/// The leading `idxp` of a whole-field-replace op: the path MINUS its last
/// element, suppressed away entirely when that leaves nothing.
fn idxp_container(path: &[LedgerKey]) -> Vec<ImpactOp> {
    let head = &path[..path.len() - 1];
    if head.is_empty() {
        Vec::new()
    } else {
        vec![idx_path(false, true, head)]
    }
}

/// The closing `insc` of a whole-field-replace op: `len(f) − 1`, suppressed
/// away entirely at zero.
fn insc_container(path: &[LedgerKey]) -> Vec<ImpactOp> {
    if path.len() == 1 {
        Vec::new()
    } else {
        vec![insc(path.len() - 1)]
    }
}

// --- compactc's vm-code per ledger operation (midnight-ledger.ss) -----------
//
// Every builder comes in two forms: `foo(index: u8, ..)` for a top-level
// field and `foo_at(path: &[LedgerKey], ..)` for the general case. The `u8`
// form is a one-line wrapper over the one-element path, so the widening adds
// a capability without moving a single byte of what the crate already emits
// (M22 stage B1's zero-movement gate).

/// `Counter.increment(amount)` on ledger field `index`
/// (midnight-ledger.ss:605-609): `idxp [field]; addi amount; insc 1`.
pub fn counter_increment(index: u8, amount: u32) -> Vec<ImpactOp> {
    counter_increment_at(&field_path(index), amount)
}

/// [`counter_increment`] on a general path: `idxp f; addi amount; insc len(f)`.
pub fn counter_increment_at(path: &[LedgerKey], amount: u32) -> Vec<ImpactOp> {
    vec![
        idx_path(false, true, path),
        ImpactOp::constant(&Op::Addi { immediate: amount }),
        insc(path.len()),
    ]
}

/// `field = value` — Cell write to a top-level field
/// (midnight-ledger.ss:552-558 with the idxp/insc pair suppressed for
/// top-level fields, reduce-to-zkir.ss:595-608): `push key; pushs value;
/// ins 1`.
pub fn cell_write(index: u8, value: &LedgerValue) -> Vec<ImpactOp> {
    cell_write_at(&field_path(index), value)
}

/// [`cell_write`] on a general path — one of the NINE whole-field-replace ops
/// (see "PATH SUPPRESSION" above), so the leading `idxp` and closing `insc`
/// are live at depth 2 and suppressed at depth 1:
///
/// ```text
/// idxp f[..len-1];  push f[len-1];  pushs value;  ins 1;  insc len(f)-1
/// ```
pub fn cell_write_at(path: &[LedgerKey], value: &LedgerValue) -> Vec<ImpactOp> {
    let mut ops = idxp_container(path);
    ops.push(path[path.len() - 1].push_as_cell());
    ops.push(push_cell(true, value));
    ops.push(ins1());
    ops.extend(insc_container(path));
    ops
}

/// `Cell<QualifiedShieldedCoinInfo>.writeCoin(coin, recipient)` on the
/// top-level field `index` (midnight-ledger.ss:567-583): the coin's
/// Merkle-tree index is resolved by indexing the context's
/// commitment-index map (context\[1\]) with the coin's commitment (from the
/// stack) and concatenated onto the coin, writing the resulting
/// QualifiedShieldedCoinInfo. `push key; dup 3; push cm; idxc [1, stack];
/// push coin; swap 0; concatc 91; ins 1` — the leading idx (empty path)
/// and trailing insc 0 are compactc's depth-1 suppressions; the `dup 3`
/// reaches the context past the key push, the result slot, and effects.
/// `cm` is the runtime coin commitment (`rt-coin-commit`, a `bytes<32>`);
/// `coin` the 3-atom `[bytes<32>, bytes<32>, bytes<16>]` ShieldedCoinInfo.
///
/// The middle six are [`qualify_coin`], shared with the three collection
/// arms; this is `cell_write` with its value push replaced by them.
pub fn cell_write_coin(index: u8, cm: &LedgerValue, coin: &LedgerValue) -> Vec<ImpactOp> {
    cell_write_coin_at(&field_path(index), cm, coin)
}

/// [`cell_write_coin`] on a general path — [`cell_write_at`] with its value
/// push replaced by [`qualify_coin`], and the `dup` reach growing with the
/// path ([`cell_coin_dup`]).
pub fn cell_write_coin_at(path: &[LedgerKey], cm: &LedgerValue, coin: &LedgerValue) -> Vec<ImpactOp> {
    let mut ops = idxp_container(path);
    ops.push(path[path.len() - 1].push_as_cell());
    ops.extend(qualify_coin(cell_coin_dup(path.len()), cm, coin));
    ops.push(ins1());
    ops.extend(insc_container(path));
    ops
}

/// THE QUALIFY DANCE — the six instructions all four coin arms share
/// (`Cell.writeCoin`, `Set.insertCoin`, `Map.insertCoin`,
/// `List.pushFrontCoin`; midnight-ledger.ss:567-583, :670-696, :769-795,
/// :918-968).
///
/// It turns a `ShieldedCoinInfo` into the `QualifiedShieldedCoinInfo` the
/// four store, by resolving the coin's Merkle-tree index on chain and
/// concatenating it on:
///
/// ```text
/// dup dup_n                   // reach the CONTEXT down the stack
/// push (cell cm)              // the runtime coin commitment
/// idxc [(1), stack]           // context[1][cm] → the coin's mt_index
/// push (cell coin)            // the 3-atom ShieldedCoinInfo
/// swap 0
/// concatc 91                  // [nonce, color, value] ++ [mt_index]
/// ```
///
/// `91` is `2 + rt-max-sizeof(QualifiedShieldedCoinInfo)` and is a literal in
/// compactc's source. `cm` is the runtime coin commitment (`rt-coin-commit`,
/// a `bytes<32>`); `coin` the 3-atom `[bytes<32>, bytes<32>, bytes<16>]`
/// `ShieldedCoinInfo`.
///
/// THE ONLY THING THAT DIFFERS between the four arms is `dup_n` and what
/// surrounds the six — each arm is its plain twin with one push replaced by
/// this. The reach is past the pushes the arm has already made, the result
/// slot, the `2n` path items the leading `idx` left, and the effects, so it
/// is a per-arm constant at depth 1 (the four `*_COIN_DUP` below).
fn qualify_coin(dup_n: u8, cm: &LedgerValue, coin: &LedgerValue) -> [ImpactOp; 6] {
    [
        dup(dup_n),
        push_cell(false, cm),
        ImpactOp::constant(&Op::Idx {
            cached: true,
            push_path: false,
            path: vec![Key::Value(field_key(1)), Key::Stack].into(),
        }),
        push_cell(false, coin),
        ImpactOp::constant(&Op::Swap { n: 0 }),
        ImpactOp::constant(&Op::Concat { cached: true, n: 91 }),
    ]
}

/// The four coin arms' [`qualify_coin`] reaches, as compactc writes them —
/// each counting the arm's own pushes, the result slot, the `2·len(f)` path
/// items the leading `idx` left, and the effects. At `len(f) = 1` they are
/// 3, 4, 5 and 7, which is what M22 stage A pinned.
///
/// compactc notes at midnight-ledger.ss:576-577 that a long `f` overflows the
/// `dup` nibble; [`dup`] asserts what compactc only comments.
fn cell_coin_dup(len: usize) -> u8 {
    (3 + 2 * (len - 1)) as u8
}

/// See [`cell_coin_dup`].
fn set_coin_dup(len: usize) -> u8 {
    (2 + 2 * len) as u8
}

/// See [`cell_coin_dup`].
fn map_coin_dup(len: usize) -> u8 {
    (3 + 2 * len) as u8
}

/// See [`cell_coin_dup`].
fn list_coin_dup(len: usize) -> u8 {
    (5 + 2 * len) as u8
}

/// `map.insert(key, value)` on ledger field `index`:
/// `idxp [field]; push key; pushs value; ins 1; insc 1`.
pub fn map_insert(index: u8, key: &LedgerValue, value: &LedgerValue) -> Vec<ImpactOp> {
    map_insert_at(&field_path(index), key, value)
}

/// [`map_insert`] on a general path: `idxp f; push key; pushs value; ins 1;
/// insc len(f)`. The nested form of `m.lookup(k).insert(k2, v)`, and the
/// stream OpenZeppelin's `ShieldedMultiSig.approveProposal` compiles to
/// (`0x71 … 0x91 0xa2`).
pub fn map_insert_at(path: &[LedgerKey], key: &LedgerValue, value: &LedgerValue) -> Vec<ImpactOp> {
    vec![
        idx_path(false, true, path),
        push_cell(false, key),
        push_cell(true, value),
        ins1(),
        insc(path.len()),
    ]
}

/// `Map<K, QualifiedShieldedCoinInfo>.insertCoin(key, coin, recipient)` on
/// ledger field `index` (midnight-ledger.ss:769-795) — [`map_insert`] with
/// its `pushs value` replaced by [`qualify_coin`]:
///
/// ```text
/// idxp [field]; push key
/// dup 5; push cm; idxc [(1), stack]; push coin; swap 0; concatc 91
/// ins 1; insc 1
/// ```
///
/// The `dup 5` reaches the context past the key push, the map, the two path
/// items the `idxp` left, and the effects.
pub fn map_insert_coin(
    index: u8,
    key: &LedgerValue,
    cm: &LedgerValue,
    coin: &LedgerValue,
) -> Vec<ImpactOp> {
    map_insert_coin_at(&field_path(index), key, cm, coin)
}

/// [`map_insert_coin`] on a general path.
pub fn map_insert_coin_at(
    path: &[LedgerKey],
    key: &LedgerValue,
    cm: &LedgerValue,
    coin: &LedgerValue,
) -> Vec<ImpactOp> {
    let mut ops = vec![idx_path(false, true, path), push_cell(false, key)];
    ops.extend(qualify_coin(map_coin_dup(path.len()), cm, coin));
    ops.push(ins1());
    ops.push(insc(path.len()));
    ops
}

/// `map.remove(key)` on ledger field `index` (midnight-ledger.ss Map
/// `remove`; claim.zkir:287-291): `idxp [field]; push key; rem; insc 1`.
pub fn map_remove(index: u8, key: &LedgerValue) -> Vec<ImpactOp> {
    map_remove_at(&field_path(index), key)
}

/// [`map_remove`] on a general path.
pub fn map_remove_at(path: &[LedgerKey], key: &LedgerValue) -> Vec<ImpactOp> {
    vec![
        idx_path(false, true, path),
        push_cell(false, key),
        ImpactOp::constant(&Op::Rem { cached: false }),
        insc(path.len()),
    ]
}

/// `set.insert(elem)` on ledger field `index` — `map_insert` with a `Null`
/// value (midnight-ledger.ss's Set vm-code; xcontract-events
/// depositViaVault): `idxp [field]; push elem; pushs null; ins 1; insc 1`.
pub fn set_insert(index: u8, elem: &LedgerValue) -> Vec<ImpactOp> {
    set_insert_at(&field_path(index), elem)
}

/// [`set_insert`] on a general path.
pub fn set_insert_at(path: &[LedgerKey], elem: &LedgerValue) -> Vec<ImpactOp> {
    vec![
        idx_path(false, true, path),
        push_cell(false, elem),
        ImpactOp::constant(&Op::Push {
            storage: true,
            value: midnight_onchain_state::state::StateValue::Null,
        }),
        ins1(),
        insc(path.len()),
    ]
}

/// `Set<QualifiedShieldedCoinInfo>.insertCoin(coin, recipient)` on ledger
/// field `index` (midnight-ledger.ss:670-696) — [`set_insert`] with its
/// `push elem` replaced by [`qualify_coin`]:
///
/// ```text
/// idxp [field]
/// dup 4; push cm; idxc [(1), stack]; push coin; swap 0; concatc 91
/// pushs null; ins 1; insc 1
/// ```
///
/// The qualified coin is the KEY the `Null` is stored under, so the dance
/// runs BEFORE the `pushs null` — the `dup 4` reaches the context past the
/// set, the two path items the `idxp` left, and the effects.
pub fn set_insert_coin(index: u8, cm: &LedgerValue, coin: &LedgerValue) -> Vec<ImpactOp> {
    set_insert_coin_at(&field_path(index), cm, coin)
}

/// [`set_insert_coin`] on a general path.
pub fn set_insert_coin_at(path: &[LedgerKey], cm: &LedgerValue, coin: &LedgerValue) -> Vec<ImpactOp> {
    let mut ops = vec![idx_path(false, true, path)];
    ops.extend(qualify_coin(set_coin_dup(path.len()), cm, coin));
    ops.push(ImpactOp::constant(&Op::Push {
        storage: true,
        value: midnight_onchain_state::state::StateValue::Null,
    }));
    ops.push(ins1());
    ops.push(insc(path.len()));
    ops
}

/// `set.remove(elem)` on ledger field `index` — the SAME instruction stream
/// `map.remove(key)` is, because a Compact `Set` is a `Map` with `Null`
/// values and `remove` does not touch the value (fixture `setRemove` is
/// `map_remove`'s stream, notes/ledger-adts.org §1). Named for the caller's
/// sake; it emits nothing of its own.
pub fn set_remove(index: u8, elem: &LedgerValue) -> Vec<ImpactOp> {
    map_remove(index, elem)
}

/// [`set_remove`] on a general path — see [`map_remove_at`].
pub fn set_remove_at(path: &[LedgerKey], elem: &LedgerValue) -> Vec<ImpactOp> {
    map_remove_at(path, elem)
}

/// `map.insertDefault(key)` / a `Map` whose value type's default is written
/// (midnight-ledger.ss Map `insertDefault`): `idxp [field]; push key;
/// pushs default; ins 1; insc 1`. `value_atoms` is the VALUE type's
/// alignment; the limbs are zeros ([`default_value`]).
pub fn map_insert_default(index: u8, key: &LedgerValue, value_atoms: Vec<AlignmentAtom>) -> Vec<ImpactOp> {
    map_insert(index, key, &default_value(value_atoms))
}

/// [`map_insert_default`] on a general path.
pub fn map_insert_default_at(
    path: &[LedgerKey],
    key: &LedgerValue,
    value_atoms: Vec<AlignmentAtom>,
) -> Vec<ImpactOp> {
    map_insert_at(path, key, &default_value(value_atoms))
}

/// `map.insertDefault(key)` where the VALUE TYPE IS AN ADT — a different
/// instruction from [`map_insert_default`], and the one place stage B1 found
/// the crate would have been wrong rather than merely unable.
///
/// compactc's `insert`/`insertDefault` push `(state-value 'ADT value
/// value_type)`, and `assemble-operand-acc`'s `VMstate-value-ADT` case
/// (reduce-to-zkir.ss:424-433) DISCARDS the value and emits the ADT's own
/// `(initial-value …)` whenever the type is an ADT — the empty map for
/// `Map`/`Set`, `[null, null, cell 0u64]` for `List`, `cell 0u64` for
/// `Counter`, the blank tree pair for the two trees. Only when the type is
/// NOT an ADT does it fall through to `(cons 1 val)`, the plain cell
/// [`map_insert_default`] pushes.
///
/// So an ADT-valued `insertDefault` is `idxp f; push key; pushs <the ADT's
/// initial value>; ins 1; insc len(f)` — verified against compactc for
/// `Map<K, Map<..>>`, `Map<K, List<..>>` and `Map<K, Counter>`. The initial
/// values are the same constants `resetToDefault` writes, so they come from
/// [`empty_map`], [`empty_list`], [`empty_counter`] and [`empty_merkle_tree`]
/// rather than a second table.
pub fn map_insert_adt_default_at(
    path: &[LedgerKey],
    key: &LedgerValue,
    initial: StateValue<InMemoryDB>,
) -> Vec<ImpactOp> {
    vec![
        idx_path(false, true, path),
        push_cell(false, key),
        ImpactOp::constant(&Op::Push {
            storage: true,
            value: initial,
        }),
        ins1(),
        insc(path.len()),
    ]
}

/// The shared shape of every `resetToDefault`: `idxp f[..len-1];
/// push f[len-1]; pushs initial; ins 1; insc len(f)-1`, the first and last
/// suppressed at depth 1.
///
/// One of the NINE whole-field-replace ops — see "PATH SUPPRESSION" above and
/// notes/ledger-adts.org finding (d). Five of the six `resetToDefault`s go
/// through here; `HistoricMerkleTree`'s open-codes its own because its
/// closing pair is asymmetric.
fn reset_to_at(path: &[LedgerKey], initial: StateValue<InMemoryDB>) -> Vec<ImpactOp> {
    let mut ops = idxp_container(path);
    ops.push(path[path.len() - 1].push_as_cell());
    ops.push(ImpactOp::constant(&Op::Push {
        storage: true,
        value: initial,
    }));
    ops.push(ins1());
    ops.extend(insc_container(path));
    ops
}

/// The field index as a pushable `bytes<1>` value — the key half of
/// [`field_key`], for the ops that push it rather than index by it.
fn field_index_value(index: u8) -> LedgerValue {
    LedgerValue::bytes(1, vec![ImpactElem::Imm(Fr::from(u64::from(index)))])
}

/// `map.resetToDefault()` on field `index`: `push key; pushs (empty map);
/// ins 1`.
pub fn map_reset(index: u8) -> Vec<ImpactOp> {
    map_reset_at(&field_path(index))
}

/// [`map_reset`] on a general path.
pub fn map_reset_at(path: &[LedgerKey]) -> Vec<ImpactOp> {
    reset_to_at(path, empty_map())
}

/// `set.resetToDefault()` — [`map_reset`], since a `Set`'s initial value is
/// the empty map a `Map`'s is.
pub fn set_reset(index: u8) -> Vec<ImpactOp> {
    map_reset(index)
}

/// [`set_reset`] on a general path.
pub fn set_reset_at(path: &[LedgerKey]) -> Vec<ImpactOp> {
    map_reset_at(path)
}

/// A `Map`'s (and a `Set`'s) initial value: the empty map.
pub fn empty_map() -> StateValue<InMemoryDB> {
    StateValue::Map(StorageHashMap::new())
}

/// A `Counter`'s initial value: `cell 0u64`.
pub fn empty_counter() -> StateValue<InMemoryDB> {
    StateValue::Cell(Sp::new(u64_aligned(0)))
}

/// `counter.resetToDefault()` on field `index` (midnight-ledger.ss:614-620) —
/// the fourth of the nine whole-field-replace ops, and the one the crate had
/// no builder for until a NESTED `Map<K, Counter>` needed it.
pub fn counter_reset(index: u8) -> Vec<ImpactOp> {
    counter_reset_at(&field_path(index))
}

/// [`counter_reset`] on a general path.
pub fn counter_reset_at(path: &[LedgerKey]) -> Vec<ImpactOp> {
    reset_to_at(path, empty_counter())
}

// --- List: an `Array[3]` of `{head cell, tail list, length}` ----------------

/// A `List`'s initial value: `[null, null, cell 0u64]`.
pub fn empty_list() -> StateValue<InMemoryDB> {
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
    list_reset_at(&field_path(index))
}

/// [`list_reset`] on a general path.
pub fn list_reset_at(path: &[LedgerKey]) -> Vec<ImpactOp> {
    reset_to_at(path, empty_list())
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
    list_push_front_at(&field_path(index), value)
}

/// [`list_push_front`] on a general path. The closing `insc` is
/// `len(f) + 1` — the only op family whose depth arithmetic is not
/// `len(f)` — and the `insc 1` in the middle is a literal 1 at every depth.
pub fn list_push_front_at(path: &[LedgerKey], value: &LedgerValue) -> Vec<ImpactOp> {
    vec![
        idx_path(false, true, path),
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
        insc(path.len() + 1),
    ]
}

/// `List<QualifiedShieldedCoinInfo>.pushFrontCoin(coin, recipient)` on field
/// `index` (midnight-ledger.ss:918-968) — the one arm that is NOT a
/// one-for-one swap, because [`list_push_front`] builds its new node with the
/// value already in it and this cannot: the qualified coin does not exist
/// until the dance has run against a node that is already on the stack.
///
/// So the node is pushed BLANK, the position key `0u8` goes on, the dance
/// runs, and an `insc 1` puts the coin at `node[0]`. Eight instructions
/// longer than `pushFront`'s thirteen; the tail is identical.
///
/// ```text
/// idxp [field]; dup 0; idx [2]; addi 1        // len + 1
/// pushs [null, null, null]                    // the BLANK new node
/// push 0u8                                    // node[0], the head slot
/// dup 7; push cm; idxc [(1), stack]; push coin; swap 0; concatc 91
/// insc 1                                      // node[0] = the qualified coin
/// swap 0; push 2u8; swap 0; insc 1            // node[2] = len + 1
/// swap 0; push 1u8; swap 0; insc 2            // node[1] = the old list
/// ```
pub fn list_push_front_coin(index: u8, cm: &LedgerValue, coin: &LedgerValue) -> Vec<ImpactOp> {
    list_push_front_coin_at(&field_path(index), cm, coin)
}

/// [`list_push_front_coin`] on a general path.
pub fn list_push_front_coin_at(
    path: &[LedgerKey],
    cm: &LedgerValue,
    coin: &LedgerValue,
) -> Vec<ImpactOp> {
    let mut ops = vec![
        idx_path(false, true, path),
        dup(0),
        idx_one(false, false, LIST_LENGTH),
        ImpactOp::constant(&Op::Addi { immediate: 1 }),
        push_array(true, &[LedgerElem::Null, LedgerElem::Null, LedgerElem::Null]),
        push_cell(false, &field_index_value(LIST_HEAD)),
    ];
    ops.extend(qualify_coin(list_coin_dup(path.len()), cm, coin));
    ops.extend([
        ImpactOp::constant(&Op::Ins { cached: true, n: 1 }),
        swap(0),
        push_cell(false, &field_index_value(LIST_LENGTH)),
        swap(0),
        ImpactOp::constant(&Op::Ins { cached: true, n: 1 }),
        swap(0),
        push_cell(false, &field_index_value(LIST_TAIL)),
        swap(0),
        insc(path.len() + 1),
    ]);
    ops
}

/// `list.popFront()` on field `index`: `idxp [field]; idx [1]; insc 1` — the
/// list becomes its own tail.
pub fn list_pop_front(index: u8) -> Vec<ImpactOp> {
    list_pop_front_at(&field_path(index))
}

/// [`list_pop_front`] on a general path.
pub fn list_pop_front_at(path: &[LedgerKey]) -> Vec<ImpactOp> {
    vec![
        idx_path(false, true, path),
        idx_one(false, false, LIST_TAIL),
        insc(path.len()),
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

/// A `MerkleTree`'s initial value as one `StateValue`
/// (midnight-ledger.ss:973): `[merkle-tree nat (), cell 0u64]`.
///
/// The constant `resetToDefault` writes AND the one an ADT-valued
/// `insertDefault` pushes — `VMstate-value-ADT` expands the declared
/// `(initial-value …)` in both cases, which is why there is one function
/// rather than two tables (see [`map_insert_adt_default_at`]).
pub fn empty_merkle_tree_value(depth: u8) -> StateValue<InMemoryDB> {
    StateValue::Array(empty_merkle_tree(depth).into_iter().collect())
}

/// A `HistoricMerkleTree`'s initial value (midnight-ledger.ss:1129):
/// [`empty_merkle_tree_value`] plus an empty history map.
///
/// NOTE the asymmetry with [`historic_merkle_tree_reset_at`], which pushes
/// this and then APPENDS the blank tree's root to the history; the declared
/// initial value itself has the history empty.
pub fn empty_historic_merkle_tree_value(depth: u8) -> StateValue<InMemoryDB> {
    let [tree, next] = empty_merkle_tree(depth);
    StateValue::Array([tree, next, empty_map()].into_iter().collect())
}

/// `mt.resetToDefault()` on field `index`.
pub fn merkle_tree_reset(index: u8, depth: u8) -> Vec<ImpactOp> {
    merkle_tree_reset_at(&field_path(index), depth)
}

/// [`merkle_tree_reset`] on a general path.
pub fn merkle_tree_reset_at(path: &[LedgerKey], depth: u8) -> Vec<ImpactOp> {
    reset_to_at(path, empty_merkle_tree_value(depth))
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
    merkle_tree_insert_at(&field_path(index), leaf)
}

/// [`merkle_tree_insert`] on a general path — the closing `insc` is
/// `len(f) + 1`; the two in the middle are literal 1s at every depth.
pub fn merkle_tree_insert_at(path: &[LedgerKey], leaf: &LedgerValue) -> Vec<ImpactOp> {
    vec![
        idx_path(false, true, path),
        idx_one(false, true, TREE),
        dup(2),
        idx_one(false, false, TREE_NEXT),
        push_cell(true, leaf),
        ins1(),
        ImpactOp::constant(&Op::Ins { cached: true, n: 1 }),
        idx_one(false, true, TREE_NEXT),
        ImpactOp::constant(&Op::Addi { immediate: 1 }),
        insc(path.len() + 1),
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
    merkle_tree_insert_index_at(&field_path(index), leaf, at)
}

/// [`merkle_tree_insert_index`] on a general path.
pub fn merkle_tree_insert_index_at(
    path: &[LedgerKey],
    leaf: &LedgerValue,
    at: &LedgerValue,
) -> Vec<ImpactOp> {
    vec![
        idx_path(false, true, path),
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
        ins1(),
        insc(path.len()),
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
    historic_merkle_tree_insert_at(&field_path(index), leaf)
}

/// [`historic_merkle_tree_insert`] on a general path. The `insc` the plain
/// tree closed with is demoted to a LITERAL 1 (midnight-ledger.ss:1222) at
/// every depth; only the new closing `insc` tracks `len(f) + 1`.
pub fn historic_merkle_tree_insert_at(path: &[LedgerKey], leaf: &LedgerValue) -> Vec<ImpactOp> {
    let mut ops = merkle_tree_insert_at(path, leaf);
    let last = ops.len() - 1;
    ops[last] = ImpactOp::constant(&Op::Ins { cached: true, n: 1 });
    ops.extend(history_append());
    ops.push(ins1());
    ops.push(insc(path.len() + 1));
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
    historic_merkle_tree_insert_index_at(&field_path(index), leaf, at)
}

/// [`historic_merkle_tree_insert_index`] on a general path.
pub fn historic_merkle_tree_insert_index_at(
    path: &[LedgerKey],
    leaf: &LedgerValue,
    at: &LedgerValue,
) -> Vec<ImpactOp> {
    let mut ops = merkle_tree_insert_index_at(path, leaf, at);
    ops.pop();
    ops.extend(history_append());
    ops.push(ins1());
    ops.push(insc(path.len() + 1));
    ops
}

/// `hmt.resetHistory()` on field `index` (midnight-ledger.ss
/// HistoricMerkleTree `resetHistory`): replace the history with a one-entry
/// map holding the CURRENT root.
pub fn historic_merkle_tree_reset_history(index: u8) -> Vec<ImpactOp> {
    historic_merkle_tree_reset_history_at(&field_path(index))
}

/// [`historic_merkle_tree_reset_history`] on a general path — the ONE
/// operation whose closing depth is `len(f) + 2` (midnight-ledger.ss:1338).
pub fn historic_merkle_tree_reset_history_at(path: &[LedgerKey]) -> Vec<ImpactOp> {
    vec![
        idx_path(false, true, path),
        push_cell(false, &field_index_value(TREE_HISTORY)),
        ImpactOp::constant(&Op::Push {
            storage: true,
            value: empty_map(),
        }),
        dup(2),
        idx_one(false, false, TREE),
        ImpactOp::constant(&Op::Root),
        ImpactOp::constant(&Op::Push {
            storage: true,
            value: StateValue::Null,
        }),
        insc(path.len() + 2),
    ]
}

/// `hmt.resetToDefault()` on field `index` — the ONE `resetToDefault` that is
/// not three instructions, because the fresh history has to be seeded with
/// the blank tree's root.
pub fn historic_merkle_tree_reset(index: u8, depth: u8) -> Vec<ImpactOp> {
    historic_merkle_tree_reset_at(&field_path(index), depth)
}

/// [`historic_merkle_tree_reset`] on a general path — the ninth and last of
/// the whole-field-replace ops, and the one that open-codes the suppression
/// rather than going through [`reset_to_at`] because its closing pair is
/// `insc 2; ins 1` where every other reset's is `ins 1; insc len(f)-1`.
pub fn historic_merkle_tree_reset_at(path: &[LedgerKey], depth: u8) -> Vec<ImpactOp> {
    let initial = empty_historic_merkle_tree_value(depth);
    let mut ops = idxp_container(path);
    ops.push(path[path.len() - 1].push_as_cell());
    ops.push(ImpactOp::constant(&Op::Push {
        storage: true,
        value: initial,
    }));
    ops.extend(history_append());
    ops.push(ImpactOp::constant(&Op::Ins { cached: true, n: 2 }));
    ops.push(ins1());
    ops.extend(insc_container(path));
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
pub fn emit<V: Visibility + minocrab::OnChainGuard>(
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
pub fn mint_read_with<V: Visibility + Copy + minocrab::OnChainGuard>(
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
const U128_ATOM: AlignmentAtom = AlignmentAtom::Bytes { length: 16 };
const BOOL_ATOM: AlignmentAtom = AlignmentAtom::Bytes { length: 1 };

/// `Cell.read()` of the top-level field `index`
/// (midnight-ledger.ss:547-551): `dup 0; idx [field]; popeq` — both the idx
/// and the popeq uncached (`f-cached` = #f). `atoms` is the cell type's FAB
/// alignment; returns one wire per limb, in slot order.
pub fn cell_read<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
    atoms: Vec<AlignmentAtom>,
) -> Vec<Wire3<FieldT, Public>> {
    cell_read_at(c, guard, &field_path(index), atoms)
}

/// [`cell_read`] on a general path.
pub fn cell_read_at<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    path: &[LedgerKey],
    atoms: Vec<AlignmentAtom>,
) -> Vec<Wire3<FieldT, Public>> {
    let guard = guard.into();
    let (wires, value) = mint_read(c, atoms);
    cell_read_embedded_at(c, guard, path, &value);
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
pub fn cell_read_embedded<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
    value: &LedgerValue,
) {
    cell_read_embedded_at(c, guard, &field_path(index), value)
}

/// [`cell_read_embedded`] on a general path.
pub fn cell_read_embedded_at<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    path: &[LedgerKey],
    value: &LedgerValue,
) {
    emit(
        c,
        guard,
        &[dup(0), idx_path(false, false, path), popeq(false, value)],
    );
}

/// `Counter.read()` on field `index` (midnight-ledger.ss:590-594):
/// `dup 0; idx [field]; popeqc` — the popeq is cached even on the first
/// access (unlike Cell.read). Returns the u64 counter value.
pub fn counter_read<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
) -> Wire3<FieldT, Public> {
    counter_read_at(c, guard, &field_path(index))
}

/// [`counter_read`] on a general path.
pub fn counter_read_at<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    path: &[LedgerKey],
) -> Wire3<FieldT, Public> {
    let guard = guard.into();
    let (wires, value) = mint_read(c, vec![U64_ATOM]);
    emit(
        c,
        guard,
        &[dup(0), idx_path(false, false, path), popeq(true, &value)],
    );
    wires[0]
}

/// `Counter.lessThan(threshold)` (midnight-ledger.ss:595-600):
/// `dup 0; idx [field]; push threshold (u64 cell); lt; popeqc` → Boolean.
pub fn counter_less_than<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
    threshold: &LedgerValue,
) -> Wire3<FieldT, Public> {
    counter_less_than_at(c, guard, &field_path(index), threshold)
}

/// [`counter_less_than`] on a general path.
pub fn counter_less_than_at<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    path: &[LedgerKey],
    threshold: &LedgerValue,
) -> Wire3<FieldT, Public> {
    let guard = guard.into();
    let (wires, value) = mint_read(c, vec![BOOL_ATOM]);
    emit(
        c,
        guard,
        &[
            dup(0),
            idx_path(false, false, path),
            push_cell(false, threshold),
            ImpactOp::constant(&Op::Lt),
            popeq(true, &value),
        ],
    );
    wires[0]
}

/// `Map.member(key)` on field `index` (midnight-ledger.ss:649-655):
/// `dup 0; idx [field]; push key; member; popeqc` → Boolean.
pub fn map_member<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
    key: &LedgerValue,
) -> Wire3<FieldT, Public> {
    map_member_at(c, guard, &field_path(index), key)
}

/// [`map_member`] on a general path.
pub fn map_member_at<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    path: &[LedgerKey],
    key: &LedgerValue,
) -> Wire3<FieldT, Public> {
    let guard = guard.into();
    let (wires, value) = mint_read(c, vec![BOOL_ATOM]);
    emit(
        c,
        guard,
        &[
            dup(0),
            idx_path(false, false, path),
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
pub fn map_lookup<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
    key: &LedgerValue,
    value_atoms: Vec<AlignmentAtom>,
) -> Vec<Wire3<FieldT, Public>> {
    map_lookup_at(c, guard, &field_path(index), key, value_atoms)
}

/// [`map_lookup`] on a general path.
///
/// NOTE THE TWO `idx`: the path reaches the MAP, and the key descent is a
/// SECOND one-element `idx` (`(idx … [path (list key)])`,
/// midnight-ledger.ss:745-746). A leaf lookup does not append its key to
/// `f`; only an INTERMEDIATE `lookup` — the one whose result is another ADT —
/// does, and that one emits nothing at all.
pub fn map_lookup_at<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    path: &[LedgerKey],
    key: &LedgerValue,
    value_atoms: Vec<AlignmentAtom>,
) -> Vec<Wire3<FieldT, Public>> {
    let guard = guard.into();
    let (wires, value) = mint_read(c, value_atoms);
    emit(
        c,
        guard,
        &[
            dup(0),
            idx_path(false, false, path),
            idx_key(key),
            popeq(false, &value),
        ],
    );
    wires
}

/// `Map.size()` on field `index` (midnight-ledger.ss:728-733):
/// `dup 0; idx [field]; size; popeqc` → Uint64.
pub fn map_size<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
) -> Wire3<FieldT, Public> {
    map_size_at(c, guard, &field_path(index))
}

/// [`map_size`] on a general path.
pub fn map_size_at<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    path: &[LedgerKey],
) -> Wire3<FieldT, Public> {
    let guard = guard.into();
    let (wires, value) = mint_read(c, vec![U64_ATOM]);
    emit(
        c,
        guard,
        &[
            dup(0),
            idx_path(false, false, path),
            ImpactOp::constant(&Op::Size),
            popeq(true, &value),
        ],
    );
    wires[0]
}

/// `Map.isEmpty()` on field `index` (midnight-ledger.ss:720-727):
/// `dup 0; idx [field]; size; push 0 (u64 cell); eq; popeqc` → Boolean.
pub fn map_is_empty<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
) -> Wire3<FieldT, Public> {
    map_is_empty_at(c, guard, &field_path(index))
}

/// [`map_is_empty`] on a general path.
pub fn map_is_empty_at<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    path: &[LedgerKey],
) -> Wire3<FieldT, Public> {
    let guard = guard.into();
    let zero = LedgerValue::bytes(8, vec![ImpactElem::Imm(Fr::from(0u64))]);
    let (wires, value) = mint_read(c, vec![BOOL_ATOM]);
    emit(
        c,
        guard,
        &[
            dup(0),
            idx_path(false, false, path),
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
pub fn set_size<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
) -> Wire3<FieldT, Public> {
    map_size(c, guard, index)
}

/// [`set_size`] on a general path.
pub fn set_size_at<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    path: &[LedgerKey],
) -> Wire3<FieldT, Public> {
    map_size_at(c, guard, path)
}

/// See [`set_size`].
pub fn set_is_empty<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
) -> Wire3<FieldT, Public> {
    map_is_empty(c, guard, index)
}

/// [`set_is_empty`] on a general path.
pub fn set_is_empty_at<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    path: &[LedgerKey],
) -> Wire3<FieldT, Public> {
    map_is_empty_at(c, guard, path)
}

// --- List reads --------------------------------------------------------------

/// `list.length()` on field `index`: `dup 0; idx [field]; idx [2]; popeqc`
/// → Uint64. The length is a stored cell, not a computed `size`.
pub fn list_length<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
) -> Wire3<FieldT, Public> {
    list_length_at(c, guard, &field_path(index))
}

/// [`list_length`] on a general path.
pub fn list_length_at<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    path: &[LedgerKey],
) -> Wire3<FieldT, Public> {
    let guard = guard.into();
    let (wires, value) = mint_read(c, vec![U64_ATOM]);
    emit(
        c,
        guard,
        &[
            dup(0),
            idx_path(false, false, path),
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
pub fn list_is_empty<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
) -> Wire3<FieldT, Public> {
    list_is_empty_at(c, guard, &field_path(index))
}

/// [`list_is_empty`] on a general path.
pub fn list_is_empty_at<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    path: &[LedgerKey],
) -> Wire3<FieldT, Public> {
    let guard = guard.into();
    let (wires, value) = mint_read(c, vec![BOOL_ATOM]);
    emit(
        c,
        guard,
        &[
            dup(0),
            idx_path(false, false, path),
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
pub fn list_head<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
    elem_atoms: Vec<AlignmentAtom>,
) -> Vec<Wire3<FieldT, Public>> {
    list_head_at(c, guard, &field_path(index), elem_atoms)
}

/// [`list_head`] on a general path.
pub fn list_head_at<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    path: &[LedgerKey],
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
            idx_path(false, false, path),
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
pub fn merkle_tree_is_full<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
    depth: u8,
) -> Wire3<FieldT, Public> {
    merkle_tree_is_full_at(c, guard, &field_path(index), depth)
}

/// [`merkle_tree_is_full`] on a general path.
pub fn merkle_tree_is_full_at<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    path: &[LedgerKey],
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
            idx_path(false, false, path),
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
pub fn merkle_tree_check_root<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
    root: &LedgerValue,
) -> Wire3<FieldT, Public> {
    merkle_tree_check_root_at(c, guard, &field_path(index), root)
}

/// [`merkle_tree_check_root`] on a general path.
pub fn merkle_tree_check_root_at<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    path: &[LedgerKey],
    root: &LedgerValue,
) -> Wire3<FieldT, Public> {
    let guard = guard.into();
    let (wires, value) = mint_read(c, vec![BOOL_ATOM]);
    emit(
        c,
        guard,
        &[
            dup(0),
            idx_path(false, false, path),
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
pub fn historic_merkle_tree_check_root<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    index: u8,
    root: &LedgerValue,
) -> Wire3<FieldT, Public> {
    historic_merkle_tree_check_root_at(c, guard, &field_path(index), root)
}

/// [`historic_merkle_tree_check_root`] on a general path.
pub fn historic_merkle_tree_check_root_at<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    path: &[LedgerKey],
    root: &LedgerValue,
) -> Wire3<FieldT, Public> {
    let guard = guard.into();
    let (wires, value) = mint_read(c, vec![BOOL_ATOM]);
    emit(
        c,
        guard,
        &[
            dup(0),
            idx_path(false, false, path),
            idx_one(false, false, TREE_HISTORY),
            push_cell(false, root),
            ImpactOp::constant(&Op::Member),
            popeq(true, &value),
        ],
    );
    wires[0]
}

// --- the context reads: balances and block time -----------------------------
//
// Both read the CONTEXT (stack slot 2) rather than the contract's state, and
// both are `popeqc`. They are the two shapes of notes/kernel-tokens.org
// finding (c) that the crate did not already have.

/// Comparison tail of a balance read.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BalanceCmp {
    /// `kernel.balance(t)` — the balance itself, a `Uint<128>`.
    Value,
    /// `kernel.balanceLessThan(t, n)` — `balance < n`.
    LessThan,
    /// `kernel.balanceGreaterThan(t, n)` — `balance > n`.
    GreaterThan,
}

/// `kernel.balance*(token_type[, amount])` (midnight-ledger.ss:427-540).
///
/// One shape for all three: fetch the context's unshielded-balances map
/// (context\[5\]), yield `map[token_type]` or ZERO if the key is absent, then
/// compare or not.
///
/// ```text
/// dup 2; idxc [5]; dup 0; push token_type; member
/// branch 3;  pop; push 0u128; jmp 1
///            idxc [token_type]
/// [push amount; lt|gt]
/// popeqc
/// ```
///
/// The zero default is why `unshieldedBalance` on a token the contract has
/// never held is `0` rather than a failure. Note the balance is the one at
/// the START of execution — the effect accumulator's entries do not feed back
/// into it, which is the caveat Compact's own stdlib comment carries.
pub fn kernel_balance<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    token_type: &LedgerValue,
    cmp: BalanceCmp,
    amount: Option<&LedgerValue>,
) -> Wire3<FieldT, Public> {
    let guard = guard.into();
    let result_atom = if cmp == BalanceCmp::Value {
        U128_ATOM
    } else {
        BOOL_ATOM
    };
    let (wires, value) = mint_read(c, vec![result_atom]);
    let zero = LedgerValue::new(vec![U128_ATOM], vec![ImpactElem::Imm(Fr::from(0u64))]);
    // `greaterThan` pushes the amount BEFORE the lookup and ends with a bare
    // `lt`, which is how compactc turns `<` into `>` without a `gt` opcode —
    // the same trick `blockTimeGreaterThan` uses. Hence the leading push and
    // the `dup 3` in that arm.
    let greater = cmp == BalanceCmp::GreaterThan;
    let mut ops = Vec::new();
    if greater {
        ops.push(push_cell(false, amount.expect("a comparison needs an amount")));
    }
    ops.extend([
        dup(if greater { 3 } else { 2 }),
        ImpactOp::constant(&Op::Idx {
            cached: true,
            push_path: false,
            path: vec![Key::Value(field_key(5))].into(),
        }),
        dup(0),
        push_cell(false, token_type),
        ImpactOp::constant(&Op::Member),
        ImpactOp::constant(&Op::Branch { skip: 3 }),
        ImpactOp::constant(&Op::Pop),
        push_cell(false, &zero),
        ImpactOp::constant(&Op::Jmp { skip: 1 }),
        idx_key_cached(token_type),
    ]);
    if cmp == BalanceCmp::LessThan {
        ops.push(push_cell(false, amount.expect("a comparison needs an amount")));
    }
    if cmp != BalanceCmp::Value {
        ops.push(ImpactOp::constant(&Op::Lt));
    }
    ops.push(popeq(true, &value));
    emit(c, guard, &ops);
    wires[0]
}

/// `idx` by a single dynamic key, CACHED — [`idx_key`]'s twin, and the shape
/// the balance lookup descends with.
pub fn idx_key_cached(key: &LedgerValue) -> ImpactOp {
    let mut elems = vec![ImpactElem::Imm(Fr::from(0x60u64))];
    elems.extend(alignment_header(&key.atoms));
    elems.extend(key.elems.iter().copied());
    ImpactOp(elems)
}

/// `kernel.blockTimeLessThan(t)` / `kernel.blockTimeGreaterThan(t)`
/// (midnight-ledger.ss:513-540): five instructions, and the two differ ONLY
/// in the order the operands reach `lt` — which is how a `<` becomes a `>`.
///
/// ```text
/// less than:    dup 2; idxc [2]; push t; lt; popeqc
/// greater than: push t; dup 3; idxc [2]; lt; popeqc
/// ```
///
/// The `dup 3` rather than `dup 2` in the greater-than form is the pushed `t`
/// sitting on the stack already.
pub fn kernel_block_time<V: Visibility + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: impl Into<Operand<FieldT, V>>,
    time: &LedgerValue,
    greater: bool,
) -> Wire3<FieldT, Public> {
    let guard = guard.into();
    let (wires, value) = mint_read(c, vec![BOOL_ATOM]);
    let block_time = ImpactOp::constant(&Op::Idx {
        cached: true,
        push_path: false,
        path: vec![Key::Value(field_key(2))].into(),
    });
    let ops = if greater {
        vec![
            push_cell(false, time),
            dup(3),
            block_time,
            ImpactOp::constant(&Op::Lt),
            popeq(true, &value),
        ]
    } else {
        vec![
            dup(2),
            block_time,
            push_cell(false, time),
            ImpactOp::constant(&Op::Lt),
            popeq(true, &value),
        ]
    };
    emit(c, guard, &ops);
    wires[0]
}

/// `kernel.self()` (midnight-ledger.ss:256-260): `dup 2` to reach the
/// context array, `idxc [0]` (cached, path not remembered), `popeqc` →
/// the contract's own address as `Bytes<32>` `[hi, lo]` wires.
pub fn kernel_self<V: Visibility + minocrab::OnChainGuard>(
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
pub fn cell_read_guarded<V: Visibility + Copy + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    index: u8,
    atoms: Vec<AlignmentAtom>,
) -> Vec<Wire3<FieldT, Public>> {
    cell_read_guarded_at(c, guard, &field_path(index), atoms)
}

/// [`cell_read_guarded`] on a general path.
pub fn cell_read_guarded_at<V: Visibility + Copy + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    path: &[LedgerKey],
    atoms: Vec<AlignmentAtom>,
) -> Vec<Wire3<FieldT, Public>> {
    let (wires, value) = mint_read_with(c, Some(guard), atoms);
    emit(
        c,
        guard,
        &[dup(0), idx_path(false, false, path), popeq(false, &value)],
    );
    wires
}

/// Guarded [`counter_read`].
pub fn counter_read_guarded<V: Visibility + Copy + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    index: u8,
) -> Wire3<FieldT, Public> {
    counter_read_guarded_at(c, guard, &field_path(index))
}

/// [`counter_read_guarded`] on a general path.
pub fn counter_read_guarded_at<V: Visibility + Copy + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    path: &[LedgerKey],
) -> Wire3<FieldT, Public> {
    let (wires, value) = mint_read_with(c, Some(guard), vec![U64_ATOM]);
    emit(
        c,
        guard,
        &[dup(0), idx_path(false, false, path), popeq(true, &value)],
    );
    wires[0]
}

/// Guarded [`map_member`].
pub fn map_member_guarded<V: Visibility + Copy + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    index: u8,
    key: &LedgerValue,
) -> Wire3<FieldT, Public> {
    map_member_guarded_at(c, guard, &field_path(index), key)
}

/// [`map_member_guarded`] on a general path.
pub fn map_member_guarded_at<V: Visibility + Copy + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    path: &[LedgerKey],
    key: &LedgerValue,
) -> Wire3<FieldT, Public> {
    let (wires, value) = mint_read_with(c, Some(guard), vec![BOOL_ATOM]);
    emit(
        c,
        guard,
        &[
            dup(0),
            idx_path(false, false, path),
            push_cell(false, key),
            ImpactOp::constant(&Op::Member),
            popeq(true, &value),
        ],
    );
    wires[0]
}

/// Guarded [`map_lookup`].
pub fn map_lookup_guarded<V: Visibility + Copy + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    index: u8,
    key: &LedgerValue,
    value_atoms: Vec<AlignmentAtom>,
) -> Vec<Wire3<FieldT, Public>> {
    map_lookup_guarded_at(c, guard, &field_path(index), key, value_atoms)
}

/// [`map_lookup_guarded`] on a general path.
pub fn map_lookup_guarded_at<V: Visibility + Copy + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    path: &[LedgerKey],
    key: &LedgerValue,
    value_atoms: Vec<AlignmentAtom>,
) -> Vec<Wire3<FieldT, Public>> {
    let (wires, value) = mint_read_with(c, Some(guard), value_atoms);
    emit(
        c,
        guard,
        &[
            dup(0),
            idx_path(false, false, path),
            idx_key(key),
            popeq(false, &value),
        ],
    );
    wires
}

/// Guarded [`kernel_self`].
pub fn kernel_self_guarded<V: Visibility + Copy + minocrab::OnChainGuard>(
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
/// The EFFECT ACCUMULATOR, shared by five kernel operations
/// (notes/kernel-tokens.org finding (c)): `effects[slot][key] += amount`,
/// where a key not already present starts from zero.
///
/// ```text
/// swap 0; idxpc [slot]                       // reach the effects map
/// push key; dup 1; dup 1; member             // is the key there?
/// push amount; swap 0; neg; branch 4
///     dup 2; dup 2; idxc [stack]; add        // …if so, add what is there
/// insc 2; swap 0
/// ```
///
/// The `branch` is resolved on chain and the PI stream is identical on both
/// paths, so this costs the circuit nothing conditional. The five callers
/// differ ONLY in the slot, the key's type and the amount's width:
///
/// | operation | slot | key |
/// |---|---|---|
/// | `mintShielded` | 4 | `Bytes<32>` domain separator |
/// | `mintUnshielded` | 5 | `Bytes<32>` domain separator |
/// | `incUnshieldedInputs` | 6 | `TokenType` |
/// | `incUnshieldedOutputs` | 7 | `TokenType` |
/// | `claimUnshieldedCoinSpend` | 8 | `(TokenType, UnshieldedRecipient)` |
fn kernel_effect_add(slot: u8, key: &LedgerValue, amount: &LedgerValue) -> Vec<ImpactOp> {
    vec![
        ImpactOp::constant(&Op::Swap { n: 0 }),
        ImpactOp::constant(&Op::Idx {
            cached: true,
            push_path: true,
            path: vec![Key::Value(field_key(slot))].into(),
        }),
        push_cell(false, key),
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

/// `kernel.mintShielded(domain_sep, amount)` — `kernel_effect_add` at
/// effects\[4\]. This was the shape's only caller until M17 found it was five.
pub fn kernel_mint_shielded(domain_sep: &LedgerValue, amount: &LedgerValue) -> Vec<ImpactOp> {
    kernel_effect_add(4, domain_sep, amount)
}

/// `kernel.mintUnshielded(domain_sep, amount)` — effects\[5\], `Uint<64>`.
pub fn kernel_mint_unshielded(domain_sep: &LedgerValue, amount: &LedgerValue) -> Vec<ImpactOp> {
    kernel_effect_add(5, domain_sep, amount)
}

/// `kernel.incUnshieldedInputs(token_type, amount)` — effects\[6\],
/// `Uint<128>`. Called when RECEIVING an unshielded token.
pub fn kernel_inc_unshielded_inputs(
    token_type: &LedgerValue,
    amount: &LedgerValue,
) -> Vec<ImpactOp> {
    kernel_effect_add(6, token_type, amount)
}

/// `kernel.incUnshieldedOutputs(token_type, amount)` — effects\[7\],
/// `Uint<128>`. Called when SENDING one.
pub fn kernel_inc_unshielded_outputs(
    token_type: &LedgerValue,
    amount: &LedgerValue,
) -> Vec<ImpactOp> {
    kernel_effect_add(7, token_type, amount)
}

/// `kernel.claimUnshieldedCoinSpend(token_type, recipient, amount)` —
/// effects\[8\]. The key is the CONCATENATION of the token type and the
/// recipient, which is why the caller passes one `LedgerValue` of six atoms
/// rather than two of three.
pub fn kernel_claim_unshielded_coin_spend(
    token_and_recipient: &LedgerValue,
    amount: &LedgerValue,
) -> Vec<ImpactOp> {
    kernel_effect_add(8, token_and_recipient, amount)
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

/// `kernel.claimZswapNullifier(nul)` — effects\[0\].
pub fn kernel_claim_zswap_nullifier(nul: &LedgerValue) -> Vec<ImpactOp> {
    kernel_claim(0, nul)
}

/// `kernel.claimZswapCoinReceive(note)` — effects\[1\].
pub fn kernel_claim_zswap_coin_receive(note: &LedgerValue) -> Vec<ImpactOp> {
    kernel_claim(1, note)
}

/// `kernel.claimZswapCoinSpend(note)` — effects\[2\].
pub fn kernel_claim_zswap_coin_spend(note: &LedgerValue) -> Vec<ImpactOp> {
    kernel_claim(2, note)
}

/// `kernel.claimContractCall(addr, entry_point, comm)`
/// (midnight-ledger.ss:195-215): insert `size(claims) ‖ addr ‖ ep ‖ comm →
/// Null` into the claimed-contract-calls map at effects\[3\]. `addr_ep_comm`
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
pub fn contract_call<V: Visibility + Copy + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    addr: [Wire3<FieldT, Public>; 2],
    args: &[Wire3<FieldT, Public>],
    results: &[LimbConstraint],
) -> Vec<Wire3<FieldT, Public>> {
    // Every witness of the call is read UNDER THE CALL'S GUARD, as the op
    // that claims it is emitted under it: a call inside a branch consumes
    // the prover's cc-rand, entry-point limbs and results only where the
    // branch runs, or the private transcript shifts for everything after
    // it (the external review's §4.3; the same class the choke point closed
    // for the scope-based reads). Straight-line callers pass a constant
    // true, which lowers to compactc's own `guard: null`.
    let results: Vec<_> = results
        .iter()
        .map(|&constraint| {
            let w = c.witness_guarded::<FieldT, V>(guard);
            constraint.emit(c, w);
            w
        })
        .collect();
    let cc_rand = c.witness_guarded::<FieldT, V>(guard);
    let ep_hi = c.witness_guarded::<FieldT, V>(guard);
    c.assert_bits(ep_hi, 8);
    let ep_lo = c.witness_guarded::<FieldT, V>(guard);
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
    pub fn pin<V: Visibility + Copy + minocrab::OnChainGuard>(self, c: &mut Circuit3, guard: Wire3<FieldT, V>) -> Callee {
        Callee::Pinned(self.address(c, guard))
    }

    /// The address limbs — for [`Callee::Field`], the fresh uncached read.
    fn address<V: Visibility + Copy + minocrab::OnChainGuard>(
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
/// [`CircuitAbi::prims`](minocrab::v3::CircuitAbi::prims) run through
/// compactc's own table. A caller can no
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
pub fn call<A: CallArgs, R: CallResult, V: Visibility + Copy + minocrab::OnChainGuard>(
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
    /// swap = 0x40, idxpc effects\[3\] = [0x80,1,1,3], dup 0 = 0x30,
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

    /// A `bytes<32>` commitment and a 3-atom `ShieldedCoinInfo`, the two
    /// operands every coin arm takes.
    fn coin_operands() -> (LedgerValue, LedgerValue) {
        (
            LedgerValue::bytes(
                32,
                vec![ImpactElem::Imm(Fr::from(3u64)), ImpactElem::Imm(Fr::from(4u64))],
            ),
            LedgerValue::new(
                vec![
                    AlignmentAtom::Bytes { length: 32 },
                    AlignmentAtom::Bytes { length: 32 },
                    AlignmentAtom::Bytes { length: 16 },
                ],
                (5u64..10).map(|n| ImpactElem::Imm(Fr::from(n))).collect(),
            ),
        )
    }

    /// The six shared instructions, in the encodings all four arms embed:
    /// dup `n` = 0x30 | n, push cm, idxc [(1), stack] = [0x61, 1, 1, 1, −1],
    /// push coin (three atoms: 0x20, 0x20, 0x10), swap 0, concatc 91 =
    /// [0x17, 0x5b].
    fn assert_qualify_dance(ops: &[ImpactOp], dup_n: u64) {
        assert_eq!(imms(&ops[0]), repr(&Op::Dup { n: dup_n as u8 }));
        assert_eq!(imms(&ops[0]), vec![Fr::from(0x30u64 + dup_n)]);
        assert_eq!(
            imms(&ops[1])[..4],
            [Fr::from(0x10u64), 1u64.into(), 1u64.into(), 0x20u64.into()]
        );
        assert_eq!(
            imms(&ops[2]),
            repr(&Op::Idx {
                cached: true,
                push_path: false,
                path: vec![Key::Value(field_key(1)), Key::Stack].into(),
            })
        );
        assert_eq!(
            imms(&ops[2]),
            vec![
                Fr::from(0x61u64),
                1u64.into(),
                1u64.into(),
                1u64.into(),
                Fr::from(0u64) - Fr::from(1u64),
            ]
        );
        assert_eq!(
            imms(&ops[3])[..6],
            [
                Fr::from(0x10u64),
                1u64.into(),
                3u64.into(),
                0x20u64.into(),
                0x20u64.into(),
                0x10u64.into(),
            ]
        );
        assert_eq!(imms(&ops[4]), repr(&Op::Swap { n: 0 }));
        assert_eq!(imms(&ops[5]), vec![Fr::from(0x17u64), Fr::from(0x5bu64)]);
    }

    /// `set_insert_coin` against real Op encodings and the fixture's
    /// `setInsertCoin.zkir`: `idxp [field]` then the dance at `dup 4`
    /// (0x34), then `pushs null` (0x11 0x00), `ins 1` (0x91), `insc 1`
    /// (0xa1) — `set_insert`'s tail with the element push replaced.
    #[test]
    fn set_insert_coin_matches_field_repr() {
        use midnight_onchain_state::state::StateValue;

        let (cm, coin) = coin_operands();
        let ops = set_insert_coin(0, &cm, &coin);
        assert_eq!(ops.len(), 10);
        assert_eq!(
            imms(&ops[0]),
            vec![Fr::from(0x70u64), 1u64.into(), 1u64.into(), 0u64.into()]
        );
        assert_qualify_dance(&ops[1..7], 4);
        assert_eq!(
            imms(&ops[7]),
            repr(&Op::Push {
                storage: true,
                value: StateValue::Null,
            })
        );
        assert_eq!(imms(&ops[7]), vec![Fr::from(0x11u64), Fr::from(0u64)]);
        assert_eq!(imms(&ops[8]), vec![Fr::from(0x91u64)]);
        assert_eq!(imms(&ops[9]), vec![Fr::from(0xa1u64)]);
    }

    /// `map_insert_coin` against real Op encodings and the fixture's
    /// `mapInsertCoin.zkir`: the KEY push comes before the dance, which is
    /// why the reach is `dup 5` (0x35) and not the `Set`'s 4.
    #[test]
    fn map_insert_coin_matches_field_repr() {
        let (cm, coin) = coin_operands();
        let key = LedgerValue::bytes(
            32,
            vec![ImpactElem::Imm(Fr::from(1u64)), ImpactElem::Imm(Fr::from(2u64))],
        );
        let ops = map_insert_coin(1, &key, &cm, &coin);
        assert_eq!(ops.len(), 10);
        assert_eq!(
            imms(&ops[0]),
            vec![Fr::from(0x70u64), 1u64.into(), 1u64.into(), 1u64.into()]
        );
        assert_eq!(
            imms(&ops[1]),
            vec![
                Fr::from(0x10u64),
                1u64.into(),
                1u64.into(),
                0x20u64.into(),
                1u64.into(),
                2u64.into(),
            ]
        );
        assert_qualify_dance(&ops[2..8], 5);
        assert_eq!(imms(&ops[8]), vec![Fr::from(0x91u64)]);
        assert_eq!(imms(&ops[9]), vec![Fr::from(0xa1u64)]);
    }

    /// `list_push_front_coin` against real Op encodings and the fixture's
    /// `listPushFrontCoin.zkir`: eight instructions longer than
    /// [`list_push_front`], and the pushed node is BLANK — `[0x11, 0x33,
    /// 0x00, 0x00, 0x00]`, an `Array[3]` of three `Null`s — with the coin
    /// put at `node[0]` by the `insc 1` that closes the dance.
    #[test]
    fn list_push_front_coin_matches_field_repr() {
        let (cm, coin) = coin_operands();
        let ops = list_push_front_coin(2, &cm, &coin);
        let plain = list_push_front(2, &coin);
        assert_eq!(ops.len(), plain.len() + 8);

        // The head — identical to `pushFront`'s, up to the node push.
        for (i, (mine, twin)) in ops.iter().zip(&plain).take(4).enumerate() {
            assert_eq!(imms(mine), imms(twin), "instruction {i}");
        }
        assert_eq!(
            imms(&ops[4]),
            vec![
                Fr::from(0x11u64),
                Fr::from(0x33u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
            ]
        );
        // push 0u8 — the head slot the qualified coin is inserted at.
        assert_eq!(
            imms(&ops[5]),
            vec![Fr::from(0x10u64), 1u64.into(), 1u64.into(), 1u64.into(), 0u64.into()]
        );
        assert_qualify_dance(&ops[6..12], 7);
        assert_eq!(imms(&ops[12]), vec![Fr::from(0xa1u64)]);
        // …and the tail is `pushFront`'s, instruction for instruction.
        for (i, (mine, twin)) in ops[13..].iter().zip(&plain[5..]).enumerate() {
            assert_eq!(imms(mine), imms(twin), "tail instruction {i}");
        }
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

    // --- M22 stage B1: the general path -------------------------------------

    /// A `Bytes<32>` map key as both a real `AlignedValue` (for `Op`) and a
    /// [`LedgerValue`] (for ours), with the same limbs.
    fn b32_key() -> (AlignedValue, LedgerValue) {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x2a; // lo limb
        bytes[31] = 0x01; // hi byte
        let av = AlignedValue::new(
            Value(vec![ValueAtom(bytes.to_vec()).normalize()]),
            Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes {
                length: 32,
            })]),
        )
        .unwrap();
        let lv = LedgerValue::bytes(
            32,
            vec![
                ImpactElem::Imm(Fr::from(1u64)),
                ImpactElem::Imm(Fr::from(0x2au64)),
            ],
        );
        (av, lv)
    }

    /// EVERY [`LedgerKey`] variant encodes as upstream's `Key::field_repr`.
    ///
    /// This is the whole soundness claim of `LedgerKey`: the enum splits
    /// `Key::Value(AlignedValue)` into a const-known field index and a
    /// possibly-wire-bearing value, and adds nothing. If the split were
    /// wrong, every nested path would be wrong in the same way.
    #[test]
    fn key_encoding_matches_field_repr() {
        fn ours(key: &LedgerKey) -> Vec<Fr> {
            let mut out = Vec::new();
            key.push_elems(&mut out);
            out.into_iter()
                .map(|e| match e {
                    ImpactElem::Imm(f) => f,
                    ImpactElem::Wire(_) => panic!("expected constant"),
                })
                .collect()
        }
        fn real(key: &Key) -> Vec<Fr> {
            let mut out = Vec::new();
            key.field_repr(&mut out);
            out
        }

        for index in [0u8, 1, 7, 255] {
            assert_eq!(
                ours(&LedgerKey::Field(index)),
                real(&Key::Value(field_key(index))),
                "field {index}"
            );
        }
        let (av, lv) = b32_key();
        assert_eq!(ours(&LedgerKey::Value(lv)), real(&Key::Value(av)));
        assert_eq!(ours(&LedgerKey::Stack), real(&Key::Stack));
    }

    /// [`idx_path`] is `Op::Idx`'s encoding at every depth and in all four
    /// cached/pushPath corners — the opcode's low nibble is `len − 1`
    /// (ops.rs:510-524, reduce-to-zkir.ss:586-601).
    #[test]
    fn idx_path_matches_field_repr() {
        let (av, lv) = b32_key();
        let cases: Vec<(Vec<LedgerKey>, Vec<Key>)> = vec![
            (vec![LedgerKey::Field(3)], vec![Key::Value(field_key(3))]),
            (
                vec![LedgerKey::Field(0), LedgerKey::Value(lv.clone())],
                vec![Key::Value(field_key(0)), Key::Value(av.clone())],
            ),
            (
                vec![
                    LedgerKey::Field(6),
                    LedgerKey::Value(lv.clone()),
                    LedgerKey::Value(lv),
                ],
                vec![
                    Key::Value(field_key(6)),
                    Key::Value(av.clone()),
                    Key::Value(av),
                ],
            ),
            (
                vec![LedgerKey::Field(1), LedgerKey::Stack],
                vec![Key::Value(field_key(1)), Key::Stack],
            ),
        ];
        for (ours, theirs) in cases {
            for (cached, push_path) in [(false, false), (true, false), (false, true), (true, true)] {
                assert_eq!(
                    imms(&idx_path(cached, push_path, &ours)),
                    repr(&Op::Idx {
                        cached,
                        push_path,
                        path: theirs.clone().into(),
                    }),
                    "depth {} cached={cached} pushPath={push_path}",
                    ours.len()
                );
            }
        }
    }

    /// THE ADDITIVITY CLAIM, checked rather than asserted: every `u8` builder
    /// is its `_at` twin on the one-element path, byte for byte. This is what
    /// makes the widening free of movement for all 167 pre-existing circuits.
    #[test]
    fn the_u8_builders_are_the_one_element_path() {
        fn same(a: &[ImpactOp], b: &[ImpactOp], what: &str) {
            assert_eq!(a.len(), b.len(), "{what}: length");
            for (i, (x, y)) in a.iter().zip(b).enumerate() {
                assert_eq!(imms(x), imms(y), "{what}: op {i}");
            }
        }
        let (_, key) = b32_key();
        let one = [LedgerKey::Field(2)];
        same(&cell_write(2, &key), &cell_write_at(&one, &key), "cell_write");
        same(
            &counter_increment(2, 5),
            &counter_increment_at(&one, 5),
            "counter_increment",
        );
        same(
            &map_insert(2, &key, &key),
            &map_insert_at(&one, &key, &key),
            "map_insert",
        );
        same(&map_remove(2, &key), &map_remove_at(&one, &key), "map_remove");
        same(&set_insert(2, &key), &set_insert_at(&one, &key), "set_insert");
        same(&map_reset(2), &map_reset_at(&one), "map_reset");
        same(&list_reset(2), &list_reset_at(&one), "list_reset");
        same(
            &list_push_front(2, &key),
            &list_push_front_at(&one, &key),
            "list_push_front",
        );
        same(&list_pop_front(2), &list_pop_front_at(&one), "list_pop_front");
        same(
            &merkle_tree_insert(2, &key),
            &merkle_tree_insert_at(&one, &key),
            "merkle_tree_insert",
        );
        same(
            &merkle_tree_insert_index(2, &key, &key),
            &merkle_tree_insert_index_at(&one, &key, &key),
            "merkle_tree_insert_index",
        );
        same(
            &merkle_tree_reset(2, 8),
            &merkle_tree_reset_at(&one, 8),
            "merkle_tree_reset",
        );
        same(
            &historic_merkle_tree_insert(2, &key),
            &historic_merkle_tree_insert_at(&one, &key),
            "historic_merkle_tree_insert",
        );
        same(
            &historic_merkle_tree_insert_index(2, &key, &key),
            &historic_merkle_tree_insert_index_at(&one, &key, &key),
            "historic_merkle_tree_insert_index",
        );
        same(
            &historic_merkle_tree_reset_history(2),
            &historic_merkle_tree_reset_history_at(&one),
            "historic_merkle_tree_reset_history",
        );
        same(
            &historic_merkle_tree_reset(2, 8),
            &historic_merkle_tree_reset_at(&one, 8),
            "historic_merkle_tree_reset",
        );
        same(
            &cell_write_coin(2, &key, &key),
            &cell_write_coin_at(&one, &key, &key),
            "cell_write_coin",
        );
        same(
            &set_insert_coin(2, &key, &key),
            &set_insert_coin_at(&one, &key, &key),
            "set_insert_coin",
        );
        same(
            &map_insert_coin(2, &key, &key, &key),
            &map_insert_coin_at(&one, &key, &key, &key),
            "map_insert_coin",
        );
        same(
            &list_push_front_coin(2, &key, &key),
            &list_push_front_coin_at(&one, &key, &key),
            "list_push_front_coin",
        );
    }

    /// A two-element path against the stream compactc actually emits for
    /// `mm.lookup(k).insert(k2, v)` — the `0x71 … 0x91 0xa2` the note
    /// predicted from `ShieldedMultiSig`, decoded here from a probe compiled
    /// with the pinned compactc:
    ///
    /// ```text
    /// 0x71 [1,1,0] [1,-2,k]    idxp [field 0, k]
    /// 0x10 [1,1,-2,k2]         push k2
    /// 0x11 [1,1,8,7]           pushs (cell u64 7)
    /// 0x91                     ins 1
    /// 0xa2                     insc 2
    /// ```
    #[test]
    fn nested_map_insert_matches_compactc() {
        let key = LedgerValue::new(
            vec![AlignmentAtom::Field],
            vec![ImpactElem::Imm(Fr::from(11u64))],
        );
        let value = LedgerValue::bytes(8, vec![ImpactElem::Imm(Fr::from(7u64))]);
        let path = [LedgerKey::Field(0), LedgerKey::Value(key.clone())];
        let ops = map_insert_at(&path, &key, &value);
        assert_eq!(ops.len(), 5);
        let field = Fr::from(0u64) - Fr::from(2u64);
        assert_eq!(
            imms(&ops[0]),
            vec![
                Fr::from(0x71u64),
                1u64.into(),
                1u64.into(),
                0u64.into(),
                1u64.into(),
                field,
                11u64.into()
            ]
        );
        assert_eq!(
            imms(&ops[1]),
            vec![Fr::from(0x10u64), 1u64.into(), 1u64.into(), field, 11u64.into()]
        );
        assert_eq!(
            imms(&ops[2]),
            vec![Fr::from(0x11u64), 1u64.into(), 1u64.into(), 8u64.into(), 7u64.into()]
        );
        assert_eq!(imms(&ops[3]), vec![Fr::from(0x91u64)]);
        assert_eq!(imms(&ops[4]), vec![Fr::from(0xa2u64)]);
    }

    /// A THREE-element path: the opcode nibble and the closing `insc` both
    /// track `len(f)`, which is what a `Map<K, Map<K, Map<K, V>>>` write
    /// compiles to (`0x72 … 0xa3`).
    #[test]
    fn three_level_path_tracks_the_depth() {
        let key = LedgerValue::new(
            vec![AlignmentAtom::Field],
            vec![ImpactElem::Imm(Fr::from(3u64))],
        );
        let path = [
            LedgerKey::Field(6),
            LedgerKey::Value(key.clone()),
            LedgerKey::Value(key.clone()),
        ];
        let ops = map_insert_at(&path, &key, &key);
        assert_eq!(imms(&ops[0])[0], Fr::from(0x72u64));
        assert_eq!(imms(&ops[4]), vec![Fr::from(0xa3u64)]);
    }

    /// PATH SUPPRESSION, both halves, at the depth where they come alive.
    ///
    /// `map_reset(0)` is three instructions because `(suppress-null …)` and
    /// `(suppress-zero …)` both fire; `map_reset_at([field, k])` is FIVE —
    /// the `idxp [field 0]` and the `insc 1` reappear around the same middle.
    /// Verified against compactc's own `a.lookup(k).resetToDefault()`.
    #[test]
    fn reset_suppression_comes_alive_at_depth_two() {
        let key = LedgerValue::new(
            vec![AlignmentAtom::Field],
            vec![ImpactElem::Imm(Fr::from(11u64))],
        );
        let field = Fr::from(0u64) - Fr::from(2u64);

        let flat = map_reset(0);
        assert_eq!(flat.len(), 3);
        assert_eq!(imms(&flat[0])[0], Fr::from(0x10u64));

        let ops = map_reset_at(&[LedgerKey::Field(0), LedgerKey::Value(key)]);
        assert_eq!(ops.len(), 5);
        assert_eq!(
            imms(&ops[0]),
            vec![Fr::from(0x70u64), 1u64.into(), 1u64.into(), 0u64.into()]
        );
        assert_eq!(
            imms(&ops[1]),
            vec![Fr::from(0x10u64), 1u64.into(), 1u64.into(), field, 11u64.into()],
            "the LAST path element is what gets pushed, not the field index"
        );
        assert_eq!(imms(&ops[2]), vec![Fr::from(0x11u64), 2u64.into()]);
        assert_eq!(imms(&ops[3]), vec![Fr::from(0x91u64)]);
        assert_eq!(imms(&ops[4]), vec![Fr::from(0xa1u64)]);
    }

    /// The two op families whose closing depth is NOT `len(f)`:
    /// `List.pushFront` and `MerkleTree.insert` close at `len(f) + 1`, and
    /// `HistoricMerkleTree.resetHistory` at `len(f) + 2`.
    #[test]
    fn the_off_by_one_closings_track_the_depth() {
        let key = LedgerValue::new(
            vec![AlignmentAtom::Field],
            vec![ImpactElem::Imm(Fr::from(1u64))],
        );
        let path = [LedgerKey::Field(1), LedgerKey::Value(key.clone())];

        let push = list_push_front_at(&path, &key);
        assert_eq!(*imms(&push[push.len() - 1]).last().unwrap(), Fr::from(0xa3u64));
        let pop = list_pop_front_at(&path);
        assert_eq!(imms(&pop[pop.len() - 1]), vec![Fr::from(0xa2u64)]);

        let mt = merkle_tree_insert_at(&path, &key);
        assert_eq!(imms(&mt[mt.len() - 1]), vec![Fr::from(0xa3u64)]);
        let mti = merkle_tree_insert_index_at(&path, &key, &key);
        assert_eq!(imms(&mti[mti.len() - 1]), vec![Fr::from(0xa2u64)]);

        let hmt = historic_merkle_tree_insert_at(&path, &key);
        assert_eq!(imms(&hmt[hmt.len() - 1]), vec![Fr::from(0xa3u64)]);
        let hist = historic_merkle_tree_reset_history_at(&path);
        assert_eq!(imms(&hist[hist.len() - 1]), vec![Fr::from(0xa4u64)]);
    }

    /// A NESTED `Cell` WRITE, which Compact reaches by a route that has
    /// nothing to do with `Map` nesting.
    ///
    /// `determine-ledger-paths.ss` BATCHES a contract's ledger fields into
    /// segments of `maximum-ledger-segment-length` = 15 (langs.ss:851), so a
    /// contract with sixteen fields gives every field a TWO-element path and
    /// every top-level `Cell` write becomes a nested one. Compiled with the
    /// pinned compactc, a 16-field contract's `f0 = v` is
    ///
    /// ```text
    /// 0x70 [1,1,0]        idxp [segment 0]
    /// 0x10 [1,1,1,0]      push the field index
    /// 0x11 [1,1,8,v]      pushs v
    /// 0x91                ins 1
    /// 0xa1                insc 1
    /// ```
    ///
    /// and `f15 = v` is the same with `[1, 14]`. Both suppressions are live.
    /// No MinoCrab contract declares more than thirteen fields today, which
    /// is why nothing had noticed; the general path is the fix, and the
    /// derive's `at(index)` is what still has to learn it (stage B2).
    #[test]
    fn a_sixteen_field_contract_makes_every_cell_write_nested() {
        let v = LedgerValue::bytes(8, vec![ImpactElem::Imm(Fr::from(9u64))]);
        for (segment, index) in [(0u8, 0u8), (1, 14)] {
            let ops = cell_write_at(&[LedgerKey::Field(segment), LedgerKey::Field(index)], &v);
            assert_eq!(ops.len(), 5);
            assert_eq!(
                imms(&ops[0]),
                vec![
                    Fr::from(0x70u64),
                    1u64.into(),
                    1u64.into(),
                    u64::from(segment).into()
                ]
            );
            assert_eq!(
                imms(&ops[1]),
                vec![
                    Fr::from(0x10u64),
                    1u64.into(),
                    1u64.into(),
                    1u64.into(),
                    u64::from(index).into()
                ]
            );
            assert_eq!(
                imms(&ops[2]),
                vec![Fr::from(0x11u64), 1u64.into(), 1u64.into(), 8u64.into(), 9u64.into()]
            );
            assert_eq!(imms(&ops[3]), vec![Fr::from(0x91u64)]);
            assert_eq!(imms(&ops[4]), vec![Fr::from(0xa1u64)]);
        }
    }

    /// The four coin arms' `dup` reaches are compactc's formulas in `len(f)`,
    /// and they agree with stage A's four constants at depth 1.
    ///
    /// The depth-2 row is compactc's, not arithmetic: a probe declaring
    /// `Map<K, Set<QSCI>>`, `Map<K, Map<K, QSCI>>` and `Map<K, List<QSCI>>`
    /// compiles to `dup 6` / `dup 7` / `dup 9`.
    #[test]
    fn the_coin_reaches_are_compactcs_formulas() {
        assert_eq!(
            [
                cell_coin_dup(1),
                set_coin_dup(1),
                map_coin_dup(1),
                list_coin_dup(1)
            ],
            [3, 4, 5, 7],
            "stage A's CELL/SET/MAP/LIST_COIN_DUP"
        );
        assert_eq!(
            [
                cell_coin_dup(2),
                set_coin_dup(2),
                map_coin_dup(2),
                list_coin_dup(2)
            ],
            [5, 6, 7, 9]
        );
        let (_, key) = b32_key();
        let path = [LedgerKey::Field(0), LedgerKey::Value(key.clone())];
        // `dup 7` is the second instruction of a nested Map.insertCoin (after
        // the idxp and the key push it is the third).
        let ops = map_insert_coin_at(&path, &key, &key, &key);
        assert_eq!(imms(&ops[2]), vec![Fr::from(0x37u64)]);
    }

    /// AN ADT-VALUED `insertDefault` PUSHES THE ADT'S INITIAL VALUE, not a
    /// zero cell — `VMstate-value-ADT` discards the value and expands the
    /// ADT's `(initial-value …)` (reduce-to-zkir.ss:424-433). Against
    /// compactc's `a.insertDefault(k)` on `Map<Field, Map<Field, Uint<64>>>`,
    /// which emits `0x11 0x02` (the empty map) where the flat form emits
    /// `0x11 [1,1,8,0]`.
    #[test]
    fn adt_valued_insert_default_pushes_the_initial_value() {
        let key = LedgerValue::new(
            vec![AlignmentAtom::Field],
            vec![ImpactElem::Imm(Fr::from(11u64))],
        );
        let flat = map_insert_default_at(&field_path(0), &key, vec![U64_ATOM]);
        assert_eq!(
            imms(&flat[2]),
            vec![Fr::from(0x11u64), 1u64.into(), 1u64.into(), 8u64.into(), 0u64.into()]
        );

        let nested = map_insert_adt_default_at(&field_path(0), &key, empty_map());
        assert_eq!(imms(&nested[2]), vec![Fr::from(0x11u64), 2u64.into()]);
        assert_eq!(
            imms(&nested[2]),
            imms(&map_reset(0)[1]),
            "the initial value is the one resetToDefault writes"
        );

        let list = map_insert_adt_default_at(&field_path(1), &key, empty_list());
        assert_eq!(imms(&list[2]), imms(&list_reset(1)[1]));

        let counter = map_insert_adt_default_at(&field_path(2), &key, empty_counter());
        assert_eq!(
            imms(&counter[2]),
            vec![Fr::from(0x11u64), 1u64.into(), 1u64.into(), 8u64.into(), 0u64.into()]
        );
    }
}
