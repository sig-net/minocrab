//! The reference models' Impact op builders, over a compactc ledger block
//! of `super::FIELDS` fields.
//!
//! One body for the three harnesses that would otherwise carry a copy each
//! (`tests/vault/ops.rs`, 35 fields; `tests/vault_pending/ops.rs`, 21;
//! `tests/treasury/ops.rs`, 7). Each of those files sets its block's field
//! count and declares this file as a submodule by path:
//!
//! ```ignore
//! pub const FIELDS: u8 = 35;
//! #[path = "../support/ledger_ops.rs"]
//! mod builders;
//! pub use builders::*;
//! ```
//!
//! so it is not a module of `support` (it reads `FIELDS` and the FAB
//! helpers `atom`, `bytesn_value`, `cell`, `VmOp` from its parent). The
//! field count is what the copies differed by, and everything that depends
//! on it is derived from it here:
//!
//! - compactc batches a ledger block into segments of fifteen
//!   (`maximum-ledger-segment-length`, langs.ss:851;
//!   `determine-ledger-paths.ss`). A block within one segment has
//!   one-element paths (the bare declaration index) and no nested write; a
//!   wider block has two-element paths `[segment, offset]` with the
//!   remainder segment leading (`batch`), so 35 fields put the first
//!   `35 mod 15 = 5` in segment 0 and 21 fields the first 6.
//! - The closing `insc n` of a map insert, a set insert, a remove and a
//!   counter increment re-seats the container at every path element
//!   (minocrab-ledger `ops::map_insert`), so `n` is the path's length.
//!
//! Keys are anything [`MapKey`]: an `AlignedValue` as it is (the flush
//! vault keys its maps by `Uint<64>` index, `Bytes<32>` id and a
//! `Bytes<20>` set element), or a `&[u8; 32]` as a `Bytes<32>` (the Pending
//! lineage and the treasury key every map that way).
//!
//! Independent of `minocrab-ledger` on purpose: this is the oracle the
//! eDSL's `LedgerMap` / `LedgerSet` / `LedgerCell` / `LedgerCounter` /
//! `Pending` methods are checked against, so it must not be built from
//! them.
#![allow(dead_code)]

use midnight_base_crypto::fab::{Alignment, AlignmentAtom, AlignmentSegment, AlignedValue, Value, ValueAtom};
use midnight_onchain_state::state::StateValue;
use midnight_onchain_vm::ops::{Key, Op};
use midnight_transient_crypto::fab::ValueReprAlignedValue;
use midnight_transient_crypto::repr::FieldRepr;
use minocrab::Fr;

use super::{atom, bytesn_value, cell, VmOp, FIELDS};

/// compactc's segment length.
const SEGMENT: u8 = 15;

/// Whether the block is past one segment, so every path is two elements
/// and a whole-field write is nested.
pub const SEGMENTED: bool = FIELDS > SEGMENT;

/// A segmented field's `[segment, offset]`. The remainder segment leads
/// (`batch` in determine-ledger-paths.ss).
pub fn segment_of(field: u8) -> (u8, u8) {
    assert!(field < FIELDS, "field {field} is not one of the block's {FIELDS}");
    if !SEGMENTED {
        panic!("a block of {FIELDS} fields is one segment: its paths are the bare field index");
    }
    let lead = FIELDS % SEGMENT;
    if field < lead {
        (0, field)
    } else {
        (1 + (field - lead) / SEGMENT, (field - lead) % SEGMENT)
    }
}

fn key(i: u8) -> Key {
    Key::Value(bytesn_value(1, &[i]).try_into().expect("a canonical value"))
}

/// A field's path: `[segment, offset]` in a segmented block, `[field]`
/// otherwise.
pub fn field_path(field: u8) -> Vec<Key> {
    assert!(field < FIELDS, "field {field} is not one of the block's {FIELDS}");
    if SEGMENTED {
        let (seg, off) = segment_of(field);
        vec![key(seg), key(off)]
    } else {
        vec![key(field)]
    }
}

/// The closing `insc` of a write through `field`'s path: one per element.
fn depth(field: u8) -> u8 {
    u8::try_from(field_path(field).len()).expect("a path of one or two elements")
}

/// A map key or set element, as the `AlignedValue` the ledger stores.
pub trait MapKey {
    fn aligned(self) -> AlignedValue;
}

impl MapKey for AlignedValue {
    fn aligned(self) -> AlignedValue {
        self
    }
}

/// A `Bytes<32>` key.
impl MapKey for &[u8; 32] {
    fn aligned(self) -> AlignedValue {
        bytesn_value(32, self)
    }
}

/// A `Uint<64>` map key.
pub fn key_u64(i: u64) -> AlignedValue {
    bytesn_value(8, &i.to_le_bytes())
}

/// A `Bytes<32>` map key.
pub fn key32(k: &[u8; 32]) -> AlignedValue {
    bytesn_value(32, k)
}

/// A `Bytes<20>` set element.
pub fn key20(k: &[u8; 20]) -> AlignedValue {
    bytesn_value(20, k)
}

/// `field.read()` — `dup 0; idx f; popeq[c]`. Counters read cached
/// (`popeqc`), cells uncached (`popeq`).
pub fn read(field: u8, cached: bool, result: AlignedValue) -> Vec<VmOp> {
    vec![
        Op::Dup { n: 0 },
        Op::Idx {
            cached: false,
            push_path: false,
            path: field_path(field).into(),
        },
        Op::Popeq { cached, result },
    ]
}

/// `kernel.self()` — `dup 2; idxc [0]; popeqc` against the context.
pub fn kernel_self(addr: &[u8; 32]) -> Vec<VmOp> {
    vec![
        Op::Dup { n: 2 },
        Op::Idx {
            cached: true,
            push_path: false,
            path: vec![key(0)].into(),
        },
        Op::Popeq {
            cached: true,
            result: bytesn_value(32, addr),
        },
    ]
}

/// `map.member(key)` / `set.member(elem)` — `dup 0; idx f; push key; member; popeqc`.
pub fn member(field: u8, k: impl MapKey, result: bool) -> Vec<VmOp> {
    vec![
        Op::Dup { n: 0 },
        Op::Idx {
            cached: false,
            push_path: false,
            path: field_path(field).into(),
        },
        Op::Push {
            storage: false,
            value: cell(k.aligned()).try_into_checked().expect("a canonical value"),
        },
        Op::Member,
        Op::Popeq {
            cached: true,
            result: bytesn_value(1, &[u8::from(result)]),
        },
    ]
}

/// `map.lookup(key)` — `dup 0; idx f; idx [key]; popeq`.
pub fn lookup(field: u8, k: impl MapKey, result: AlignedValue) -> Vec<VmOp> {
    vec![
        Op::Dup { n: 0 },
        Op::Idx {
            cached: false,
            push_path: false,
            path: field_path(field).into(),
        },
        Op::Idx {
            cached: false,
            push_path: false,
            path: vec![Key::Value(k.aligned().try_into().expect("a canonical value"))].into(),
        },
        Op::Popeq { cached: false, result },
    ]
}

/// `map.insert(key, value)` — `idxp f; push key; pushs value; ins 1; insc len(f)`.
pub fn insert(field: u8, k: impl MapKey, value: AlignedValue) -> Vec<VmOp> {
    vec![
        Op::Idx {
            cached: false,
            push_path: true,
            path: field_path(field).into(),
        },
        Op::Push {
            storage: false,
            value: cell(k.aligned()).try_into_checked().expect("a canonical value"),
        },
        Op::Push {
            storage: true,
            value: cell(value).try_into_checked().expect("a canonical value"),
        },
        Op::Ins { cached: false, n: 1 },
        Op::Ins { cached: true, n: depth(field) },
    ]
}

/// `set.insert(elem)` — `idxp f; push elem; pushs null; ins 1; insc len(f)`.
pub fn set_insert(field: u8, elem: impl MapKey) -> Vec<VmOp> {
    vec![
        Op::Idx {
            cached: false,
            push_path: true,
            path: field_path(field).into(),
        },
        Op::Push {
            storage: false,
            value: cell(elem.aligned()).try_into_checked().expect("a canonical value"),
        },
        Op::Push {
            storage: true,
            value: StateValue::Null,
        },
        Op::Ins { cached: false, n: 1 },
        Op::Ins { cached: true, n: depth(field) },
    ]
}

/// `map.remove(key)` — `idxp f; push key; rem; insc len(f)`.
pub fn remove(field: u8, k: impl MapKey) -> Vec<VmOp> {
    vec![
        Op::Idx {
            cached: false,
            push_path: true,
            path: field_path(field).into(),
        },
        Op::Push {
            storage: false,
            value: cell(k.aligned()).try_into_checked().expect("a canonical value"),
        },
        Op::Rem { cached: false },
        Op::Ins { cached: true, n: depth(field) },
    ]
}

/// `counter.increment(1)` — `idxp f; addi 1; insc len(f)`.
pub fn counter_inc(field: u8) -> Vec<VmOp> {
    vec![
        Op::Idx {
            cached: false,
            push_path: true,
            path: field_path(field).into(),
        },
        Op::Addi { immediate: 1 },
        Op::Ins { cached: true, n: depth(field) },
    ]
}

/// `cell = value` — the nested whole-field write of a segmented block:
/// `idxp [segment]; push offset; pushs value; ins 1; insc 1`.
pub fn cell_write(field: u8, value: AlignedValue) -> Vec<VmOp> {
    let (seg, off) = segment_of(field);
    vec![
        Op::Idx {
            cached: false,
            push_path: true,
            path: vec![key(seg)].into(),
        },
        Op::Push {
            storage: false,
            value: cell(bytesn_value(1, &[off])).try_into_checked().expect("a canonical value"),
        },
        Op::Push {
            storage: true,
            value: cell(value).try_into_checked().expect("a canonical value"),
        },
        Op::Ins { cached: false, n: 1 },
        Op::Ins { cached: true, n: 1 },
    ]
}

/// One kernel claim into effects map `effect` (0 nullifiers, 1 receives, 2
/// spends): `swap 0; idxpc [effect]; push note; push null; insc 2; swap 0`.
pub fn claim(effect: u8, note: &[u8; 32]) -> Vec<VmOp> {
    vec![
        Op::Swap { n: 0 },
        Op::Idx {
            cached: true,
            push_path: true,
            path: vec![key(effect)].into(),
        },
        Op::Push {
            storage: false,
            value: cell(key32(note)).try_into_checked().expect("a canonical value"),
        },
        Op::Push {
            storage: false,
            value: StateValue::Null,
        },
        Op::Ins { cached: true, n: 2 },
        Op::Swap { n: 0 },
    ]
}

/// `kernel.mintShielded(domainSep, amount)` — effects map 4, the
/// add-or-insert on the colour's running total.
pub fn mint_shielded(domain_sep: &[u8; 32], amount: u64) -> Vec<VmOp> {
    vec![
        Op::Swap { n: 0 },
        Op::Idx {
            cached: true,
            push_path: true,
            path: vec![key(4)].into(),
        },
        Op::Push {
            storage: false,
            value: cell(key32(domain_sep)).try_into_checked().expect("a canonical value"),
        },
        Op::Dup { n: 1 },
        Op::Dup { n: 1 },
        Op::Member,
        Op::Push {
            storage: false,
            value: cell(bytesn_value(8, &amount.to_le_bytes())).try_into_checked().expect("a canonical value"),
        },
        Op::Swap { n: 0 },
        Op::Neg,
        Op::Branch { skip: 4 },
        Op::Dup { n: 2 },
        Op::Dup { n: 2 },
        Op::Idx {
            cached: true,
            push_path: false,
            path: vec![Key::Stack].into(),
        },
        Op::Add,
        Op::Ins { cached: true, n: 2 },
        Op::Swap { n: 0 },
    ]
}

/// The whole `mintShieldedToken` tail after its `kernel.self()` read:
/// the mint and the spend claim of the new coin's commitment.
pub fn mint_and_spend(domain_sep: &[u8; 32], amount: u64, cm: &[u8; 32]) -> Vec<VmOp> {
    let mut ops = mint_shielded(domain_sep, amount);
    ops.extend(claim(2, cm));
    ops
}

/// `kernel.claimContractCall(addr, ep, comm)` — effects map 3, appended
/// with its sequence number: `swap 0; idxpc [3]; dup 0; size; push (addr,
/// ep, comm); concatc 160; push null; insc 2; swap 0`.
pub fn claim_contract_call(addr: &[u8; 32], ep: &[u8; 32], comm: Fr) -> Vec<VmOp> {
    let mut comm_bytes = comm.as_le_bytes();
    while comm_bytes.last() == Some(&0) {
        comm_bytes.pop();
    }
    let addr_ep_comm = AlignedValue::new(
        Value(vec![
            ValueAtom(addr.to_vec()).normalize(),
            ValueAtom(ep.to_vec()).normalize(),
            ValueAtom(comm_bytes).normalize(),
        ]),
        Alignment(vec![atom(32), atom(32), AlignmentSegment::Atom(AlignmentAtom::Field)]),
    )
    .unwrap();
    vec![
        Op::Swap { n: 0 },
        Op::Idx {
            cached: true,
            push_path: true,
            path: vec![key(3)].into(),
        },
        Op::Dup { n: 0 },
        Op::Size,
        Op::Push {
            storage: false,
            value: cell(addr_ep_comm).try_into_checked().expect("a canonical value"),
        },
        Op::Concat { cached: true, n: 160 },
        Op::Push {
            storage: false,
            value: StateValue::Null,
        },
        Op::Ins { cached: true, n: 2 },
        Op::Swap { n: 0 },
    ]
}

/// The popeq results of an op stream, value-only, in read order — the
/// preimage's `public_transcript_outputs`. Derived from the ops rather than
/// listed beside them, so the two cannot disagree.
pub fn outputs_of(ops: &[VmOp]) -> Vec<Fr> {
    let mut out = Vec::new();
    for op in ops {
        if let Op::Popeq { result, .. } = op {
            ValueReprAlignedValue(result.clone()).field_repr(&mut out);
        }
    }
    out
}

/// `field_repr` of an op stream — the preimage's `public_transcript_inputs`.
pub fn transcript_of(ops: &[VmOp]) -> Vec<Fr> {
    let mut out = Vec::new();
    for op in ops {
        op.field_repr(&mut out);
    }
    out
}
