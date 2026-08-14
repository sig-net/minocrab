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
use midnight_onchain_vm::ops::{Key, Op};
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::db::InMemoryDB;
use midnight_transient_crypto::repr::FieldRepr;
use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Fr, Public, Visibility};

pub use minocrab::v3::ImpactElem;

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

fn atom_limbs(atom: &AlignmentAtom) -> usize {
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

/// `idxp [field]`: uncached path-remembering fetch of a top-level field
/// (the shape compactc emits to reach any field it will write back).
pub fn idxp_field(index: u8) -> ImpactOp {
    ImpactOp::constant(&Op::Idx {
        cached: false,
        push_path: true,
        path: vec![Key::Value(field_key(index))].into(),
    })
}

/// `idx [field]`: uncached fetch of a top-level field WITHOUT remembering
/// the path — the read shape (nothing is written back).
pub fn idx_field(index: u8) -> ImpactOp {
    ImpactOp::constant(&Op::Idx {
        cached: false,
        push_path: false,
        path: vec![Key::Value(field_key(index))].into(),
    })
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

/// Emit `ops` as Impact instructions (one per op) under `guard`.
pub fn emit<V: Visibility>(c: &mut Circuit3, guard: Wire3<FieldT, V>, ops: &[ImpactOp])
where
    V: Visibility + Copy,
{
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
/// plus the same wires packaged for a `popeq[c]` embed.
fn mint_read(c: &mut Circuit3, atoms: Vec<AlignmentAtom>) -> (Vec<Wire3<FieldT, Public>>, LedgerValue) {
    let limbs: usize = atoms.iter().map(atom_limbs).sum();
    let wires: Vec<Wire3<FieldT, Public>> = (0..limbs)
        .map(|_| c.public_transcript_input::<FieldT>())
        .collect();
    let value = LedgerValue::new(atoms, wires.iter().map(|&w| ImpactElem::Wire(w)).collect());
    (wires, value)
}

const U64_ATOM: AlignmentAtom = AlignmentAtom::Bytes { length: 8 };
const BOOL_ATOM: AlignmentAtom = AlignmentAtom::Bytes { length: 1 };

/// `Cell.read()` of the top-level field `index`
/// (midnight-ledger.ss:547-551): `dup 0; idx [field]; popeq` — both the idx
/// and the popeq uncached (`f-cached` = #f). `atoms` is the cell type's FAB
/// alignment; returns one wire per limb, in slot order.
pub fn cell_read<V: Visibility + Copy>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    index: u8,
    atoms: Vec<AlignmentAtom>,
) -> Vec<Wire3<FieldT, Public>> {
    let (wires, value) = mint_read(c, atoms);
    emit(c, guard, &[dup(0), idx_field(index), popeq(false, &value)]);
    wires
}

/// `Counter.read()` on field `index` (midnight-ledger.ss:590-594):
/// `dup 0; idx [field]; popeqc` — the popeq is cached even on the first
/// access (unlike Cell.read). Returns the u64 counter value.
pub fn counter_read<V: Visibility + Copy>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    index: u8,
) -> Wire3<FieldT, Public> {
    let (wires, value) = mint_read(c, vec![U64_ATOM]);
    emit(c, guard, &[dup(0), idx_field(index), popeq(true, &value)]);
    wires[0]
}

/// `Counter.lessThan(threshold)` (midnight-ledger.ss:595-600):
/// `dup 0; idx [field]; push threshold (u64 cell); lt; popeqc` → Boolean.
pub fn counter_less_than<V: Visibility + Copy>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    index: u8,
    threshold: &LedgerValue,
) -> Wire3<FieldT, Public> {
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
pub fn map_member<V: Visibility + Copy>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    index: u8,
    key: &LedgerValue,
) -> Wire3<FieldT, Public> {
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
pub fn map_lookup<V: Visibility + Copy>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    index: u8,
    key: &LedgerValue,
    value_atoms: Vec<AlignmentAtom>,
) -> Vec<Wire3<FieldT, Public>> {
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
pub fn map_size<V: Visibility + Copy>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    index: u8,
) -> Wire3<FieldT, Public> {
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
pub fn map_is_empty<V: Visibility + Copy>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    index: u8,
) -> Wire3<FieldT, Public> {
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

/// `kernel.self()` (midnight-ledger.ss:256-260): `dup 2` to reach the
/// context array, `idxc [0]` (cached, path not remembered), `popeqc` →
/// the contract's own address as `Bytes<32>` `[hi, lo]` wires.
pub fn kernel_self<V: Visibility + Copy>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
) -> [Wire3<FieldT, Public>; 2] {
    let (wires, value) = mint_read(c, vec![AlignmentAtom::Bytes { length: 32 }]);
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
