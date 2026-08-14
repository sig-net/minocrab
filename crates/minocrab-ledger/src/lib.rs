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
use minocrab::{Fr, Visibility};

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
}
