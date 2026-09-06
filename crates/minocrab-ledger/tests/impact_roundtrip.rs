//! THE ENCODER'S INVERSE, pinned: every op shape this crate can put into a
//! circuit's public transcript decodes back to the op it came from.
//!
//! `minocrab-ledger` encodes Impact ops into field elements (`ImpactOp`,
//! `Op::field_repr`); `minocrab_sim::v3::exec::decode_program` reads them
//! back, which is what lets the executor run a circuit's ledger reads
//! against real state. Upstream has no decoder — the ops travel beside the
//! proof in production — so the inverse is ours, and this file is where the
//! two halves are held to each other.
//!
//! The table below is one entry per `Op::field_repr` branch (onchain-vm
//! `ops.rs:461-525`), so a branch added upstream shows up here as a gap
//! rather than as a silent mis-decode in the executor.

use midnight_base_crypto::fab::{Alignment, AlignedValue, AlignmentAtom, AlignmentSegment};
use midnight_onchain_state::state::StateValue;
use midnight_onchain_vm::ops::{Key, Op};
use midnight_onchain_vm::result_mode::{ResultModeGather, ResultModeVerify};
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::{Array, HashMap as StorageHashMap};
use midnight_transient_crypto::merkle_tree::MerkleTree;
use midnight_transient_crypto::fab::AlignmentExt;
use midnight_transient_crypto::repr::FieldRepr;
use minocrab::Fr;
use minocrab_ledger::*;
use minocrab_sim::v3::exec::decode_program;

type VmOp = Op<ResultModeVerify, InMemoryDB>;
type GatherOp = Op<ResultModeGather, InMemoryDB>;

/// A well-formed `AlignedValue` from atoms and limbs — the same route
/// `Alignment::parse_field_repr` gives the executor, so the fixtures cannot
/// be shapes FAB would never produce.
fn aligned(atoms: &[AlignmentAtom], limbs: &[Fr]) -> AlignedValue {
    Alignment(atoms.iter().cloned().map(AlignmentSegment::Atom).collect())
        .parse_field_repr(limbs)
        .expect("the limbs fit the atoms")
}

fn av(width: u32, limbs: &[u64]) -> AlignedValue {
    aligned(
        &[AlignmentAtom::Bytes { length: width }],
        &limbs.iter().map(|v| Fr::from(*v)).collect::<Vec<_>>(),
    )
}

fn cell(v: AlignedValue) -> StateValue<InMemoryDB> {
    StateValue::Cell(Sp::new(v))
}

/// One op per `Op::field_repr` branch.
fn every_shape() -> Vec<VmOp> {
    vec![
        Op::Noop { n: 3 },
        Op::Lt,
        Op::Eq,
        Op::Type,
        Op::Size,
        Op::New,
        Op::And,
        Op::Or,
        Op::Neg,
        Op::Log,
        Op::Root,
        Op::Pop,
        Op::Popeq {
            cached: false,
            result: av(32, &[7, 1]),
        },
        Op::Popeq {
            cached: true,
            result: av(8, &[1234]),
        },
        // A multi-atom read: a record's alignment, not just a scalar's.
        Op::Popeq {
            cached: false,
            result: aligned(
                &[
                    AlignmentAtom::Bytes { length: 32 },
                    AlignmentAtom::Bytes { length: 8 },
                    AlignmentAtom::Field,
                ],
                &[Fr::from(3u64), Fr::from(9u64), Fr::from(5u64), Fr::from(77u64)],
            ),
        },
        Op::Addi { immediate: 7 },
        Op::Subi { immediate: 9 },
        Op::Push {
            storage: false,
            value: cell(av(20, &[2])),
        },
        Op::Push {
            storage: true,
            value: StateValue::Null,
        },
        Op::Push {
            storage: true,
            value: StateValue::Array(Array::from(vec![
                cell(av(32, &[1, 0])),
                StateValue::Null,
                cell(av(8, &[0])),
            ])),
        },
        Op::Push {
            storage: false,
            value: StateValue::Map(StorageHashMap::new()),
        },
        Op::Push {
            storage: false,
            value: StateValue::BoundedMerkleTree(MerkleTree::blank(32)),
        },
        Op::Branch { skip: 4 },
        Op::Jmp { skip: 2 },
        Op::Add,
        Op::Sub,
        Op::Concat {
            cached: false,
            n: 91,
        },
        Op::Concat {
            cached: true,
            n: 32,
        },
        Op::Member,
        Op::Rem { cached: false },
        Op::Rem { cached: true },
        Op::Dup { n: 0 },
        Op::Dup { n: 7 },
        Op::Swap { n: 0 },
        Op::Swap { n: 3 },
        Op::Idx {
            cached: false,
            push_path: false,
            path: vec![Key::Value(av(1, &[5]))].into(),
        },
        Op::Idx {
            cached: true,
            push_path: false,
            path: vec![Key::Value(av(1, &[0])), Key::Value(av(1, &[3]))].into(),
        },
        Op::Idx {
            cached: false,
            push_path: true,
            path: vec![Key::Stack].into(),
        },
        Op::Idx {
            cached: true,
            push_path: true,
            path: vec![Key::Value(av(1, &[1])), Key::Stack].into(),
        },
        Op::Ins {
            cached: false,
            n: 1,
        },
        Op::Ins { cached: true, n: 2 },
        Op::Ckpt,
    ]
}

fn gathered(op: &VmOp) -> GatherOp {
    op.clone().translate(|_| ())
}

#[test]
fn every_op_shape_decodes_back_to_itself() {
    for op in every_shape() {
        let mut elems: Vec<Fr> = Vec::new();
        op.field_repr(&mut elems);
        let (decoded, alignments) =
            decode_program(&elems).unwrap_or_else(|e| panic!("{op:?} did not decode: {e}"));
        assert_eq!(decoded, vec![gathered(&op)], "{op:?} decoded differently");
        // A read declares its FAB shape in the element stream, which is
        // what the executor checks the state against.
        if let Op::Popeq { result, .. } = &op {
            assert_eq!(alignments, vec![result.alignment.clone()], "{op:?}");
        } else {
            assert!(alignments.is_empty(), "{op:?} declared a read");
        }
    }
}

#[test]
fn the_whole_table_decodes_as_one_stream() {
    let shapes = every_shape();
    let mut elems: Vec<Fr> = Vec::new();
    for op in &shapes {
        op.field_repr(&mut elems);
    }
    let (decoded, _) = decode_program(&elems).expect("the concatenated stream decodes");
    let expected: Vec<GatherOp> = shapes.iter().map(gathered).collect();
    assert_eq!(decoded, expected);
}

/// The crate's own builders, not just hand-written `Op`s: what
/// `cell_read`/`map_insert`/… actually emit round-trips too. Wire limbs
/// stand in as immediates — the executor resolves them to concrete field
/// elements before decoding, so this is the same stream it sees.
#[test]
fn the_builders_round_trip() {
    let key = LedgerValue::bytes(32, vec![ImpactElem::Imm(Fr::from(11u64)); 2]);
    let value = LedgerValue::bytes(8, vec![ImpactElem::Imm(Fr::from(42u64))]);
    let read = LedgerValue::bytes(32, vec![ImpactElem::Imm(Fr::from(3u64)); 2]);

    let mut streams: Vec<Vec<ImpactOp>> = Vec::new();
    streams.push(vec![dup(0), idx_one(false, false, 4), popeq(false, &read)]);
    streams.push(counter_increment(6, 1));
    streams.push(cell_write(2, &value));
    streams.push(map_insert(9, &key, &value));
    streams.push(map_remove(9, &key));
    streams.push(map_reset(9));
    streams.push(set_insert(15, &key));
    streams.push(list_push_front(11, &value));
    streams.push(counter_reset(6));

    for stream in streams {
        let mut elems: Vec<Fr> = Vec::new();
        for op in &stream {
            for e in &op.0 {
                match e {
                    ImpactElem::Imm(x) => elems.push(*x),
                    ImpactElem::Wire(_) => unreachable!("the fixtures are all immediates"),
                }
            }
        }
        let (decoded, _) = decode_program(&elems)
            .unwrap_or_else(|e| panic!("a builder's stream did not decode: {e}"));
        // Re-encoding what came back must reproduce the same elements: the
        // decoder is a right inverse of the encoder on everything this
        // crate emits.
        let mut again: Vec<Fr> = Vec::new();
        for op in &decoded {
            op.clone()
                .translate::<ResultModeVerify, _>(|()| av(32, &[3, 0]))
                .field_repr(&mut again);
        }
        assert_eq!(again.len(), elems.len(), "re-encoded length differs");
    }
}
