//! `insertIndexDefault` on the two Merkle-tree slots, as compactc lowers it.
//!
//! WHAT IS COMPACTC'S: the default leaf's digest, `persistentHash` of
//! `"mdn:lh"` and `T`'s all-zero FAB limbs, is hashed IN CIRCUIT with every
//! operand an inline constant, because compactc does not fold a
//! `persistentHash` over constants. THE LEAN FORM folds it to the two-limb
//! constant at build time, which saves the hash (one SHA-256 block is about
//! 1,885 rows, notes/op-costs.org).
//!
//! Built from the public parts std's own method is made of
//! ([`LedgerMerkleTree::insert_hash_index`] and
//! [`hash::persistent_hash_compact`]), so it emits the same instructions as
//! `minocrab_std`'s `insert_index_default` (pinned by this crate's tests).

use minocrab::{AnyWire, Circuit};
use minocrab::{Alignment, AlignmentAtom, AlignmentSegment, Fr, Public};
use minocrab_ledger::atom_limbs;
use minocrab_std::{
    hash, LedgerHistoricMerkleTree, LedgerMerkleTree, LedgerPath, LedgerRepr, Uint, B32,
};

/// A Merkle-tree slot that takes a known leaf digest at an index, and the
/// leaf type it holds: what [`insert_index_default`] needs from either tree
/// type.
pub trait IndexedTree {
    /// The tree's `T`, whose default value the leaf is.
    type Leaf: LedgerRepr;

    /// `t.insertHashIndex(hash, at)`.
    fn insert_hash_index(&self, c: &mut Circuit, hash: &B32<Public>, at: Uint<64, Public>);
}

impl<const DEPTH: u8, T: LedgerRepr, P: LedgerPath> IndexedTree for LedgerMerkleTree<DEPTH, T, P> {
    type Leaf = T;

    fn insert_hash_index(&self, c: &mut Circuit, hash: &B32<Public>, at: Uint<64, Public>) {
        LedgerMerkleTree::insert_hash_index(self, c, hash, at)
    }
}

impl<const DEPTH: u8, T: LedgerRepr, P: LedgerPath> IndexedTree for LedgerHistoricMerkleTree<DEPTH, T, P> {
    type Leaf = T;

    fn insert_hash_index(&self, c: &mut Circuit, hash: &B32<Public>, at: Uint<64, Public>) {
        LedgerHistoricMerkleTree::insert_hash_index(self, c, hash, at)
    }
}

/// `t.insertIndexDefault(at)`: insert the leaf type's DEFAULT value at `at`,
/// which is Compact's way of emulating a removal. The leaf is hashed in
/// circuit from inline constants (compactc's); the lean form inserts the
/// folded digest.
pub fn insert_index_default<S: IndexedTree>(c: &mut Circuit, tree: &S, at: Uint<64, Public>) {
    let hash = default_leaf_hash::<S::Leaf>(c);
    tree.insert_hash_index(c, &hash, at);
}

/// compactc's `rt-leaf-hash` of `T`'s DEFAULT value: all-zero limbs behind
/// the separator, every operand an inline immediate (compactc's
/// `insertIndexDefault` hashes `["0x6d646e3a6c68", "0x00", "0x00"]` with no
/// `copy` in sight).
fn default_leaf_hash<T: LedgerRepr>(c: &mut Circuit) -> B32<Public> {
    let atoms = T::atoms();
    let zeros = atoms.iter().map(atom_limbs).sum::<usize>();
    let mut segments = vec![AlignmentSegment::Atom(AlignmentAtom::Bytes { length: LEAF_HASH_DOMAIN_SEP.len() as u32 })];
    segments.extend(atoms.into_iter().map(AlignmentSegment::Atom));
    let mut slots = vec![AnyWire::immediate(Fr::from_le_bytes(LEAF_HASH_DOMAIN_SEP).expect("6 bytes fit"))];
    slots.extend(vec![AnyWire::immediate(0u64); zeros]);
    hash::persistent_hash_compact(c, Alignment(segments), &slots)
}

/// The domain separator of every Merkle leaf digest, in compactc and in
/// `minocrab_std::leaf_hash`.
const LEAF_HASH_DOMAIN_SEP: &[u8; 6] = b"mdn:lh";
