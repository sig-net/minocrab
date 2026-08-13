//! Merkle tree path verification.
//!
//! Ports the Merkle-tree section of `standard-library.compact`. The leaf
//! hashing entry points (`merkleTreePathRoot` and the `NoLeafHash` variant)
//! need `persistentHash`/`degradeToTransient`, whose lowering recipes are
//! pending notes/builtin-lowering.org; what's here is the fold over path
//! entries, which is pure `transientHash` + selects.

use minocrab::{Circuit, Wire};

use crate::bundle::{Bundle, Vis};

/// `struct MerkleTreeDigest { field: Field; }`
#[derive(Clone, Copy)]
pub struct MerkleTreeDigest<V: Vis> {
    pub field: Wire<V>,
}

impl<V: Vis> Bundle<V> for MerkleTreeDigest<V> {
    const WIDTH: usize = 1;

    fn push_wires(&self, out: &mut Vec<Wire<V>>) {
        self.field.push_wires(out);
    }

    fn from_wires(wires: &mut dyn Iterator<Item = Wire<V>>) -> Self {
        MerkleTreeDigest {
            field: Wire::from_wires(wires),
        }
    }
}

/// `struct MerkleTreePathEntry { sibling: MerkleTreeDigest; goes_left: Boolean; }`
#[derive(Clone, Copy)]
pub struct MerkleTreePathEntry<V: Vis> {
    pub sibling: MerkleTreeDigest<V>,
    pub goes_left: Wire<V>,
}

impl<V: Vis> Bundle<V> for MerkleTreePathEntry<V> {
    const WIDTH: usize = 2;

    fn push_wires(&self, out: &mut Vec<Wire<V>>) {
        self.sibling.push_wires(out);
        self.goes_left.push_wires(out);
    }

    fn from_wires(wires: &mut dyn Iterator<Item = Wire<V>>) -> Self {
        MerkleTreePathEntry {
            sibling: MerkleTreeDigest::from_wires(wires),
            goes_left: Wire::from_wires(wires),
        }
    }
}

/// `circuit merkleTreePathEntryRoot(recursiveDigest: Field, entry): Field`
///
/// One fold step: hash this entry's sibling with the digest accumulated so
/// far, ordered by which side the path goes down.
pub fn merkle_tree_path_entry_root<V: Vis>(
    c: &mut Circuit,
    recursive_digest: Wire<V>,
    entry: &MerkleTreePathEntry<V>,
) -> Wire<V> {
    let left = c.cond_select(entry.goes_left, recursive_digest, entry.sibling.field);
    let right = c.cond_select(entry.goes_left, entry.sibling.field, recursive_digest);
    c.transient_hash(&[left, right])
}

/// The fold shared by `merkleTreePathRoot` and
/// `merkleTreePathRootNoLeafHash`: fold the path entries over an
/// already-degraded leaf digest. (The Compact originals differ only in how
/// they produce `leaf_digest` from the leaf value.)
pub fn merkle_tree_path_root_from_leaf_digest<V: Vis>(
    c: &mut Circuit,
    leaf_digest: Wire<V>,
    path: &[MerkleTreePathEntry<V>],
) -> MerkleTreeDigest<V> {
    let field = path.iter().fold(leaf_digest, |digest, entry| {
        merkle_tree_path_entry_root(c, digest, entry)
    });
    MerkleTreeDigest { field }
}
