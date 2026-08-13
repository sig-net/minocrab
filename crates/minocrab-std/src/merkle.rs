//! Merkle tree path verification.
//!
//! Ports the Merkle-tree section of `standard-library.compact`, lowered as
//! compactc lowers it (notes/builtin-lowering.org §11, verified probe): the
//! fold is fully unrolled, the leaf hash is
//! `persistentHash<LeafPreimage<T>>` with domain separator `"mdn:lh"`
//! (`Bytes<6>`), and `degradeToTransient` of the digest is a zero-cost
//! rebinding of its low limb.

use minocrab::{AlignmentAtom, Circuit, Wire};

use crate::bundle::{Bundle, Vis};
use crate::hash::{degrade_to_transient, persistent_hash};
use crate::types::{Bool, Bytes32, BytesN};

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

    fn push_atoms(out: &mut Vec<AlignmentAtom>) {
        out.push(AlignmentAtom::Field);
    }
}

/// `struct MerkleTreePathEntry { sibling: MerkleTreeDigest; goes_left: Boolean; }`
#[derive(Clone, Copy)]
pub struct MerkleTreePathEntry<V: Vis> {
    pub sibling: MerkleTreeDigest<V>,
    pub goes_left: Bool<V>,
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
            goes_left: Bool::from_wires(wires),
        }
    }

    fn push_atoms(out: &mut Vec<AlignmentAtom>) {
        MerkleTreeDigest::<V>::push_atoms(out);
        Bool::<V>::push_atoms(out);
    }
}

/// `struct MerkleTreePath<#n, T> { leaf: T; path: Vector<n, MerkleTreePathEntry>; }`
/// (n is a runtime slice here; compactc unrolls the fold anyway.)
#[derive(Clone)]
pub struct MerkleTreePath<V: Vis, T: Bundle<V>> {
    pub leaf: T,
    pub path: Vec<MerkleTreePathEntry<V>>,
}

/// `struct LeafPreimage<T> { domain_sep: Bytes<6>, data: T }` — private in
/// the Compact stdlib; the domain separator is always `"mdn:lh"`.
struct LeafPreimage<V: Vis, T: Bundle<V>> {
    domain_sep: BytesN<V, 6>,
    data: T,
}

impl<V: Vis, T: Bundle<V>> Bundle<V> for LeafPreimage<V, T> {
    const WIDTH: usize = 1 + T::WIDTH;

    fn push_wires(&self, out: &mut Vec<Wire<V>>) {
        self.domain_sep.push_wires(out);
        self.data.push_wires(out);
    }

    fn from_wires(wires: &mut dyn Iterator<Item = Wire<V>>) -> Self {
        LeafPreimage {
            domain_sep: BytesN::from_wires(wires),
            data: T::from_wires(wires),
        }
    }

    fn push_atoms(out: &mut Vec<AlignmentAtom>) {
        BytesN::<V, 6>::push_atoms(out);
        T::push_atoms(out);
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
    let left = c.cond_select(entry.goes_left.0, recursive_digest, entry.sibling.field);
    let right = c.cond_select(entry.goes_left.0, entry.sibling.field, recursive_digest);
    c.transient_hash(&[left, right])
}

/// The fold shared by both root circuits: fold the path entries over an
/// already-degraded leaf digest.
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

/// `circuit merkleTreePathRoot<#n, T>(path: MerkleTreePath<n, T>): MerkleTreeDigest`
pub fn merkle_tree_path_root<V: Vis, T: Bundle<V>>(
    c: &mut Circuit,
    path: &MerkleTreePath<V, T>,
) -> MerkleTreeDigest<V>
where
    T: Clone,
{
    let domain_sep = BytesN::literal(c, b"mdn:lh");
    let preimage = LeafPreimage {
        domain_sep,
        data: path.leaf.clone(),
    };
    let digest = persistent_hash(c, &preimage);
    let leaf_digest = degrade_to_transient(&digest);
    merkle_tree_path_root_from_leaf_digest(c, leaf_digest, &path.path)
}

/// `circuit merkleTreePathRootNoLeafHash<#n>(path: MerkleTreePath<n, Bytes<32>>)`
pub fn merkle_tree_path_root_no_leaf_hash<V: Vis>(
    c: &mut Circuit,
    path: &MerkleTreePath<V, Bytes32<V>>,
) -> MerkleTreeDigest<V> {
    let leaf_digest = degrade_to_transient(&path.leaf);
    merkle_tree_path_root_from_leaf_digest(c, leaf_digest, &path.path)
}
