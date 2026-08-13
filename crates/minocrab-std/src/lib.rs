//! L3 — the MinoCrab standard library.
//!
//! Ports of Compact's `standard-library.compact` (and, for ZKIR v3 targets,
//! `zkir-v3-library.compact`), expressed against the L2 eDSL. Translation is
//! mechanical from Midnight's sources (corpus/src/compact/compiler/); each
//! ported item is differential-tested against compactc's compilation of the
//! original.
//!
//! Values above single field elements (structs, vectors) are [`bundle::Bundle`]s:
//! fixed-width groups of same-visibility wires flattened in declaration
//! order, mirroring how compactc lays Compact values out over circuit memory.

pub mod bundle;
pub mod data;
pub mod merkle;

pub use bundle::{and, boolean, cond_select, default_bundle, eq, or, Bundle, Vis};
pub use data::{left, none, right, some, Either, Maybe};
pub use merkle::{
    merkle_tree_path_entry_root, merkle_tree_path_root_from_leaf_digest, MerkleTreeDigest,
    MerkleTreePathEntry,
};
