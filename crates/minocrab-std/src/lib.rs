//! L3 — the MinoCrab standard library.
//!
//! Ports of Compact's `standard-library.compact` (and, for ZKIR v3 targets,
//! `zkir-v3-library.compact`), expressed against the L2 eDSL. Translation is
//! mechanical from Midnight's sources (corpus/src/compact/compiler/), with
//! the lowering recipes pinned in notes/builtin-lowering.org; each ported
//! item is differential-tested against compactc's compilation of the
//! original.
//!
//! Values above single field elements are [`bundle::Bundle`]s: fixed-width
//! groups of same-visibility wires flattened in declaration order, paired
//! with the type's FAB alignment atoms — exactly compactc's
//! flatten-datatypes view of Compact values.
//!
//! Not yet here: the `kernel.*`-calling circuits (mint/send/receive/claim,
//! blockTime*, unshieldedBalance*) — they need ledger-op emission in the
//! eDSL (notes/ledger-abi.org) — and the ZKIR v3-only pieces
//! (`secp256k1EcdsaVerify`, `secp256k1EthereumAddress`, keccak256), which
//! land with the eDSL's v3 backend.

pub mod bundle;
pub mod coin;
pub mod data;
pub mod hash;
pub mod merkle;
pub mod schnorr;
pub mod types;

pub use bundle::{and, boolean, cond_select, default_bundle, eq, or, Bundle, Vis};
pub use coin::{
    coin_commitment, coin_nullifier, evolve_nonce, native_token, token_type, ContractAddress,
    QualifiedShieldedCoinInfo, ShieldedCoinInfo, UserAddress, ZswapCoinPublicKey,
};
pub use data::{left, none, right, some, Either, Maybe};
pub use hash::{
    degrade_to_transient, persistent_commit, persistent_hash, transient_commit, transient_hash,
    upgrade_from_transient,
};
pub use merkle::{
    merkle_tree_path_entry_root, merkle_tree_path_root, merkle_tree_path_root_from_leaf_digest,
    merkle_tree_path_root_no_leaf_hash, MerkleTreeDigest, MerkleTreePath, MerkleTreePathEntry,
};
pub use schnorr::{jubjub_schnorr_verify, JubjubSchnorrSignature};
pub use types::{str_as_field, Bool, Bytes32, BytesN, JubjubPoint, UintN, U128, U16, U32, U64, U8};
