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
//! # v2 and v3
//!
//! The items at this crate's root target ZKIR v2, where values above a single
//! field element are [`bundle::Bundle`]s. **[`v3`] is the current surface**
//! and is where contract code lives: the `zkir-v3-library.compact` ports, the
//! typed leaves ([`v3::Uint`], [`v3::Bytes`], [`v3::B32`]), the ledger block,
//! the kernel ADT, Borsh, and the `secp256k1`/keccak circuits that exist only
//! on v3. Every contract in this workspace is v3.
//!
//! # Where this sits
//!
//! The top of the library stack: [`minocrab`] (L2) supplies the eDSL and
//! [`minocrab_ledger`] (L2.5) the Impact op emission that [`v3::LedgerMap`]
//! and [`v3::kernel`] wrap, and with the default `macros` feature the
//! `minocrab-macros` decorators are re-exported from here beside the traits
//! they implement. A contract crate normally depends on this crate alone, and
//! on `minocrab-sim` as a dev-dependency to run its circuits under
//! `cargo test`.
//!
//! # Start here
//!
//! - [`v3::Uint`], [`v3::Bytes`], [`v3::B32`], [`v3::Bool`] — the typed
//!   leaves; an argument's type *is* its range constraint
//! - [`v3::hash`] — the two hash flavors, always called module-qualified
//!   because which bytes get hashed is a decision
//! - [`v3::borsh`] — canonical Borsh over the fixed-width subset a circuit
//!   can emit
//! - [`v3::LedgerMap`], [`v3::LedgerCell`], [`v3::LedgerCounter`] — the
//!   ledger block as types, carrying Compact's own method names
//! - [`v3::kernel`] — mint/send/receive/claim, `blockTime*`,
//!   `unshieldedBalance*`
//! - [`macro@v3::circuit`] and [`macro@v3::CircuitArg`] — the decorators
//!   (default `macros` feature)

pub mod bundle;
pub mod coin;
pub mod data;
pub mod hash;
pub mod merkle;
pub mod schnorr;
pub mod types;
pub mod v3;

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
