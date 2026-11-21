//! The Impact primitives a contract author writes ledger operations with,
//! UNCHECKED.
//!
//! Re-exported from `minocrab-ledger` (and [`ImpactElem`] from `minocrab`)
//! unchanged: importing from here emits exactly what importing from there
//! does. The set is what the in-tree contracts write by hand, not the whole
//! op layer; an op builder joins when a contract needs it.
//!
//! WHAT IS NOT CHECKED. A write built here and emitted with [`emit`] is not
//! run through the stale-read check (`Circuit3::refuse_stale`): it can store
//! a value computed from an inline ledger read that was never acknowledged
//! with `.stale(c)`. Nor is anything checking that a field index is written
//! with its declared type's layout: the index and the [`LedgerValue`] are
//! separate arguments. The ports of Compact contracts use this form because
//! they reproduce compactc's op stream and its reads.
//!
//! WHAT STILL APPLIES. Every op element that is a wire is a public wire and
//! is recorded as a disclosure, and [`emit`] resolves the ambient guard of
//! `c.when(…)` (and refuses inside `c.when_private(…)`).

// --- the op, its elements, and emission --------------------------------------

/// One Impact instruction's element stream, and its emission under the
/// ambient guard.
pub use minocrab_ledger::{emit, ImpactOp};
/// The values and keys ops are built over.
pub use minocrab_ledger::{atom_limbs, LedgerKey, LedgerValue};
/// One element of an op: an inline constant, or a public wire.
pub use minocrab::v3::ImpactElem;

// --- reads --------------------------------------------------------------------

/// Witnessing a read by hand: mint the `public_input` gates, and the `popeq`
/// that embeds them. Name the minted wires for the stale-read backstop with
/// `Circuit3::label_reads`, as the whole reads below do, so a refusal can
/// say which read a value descends from.
pub use minocrab_ledger::{mint_read, popeq};
/// The stack and path primitives a hand-written read is built from.
pub use minocrab_ledger::{dup, idx_key, idx_path};
/// Whole reads, emitted at once: each mints, labels and emits.
pub use minocrab_ledger::{
    cell_read, counter_read, counter_read_at, list_head_at, list_is_empty_at, list_length_at,
    map_is_empty_at, map_lookup_at, map_member_at, map_size_at, merkle_tree_check_root_at,
};

// --- writes (each returns the ops; emit them) --------------------------------

/// Cells and counters.
pub use minocrab_ledger::{
    cell_write, cell_write_coin, counter_increment, counter_increment_at, counter_reset_at,
};
/// Maps and sets, and the initial state of a nested map.
pub use minocrab_ledger::{
    empty_map, map_insert, map_insert_adt_default_at, map_insert_at, map_insert_default_at,
    map_remove_at, map_reset_at, set_insert, set_insert_at, set_remove_at, set_reset_at,
};
/// Lists and Merkle trees.
pub use minocrab_ledger::{
    historic_merkle_tree_insert_at, historic_merkle_tree_reset_at,
    historic_merkle_tree_reset_history_at, list_pop_front_at, list_push_front_at, list_reset_at,
    merkle_tree_insert_at, merkle_tree_reset_at,
};

// --- events and the kernel ------------------------------------------------------

/// A contract event.
pub use minocrab_ledger::emit_event;
/// The shielded-coin kernel claims and the shielded mint.
pub use minocrab_ledger::{
    kernel_claim_zswap_coin_receive, kernel_claim_zswap_coin_spend, kernel_claim_zswap_nullifier,
    kernel_mint_shielded,
};
