//! The `erc20_vault_pending` reference model's Impact op builders, over the
//! Pending lineage's segmented 21-field ledger (`21 = 6 + 15`, remainder
//! leads, so field `i` is `[0, i]` for `i < 6` and `[1, i − 6]` otherwise;
//! notes/signet-async.org "Rung C, lending extension" has the shape,
//! confirmed instruction for instruction against the dumped `.zkir`).
//!
//! The builders themselves are `tests/support/ledger_ops.rs`, shared with
//! the flush vault's and the treasury's harnesses; this file sets the one
//! thing they differ by, the field count.

use super::prims::{atom, bytesn_value, cell, VmOp};

#[path = "../support/ledger_ops.rs"]
mod builders;
pub use builders::*;

/// The Pending lineage's field count.
///
/// Twenty-one since M44 rung D, where it was twenty-two: `Signet` lost its
/// request-nonce counter and its caip2 cell and gained `mpcKeyVersion`. The
/// count is not cosmetic — it sets the segmentation boundary, so one field
/// fewer moves every path in the block.
pub const FIELDS: u8 = 21;
