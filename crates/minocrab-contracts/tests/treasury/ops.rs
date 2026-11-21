//! The treasury's Impact op builders, over a NARROW block.
//!
//! The treasury declares seven ledger fields (`Signet`'s five, then the
//! transfer slot's record and environment maps), which is under compactc's
//! fifteen-field segment length, so every path is ONE element and no write
//! is nested.
//!
//! The builders themselves are `tests/support/ledger_ops.rs`, shared with
//! the two vault harnesses; this file sets the one thing they differ by,
//! the field count.

use super::prims::{atom, bytesn_value, cell, VmOp};

#[path = "../support/ledger_ops.rs"]
mod builders;
pub use builders::*;

/// The treasury's field count — seven, so one segment and one-element paths.
pub const FIELDS: u8 = 7;
