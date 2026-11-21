//! The flush vault's Impact op builders, over its SEGMENTED 35-field
//! ledger: 35 fields = a leading remainder segment of five and two full
//! segments of fifteen, so field `i` lives at `[0, i]` for `i < 5`,
//! `[1, i − 5]` for `i < 20` and `[2, i − 20]` otherwise, and every
//! whole-field write is a NESTED write. The op shapes are transcribed from
//! the `375071b` artifacts (`initialise.zkir`, `startDeposit.zkir`,
//! `completeDeposit.zkir`, `flushQueue.zkir`); the differential suite pins
//! our lowering to them and the executor runs them against a real state.
//!
//! The builders themselves are `tests/support/ledger_ops.rs`, shared with
//! the Pending lineage's and the treasury's harnesses; this file sets the
//! one thing they differ by, the field count.

use super::prims::{atom, bytesn_value, cell, VmOp};

#[path = "../support/ledger_ops.rs"]
mod builders;
pub use builders::*;

/// The vault's field count.
pub const FIELDS: u8 = 35;
