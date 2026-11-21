//! Impact ledger operations written by hand.
//!
//! A contract normally touches the ledger through `minocrab-std`'s typed
//! slots (`LedgerCell`, `LedgerMap`, …), which lower to the same Impact ops
//! this module exposes. Writing the ops by hand is for an operation the
//! slots do not cover, or for a port that has to reproduce compactc's op
//! stream exactly.
//!
//! # What hand-written Impact gives up
//!
//! Relative to a typed slot:
//!
//! - THE STALE-READ CHECK IS NOT APPLIED to a raw write. A typed write runs
//!   the value it stores through `Circuit3::refuse_stale`, which refuses at
//!   build time a value computed from an inline ledger read that was not
//!   acknowledged with `.stale(c)`. [`raw::emit`] and the builders do not, so
//!   a raw write can store a value derived from a read the transaction
//!   assumes is still current at landing, without naming that assumption.
//! - NOTHING CHECKS THE LAYOUT. A typed slot writes its field index with its
//!   declared type's alignment. A raw op takes a field index and a
//!   [`raw::LedgerValue`] separately, and nothing checks that the value has
//!   the layout the field was declared with.
//!
//! What still applies, raw or typed:
//!
//! - DISCLOSURE: every element of an Impact op is a public wire (an
//!   [`raw::ImpactElem::Wire`] is a `Wire3<FieldT, Public>`), and each one
//!   is recorded in the circuit's disclosure record.
//! - THE GUARD: [`raw::emit`] resolves the ambient guard, so an op emitted
//!   inside `c.when(…)` carries that scope's condition, and one emitted
//!   inside `c.when_private(…)` is refused at build time.

pub mod raw;
