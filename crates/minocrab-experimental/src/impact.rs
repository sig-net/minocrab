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
//! - NOTHING CHECKS THE LAYOUT. A typed slot writes its field index with its
//!   declared type's alignment. A raw op takes a field index and a
//!   [`raw::LedgerValue`] separately, and nothing checks that the value has
//!   the layout the field was declared with.
//!
//! What still applies, raw or typed:
//!
//! - THE STALE-READ CHECK: [`raw::emit`] runs the value a cell write, a map
//!   insert or a list push stores through `Circuit3::refuse_stale`, which
//!   refuses at build time a value computed from an inline ledger read that
//!   was not acknowledged with `.stale(c)` (or with
//!   `Circuit3::acknowledge_stale` on the wires a raw read returned), naming
//!   the read. It is the check a typed slot's write gets, made in the same
//!   place, so it covers the same values: keys are not checked, nor ops that
//!   store no author value (counters, the coin arms, a Merkle-tree leaf,
//!   kernel claims, events). The value a typed Merkle-tree `insert` checks,
//!   its item, is hashed before it reaches an op, so a raw leaf is not
//!   checked; nor is an op composed by hand from `minocrab_ledger::push_cell`
//!   instead of taken from a write builder.
//! - DISCLOSURE: every element of an Impact op is a public wire (an
//!   [`raw::ImpactElem::Wire`] is a `Wire3<FieldT, Public>`), and each one
//!   is recorded in the circuit's disclosure record.
//! - THE GUARD: [`raw::emit`] resolves the ambient guard, so an op emitted
//!   inside `c.when(…)` carries that scope's condition, and one emitted
//!   inside `c.when_private(…)` is refused at build time.

pub mod raw;
