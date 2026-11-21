//! # minocrab-experimental: no compatibility promise
//!
//! THIS CRATE IS PUBLISHED WITH NO BACKWARDS-COMPATIBILITY GUARANTEE. Any
//! release, a patch release included, may rename, change or remove any item
//! in it. It holds what is experimental, or an escape hatch beneath the
//! typed API of `minocrab-std`. No MinoCrab core crate depends on it, so its
//! churn cannot reach a stable crate. The version says the same thing: it is
//! 0.0.x, and under Cargo's semver rules every 0.0.x release is incompatible
//! with every other, so a dependency on it never moves to the next release
//! without being edited.
//!
//! # What is in it, and why not in `minocrab-std`
//!
//! | module | what | why it is here |
//! |---|---|---|
//! | [`impact`] | Impact ledger operations written by hand: the op builders and `emit` ([`impact::raw`]) | it bypasses the layout typing the typed slots make (see below) |
//!
//! [`impact`] is the escape hatch beneath `minocrab-std`'s typed ledger
//! slots. A typed slot knows its field index and its value's layout; an op
//! written by hand knows neither. Both kinds of write go through the
//! stale-read backstop, which [`minocrab_ledger::emit`] runs. The primitives themselves (`Circuit3::impact_mixed`,
//! [`minocrab_ledger::emit`] and the builders) stay public in the crates
//! they live in, because `minocrab-std` and `minocrab-compat` are other
//! crates and lower to them. What this crate gives a contract author is the
//! one place to import them from, with what they give up written down beside
//! them.

pub mod impact;
