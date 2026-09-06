//! The FAB primitives a signer call is built out of.
//!
//! Moved verbatim from `minocrab-contracts`' `tests/support/signet_call.rs`
//! (M29 rung C) so that the construction path is LIBRARY code a publisher
//! links, not test code a publisher would have to re-derive. The suites there
//! now call these.

use midnight_base_crypto::fab::{
    AlignedValue, Alignment, AlignmentAtom, AlignmentSegment, Value, ValueAtom,
};
use midnight_onchain_state::state::StateValue;
use midnight_storage::arena::Sp;
use midnight_storage::db::DB;
use midnight_transient_crypto::curve::Fr;

/// A `Bytes<n>` aligned value.
///
/// # Panics
///
/// If `bytes` does not fit a `Bytes<n>` atom — a fixed, statically known
/// layout at every call site in this crate (`Bytes<4>` for the event version,
/// `Bytes<1>` for the tag, `Bytes<288>` for the envelope), never a value the
/// caller supplies.
pub fn bytesn_value(n: u32, bytes: &[u8]) -> AlignedValue {
    AlignedValue::new(
        Value(vec![ValueAtom(bytes.to_vec()).normalize()]),
        Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes { length: n })]),
    )
    .expect("a Bytes<n> atom accepts n bytes")
}

/// A cell holding one aligned value.
pub fn cell<D: DB>(av: AlignedValue) -> StateValue<D> {
    StateValue::Cell(Sp::new(av))
}

/// A flat `[Field; n]` aligned value over `limbs`.
///
/// The ledger reads a call's `input` ONLY through
/// `AlignedValue::value_only_field_repr` — for the proof preimage's `inputs`
/// (via `ValueReprAlignedValue::field_vec`) and for the communication
/// commitment. The alignment itself never reaches the transaction, so an
/// argument list whose typed alignment is `[Bytes<32>, Bytes<1>, …]` and this
/// flat one produce the SAME preimage;
/// `minocrab-contracts`' `tests/signet_construction.rs::
/// the_alignment_does_not_reach_the_preimage` asserts that byte for byte.
pub fn scalar_input(limbs: &[Fr]) -> AlignedValue {
    AlignedValue::new(
        Value(limbs.iter().map(|f| ValueAtom(f.as_le_bytes().to_vec()).normalize()).collect()),
        Alignment(limbs.iter().map(|_| AlignmentSegment::Atom(AlignmentAtom::Field)).collect()),
    )
    .expect("a Field atom accepts a field element's LE bytes")
}
