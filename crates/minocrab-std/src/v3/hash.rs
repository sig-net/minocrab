//! Hash FLAVORS: Borsh (the default) and Compact/FAB (interop only).
//!
//! A hash instruction does not hash a value — it hashes BYTES, and which
//! bytes a value becomes is a choice. There are exactly two answers in this
//! codebase and this module is where they are both spelled, side by side, so
//! that picking one is a decision a reader can see:
//!
//! | flavor | preimage | use it for |
//! |---|---|---|
//! | [`persistent_hash`] / [`transient_hash`] | the value's canonical **Borsh** encoding ([`CircuitBorsh`], the fixed-width subset) | everything you write yourself |
//! | [`persistent_hash_compact`] / [`transient_hash_compact`] | Compact's **FAB** representation — `binary_repr` for the persistent flavor, `field_repr` slots for the transient one | digest agreement with a Compact contract, and nothing else |
//!
//! # When `_compact` is needed — and when it is not
//!
//! ONLY at a Compact-interop boundary: a digest a Compact contract also
//! computes (so both sides must hash the same preimage), or a digest produced
//! off-chain by Compact-derived code. If the digest is one WE define — an
//! attestation preimage, a request id, a log payload, a commitment of our own
//! — the Borsh flavor is the one to use, because it is the one with a
//! specification (`spec/borsh-subset.md`) and a parser on every other side of
//! the wire.
//!
//! It is NOT needed for any of the following, which is most of what a
//! contract does (notes/borsh-format.org §"Stage 9"):
//!
//! - **Ledger maps and state.** Nothing there is hashed in-circuit: keys and
//!   values travel as typed limbs plus an alignment, and the storage-level
//!   keying is the ledger's own, off circuit.
//! - **The pinned protocol preimages** — `tokenType`, coin commitments and
//!   nullifiers, the entry-point hash, the cross-contract communications
//!   commitment, merkle interiors. Each already lives INSIDE its own stdlib
//!   or ledger wrapper, where the flavor is fixed by the protocol and
//!   invisible to the caller. (Those wrappers are the `_compact` flavor's
//!   real callers; they take it through this module so that the fact is
//!   greppable.)
//!
//! # The two flavors agree more often than they differ
//!
//! For a value whose FAB alignment is all `bytes<n>` atoms — which is every
//! type in the Borsh subset — `persistent_hash` and `persistent_hash_compact`
//! hash THE SAME BYTES: Compact's `binary_repr` of a sequence of `bytes<n>`
//! atoms is the plain concatenation of fixed-width little-endian fields,
//! which is Borsh's struct rule (notes/borsh-format.org, finding #1 —
//! measured against the deployed vault records and every attestation
//! preimage). `the_persistent_flavors_agree_on_the_subset` in
//! `tests/v3_borsh.rs` pins that as byte-identical ZKIR. The flavors part
//! company only where the alignment leaves the subset: `field` atoms (reduced
//! mod p, 32 bytes), `compress` atoms (hashed through `transient_commit`) and
//! FAB's option segments have no Borsh spelling at all.
//!
//! The TRANSIENT flavors differ in general, and the difference is not
//! cosmetic: Poseidon absorbs field elements, so the preimage is a LIMBING,
//! and the two limbings are different. Borsh limbs the encoded byte string in
//! 31-byte little-endian chunks IN STRING ORDER; FAB limbs each field
//! separately and puts a byte string's leftover chunk FIRST (`field_repr`'s
//! reversed-chunk rule — `BytesN`'s slot 0 is the most significant chunk).
//! `the_transient_flavors_disagree` pins that they are genuinely different
//! digests, so that choosing between them is a real choice.

use minocrab::v3::{AnyWire3, Circuit3, FieldT, Wire3};
use minocrab::Alignment;

use super::borsh::{limbs_of, CircuitBorsh};
use super::{Serializer, Vis3, B32};

/// `persistentHash` (SHA-256) of the value's canonical Borsh encoding — the
/// DEFAULT flavor, and the free one.
///
/// The preimage is described by [`CircuitBorsh::push_limbs`], which emits no
/// instruction at all: the alignment atoms ARE the Borsh field widths, so the
/// hash chip packs the bytes in-chip and its per-limb byte decomposition is
/// what makes the encoding injective. The digest is therefore
/// `SHA-256(borsh::to_vec(value))`, for zero rows over the hash itself
/// (`persistent_hash_is_sha256_of_the_borsh_encoding` proves the equality
/// through the simulator, against borsh's own encoder).
///
/// PRECONDITION, as everywhere in the Borsh layer: the value's leaves are
/// already range-constrained — by their argument constraints, by
/// [`CircuitBorsh::constrain_canonical`], or by the instruction that produced
/// them. Without that the packing is not injective and the digest binds
/// nothing.
pub fn persistent_hash<V: Vis3, T: CircuitBorsh<V>>(c: &mut Circuit3, value: &T) -> B32<V> {
    let digest = limbs_of(value).persistent_hash(c);
    B32::from_typed(c, digest)
}

/// `persistentHash` (SHA-256) of Compact's FAB `binary_repr` — the
/// INTEROP flavor.
///
/// `alignment` is the FAB alignment of the preimage and `slots` its
/// `field_repr` slots, in FAB order: exactly the two operands the Compact
/// compiler emits, and exactly what a Compact contract computing the same
/// digest will use. Reach for it only when a Compact contract (or
/// Compact-derived off-chain code) computes the same digest — see the module
/// docs for the list of things that do NOT need it.
///
/// This is a thin, deliberate wrapper over [`Circuit3::persistent_hash`] plus
/// the `[hi, lo]` split every Compact `Bytes<32>` value carries: it names the
/// flavor at the call site and costs the same instructions the raw call did.
pub fn persistent_hash_compact<V: Vis3>(
    c: &mut Circuit3,
    alignment: Alignment,
    slots: &[AnyWire3<V>],
) -> B32<V> {
    let digest = c.persistent_hash(alignment, slots);
    B32::from_typed(c, digest)
}

/// `transientHash` (Poseidon) over the value's canonical Borsh encoding,
/// limbed in 31-byte little-endian chunks IN STRING ORDER — the DEFAULT
/// flavor.
///
/// Unlike [`persistent_hash`] this one is NOT free: Poseidon absorbs field
/// elements, not bytes, so the encoding has to be materialised and that is
/// the M7 segment packing (one `div_mod` per 31-byte output-limb boundary a
/// field straddles). Where a value is only going to be hashed and the hash
/// may be SHA-256, [`persistent_hash`] is strictly cheaper.
///
/// The limbing is the plain one — chunk `i` is bytes `31i .. 31i+31` as a
/// little-endian field element, the last chunk short — so a native
/// implementation is `borsh::to_vec(v).chunks(31).map(Fr::from_le_bytes)`,
/// which is what `transient_hash_limbs_the_borsh_bytes_in_string_order`
/// checks against. NOT the FAB limbing, whose leftover chunk comes first.
///
/// Same precondition as [`persistent_hash`]: the leaves are already
/// range-constrained (the [`Serializer`]'s own precondition).
pub fn transient_hash<V: Vis3, T: CircuitBorsh<V>>(
    c: &mut Circuit3,
    value: &T,
) -> Wire3<FieldT, V> {
    let mut out = Serializer::new();
    value.push_segments(&mut out);
    let packed = out.finish_dyn(c, T::LEN);
    // `BytesNDyn` keeps FAB slot order (leftover chunk first); the Borsh
    // limbing is that string-order, so the absorb order is the reverse.
    let mut limbs = packed.limbs;
    limbs.reverse();
    c.transient_hash(&limbs)
}

/// `transientHash` (Poseidon) over Compact's FAB `field_repr` slots — the
/// INTEROP flavor, and Compact's `transientHash<T>(value)` exactly.
///
/// `slots` are the value's flattened FAB slots in declaration order, which
/// for a byte string means its limbs in SLOT order (leftover chunk first —
/// the reversed-chunk rule). Same rule as the persistent flavor for when to
/// use it: only where a Compact contract computes the same digest.
pub fn transient_hash_compact<V: Vis3>(
    c: &mut Circuit3,
    slots: &[Wire3<FieldT, V>],
) -> Wire3<FieldT, V> {
    c.transient_hash(slots)
}
