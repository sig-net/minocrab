//! Hash FLAVORS: Borsh (the default) and Compact/FAB (interop only).
//!
//! A hash instruction does not hash a value — it hashes BYTES, and which
//! bytes a value becomes is a choice. There are exactly two answers in this
//! codebase and this module is where they are both spelled, side by side, so
//! that picking one is a decision a reader can see:
//!
//! | flavor | preimage | use it for |
//! |---|---|---|
//! | [`persistent_hash`](crate::v3::hash::persistent_hash) / [`transient_hash`](crate::v3::hash::transient_hash) | the value's canonical **Borsh** encoding ([`CircuitBorsh`](crate::v3::borsh::CircuitBorsh), the fixed-width subset) | everything you write yourself |
//! | [`persistent_hash_compact`](crate::v3::hash::persistent_hash_compact) / [`transient_hash_compact`](crate::v3::hash::transient_hash_compact) | Compact's **FAB** representation — `binary_repr` for the persistent flavor, `field_repr` slots for the transient one | digest agreement with a Compact contract, and nothing else |
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

use midnight_base_crypto::repr::BinaryHashRepr;
use midnight_transient_crypto::fab::{AlignmentExt, ValueReprAlignedValue};
use minocrab::{AlignmentAtom, AlignmentSegment, Fr};
use sha2::{Digest, Sha256};

use super::borsh::{limbs_of, CircuitBorsh};
use super::{BytesN, Serializer, Uint, Vis3, B32};

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
///
/// HOW TO DISCHARGE IT RATHER THAN ASSUME IT: call
/// [`CircuitBorsh::constrain_canonical`] on the value here, at the hash,
/// where the obligation actually lives. That is a re-constraint of leaves a
/// caller has usually already constrained, which is why it was written as a
/// precondition instead — and with `Circuit3::dedup_range_constraints` on it
/// costs nothing, because the duplicate constraints are exactly what the
/// pass removes (`tests/v3_dedup.rs`; notes/ir-passes.org §11). There is no
/// checked twin of this function because there is nothing to wrap: the check
/// is one call the caller can already make.
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
/// Same precondition as [`persistent_hash`], and discharged the same way:
/// the leaves are already range-constrained (the [`Serializer`]'s own
/// precondition — this builds an unconstrained one, so
/// [`CircuitBorsh::constrain_canonical`] plus the dedup flag is the checked
/// path here too).
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

/// `degradeToTransient(b)`: the low limb (bytes 0..30 little-endian; byte 31
/// is DISCARDED), as a field element fit to absorb into a Poseidon hash.
///
/// The lossy direction, and deliberately so — a `Bytes<32>` does not fit a
/// 255-bit field, so the pair `[degrade, upgrade]` is not a round trip and
/// nothing should treat it as one.
///
/// One `Copy`, which is zero rows and is compactc's own shape for a cast
/// (`kernel.compact`'s `sMergeCoin`: `copy %t.23 = %a.1` before the
/// `transient_hash`).
pub fn degrade_to_transient<V: Vis3>(c: &mut Circuit3, b: &B32<V>) -> Wire3<FieldT, V> {
    c.copy(b.lo)
}

/// `upgradeFromTransient(f)`: the field element's low 31 bytes as a
/// `Bytes<32>` whose byte 31 is zero — `div_mod_power_of_two(f, 248)` keeping
/// the remainder, and a literal `0` for the high limb.
///
/// The high limb is emitted FIRST, which is compactc's order (`copy 0x00`,
/// then the `div_mod`), and it is a named `Copy` rather than an inline
/// immediate because it is a VALUE: it goes on to be a struct field, a hash
/// operand and — in `sendShielded` — a circuit output, and an output slot
/// names a wire.
pub fn upgrade_from_transient<V: Vis3>(c: &mut Circuit3, f: Wire3<FieldT, V>) -> B32<V> {
    let hi = V::from_public(c.constant(0u64));
    let (_over_31_bytes, lo) = c.div_mod_power_of_two(f, 248);
    B32 { hi, lo }
}

// ---- the preimage builder ----------------------------------------------------

/// A `persistentHash` preimage in FAB layout, built one typed field at a
/// time — the Compact-parity flavor of [`persistent_hash_compact`] without
/// the hand-written alignment.
///
/// ```ignore
/// let entry = Preimage::tag("midnight:account:device:v1")
///     .bytes(me)              // a Bytes<32>
///     .uint(epoch)            // a Uint<32>: a 4-byte atom, width FROM THE TYPE
///     .uint(counter)          // a Uint<64>: 8 bytes
///     .hash(c);
/// ```
///
/// Two things it does that the raw call does not:
///
/// - **The limb width comes from the type.** `uint` takes a `Uint<BITS>`, so
///   the atom's byte width and the wire's proven bound are one object; the
///   taint lint's §B3 class (a hash limb wider than its slot, where the FAB
///   packing stops being injective) cannot be written with it.
/// - **An all-constant preimage is hashed OFF-circuit.** [`Self::tag`] and
///   [`Self::blob_const`] add immediates, and [`Self::hash`] on a preimage
///   of nothing but immediates computes the SHA-256 here and emits the digest
///   as two constants: ~1.9k rows per 64-byte block that compactc spends
///   hashing a literal domain separator at proving time, saved. Measured on
///   the passport account custody contract: every challenge-bearing circuit
///   hashes a 64-byte constant tag, 3,750 rows each.
///
/// Lifted from the passport port's `Preimage` (PR #184, Apache-2.0), where
/// it was the one builder every hash in the contract went through.
#[derive(Clone)]
pub struct Preimage<V: Vis3> {
    atoms: Vec<AlignmentSegment>,
    slots: Vec<AnyWire3<V>>,
}

impl<V: Vis3> Default for Preimage<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V: Vis3> Preimage<V> {
    pub fn new() -> Self {
        Preimage {
            atoms: Vec::new(),
            slots: Vec::new(),
        }
    }

    /// `pad(32, s)` as the FIRST field: the usual domain separator. An
    /// immediate, so a preimage of tag-only folds (see [`Self::hash`]).
    pub fn tag(s: &str) -> Self {
        assert!(s.len() <= 32, "pad(32, ..) literal longer than 32 bytes: {s:?}");
        let mut bytes = [0u8; 32];
        bytes[..s.len()].copy_from_slice(s.as_bytes());
        Self::new().bytes_const(&bytes)
    }

    /// A constant `Bytes<32>`, as immediates.
    pub fn bytes_const(mut self, bytes: &[u8; 32]) -> Self {
        self.atoms.push(AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }));
        self.slots.push(AnyWire3::immediate(Fr::from(u64::from(bytes[31]))));
        self.slots.push(AnyWire3::immediate(Fr::from_le_bytes(&bytes[..31]).expect("31 bytes fit")));
        self
    }

    /// A constant `Bytes<N>` (`N > 31`), as immediates in slot order —
    /// `pad(N, s)` for the long tags.
    pub fn blob_const<const N: usize>(mut self, bytes: &[u8; N]) -> Self {
        const { assert!(N > 31, "Bytes<N> here needs N > 31 — bytes_const below that") };
        self.atoms.push(AlignmentSegment::Atom(AlignmentAtom::Bytes { length: N as u32 }));
        // Slot order is leftover (most significant) chunk first; each limb is
        // its chunk little-endian — the inverse of `BytesN::to_le_bytes`.
        let leftover = match N % 31 {
            0 => 31,
            r => r,
        };
        let mut end = N;
        let mut len = leftover;
        while end > 0 {
            let start = end - len;
            self.slots.push(AnyWire3::immediate(
                Fr::from_le_bytes(&bytes[start..end]).expect("at most 31 bytes fit"),
            ));
            end = start;
            len = 31;
        }
        self
    }

    /// A `Bytes<32>` field.
    pub fn bytes(mut self, value: B32<V>) -> Self {
        self.atoms.push(AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }));
        self.slots.extend([value.hi.erase(), value.lo.erase()]);
        self
    }

    /// A `Uint<BITS>` field: a `BITS / 8`-byte atom, the width from the type.
    pub fn uint<const BITS: u32>(mut self, value: Uint<BITS, V>) -> Self {
        const { assert!(BITS % 8 == 0, "a hashed Uint<BITS> needs a whole number of bytes") };
        self.atoms.push(AlignmentSegment::Atom(AlignmentAtom::Bytes { length: BITS / 8 }));
        self.slots.push(value.field().erase());
        self
    }

    /// A `Field` field — a native scalar, no byte width (a curve coordinate).
    pub fn field(mut self, value: Wire3<FieldT, V>) -> Self {
        self.atoms.push(AlignmentSegment::Atom(AlignmentAtom::Field));
        self.slots.push(value.erase());
        self
    }

    /// A `Bytes<N>` field (`N > 31`), its limbs in slot order.
    pub fn blob<const N: usize>(mut self, value: &BytesN<V, N>) -> Self {
        self.atoms.push(AlignmentSegment::Atom(AlignmentAtom::Bytes { length: N as u32 }));
        self.slots.extend(value.limbs().iter().map(|w| w.erase()));
        self
    }

    /// Concatenate another preimage's fields after this one's.
    pub fn append(mut self, rhs: Self) -> Self {
        self.atoms.extend(rhs.atoms);
        self.slots.extend(rhs.slots);
        self
    }

    /// The alignment built so far (the operand compactc emits).
    pub fn alignment(&self) -> Alignment {
        Alignment(self.atoms.clone())
    }

    /// `persistentHash` of the preimage. All-immediate preimages are hashed
    /// here and come back as two constants (zero rows); anything with a wire
    /// in it is [`persistent_hash_compact`].
    pub fn hash(self, c: &mut Circuit3) -> B32<V> {
        let immediates: Option<Vec<Fr>> = self.slots.iter().map(|w| w.as_immediate()).collect();
        match immediates {
            Some(limbs) => constant_persistent_hash(c, &Alignment(self.atoms), &limbs),
            None => persistent_hash_compact(c, Alignment(self.atoms), &self.slots),
        }
    }
}

/// SHA-256 of a CONSTANT FAB-aligned value, computed here and emitted as
/// the digest's two `Bytes<32>` limbs (two `Copy`s of immediates: zero
/// rows). The encoding is the one the backend hashes in-circuit
/// (`ValueReprAlignedValue::binary_repr`, as `minocrab_sim`'s
/// `persistent_hash` arm and ir_vm.rs:478-506), so the two agree by
/// construction; `constant_persistent_hash_matches_the_circuit` holds them
/// together.
pub fn constant_persistent_hash<V: Vis3>(c: &mut Circuit3, alignment: &Alignment, limbs: &[Fr]) -> B32<V> {
    let value = alignment
        .parse_field_repr(limbs)
        .expect("a constant preimage's limbs fit its alignment");
    let mut repr = Vec::new();
    ValueReprAlignedValue(value).binary_repr(&mut repr);
    let digest: [u8; 32] = Sha256::digest(&repr).into();
    B32 {
        hi: V::from_public(c.constant(Fr::from(u64::from(digest[31])))),
        lo: V::from_public(c.constant(Fr::from_le_bytes(&digest[..31]).expect("31 bytes fit"))),
    }
}
