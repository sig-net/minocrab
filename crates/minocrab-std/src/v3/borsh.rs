//! Borsh — the FIXED-WIDTH SUBSET — in circuit.
//!
//! **THIS IS BORSH, RESTRICTED — NOT A SEPARATE FORMAT.** Every byte the
//! encoders here emit is valid canonical Borsh for the declared types: any
//! Borsh implementation (borsh-rs, borsh-js, borsh-go, the Rust MPC) parses
//! it from the same declarations, and `borsh::to_vec` of the matching plain
//! Rust struct is byte-for-byte the same string. Nothing is redefined, no
//! framing is added, no field is reordered. The subset exists for exactly one
//! reason: **a circuit cannot have data-dependent layout** — every offset has
//! to be a compile-time constant, because the instruction stream is fixed
//! before any value exists. So the subset admits only types whose Borsh
//! encoding has a fixed width, and Borsh's own value-dependent shapes are
//! spelled with fixed-width ones instead:
//!
//! | excluded | why | replacement |
//! |---|---|---|
//! | `Vec<T>`, `String`, maps | `u32` length prefix ⇒ value-dependent offsets | `[T; K]` plus a separate count field |
//! | `Option<T>` | Borsh omits the payload on `None` | [`Flagged<T>`] — a `bool` tag and an ALWAYS-PRESENT payload, which is an ordinary Borsh struct (and is what Compact's `Maybe` already compiles to) |
//! | data-carrying enums | payload width follows the tag | one record type per kind, or `{tag, widest payload}` |
//! | `Uint<BITS>` off a Borsh width | `u24` is not a Borsh primitive | the next width up plus a range constraint ([`CircuitBorsh`] is implemented only at 8/16/32/64/128) |
//!
//! Fieldless enums are `Tag<K>` here — ONE byte, range-checked `< K`, which
//! is exactly Borsh's own 1-byte discriminant. The SPEC-side declaration of
//! such a field is a plain `u8` (notes/borsh-format.org §"Two corrections":
//! a Rust `enum` leaves the dual-oracle subset, because bincode-fixint writes
//! a 4-byte variant index where Borsh writes one).
//!
//! Trailing zero padding — what a fixed envelope like the singleton's
//! `Bytes<256>` `Misc` payload needs — is NOT Borsh and is not claimed to be:
//! the rule the spec states is "bytes `0..LEN` are the Borsh encoding, bytes
//! `LEN..N` MUST be zero". [`to_bytes`] writes exactly that (the pad is
//! constant zero limbs), and a decoder is required to check it.
//!
//! # What the layer buys
//!
//! [`CircuitBorsh`] is a strict extension of [`CircuitArg`]: the same type
//! that declares and range-constrains a circuit argument also states its
//! Borsh width, its hash-preimage limbs, its packed segments, its canonicity
//! constraints and its offset table, so those cannot drift apart. Two
//! encoders, because the two consumers are different:
//!
//! - [`CircuitBorsh::push_limbs`] feeds the ALIGNMENT-AWARE hash instructions
//!   ([`Limbs::keccak256`] / [`Limbs::persistent_hash`]). The chips do the
//!   byte packing in-chip, so this path costs ZERO extra rows — choosing the
//!   atom widths to be the Borsh widths gets the Borsh encoding for free
//!   (notes/borsh-format.org, finding #2).
//! - [`CircuitBorsh::push_segments`] feeds the packed [`Serializer`], for the
//!   places that need the bytes as a value (log payloads, `Bytes<N>` fields).
//!   This one costs the M7 segment packing, which is what it already cost.
//!
//! And one decoder, in two modes ([`BorshReader`], [`Split`],
//! [`WitnessCheck`]) — deliberately off the critical path: no vault circuit
//! uses it, because an attested output arrives as typed circuit ARGUMENTS and
//! running the serializer forwards over declared fields is already a complete
//! sound deserialization. The reader is for packed state and future formats.
//!
//! # The laws every impl must satisfy
//!
//! 1. `LEN` is the type's Borsh width — `borsh::object_length(v) == LEN` for
//!    EVERY value of the corresponding spec type, not just some.
//! 2. `push_limbs` and `push_segments` describe the same `LEN` bytes in the
//!    same order (the declaration order of the spec type), and that order is
//!    Borsh's.
//! 3. `constrain_canonical` emits every constraint that makes the encoding
//!    canonical and the packing injective: the leaf range checks, booleanity
//!    for `bool`, `tag < K` for a tag. For every leaf that is also a
//!    [`CircuitArg`] it equals `CircuitArg::constrain` — except [`Tag`],
//!    which adds the bound compactc does not emit (`constrain_canonical_is_
//!    the_argument_constraint` in `tests/v3_borsh.rs` pins both halves).
//! 4. `push_layout` walks the same fields in the same order with the same
//!    widths, and the SPEC-side path/kind names — dot-joined field names and
//!    `[i]` indices, `u64` / `bool` / `[u8; 32]` kinds — because that table is
//!    cross-checked against `borsh::schema_container_of` walked the same way
//!    (stage 0's `layout_rows`), and published as the offset table the TS and
//!    MPC sides implement against.
//!
//! 5. `read` takes the same fields in the same order, so it is the inverse of
//!    the encoders: `read(to_bytes(v)) == v` in both modes, which
//!    `tests/v3_borsh.rs` proves through the simulator — including against
//!    bytes produced natively by `borsh::to_vec`.
//!
//! Laws 1, 2 and 4 are checked mechanically for every leaf: the layout widths
//! must sum to `LEN` ([`CircuitBorsh::layout`] asserts it), the limbs must sum
//! to `LEN` ([`limbs_of`] asserts it), and the tests compare simulated
//! in-circuit bytes against `borsh::to_vec`.

use minocrab::v3::{AnyWire3, Bytes32T, Circuit3, FieldT, Wire3};
use minocrab::{Alignment, AlignmentAtom, AlignmentSegment, Private, Public};

/// Borsh's own schema of the SPEC type, walked into the same offset table
/// [`CircuitBorsh::layout`] produces — the cross-check
/// `#[borsh(spec = …)]` generates. Behind the off-by-default `borsh-schema`
/// feature, since it is the only thing here that links borsh.
#[cfg(feature = "borsh-schema")]
pub mod schema;

/// `#[derive(CircuitBorsh)]` — the [`CircuitBorsh`] impl AND the
/// [`CircuitArg`] family, generated from one struct's fields (field order is
/// the wire contract, and it is the BORSH order). Named the same as the trait
/// it implements, the way `serde::Serialize` is.
#[cfg(feature = "macros")]
pub use minocrab_macros::CircuitBorsh;

use super::{ArgPath, Bool, Bytes, BytesN, CircuitArg, Maybe, Serializer, Uint, Vis3, B32};

// ---- the trait ---------------------------------------------------------------

/// A type with a fixed-width canonical Borsh encoding the circuit can emit.
///
/// Parameterised by the wire visibility, because the same shape is serialized
/// at both ends of the disclosure lattice (private hash preimages, public log
/// payloads).
///
/// See the module docs for the four laws an impl must satisfy, and for why
/// this is Borsh rather than a format of ours.
///
/// # Relationship to [`CircuitArg`]
///
/// The design of record writes this trait as `CircuitBorsh<V>: CircuitArg`.
/// It cannot be spelled that way: [`CircuitArg`] is implemented for `Private`
/// leaves only (a circuit argument is witness data, so `Circuit3::arg` can
/// only hand back a private wire), while serialization applies at every
/// visibility. The extension is enforced instead by [`CircuitBorshArg`],
/// which every `Private` leaf and every derived struct satisfies, and which
/// the tests name for each of them.
pub trait CircuitBorsh<V: Vis3>: Sized {
    /// The serialized width in bytes — a compile-time constant, which is the
    /// whole point of the subset.
    const LEN: usize;

    /// Read this value out of packed Borsh bytes, leaf by leaf, in
    /// declaration order.
    ///
    /// Extraction ONLY: it emits no constraint, so on its own it is not a
    /// sound deserialization in either mode. Use [`read_canonical`] (or the
    /// whole-buffer [`read_split`] / [`read_witness_checked`]), which follow
    /// it with [`CircuitBorsh::constrain_canonical`].
    fn read<R: BorshReader<V>>(c: &mut Circuit3, r: &mut R) -> Self;

    /// Push this value's hash-preimage limbs: one alignment atom per Borsh
    /// leaf, with the wires that carry it. Emits NO instructions.
    fn push_limbs(&self, limbs: &mut Limbs<V>);

    /// Push this value's bytes as [`Serializer`] segments, in Borsh order.
    /// Emits no instructions itself; the packing happens in
    /// [`Serializer::finish`].
    fn push_segments(&self, out: &mut Serializer<V>);

    /// Emit the constraints that make this value's encoding canonical: the
    /// leaf range checks, booleanity, `tag < K`.
    fn constrain_canonical(&self, c: &mut Circuit3);

    /// Walk this type's leaves into the offset table, starting at `offset`
    /// under `path`. A type-level operation: no value, no circuit.
    fn push_layout(path: &LayoutPath, offset: &mut usize, out: &mut Vec<FieldSpec>);

    /// The type's whole offset table — the published spec's rows, and what
    /// the derive's schema cross-check compares against.
    fn layout() -> Vec<FieldSpec> {
        let mut out = Vec::new();
        let mut offset = 0usize;
        Self::push_layout(&LayoutPath::root(), &mut offset, &mut out);
        assert_eq!(
            offset,
            Self::LEN,
            "layout covers {offset} bytes but LEN is {} — the layout table and \
             the encoders disagree",
            Self::LEN
        );
        out
    }
}

/// The strict extension the design of record asks for, as a checkable bound:
/// a `Private` value that is both a circuit argument and Borsh-serializable.
///
/// Every leaf in this module and every `#[derive(CircuitBorsh)]` struct
/// satisfies it; the tests name each of them at this bound, which is what
/// makes "one derive yields circuit args AND serialization" a compile-time
/// fact rather than a convention.
pub trait CircuitBorshArg: CircuitArg + CircuitBorsh<Private> {}

impl<T: CircuitArg + CircuitBorsh<Private>> CircuitBorshArg for T {}

// ---- the hash-preimage path ----------------------------------------------------

/// A hash preimage under construction: the FAB alignment and the wires that
/// carry it, in Borsh byte order.
///
/// This is the ZERO-COST encoder. `Keccak256`/`PersistentHash` take an
/// alignment and pack the bytes in-chip, and their per-limb byte
/// decomposition is what makes the packing injective — so when the atom
/// widths ARE the Borsh widths, the circuit hashes the canonical Borsh
/// encoding without emitting a single packing instruction.
///
/// A `bytes<n>` atom may span several wires (a `Bytes<32>` is the `[hi, lo]`
/// slot pair, a `Bytes<N>` its FAB limbs in slot order); that is the deployed
/// layout, and stage 0 proved the resulting byte string IS the Borsh one.
pub struct Limbs<V: Vis3> {
    atoms: Vec<AlignmentAtom>,
    wires: Vec<AnyWire3<V>>,
    len: usize,
}

impl<V: Vis3> Limbs<V> {
    pub fn new() -> Limbs<V> {
        Limbs { atoms: Vec::new(), wires: Vec::new(), len: 0 }
    }

    /// One `bytes<width>` atom carried by `wires`, in FAB slot order (one
    /// wire for a single-slot leaf, `[hi, lo]` for a `Bytes<32>`, the limbs
    /// for a longer byte string).
    pub fn push_atom(&mut self, width: usize, wires: &[Wire3<FieldT, V>]) {
        assert!(!wires.is_empty(), "a bytes<{width}> atom needs at least one wire");
        self.atoms.push(AlignmentAtom::Bytes { length: width as u32 });
        self.wires.extend(wires.iter().map(|w| w.erase()));
        self.len += width;
    }

    /// The alignment these atoms describe.
    pub fn alignment(&self) -> Alignment {
        Alignment(
            self.atoms
                .iter()
                .cloned()
                .map(AlignmentSegment::Atom)
                .collect(),
        )
    }

    /// The atoms, in order.
    pub fn atoms(&self) -> &[AlignmentAtom] {
        &self.atoms
    }

    /// The wires, in order.
    pub fn wires(&self) -> &[AnyWire3<V>] {
        &self.wires
    }

    /// Bytes the preimage occupies — the sum of the atom widths.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// `keccak256(borsh(value))`, in one instruction.
    pub fn keccak256(&self, c: &mut Circuit3) -> Wire3<Bytes32T, V> {
        c.keccak256(self.alignment(), &self.wires)
    }

    /// `persistentHash(borsh(value))` (SHA-256), in one instruction.
    pub fn persistent_hash(&self, c: &mut Circuit3) -> Wire3<Bytes32T, V> {
        c.persistent_hash(self.alignment(), &self.wires)
    }
}

impl<V: Vis3> Default for Limbs<V> {
    fn default() -> Self {
        Limbs::new()
    }
}

// ---- the free functions --------------------------------------------------------

/// The value's hash-preimage limbs. Emits NO instructions: this is pure
/// bookkeeping over wires that already exist.
pub fn limbs_of<V: Vis3, T: CircuitBorsh<V>>(value: &T) -> Limbs<V> {
    let mut limbs = Limbs::new();
    value.push_limbs(&mut limbs);
    assert_eq!(
        limbs.len(),
        T::LEN,
        "push_limbs described {} bytes but LEN is {}",
        limbs.len(),
        T::LEN
    );
    limbs
}

/// The FAB alignment of the value's Borsh encoding — the one to hand a hash
/// instruction. Value-independent (that is what fixed-width MEANS), and free.
pub fn alignment_of<V: Vis3, T: CircuitBorsh<V>>(value: &T) -> Alignment {
    limbs_of(value).alignment()
}

/// The value's Borsh bytes, packed into a `Bytes<N>` envelope: bytes
/// `0..T::LEN` are the canonical Borsh encoding, bytes `T::LEN..N` are zero.
///
/// `N == T::LEN` is the exact encoding; `N > T::LEN` is the padded-envelope
/// rule the spec states for fixed containers like the singleton's 288-byte
/// `Misc` (and the pad is constant zero limbs, so it costs nothing).
///
/// THIS is the path that costs rows — the M7 segment packing, one `div_mod`
/// per 31-byte output-limb boundary a field straddles. Where the bytes are
/// only going to be hashed, use [`limbs_of`] instead and pay nothing.
pub fn to_bytes<const N: usize, V: Vis3, T: CircuitBorsh<V>>(
    c: &mut Circuit3,
    value: &T,
) -> BytesN<V, N> {
    assert!(
        N >= T::LEN,
        "Bytes<{N}> cannot hold a {}-byte Borsh encoding",
        T::LEN
    );
    let mut out = Serializer::new();
    value.push_segments(&mut out);
    out.finish::<N>(c)
}

// ---- the deserializer ------------------------------------------------------------
//
// DELIBERATELY OFF THE CRITICAL PATH, and a library component: no vault
// circuit uses it. The vault does not need a reader at all — an attested
// output arrives as typed circuit ARGUMENTS and the MPC signs
// keccak(requestId ‖ bytes), so declaring the fields and running the
// SERIALIZER forwards is already a complete sound deserialization (the
// four-line theorem: packing is injective on range-constrained inputs, the
// MPC signed the digest, the circuit constrains bytes == serialize(fields)
// with the fields in range, therefore the fields are what the MPC encoded).
// What the reader is for is packed state and future formats — so it is built,
// tested and PRICED here, and used by nothing.

/// A source of packed Borsh bytes: hands back one little-endian field element
/// per leaf, in byte order.
///
/// `V` is the visibility of the values it produces. The two implementations
/// are the two modes of the design of record:
///
/// - [`Split`] — the M7 segment packing run BACKWARDS. One `div_mod` per
///   field boundary that falls inside a limb, and the leaves keep the packed
///   buffer's own visibility, so a public buffer yields public fields with no
///   disclosure.
/// - [`WitnessCheck`] — witness each leaf, constrain it, re-pack the lot and
///   assert limb equality with the buffer. Much cheaper (the packing costs
///   one `div_mod` per LIMB boundary rather than per FIELD boundary), but the
///   leaves are witnesses, hence `Private`: ledger use needs `disclose`.
///
/// Two types rather than the one enum the design of record sketched, because
/// the modes differ in the VISIBILITY they produce and that is a type, not a
/// value: `Split<V>` reads at `V`, `WitnessCheck` reads at `Private`.
pub trait BorshReader<V: Vis3> {
    /// The next `width` bytes as one little-endian field element.
    ///
    /// PRECONDITION (both modes): the packed buffer's limbs are already
    /// constrained to their byte widths — the same precondition
    /// [`Serializer`] states, and for the same reason (the packing is
    /// injective only on in-range limbs).
    fn take(&mut self, c: &mut Circuit3, width: usize) -> Wire3<FieldT, V>;
}

/// Split mode: read fields out of the packed limbs directly, one `div_mod`
/// per field boundary interior to a limb.
///
/// This is [`Serializer::finish`] backwards, segment for segment: the buffer
/// is a queue of `(wire, byte length)` in string order, a field takes whole
/// segments while they fit and splits the one that straddles.
pub struct Split<V: Vis3> {
    /// `(wire, byte length)` in STRING order — the packed limbs reversed,
    /// since limb 0 is the leftover (most significant) chunk.
    segments: std::collections::VecDeque<(Wire3<FieldT, V>, usize)>,
}

impl<V: Vis3> Split<V> {
    /// Read from a packed `Bytes<N>`.
    pub fn new<const N: usize>(bytes: &BytesN<V, N>) -> Split<V> {
        let mut segments = std::collections::VecDeque::new();
        for (i, limb) in bytes.limbs().iter().enumerate().rev() {
            segments.push_back((*limb, BytesN::<V, N>::limb_len(i)));
        }
        Split { segments }
    }

    /// Bytes not yet read.
    pub fn remaining(&self) -> usize {
        self.segments.iter().map(|&(_, len)| len).sum()
    }

    /// The padding rule: everything after the value MUST be zero. One
    /// `assert_eq` per leftover segment (never more than one per limb).
    pub fn assert_pad_zero(self, c: &mut Circuit3) {
        if self.segments.is_empty() {
            return;
        }
        let zero = c.constant(0u64);
        for (wire, _) in self.segments {
            c.assert_eq(wire, V::from_public(zero));
        }
    }
}

impl<V: Vis3> BorshReader<V> for Split<V> {
    fn take(&mut self, c: &mut Circuit3, width: usize) -> Wire3<FieldT, V> {
        assert!(
            width > 0 && width <= 31,
            "a Borsh leaf is 1..=31 bytes here (Bytes<32> reads as 31 + 1, \
             Bytes<N> limb by limb)"
        );
        let mut acc: Option<Wire3<FieldT, V>> = None;
        let mut filled = 0usize;
        while filled < width {
            let (wire, len) = self
                .segments
                .pop_front()
                .expect("the reader ran past the end of the buffer");
            let (piece, piece_len) = if len > width - filled {
                // The field ends inside this segment: split at the boundary
                // and put the high rest back for the next read.
                let take = width - filled;
                let (rest, low) = c.div_mod_power_of_two(wire, (8 * take) as u32);
                self.segments.push_front((rest, len - take));
                (low, take)
            } else {
                (wire, len)
            };
            let weighted = if filled == 0 {
                piece
            } else {
                let shift = V::from_public(super::pow2_const(c, filled));
                c.mul(piece, shift)
            };
            acc = Some(match acc {
                None => weighted,
                Some(a) => c.add(a, weighted),
            });
            filled += piece_len;
        }
        acc.expect("width > 0")
    }
}

/// WitnessCheck mode: witness every leaf, then prove the witnesses ARE the
/// buffer by re-packing them and asserting limb equality.
///
/// Sound exactly when the leaves are range-constrained
/// ([`CircuitBorsh::constrain_canonical`], which [`read_canonical`] emits):
/// the packing is injective on in-range leaves, so the equality pins each
/// leaf to the one value the buffer encodes. Cheaper than [`Split`] because
/// the `div_mod`s move from field boundaries to LIMB boundaries — at most one
/// per 31 bytes, whatever the field layout.
///
/// The re-pack also enforces the PADDING RULE for free: the [`Serializer`]
/// zero-fills the tail of the `Bytes<N>`, so the equality asserts that the
/// buffer's own tail is zero.
///
/// [`read_witness_checked`] is the entry point that cannot be misused; the
/// bare struct exists for partial reads, where [`WitnessCheck::finish`] is
/// the caller's responsibility and skipping it makes the whole read vacuous.
#[must_use = "a WitnessCheck read proves nothing until finish() emits the equality"]
pub struct WitnessCheck<const N: usize> {
    /// The witnessed leaves, in byte order, ready to re-pack.
    repack: Serializer<Private>,
    /// The buffer's limbs, in slot order.
    expected: Vec<Wire3<FieldT, Private>>,
}

impl<const N: usize> WitnessCheck<N> {
    /// Read from a packed `Bytes<N>` of any visibility: the leaves are
    /// witnesses, so they come back `Private` whatever the buffer was.
    pub fn new<W: Vis3>(bytes: &BytesN<W, N>) -> WitnessCheck<N> {
        WitnessCheck {
            repack: Serializer::new(),
            expected: bytes.limbs().iter().map(|w| w.private()).collect(),
        }
    }

    /// Re-pack the witnessed leaves and assert they are the buffer, limb for
    /// limb. WITHOUT THIS THE READ PROVES NOTHING.
    pub fn finish(self, c: &mut Circuit3) {
        let packed = self.repack.finish::<N>(c);
        assert_eq!(packed.limbs().len(), self.expected.len());
        for (got, want) in packed.limbs().iter().zip(&self.expected) {
            c.assert_eq(*got, *want);
        }
    }
}

impl<const N: usize> BorshReader<Private> for WitnessCheck<N> {
    fn take(&mut self, c: &mut Circuit3, width: usize) -> Wire3<FieldT, Private> {
        assert!(width > 0 && width <= 31, "a Borsh leaf is 1..=31 bytes here");
        let leaf = c.witness::<FieldT>();
        self.repack.push_uint(leaf, width);
        leaf
    }
}

/// Read a value and constrain it — the sound single-value read, in either
/// mode. (In WitnessCheck mode the caller still owes
/// [`WitnessCheck::finish`]; [`read_witness_checked`] owes nothing.)
pub fn read_canonical<V: Vis3, T: CircuitBorsh<V>, R: BorshReader<V>>(
    c: &mut Circuit3,
    r: &mut R,
) -> T {
    let value = T::read(c, r);
    value.constrain_canonical(c);
    value
}

/// Deserialize a whole `Bytes<N>` in [`Split`] mode: read the value,
/// constrain it, and assert the padding is zero. The leaves keep the
/// buffer's visibility.
pub fn read_split<const N: usize, V: Vis3, T: CircuitBorsh<V>>(
    c: &mut Circuit3,
    bytes: &BytesN<V, N>,
) -> T {
    assert!(
        N >= T::LEN,
        "a {}-byte value cannot be read out of Bytes<{N}>",
        T::LEN
    );
    let mut reader = Split::new(bytes);
    let value = read_canonical::<V, T, _>(c, &mut reader);
    reader.assert_pad_zero(c);
    value
}

/// Deserialize a whole `Bytes<N>` in [`WitnessCheck`] mode: witness the
/// leaves, constrain them, re-pack and assert equality (which also asserts
/// the padding is zero). The leaves are `Private`.
pub fn read_witness_checked<const N: usize, W: Vis3, T: CircuitBorsh<Private>>(
    c: &mut Circuit3,
    bytes: &BytesN<W, N>,
) -> T {
    assert!(
        N >= T::LEN,
        "a {}-byte value cannot be read out of Bytes<{N}>",
        T::LEN
    );
    let mut reader = WitnessCheck::<N>::new(bytes);
    let value = read_canonical::<Private, T, _>(c, &mut reader);
    reader.finish(c);
    value
}

// ---- the layout table ------------------------------------------------------------

/// One leaf of a type's published layout: where a primitive field sits and
/// how wide it is.
///
/// Deliberately the same four columns as the stage-0 conformance suite's
/// schema walk (`(path, kind, offset, width)`), so the derive's cross-check
/// against `borsh::schema_container_of` is a plain equality.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldSpec {
    /// Dot-joined field path, `[i]` for array elements — the SPEC type's
    /// path, not the circuit argument's label.
    pub path: String,
    /// The Borsh declaration of the leaf: `u8`..`u128`, `bool`, `[u8; N]`.
    pub kind: String,
    /// Byte offset from the start of the encoding.
    pub offset: usize,
    /// Byte width of the leaf.
    pub width: usize,
}

/// The path to a leaf in the layout table.
///
/// NOT [`ArgPath`]: argument labels are `_`-joined and follow Compact's
/// naming (`recipient_is_some`), while these paths are the SPEC type's —
/// `tx_params.calldata.value.words[0]` — because they are compared against
/// borsh's own schema walk and published as the offset table.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct LayoutPath(String);

impl LayoutPath {
    /// The whole value: the empty path, as borsh's schema walk starts.
    pub fn root() -> LayoutPath {
        LayoutPath(String::new())
    }

    /// A named field of this value.
    pub fn field(&self, name: &str) -> LayoutPath {
        if self.0.is_empty() {
            LayoutPath(name.to_string())
        } else {
            LayoutPath(format!("{}.{name}", self.0))
        }
    }

    /// Element `i` of this array.
    pub fn index(&self, i: usize) -> LayoutPath {
        LayoutPath(format!("{}[{i}]", self.0))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for LayoutPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Push one leaf row and advance the offset.
fn push_leaf(
    path: &LayoutPath,
    kind: String,
    width: usize,
    offset: &mut usize,
    out: &mut Vec<FieldSpec>,
) {
    out.push(FieldSpec {
        path: path.as_str().to_string(),
        kind,
        offset: *offset,
        width,
    });
    *offset += width;
}

/// Borsh's declaration for a fixed byte array.
fn byte_array_kind(n: usize) -> String {
    format!("[u8; {n}]")
}

// ---- leaves: the unsigned integers ------------------------------------------------
//
// THE SUBSET'S LEAF TABLE, AS CODE. `Uint<BITS>` is a Borsh integer only at
// the five Borsh widths; `Uint<24>` simply has no impl, so using one is a
// trait error naming this table rather than a silently narrower field. A
// tighter RANGE than the width is a range constraint on the next width up —
// `Uint<40>` is not a leaf, `Uint<64>` range-checked to 40 bits is.

macro_rules! borsh_uint {
    ($($bits:literal => ($len:literal, $kind:literal)),+ $(,)?) => {$(
        impl<V: Vis3> CircuitBorsh<V> for Uint<$bits, V> {
            const LEN: usize = $len;

            fn push_limbs(&self, limbs: &mut Limbs<V>) {
                limbs.push_atom($len, &[self.field()]);
            }

            fn push_segments(&self, out: &mut Serializer<V>) {
                out.push_uint(self.field(), $len);
            }

            fn constrain_canonical(&self, c: &mut Circuit3) {
                self.constrain_input(c);
            }

            fn read<R: BorshReader<V>>(c: &mut Circuit3, r: &mut R) -> Self {
                Uint::from_field(r.take(c, $len))
            }

            fn push_layout(path: &LayoutPath, offset: &mut usize, out: &mut Vec<FieldSpec>) {
                push_leaf(path, $kind.to_string(), $len, offset, out);
            }
        }
    )+};
}

borsh_uint!(
    8 => (1, "u8"),
    16 => (2, "u16"),
    32 => (4, "u32"),
    64 => (8, "u64"),
    128 => (16, "u128"),
);

// ---- leaves: bool ------------------------------------------------------------------

/// Borsh `bool`: one byte, `0` or `1` AND NOTHING ELSE — which is why
/// `constrain_canonical` is `assert_boolean` and not a range check. (That
/// rule is what closes the 0x02 hazard when stage 5 makes the attested
/// success byte a `bool`: today any byte is accepted and everything but
/// `0x01` refunds.)
impl<V: Vis3> CircuitBorsh<V> for Bool<V> {
    const LEN: usize = 1;

    fn push_limbs(&self, limbs: &mut Limbs<V>) {
        limbs.push_atom(1, &[self.field()]);
    }

    fn push_segments(&self, out: &mut Serializer<V>) {
        out.push_uint(self.field(), 1);
    }

    fn constrain_canonical(&self, c: &mut Circuit3) {
        self.constrain_input(c);
    }

    fn read<R: BorshReader<V>>(c: &mut Circuit3, r: &mut R) -> Self {
        Bool::from_field(r.take(c, 1))
    }

    fn push_layout(path: &LayoutPath, offset: &mut usize, out: &mut Vec<FieldSpec>) {
        push_leaf(path, "bool".to_string(), 1, offset, out);
    }
}

// ---- leaves: the byte strings ---------------------------------------------------------

/// Borsh `[u8; N]` for `N <= 31`: the bytes verbatim, `bytes[0]` first — one
/// native slot holding them little-endian, which is the same string.
impl<const N: usize, V: Vis3> CircuitBorsh<V> for Bytes<N, V> {
    const LEN: usize = N;

    fn push_limbs(&self, limbs: &mut Limbs<V>) {
        limbs.push_atom(N, &[self.field()]);
    }

    fn push_segments(&self, out: &mut Serializer<V>) {
        out.push_uint(self.field(), N);
    }

    fn constrain_canonical(&self, c: &mut Circuit3) {
        self.constrain_input(c);
    }

    fn read<R: BorshReader<V>>(c: &mut Circuit3, r: &mut R) -> Self {
        Bytes::from_field(r.take(c, N))
    }

    fn push_layout(path: &LayoutPath, offset: &mut usize, out: &mut Vec<FieldSpec>) {
        push_leaf(path, byte_array_kind(N), N, offset, out);
    }
}

/// Borsh `[u8; 32]`: one atom over the `[hi, lo]` slot pair.
impl<V: Vis3> CircuitBorsh<V> for B32<V> {
    const LEN: usize = 32;

    fn push_limbs(&self, limbs: &mut Limbs<V>) {
        limbs.push_atom(32, &[self.hi, self.lo]);
    }

    fn push_segments(&self, out: &mut Serializer<V>) {
        out.push_b32(self);
    }

    fn constrain_canonical(&self, c: &mut Circuit3) {
        self.constrain_input(c);
    }

    /// Bytes 0..30 are the low limb and byte 31 is the high one, which is
    /// the `[hi, lo]` pair's own layout — so a `Bytes<32>` is two reads.
    fn read<R: BorshReader<V>>(c: &mut Circuit3, r: &mut R) -> Self {
        let lo = r.take(c, 31);
        let hi = r.take(c, 1);
        B32 { hi, lo }
    }

    fn push_layout(path: &LayoutPath, offset: &mut usize, out: &mut Vec<FieldSpec>) {
        push_leaf(path, byte_array_kind(32), 32, offset, out);
    }
}

/// Borsh `[u8; N]` for `N > 31`: one atom over the FAB limbs, in slot order
/// (limb 0 is the leftover, most significant chunk).
impl<const N: usize, V: Vis3> CircuitBorsh<V> for BytesN<V, N> {
    const LEN: usize = N;

    fn push_limbs(&self, limbs: &mut Limbs<V>) {
        limbs.push_atom(N, self.limbs());
    }

    fn push_segments(&self, out: &mut Serializer<V>) {
        out.push_bytes_n(self);
    }

    fn constrain_canonical(&self, c: &mut Circuit3) {
        self.constrain_input(c);
    }

    /// String order is the FAB limbs BACKWARDS — the full 31-byte limbs
    /// first, the leftover (most significant) chunk last.
    fn read<R: BorshReader<V>>(c: &mut Circuit3, r: &mut R) -> Self {
        let mut limbs: Vec<Wire3<FieldT, V>> = (0..Self::LIMBS)
            .rev()
            .map(|i| r.take(c, Self::limb_len(i)))
            .collect();
        limbs.reverse();
        BytesN::from_limbs(limbs)
    }

    fn push_layout(path: &LayoutPath, offset: &mut usize, out: &mut Vec<FieldSpec>) {
        push_leaf(path, byte_array_kind(N), N, offset, out);
    }
}

// ---- leaves: the tag ---------------------------------------------------------------

/// A fieldless enum of `K` variants: Borsh's own 1-byte discriminant, range
/// checked `< K`.
///
/// The SPEC-side declaration of a `Tag<K>` field is a plain `u8` — a Rust
/// `enum` leaves the dual-oracle subset, since bincode-fixint writes a 4-byte
/// variant index where Borsh writes one (notes/borsh-format.org §"Two
/// corrections to the design of record"). So the layout kind below is `u8`,
/// and a TS or Go decoder reads a byte. What `Tag` adds over `Uint<8>` is the
/// `< K` bound, which no Compact circuit emits today and Borsh's own decoder
/// does.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Tag<const K: u32, V: Vis3 = Private>(Wire3<FieldT, V>);

impl<const K: u32, V: Vis3> Tag<K, V> {
    /// Wrap a wire already known to hold a discriminant.
    pub fn from_field(w: Wire3<FieldT, V>) -> Self {
        const {
            assert!(
                K > 0 && K <= 256,
                "Tag<K> needs 0 < K <= 256 — a Borsh fieldless-enum discriminant is one byte"
            )
        };
        Tag(w)
    }

    /// The discriminant wire — the same slot, no instructions.
    pub fn field(self) -> Wire3<FieldT, V> {
        self.0
    }

    /// The byte-width constraint of the wire, as compactc constrains any
    /// one-byte argument. The `< K` bound is NOT here: it is Borsh's
    /// canonicity check, emitted by
    /// [`CircuitBorsh::constrain_canonical`].
    pub fn constrain_input(self, c: &mut Circuit3) {
        c.assert_bits(self.0, 8);
    }
}

impl<const K: u32> Tag<K, Public> {
    /// A constant discriminant; panics at circuit-build time if it is not a
    /// variant of the enum.
    pub fn constant(c: &mut Circuit3, variant: u32) -> Self {
        assert!(variant < K, "{variant} is not a variant of Tag<{K}>");
        Tag::from_field(c.constant(u64::from(variant)))
    }
}

impl<const K: u32> CircuitArg for Tag<K, Private> {
    const SLOTS: usize = 1;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        atoms.push(AlignmentAtom::Bytes { length: 1 });
    }

    fn declare(c: &mut Circuit3, path: &ArgPath) -> Self {
        Tag::from_field(c.arg::<FieldT>(path.as_str()))
    }

    fn constrain(&self, c: &mut Circuit3) {
        self.constrain_input(c);
    }
}

impl<const K: u32, V: Vis3> CircuitBorsh<V> for Tag<K, V> {
    const LEN: usize = 1;

    fn push_limbs(&self, limbs: &mut Limbs<V>) {
        limbs.push_atom(1, &[self.field()]);
    }

    fn push_segments(&self, out: &mut Serializer<V>) {
        out.push_uint(self.field(), 1);
    }

    /// One byte, and a variant of the enum: the range check plus the bound
    /// Borsh's decoder makes. `K == 256` needs no bound (every byte is a
    /// variant) and emits none.
    fn constrain_canonical(&self, c: &mut Circuit3) {
        self.constrain_input(c);
        if K < 256 {
            let bound = c.constant(u64::from(K));
            let in_range = c.less_than(self.field(), V::from_public(bound), 8);
            c.assert(in_range);
        }
    }

    fn read<R: BorshReader<V>>(c: &mut Circuit3, r: &mut R) -> Self {
        Tag::from_field(r.take(c, 1))
    }

    fn push_layout(path: &LayoutPath, offset: &mut usize, out: &mut Vec<FieldSpec>) {
        push_leaf(path, "u8".to_string(), 1, offset, out);
    }
}

// ---- composites ----------------------------------------------------------------------

/// Borsh `[T; K]`: the elements back to back, nothing between them.
impl<T: CircuitBorsh<V>, V: Vis3, const K: usize> CircuitBorsh<V> for [T; K] {
    const LEN: usize = T::LEN * K;

    fn push_limbs(&self, limbs: &mut Limbs<V>) {
        for element in self {
            element.push_limbs(limbs);
        }
    }

    fn push_segments(&self, out: &mut Serializer<V>) {
        for element in self {
            element.push_segments(out);
        }
    }

    fn constrain_canonical(&self, c: &mut Circuit3) {
        for element in self {
            element.constrain_canonical(c);
        }
    }

    fn read<R: BorshReader<V>>(c: &mut Circuit3, r: &mut R) -> Self {
        // Through a Vec rather than `array::from_fn`, whose call order is
        // not part of its contract: here the order IS the byte layout.
        let mut elements = Vec::with_capacity(K);
        for _ in 0..K {
            elements.push(T::read(c, r));
        }
        match <[T; K]>::try_from(elements) {
            Ok(array) => array,
            Err(_) => unreachable!("K elements were pushed"),
        }
    }

    fn push_layout(path: &LayoutPath, offset: &mut usize, out: &mut Vec<FieldSpec>) {
        for i in 0..K {
            T::push_layout(&path.index(i), offset, out);
        }
    }
}

/// Optionality in the subset: a `bool` tag and an ALWAYS-PRESENT payload.
///
/// **Maybe ↦ Flagged, never Option** — the single most important line of the
/// spec for the TS side. `Option<T>` is excluded not because Borsh cannot
/// express it but because Borsh omits the payload on `None`, which makes
/// every following offset value-dependent; `Flagged` is an ordinary Borsh
/// struct whose encoding is `is_some ‖ value` at fixed offsets. It is also
/// exactly what Compact's `Maybe` already compiles to (the deployed record
/// carries `calldata.is_some` followed by the full calldata whether or not
/// the tag is set), which is why this is a type ALIAS of the v3 [`Maybe`]
/// rather than a second type: the circuit type is Compact's, the spec name is
/// Borsh-side.
///
/// The always-max-size cost is circuit physics, not a format choice: both
/// arms always cost rows in a circuit, so eliding the payload on the wire
/// would save off-chain bytes only, at the price of data-dependent offsets.
pub type Flagged<T, V = Private> = Maybe<T, V>;

impl<T: CircuitBorsh<V>, V: Vis3> CircuitBorsh<V> for Maybe<T, V> {
    const LEN: usize = 1 + T::LEN;

    fn push_limbs(&self, limbs: &mut Limbs<V>) {
        self.is_some.push_limbs(limbs);
        self.value.push_limbs(limbs);
    }

    fn push_segments(&self, out: &mut Serializer<V>) {
        self.is_some.push_segments(out);
        self.value.push_segments(out);
    }

    fn constrain_canonical(&self, c: &mut Circuit3) {
        self.is_some.constrain_canonical(c);
        self.value.constrain_canonical(c);
    }

    fn read<R: BorshReader<V>>(c: &mut Circuit3, r: &mut R) -> Self {
        Maybe {
            is_some: <Bool<V> as CircuitBorsh<V>>::read(c, r),
            value: T::read(c, r),
        }
    }

    fn push_layout(path: &LayoutPath, offset: &mut usize, out: &mut Vec<FieldSpec>) {
        <Bool<V> as CircuitBorsh<V>>::push_layout(&path.field("is_some"), offset, out);
        T::push_layout(&path.field("value"), offset, out);
    }
}
