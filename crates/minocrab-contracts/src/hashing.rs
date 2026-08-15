//! `hashing` and `keccak` (signet-midnight-experiments) — hash-cost
//! experiments. Both contracts share the same circuit shapes over
//! different hash builtins and input sizes:
//!
//! ```text
//! export ledger callCount: Counter;   // field 0
//! export ledger digest: Bytes<32>;    // field 1
//! export ledger fdigest: Field;       // field 2 (hashing only)
//!
//! controlN/cN(data: Bytes<N>):    callCount.increment(1)   // no hash
//! persistentN/pN(data):  … digest  = disclose(persistentHash<Bytes<N>>(data))
//! kN(data):              … digest  = disclose(keccak256<Bytes<N>>(data))
//! transientN(data):      … fdigest = disclose(transientHash<Bytes<N>>(data))
//! persistentVec8(data: Vector<8, Bytes<32>>): … digest = …persistentHash…
//! ```
//!
//! # The one family that is NOT a `#[circuit]` (M9 phase 5)
//!
//! `control`/`persistent`/`keccak`/`transient` take their input WIDTH as a
//! Rust parameter — the experiment sweeps 32/64/128/256/1024 bytes in a
//! loop, and the sweep is the point — while a `CircuitArg` is a type and
//! `CircuitArgs::SLOTS` is a `const`. Expressing these through the typed
//! API would mean either const-generic entry points the sweeping loops
//! cannot call, or a `match` over the sizes that happen to be swept today,
//! turning a general experiment into a closed enumeration with a panic for
//! any new size. Neither is worth it HERE, because the soundness the typed
//! layer buys is already present: [`BytesNDyn::constrain_input`] derives the
//! per-limb widths from the same `len` that declared the limbs, so there is
//! no hand-written parallel constraint block to drift. [`persistent_vec8`],
//! whose shape is fixed, IS ported.
//!
//! The same sixteen circuits are therefore the ONLY ones in the corpus
//! without a typed disclosure declaration (M9 closure): a `Discloses<..>` is
//! a return type, and these have no typed entry point to return from —
//! `hash_circuit` calls `Circuit3::finish` itself. Nothing is hidden by that.
//! Each discloses exactly one value, the digest it writes to the ledger, and
//! the write is right there in `hash_circuit`; the declaration would restate
//! one line of a measurement rig. Porting the family is what would close it,
//! and the paragraph above is why nobody should.

use minocrab::v3::{Circuit3, Compiled3, Wire3};
use minocrab::{label, Alignment, AlignmentAtom, AlignmentSegment, Private};
use minocrab_ledger::{cell_write, counter_increment, emit, ImpactElem, LedgerValue};
use minocrab_std::v3::{circuit, BytesNDyn, Disclose, Discloses, B32};

label! {
    /// [`persistent_vec8`]'s digest. The `Bytes<len>` sweep below discloses
    /// the same value under the same string, but through the free-string
    /// `c.disclose` — those circuits are not `#[circuit]`s (their width is a
    /// runtime parameter, see the module docs), so there is no signature to
    /// declare in and no attribute to generate the test from.
    TheDigest = "the digest";
}

/// Ledger field indices (identical in both contracts; `fdigest` exists
/// only in `hashing`).
pub const CALL_COUNT: u8 = 0;
pub const DIGEST: u8 = 1;
pub const FDIGEST: u8 = 2;

/// Declare a constrained `Bytes<len>` argument (len > 31).
fn bytesn_arg(c: &mut Circuit3, len: usize) -> BytesNDyn<Private> {
    let limbs = (0..len.div_ceil(31))
        .map(|i| c.arg(&format!("data_{i}")))
        .collect();
    let data = BytesNDyn::new(len, limbs);
    data.constrain_input(c);
    data
}

fn bytes_alignment(len: u32) -> Alignment {
    Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes {
        length: len,
    })])
}

/// The hash performed by a measured circuit, `Bytes<len>` → ledger write.
enum HashKind {
    None,
    Persistent,
    Keccak,
    Transient,
}

fn hash_circuit(len: usize, kind: HashKind) -> Compiled3 {
    let mut c = Circuit3::new();
    let data = bytesn_arg(&mut c, len);
    let one = c.constant(1u64);

    emit(&mut c, one, &counter_increment(CALL_COUNT, 1));

    let inputs: Vec<_> = data.limbs.iter().map(|w| w.erase()).collect();
    match kind {
        HashKind::None => {}
        HashKind::Persistent | HashKind::Keccak => {
            let alignment = bytes_alignment(len as u32);
            let typed = match kind {
                HashKind::Persistent => c.persistent_hash(alignment, &inputs),
                _ => c.keccak256(alignment, &inputs),
            };
            let digest = B32::from_typed(&mut c, typed);
            let hi = c.disclose(digest.hi, "the digest (hi)");
            let lo = c.disclose(digest.lo, "the digest (lo)");
            let value = LedgerValue::bytes(32, vec![ImpactElem::Wire(hi), ImpactElem::Wire(lo)]);
            emit(&mut c, one, &cell_write(DIGEST, &value));
        }
        HashKind::Transient => {
            let limbs: Vec<Wire3<_, Private>> = data.limbs.clone();
            let f = c.transient_hash(&limbs);
            let f = c.disclose(f, "the field digest");
            let value = LedgerValue::new(vec![AlignmentAtom::Field], vec![ImpactElem::Wire(f)]);
            emit(&mut c, one, &cell_write(FDIGEST, &value));
        }
    }
    c.finish(true)
}

/// `controlN` / `cN`: the N-byte input, no hash.
pub fn control(len: usize) -> Compiled3 {
    hash_circuit(len, HashKind::None)
}

/// `persistentN` / `pN`.
pub fn persistent(len: usize) -> Compiled3 {
    hash_circuit(len, HashKind::Persistent)
}

/// `kN` (keccak contract).
pub fn keccak(len: usize) -> Compiled3 {
    hash_circuit(len, HashKind::Keccak)
}

/// `transientN` (hashing contract).
pub fn transient(len: usize) -> Compiled3 {
    hash_circuit(len, HashKind::Transient)
}

/// `persistentVec8(data: Vector<8, Bytes<32>>)`: the same 256 bytes as a
/// data structure — 8 × `Bytes<32>` atoms, 16 limbs.
///
/// The one circuit of this experiment whose argument WIDTH is fixed, so the
/// one that is a `#[circuit]`: `[B32; 8]` declares `data_0_hi` … `data_7_lo`
/// and constrains all sixteen limbs from the type (see the module docs for
/// why the `Bytes<len>` family stays hand-declared).
#[circuit]
pub fn persistent_vec8(c: &mut Circuit3, data: [B32<Private>; 8]) -> Discloses<(TheDigest,)> {
    let parts = data;
    let one = c.constant(1u64);

    emit(c, one, &counter_increment(CALL_COUNT, 1));

    let alignment = Alignment(
        (0..8)
            .map(|_| AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }))
            .collect(),
    );
    let mut inputs = Vec::new();
    for p in &parts {
        inputs.push(p.hi.erase());
        inputs.push(p.lo.erase());
    }
    let typed = c.persistent_hash(alignment, &inputs);
    let digest = B32::from_typed(c, typed).disclose_as::<TheDigest>(c);
    let value = LedgerValue::bytes(
        32,
        vec![ImpactElem::Wire(digest.hi), ImpactElem::Wire(digest.lo)],
    );
    emit(c, one, &cell_write(DIGEST, &value));
    Discloses::of(())
}
