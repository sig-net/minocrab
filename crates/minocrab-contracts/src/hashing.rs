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

use minocrab::v3::{Circuit3, Compiled3, Wire3};
use minocrab::{Alignment, AlignmentAtom, AlignmentSegment, Private};
use minocrab_ledger::{cell_write, counter_increment, emit, ImpactElem, LedgerValue};
use minocrab_std::v3::{BytesN, B32};

/// Ledger field indices (identical in both contracts; `fdigest` exists
/// only in `hashing`).
pub const CALL_COUNT: u8 = 0;
pub const DIGEST: u8 = 1;
pub const FDIGEST: u8 = 2;

/// Declare a constrained `Bytes<len>` argument (len > 31).
fn bytesn_arg(c: &mut Circuit3, len: usize) -> BytesN<Private> {
    let limbs = (0..len.div_ceil(31))
        .map(|i| c.arg(&format!("data_{i}")))
        .collect();
    let data = BytesN::new(len, limbs);
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
pub fn persistent_vec8() -> Compiled3 {
    let mut c = Circuit3::new();
    let parts: Vec<B32<Private>> = (0..8)
        .map(|i| B32 {
            hi: c.arg(&format!("data_{i}_hi")),
            lo: c.arg(&format!("data_{i}_lo")),
        })
        .collect();
    for p in &parts {
        p.constrain_input(&mut c);
    }
    let one = c.constant(1u64);

    emit(&mut c, one, &counter_increment(CALL_COUNT, 1));

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
    let digest = B32::from_typed(&mut c, typed);
    let hi = c.disclose(digest.hi, "the digest (hi)");
    let lo = c.disclose(digest.lo, "the digest (lo)");
    let value = LedgerValue::bytes(32, vec![ImpactElem::Wire(hi), ImpactElem::Wire(lo)]);
    emit(&mut c, one, &cell_write(DIGEST, &value));
    c.finish(true)
}
