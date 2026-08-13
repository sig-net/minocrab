//! Compact's scalar and byte-string types as wire bundles.
//!
//! Value representation follows notes/builtin-lowering.org §1
//! (flatten-datatypes): `Boolean`/`Uint<N>` are one slot with a `bytes k`
//! alignment atom; `Bytes<N>` is ceil(N/31) slots, **most-significant chunk
//! first**, bytes little-endian within a chunk, covered by a single
//! `bytes N` atom. `Bytes<32>` is therefore `[hi, lo]` with hi = byte 31.

use minocrab::{AlignmentAtom, Circuit, Fr, Wire};

use crate::bundle::{Bundle, Vis};

/// `Boolean`: one slot holding 0 or 1; alignment atom `bytes 1`.
#[derive(Clone, Copy)]
pub struct Bool<V: Vis>(pub Wire<V>);

impl<V: Vis> Bundle<V> for Bool<V> {
    const WIDTH: usize = 1;

    fn push_wires(&self, out: &mut Vec<Wire<V>>) {
        out.push(self.0);
    }

    fn from_wires(wires: &mut dyn Iterator<Item = Wire<V>>) -> Self {
        Bool(Wire::from_wires(wires))
    }

    fn push_atoms(out: &mut Vec<AlignmentAtom>) {
        out.push(AlignmentAtom::Bytes { length: 1 });
    }
}

impl<V: Vis> Bool<V> {
    /// Constrain a boolean entering the circuit (argument/witness), as
    /// compactc does for every `tunsigned 1` slot.
    pub fn constrain_input(self, c: &mut Circuit) {
        c.assert_boolean(self.0);
    }
}

/// `Uint<BITS>`: one slot bounded by 2^BITS − 1; alignment atom
/// `bytes ceil(BITS/8)` (atom length tracks the max value's byte length).
#[derive(Clone, Copy)]
pub struct UintN<V: Vis, const BITS: u32>(pub Wire<V>);

pub type U8<V> = UintN<V, 8>;
pub type U16<V> = UintN<V, 16>;
pub type U32<V> = UintN<V, 32>;
pub type U64<V> = UintN<V, 64>;
pub type U128<V> = UintN<V, 128>;

impl<V: Vis, const BITS: u32> Bundle<V> for UintN<V, BITS> {
    const WIDTH: usize = 1;

    fn push_wires(&self, out: &mut Vec<Wire<V>>) {
        out.push(self.0);
    }

    fn from_wires(wires: &mut dyn Iterator<Item = Wire<V>>) -> Self {
        UintN(Wire::from_wires(wires))
    }

    fn push_atoms(out: &mut Vec<AlignmentAtom>) {
        out.push(AlignmentAtom::Bytes {
            length: BITS.div_ceil(8),
        });
    }
}

impl<V: Vis, const BITS: u32> UintN<V, BITS> {
    /// Range-constrain a `Uint<BITS>` entering the circuit (the max value
    /// 2^BITS − 1 takes the `constrain_bits` shape).
    pub fn constrain_input(self, c: &mut Circuit) {
        c.assert_bits(self.0, BITS);
    }

    /// `x as Field` — a safe cast: same slot, no instructions.
    pub fn as_field(self) -> Wire<V> {
        self.0
    }
}

/// `Bytes<N>`: ceil(N/31) slots, most-significant chunk first.
#[derive(Clone)]
pub struct BytesN<V: Vis, const N: u32> {
    /// Invariant: `limbs.len() == Self::WIDTH`; `limbs[0]` is the partial
    /// (most-significant) chunk, the last limb is bytes 0..30.
    limbs: Vec<Wire<V>>,
}

/// `Bytes<32>` — the workhorse: `[hi = byte 31 (8 bits), lo = bytes 0..30
/// LE (248 bits)]`.
pub type Bytes32<V> = BytesN<V, 32>;

impl<V: Vis, const N: u32> Bundle<V> for BytesN<V, N> {
    const WIDTH: usize = (N as usize).div_ceil(31);

    fn push_wires(&self, out: &mut Vec<Wire<V>>) {
        out.extend(self.limbs.iter().copied());
    }

    fn from_wires(wires: &mut dyn Iterator<Item = Wire<V>>) -> Self {
        BytesN {
            limbs: (0..Self::WIDTH)
                .map(|_| wires.next().expect("bundle width mismatch"))
                .collect(),
        }
    }

    fn push_atoms(out: &mut Vec<AlignmentAtom>) {
        out.push(AlignmentAtom::Bytes { length: N });
    }
}

impl<V: Vis, const N: u32> BytesN<V, N> {
    /// Wrap existing limb wires (most-significant chunk first).
    pub fn from_limbs(limbs: Vec<Wire<V>>) -> Self {
        assert_eq!(limbs.len(), Self::WIDTH, "Bytes<{N}> takes {} limbs", Self::WIDTH);
        BytesN { limbs }
    }

    pub fn limbs(&self) -> &[Wire<V>] {
        &self.limbs
    }

    /// The least-significant limb (bytes 0..30 little-endian).
    pub fn lo(&self) -> Wire<V> {
        *self.limbs.last().expect("Bytes<N> has at least one limb")
    }

    /// The most-significant (partial) limb.
    pub fn hi(&self) -> Wire<V> {
        self.limbs[0]
    }

    /// The byte length of limb `i` (limb 0 is the partial chunk).
    fn limb_bytes(i: usize) -> u32 {
        if i == 0 {
            match N % 31 {
                0 => 31,
                partial => partial,
            }
        } else {
            31
        }
    }

    /// Constrain a `Bytes<N>` entering the circuit: 8·(N mod 31) bits on
    /// the partial limb, 248 bits on the rest (e.g. 8/248 for `Bytes<32>`).
    pub fn constrain_input(&self, c: &mut Circuit) {
        for (i, &limb) in self.limbs.iter().enumerate() {
            c.assert_bits(limb, 8 * Self::limb_bytes(i));
        }
    }

    /// A compile-time byte-string constant. `bytes` must be exactly N long;
    /// chunks of 31 bytes from the start, each read little-endian, the low
    /// chunk landing in the last slot.
    pub fn literal(c: &mut Circuit, bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), N as usize, "Bytes<{N}> literal length");
        let limbs = bytes
            .chunks(31)
            .rev()
            .map(|chunk| {
                let imm = Fr::from_le_bytes(chunk).expect("≤31 bytes always fit in Fr");
                V::from_public(c.constant(imm))
            })
            .collect();
        BytesN { limbs }
    }

    /// `pad(N, s)`: the UTF-8 bytes of `s` zero-padded at the end (the high
    /// bytes) to length N.
    pub fn pad(c: &mut Circuit, s: &str) -> Self {
        let mut bytes = s.as_bytes().to_vec();
        assert!(bytes.len() <= N as usize, "pad({N}, ..): string too long");
        bytes.resize(N as usize, 0);
        Self::literal(c, &bytes)
    }
}

/// A ≤31-byte string literal used `as Field`: one slot, the little-endian
/// integer of its UTF-8 bytes (e.g. Compact's
/// `"midnight:kernel:nonce_evolve" as Field`).
pub fn str_as_field<V: Vis>(c: &mut Circuit, s: &str) -> Wire<V> {
    assert!(s.len() <= 31, "string-as-Field literals fit one slot");
    let imm = Fr::from_le_bytes(s.as_bytes()).expect("≤31 bytes always fit in Fr");
    V::from_public(c.constant(imm))
}

/// `JubjubPoint` under ZKIR v2: two native slots (x, y), `field` atoms.
#[derive(Clone, Copy)]
pub struct JubjubPoint<V: Vis> {
    pub x: Wire<V>,
    pub y: Wire<V>,
}

impl<V: Vis> Bundle<V> for JubjubPoint<V> {
    const WIDTH: usize = 2;

    fn push_wires(&self, out: &mut Vec<Wire<V>>) {
        out.push(self.x);
        out.push(self.y);
    }

    fn from_wires(wires: &mut dyn Iterator<Item = Wire<V>>) -> Self {
        JubjubPoint {
            x: Wire::from_wires(wires),
            y: Wire::from_wires(wires),
        }
    }

    fn push_atoms(out: &mut Vec<AlignmentAtom>) {
        out.push(AlignmentAtom::Field);
        out.push(AlignmentAtom::Field);
    }
}
