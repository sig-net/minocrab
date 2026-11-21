//! `deserialize<T, N>(bytes)`, as compactc 0.36 lowers it, one field at a
//! time.
//!
//! WHAT IS COMPACTC'S: each byte a field occupies is read ON ITS OWN, from the
//! limb that holds it, by two splits: `div_mod_power_of_two(limb, 8·k)` keeps
//! the quotient (the limb shifted down to byte `k`), then
//! `div_mod_power_of_two(_, 8)` keeps the remainder (the byte). That is
//! `bytes-ref` / `bytes-slice` as `build-deserialize`
//! (`compiler/analysis-passes/expand-serialize.ss`) emits them. A byte no
//! field occupies, and a field the circuit never reads, is not split at all:
//! compactc's `optimize-circuit` drops a split whose outputs are unread. So a
//! port reads only the fields its circuit uses, through these readers, and
//! emits nothing for the rest (the padding included).
//!
//! THE LEAN FORM splits once per byte, as one chain down the limb
//! (`minocrab_std::v3::explode_limb`), stopped at the last byte read. Splitting
//! a whole `Bytes<N>` with `BytesN::to_le_bytes` and reading a few of its
//! bytes is neither: under the compactc profile, which does not delete dead
//! instructions, every unread split stays in the circuit and is paid for
//! (notes/ir-passes.org, "Correction to the row table above").
//!
//! The field readers cover the widths a measured port needs, each checked
//! against compactc's artifact instruction for instruction
//! (`tests/attest_differential.rs`, `tests/serde_builtin_differential.rs` in
//! `minocrab-contracts`): `Boolean`, `Uint<8·LEN>` and `Bytes<32>`. Offsets
//! and widths are const generics, so a field that does not fit is a compile
//! error.

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab_std::v3::{rebuild_limb, BytesN, Vis3, B32};

/// The bytes of a packed struct (`Bytes<N>`, the struct at the start,
/// zero-padded), read field by field in compactc's shape.
pub struct Packed<'a, V: Vis3, const N: usize> {
    bytes: &'a BytesN<V, N>,
}

impl<'a, V: Vis3, const N: usize> Packed<'a, V, N> {
    pub fn new(bytes: &'a BytesN<V, N>) -> Self {
        Packed { bytes }
    }

    /// `bytes-ref(bytes, at)`: byte `at` of the string, 0 first. Byte `at`
    /// lives in the limb `at / 31` from the END of the slot order (the last
    /// limb holds bytes 0..31), `at % 31` bytes up.
    fn byte_at(&self, c: &mut Circuit3, at: usize) -> Wire3<FieldT, V> {
        let limbs = self.bytes.limbs();
        let limb = limbs[limbs.len() - 1 - at / 31];
        let (shifted, _) = c.div_mod_power_of_two(limb, 8 * (at % 31) as u32);
        let (_, byte) = c.div_mod_power_of_two(shifted, 8);
        byte
    }

    fn bytes_at(&self, c: &mut Circuit3, at: usize, len: usize) -> Vec<Wire3<FieldT, V>> {
        (at..at + len).map(|i| self.byte_at(c, i)).collect()
    }

    /// A `Boolean` field at byte `AT`: `bytes-ref(bytes, AT) == 1`. compactc
    /// 0.36 also constrains the byte to 0 or 1 (`constrain_to_boolean`), so a
    /// byte above 1 makes the call unprovable rather than reading false; the
    /// byte is then named (`copy`) and compared with 1.
    pub fn boolean<const AT: usize>(&self, c: &mut Circuit3) -> Wire3<FieldT, V> {
        const { assert!(AT < N, "a Boolean field must lie inside the Bytes<N>") };
        let byte = self.byte_at(c, AT);
        let byte = c.assert_boolean(byte);
        let named = c.copy(byte);
        c.test_eq(named, 1u64)
    }

    /// A `Uint<8·LEN>` field at bytes `AT..AT+LEN`, little-endian:
    /// `cast-from-bytes` of the slice. The slice becomes one limb (a single
    /// byte is named by a `copy`; more are folded by `reconstitute_field`,
    /// most significant first), the cast names it (`copy`) and range-checks
    /// it to `8·LEN` bits, which the bytes already imply. Returns the
    /// checked value.
    ///
    /// A `Uint<w>` whose width is not a whole number of bytes casts with a
    /// different check, and is not covered here.
    pub fn uint<const AT: usize, const LEN: usize>(&self, c: &mut Circuit3) -> Wire3<FieldT, V> {
        const {
            assert!(LEN >= 1 && LEN <= 31, "a Uint field here is 1..=31 bytes");
            assert!(AT + LEN <= N, "a Uint field must lie inside the Bytes<N>");
        };
        let bytes = self.bytes_at(c, AT, LEN);
        let limb = limb_of(c, &bytes);
        let value = c.copy(limb);
        c.assert_bits(value, 8 * LEN as u32)
    }

    /// A `Bytes<32>` field at bytes `AT..AT+32`: the slice, as the two limbs
    /// of a `Bytes<32>` in slot order. The high limb is the slice's last
    /// byte (named by a `copy`), the low limb its first 31 bytes folded by
    /// `reconstitute_field`. No range check: the bytes are bytes.
    pub fn bytes32<const AT: usize>(&self, c: &mut Circuit3) -> B32<V> {
        const { assert!(AT + 32 <= N, "a Bytes<32> field must lie inside the Bytes<N>") };
        let bytes = self.bytes_at(c, AT, 32);
        let hi = limb_of(c, &bytes[31..]);
        let lo = limb_of(c, &bytes[..31]);
        B32 { hi, lo }
    }
}

/// One limb from its bytes (least significant first), as compactc builds a
/// `Bytes` limb: a lone byte is named by a `copy`, more are folded by
/// `reconstitute_field` ([`rebuild_limb`]).
fn limb_of<V: Vis3>(c: &mut Circuit3, bytes: &[Wire3<FieldT, V>]) -> Wire3<FieldT, V> {
    match bytes {
        [byte] => c.copy(*byte),
        _ => rebuild_limb(c, bytes),
    }
}
