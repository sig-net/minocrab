//! `serde-builtin` (signet-midnight-experiments) — pins the builtin
//! serialize/deserialize byte layout. Only `checkRoundtrip` compiles to
//! ZKIR (the `ser*`/`de*` circuits are pure):
//!
//! ```text
//! export ledger checks: Counter;                    // field 0
//! struct Mixed { flag: Boolean; amount: Uint<128>; small: Uint<8>; tag: Bytes<32> }
//!
//! checkRoundtrip(bytes: Bytes<128>):
//!   const v = deserialize<Mixed, 128>(bytes);
//!   assert(serialize<Mixed, 128>(v) == bytes, "serialize/deserialize roundtrip mismatch");
//!   checks.increment(1);
//! ```
//! Mixed layout: flag @0 (1 byte, == 1), amount @1..17 (LE), small @17,
//! tag @18..50, zero padding to 128.

use minocrab::Circuit;
use minocrab::Private;
use minocrab_experimental::impact::raw::{counter_increment, emit};
use minocrab_compat::deserialize::Packed;
use minocrab_std::{contract, BytesN, Discloses, Serializer};

/// Ledger field indices.
pub const CHECKS: u8 = 0;

/// `serde-builtin` — the one circuit that compiles to ZKIR.
pub struct SerdeBuiltin;

#[contract(lowering = minocrab_compat::profile)]
impl SerdeBuiltin {
    /// `export circuit checkRoundtrip(bytes: Bytes<128>): []`
    ///
    /// `Discloses<()>` is the positive statement that this circuit reveals
    /// NOTHING: the roundtrip is checked entirely inside the private domain, and
    /// only the counter increment is public. The generated test says so.
    #[circuit]
    pub fn check_roundtrip(c: &mut Circuit, bytes: BytesN<Private, 128>) -> Discloses<()> {
        let data = bytes;

        // const v = deserialize<Mixed, 128>(bytes), in compactc's shape: the
        // 50 bytes the fields occupy are split, one field at a time; the 78
        // padding bytes are not (the round trip below compares them, limb by
        // limb, with the zeros the serializer writes). The flag byte is
        // constrained to 0 or 1, the Uints are range-checked, as compactc's.
        let packed = Packed::new(&data);
        let (flag, amount, small, tag) = c.region("deserialize Mixed", |c| {
            (packed.boolean::<0>(c), packed.uint::<1, 16>(c), packed.uint::<17, 1>(c), packed.bytes32::<18>(c))
        });

        // serialize<Mixed, 128>(v)
        let mut s = Serializer::<Private>::new();
        s.push_uint(flag, 1); // Boolean: the 0/1 wire as one byte
        s.push_uint(amount, 16);
        s.push_uint(small, 1);
        s.push_b32(&tag);
        let reserialized = s.finish::<128>(c);

        // assert(… == bytes): limbwise equality, folded by multiplication.
        let mut all = c.constant(1u64).private();
        for (ours, theirs) in reserialized.limbs().iter().zip(data.limbs()) {
            let eq = c.test_eq(*ours, *theirs);
            all = c.mul(all, eq);
        }
        c.assert(all); // "serialize/deserialize roundtrip mismatch"

        emit(c, &counter_increment(CHECKS, 1));
        Discloses::of(())
    }
}
