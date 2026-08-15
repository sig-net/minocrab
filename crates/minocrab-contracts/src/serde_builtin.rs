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

use minocrab::v3::Circuit3;
use minocrab::Private;
use minocrab_ledger::{counter_increment, emit};
use minocrab_std::v3::{bytes_to_b32, circuit, rebuild_limb, BytesN, Serializer};

/// Ledger field indices.
pub const CHECKS: u8 = 0;

/// `export circuit checkRoundtrip(bytes: Bytes<128>): []`
#[circuit]
pub fn check_roundtrip(c: &mut Circuit3, bytes: BytesN<Private, 128>) {
    let data = bytes;
    let one = c.constant(1u64);

    // const v = deserialize<Mixed, 128>(bytes)
    let bytes = data.to_le_bytes(c);
    let one_p = one.private();
    let flag = c.test_eq(bytes[0], one_p);
    let amount = rebuild_limb(c, &bytes[1..17]);
    let small = bytes[17];
    let tag = bytes_to_b32(c, &bytes[18..50]);

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

    emit(c, one, &counter_increment(CHECKS, 1));
}
