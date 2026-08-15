//! The two conformance oracles and the schema walk.
//!
//! The format is Borsh, restricted to the fixed-width subset
//! (notes/borsh-format.org): every byte emitted is valid canonical Borsh for
//! the declared types. serde + bincode's fixint/little-endian mode emits the
//! same bytes for that subset, which makes it a second, INDEPENDENT witness:
//! a spec type that stays inside the subset makes the two agree byte for
//! byte, and one that strays (a data-carrying tag, a length-prefixed
//! sequence) makes them disagree. Running both is how the suite tells
//! "conformant" from "borsh happens to encode whatever I wrote".

use borsh::BorshSerialize;
use serde::Serialize;

/// The schema walk itself now lives in `minocrab_std::v3::borsh::schema`
/// (M11 stage 3), so the derive's generated `#[borsh(spec = …)]` cross-check
/// and this suite use ONE walker rather than two. Re-exported here because
/// the stage-0 tests were written against these names.
pub use minocrab_std::v3::borsh::schema::{layout_rows, schema_len, Row};

/// Oracle 1: canonical Borsh.
pub fn borsh_bytes<T: BorshSerialize>(value: &T) -> Vec<u8> {
    borsh::to_vec(value).expect("spec types serialize infallibly")
}

/// Oracle 2: serde through bincode in FIXED-WIDTH LITTLE-ENDIAN mode.
///
/// Spelled out rather than taken from `config::legacy()`: fixed integers
/// (bincode's default is varint, which would make every offset
/// value-dependent — the very thing the subset excludes), little-endian, no
/// length limit.
pub fn bincode_fixint_bytes<T: Serialize>(value: &T) -> Vec<u8> {
    let config = bincode::config::standard()
        .with_fixed_int_encoding()
        .with_little_endian()
        .with_no_limit();
    bincode::serde::encode_to_vec(value, config).expect("spec types serialize infallibly")
}
