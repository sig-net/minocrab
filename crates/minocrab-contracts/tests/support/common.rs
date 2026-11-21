//! Small helpers the differential suites share: reading a corpus artifact,
//! the identifier-renaming canonical form, and the FAB encodings of a
//! `Bytes<N>` value and of a `Bytes<32>`'s two field slots.
//!
//! `support/mod.rs` declares this as `support::common` and re-exports it;
//! a test binary that does not need the rest of `support` (which builds
//! every circuit of the workspace) declares this file alone by path:
//!
//! ```ignore
//! #[path = "support/common.rs"]
//! mod common;
//! ```
//!
//! Each binary uses only part of it, hence the blanket `dead_code`
//! allowance, as in `support/mod.rs`.
#![allow(dead_code)]

use midnight_base_crypto::fab::{AlignedValue, Alignment, AlignmentAtom, AlignmentSegment, Value, ValueAtom};
use minocrab::Fr;
use minocrab_zkir::v3::{to_zkir_string, IrSource};

/// A compactc artifact from the pinned corpus:
/// `corpus/zkir/{dir}/{name}.zkir`.
pub fn corpus_zkir(dir: &str, name: &str) -> IrSource {
    let path = format!("{}/../../corpus/zkir/{dir}/{name}.zkir", env!("CARGO_MANIFEST_DIR"));
    minocrab_zkir::v3::read_zkir(&path).expect("corpus golden parses")
}

/// A circuit's serialized ZKIR with every `%identifier` renamed to `%k` in
/// order of first appearance, so two streams that differ only in naming
/// compare equal.
///
/// BOTH SIDES are folded first (notes/ir-passes.org §2 ii): our builder
/// inlines a `Copy` of an immediate at `finish`, and compactc names some of
/// the constants it inlines elsewhere, so the comparison is instruction for
/// instruction MODULO the naming of constants — a rename with no rows, no
/// public input and no semantics. Everything else still compares exactly.
pub fn canonical(ir: &IrSource) -> String {
    let ir = &minocrab_compat::normalise::folded(ir);
    canonicalize(&to_zkir_string(ir).expect("serializes"))
}

/// [`canonical`]'s renaming, on any text.
pub fn canonicalize(text: &str) -> String {
    let mut renames: Vec<(String, String)> = Vec::new();
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('%') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let end = rest[1..]
            .find(|ch: char| !(ch.is_alphanumeric() || ch == '_' || ch == '.'))
            .map(|i| i + 1)
            .unwrap_or(rest.len());
        let name = &rest[..end];
        let next = renames.len();
        let canon = match renames.iter().find(|(from, _)| from == name) {
            Some((_, to)) => to.clone(),
            None => {
                let to = format!("%{next}");
                renames.push((name.to_string(), to.clone()));
                to
            }
        };
        out.push_str(&canon);
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// A `Bytes<n>` alignment atom.
pub fn atom(n: u32) -> AlignmentSegment {
    AlignmentSegment::Atom(AlignmentAtom::Bytes { length: n })
}

/// A `Bytes<n>` value: one normalized atom.
pub fn bytesn_value(n: u32, bytes: &[u8]) -> AlignedValue {
    AlignedValue::new(Value(vec![ValueAtom(bytes.to_vec()).normalize()]), Alignment(vec![atom(n)]))
        .expect("the bytes fit the atom")
}

/// A `Bytes<32>`'s two field slots, as compactc lays them out: the last
/// byte, then the first thirty-one little-endian.
pub fn b32_slots(bytes: &[u8; 32]) -> (Fr, Fr) {
    (Fr::from(u64::from(bytes[31])), Fr::from_le_bytes(&bytes[..31]).expect("31 bytes fit"))
}
