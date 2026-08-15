//! Hashing builtins over bundles, lowered exactly as compactc lowers them
//! (notes/builtin-lowering.org §§2-5).
//!
//! EVERYTHING HERE IS THE COMPACT (FAB) FLAVOR, by definition: this is the v2
//! layer, whose whole job is to reproduce compactc's own lowering for the
//! compat ports, so a preimage is `binary_repr`/`field_repr` and there is no
//! choice to make. The flavor SPLIT — a value's Borsh encoding as the default
//! preimage, FAB kept for Compact-interop digest agreement — lives one layer
//! up, in [`crate::v3::hash`], where the `_compact` suffix marks these
//! semantics. Nothing here is renamed: the ports call these by the names
//! compactc's builtins have.

use minocrab::{Circuit, Wire};

use crate::bundle::{Bundle, Vis};
use crate::types::Bytes32;

/// `transientHash<T>(value)`: Poseidon over the flattened slots.
pub fn transient_hash<V: Vis, B: Bundle<V>>(c: &mut Circuit, value: &B) -> Wire<V> {
    c.transient_hash(&value.wires())
}

/// `transientCommit<T>(value, rand)`: the same gate with `rand` in front.
pub fn transient_commit<V: Vis, B: Bundle<V>>(
    c: &mut Circuit,
    value: &B,
    rand: Wire<V>,
) -> Wire<V> {
    let mut inputs = vec![rand];
    value.push_wires(&mut inputs);
    c.transient_hash(&inputs)
}

/// `persistentHash<T>(value)`: SHA-256 of the FAB binary form; the digest is
/// a `Bytes<32>` whose two slots the instruction produces as [hi, lo].
pub fn persistent_hash<V: Vis, B: Bundle<V>>(c: &mut Circuit, value: &B) -> Bytes32<V> {
    let (hi, lo) = c.persistent_hash(B::alignment(), &value.wires());
    Bytes32::from_limbs(vec![hi, lo])
}

/// `persistentCommit<T>(value, rand)`: one `persistent_hash` whose preimage
/// is rand-then-value — alignment `bytes 32` consed onto T's atoms.
pub fn persistent_commit<V: Vis, B: Bundle<V>>(
    c: &mut Circuit,
    value: &B,
    rand: &Bytes32<V>,
) -> Bytes32<V> {
    let alignment = <(Bytes32<V>, B)>::alignment();
    let mut inputs = rand.wires();
    value.push_wires(&mut inputs);
    let (hi, lo) = c.persistent_hash(alignment, &inputs);
    Bytes32::from_limbs(vec![hi, lo])
}

/// `degradeToTransient(b)`: the low limb (bytes 0..30 LE; byte 31 is
/// discarded). Zero instructions — a slot re-binding.
pub fn degrade_to_transient<V: Vis>(b: &Bytes32<V>) -> Wire<V> {
    b.lo()
}

/// `upgradeFromTransient(f)`: low 31 bytes of the field element, byte 31 =
/// 0 (the top ~7 bits are dropped): `div_mod_power_of_two(f, 248)` keeping
/// the remainder, hi = literal 0.
pub fn upgrade_from_transient<V: Vis>(c: &mut Circuit, f: Wire<V>) -> Bytes32<V> {
    let (_quotient, lo) = c.div_mod_power_of_two(f, 248);
    let hi = V::from_public(c.constant(0u64));
    Bytes32::from_limbs(vec![hi, lo])
}

