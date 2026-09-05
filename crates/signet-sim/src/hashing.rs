//! Compact-compatible hashing for the protocol values — the MPC's
//! `chain-midnight/src/hashing.rs` and `compact-hashing/src/lib.rs` at
//! `10360c3c` (develop, 2026-09-05; "fix(midnight): align Compact hashing",
//! #1206), translated. Both are Poseidon (`transient_hash`) over the FAB
//! field representation, upgraded to 32 bytes — what the Signet module
//! computes in-circuit since signet-midnight `fff3421c`.

use midnight_base_crypto::fab::AlignedValue;
use midnight_transient_crypto::fab::AlignedValueExt as _;
use midnight_transient_crypto::hash::{transient_hash, upgrade_from_transient};
use midnight_transient_crypto::repr::FieldRepr as _;
use sha3::{Digest, Keccak256};

/// The request id the contract mints for a stored request-record cell:
/// Poseidon over the cell's value-only field representation (one field
/// element per FAB limb, in slot order), upgraded to `Bytes<32>`.
pub fn compute_request_id(cell: &AlignedValue) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(cell.value_only_field_size());
    cell.value_only_field_repr(&mut preimage);
    upgrade_from_transient(transient_hash(&preimage)).0
}

/// The attestation digest: Poseidon over the field representation of the
/// request id (32 bytes → two field elements) followed by the serialized
/// output's, upgraded to `Bytes<32>`.
pub fn compute_response_hash(request_id: &[u8; 32], serialized_output: &[u8]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(request_id.field_size() + serialized_output.field_size());
    request_id.field_repr(&mut preimage);
    serialized_output.field_repr(&mut preimage);
    upgrade_from_transient(transient_hash(&preimage)).0
}

/// The LEGACY request id — keccak256 over the record's byte layout — which
/// is what the DEPLOYED singleton's callers minted before `fff3421c` and
/// what the MPC's captured fixture carries. Kept so the fixture stays
/// readable under the rule it was filed under.
pub fn legacy_request_id(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The MPC's own golden (`compact-hashing`): thirty-two output bytes
    /// cross the 31-byte field-packing boundary.
    #[test]
    fn response_hash_matches_compact_golden() {
        let serialized_output = (1..=32).collect::<Vec<_>>();
        assert_eq!(
            hex::encode(compute_response_hash(&[0x2f; 32], &serialized_output)),
            "61c48f724b114d830caafcb9722b07c5428e2b906b5a61afa26c063735722700"
        );
    }
}
