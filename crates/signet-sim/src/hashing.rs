//! Compact-compatible hashing for the protocol values — the MPC's
//! `chain-midnight/src/hashing.rs` and `compact-hashing/src/lib.rs` at
//! `10360c3c` (develop; "fix(midnight): align Compact hashing",
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

/// The legacy request id — keccak256 over the record's byte layout — which
/// is what the deployed signet signer's callers minted before `fff3421c` and
/// what the MPC's captured fixture carries. Kept so the fixture stays
/// readable under the rule it was filed under.
pub fn legacy_request_id(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

/// The V1 hashes — `@sig-net/midnight` 0.24.1, translated from
/// `minocrab_contracts::signet_v1` (the MPC's own reader has not
/// moved, see [`crate::records::SignBidirectionalRecordV1`]).
///
/// Three differences from the `fff3421c` rules above, and each one is why a
/// V1 attestation cannot be produced by the V2 code path:
///
/// - every hash is prefixed with a [`v1::hash_domain`] tag, so a transaction
///   digest and a request id over the same limbs differ;
/// - the request id hashes a seven-field preimage whose transaction enters as
///   its own digest, which in turn hashes only the used calldata words —
///   never the whole record cell;
/// - the attestation digest commits to the block height, the MPC's verdict
///   and the output's width beside the output itself.
pub mod v1 {
    use midnight_transient_crypto::curve::Fr;
    use midnight_transient_crypto::hash::{transient_hash, upgrade_from_transient};

    /// `enum HashDomain` — the u8 index every V1 hash is prefixed with.
    pub mod hash_domain {
        pub const REQUEST_ID: u64 = 0;
        pub const ATTESTATION_DIGEST: u64 = 1;
        pub const EVM_TYPE2_TX_HEADER: u64 = 2;
        pub const EVM_TYPE2_TX_WORD: u64 = 3;
    }

    /// `enum OutputKind` — the MPC's verdict.
    pub mod output_kind {
        pub const EXECUTED: u64 = 0;
        pub const FAILED: u64 = 1;
        pub const UNVIABLE: u64 = 2;
    }

    /// `pad(64, "eip155:1")` — `executionDest` for every Ethereum network.
    pub fn ethereum_caip2_id() -> [u8; 64] {
        signet_hashing::ETHEREUM_CAIP2_ID
    }

    /// A `Bytes<32>`'s FAB slot pair — `hi` is byte 31, `lo` is bytes 0..30.
    pub fn b32_slots(bytes: &[u8; 32]) -> (Fr, Fr) {
        (
            Fr::from(u64::from(bytes[31])),
            Fr::from_le_bytes(&bytes[..31]).expect("31 bytes fit a limb"),
        )
    }

    fn limb(bytes: &[u8]) -> Fr {
        Fr::from_le_bytes(bytes).expect("at most 31 bytes fit a limb")
    }

    /// `calculateEvmType2TxParamsDigestV1` over an empty access list: the
    /// tagged head, then each used word chained on under its own tag.
    ///
    /// `calldata` is `None` for a transaction with no calldata, in which case
    /// `is_some`, the selector and the word count all enter as zero — the
    /// source's `calldata.is_some ? … : default`.
    #[allow(clippy::too_many_arguments)]
    pub fn tx_params_digest(
        chain_id: u64,
        nonce: u64,
        max_priority_fee_per_gas: u128,
        max_fee_per_gas: u128,
        gas_limit: u64,
        to: &[u8; 20],
        value: u128,
        calldata: Option<(&[u8; 4], &[[u8; 32]])>,
    ) -> [u8; 32] {
        let (is_some, selector, words): (u64, Fr, &[[u8; 32]]) = match calldata {
            Some((sel, words)) => (1, limb(sel), words),
            None => (0, Fr::from(0u64), &[]),
        };
        let mut acc = transient_hash(&[
            Fr::from(hash_domain::EVM_TYPE2_TX_HEADER),
            Fr::from(chain_id),
            Fr::from(nonce),
            limb(&max_priority_fee_per_gas.to_le_bytes()),
            limb(&max_fee_per_gas.to_le_bytes()),
            Fr::from(gas_limit),
            limb(to),
            limb(&value.to_le_bytes()),
            Fr::from(is_some),
            selector,
            Fr::from(words.len() as u64),
            Fr::from(0u64), // accessListEntryCount
        ]);
        for w in words {
            let (hi, lo) = b32_slots(w);
            acc = transient_hash(&[Fr::from(hash_domain::EVM_TYPE2_TX_WORD), acc, hi, lo]);
        }
        upgrade_from_transient(acc).0
    }

    /// `calculateRequestIdV1(RequestIdPreimageV1 { keyVersion, sender, path,
    /// algo, txParamType, txParamsDigest, executionDest })` — `signet-hashing`'s.
    pub fn request_id(
        key_version: u8,
        sender: &[u8; 32],
        path: &[u8; 32],
        algo: u8,
        tx_param_type: u8,
        tx_params_digest: &[u8; 32],
        execution_dest: &[u8; 64],
    ) -> [u8; 32] {
        assert_eq!((algo, tx_param_type), (0, 0), "the sim signs ecdsa evmType2 requests only");
        signet_hashing::request_id(&signet_hashing::RequestIdPreimage {
            key_version,
            sender: *sender,
            path: *path,
            algo: signet_hashing::SignatureAlgorithm::Ecdsa,
            tx_param_type: signet_hashing::TxParamType::EvmType2,
            tx_params_digest: *tx_params_digest,
            execution_dest: *execution_dest,
        })
    }

    /// The request id of a decoded V1 record: its own transaction digested
    /// over the words its `noWords` declares used, then
    /// [`request_id`]. This is how a reader verifies that a record was filed
    /// under the id it is keyed by.
    pub fn record_request_id(record: &crate::records::SignBidirectionalRecordV1) -> [u8; 32] {
        let t = &record.tx_params;
        let used = usize::from(t.calldata.value.no_words).min(t.calldata.value.words.len());
        let digest = if t.calldata.is_some {
            tx_params_digest(
                t.chain_id,
                t.nonce,
                t.max_priority_fee_per_gas,
                t.max_fee_per_gas,
                t.gas_limit,
                &t.to,
                t.value,
                Some((&t.calldata.value.selector, &t.calldata.value.words[..used])),
            )
        } else {
            tx_params_digest(
                t.chain_id,
                t.nonce,
                t.max_priority_fee_per_gas,
                t.max_fee_per_gas,
                t.gas_limit,
                &t.to,
                t.value,
                None,
            )
        };
        request_id(
            record.key_version,
            &record.sender,
            &record.path,
            record.algo,
            record.tx_param_type,
            &digest,
            &record.execution_dest,
        )
    }

    /// `calculateSignetAttestationDigestV1(requestId, blockHeight,
    /// outputKind, serializedOutputLength, outputHash)` over
    /// `serialized_output` — `signet-hashing`'s, with the width and the
    /// hash taken from the output itself, so the caller cannot sign a width
    /// it did not produce. Returns `(outputHash, digest)`.
    pub fn attestation_digest(
        request_id: &[u8; 32],
        block_height: u64,
        output_kind: u64,
        serialized_output: &[u8],
    ) -> ([u8; 32], [u8; 32]) {
        let kind = signet_hashing::OutputKind::ALL[output_kind as usize];
        let a = signet_hashing::Attestation::over(request_id, block_height, kind, serialized_output)
            .expect("a non-execution attests an empty output");
        (a.output_hash, a.digest)
    }

    /// A `Bytes<N>`'s FAB limbs in slot order: the leftover
    /// most-significant chunk first, then 31-byte limbs — `[]` for `Bytes<0>`,
    /// one limb for `Bytes<1>`, `[hi, lo]` for `Bytes<32>`.
    pub fn output_limbs(bytes: &[u8]) -> Vec<Fr> {
        let mut limbs: Vec<Fr> = bytes.chunks(31).map(limb).collect();
        limbs.reverse();
        limbs
    }
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
