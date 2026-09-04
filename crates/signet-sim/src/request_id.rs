//! The request-id twin: keccak256 over the record's byte layout.
//!
//! MECHANICAL TRANSLATION of `chain-midnight/src/request_id.rs` at
//! `b940f0a7`, with the stage-7 twin beside it (the version byte in front,
//! the kind byte where the schemas were, nothing else moved).

use sha3::{Digest, Keccak256};

use crate::records::{
    CompactMaybe, EvmAccessListEntry, EvmCalldata, EvmType2TxParams, SignBidirectionalRecord,
    SignBidirectionalRecordV2,
};

/// `hash_payload`: keccak256.
pub fn hash_payload(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// The request id the contract mints for `record` (deployed format).
pub fn compute_request_id(record: &SignBidirectionalRecord) -> [u8; 32] {
    hash_payload(&binary_repr(record))
}

/// The request id the contract mints for a stage-7 `record`.
pub fn compute_request_id_v2(record: &SignBidirectionalRecordV2) -> [u8; 32] {
    hash_payload(&binary_repr_v2(record))
}

/// The hash preimage: each field at its declared width, in declaration order.
pub fn binary_repr(record: &SignBidirectionalRecord) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&record.sender);
    buf.extend_from_slice(&record.request_nonce.to_le_bytes());
    buf.push(record.key_version);
    buf.extend_from_slice(&record.path);
    buf.push(record.algo);
    buf.push(record.dest);
    buf.extend_from_slice(&record.params);
    buf.push(record.tx_param_type);
    push_tx_params(&mut buf, &record.tx_params);
    buf.extend_from_slice(&record.caip2_id);
    buf.extend_from_slice(&record.output_deserialization_schema);
    buf.extend_from_slice(&record.respond_serialization_schema);
    buf
}

/// The stage-7 preimage.
pub fn binary_repr_v2(record: &SignBidirectionalRecordV2) -> Vec<u8> {
    let mut buf = vec![record.format_version];
    buf.extend_from_slice(&record.sender);
    buf.extend_from_slice(&record.request_nonce.to_le_bytes());
    buf.push(record.key_version);
    buf.extend_from_slice(&record.path);
    buf.push(record.algo);
    buf.push(record.dest);
    buf.extend_from_slice(&record.params);
    buf.push(record.tx_param_type);
    push_tx_params(&mut buf, &record.tx_params);
    buf.extend_from_slice(&record.caip2_id);
    buf.push(record.response_kind);
    buf
}

fn push_tx_params(buf: &mut Vec<u8>, params: &EvmType2TxParams) {
    buf.extend_from_slice(&params.chain_id.to_le_bytes());
    buf.extend_from_slice(&params.nonce.to_le_bytes());
    buf.extend_from_slice(&params.max_priority_fee_per_gas.to_le_bytes());
    buf.extend_from_slice(&params.max_fee_per_gas.to_le_bytes());
    buf.extend_from_slice(&params.gas_limit.to_le_bytes());
    buf.extend_from_slice(&params.to);
    buf.extend_from_slice(&params.value.to_le_bytes());
    push_calldata(buf, &params.calldata);
    buf.push(params.access_list_entry_count);
    for entry in &params.access_list {
        push_access_list_entry(buf, entry);
    }
}

fn push_calldata(buf: &mut Vec<u8>, calldata: &CompactMaybe<EvmCalldata>) {
    buf.push(u8::from(calldata.is_some));
    buf.extend_from_slice(&calldata.value.selector);
    buf.extend_from_slice(&calldata.value.no_words.to_le_bytes());
    for word in &calldata.value.words {
        buf.extend_from_slice(word);
    }
}

fn push_access_list_entry(buf: &mut Vec<u8>, entry: &EvmAccessListEntry) {
    buf.extend_from_slice(&entry.address);
    buf.push(entry.storage_key_count);
    for storage_key in &entry.storage_keys {
        buf.extend_from_slice(storage_key);
    }
}
