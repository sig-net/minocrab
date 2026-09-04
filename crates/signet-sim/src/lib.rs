//! The Sig Network MPC as a pure function — the `Responder` a Midnight
//! contract's tests drive instead of a cluster (M35 rung D,
//! notes/signet-async.org §6).
//!
//! The boundary it simulates is the PROTOCOL boundary: (the singleton's
//! `SignBidirectionalEvent`, the caller's ledger state, an EVM outcome) →
//! (the attestation the caller's settle circuit takes). Inside that
//! boundary it does what the MPC does, with the MPC's own code where the
//! MPC has any — [`reader`] and [`request_id`] are translated from
//! `sig-net/mpc` `chain-signatures/chain-midnight` and [`kdf`] from
//! `signet-crypto`, all at `b940f0a7`, pinned by the fixtures the MPC pins
//! itself against — so a record format that drifts from what the reader
//! decodes fails here the way it fails in production.
//!
//! The one thing it does not do is execute an EVM: the outcome is an
//! ORACLE the test supplies ([`EvmOutcome`]).
//!
//! What it can and cannot exercise today: the attestation it produces has
//! the wire shape and key the caller's settle circuit verifies, but driving
//! that circuit end to end needs a transcript executor for v3 circuits
//! (ledger reads answered from a live state), which this workspace does not
//! have — the harness item dmd holds in M26. Until that lands, the round
//! trip stops at the attestation, and the circuit-side acceptance is
//! covered by the vault harness's own signing model.

pub mod kdf;
pub mod reader;
pub mod records;
pub mod request_id;
pub mod sign;

use k256::{AffinePoint, ProjectivePoint, Scalar};
use midnight_onchain_state::state::{ContractState, StateValue};
use midnight_storage::DefaultDB;

use reader::{
    decode_notification, resolve_verified_record_v2, signet_field_node_by_path,
    unpack_notification_v1, Resolved, MISC_PAYLOAD_LEN,
};
use records::SignBidirectionalRecordV2;
use request_id::hash_payload;
pub use sign::Signature;

/// What happened on the destination chain — chosen by the test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvmOutcome {
    /// The transaction executed; `body` is the response body the MPC
    /// serializes for the record's kind (a Borsh `bool` for a transfer, a
    /// `u64` amount for a swap). The kind byte is prepended here.
    Executed { body: Vec<u8> },
    /// The transaction never executed: the MPC's failure output, one kind
    /// byte.
    NeverExecuted,
}

/// The MPC's answer: what the caller's settle circuit takes as its ticket.
#[derive(Debug, Clone, PartialEq)]
pub struct Attestation {
    pub request_id: [u8; 32],
    /// `serializedOutput` on the wire: the kind byte then the body.
    pub output: Vec<u8>,
    /// Over `keccak256(request_id ‖ output)`, under the response key.
    pub signature: Signature,
    /// The record the MPC read, for the test's own assertions.
    pub record: SignBidirectionalRecordV2,
}

/// Why the MPC would not sign — the reader's own drop reasons, by name.
#[derive(Debug, thiserror::Error)]
pub enum Refusal {
    #[error("notification: {0}")]
    Notification(String),
    #[error("ledger path: {0}")]
    Path(String),
    #[error("request id absent from the caller's index")]
    Absent,
    #[error("dropped ({reason}): {detail}")]
    Dropped { reason: &'static str, detail: String },
}

/// Everything the MPC does between seeing `SignBidirectionalEvent` and
/// calling `respondBidirectional`. Pure: no I/O, no clock.
pub trait Responder {
    fn respond(
        &mut self,
        event_payload: &[u8; MISC_PAYLOAD_LEN],
        caller_state: &StateValue<DefaultDB>,
        outcome: EvmOutcome,
    ) -> Result<Attestation, Refusal>;
}

/// The simulated MPC: one root key and the real derivation, so the response
/// key it signs under is the one a cluster with that root would derive for
/// the same caller — what a contract's `initialize` should store.
pub struct SigNetSim {
    root: Scalar,
    /// The response-kind byte the failure output carries.
    failure_kind: u8,
}

impl SigNetSim {
    pub fn new(root: Scalar, failure_kind: u8) -> Self {
        SigNetSim { root, failure_kind }
    }

    /// A root from a test seed.
    pub fn from_seed(seed: &[u8], failure_kind: u8) -> Self {
        let hash: [u8; 32] = <sha3::Keccak256 as sha3::Digest>::digest(seed).into();
        Self::new(sign::message_scalar(&hash), failure_kind)
    }

    /// The root public key.
    pub fn root_public_key(&self) -> AffinePoint {
        (ProjectivePoint::GENERATOR * self.root).to_affine()
    }

    /// The RESPONSE key for `caller` at `key_version`: derived under the
    /// fixed path `"midnight response key"` with the caller contract's
    /// address as the requester (the MPC's `respond_bidirectional_path`).
    pub fn response_key(&self, key_version: u32, caller: &[u8; 32]) -> AffinePoint {
        kdf::derive_key(self.root_public_key(), self.response_epsilon(key_version, caller))
    }

    fn response_epsilon(&self, key_version: u32, caller: &[u8; 32]) -> Scalar {
        kdf::derive_epsilon_midnight(key_version, &hex::encode(caller), kdf::MIDNIGHT_RESPOND_BIDIRECTIONAL_PATH)
    }

    /// The USER key a request signs its EVM transaction with, and its EVM
    /// address: `(key_version, requester = caller, path = hex(record.path))`.
    pub fn user_address(&self, record: &SignBidirectionalRecordV2, caller: &[u8; 32]) -> [u8; 20] {
        let epsilon = kdf::derive_epsilon_midnight(u32::from(record.key_version), &hex::encode(caller), &hex::encode(record.path));
        kdf::public_key_to_address(&kdf::derive_key(self.root_public_key(), epsilon))
    }

    /// The attestation digest: `keccak256(request_id ‖ output)`.
    pub fn attestation_digest(request_id: &[u8; 32], output: &[u8]) -> [u8; 32] {
        let mut combined = Vec::with_capacity(32 + output.len());
        combined.extend_from_slice(request_id);
        combined.extend_from_slice(output);
        hash_payload(&combined)
    }
}

impl Responder for SigNetSim {
    fn respond(
        &mut self,
        event_payload: &[u8; MISC_PAYLOAD_LEN],
        caller_state: &StateValue<DefaultDB>,
        outcome: EvmOutcome,
    ) -> Result<Attestation, Refusal> {
        let notification = decode_notification(event_payload);
        let unpacked = unpack_notification_v1(&notification).map_err(|e| Refusal::Notification(format!("{e:#}")))?;
        let map = signet_field_node_by_path(caller_state, &unpacked.requests_path).map_err(|e| Refusal::Path(format!("{e:#}")))?;
        let record = match resolve_verified_record_v2(map, notification.request_id) {
            Resolved::Found(record) => *record,
            Resolved::Absent => return Err(Refusal::Absent),
            Resolved::Dropped { reason, detail } => return Err(Refusal::Dropped { reason, detail }),
        };
        // The requester the key derives under is the address the record was
        // READ from — the notification's caller address — never the record's
        // own `sender` field (convert.rs's rule).
        let caller = unpacked.caller_address;
        let output = match outcome {
            EvmOutcome::Executed { body } => {
                let mut out = vec![record.response_kind];
                out.extend_from_slice(&body);
                out
            }
            EvmOutcome::NeverExecuted => vec![self.failure_kind],
        };
        let digest = Self::attestation_digest(&notification.request_id, &output);
        let d = self.root + self.response_epsilon(u32::from(record.key_version), &caller);
        let signature = sign::sign(&digest, &d);
        Ok(Attestation { request_id: notification.request_id, output, signature, record })
    }
}

/// Decode a `contract-state` blob down to the ledger root, over the
/// ledger's own deserializer.
pub fn decode_contract_state(bytes: &[u8]) -> anyhow::Result<StateValue<DefaultDB>> {
    let contract: ContractState<DefaultDB> = midnight_serialize::tagged_deserialize(&mut &bytes[..])?;
    Ok(contract.data.get_ref().clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use midnight_base_crypto::fab::{AlignedValue, Alignment, AlignmentAtom, AlignmentSegment, Value, ValueAtom};
    use midnight_storage::arena::Sp;
    use midnight_storage::storage::{Array, HashMap};
    use records::{CompactMaybe, EvmCalldata, EvmType2TxParams, RECORD_FORMAT_VERSION};
    use request_id::{binary_repr_v2, compute_request_id_v2};

    /// The MPC's captured caller state: the DEPLOYED-format record at ledger
    /// field 4 decodes and hashes back to its id — the regression the MPC
    /// keeps, now kept here against the same bytes.
    #[test]
    fn the_captured_caller_record_resolves_in_the_deployed_format() {
        let root = decode_contract_state(include_bytes!("../fixtures/caller-post-state-156.mn")).expect("the v8 blob deserializes at our ledger pin");
        let map = signet_field_node_by_path(&root, &[4]).unwrap();
        let mut id = [0u8; 32];
        hex::decode_to_slice("1cd10eb1f4fa5c665084d24a7982b09aa321886dce77d85b5f6feee0687a414b", &mut id).unwrap();
        match reader::resolve_verified_record(map, id) {
            Resolved::Found(record) => {
                assert_eq!(record.tx_param_type, 0);
                assert_eq!(request_id::compute_request_id(&record), id);
            }
            other => panic!("expected the captured record, got {other:?}"),
        }
        // And the stage-7 decoder REFUSES it by name: the format-version byte
        // is where the deployed record's sender starts.
        match resolve_verified_record_v2(map, id) {
            Resolved::Dropped { reason, .. } => assert_eq!(reason, "record-version"),
            other => panic!("expected a record-version drop, got {other:?}"),
        }
    }

    fn atom(bytes: &[u8], width: u32) -> (AlignmentSegment, ValueAtom) {
        // Stored trailing-zero-trimmed, as the ledger keeps them.
        let mut v = bytes.to_vec();
        while v.last() == Some(&0) {
            v.pop();
        }
        (AlignmentSegment::Atom(AlignmentAtom::Bytes { length: width }), ValueAtom(v))
    }

    /// A stage-7 record as the ledger would hold it: atoms at the widths
    /// `SignBidirectionalEventV2::atoms()` declares, values trimmed.
    fn v2_cell(record: &SignBidirectionalRecordV2) -> StateValue<DefaultDB> {
        let t = &record.tx_params;
        let mut atoms = vec![
            atom(&[record.format_version], 1),
            atom(&record.sender, 32),
            atom(&record.request_nonce.to_le_bytes(), 8),
            atom(&[record.key_version], 1),
            atom(&record.path, 32),
            atom(&[record.algo], 1),
            atom(&[record.dest], 1),
            atom(&record.params, 64),
            atom(&[record.tx_param_type], 1),
            atom(&t.chain_id.to_le_bytes(), 8),
            atom(&t.nonce.to_le_bytes(), 8),
            atom(&t.max_priority_fee_per_gas.to_le_bytes(), 16),
            atom(&t.max_fee_per_gas.to_le_bytes(), 16),
            atom(&t.gas_limit.to_le_bytes(), 8),
            atom(&t.to, 20),
            atom(&t.value.to_le_bytes(), 16),
            atom(&[u8::from(t.calldata.is_some)], 1),
            atom(&t.calldata.value.selector, 4),
            atom(&t.calldata.value.no_words.to_le_bytes(), 2),
        ];
        for w in &t.calldata.value.words {
            atoms.push(atom(w, 32));
        }
        atoms.push(atom(&[t.access_list_entry_count], 1));
        atoms.push(atom(&record.caip2_id, 32));
        atoms.push(atom(&[record.response_kind], 1));
        let (alignment, value): (Vec<_>, Vec<_>) = atoms.into_iter().unzip();
        StateValue::Cell(Sp::new(AlignedValue { alignment: Alignment(alignment), value: Value(value) }))
    }

    fn sample_v2() -> SignBidirectionalRecordV2 {
        let mut caip2 = [0u8; 32];
        caip2[..10].copy_from_slice(b"eip155:1  ");
        caip2[8] = 0;
        caip2[9] = 0;
        SignBidirectionalRecordV2 {
            format_version: RECORD_FORMAT_VERSION,
            sender: [0xe4; 32],
            request_nonce: 7,
            key_version: 1,
            path: [0xab; 32],
            algo: 0,
            dest: 0,
            params: [0u8; 64],
            tx_param_type: 0,
            tx_params: EvmType2TxParams {
                chain_id: 31337,
                nonce: 3,
                max_priority_fee_per_gas: 1_000_000_000,
                max_fee_per_gas: 30_000_000_000,
                gas_limit: 100_000,
                to: [0x42; 20],
                value: 0,
                calldata: CompactMaybe {
                    is_some: true,
                    value: EvmCalldata { selector: [0xa9, 0x05, 0x9c, 0xbb], no_words: 2, words: vec![[1u8; 32], [2u8; 32]] },
                },
                access_list_entry_count: 0,
                access_list: vec![],
            },
            caip2_id: caip2,
            response_kind: 0,
        }
    }

    /// The stage-7 decode round-trips a ledger cell, and the id it recomputes
    /// is keccak over the FAB binary representation of that cell — which is
    /// what the circuit hashes (`calculate_request_id_v2`).
    #[test]
    fn a_stage_7_record_decodes_and_hashes_like_its_fab_representation() {
        use midnight_base_crypto::repr::BinaryHashRepr;
        use midnight_transient_crypto::fab::ValueReprAlignedValue;
        let record = sample_v2();
        let cell = v2_cell(&record);
        let decoded = reader::decode_record_v2(&cell).unwrap();
        assert_eq!(decoded, record);
        let StateValue::Cell(aligned) = &cell else { unreachable!() };
        let mut fab = Vec::new();
        ValueReprAlignedValue((**aligned).clone()).binary_repr(&mut fab);
        assert_eq!(fab, binary_repr_v2(&record), "the reader's preimage is the FAB repr");
        assert_eq!(compute_request_id_v2(&record), hash_payload(&fab));
    }

    fn map_with(record: &SignBidirectionalRecordV2) -> ([u8; 32], StateValue<DefaultDB>) {
        let id = compute_request_id_v2(record);
        let mut map: HashMap<AlignedValue, StateValue<DefaultDB>, DefaultDB> = HashMap::new();
        map = map.insert(AlignedValue::from(id), v2_cell(record));
        (id, StateValue::Map(map))
    }

    fn root_of(map: StateValue<DefaultDB>) -> StateValue<DefaultDB> {
        StateValue::Array(Array::from(vec![StateValue::Null, map]))
    }

    fn payload(id: [u8; 32], caller: [u8; 32], path: &[u8]) -> [u8; MISC_PAYLOAD_LEN] {
        let mut p = [0u8; MISC_PAYLOAD_LEN];
        p[0] = 1;
        p[1..33].copy_from_slice(&id);
        p[33..65].copy_from_slice(&caller);
        p[65] = path.len() as u8;
        p[66..66 + path.len()].copy_from_slice(path);
        p
    }

    /// The whole responder: notification → path walk → verified record →
    /// output → signature under the derived response key, which verifies.
    #[test]
    fn the_sim_signs_under_the_derived_response_key() {
        let record = sample_v2();
        let (id, map) = map_with(&record);
        let root = root_of(map);
        let caller = [0x11u8; 32];
        let mut sim = SigNetSim::from_seed(b"root", 3);
        let att = sim.respond(&payload(id, caller, &[1]), &root, EvmOutcome::Executed { body: vec![1] }).unwrap();
        assert_eq!(att.output, vec![0, 1], "kind byte then body");
        let digest = SigNetSim::attestation_digest(&id, &att.output);
        assert!(sign::verify(&digest, &att.signature, &sim.response_key(1, &caller)));
        // A different caller derives a different response key.
        assert!(!sign::verify(&digest, &att.signature, &sim.response_key(1, &[0x22; 32])));
        // The failure output is the failure kind alone.
        let failed = sim.respond(&payload(id, caller, &[1]), &root, EvmOutcome::NeverExecuted).unwrap();
        assert_eq!(failed.output, vec![3]);
    }

    /// The reader's drops, by name: an unfiled id, a spoofed record, a wrong
    /// path, an unsupported notification version.
    #[test]
    fn the_sim_refuses_what_the_reader_refuses() {
        let record = sample_v2();
        let (id, map) = map_with(&record);
        let root = root_of(map);
        let caller = [0x11u8; 32];
        let mut sim = SigNetSim::from_seed(b"root", 3);
        let mut other = id;
        other[0] ^= 1;
        assert!(matches!(sim.respond(&payload(other, caller, &[1]), &root, EvmOutcome::NeverExecuted), Err(Refusal::Absent)));
        assert!(matches!(sim.respond(&payload(id, caller, &[0]), &root, EvmOutcome::NeverExecuted), Err(Refusal::Dropped { reason: "request-index-not-a-map", .. })));
        let mut bad_version = payload(id, caller, &[1]);
        bad_version[0] = 2;
        assert!(matches!(sim.respond(&bad_version, &root, EvmOutcome::NeverExecuted), Err(Refusal::Notification(_))));
        // Spoofed: filed under an id it does not hash to.
        let mut spoofed = record.clone();
        spoofed.request_nonce += 1;
        let mut map2: HashMap<AlignedValue, StateValue<DefaultDB>, DefaultDB> = HashMap::new();
        map2 = map2.insert(AlignedValue::from(id), v2_cell(&spoofed));
        let root2 = root_of(StateValue::Map(map2));
        assert!(matches!(sim.respond(&payload(id, caller, &[1]), &root2, EvmOutcome::NeverExecuted), Err(Refusal::Dropped { reason: "rid-mismatch", .. })));
    }
}
