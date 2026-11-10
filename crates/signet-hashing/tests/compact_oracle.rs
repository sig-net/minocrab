//! The hashes against the COMPILED Compact circuits.
//!
//! `fixtures/api-parity-vectors.json` was produced by running the Signet
//! module's exported pure circuits (`calculateEvmType2RequestIdV1_*`,
//! `calculateEvmType2TxParamsDigestV1_*`, `calculateAttestedOutputHash*`,
//! `calculateSignetAttestationDigestV1`) under compactc 0.33.0-rc.2 over
//! `@sig-net/midnight@0.25.0-rc.1` (`350f9a3`; the hashing is unchanged at
//! v0.25.0), captured by sig-net/mpc for its own `compact-hashing` crate. No
//! Rust hash took part in producing the expected bytes, so agreement here is
//! agreement with the circuits a client contract runs.
//!
//! A request vector is the record's FAB atoms in slot order (hex, trailing
//! zeros trimmed) with their widths, so the record is decoded here the way
//! the MPC decodes a ledger cell — which also pins the struct shapes the
//! atoms imply: `EvmType2TxParams<1, 0, 0>`, `<0, 0, 0>`, `<1, 2, 3>` and
//! `<2, 2, 3>`.

use serde_json::Value;
use signet_hashing::{
    attestation_digest, attested_output_hash, evm_type2_tx_params_digest, Attestation,
    EvmAccessListEntry, EvmCalldata, EvmType2TxParams, OutputKind, SignBidirectionalRecord,
    SignatureAlgorithm, SignatureDestination, TxParams,
};

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/api-parity-vectors.json")).unwrap()
}

fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

/// One FAB atom: its bytes right-padded with zeros to `width`.
struct Atom(Vec<u8>);

impl Atom {
    fn bytes<const N: usize>(&self) -> [u8; N] {
        assert_eq!(self.0.len(), N);
        self.0.clone().try_into().unwrap()
    }
    fn uint(&self) -> u128 {
        let mut le = [0u8; 16];
        le[..self.0.len()].copy_from_slice(&self.0);
        u128::from_le_bytes(le)
    }
    fn u8(&self) -> u8 {
        u8::try_from(self.uint()).unwrap()
    }
}

fn atoms(vector: &Value) -> Vec<Atom> {
    let hexes = vector["atoms"].as_array().unwrap();
    let widths = vector["widths"].as_array().unwrap();
    assert_eq!(hexes.len(), widths.len());
    hexes
        .iter()
        .zip(widths)
        .map(|(h, w)| {
            let mut bytes = hex::decode(h.as_str().unwrap()).unwrap();
            let width = w.as_u64().unwrap() as usize;
            assert!(bytes.len() <= width, "atom wider than its declared width");
            bytes.resize(width, 0);
            Atom(bytes)
        })
        .collect()
}

/// `SignBidirectionalEventV1<EvmType2TxParams<W, E, K>, LenOut, LenResp>`
/// from its atoms, the capacities read off the widths: after `noWords`, the
/// 32-wide atoms up to the 1-wide `accessListEntryCount` are the word slots;
/// then each entry is `[20, 1, K × 32]` until the 64-wide `executionDest`.
struct Cursor<'a> {
    atoms: &'a [Atom],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn next(&mut self) -> &'a Atom {
        self.at += 1;
        &self.atoms[self.at - 1]
    }
    fn peek(&self) -> &'a Atom {
        &self.atoms[self.at]
    }
    fn last(&self) -> &'a Atom {
        &self.atoms[self.at - 1]
    }
}

fn decode(atoms: &[Atom]) -> (SignBidirectionalRecord, Shape) {
    let mut cursor = Cursor { atoms, at: 0 };
    let key_version = cursor.next().u8();
    let sender = cursor.next().bytes::<32>();
    let path = cursor.next().bytes::<32>();
    let algo = SignatureAlgorithm::try_from(cursor.next().u8()).unwrap();
    let tx_param_type = cursor.next().u8();
    assert_eq!(tx_param_type, 0, "evmType2");
    let chain_id = cursor.next().uint() as u64;
    let nonce = cursor.next().uint() as u64;
    let max_priority_fee_per_gas = cursor.next().uint();
    let max_fee_per_gas = cursor.next().uint();
    let gas_limit = cursor.next().uint() as u64;
    let to = cursor.next().bytes::<20>();
    let value = cursor.next().uint();
    let is_some = cursor.next().u8() == 1;
    let selector = cursor.next().bytes::<4>();
    let no_words = cursor.next().uint() as usize;
    let mut word_slots = Vec::new();
    loop {
        let a = cursor.next();
        if a.0.len() == 1 {
            break;
        }
        word_slots.push(a.bytes::<32>());
    }
    let entry_count = cursor.last().u8() as usize;
    let mut entry_slots: Vec<(EvmAccessListEntry, usize)> = Vec::new();
    let mut key_capacity = 0;
    let execution_dest = loop {
        let a = cursor.next();
        if a.0.len() == 64 {
            break a.bytes::<64>();
        }
        let address = a.bytes::<20>();
        let key_count = cursor.next().u8() as usize;
        let mut keys = Vec::new();
        while cursor.peek().0.len() == 32 {
            keys.push(cursor.next().bytes::<32>());
        }
        key_capacity = keys.len();
        keys.truncate(key_count);
        entry_slots.push((EvmAccessListEntry { address, storage_keys: keys }, key_count));
    };
    let signature_dest = SignatureDestination::try_from(cursor.next().u8()).unwrap();
    let params = cursor.next().bytes::<64>();
    let output_deserialization_schema = cursor.next().0.clone();
    let respond_serialization_schema = cursor.next().0.clone();
    assert_eq!(cursor.at, atoms.len(), "every atom consumed");

    let shape = Shape {
        words: word_slots.len(),
        entries: entry_slots.len(),
        keys: key_capacity,
        len_out: output_deserialization_schema.len(),
    };
    assert!(no_words <= word_slots.len());
    assert!(entry_count <= entry_slots.len());
    word_slots.truncate(no_words);
    let access_list = entry_slots.into_iter().take(entry_count).map(|(e, _)| e).collect();
    let record = SignBidirectionalRecord {
        key_version,
        sender,
        path,
        algo,
        tx_params: TxParams::EvmType2(EvmType2TxParams {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            calldata: is_some.then_some(EvmCalldata { selector, words: word_slots }),
            access_list,
        }),
        execution_dest,
        signature_dest,
        params,
        output_deserialization_schema,
        respond_serialization_schema,
    };
    (record, shape)
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct Shape {
    words: usize,
    entries: usize,
    keys: usize,
    len_out: usize,
}

#[test]
fn request_ids_and_transaction_digests_match_the_compiled_circuits() {
    let fixture = fixture();
    let vectors = fixture["requestVectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 9);
    let mut shapes = Vec::new();
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let (record, shape) = decode(&atoms(vector));
        shapes.push(shape);
        let TxParams::EvmType2(tx) = &record.tx_params;
        assert_eq!(
            hex::encode(evm_type2_tx_params_digest(tx).unwrap()),
            vector["txParamsDigest"].as_str().unwrap(),
            "{name}: txParamsDigest"
        );
        assert_eq!(
            hex::encode(record.request_id().unwrap()),
            vector["requestId"].as_str().unwrap(),
            "{name}: requestId"
        );
    }
    // The shapes the vectors cover: the caller contracts' <1, 0, 0>, the
    // empty <0, 0, 0>, <1, 2, 2> and <2, 2, 3> with partly used slots, so
    // capacity and unused slots demonstrably enter nothing.
    assert_eq!(shapes[0], Shape { words: 1, entries: 0, keys: 0, len_out: 34 });
    assert_eq!(shapes[1], Shape { words: 0, entries: 0, keys: 0, len_out: 34 });
    assert_eq!(shapes[2], Shape { words: 1, entries: 2, keys: 2, len_out: 34 });
    assert!(shapes[3..].iter().all(|s| *s == Shape { words: 2, entries: 2, keys: 3, len_out: 34 }), "{shapes:?}");
    // The `request` object is the sample vector by another name.
    assert_eq!(fixture["request"]["requestId"], vectors[0]["requestId"]);
}

#[test]
fn attestation_digests_match_the_compiled_circuits() {
    let fixture = fixture();
    let vectors = fixture["attestations"].as_array().unwrap();
    assert_eq!(vectors.len(), 10);
    for vector in vectors {
        let rid = hex32(vector["requestId"].as_str().unwrap());
        let kind = OutputKind::try_from(vector["kind"].as_u64().unwrap() as u8).unwrap();
        let height: u64 = vector["blockHeight"].as_str().unwrap().parse().unwrap();
        let output = hex::decode(vector["data"].as_str().unwrap()).unwrap();
        let expected_hash = vector["outputHash"].as_str().unwrap();
        let expected_digest = vector["digest"].as_str().unwrap();
        assert_eq!(hex::encode(attested_output_hash(&output)), expected_hash);
        let attestation = Attestation::over(&rid, height, kind, &output).unwrap();
        assert_eq!(hex::encode(attestation.digest), expected_digest, "{vector}");
        assert!(attestation.digest_is_consistent(&rid));
        assert_eq!(
            hex::encode(attestation_digest(
                &rid,
                height,
                kind,
                output.len() as u64,
                &attestation.output_hash
            )),
            expected_digest
        );
    }
}

/// The SDK's own vector (`tests/circuits.test.ts`, `RECORD_2_1_2`): the
/// attestation of a 32-byte output at height 42 for its request id.
#[test]
fn the_sdk_domain_vector() {
    let rid = hex32("2985be91d1a1191749abaee288eed371d19607e69cec0b43468cb750a9dc8d00");
    assert_eq!(
        hex::encode(attested_output_hash(&[0xab; 32])),
        "ebb2798826150dd6a814821b318928f517888e8978ca5207a35b3fc5253d1f00"
    );
    let attestation = Attestation::over(&rid, 42, OutputKind::Executed, &[0xab; 32]).unwrap();
    assert_eq!(
        hex::encode(attestation.digest),
        "174ac56d23e49f26fc8dff9b72d76f3abaaae5867f03c8594122640585042300"
    );
}

/// The fixture's `responseEvent` is the compiled circuit's own emission:
/// its `digest` field is the digest over its other fields.
#[test]
fn the_fixture_event_carries_a_consistent_digest() {
    let fixture = fixture();
    let event = &fixture["responseEvent"];
    let rid = hex32(event["requestId"].as_str().unwrap());
    let attestation = Attestation {
        block_height: event["blockHeight"].as_str().unwrap().parse().unwrap(),
        output_kind: OutputKind::try_from(event["outputKind"].as_u64().unwrap() as u8).unwrap(),
        serialized_output_length: event["serializedOutputLength"].as_str().unwrap().parse().unwrap(),
        output_hash: hex32(event["outputHash"].as_str().unwrap()),
        digest: hex32(event["digest"].as_str().unwrap()),
    };
    assert!(attestation.digest_is_consistent(&rid));
}
