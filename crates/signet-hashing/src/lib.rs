//! The Signet protocol's hashes, off circuit (midnight-integration v0.25.0,
//! `Signet.compact`).
//!
//! Every one of them is `upgradeFromTransient(transientHash([HashDomain.x,
//! …]))`: Poseidon over the preimage's FIELD-ALIGNED representation, then
//! the field element written out as 32 bytes. The field representation is
//! the ledger's: [`FieldRepr`] packs a `Bytes<N>` as the compiler's FAB
//! alignment does (the `N mod 31` leftover bytes as the first limb, then
//! 31-byte limbs from the top down — `[hi, lo]` for a `Bytes<32>`), and an
//! integer, a `Boolean` or an enum as one limb — so this crate adds no
//! packing of its own. The domain tags and enums are
//! [`signet_protocol`]'s.
//!
//! Three readers agree through this crate:
//!
//! - **sig-net/mpc** computes the request id of a record it has read to
//!   know what it is signing for, and the attestation digest to know what it
//!   is signing. Until this crate it carried its own copy
//!   (`chain-signatures/compact-hashing`).
//! - **`minocrab-publisher`** builds the attestation half of a
//!   `respondBidirectional` call from the output the MPC attests.
//! - **the contract tests** drive a request → respond → settle round trip
//!   and need the MPC's half of it as a function.
//!
//! Pinned against the compiled Compact circuits through
//! `tests/fixtures/api-parity-vectors.json`: request ids and transaction
//! digests of nine records at four struct shapes, and ten attestation
//! digests, produced by compactc 0.33.0-rc.2 over
//! `@sig-net/midnight@0.25.0-rc.1` (the hashing has not changed since) and
//! captured by sig-net/mpc. No Rust hash took part in producing those bytes.

use midnight_transient_crypto::curve::Fr;
use midnight_transient_crypto::hash::{transient_hash, upgrade_from_transient};
use midnight_transient_crypto::repr::FieldRepr;
pub use signet_protocol::{
    HashDomain, OutputKind, SignatureAlgorithm, SignatureDestination, TxParamType,
};

/// A preimage under construction: the domain tag, then each value's field
/// representation in order.
struct Preimage(Vec<Fr>);

impl Preimage {
    fn new(domain: HashDomain) -> Preimage {
        Preimage(vec![Fr::from(u64::from(domain as u8))])
    }

    fn push<T: FieldRepr + ?Sized>(mut self, value: &T) -> Preimage {
        value.field_repr(&mut self.0);
        self
    }

    /// `transientHash` of the preimage, as the field element the next fold
    /// step chains onto.
    fn hash(self) -> Fr {
        transient_hash(&self.0)
    }

    /// `upgradeFromTransient(transientHash(…))`: the 32-byte form.
    fn upgrade(self) -> [u8; 32] {
        upgrade_from_transient(self.hash()).0
    }
}

/// A count that does not fit the counter the circuit folds with: more than
/// `u16::MAX` calldata words, or more than `u8::MAX` access-list entries or
/// storage keys in one entry. The circuit's `noWords`, `accessListEntryCount`
/// and `storageKeyCount` are a `Uint<16>` and two `Uint<8>`s, so no record
/// can carry such a transaction and no digest is defined for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{what}: {count} do not fit the circuit's {counter}")]
pub struct TooMany {
    pub what: &'static str,
    pub count: usize,
    pub counter: &'static str,
}

/// An `OutputKind` other than `Executed` was given output bytes. The
/// protocol defines a failed or unviable execution's attested output as
/// `Bytes<0>`; an attestation that says otherwise is not one the circuits
/// produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("a {kind:?} attestation carries no output, but {len} bytes were given")]
pub struct OutputNotEmpty {
    pub kind: OutputKind,
    pub len: usize,
}

// ---- the attestation --------------------------------------------------------

/// `calculateAttestedOutputHashV1<N>(serializedOutput)`:
/// `[HashDomain.attestedOutput, Bytes<N>]`.
///
/// The bytes pack into limbs without their width, so outputs that differ
/// only in trailing zero bytes hash alike. The width is committed beside
/// this hash, in the attestation digest's `serializedOutputLength`.
pub fn attested_output_hash(serialized_output: &[u8]) -> [u8; 32] {
    Preimage::new(HashDomain::AttestedOutput).push(serialized_output).upgrade()
}

/// `calculateSignetAttestationDigestV1(requestId, blockHeight, outputKind,
/// serializedOutputLength, outputHash)`: the 32 bytes the MPC signs, over
/// `[HashDomain.attestationDigest, Bytes<32>, Uint<64>, OutputKind, Uint<64>,
/// Bytes<32>]`. Every input is fixed-width, so a reader holding an event and
/// no output recomputes it from the event's fields alone.
pub fn attestation_digest(
    request_id: &[u8; 32],
    block_height: u64,
    output_kind: OutputKind,
    serialized_output_length: u64,
    output_hash: &[u8; 32],
) -> [u8; 32] {
    Preimage::new(HashDomain::AttestationDigest)
        .push(request_id)
        .push(&block_height)
        .push(&(output_kind as u8))
        .push(&serialized_output_length)
        .push(output_hash)
        .upgrade()
}

/// The attestation half of a `respondBidirectional`: what the MPC signs over
/// besides the request id, with the digest the signature is over.
///
/// `RespondBidirectionalEventV1` minus the request id and the signature, in
/// the struct's field order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attestation {
    /// Height of the finalised destination-chain block holding the
    /// transaction, in that chain's own numbering.
    pub block_height: u64,
    /// The MPC's verdict.
    pub output_kind: OutputKind,
    /// The byte width of the serialised output: 0 unless `Executed`.
    pub serialized_output_length: u64,
    /// [`attested_output_hash`] of the serialised output.
    pub output_hash: [u8; 32],
    /// [`attestation_digest`] over the four fields above and the request id.
    pub digest: [u8; 32],
}

impl Attestation {
    /// The attestation of `serialized_output` for `request_id`: its width,
    /// its hash and the digest over them.
    ///
    /// # Errors
    ///
    /// [`OutputNotEmpty`] if `output_kind` is not `Executed` and
    /// `serialized_output` is not empty.
    pub fn over(
        request_id: &[u8; 32],
        block_height: u64,
        output_kind: OutputKind,
        serialized_output: &[u8],
    ) -> Result<Attestation, OutputNotEmpty> {
        if output_kind != OutputKind::Executed && !serialized_output.is_empty() {
            return Err(OutputNotEmpty { kind: output_kind, len: serialized_output.len() });
        }
        let serialized_output_length = serialized_output.len() as u64;
        let output_hash = attested_output_hash(serialized_output);
        let digest = attestation_digest(
            request_id,
            block_height,
            output_kind,
            serialized_output_length,
            &output_hash,
        );
        Ok(Attestation { block_height, output_kind, serialized_output_length, output_hash, digest })
    }

    /// Whether `digest` is what the other four fields and `request_id` hash
    /// to — the check a reader makes on an event before trusting the digest
    /// it carries, which the circuits never read.
    pub fn digest_is_consistent(&self, request_id: &[u8; 32]) -> bool {
        attestation_digest(
            request_id,
            self.block_height,
            self.output_kind,
            self.serialized_output_length,
            &self.output_hash,
        ) == self.digest
    }
}

// ---- the transaction ---------------------------------------------------------

/// `EvmCalldata`: the ABI selector and the USED words. The circuit's struct
/// has a capacity and a `noWords`; off circuit the words present are the
/// words used, and the capacity, which the digest does not commit to, is the
/// requester's business.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmCalldata {
    pub selector: [u8; 4],
    pub words: Vec<[u8; 32]>,
}

/// `EvmAccessListEntry`: an address and its USED storage keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmAccessListEntry {
    pub address: [u8; 20],
    pub storage_keys: Vec<[u8; 32]>,
}

/// `EvmType2TxParams`: an EIP-1559 transaction as the record carries it,
/// with the calldata and the access list holding their USED entries only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmType2TxParams {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: u128,
    /// `None` is a plain ETH transfer (`"0x"` data).
    pub calldata: Option<EvmCalldata>,
    pub access_list: Vec<EvmAccessListEntry>,
}

/// `calculateEvmType2TxParamsDigestV1(txParams)`: the head tuple (the domain
/// tag, the scalar fields, the calldata's presence, selector and word count,
/// the entry count) as one hash, then each used word chained on under
/// `evmType2TxWord`, then each used entry chained on under
/// `evmType2TxAccessEntry` as its address, its key count and the fold of its
/// used keys under `evmType2TxStorageKey` (from a zero field). Capacities
/// and unused slots enter nowhere, so one transaction has one digest
/// whatever shape the requester compiled its struct with.
///
/// # Errors
///
/// [`TooMany`] if a count overflows the counter the circuit folds with.
pub fn evm_type2_tx_params_digest(tx: &EvmType2TxParams) -> Result<[u8; 32], TooMany> {
    let (is_some, selector, words): (bool, [u8; 4], &[[u8; 32]]) = match &tx.calldata {
        Some(calldata) => (true, calldata.selector, &calldata.words),
        None => (false, [0; 4], &[]),
    };
    let no_words = u16::try_from(words.len()).map_err(|_| TooMany {
        what: "calldata words",
        count: words.len(),
        counter: "Uint<16> noWords",
    })?;
    let entry_count = u8::try_from(tx.access_list.len()).map_err(|_| TooMany {
        what: "access-list entries",
        count: tx.access_list.len(),
        counter: "Uint<8> accessListEntryCount",
    })?;

    let mut acc = Preimage::new(HashDomain::EvmType2TxHeader)
        .push(&tx.chain_id)
        .push(&tx.nonce)
        .push(&tx.max_priority_fee_per_gas)
        .push(&tx.max_fee_per_gas)
        .push(&tx.gas_limit)
        .push(&tx.to)
        .push(&tx.value)
        .push(&is_some)
        .push(&selector)
        .push(&no_words)
        .push(&entry_count)
        .hash();
    for word in words {
        acc = Preimage::new(HashDomain::EvmType2TxWord).push(&acc).push(word).hash();
    }
    for entry in &tx.access_list {
        let key_count = u8::try_from(entry.storage_keys.len()).map_err(|_| TooMany {
            what: "storage keys in one access-list entry",
            count: entry.storage_keys.len(),
            counter: "Uint<8> storageKeyCount",
        })?;
        let mut keys = Fr::from(0u64);
        for key in &entry.storage_keys {
            keys = Preimage::new(HashDomain::EvmType2TxStorageKey).push(&keys).push(key).hash();
        }
        acc = Preimage::new(HashDomain::EvmType2TxAccessEntry)
            .push(&acc)
            .push(&entry.address)
            .push(&key_count)
            .push(&keys)
            .hash();
    }
    Ok(upgrade_from_transient(acc).0)
}

// ---- the request --------------------------------------------------------------

/// `ethereumCaip2Id()`: `pad(64, "eip155:1")`, the `executionDest` of every
/// request bound for an Ethereum network (the transaction's own `chainId`
/// picks which).
pub const ETHEREUM_CAIP2_ID: [u8; 64] = pad64(b"eip155:1");

const fn pad64(text: &[u8]) -> [u8; 64] {
    assert!(text.len() <= 64);
    let mut out = [0u8; 64];
    let mut i = 0;
    while i < text.len() {
        out[i] = text[i];
        i += 1;
    }
    out
}

/// `RequestIdPreimageV1`: the fields of a request that name one execution,
/// with the transaction as its digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestIdPreimage {
    pub key_version: u8,
    /// The requesting contract's address.
    pub sender: [u8; 32],
    pub path: [u8; 32],
    pub algo: SignatureAlgorithm,
    pub tx_param_type: TxParamType,
    pub tx_params_digest: [u8; 32],
    pub execution_dest: [u8; 64],
}

/// `calculateRequestIdV1(preimage)`: `[HashDomain.requestId, Uint<8>,
/// ContractAddress, Bytes<32>, MPCSignatureAlgorithm, TxParamType, Bytes<32>,
/// Bytes<64>]`, thirteen limbs.
pub fn request_id(preimage: &RequestIdPreimage) -> [u8; 32] {
    Preimage::new(HashDomain::RequestId)
        .push(&preimage.key_version)
        .push(&preimage.sender)
        .push(&preimage.path)
        .push(&(preimage.algo as u8))
        .push(&(preimage.tx_param_type as u8))
        .push(&preimage.tx_params_digest)
        .push(&preimage.execution_dest)
        .upgrade()
}

/// A request's transaction, tagged by its `TxParamType`. One variant today;
/// the enum is where the next decomposition goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxParams {
    EvmType2(EvmType2TxParams),
}

impl TxParams {
    /// The `txParamType` that tags this decomposition.
    pub fn ty(&self) -> TxParamType {
        match self {
            TxParams::EvmType2(_) => TxParamType::EvmType2,
        }
    }

    /// The digest the request id commits to.
    pub fn digest(&self) -> Result<[u8; 32], TooMany> {
        match self {
            TxParams::EvmType2(tx) => evm_type2_tx_params_digest(tx),
        }
    }
}

/// `SignBidirectionalEventV1`: a client contract's request record, as the
/// MPC reads it from the client's ledger. The first six fields and
/// `execution_dest` are the request id's preimage; the rest are outside
/// request identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignBidirectionalRecord {
    pub key_version: u8,
    pub sender: [u8; 32],
    pub path: [u8; 32],
    pub algo: SignatureAlgorithm,
    /// `txParamType` and `txParams` as one field, so they cannot disagree.
    pub tx_params: TxParams,
    pub execution_dest: [u8; 64],
    pub signature_dest: SignatureDestination,
    pub params: [u8; 64],
    /// `Bytes<LenOutputDeserialization>`, a width the requester chooses.
    pub output_deserialization_schema: Vec<u8>,
    /// `Bytes<LenRespondSerialization>`, a width the requester chooses.
    pub respond_serialization_schema: Vec<u8>,
}

impl SignBidirectionalRecord {
    /// The record's `RequestIdPreimageV1`, its transaction digested.
    pub fn request_id_preimage(&self) -> Result<RequestIdPreimage, TooMany> {
        Ok(RequestIdPreimage {
            key_version: self.key_version,
            sender: self.sender,
            path: self.path,
            algo: self.algo,
            tx_param_type: self.tx_params.ty(),
            tx_params_digest: self.tx_params.digest()?,
            execution_dest: self.execution_dest,
        })
    }

    /// `calculateEvmType2RequestIdV1(request)` for an EVM record, and its
    /// analogue for any other: the id the client contract filed this record
    /// under.
    pub fn request_id(&self) -> Result<[u8; 32], TooMany> {
        Ok(request_id(&self.request_id_preimage()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `[u8]` representation this crate rests on is the FAB packing:
    /// `Bytes<32>` is `[byte 31, bytes 0..31]`, `Bytes<64>` is `[bytes
    /// 62..64, bytes 31..62, bytes 0..31]`, `Bytes<20>` is one limb.
    #[test]
    fn field_repr_of_bytes_is_the_fab_packing() {
        let mut b32 = [0u8; 32];
        for (i, b) in b32.iter_mut().enumerate() {
            *b = i as u8 + 1;
        }
        let limbs = b32.field_vec();
        assert_eq!(limbs, vec![Fr::from(32u64), Fr::from_le_bytes(&b32[..31]).unwrap()]);
        let b64 = [7u8; 64];
        let limbs = b64.field_vec();
        assert_eq!(limbs.len(), 3);
        assert_eq!(limbs[0], Fr::from_le_bytes(&[7, 7]).unwrap());
        assert_eq!(limbs[1], Fr::from_le_bytes(&[7; 31]).unwrap());
        assert_eq!([9u8; 20].field_vec().len(), 1);
        assert_eq!(true.field_vec(), vec![Fr::from(1u64)]);
        assert_eq!(u128::MAX.field_vec(), vec![Fr::from(u128::MAX)]);
    }

    #[test]
    fn the_output_hash_ignores_trailing_zeros_and_the_digest_does_not() {
        assert_eq!(attested_output_hash(&[1]), attested_output_hash(&[1, 0]));
        let rid = [0x2f; 32];
        let a = Attestation::over(&rid, 42, OutputKind::Executed, &[1]).unwrap();
        let b = Attestation::over(&rid, 42, OutputKind::Executed, &[1, 0]).unwrap();
        assert_eq!(a.output_hash, b.output_hash);
        assert_ne!(a.digest, b.digest);
        assert!(a.digest_is_consistent(&rid));
        assert!(!a.digest_is_consistent(&[0x30; 32]));
    }

    #[test]
    fn only_an_executed_attestation_carries_output() {
        let rid = [0x2f; 32];
        for kind in [OutputKind::Failed, OutputKind::Unviable] {
            assert!(Attestation::over(&rid, 1, kind, &[]).is_ok());
            assert_eq!(
                Attestation::over(&rid, 1, kind, &[1]),
                Err(OutputNotEmpty { kind, len: 1 })
            );
        }
    }

    #[test]
    fn capacity_overflow_is_an_error_not_a_wrap() {
        let mut tx = EvmType2TxParams {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            gas_limit: 0,
            to: [0; 20],
            value: 0,
            calldata: None,
            access_list: vec![EvmAccessListEntry { address: [0; 20], storage_keys: vec![[0; 32]; 256] }],
        };
        assert_eq!(
            evm_type2_tx_params_digest(&tx).unwrap_err().counter,
            "Uint<8> storageKeyCount"
        );
        tx.access_list = vec![EvmAccessListEntry { address: [0; 20], storage_keys: vec![] }; 256];
        assert_eq!(
            evm_type2_tx_params_digest(&tx).unwrap_err().counter,
            "Uint<8> accessListEntryCount"
        );
        tx.access_list.clear();
        tx.calldata = Some(EvmCalldata { selector: [0; 4], words: vec![[0; 32]; 65536] });
        assert_eq!(evm_type2_tx_params_digest(&tx).unwrap_err().counter, "Uint<16> noWords");
    }

    #[test]
    fn the_ethereum_caip2_id_is_padded_to_64() {
        assert_eq!(&ETHEREUM_CAIP2_ID[..8], b"eip155:1");
        assert!(ETHEREUM_CAIP2_ID[8..].iter().all(|&b| b == 0));
    }
}
