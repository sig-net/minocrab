//! FROZEN: the `@sig-net/midnight` 0.24.1 request record and attestation
//! (`signet-midnight-integration-v0241`, `a80e98e`), kept only for the
//! erc20-vault port at `375071b` until it is re-ported to 0.7.0-rc.2 (M48 L,
//! notes/mainnet-pin.org). It is the part of `minocrab_signet::signet_v1`
//! that v0.26.0-rc.15 changed (the 32-byte `executionDest`, the attestation
//! without `outputHash` and its digest over the output itself), copied
//! verbatim when the library moved; everything that did not change is the
//! library's. Nothing else may use it.

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{AlignmentAtom, Public};
use minocrab_std::v3::hash::upgrade_from_transient;
use minocrab_std::v3::{BytesN, CircuitArg, ContractAddress, LedgerRepr, Uint, Vis3, B32};
use minocrab_signet::common::{Caip2Id, SigningPath};
use minocrab_signet::signet_v1::{
    calculate_evm_type2_tx_params_digest_v1, hash_domain, verify_attestation_signature,
    EvmType2TxParams, OutputKind, SchemaBytes, Secp256k1SigLimbs, ETHEREUM_CAIP2_ID,
    MPC_ALGO_ECDSA, MPC_DEST_UNUSED, PARAMS_LEN, RESPONSE_KEY_PATH, TX_PARAM_TYPE_EVM_TYPE2,
};
use signet_responder_interface::Signature;
pub use signet_signer_interface::RequestId;

fn bytes(length: u32) -> AlignmentAtom {
    AlignmentAtom::Bytes { length }
}

// ---- the record ---------------------------------------------------------------------

/// `struct SignBidirectionalEventV1<EvmType2TxParams<WORDS, 0, 0>, LEN_OUT, 0>`
/// — field order is the wire contract (the ledger record layout; the request
/// id hashes a [`RequestIdPreimageV1`] drawn from it, not the record).
/// `respondSerializationSchema` is `Bytes<0>`: present in the alignment,
/// absent from the limbs, so it has no field here.
#[derive(Clone)]
pub struct SignBidirectionalEventV1<V: Vis3, const WORDS: usize, S: SchemaBytes<V>> {
    pub key_version: Wire3<FieldT, V>,
    pub sender: ContractAddress<V>,
    pub path: SigningPath<V>,
    pub algo: Wire3<FieldT, V>,
    pub tx_param_type: Wire3<FieldT, V>,
    pub tx_params: EvmType2TxParams<V, WORDS>,
    pub execution_dest: Caip2Id<V>,
    pub signature_dest: Wire3<FieldT, V>,
    /// `params: Bytes<64>` — 3 limbs `[2, 31, 31]`, zero-fill.
    pub params: BytesN<V, PARAMS_LEN>,
    pub output_deserialization_schema: S,
}

/// The record's FAB slot layout: each field's first slot, by summing the
/// widths before it — the order [`SignBidirectionalEventV1::limbs`] emits.
pub mod layout {
    use minocrab_std::v3::bytes_limbs;

    pub const KEY_VERSION: usize = 0;
    /// `sender: ContractAddress` — `[hi, lo]`.
    pub const SENDER: usize = KEY_VERSION + 1;
    /// `path: Bytes<32>` — `[hi, lo]`.
    pub const PATH: usize = SENDER + 2;
    pub const ALGO: usize = PATH + 2;
    pub const TX_PARAM_TYPE: usize = ALGO + 1;

    // `txParams: EvmType2TxParams<WORDS, 0, 0>`, field by field.
    pub const CHAIN_ID: usize = TX_PARAM_TYPE + 1;
    pub const NONCE: usize = CHAIN_ID + 1;
    pub const MAX_PRIORITY_FEE_PER_GAS: usize = NONCE + 1;
    pub const MAX_FEE_PER_GAS: usize = MAX_PRIORITY_FEE_PER_GAS + 1;
    pub const GAS_LIMIT: usize = MAX_FEE_PER_GAS + 1;
    pub const TO: usize = GAS_LIMIT + 1;
    pub const VALUE: usize = TO + 1;
    pub const CALLDATA_IS_SOME: usize = VALUE + 1;
    pub const SELECTOR: usize = CALLDATA_IS_SOME + 1;
    pub const NO_WORDS: usize = SELECTOR + 1;
    /// `calldata.words` — `[hi, lo]` per word.
    pub const WORDS: usize = NO_WORDS + 1;

    pub const fn word_hi(i: usize) -> usize {
        WORDS + 2 * i
    }
    pub const fn word_lo(i: usize) -> usize {
        word_hi(i) + 1
    }
    pub const fn access_list_entry_count(words: usize) -> usize {
        word_hi(words)
    }
    /// `executionDest: Bytes<32>` — `[hi, lo]`.
    pub const fn execution_dest(words: usize) -> usize {
        access_list_entry_count(words) + 1
    }
    pub const fn signature_dest(words: usize) -> usize {
        execution_dest(words) + 2
    }
    /// `params: Bytes<64>` — 3 limbs.
    pub const fn params(words: usize) -> usize {
        signature_dest(words) + 1
    }
    pub const fn output_deserialization_schema(words: usize) -> usize {
        params(words) + bytes_limbs(super::PARAMS_LEN)
    }
    /// The record's total limb count (30 for the vault's `<2, 34>`).
    pub const fn limbs(words: usize, schema_limbs: usize) -> usize {
        output_deserialization_schema(words) + schema_limbs
    }
}

impl<V: Vis3, const WORDS: usize, S: SchemaBytes<V>> SignBidirectionalEventV1<V, WORDS, S> {
    /// The record's FAB limb count.
    pub const LIMBS: usize = layout::limbs(WORDS, S::LIMBS);

    /// The record's FAB atoms, one per field (the `Bytes<32>`s are one atom,
    /// two limbs; the trailing `Bytes<0>` is one atom, no limb) — 23 for the
    /// vault's 2-word instantiation.
    pub fn atoms() -> Vec<AlignmentAtom> {
        let mut a = vec![
            bytes(1),  // keyVersion
            bytes(32), // sender
            bytes(32), // path
            bytes(1),  // algo
            bytes(1),  // txParamType
            bytes(8),  // chainId
            bytes(8),  // nonce
            bytes(16), // maxPriorityFeePerGas
            bytes(16), // maxFeePerGas
            bytes(8),  // gasLimit
            bytes(20), // to
            bytes(16), // value
            bytes(1),  // calldata.is_some
            bytes(4),  // selector
            bytes(2),  // noWords
        ];
        a.extend(std::iter::repeat_n(bytes(32), WORDS)); // words
        a.push(bytes(1)); // accessListEntryCount
        a.push(bytes(32)); // executionDest
        a.push(bytes(1)); // signatureDest
        a.extend(BytesN::<V, PARAMS_LEN>::atoms()); // params
        a.extend(S::atoms()); // outputDeserializationSchema
        a.push(bytes(0)); // respondSerializationSchema: Bytes<0>
        a
    }

    /// The record's FAB limbs, slot order ([`Self::LIMBS`] of them).
    pub fn limbs(&self) -> Vec<Wire3<FieldT, V>> {
        let mut l = vec![
            self.key_version,
            self.sender.bytes().hi,
            self.sender.bytes().lo,
            self.path.bytes().hi,
            self.path.bytes().lo,
            self.algo,
            self.tx_param_type,
        ];
        l.extend(self.tx_params.limbs());
        l.push(self.execution_dest.bytes().hi);
        l.push(self.execution_dest.bytes().lo);
        l.push(self.signature_dest);
        l.extend(self.params.limbs().iter().copied());
        l.extend(self.output_deserialization_schema.limbs());
        debug_assert_eq!(l.len(), Self::LIMBS);
        l
    }
}

/// What the LEDGER holds a V1 request as: the limbs of
/// [`SignBidirectionalEventV1`] in slot order, under its atoms. The map that
/// stores a request and the circuit that reads it back share this one impl.
pub struct EventRecordV1<const WORDS: usize, S: SchemaBytes<Public>>(Vec<Wire3<FieldT, Public>>, std::marker::PhantomData<S>);

impl<const WORDS: usize, S: SchemaBytes<Public>> EventRecordV1<WORDS, S> {
    pub const LIMBS: usize = layout::limbs(WORDS, S::LIMBS);

    /// A disclosed request as the record the map stores.
    pub fn from_event(event: &SignBidirectionalEventV1<Public, WORDS, S>) -> Self {
        EventRecordV1(event.limbs(), std::marker::PhantomData)
    }

    /// `txParams.nonce` — what `sentVaultNonce` reads off a sent request.
    pub fn nonce(&self) -> Uint<64, Public> {
        Uint::from_field_unchecked(self.0[layout::NONCE])
    }

    /// `path`.
    pub fn path(&self) -> SigningPath<Public> {
        SigningPath(B32 {
            hi: self.0[layout::PATH],
            lo: self.0[layout::PATH + 1],
        })
    }

    /// The raw limbs, slot order.
    pub fn limbs(&self) -> &[Wire3<FieldT, Public>] {
        &self.0
    }
}

impl<const WORDS: usize, S: SchemaBytes<Public>> minocrab_std::v3::ProofWires for EventRecordV1<WORDS, S> {
    fn push_wires(&self, out: &mut Vec<minocrab::v3::Val>) {
        out.extend(self.0.iter().map(|w| w.val()));
    }
}

impl<const WORDS: usize, S: SchemaBytes<Public>> LedgerRepr for EventRecordV1<WORDS, S> {
    fn atoms() -> Vec<AlignmentAtom> {
        SignBidirectionalEventV1::<Public, WORDS, S>::atoms()
    }

    fn push_limbs(&self, _c: &mut Circuit3, limbs: &mut Vec<Wire3<FieldT, Public>>) {
        limbs.extend_from_slice(&self.0);
    }

    fn from_limbs(limbs: Vec<Wire3<FieldT, Public>>) -> Self {
        assert_eq!(limbs.len(), Self::LIMBS, "V1 event record takes {} limbs", Self::LIMBS);
        EventRecordV1(limbs, std::marker::PhantomData)
    }
}

/// `constructSignBidirectionalEventV1(keyVersion, sender, path, ecdsa,
/// evmType2, txParams, executionDest, unused, pad(64, ""), outputSchema)` —
/// the record, with the source's two live asserts (`keyVersion >= 1`, `path
/// != pad(32, "midnight response key")`); the other two (`signatureDest ==
/// unused`, `params == 0`) are over constants here and fold away as they do
/// in compactc's artifact.
pub fn construct_sign_bidirectional_event_v1<V: Vis3, const WORDS: usize, S: SchemaBytes<V>>(
    c: &mut Circuit3,
    key_version: Wire3<FieldT, V>,
    sender: ContractAddress<V>,
    path: SigningPath<V>,
    tx_params: EvmType2TxParams<V, WORDS>,
    execution_dest: Caip2Id<V>,
    output_schema: &[u8],
) -> SignBidirectionalEventV1<V, WORDS, S> {
    construct_sign_bidirectional_event_v1_with(c, key_version, sender, path, tx_params, execution_dest, output_schema, true)
}

/// [`construct_sign_bidirectional_event_v1`] for a path that is a CONSTANT
/// of the contract (its own `pad(32, …)`): the reserved-path assert is over
/// two constants, which compactc folds away, so it is not emitted here
/// either — the circuits' leakage surfaces stay twins. A path derived from
/// an input (a deposit's depositor commitment) takes the checking form.
pub fn construct_sign_bidirectional_event_v1_const_path<V: Vis3, const WORDS: usize, S: SchemaBytes<V>>(
    c: &mut Circuit3,
    key_version: Wire3<FieldT, V>,
    sender: ContractAddress<V>,
    path: SigningPath<V>,
    tx_params: EvmType2TxParams<V, WORDS>,
    execution_dest: Caip2Id<V>,
    output_schema: &[u8],
) -> SignBidirectionalEventV1<V, WORDS, S> {
    construct_sign_bidirectional_event_v1_with(c, key_version, sender, path, tx_params, execution_dest, output_schema, false)
}

#[allow(clippy::too_many_arguments)]
fn construct_sign_bidirectional_event_v1_with<V: Vis3, const WORDS: usize, S: SchemaBytes<V>>(
    c: &mut Circuit3,
    key_version: Wire3<FieldT, V>,
    sender: ContractAddress<V>,
    path: SigningPath<V>,
    tx_params: EvmType2TxParams<V, WORDS>,
    execution_dest: Caip2Id<V>,
    output_schema: &[u8],
    check_path: bool,
) -> SignBidirectionalEventV1<V, WORDS, S> {
    c.region("signet v1: event assembly", |c| {
        let zero = V::from_public(c.constant(0u64));
        let one = V::from_public(c.constant(1u64));

        // assert(keyVersion >= 1): !(keyVersion < 1) over 8 bits.
        let below = c.less_than(key_version, one, 8);
        let at_least_one = c.not(below);
        c.assert_with(at_least_one, Some("keyVersion must be >= 1"));

        // assert(path != pad(32, "midnight response key")).
        if check_path {
            let reserved = B32::pad(c, RESPONSE_KEY_PATH);
            let p = path.bytes();
            let hi_eq = c.test_eq(p.hi, V::from_public(reserved.hi));
            let lo_eq = c.test_eq(p.lo, V::from_public(reserved.lo));
            let both = c.mul(hi_eq, lo_eq);
            let distinct = c.not(both);
            c.assert_with(distinct, Some("path is reserved for the MPC response key"));
        }

        let params = BytesN::from_limbs(vec![zero; BytesN::<V, PARAMS_LEN>::LIMBS]);
        let output_deserialization_schema = S::literal(c, output_schema);
        SignBidirectionalEventV1 {
            key_version,
            sender,
            path,
            algo: V::from_public(c.constant(MPC_ALGO_ECDSA)),
            tx_param_type: V::from_public(c.constant(TX_PARAM_TYPE_EVM_TYPE2)),
            tx_params,
            execution_dest,
            signature_dest: V::from_public(c.constant(MPC_DEST_UNUSED)),
            params,
            output_deserialization_schema,
        }
    })
}

// ---- the request id ----------------------------------------------------------------

/// `struct RequestIdPreimageV1` — the fields of a request that name ONE
/// execution, in the record's order, with the transaction as its digest.
#[derive(Clone)]
pub struct RequestIdPreimageV1<V: Vis3> {
    pub key_version: Wire3<FieldT, V>,
    pub sender: ContractAddress<V>,
    pub path: SigningPath<V>,
    pub algo: Wire3<FieldT, V>,
    pub tx_param_type: Wire3<FieldT, V>,
    pub tx_params_digest: B32<V>,
    pub execution_dest: Caip2Id<V>,
}

/// `calculateRequestIdV1(preimage)` —
/// `upgradeFromTransient(transientHash([HashDomain.requestId, preimage]))`
/// over the preimage's twelve field-aligned limbs.
pub fn calculate_request_id_v1<V: Vis3>(c: &mut Circuit3, p: &RequestIdPreimageV1<V>) -> RequestId<V> {
    c.region("signet v1: request id (transientHash)", |c| {
        let tag = V::from_public(c.constant(hash_domain::REQUEST_ID));
        let f = c.transient_hash(&[
            tag,
            p.key_version,
            p.sender.bytes().hi,
            p.sender.bytes().lo,
            p.path.bytes().hi,
            p.path.bytes().lo,
            p.algo,
            p.tx_param_type,
            p.tx_params_digest.hi,
            p.tx_params_digest.lo,
            p.execution_dest.bytes().hi,
            p.execution_dest.bytes().lo,
        ]);
        RequestId(upgrade_from_transient(c, f))
    })
}

/// `calculateEvmType2RequestIdV1(request)` — the preimage drawn from the
/// record with its transaction digested, then [`calculate_request_id_v1`].
/// The source's `txParamType == evmType2` assert is over the constant the
/// constructor wrote and folds away.
pub fn calculate_evm_type2_request_id_v1<V: Vis3, const WORDS: usize, S: SchemaBytes<V>>(
    c: &mut Circuit3,
    request: &SignBidirectionalEventV1<V, WORDS, S>,
    words_used: Option<usize>,
) -> RequestId<V> {
    let tx_params_digest = calculate_evm_type2_tx_params_digest_v1(c, &request.tx_params, words_used);
    calculate_request_id_v1(
        c,
        &RequestIdPreimageV1 {
            key_version: request.key_version,
            sender: request.sender,
            path: request.path,
            algo: request.algo,
            tx_param_type: request.tx_param_type,
            tx_params_digest,
            execution_dest: request.execution_dest,
        },
    )
}

// ---- the attestation ------------------------------------------------------------------

/// Compact `struct RespondBidirectionalEventV1 { requestId: RequestId,
/// blockHeight: Uint<64>, outputKind: OutputKind, serializedOutputLength:
/// Uint<64>, digest: Bytes<32>, signature: Signature }` at 0.24.1 — the
/// attestation the vault's `queueAttestation*` circuits take. The deployed
/// signet signer's struct (`signet_signer_interface::RespondBidirectionalEventV1`,
/// 0.25.0) also carries `outputHash`; the two share every other field.
#[derive(Clone, CircuitArg)]
pub struct RespondBidirectionalEventV1<V: Vis3> {
    pub request_id: RequestId<V>,
    pub block_height: Uint<64, V>,
    pub output_kind: OutputKind<V>,
    pub serialized_output_length: Uint<64, V>,
    pub digest: B32<V>,
    pub signature: Signature<V>,
}

/// `calculateSignetAttestationDigestV1<LEN>(requestId, blockHeight,
/// outputKind, serializedOutput)` — Poseidon over `[HashDomain.attestationDigest,
/// requestId, blockHeight, outputKind, LEN, serializedOutput]`, the width
/// entering as the constant `LEN`, then `upgradeFromTransient`.
/// `output_limbs` are the output's FAB limbs (none for `Bytes<0>`, one for
/// `Bytes<1>`, `[hi, lo]` for `Bytes<32>`).
pub fn calculate_attestation_digest_v1<V: Vis3, const LEN: usize>(
    c: &mut Circuit3,
    request_id: &RequestId<V>,
    block_height: Wire3<FieldT, V>,
    output_kind: Wire3<FieldT, V>,
    output_limbs: &[Wire3<FieldT, V>],
) -> B32<V> {
    calculate_attestation_digest_v1_at(c, request_id, block_height, output_kind, LEN as u64, output_limbs)
}

/// [`calculate_attestation_digest_v1`] WITH THE WIDTH AS DATA.
///
/// The compat port's widths are consts of the circuit, so it names them as
/// const parameters and the type says which `queueAttestation*` it is. The
/// typed API's width is `<Call::Return as AbiReturn>::LEN`, an ASSOCIATED
/// const, and stable Rust cannot pass one as a const-generic argument
/// (`generic_const_exprs`) — so this is the same function with the number in
/// the argument list. It emits the same `constant`, in the same place: the
/// two forms are instruction-identical.
pub fn calculate_attestation_digest_v1_at<V: Vis3>(
    c: &mut Circuit3,
    request_id: &RequestId<V>,
    block_height: Wire3<FieldT, V>,
    output_kind: Wire3<FieldT, V>,
    len: u64,
    output_limbs: &[Wire3<FieldT, V>],
) -> B32<V> {
    c.region("signet v1: attestation digest (transientHash)", |c| {
        let f = attestation_transient_hash_v1(c, request_id, block_height, output_kind, len, output_limbs);
        upgrade_from_transient(c, f)
    })
}

/// [`calculate_attestation_digest_v1`] WITHOUT THE UPGRADE, and with the
/// width as data rather than as a const.
///
/// Two callers need the raw Poseidon output. A refund accepts TWO
/// attestations whose preimages differ in both the width and the limbs — the
/// MPC's verdict over an EMPTY output (width 0) and this call's output at its
/// own width — and Poseidon is not a stream, so one hash cannot cover both:
/// `Pending::refund` hashes it both ways, selects the field element by the
/// verdict and upgrades ONCE, which is also where the const width stops
/// being a const. Everything else goes through
/// [`calculate_attestation_digest_v1`], whose `LEN` keeps the width a fact
/// about the call's type.
pub fn attestation_transient_hash_v1<V: Vis3>(
    c: &mut Circuit3,
    request_id: &RequestId<V>,
    block_height: Wire3<FieldT, V>,
    output_kind: Wire3<FieldT, V>,
    len: u64,
    output_limbs: &[Wire3<FieldT, V>],
) -> Wire3<FieldT, V> {
    let tag = V::from_public(c.constant(hash_domain::ATTESTATION_DIGEST));
    let width = V::from_public(c.constant(len));
    let mut limbs = vec![tag, request_id.bytes().hi, request_id.bytes().lo, block_height, output_kind, width];
    limbs.extend_from_slice(output_limbs);
    c.transient_hash(&limbs)
}

/// `verifyRespondBidirectionalEventV1<LEN>(serializedOutput, event,
/// mpcResponseKey)` — the digest over the event's id, height and verdict
/// with the caller's output, then the ECDSA check over `bigR.x` and `s`
/// (little-endian, as the circuit-input form has them). `serializedOutputLength`
/// and `digest` on the event serve off-chain readers and enter nothing.
pub fn verify_respond_bidirectional_event_v1<V: Vis3, const LEN: usize>(
    c: &mut Circuit3,
    output_limbs: &[Wire3<FieldT, V>],
    event: &RespondBidirectionalEventV1<V>,
    mpc_response_key: Wire3<minocrab::v3::Secp256k1PointT, V>,
) -> Wire3<FieldT, V> {
    verify_respond_bidirectional_event_v1_at(c, LEN as u64, output_limbs, event, mpc_response_key)
}

/// [`verify_respond_bidirectional_event_v1`] WITH THE WIDTH AS DATA — the
/// typed API's form, for the same reason
/// [`calculate_attestation_digest_v1_at`] exists: the width is an associated
/// const of the call's return type, and stable Rust cannot pass one as a
/// const-generic argument.
pub fn verify_respond_bidirectional_event_v1_at<V: Vis3>(
    c: &mut Circuit3,
    len: u64,
    output_limbs: &[Wire3<FieldT, V>],
    event: &RespondBidirectionalEventV1<V>,
    mpc_response_key: Wire3<minocrab::v3::Secp256k1PointT, V>,
) -> Wire3<FieldT, V> {
    let digest = calculate_attestation_digest_v1_at(
        c,
        &event.request_id,
        event.block_height.field(),
        event.output_kind.field(),
        len,
        output_limbs,
    );
    verify_attestation_signature(
        c,
        &digest,
        &Secp256k1SigLimbs {
            big_r_x: event.signature.big_r.x,
            s: event.signature.s,
        },
        mpc_response_key,
    )
}

/// `pad(32, "eip155:1")` as the record's `executionDest`.
pub fn ethereum_caip2_id<V: Vis3>(c: &mut Circuit3) -> Caip2Id<V> {
    let p = B32::pad(c, ETHEREUM_CAIP2_ID);
    Caip2Id(B32 {
        hi: V::from_public(p.hi),
        lo: V::from_public(p.lo),
    })
}
