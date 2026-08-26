//! The `@sig-net/midnight` Signet protocol module
//! (signet-midnight-integration packages/signet-midnight/src/Signet.compact)
//! — mechanical port of the pieces the client contracts use in-circuit:
//! the SignBidirectionalEvent record and its FAB layout, request ids
//! (keccak256 of the record), the V1 notification payload, the attestation
//! verify, and the ABI calldata word utilities.
//!
//! The record's FAB atom layout is confirmed against the erc20-vault
//! corpus artifact (claim.zkir:287 — the 24-atom, 33-limb popeq of
//! `SignBidirectionalEvent<EvmType2TxParams<2, 0, 0>, 34, 34>`).
//!
//! Access lists are fixed empty (`maxAccessListEntries = 0`), as every
//! sig-net client contract in the corpus declares; word capacity and the
//! two schema widths are const parameters of the record type — one
//! definition, monomorphized per instantiation (the vault uses
//! `<2, 0, 0>, 34, 34` for transfers and `<7, 0, 0>, 38, 37` for swaps).

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Alignment, AlignmentAtom, AlignmentSegment, Public};
use minocrab_std::v3::borsh::{CircuitBorsh, Limbs};
use minocrab_std::v3::{
    pow2_const, secp256k1_ecdsa_verify, BytesN, LedgerRepr, Secp256k1EcdsaSignature, Vis3, B32,
};

/// The signer's request id — the keccak of a whole signing record, and the
/// key every event map and every refund commitment is filed under.
///
/// Re-exported from the interface crate (where the generator emits it from
/// the callee's own `RequestId = Bytes<32>` alias) so a vault fork can write
/// `signet::RequestId` without importing the crate: the forks already declare
/// a DISCLOSURE LABEL called `RequestId`, and the module qualifier keeps the
/// two apart at every use.
pub use signet_signer_interface::RequestId;

fn atom(n: u32) -> AlignmentSegment {
    AlignmentSegment::Atom(AlignmentAtom::Bytes { length: n })
}

fn bytes(length: u32) -> AlignmentAtom {
    AlignmentAtom::Bytes { length }
}

// ---- EVM Type2 transaction parameters ---------------------------------------

/// `struct EvmCalldata<#maxWords>` — selector (`Bytes<4>`), used-word
/// count (`Uint<16>`), and the canonical big-endian ABI words.
#[derive(Clone)]
pub struct EvmCalldata<V: Vis3, const WORDS: usize> {
    pub selector: Wire3<FieldT, V>,
    pub no_words: Wire3<FieldT, V>,
    pub words: [B32<V>; WORDS],
}

/// `struct EvmType2TxParams<#maxCalldataWords, 0, 0>` — the EIP-1559
/// envelope with an empty access list. `calldata` is
/// `Maybe<EvmCalldata<n>>`: the tag is `calldata_is_some`, a `none` value
/// carries a zeroed calldata.
#[derive(Clone)]
pub struct EvmType2TxParams<V: Vis3, const WORDS: usize> {
    pub chain_id: Wire3<FieldT, V>,
    pub nonce: Wire3<FieldT, V>,
    pub max_priority_fee_per_gas: Wire3<FieldT, V>,
    pub max_fee_per_gas: Wire3<FieldT, V>,
    pub gas_limit: Wire3<FieldT, V>,
    pub to: Wire3<FieldT, V>,
    pub value: Wire3<FieldT, V>,
    pub calldata_is_some: Wire3<FieldT, V>,
    pub calldata: EvmCalldata<V, WORDS>,
    pub access_list_entry_count: Wire3<FieldT, V>,
}

impl<V: Vis3, const WORDS: usize> EvmType2TxParams<V, WORDS> {
    /// FAB limbs, slot order (one per atom except `bytes<32>` words = 2).
    fn limbs(&self) -> Vec<Wire3<FieldT, V>> {
        let mut l = vec![
            self.chain_id,
            self.nonce,
            self.max_priority_fee_per_gas,
            self.max_fee_per_gas,
            self.gas_limit,
            self.to,
            self.value,
            self.calldata_is_some,
            self.calldata.selector,
            self.calldata.no_words,
        ];
        for w in &self.calldata.words {
            l.push(w.hi);
            l.push(w.lo);
        }
        l.push(self.access_list_entry_count);
        l
    }
}

// ---- SignBidirectionalEvent -------------------------------------------------

/// `params: Bytes<64>`'s width — the record's one fixed-size byte field.
pub const PARAMS_LEN: usize = 64;

/// The FAB atoms both record formats share: `sender` through `caip2Id`.
///
/// One definition, so the deployed record ([`SignBidirectionalEvent`]) and the
/// stage-7 record ([`SignBidirectionalEventV2`]) cannot drift in the middle —
/// stage 7 changes the two ENDS, and this function is what says so.
fn record_atoms_through_caip2<V: Vis3, const WORDS: usize>() -> Vec<AlignmentAtom> {
    let mut a = vec![
        bytes(32), // sender
        bytes(8),  // requestNonce
        bytes(1),  // keyVersion
        bytes(32), // path
        bytes(1),  // algo
        bytes(1),  // dest
    ];
    a.extend(BytesN::<V, PARAMS_LEN>::atoms()); // params
    a.extend([
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
    ]);
    a.extend(std::iter::repeat_n(bytes(32), WORDS)); // words
    a.push(bytes(1)); // accessListEntryCount
    a.push(bytes(32)); // caip2Id
    a
}

/// `struct SignBidirectionalEvent<TxParams, #LenOut, #LenRespond>` with
/// `TxParams = EvmType2TxParams<#WORDS, 0, 0>`. Field order is the wire
/// contract (the request-id hash order and the ledger record layout).
#[derive(Clone)]
pub struct SignBidirectionalEvent<
    V: Vis3,
    const WORDS: usize,
    const LEN_OUT: usize,
    const LEN_RESPOND: usize,
> {
    pub sender: B32<V>,
    pub request_nonce: Wire3<FieldT, V>,
    pub key_version: Wire3<FieldT, V>,
    pub path: B32<V>,
    pub algo: Wire3<FieldT, V>,
    pub dest: Wire3<FieldT, V>,
    /// `params: Bytes<64>` — 3 limbs `[2, 31, 31]`, zero-fill today.
    pub params: BytesN<V, PARAMS_LEN>,
    pub tx_param_type: Wire3<FieldT, V>,
    pub tx_params: EvmType2TxParams<V, WORDS>,
    pub caip2_id: B32<V>,
    pub output_deserialization_schema: BytesN<V, LEN_OUT>,
    pub respond_serialization_schema: BytesN<V, LEN_RESPOND>,
}

/// `MPCSignatureAlgorithm.ecdsa` / `MPCDestination.unused` /
/// `TxParamType.evmType2` — all first enum members, value 0.
pub const MPC_ALGO_ECDSA: u64 = 0;
pub const MPC_DEST_UNUSED: u64 = 0;
pub const TX_PARAM_TYPE_EVM_TYPE2: u64 = 0;

/// The record's FAB slot layout: each field's first slot, derived by
/// summing the widths of the fields before it — the same declaration order
/// [`SignBidirectionalEvent::limbs`] emits. Nothing here is counted by
/// hand, so a field width change moves every later offset with it.
pub mod layout {
    use minocrab_std::v3::bytes_limbs;

    /// `sender: Bytes<32>` — `[hi, lo]`.
    pub const SENDER: usize = 0;
    pub const REQUEST_NONCE: usize = SENDER + 2;
    pub const KEY_VERSION: usize = REQUEST_NONCE + 1;
    /// `path: Bytes<32>` — `[hi, lo]`.
    pub const PATH: usize = KEY_VERSION + 1;
    pub const ALGO: usize = PATH + 2;
    pub const DEST: usize = ALGO + 1;
    /// `params: Bytes<PARAMS_LEN>`.
    pub const PARAMS: usize = DEST + 1;
    pub const TX_PARAM_TYPE: usize = PARAMS + bytes_limbs(super::PARAMS_LEN);

    // `tx_params: EvmType2TxParams<WORDS, 0, 0>`, field by field.
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
    /// `calldata.words` — `[hi, lo]` per word, so the fields after the
    /// words depend on the instantiation's word count.
    pub const WORDS: usize = NO_WORDS + 1;

    /// `calldata.words[i]`'s `[hi, lo]` pair. The `i < WORDS` bound is the
    /// caller's ([`super::EventRecord::word`]).
    pub const fn word_hi(i: usize) -> usize {
        WORDS + 2 * i
    }
    pub const fn word_lo(i: usize) -> usize {
        word_hi(i) + 1
    }

    pub const fn access_list_entry_count(words: usize) -> usize {
        word_hi(words)
    }
    /// `caip2Id: Bytes<32>` — `[hi, lo]`.
    pub const fn caip2_id(words: usize) -> usize {
        access_list_entry_count(words) + 1
    }
    pub const fn output_deserialization_schema(words: usize) -> usize {
        caip2_id(words) + 2
    }
    pub const fn respond_serialization_schema(words: usize, len_out: usize) -> usize {
        output_deserialization_schema(words) + bytes_limbs(len_out)
    }

    /// The record's total limb count (33 for the vault's `<2, 34, 34>`).
    pub const fn limbs(words: usize, len_out: usize, len_respond: usize) -> usize {
        respond_serialization_schema(words, len_out) + bytes_limbs(len_respond)
    }
}

impl<V: Vis3, const WORDS: usize, const LEN_OUT: usize, const LEN_RESPOND: usize>
    SignBidirectionalEvent<V, WORDS, LEN_OUT, LEN_RESPOND>
{
    /// The record's FAB limb count (claim.zkir:287 — 33 for the vault's
    /// 2-word instantiation).
    pub const LIMBS: usize = layout::limbs(WORDS, LEN_OUT, LEN_RESPOND);

    /// The record's FAB atoms, one per field except the `Bytes<32>` pairs
    /// (claim.zkir:287 — 24 atoms for the 2-word vault instantiation).
    pub fn atoms() -> Vec<AlignmentAtom> {
        let mut a = record_atoms_through_caip2::<V, WORDS>();
        a.extend(BytesN::<V, LEN_OUT>::atoms());
        a.extend(BytesN::<V, LEN_RESPOND>::atoms());
        a
    }

    /// The record's FAB limbs, slot order ([`Self::LIMBS`] of them).
    pub fn limbs(&self) -> Vec<Wire3<FieldT, V>> {
        let mut l = vec![
            self.sender.hi,
            self.sender.lo,
            self.request_nonce,
            self.key_version,
            self.path.hi,
            self.path.lo,
            self.algo,
            self.dest,
        ];
        l.extend(self.params.limbs().iter().copied());
        l.push(self.tx_param_type);
        l.extend(self.tx_params.limbs());
        l.push(self.caip2_id.hi);
        l.push(self.caip2_id.lo);
        l.extend(self.output_deserialization_schema.limbs().iter().copied());
        l.extend(self.respond_serialization_schema.limbs().iter().copied());
        debug_assert_eq!(l.len(), Self::LIMBS);
        l
    }
}

// ---- SignBidirectionalEventV2 — the M11 stage 7 record -----------------------

/// The record's FORMAT VERSION byte, at offset 0 of every stage-7 record.
///
/// `0x80` — the byte with only the HIGH BIT set (dmd, 2026-08-16). The point
/// is headroom rather than taste: every version number anywhere in the pinned
/// stack is small (ZKIR envelope 2 and 3, Impact transcript 2.3, Compact
/// `language_version` 0.12..0.23, compactc 0.33), the largest number in any
/// position being 33 — so "this is not a small version number" is a single bit
/// test rather than a magnitude comparison, every value below it stays
/// available to Compact/Midnight, and a decoder that reads `0x80` where it
/// expected a Compact version knows immediately which format it is holding.
///
/// It is in the RECORD only — never in an attested output, where the kind tag
/// suffices and the digest is signed (notes/borsh-format.org §"ANSWERED from
/// MPC source", Q4). The record is what the MPC reads back out of ledger
/// STATE, so this byte is what its FAB cursor sees first; the singleton's
/// notification payload is a different, unchanged shape (Q6), and it is the
/// notification — not the record — that is logged today.
pub const RECORD_FORMAT_VERSION: u8 = 0x80;

/// `struct SignBidirectionalEvent` as M11 stage 7 defines it: the same request
/// record with a FORMAT VERSION byte in front and a 1-byte RESPONSE KIND where
/// the two in-band ABI-JSON schema strings used to be.
///
/// | change | old | new |
/// |--------|-----|-----|
/// | head | — | `formatVersion: Uint<8>` = [`RECORD_FORMAT_VERSION`] |
/// | tail | `outputDeserializationSchema: Bytes<LEN_OUT>` + `respondSerializationSchema: Bytes<LEN_RESPOND>` | `responseKind: Uint<8>` |
///
/// Everything between is [`SignBidirectionalEvent`]'s, field for field, at the
/// same relative order — so every offset is the old one plus the version
/// byte ([`layout_v2`] is written that way rather than recounted).
///
/// WHAT THE KIND REPLACES: the schemas were the ABI types the MPC decodes the
/// destination-chain return data with, and the shape it serializes the
/// response back in — 68 bytes on a `<2>` record and 75 on a `<7>` one, hashed
/// into the request id on every request. A response KIND says the same thing
/// through a lookup table on the MPC side (`kind ↦ (ABI types, response
/// shape)`), in one byte, and it is the SAME enumeration the attested output
/// carries at its own byte 0 (M11 stage 5) — so the record declares which
/// response kind will settle it. WHO CHECKS WHAT, precisely: the settle
/// circuit asserts the ATTESTED OUTPUT's kind against its own compile-time
/// constant; the RECORD's kind byte is read by the MPC (which derives the
/// response shape from it) and is NOT yet read by any circuit — the
/// in-circuit bind of `record.kind == output.kind`, and a version-byte
/// assert beside it, are the queued hardening stage (milestones.org M11
/// follow-up), each one wire equality. Until it lands, an MPC that signed a
/// mismatched kind is caught by the settle circuit's own constant, and a
/// cross-request replay by the depositor gate.
///
/// The type parameter list also loses `LEN_OUT`/`LEN_RESPOND`: there are no
/// schema widths left for an instantiation to disagree about.
#[derive(Clone)]
pub struct SignBidirectionalEventV2<V: Vis3, const WORDS: usize> {
    /// [`RECORD_FORMAT_VERSION`] — a `Uint<8>`, the first byte a decoder reads.
    pub format_version: Wire3<FieldT, V>,
    pub sender: B32<V>,
    pub request_nonce: Wire3<FieldT, V>,
    pub key_version: Wire3<FieldT, V>,
    pub path: B32<V>,
    pub algo: Wire3<FieldT, V>,
    pub dest: Wire3<FieldT, V>,
    /// `params: Bytes<64>` — 3 limbs `[2, 31, 31]`, zero-fill today.
    pub params: BytesN<V, PARAMS_LEN>,
    pub tx_param_type: Wire3<FieldT, V>,
    pub tx_params: EvmType2TxParams<V, WORDS>,
    pub caip2_id: B32<V>,
    /// The response KIND this request expects — one Borsh byte, the same
    /// enumeration the attested output carries (the vault's
    /// `erc20_vault_borsh::RESPONSE_KIND_*`). A raw wire rather than a
    /// `Tag<K>`: the value is a contract-fixed constant at every construction
    /// site, so there is no argument to range-check, and the K would have to
    /// become a third const parameter of this type for no reader's benefit.
    pub response_kind: Wire3<FieldT, V>,
}

/// [`SignBidirectionalEventV2`]'s FAB slot layout — [`layout`]'s, shifted by
/// the one format-version limb, with the schemas' slots replaced by the kind's.
///
/// Written as `1 + layout::X` rather than recounted, which is the statement
/// that stage 7 changes the record at its two ENDS and nowhere in between:
/// there is no offset here that can drift from the deployed record's except by
/// that one limb.
pub mod layout_v2 {
    use super::layout;

    /// `formatVersion: Uint<8>` — the first byte and the first slot.
    pub const FORMAT_VERSION: usize = 0;
    /// The shift every later field takes: the version limb.
    const HEAD: usize = 1;

    pub const SENDER: usize = HEAD + layout::SENDER;
    pub const REQUEST_NONCE: usize = HEAD + layout::REQUEST_NONCE;
    pub const KEY_VERSION: usize = HEAD + layout::KEY_VERSION;
    pub const PATH: usize = HEAD + layout::PATH;
    pub const ALGO: usize = HEAD + layout::ALGO;
    pub const DEST: usize = HEAD + layout::DEST;
    pub const PARAMS: usize = HEAD + layout::PARAMS;
    pub const TX_PARAM_TYPE: usize = HEAD + layout::TX_PARAM_TYPE;
    pub const CHAIN_ID: usize = HEAD + layout::CHAIN_ID;
    pub const NONCE: usize = HEAD + layout::NONCE;
    pub const MAX_PRIORITY_FEE_PER_GAS: usize = HEAD + layout::MAX_PRIORITY_FEE_PER_GAS;
    pub const MAX_FEE_PER_GAS: usize = HEAD + layout::MAX_FEE_PER_GAS;
    pub const GAS_LIMIT: usize = HEAD + layout::GAS_LIMIT;
    pub const TO: usize = HEAD + layout::TO;
    pub const VALUE: usize = HEAD + layout::VALUE;
    pub const CALLDATA_IS_SOME: usize = HEAD + layout::CALLDATA_IS_SOME;
    pub const SELECTOR: usize = HEAD + layout::SELECTOR;
    pub const NO_WORDS: usize = HEAD + layout::NO_WORDS;
    pub const WORDS: usize = HEAD + layout::WORDS;

    pub const fn word_hi(i: usize) -> usize {
        HEAD + layout::word_hi(i)
    }
    pub const fn word_lo(i: usize) -> usize {
        HEAD + layout::word_lo(i)
    }
    pub const fn access_list_entry_count(words: usize) -> usize {
        HEAD + layout::access_list_entry_count(words)
    }
    pub const fn caip2_id(words: usize) -> usize {
        HEAD + layout::caip2_id(words)
    }
    /// `responseKind: Uint<8>` — where the two schemas used to start.
    pub const fn response_kind(words: usize) -> usize {
        caip2_id(words) + 2
    }

    /// The record's total limb count (31 for the vault's `<2>`, 41 for `<7>`).
    pub const fn limbs(words: usize) -> usize {
        response_kind(words) + 1
    }
}

impl<V: Vis3, const WORDS: usize> SignBidirectionalEventV2<V, WORDS> {
    /// The record's FAB limb count.
    pub const LIMBS: usize = layout_v2::limbs(WORDS);

    /// The record's FAB atoms — [`SignBidirectionalEvent::atoms`] with the
    /// version byte in front and the kind byte where the schemas were.
    pub fn atoms() -> Vec<AlignmentAtom> {
        let mut a = vec![bytes(1)]; // formatVersion
        a.extend(record_atoms_through_caip2::<V, WORDS>());
        a.push(bytes(1)); // responseKind
        a
    }

    /// The record's FAB limbs, slot order ([`Self::LIMBS`] of them).
    pub fn limbs(&self) -> Vec<Wire3<FieldT, V>> {
        let mut l = vec![
            self.format_version,
            self.sender.hi,
            self.sender.lo,
            self.request_nonce,
            self.key_version,
            self.path.hi,
            self.path.lo,
            self.algo,
            self.dest,
        ];
        l.extend(self.params.limbs().iter().copied());
        l.push(self.tx_param_type);
        l.extend(self.tx_params.limbs());
        l.push(self.caip2_id.hi);
        l.push(self.caip2_id.lo);
        l.push(self.response_kind);
        debug_assert_eq!(l.len(), Self::LIMBS);
        l
    }
}

/// A [`SignBidirectionalEventV2`] read back out of the ledger — the stage-7
/// twin of [`EventRecord`], and a DISTINCT type, so a settle circuit cannot
/// read a stage-7 record with the deployed record's offsets (or the reverse).
pub struct EventRecordV2<const WORDS: usize>(Vec<Wire3<FieldT, Public>>);

impl<const WORDS: usize> EventRecordV2<WORDS> {
    pub const LIMBS: usize = layout_v2::limbs(WORDS);

    /// `path` — the depositor's identity commitment.
    pub fn path(&self) -> B32<Public> {
        B32 {
            hi: self.0[layout_v2::PATH],
            lo: self.0[layout_v2::PATH + 1],
        }
    }

    /// `txParams.to`.
    pub fn to(&self) -> Wire3<FieldT, Public> {
        self.0[layout_v2::TO]
    }

    /// `txParams.calldata.is_some`.
    pub fn calldata_is_some(&self) -> Wire3<FieldT, Public> {
        self.0[layout_v2::CALLDATA_IS_SOME]
    }

    /// `txParams.calldata.words[i]`.
    pub fn word(&self, i: usize) -> B32<Public> {
        assert!(i < WORDS, "word {i} of a {WORDS}-word record");
        B32 {
            hi: self.0[layout_v2::word_hi(i)],
            lo: self.0[layout_v2::word_lo(i)],
        }
    }
}

impl<const WORDS: usize> LedgerRepr for EventRecordV2<WORDS> {
    fn atoms() -> Vec<AlignmentAtom> {
        SignBidirectionalEventV2::<Public, WORDS>::atoms()
    }

    fn push_limbs(&self, _c: &mut Circuit3, limbs: &mut Vec<Wire3<FieldT, Public>>) {
        limbs.extend_from_slice(&self.0);
    }

    fn from_limbs(limbs: Vec<Wire3<FieldT, Public>>) -> Self {
        assert_eq!(
            limbs.len(),
            Self::LIMBS,
            "event record takes {} limbs",
            Self::LIMBS
        );
        EventRecordV2(limbs)
    }
}

/// [`construct_sign_bidirectional_event`] for the stage-7 record: the same
/// `keyVersion >= 1` assert and the same zero-filled `params`, with the format
/// version supplied here (a contract cannot choose it) and the two schema
/// arguments replaced by the response kind.
///
/// `response_kind` is a `u8` because the atom is `bytes(1)`: a kind of 256 or
/// more is not a wide field, it is a record whose last limb cannot hold the
/// value the caller wrote. The vault's constants are `u32` (they are also
/// `Tag<K>` parameters, where the const generic is a `u32`), so a call site
/// casts — and the cast is where the type says the wire is one byte.
#[allow(clippy::too_many_arguments)]
pub fn construct_sign_bidirectional_event_v2<V: Vis3, const WORDS: usize>(
    c: &mut Circuit3,
    sender: B32<V>,
    request_nonce: Wire3<FieldT, V>,
    key_version: Wire3<FieldT, V>,
    path: B32<V>,
    tx_params: EvmType2TxParams<V, WORDS>,
    caip2_id: B32<V>,
    response_kind: u8,
) -> SignBidirectionalEventV2<V, WORDS> {
    c.region("signet: event assembly", |c| {
        let zero = V::from_public(c.constant(0u64));
        let is_zero = c.test_eq(key_version, zero);
        let nonzero = c.not(is_zero);
        c.assert(nonzero);

        let format_version = V::from_public(c.constant(u64::from(RECORD_FORMAT_VERSION)));
        let response_kind = V::from_public(c.constant(u64::from(response_kind)));
        // pad(64, "")
        let params = BytesN::from_limbs(vec![zero; BytesN::<V, PARAMS_LEN>::LIMBS]);
        SignBidirectionalEventV2 {
            format_version,
            sender,
            request_nonce,
            key_version,
            path,
            algo: zero, // MPCSignatureAlgorithm.ecdsa
            dest: zero, // MPCDestination.unused
            params,
            tx_param_type: zero, // TxParamType.evmType2
            tx_params,
            caip2_id,
            response_kind,
        }
    })
}

/// [`calculate_request_id`] over a stage-7 record: `keccak256` of the whole
/// record in its FAB alignment, which for these all-`bytes<n>` atoms IS
/// `keccak256(borsh(record))` (notes/borsh-format.org, finding #1).
pub fn calculate_request_id_v2<V: Vis3, const WORDS: usize>(
    c: &mut Circuit3,
    request: &SignBidirectionalEventV2<V, WORDS>,
) -> RequestId<V> {
    request_id_of(
        c,
        SignBidirectionalEventV2::<V, WORDS>::atoms(),
        &request.limbs(),
    )
}

/// A `SignBidirectionalEvent` read back out of the ledger: the map value's
/// limbs in FAB slot order. The instantiation's consts are part of the
/// type, so a 2-word record cannot be read with 7-word offsets.
pub struct EventRecord<const WORDS: usize, const LEN_OUT: usize, const LEN_RESPOND: usize>(
    Vec<Wire3<FieldT, Public>>,
);

impl<const WORDS: usize, const LEN_OUT: usize, const LEN_RESPOND: usize>
    EventRecord<WORDS, LEN_OUT, LEN_RESPOND>
{
    pub const LIMBS: usize = layout::limbs(WORDS, LEN_OUT, LEN_RESPOND);

    /// `path` — the depositor's identity commitment.
    pub fn path(&self) -> B32<Public> {
        B32 {
            hi: self.0[layout::PATH],
            lo: self.0[layout::PATH + 1],
        }
    }

    /// `txParams.to`.
    pub fn to(&self) -> Wire3<FieldT, Public> {
        self.0[layout::TO]
    }

    /// `txParams.calldata.is_some`.
    pub fn calldata_is_some(&self) -> Wire3<FieldT, Public> {
        self.0[layout::CALLDATA_IS_SOME]
    }

    /// `txParams.calldata.words[i]`.
    pub fn word(&self, i: usize) -> B32<Public> {
        assert!(i < WORDS, "word {i} of a {WORDS}-word record");
        B32 {
            hi: self.0[layout::word_hi(i)],
            lo: self.0[layout::word_lo(i)],
        }
    }
}

/// What the LEDGER holds a request as: the atoms of the record type, and its
/// limbs in FAB slot order. Both directions live here, in ONE impl, which is
/// the point — the map that stores a request and the settle circuit that
/// reads it back cannot be given different atom lists, because neither
/// writes one (`LedgerMap<_, VaultRecord>` takes them from this type).
impl<const WORDS: usize, const LEN_OUT: usize, const LEN_RESPOND: usize> LedgerRepr
    for EventRecord<WORDS, LEN_OUT, LEN_RESPOND>
{
    fn atoms() -> Vec<AlignmentAtom> {
        SignBidirectionalEvent::<Public, WORDS, LEN_OUT, LEN_RESPOND>::atoms()
    }

    fn push_limbs(&self, _c: &mut Circuit3, limbs: &mut Vec<Wire3<FieldT, Public>>) {
        limbs.extend_from_slice(&self.0);
    }

    fn from_limbs(limbs: Vec<Wire3<FieldT, Public>>) -> Self {
        assert_eq!(
            limbs.len(),
            Self::LIMBS,
            "event record takes {} limbs",
            Self::LIMBS
        );
        EventRecord(limbs)
    }
}

/// `constructSignBidirectionalEvent(...)` — assembles the record and
/// asserts `keyVersion >= 1` (for a `Uint<8>`: `keyVersion != 0`).
#[allow(clippy::too_many_arguments)]
pub fn construct_sign_bidirectional_event<
    V: Vis3,
    const WORDS: usize,
    const LEN_OUT: usize,
    const LEN_RESPOND: usize,
>(
    c: &mut Circuit3,
    sender: B32<V>,
    request_nonce: Wire3<FieldT, V>,
    key_version: Wire3<FieldT, V>,
    path: B32<V>,
    tx_params: EvmType2TxParams<V, WORDS>,
    caip2_id: B32<V>,
    output_deserialization_schema: BytesN<V, LEN_OUT>,
    respond_serialization_schema: BytesN<V, LEN_RESPOND>,
) -> SignBidirectionalEvent<V, WORDS, LEN_OUT, LEN_RESPOND> {
    c.region("signet: event assembly", |c| {
        let zero = V::from_public(c.constant(0u64));
        let is_zero = c.test_eq(key_version, zero);
        let nonzero = c.not(is_zero);
        c.assert(nonzero);

        // pad(64, "")
        let params = BytesN::from_limbs(vec![zero; BytesN::<V, PARAMS_LEN>::LIMBS]);
        SignBidirectionalEvent {
            sender,
            request_nonce,
            key_version,
            path,
            algo: zero, // MPCSignatureAlgorithm.ecdsa
            dest: zero, // MPCDestination.unused
            params,
            tx_param_type: zero, // TxParamType.evmType2
            tx_params,
            caip2_id,
            output_deserialization_schema,
            respond_serialization_schema,
        }
    })
}

/// `calculateRequestId(request)` — `keccak256` of the whole record in its
/// FAB alignment.
pub fn calculate_request_id<
    V: Vis3,
    const WORDS: usize,
    const LEN_OUT: usize,
    const LEN_RESPOND: usize,
>(
    c: &mut Circuit3,
    request: &SignBidirectionalEvent<V, WORDS, LEN_OUT, LEN_RESPOND>,
) -> RequestId<V> {
    request_id_of(
        c,
        SignBidirectionalEvent::<V, WORDS, LEN_OUT, LEN_RESPOND>::atoms(),
        &request.limbs(),
    )
}

/// The keccak half of [`calculate_request_id`], over an atom list and its
/// limbs — shared with [`calculate_request_id_v2`] so the two record formats
/// hash through ONE construction rather than two copies of it. The extraction
/// is instruction-for-instruction identical to the inlined original (the row
/// and interface snapshots and every vault differential suite say so).
fn request_id_of<V: Vis3>(
    c: &mut Circuit3,
    atoms: Vec<AlignmentAtom>,
    limbs: &[Wire3<FieldT, V>],
) -> RequestId<V> {
    c.region("signet: request id (keccak)", |c| {
        let alignment = Alignment(atoms.into_iter().map(AlignmentSegment::Atom).collect());
        let limbs: Vec<_> = limbs.iter().map(|w| w.erase()).collect();
        let digest = c.keccak256(alignment, &limbs);
        RequestId::from_typed(c, digest)
    })
}

// ---- attestation verify -----------------------------------------------------

/// `calculateSignetAttestationDigest(requestId, serializedOutput)` —
/// `keccak256` over the raw concatenation `[Bytes<32>, Bytes<len>]`.
/// `output_limbs` are the serialized output's FAB limbs for `LEN_OUTPUT`
/// bytes ([`BytesN`] slot order above — the settle circuits' 1/5/8-byte
/// outputs are all the single limb of a `Bytes<n <= 31>`).
pub fn calculate_attestation_digest<V: Vis3, const LEN_OUTPUT: usize>(
    c: &mut Circuit3,
    request_id: &RequestId<V>,
    output_limbs: &[Wire3<FieldT, V>],
) -> B32<V> {
    c.region("signet: attestation digest (keccak)", |c| {
        let alignment = Alignment(vec![atom(32), atom(LEN_OUTPUT as u32)]);
        let mut limbs = vec![request_id.bytes().hi.erase(), request_id.bytes().lo.erase()];
        limbs.extend(output_limbs.iter().map(|w| w.erase()));
        let digest = c.keccak256(alignment, &limbs);
        B32::from_typed(c, digest)
    })
}

/// `reverseBytes32(b)` — byte-order adapter (stored records are
/// big-endian, the scalar casts read little-endian). ZKIR's native
/// `ReverseBytes` instruction (~150 rows) replaces the Compact stdlib's
/// explode/rebuild chain (~4600 rows, what compactc emits).
pub fn reverse_bytes32<V: Vis3>(c: &mut Circuit3, b: &B32<V>) -> B32<V> {
    let typed = b.to_typed(c);
    let rev = c.reverse_bytes(typed);
    B32::from_typed(c, rev)
}

/// `verifyRespondBidirectionalEvent(requestId, serializedOutput, event,
/// mpcResponseKey)` — recompute the attestation digest and verify the
/// event's ECDSA signature over it. Only `bigR.x` and `s` enter
/// verification (big-endian stored, reversed into scalars).
pub fn verify_respond_bidirectional_event<V: Vis3, const LEN_OUTPUT: usize>(
    c: &mut Circuit3,
    request_id: &RequestId<V>,
    output_limbs: &[Wire3<FieldT, V>],
    big_r_x: &B32<V>,
    s: &B32<V>,
    mpc_response_key: minocrab::v3::Wire3<minocrab::v3::Secp256k1PointT, V>,
) -> Wire3<FieldT, V> {
    let digest = calculate_attestation_digest::<V, LEN_OUTPUT>(c, request_id, output_limbs);
    verify_attestation_signature(c, &digest, big_r_x, s, mpc_response_key)
}

/// The signature half of [`verify_respond_bidirectional_event`], over an
/// already-computed digest: only `bigR.x` and `s` enter verification
/// (big-endian stored, reversed into scalars).
///
/// Extracted so the two digest constructions — the deployed
/// `[Bytes<32>, Bytes<len>]` concatenation and the Borsh-typed
/// [`calculate_attestation_digest_borsh`] — share one verifier rather than
/// two copies of the ECDSA plumbing. The extraction is instruction-for-
/// instruction identical to the inlined original (row and interface
/// snapshots, and every vault differential suite, say so).
fn verify_attestation_signature<V: Vis3>(
    c: &mut Circuit3,
    digest: &B32<V>,
    big_r_x: &B32<V>,
    s: &B32<V>,
    mpc_response_key: minocrab::v3::Wire3<minocrab::v3::Secp256k1PointT, V>,
) -> Wire3<FieldT, V> {
    c.region("signet: attestation verify (ecdsa)", |c| {
        let r_le = reverse_bytes32(c, big_r_x);
        let s_le = reverse_bytes32(c, s);
        let r_typed = r_le.to_typed(c);
        let s_typed = s_le.to_typed(c);
        let sig = Secp256k1EcdsaSignature {
            r: c.from_bytes32(r_typed),
            s: c.from_bytes32(s_typed),
        };
        secp256k1_ecdsa_verify(c, &digest, &sig, mpc_response_key)
    })
}

/// `calculateSignetAttestationDigest(requestId, output)` where the output is
/// a TYPED Borsh value — M11 stage 5's form of the digest.
///
/// The preimage is `borsh({ request_id: [u8; 32], output: T })`: a Borsh
/// struct is the concatenation of its fields, so this is the request id's 32
/// bytes followed by `borsh(output)`, and the alignment is the two values'
/// atoms back to back. That is exactly the shape
/// [`calculate_attestation_digest`] hashes today (stage 0 proved the deployed
/// preimage IS canonical Borsh for `{[u8; 32], [u8; N]}`); what changes is
/// that the second field is now a DECLARED type — a kind byte and its
/// payload — instead of an opaque byte string.
///
/// FREE: describing the preimage emits no instruction ([`limbs_of`] is
/// bookkeeping over wires that already exist), and the keccak chip does the
/// byte packing in-chip. The atom widths ARE the Borsh widths, so the digest
/// is `keccak256(borsh(v))` for zero extra rows.
pub fn calculate_attestation_digest_borsh<V: Vis3, T: CircuitBorsh<V>>(
    c: &mut Circuit3,
    request_id: &RequestId<V>,
    output: &T,
) -> B32<V> {
    c.region("signet: attestation digest (keccak)", |c| {
        let mut limbs = Limbs::<V>::new();
        request_id.push_limbs(&mut limbs);
        output.push_limbs(&mut limbs);
        assert_eq!(
            limbs.len(),
            <B32<V> as CircuitBorsh<V>>::LEN + T::LEN,
            "the attestation preimage is the request id followed by the output"
        );
        let digest = limbs.keccak256(c);
        B32::from_typed(c, digest)
    })
}

/// [`verify_respond_bidirectional_event`] over a TYPED Borsh output — M11
/// stage 5. Same signature check, same MPC key, a digest whose preimage
/// carries the response kind.
pub fn verify_respond_bidirectional_event_borsh<V: Vis3, T: CircuitBorsh<V>>(
    c: &mut Circuit3,
    request_id: &RequestId<V>,
    output: &T,
    big_r_x: &B32<V>,
    s: &B32<V>,
    mpc_response_key: minocrab::v3::Wire3<minocrab::v3::Secp256k1PointT, V>,
) -> Wire3<FieldT, V> {
    let digest = calculate_attestation_digest_borsh(c, request_id, output);
    verify_attestation_signature(c, &digest, big_r_x, s, mpc_response_key)
}

// ---- ABI calldata word utilities --------------------------------------------

/// `evmAddressAbiWord(addr)` — 12 zero bytes then the 20 display-order
/// address bytes. `addr` is the `Bytes<20>` single limb.
pub fn evm_address_abi_word<V: Vis3>(c: &mut Circuit3, addr: Wire3<FieldT, V>) -> B32<V> {
    c.region("abi words", |c| {
        // The word is addr·2^96 (a 12-byte shift), so split the 160-bit
        // limb at bit 152: hi byte = addr >> 152, lo = the rest shifted.
        let (hi, low152) = c.div_mod_power_of_two(addr, 152);
        let shift96 = V::from_public(pow2_const(c, 12));
        let lo = c.mul(low152, shift96);
        B32 { hi, lo }
    })
}

/// `numericAbiWord(value)` — the `Uint<128>` as a 32-byte big-endian
/// integer: 16 zero bytes then the value's 16 LE bytes reversed.
pub fn numeric_abi_word<V: Vis3>(c: &mut Circuit3, value: Wire3<FieldT, V>) -> B32<V> {
    c.region("abi words", |c| {
        // value's 16 LE bytes sit at string positions 0..15 of
        // `B32 { lo: value, hi: 0 }`; the native reversal moves them,
        // reversed, to positions 16..31 — exactly the BE ABI rendering.
        let zero = V::from_public(c.constant(0u64));
        let padded = B32 { hi: zero, lo: value };
        reverse_bytes32(c, &padded)
    })
}

/// `abiWordToUint128(word)` — asserts the leading 16 bytes are zero and
/// folds the trailing 16 big-endian bytes back into a `Uint<128>`.
pub fn abi_word_to_uint128<V: Vis3>(c: &mut Circuit3, word: &B32<V>) -> Wire3<FieldT, V> {
    abi_word_to_uint128_with(c, None, word)
}

/// [`abi_word_to_uint128`] inside a conditional: the canonical-word assert
/// only binds when the branch is taken.
pub fn abi_word_to_uint128_guarded<V: Vis3>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    word: &B32<V>,
) -> Wire3<FieldT, V> {
    abi_word_to_uint128_with(c, Some(guard), word)
}

fn abi_word_to_uint128_with<V: Vis3>(
    c: &mut Circuit3,
    guard: Option<Wire3<FieldT, V>>,
    word: &B32<V>,
) -> Wire3<FieldT, V> {
    c.region("abi words", |c| {
        // Reversed, the BE value's bytes land at string positions 0..15
        // (LSB first) and the zero head at 16..31: the value is the
        // reversal mod 2^128, and the head check is "everything above
        // bit 128 of the reversal is zero".
        let rev = reverse_bytes32(c, word);
        let (above, value) = c.div_mod_power_of_two(rev.lo, 128);
        let zero = V::from_public(c.constant(0u64));
        let above_zero = c.test_eq(above, zero);
        let hi_zero = c.test_eq(rev.hi, zero);
        let head_zero = c.mul(above_zero, hi_zero);
        match guard {
            Some(g) => {
                let one = V::from_public(c.constant(1u64));
                let gated = c.cond_select(g, head_zero, one);
                c.assert(gated);
            }
            None => c.assert(head_zero),
        }
        value
    })
}

/// `slice<20>(word, 12)` — the low 20 bytes of an ABI word as the
/// `Bytes<20>` single limb (the vault reads token addresses back out of
/// stored calldata words).
pub fn abi_word_low20<V: Vis3>(c: &mut Circuit3, word: &B32<V>) -> Wire3<FieldT, V> {
    c.region("abi words", |c| {
        // Bytes 12.. of the string are the word shifted right 96 bits:
        // (lo >> 96) plus the top byte re-shifted to string position 19.
        let (above96, _low12) = c.div_mod_power_of_two(word.lo, 96);
        let shift152 = V::from_public(pow2_const(c, 19));
        let top = c.mul(word.hi, shift152);
        c.add(above96, top)
    })
}


#[cfg(test)]
mod tests {
    use super::*;

    /// A zero-filled record of the given instantiation — only its shape
    /// (atom widths, limb count) is under test.
    fn zero_event<const WORDS: usize, const LEN_OUT: usize, const LEN_RESPOND: usize>(
        c: &mut Circuit3,
    ) -> SignBidirectionalEvent<Public, WORDS, LEN_OUT, LEN_RESPOND> {
        let zero = c.constant(0u64);
        let b32 = B32 { hi: zero, lo: zero };
        let zeros = |n: usize| vec![zero; n];
        SignBidirectionalEvent {
            sender: b32,
            request_nonce: zero,
            key_version: zero,
            path: b32,
            algo: zero,
            dest: zero,
            params: BytesN::from_limbs(zeros(BytesN::<Public, PARAMS_LEN>::LIMBS)),
            tx_param_type: zero,
            tx_params: EvmType2TxParams {
                chain_id: zero,
                nonce: zero,
                max_priority_fee_per_gas: zero,
                max_fee_per_gas: zero,
                gas_limit: zero,
                to: zero,
                value: zero,
                calldata_is_some: zero,
                calldata: EvmCalldata {
                    selector: zero,
                    no_words: zero,
                    words: [b32; WORDS],
                },
                access_list_entry_count: zero,
            },
            caip2_id: b32,
            output_deserialization_schema: BytesN::from_limbs(zeros(
                BytesN::<Public, LEN_OUT>::LIMBS,
            )),
            respond_serialization_schema: BytesN::from_limbs(zeros(
                BytesN::<Public, LEN_RESPOND>::LIMBS,
            )),
        }
    }

    fn atom_lens(atoms: &[AlignmentAtom]) -> Vec<u32> {
        atoms
            .iter()
            .map(|a| match a {
                AlignmentAtom::Bytes { length } => *length,
                _ => panic!("all atoms are bytes"),
            })
            .collect()
    }

    /// The vault's 2-word event instantiation must reproduce the corpus
    /// artifact's FAB layout: 24 atoms, 33 limbs (claim.zkir:287).
    #[test]
    fn vault_event_layout_matches_corpus() {
        type Event = SignBidirectionalEvent<Public, 2, 34, 34>;
        let mut c = Circuit3::new();
        let event = zero_event::<2, 34, 34>(&mut c);

        let atoms = Event::atoms();
        assert_eq!(atoms.len(), 24);
        // The corpus popeq's atom elements, in order (bytes lengths).
        assert_eq!(
            atom_lens(&atoms),
            vec![
                0x20, 0x08, 0x01, 0x20, 0x01, 0x01, 0x40, 0x01, // header
                0x08, 0x08, 0x10, 0x10, 0x08, 0x14, 0x10, // envelope
                0x01, 0x04, 0x02, 0x20, 0x20, // Maybe tag + calldata
                0x01, // accessListEntryCount
                0x20, 0x22, 0x22, // caip2Id + schemas
            ]
        );
        assert_eq!(Event::LIMBS, 33);
        assert_eq!(event.limbs().len(), 33);
        assert_eq!(EventRecord::<2, 34, 34>::LIMBS, 33);
    }

    /// The swap instantiation (`<7, 38, 37>`, what `swap`/`completeSwap`
    /// use): the same layout with five more calldata words and the two
    /// wider schemas — 29 atoms, 43 limbs.
    #[test]
    fn swap_event_layout() {
        type Event = SignBidirectionalEvent<Public, 7, 38, 37>;
        let mut c = Circuit3::new();
        let event = zero_event::<7, 38, 37>(&mut c);

        let atoms = Event::atoms();
        assert_eq!(atoms.len(), 29);
        assert_eq!(
            atom_lens(&atoms),
            vec![
                0x20, 0x08, 0x01, 0x20, 0x01, 0x01, 0x40, 0x01, // header
                0x08, 0x08, 0x10, 0x10, 0x08, 0x14, 0x10, // envelope
                0x01, 0x04, 0x02, // Maybe tag + calldata head
                0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, // 7 words
                0x01,  // accessListEntryCount
                0x20, 0x26, 0x25, // caip2Id + schemas (38, 37)
            ]
        );
        assert_eq!(Event::LIMBS, 43);
        assert_eq!(event.limbs().len(), 43);
        assert_eq!(EventRecord::<7, 38, 37>::LIMBS, 43);
    }

    /// M11 STAGE 7, both instantiations: the record's atoms are the deployed
    /// record's with a `bytes<1>` version in front and a `bytes<1>` kind where
    /// the two schema atoms were — stated against the DEPLOYED list rather
    /// than against a second hand count, so the two formats cannot drift in
    /// the middle.
    #[test]
    fn v2_atoms_are_the_deployed_atoms_with_the_two_ends_replaced() {
        for (deployed, v2, schemas) in [
            (
                SignBidirectionalEvent::<Public, 2, 34, 34>::atoms(),
                SignBidirectionalEventV2::<Public, 2>::atoms(),
                2usize,
            ),
            (
                SignBidirectionalEvent::<Public, 7, 38, 37>::atoms(),
                SignBidirectionalEventV2::<Public, 7>::atoms(),
                2,
            ),
        ] {
            let middle = &deployed[..deployed.len() - schemas];
            let mut expected = vec![bytes(1)];
            expected.extend(middle.iter().copied());
            expected.push(bytes(1));
            assert_eq!(atom_lens(&v2), atom_lens(&expected));
        }
    }

    /// The stage-7 records' shapes as NUMBERS: 24 atoms / 31 limbs / 338
    /// bytes for the vault instantiation, 29 / 41 / 498 for the swap one.
    /// (The deployed pair is 24 / 33 / 404 and 29 / 43 / 571.)
    #[test]
    fn v2_shapes() {
        let bin_len = |atoms: &[AlignmentAtom]| -> u32 {
            atoms
                .iter()
                .map(|a| match a {
                    AlignmentAtom::Bytes { length } => *length,
                    _ => panic!("all atoms are bytes"),
                })
                .sum()
        };
        let vault = SignBidirectionalEventV2::<Public, 2>::atoms();
        assert_eq!(vault.len(), 24);
        assert_eq!(bin_len(&vault), 338);
        assert_eq!(SignBidirectionalEventV2::<Public, 2>::LIMBS, 31);
        assert_eq!(EventRecordV2::<2>::LIMBS, 31);

        let swap = SignBidirectionalEventV2::<Public, 7>::atoms();
        assert_eq!(swap.len(), 29);
        assert_eq!(bin_len(&swap), 498);
        assert_eq!(SignBidirectionalEventV2::<Public, 7>::LIMBS, 41);
        assert_eq!(EventRecordV2::<7>::LIMBS, 41);

        // The limb count is also what the struct emits, per instantiation.
        let mut c = Circuit3::new();
        let z = c.constant(0u64);
        let b32 = B32 { hi: z, lo: z };
        let ev = SignBidirectionalEventV2::<Public, 2> {
            format_version: z,
            sender: b32,
            request_nonce: z,
            key_version: z,
            path: b32,
            algo: z,
            dest: z,
            params: BytesN::from_limbs(vec![z; BytesN::<Public, PARAMS_LEN>::LIMBS]),
            tx_param_type: z,
            tx_params: EvmType2TxParams {
                chain_id: z,
                nonce: z,
                max_priority_fee_per_gas: z,
                max_fee_per_gas: z,
                gas_limit: z,
                to: z,
                value: z,
                calldata_is_some: z,
                calldata: EvmCalldata {
                    selector: z,
                    no_words: z,
                    words: [b32; 2],
                },
                access_list_entry_count: z,
            },
            caip2_id: b32,
            response_kind: z,
        };
        assert_eq!(ev.limbs().len(), 31);
    }

    /// The stage-7 read offsets: every one is the deployed record's plus the
    /// version limb, and the kind sits where the schemas started.
    #[test]
    fn v2_read_offsets_are_the_deployed_ones_shifted_by_one() {
        assert_eq!(layout_v2::FORMAT_VERSION, 0);
        assert_eq!(layout_v2::PATH, layout::PATH + 1);
        assert_eq!(layout_v2::TO, layout::TO + 1);
        assert_eq!(layout_v2::CALLDATA_IS_SOME, layout::CALLDATA_IS_SOME + 1);
        assert_eq!(layout_v2::word_hi(0), layout::word_hi(0) + 1);
        assert_eq!(layout_v2::word_lo(5), layout::word_lo(5) + 1);
        // The kind takes the slot the first schema had.
        assert_eq!(
            layout_v2::response_kind(2),
            layout::output_deserialization_schema(2) + 1
        );
        assert_eq!(
            layout_v2::response_kind(7),
            layout::output_deserialization_schema(7) + 1
        );
    }

    /// The read offsets the settle circuits use, against the hand-counted
    /// table they replace (the 2-word record's slots).
    #[test]
    fn read_offsets_match_hand_counted_table() {
        assert_eq!(layout::PATH, 4); // [hi, lo] at 4, 5
        assert_eq!(layout::TO, 17);
        assert_eq!(layout::CALLDATA_IS_SOME, 19);
        assert_eq!(layout::word_hi(0), 22);
        assert_eq!(layout::word_lo(0), 23);
        assert_eq!(layout::word_hi(5), 32);
    }
}
