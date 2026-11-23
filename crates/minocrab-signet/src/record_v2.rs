//! The stage-7 request record (`SignBidirectionalEventV2`): the
//! `fff3421c` record with a format version byte in front and a one-byte
//! response kind where the two schema strings were — the record the pending
//! vault's `Pending` slots write — together with the `fff3421c` slot layout
//! ([`layout`]) it is written over and the two pieces both record formats
//! share ([`record_atoms_through_caip2`], [`request_id_of`]).

use minocrab::{Circuit, FieldT, Wire};
use minocrab::{AlignmentAtom, Public};
use minocrab_std::hash::upgrade_from_transient;
use minocrab_std::{BytesN, ContractAddress, LedgerRepr, ProofWires, Vis, B32};

use crate::common::{Caip2Id, SigningPath};
use crate::signet_v1::{EvmType2TxParams, RequestId, PARAMS_LEN};

fn bytes(length: u32) -> AlignmentAtom {
    AlignmentAtom::Bytes { length }
}

/// The FAB atoms both record formats share: `sender` through `caip2Id`.
///
/// One definition, so the deployed record (`SignBidirectionalEvent`) and the
/// stage-7 record ([`SignBidirectionalEventV2`]) cannot drift in the middle —
/// stage 7 changes the two ends, and this function is what says so.
pub fn record_atoms_through_caip2<V: Vis, const WORDS: usize>() -> Vec<AlignmentAtom> {
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

/// The record's FAB slot layout: each field's first slot, derived by
/// summing the widths of the fields before it — the same declaration order
/// `SignBidirectionalEvent::limbs` emits. Nothing here is counted by
/// hand, so a field width change moves every later offset with it.
pub mod layout {
    use minocrab_std::bytes_limbs;

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
    /// caller's (`EventRecord::word`).
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

// ---- SignBidirectionalEventV2 — the stage-7 record -----------------------------

/// The record's format version byte, at offset 0 of every stage-7 record.
///
/// `0x80` — the byte with only the high bit set. The point
/// is headroom rather than taste: every version number anywhere in the pinned
/// stack is small (ZKIR envelope 2 and 3, Impact transcript 2.3, Compact
/// `language_version` 0.12..0.23, compactc 0.33), the largest number in any
/// position being 33 — so "this is not a small version number" is a single bit
/// test rather than a magnitude comparison, every value below it stays
/// available to Compact/Midnight, and a decoder that reads `0x80` where it
/// expected a Compact version knows immediately which format it is holding.
///
/// It is in the record only — never in an attested output, where the kind tag
/// suffices and the digest is signed (notes/borsh-format.org §"answered from
/// MPC source", Q4). The record is what the MPC reads back out of ledger
/// state, so this byte is what its FAB cursor sees first; the signet signer's
/// notification payload is a different, unchanged shape (Q6), and it is the
/// notification — not the record — that is logged today.
pub const RECORD_FORMAT_VERSION: u8 = 0x80;

/// `struct SignBidirectionalEvent` as stage 7 defines it: the same request
/// record with a format version byte in front and a 1-byte response kind where
/// the two in-band ABI-JSON schema strings used to be.
///
/// | change | old | new |
/// |--------|-----|-----|
/// | head | — | `formatVersion: Uint<8>` = [`RECORD_FORMAT_VERSION`] |
/// | tail | `outputDeserializationSchema: Bytes<LEN_OUT>` + `respondSerializationSchema: Bytes<LEN_RESPOND>` | `responseKind: Uint<8>` |
///
/// Everything between is `SignBidirectionalEvent`'s, field for field, at the
/// same relative order — so every offset is the old one plus the version
/// byte ([`layout_v2`] is written that way rather than recounted).
///
/// What the kind replaces: the schemas were the ABI types the MPC decodes the
/// destination-chain return data with, and the shape it serializes the
/// response back in — 68 bytes on a `<2>` record and 75 on a `<7>` one, hashed
/// into the request id on every request. A response kind says the same thing
/// through a lookup table on the MPC side (`kind ↦ (ABI types, response
/// shape)`), in one byte, and it is the same enumeration the attested output
/// carries at its own byte 0 — so the record declares which
/// response kind will settle it. Who checks what, precisely: the settle
/// circuit asserts the attested output's kind against its own compile-time
/// constant; the record's kind byte is read by the MPC (which derives the
/// response shape from it) and is not yet read by any circuit — the
/// in-circuit bind of `record.kind == output.kind`, and a version-byte
/// assert beside it, are queued hardening,
/// each one wire equality. Until then, an MPC that signed a
/// mismatched kind is caught by the settle circuit's own constant, and a
/// cross-request replay by the depositor gate.
///
/// The type parameter list also loses `LEN_OUT`/`LEN_RESPOND`: there are no
/// schema widths left for an instantiation to disagree about.
#[derive(Clone)]
pub struct SignBidirectionalEventV2<V: Vis, const WORDS: usize> {
    /// [`RECORD_FORMAT_VERSION`] — a `Uint<8>`, the first byte a decoder reads.
    pub format_version: Wire<FieldT, V>,
    pub sender: ContractAddress<V>,
    pub request_nonce: Wire<FieldT, V>,
    pub key_version: Wire<FieldT, V>,
    pub path: SigningPath<V>,
    pub algo: Wire<FieldT, V>,
    pub dest: Wire<FieldT, V>,
    /// `params: Bytes<64>` — 3 limbs `[2, 31, 31]`, zero-fill today.
    pub params: BytesN<V, PARAMS_LEN>,
    pub tx_param_type: Wire<FieldT, V>,
    pub tx_params: EvmType2TxParams<V, WORDS>,
    pub caip2_id: Caip2Id<V>,
    /// The response kind this request expects — one Borsh byte, the same
    /// enumeration the attested output carries (the vault's
    /// `erc20_vault_borsh::RESPONSE_KIND_*`). A raw wire rather than a
    /// `Tag<K>`: the value is a contract-fixed constant at every construction
    /// site, so there is no argument to range-check, and the K would have to
    /// become a third const parameter of this type for no reader's benefit.
    pub response_kind: Wire<FieldT, V>,
}

/// [`SignBidirectionalEventV2`]'s FAB slot layout — [`layout`]'s, shifted by
/// the one format-version limb, with the schemas' slots replaced by the kind's.
///
/// Written as `1 + layout::X` rather than recounted, which is the statement
/// that stage 7 changes the record at its two ends and nowhere in between:
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

impl<V: Vis, const WORDS: usize> SignBidirectionalEventV2<V, WORDS> {
    /// The record's FAB limb count.
    pub const LIMBS: usize = layout_v2::limbs(WORDS);

    /// The record's FAB atoms — `SignBidirectionalEvent::atoms` with the
    /// version byte in front and the kind byte where the schemas were.
    pub fn atoms() -> Vec<AlignmentAtom> {
        let mut a = vec![bytes(1)]; // formatVersion
        a.extend(record_atoms_through_caip2::<V, WORDS>());
        a.push(bytes(1)); // responseKind
        a
    }

    /// The record's FAB limbs, slot order ([`Self::LIMBS`] of them).
    pub fn limbs(&self) -> Vec<Wire<FieldT, V>> {
        let mut l = vec![
            self.format_version,
            self.sender.bytes().hi,
            self.sender.bytes().lo,
            self.request_nonce,
            self.key_version,
            self.path.bytes().hi,
            self.path.bytes().lo,
            self.algo,
            self.dest,
        ];
        l.extend(self.params.limbs().iter().copied());
        l.push(self.tx_param_type);
        l.extend(self.tx_params.limbs());
        l.push(self.caip2_id.bytes().hi);
        l.push(self.caip2_id.bytes().lo);
        l.push(self.response_kind);
        debug_assert_eq!(l.len(), Self::LIMBS);
        l
    }
}

/// A [`SignBidirectionalEventV2`] read back out of the ledger — the stage-7
/// twin of `EventRecord`, and a distinct type, so a settle circuit cannot
/// read a stage-7 record with the deployed record's offsets (or the reverse).
pub struct EventRecordV2<const WORDS: usize>(Vec<Wire<FieldT, Public>>);

impl<const WORDS: usize> EventRecordV2<WORDS> {
    pub const LIMBS: usize = layout_v2::limbs(WORDS);

    /// `path` — the record's signing path (the depositor's identity
    /// commitment on the deposit route, the vault path elsewhere).
    pub fn path(&self) -> SigningPath<Public> {
        SigningPath(B32 {
            hi: self.0[layout_v2::PATH],
            lo: self.0[layout_v2::PATH + 1],
        })
    }

    /// `formatVersion` — the record's first byte
    /// ([`RECORD_FORMAT_VERSION`]).
    pub fn format_version(&self) -> Wire<FieldT, Public> {
        self.0[layout_v2::FORMAT_VERSION]
    }

    /// `responseKind` — which response kind the record declared would
    /// settle it.
    pub fn response_kind(&self) -> Wire<FieldT, Public> {
        self.0[layout_v2::response_kind(WORDS)]
    }

    /// `txParams.to`.
    pub fn to(&self) -> Wire<FieldT, Public> {
        self.0[layout_v2::TO]
    }

    /// `txParams.calldata.is_some`.
    pub fn calldata_is_some(&self) -> Wire<FieldT, Public> {
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

impl<const WORDS: usize> ProofWires for EventRecordV2<WORDS> {
    fn push_wires(&self, out: &mut Vec<minocrab::Val>) {
        out.extend(self.0.iter().map(|w| w.val()));
    }
}

impl<const WORDS: usize> LedgerRepr for EventRecordV2<WORDS> {
    fn atoms() -> Vec<AlignmentAtom> {
        SignBidirectionalEventV2::<Public, WORDS>::atoms()
    }

    fn push_limbs(&self, _c: &mut Circuit, limbs: &mut Vec<Wire<FieldT, Public>>) {
        limbs.extend_from_slice(&self.0);
    }

    fn from_limbs(limbs: Vec<Wire<FieldT, Public>>) -> Self {
        assert_eq!(
            limbs.len(),
            Self::LIMBS,
            "event record takes {} limbs",
            Self::LIMBS
        );
        EventRecordV2(limbs)
    }
}

/// `construct_sign_bidirectional_event` for the stage-7 record: the same
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
pub fn construct_sign_bidirectional_event_v2<V: Vis, const WORDS: usize>(
    c: &mut Circuit,
    sender: ContractAddress<V>,
    request_nonce: Wire<FieldT, V>,
    key_version: Wire<FieldT, V>,
    path: SigningPath<V>,
    tx_params: EvmType2TxParams<V, WORDS>,
    caip2_id: Caip2Id<V>,
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

/// `calculate_request_id` over a stage-7 record: `keccak256` of the whole
/// record in its FAB alignment, which for these all-`bytes<n>` atoms IS
/// `keccak256(borsh(record))` (notes/borsh-format.org).
pub fn calculate_request_id_v2<V: Vis, const WORDS: usize>(
    c: &mut Circuit,
    request: &SignBidirectionalEventV2<V, WORDS>,
) -> RequestId<V> {
    request_id_of(c, &request.limbs())
}

/// The hash half of `calculate_request_id` over a record's FAB limbs —
/// shared with [`calculate_request_id_v2`] so the two record formats hash
/// through one construction.
///
/// `upgradeFromTransient(transientHash(record))` since signet-midnight
/// `fff3421c` ("Move in circuit hashing to transientHash"):
/// Poseidon over the record's field-aligned representation — one field
/// element per FAB limb, in slot order, which is what the MPC's reader
/// recomputes off-chain (`value_only_field_repr` of the stored cell) —
/// then the 31 low bytes as a `Bytes<32>` whose byte 31 is zero. The
/// keccak construction it replaces is in git history (the corpus at
/// signet-midnight-integration `1ee4a7f3`).
pub fn request_id_of<V: Vis>(c: &mut Circuit, limbs: &[Wire<FieldT, V>]) -> RequestId<V> {
    c.region("signet: request id (transientHash)", |c| {
        let f = c.transient_hash(limbs);
        RequestId(upgrade_from_transient(c, f))
    })
}
