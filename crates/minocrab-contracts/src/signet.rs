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
//! two schema widths are runtime parameters of the port (the vault uses
//! `<2, 0, 0>, 34, 34` for transfers and `<7, 0, 0>, 38, 37` for swaps).

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Alignment, AlignmentAtom, AlignmentSegment};
use minocrab_std::v3::{
    pow2_const, secp256k1_ecdsa_verify, BytesN, BytesNDyn, Secp256k1EcdsaSignature, Vis3, B32,
};

fn atom(n: u32) -> AlignmentSegment {
    AlignmentSegment::Atom(AlignmentAtom::Bytes { length: n })
}

// ---- EVM Type2 transaction parameters ---------------------------------------

/// `struct EvmCalldata<#maxWords>` — selector (`Bytes<4>`), used-word
/// count (`Uint<16>`), and the canonical big-endian ABI words.
#[derive(Clone)]
pub struct EvmCalldata<V: Vis3> {
    pub selector: Wire3<FieldT, V>,
    pub no_words: Wire3<FieldT, V>,
    pub words: Vec<B32<V>>,
}

/// `struct EvmType2TxParams<#maxCalldataWords, 0, 0>` — the EIP-1559
/// envelope with an empty access list. `calldata` is
/// `Maybe<EvmCalldata<n>>`: the tag is `calldata_is_some`, a `none` value
/// carries a zeroed calldata.
#[derive(Clone)]
pub struct EvmType2TxParams<V: Vis3> {
    pub chain_id: Wire3<FieldT, V>,
    pub nonce: Wire3<FieldT, V>,
    pub max_priority_fee_per_gas: Wire3<FieldT, V>,
    pub max_fee_per_gas: Wire3<FieldT, V>,
    pub gas_limit: Wire3<FieldT, V>,
    pub to: Wire3<FieldT, V>,
    pub value: Wire3<FieldT, V>,
    pub calldata_is_some: Wire3<FieldT, V>,
    pub calldata: EvmCalldata<V>,
    pub access_list_entry_count: Wire3<FieldT, V>,
}

impl<V: Vis3> EvmType2TxParams<V> {
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

/// `struct SignBidirectionalEvent<TxParams, #LenOut, #LenRespond>` with
/// `TxParams = EvmType2TxParams`. Field order is the wire contract (the
/// request-id hash order and the ledger record layout).
#[derive(Clone)]
pub struct SignBidirectionalEvent<V: Vis3> {
    pub sender: B32<V>,
    pub request_nonce: Wire3<FieldT, V>,
    pub key_version: Wire3<FieldT, V>,
    pub path: B32<V>,
    pub algo: Wire3<FieldT, V>,
    pub dest: Wire3<FieldT, V>,
    /// `params: Bytes<64>` — 3 limbs `[2, 31, 31]`, zero-fill today.
    pub params: BytesN<V, 64>,
    pub tx_param_type: Wire3<FieldT, V>,
    pub tx_params: EvmType2TxParams<V>,
    pub caip2_id: B32<V>,
    /// The schemas' byte lengths vary per instantiation (34/37/38 in the
    /// vault), so they stay runtime-sized until the whole event record
    /// becomes const-generic in its `#LenOut`/`#LenRespond`.
    pub output_deserialization_schema: BytesNDyn<V>,
    pub respond_serialization_schema: BytesNDyn<V>,
}

/// `MPCSignatureAlgorithm.ecdsa` / `MPCDestination.unused` /
/// `TxParamType.evmType2` — all first enum members, value 0.
pub const MPC_ALGO_ECDSA: u64 = 0;
pub const MPC_DEST_UNUSED: u64 = 0;
pub const TX_PARAM_TYPE_EVM_TYPE2: u64 = 0;

/// The record's FAB atoms for a `words`-word empty-access-list
/// instantiation (claim.zkir:287 — 24 atoms for the vault's 2-word case).
pub fn event_atoms(words: usize, len_out: u32, len_respond: u32) -> Vec<AlignmentAtom> {
    let mut a = vec![
        AlignmentAtom::Bytes { length: 32 }, // sender
        AlignmentAtom::Bytes { length: 8 },  // requestNonce
        AlignmentAtom::Bytes { length: 1 },  // keyVersion
        AlignmentAtom::Bytes { length: 32 }, // path
        AlignmentAtom::Bytes { length: 1 },  // algo
        AlignmentAtom::Bytes { length: 1 },  // dest
        AlignmentAtom::Bytes { length: 64 }, // params
        AlignmentAtom::Bytes { length: 1 },  // txParamType
        AlignmentAtom::Bytes { length: 8 },  // chainId
        AlignmentAtom::Bytes { length: 8 },  // nonce
        AlignmentAtom::Bytes { length: 16 }, // maxPriorityFeePerGas
        AlignmentAtom::Bytes { length: 16 }, // maxFeePerGas
        AlignmentAtom::Bytes { length: 8 },  // gasLimit
        AlignmentAtom::Bytes { length: 20 }, // to
        AlignmentAtom::Bytes { length: 16 }, // value
        AlignmentAtom::Bytes { length: 1 },  // calldata.is_some
        AlignmentAtom::Bytes { length: 4 },  // selector
        AlignmentAtom::Bytes { length: 2 },  // noWords
    ];
    a.extend(std::iter::repeat_n(AlignmentAtom::Bytes { length: 32 }, words));
    a.push(AlignmentAtom::Bytes { length: 1 }); // accessListEntryCount
    a.push(AlignmentAtom::Bytes { length: 32 }); // caip2Id
    a.push(AlignmentAtom::Bytes { length: len_out });
    a.push(AlignmentAtom::Bytes { length: len_respond });
    a
}

/// Slot indices of the fields the settle circuits read back out of a
/// looked-up `words`-word event record (33 limbs for the 2-word case).
pub mod event_limb {
    /// `path` — `[hi, lo]` at 4, 5.
    pub const PATH_HI: usize = 4;
    pub const PATH_LO: usize = 5;
    /// `txParams.to`.
    pub const TO: usize = 17;
    /// `txParams.calldata.is_some`.
    pub const CALLDATA_IS_SOME: usize = 19;
    /// `txParams.calldata.words[i]` — `[hi, lo]` per word.
    pub const fn word_hi(i: usize) -> usize {
        22 + 2 * i
    }
    pub const fn word_lo(i: usize) -> usize {
        23 + 2 * i
    }
}

impl<V: Vis3> SignBidirectionalEvent<V> {
    /// The record's FAB atoms (claim.zkir:287 — 24 atoms for the 2-word
    /// vault instantiation).
    pub fn atoms(&self, len_out: u32, len_respond: u32) -> Vec<AlignmentAtom> {
        event_atoms(self.tx_params.calldata.words.len(), len_out, len_respond)
    }

    /// The record's FAB limbs, slot order (33 for the vault's 2-word
    /// instantiation).
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
        l.extend(self.output_deserialization_schema.limbs.iter().copied());
        l.extend(self.respond_serialization_schema.limbs.iter().copied());
        l
    }
}

/// `constructSignBidirectionalEvent(...)` — assembles the record and
/// asserts `keyVersion >= 1` (for a `Uint<8>`: `keyVersion != 0`).
#[allow(clippy::too_many_arguments)]
pub fn construct_sign_bidirectional_event<V: Vis3>(
    c: &mut Circuit3,
    sender: B32<V>,
    request_nonce: Wire3<FieldT, V>,
    key_version: Wire3<FieldT, V>,
    path: B32<V>,
    tx_params: EvmType2TxParams<V>,
    caip2_id: B32<V>,
    output_deserialization_schema: BytesNDyn<V>,
    respond_serialization_schema: BytesNDyn<V>,
) -> SignBidirectionalEvent<V> {
    c.region("signet: event assembly", |c| {
        let zero = V::from_public(c.constant(0u64));
        let is_zero = c.test_eq(key_version, zero);
        let nonzero = c.not(is_zero);
        c.assert(nonzero);

        let params = BytesN::from_limbs(vec![zero, zero, zero]); // pad(64, "")
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
pub fn calculate_request_id<V: Vis3>(
    c: &mut Circuit3,
    request: &SignBidirectionalEvent<V>,
    len_out: u32,
    len_respond: u32,
) -> B32<V> {
    c.region("signet: request id (keccak)", |c| {
        let alignment = Alignment(
            request
                .atoms(len_out, len_respond)
                .into_iter()
                .map(|a| AlignmentSegment::Atom(a))
                .collect(),
        );
        let limbs: Vec<_> = request.limbs().iter().map(|w| w.erase()).collect();
        let digest = c.keccak256(alignment, &limbs);
        B32::from_typed(c, digest)
    })
}

// ---- notification -----------------------------------------------------------

/// `constructSignBidirectionalEventNotificationV1(callerAddress, depth,
/// path)` with a compile-time path: the version byte (1) and the
/// `Bytes<128>` payload `callerAddress ‖ depth ‖ path[0..4] ‖ zeros`.
/// Returns `(version, payload)` — the notification struct's FAB limbs
/// are `[version, payload…]` (`Bytes<128>` = 5 limbs `[4, 31, 31, 31, 31]`).
pub fn construct_notification_v1<V: Vis3>(
    c: &mut Circuit3,
    caller_address: &B32<V>,
    requests_path_depth: u8,
    requests_path: [u8; 4],
) -> (Wire3<FieldT, V>, BytesN<V, 128>) {
    c.region("signet: notification", |c| {
        let version = V::from_public(c.constant(1u64));
        // The payload's 31-byte limbs line up with the caller address:
        // bytes 0..30 are caller.lo verbatim; bytes 31..61 pack caller.hi
        // (weight 1) with the compile-time depth ‖ path bytes at weights
        // 2^8..2^47; bytes 62..127 are zero.
        let mut packed: u64 = u64::from(requests_path_depth) << 8;
        for (i, p) in requests_path.into_iter().enumerate() {
            packed |= u64::from(p) << (16 + 8 * i);
        }
        let packed = V::from_public(c.constant(packed));
        let second = c.add(caller_address.hi, packed);
        let zero = V::from_public(c.constant(0u64));
        let payload = BytesN::from_limbs(vec![zero, zero, zero, second, caller_address.lo]);
        (version, payload)
    })
}

// ---- attestation verify -----------------------------------------------------

/// `calculateSignetAttestationDigest(requestId, serializedOutput)` —
/// `keccak256` over the raw concatenation `[Bytes<32>, Bytes<len>]`.
/// `output_limbs` are the serialized output's FAB limbs for `len_output`
/// bytes (a single limb for `len <= 31`, [`BytesN`] slot order above).
pub fn calculate_attestation_digest<V: Vis3>(
    c: &mut Circuit3,
    request_id: &B32<V>,
    output_limbs: &[Wire3<FieldT, V>],
    len_output: u32,
) -> B32<V> {
    c.region("signet: attestation digest (keccak)", |c| {
        let alignment = Alignment(vec![atom(32), atom(len_output)]);
        let mut limbs = vec![request_id.hi.erase(), request_id.lo.erase()];
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
pub fn verify_respond_bidirectional_event<V: Vis3>(
    c: &mut Circuit3,
    request_id: &B32<V>,
    output_limbs: &[Wire3<FieldT, V>],
    len_output: u32,
    big_r_x: &B32<V>,
    s: &B32<V>,
    mpc_response_key: minocrab::v3::Wire3<minocrab::v3::Secp256k1PointT, V>,
) -> Wire3<FieldT, V> {
    let digest = calculate_attestation_digest(c, request_id, output_limbs, len_output);
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
    use minocrab::Public;

    /// The vault's 2-word event instantiation must reproduce the corpus
    /// artifact's FAB layout: 24 atoms, 33 limbs (claim.zkir:287).
    #[test]
    fn vault_event_layout_matches_corpus() {
        let mut c = Circuit3::new();
        let zero = c.constant(0u64);
        let b32 = B32 { hi: zero, lo: zero };
        let word = B32 { hi: zero, lo: zero };
        let event: SignBidirectionalEvent<Public> = SignBidirectionalEvent {
            sender: b32,
            request_nonce: zero,
            key_version: zero,
            path: b32,
            algo: zero,
            dest: zero,
            params: BytesN::from_limbs(vec![zero, zero, zero]),
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
                    words: vec![word, word],
                },
                access_list_entry_count: zero,
            },
            caip2_id: b32,
            output_deserialization_schema: BytesNDyn::new(34, vec![zero, zero]),
            respond_serialization_schema: BytesNDyn::new(34, vec![zero, zero]),
        };

        let atoms = event.atoms(34, 34);
        assert_eq!(atoms.len(), 24);
        // The corpus popeq's atom elements, in order (bytes lengths).
        let lens: Vec<u32> = atoms
            .iter()
            .map(|a| match a {
                AlignmentAtom::Bytes { length } => *length,
                _ => panic!("all atoms are bytes"),
            })
            .collect();
        assert_eq!(
            lens,
            vec![
                0x20, 0x08, 0x01, 0x20, 0x01, 0x01, 0x40, 0x01, // header
                0x08, 0x08, 0x10, 0x10, 0x08, 0x14, 0x10, // envelope
                0x01, 0x04, 0x02, 0x20, 0x20, // Maybe tag + calldata
                0x01, // accessListEntryCount
                0x20, 0x22, 0x22, // caip2Id + schemas
            ]
        );
        assert_eq!(event.limbs().len(), 33);
    }
}
