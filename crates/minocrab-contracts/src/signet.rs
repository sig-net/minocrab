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
//!
//! What this generation shares with the live ones is defined there and
//! re-exported here: the transaction parameters, the ECDSA plumbing and the
//! ABI word decoder in [`crate::signet_v1`], the record layout and the
//! stage-7 record in [`minocrab_signet::record_v2`], the byte reversal in
//! [`minocrab_evm`]. Nothing outside this module's own tests reads the rest.

use minocrab::{Circuit, FieldT, Wire};
use minocrab::{AlignmentAtom, Public};
use minocrab_std::borsh::CircuitBorsh;
use minocrab_std::hash::upgrade_from_transient;
use minocrab_std::{
    pow2_const, BytesN, ContractAddress, LedgerRepr, Serializer, Vis, B32,
};

use crate::common::{Caip2Id, SigningPath};
use minocrab_signet::record_v2::{record_atoms_through_caip2, request_id_of};

pub use minocrab_evm::reverse_bytes32;
pub use minocrab_signet::record_v2::{
    calculate_request_id_v2, construct_sign_bidirectional_event_v2, layout, layout_v2,
    EventRecordV2, SignBidirectionalEventV2, RECORD_FORMAT_VERSION,
};
pub use crate::signet_v1::{
    abi_word_to_uint128, abi_word_to_uint128_guarded, verify_attestation_signature, EvmCalldata,
    EvmType2TxParams, Secp256k1SigLimbs, MPC_ALGO_ECDSA, MPC_DEST_UNUSED, PARAMS_LEN,
    TX_PARAM_TYPE_EVM_TYPE2,
};

/// The signer's request id — the keccak of a whole signing record, and the
/// key every event map and every refund commitment is filed under.
///
/// Re-exported from the interface crate (where the generator emits it from
/// the callee's own `RequestId = Bytes<32>` alias) so a vault fork can write
/// `signet::RequestId` without importing the crate: the forks already declare
/// a disclosure label called `RequestId`, and the module qualifier keeps the
/// two apart at every use.
pub use signet_signer_interface::RequestId;

/// `struct SignBidirectionalEvent<TxParams, #LenOut, #LenRespond>` with
/// `TxParams = EvmType2TxParams<#WORDS, 0, 0>`. Field order is the wire
/// contract (the request-id hash order and the ledger record layout).
#[derive(Clone)]
pub struct SignBidirectionalEvent<
    V: Vis,
    const WORDS: usize,
    const LEN_OUT: usize,
    const LEN_RESPOND: usize,
> {
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
    pub output_deserialization_schema: BytesN<V, LEN_OUT>,
    pub respond_serialization_schema: BytesN<V, LEN_RESPOND>,
}

impl<V: Vis, const WORDS: usize, const LEN_OUT: usize, const LEN_RESPOND: usize>
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
    pub fn limbs(&self) -> Vec<Wire<FieldT, V>> {
        let mut l = vec![
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
        l.extend(self.output_deserialization_schema.limbs().iter().copied());
        l.extend(self.respond_serialization_schema.limbs().iter().copied());
        debug_assert_eq!(l.len(), Self::LIMBS);
        l
    }
}

/// A `SignBidirectionalEvent` read back out of the ledger: the map value's
/// limbs in FAB slot order. The instantiation's consts are part of the
/// type, so a 2-word record cannot be read with 7-word offsets.
pub struct EventRecord<const WORDS: usize, const LEN_OUT: usize, const LEN_RESPOND: usize>(
    Vec<Wire<FieldT, Public>>,
);

impl<const WORDS: usize, const LEN_OUT: usize, const LEN_RESPOND: usize>
    EventRecord<WORDS, LEN_OUT, LEN_RESPOND>
{
    pub const LIMBS: usize = layout::limbs(WORDS, LEN_OUT, LEN_RESPOND);

    /// `path` — the record's signing path (the depositor's identity
    /// commitment on the deposit route, the vault path elsewhere).
    pub fn path(&self) -> SigningPath<Public> {
        SigningPath(B32 {
            hi: self.0[layout::PATH],
            lo: self.0[layout::PATH + 1],
        })
    }

    /// `txParams.to`.
    pub fn to(&self) -> Wire<FieldT, Public> {
        self.0[layout::TO]
    }

    /// `txParams.calldata.is_some`.
    pub fn calldata_is_some(&self) -> Wire<FieldT, Public> {
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

/// What the ledger holds a request as: the atoms of the record type, and its
/// limbs in FAB slot order. Both directions live here, in one impl, which is
/// the point — the map that stores a request and the settle circuit that
/// reads it back cannot be given different atom lists, because neither
/// writes one (`LedgerMap<_, VaultRecord>` takes them from this type).
impl<const WORDS: usize, const LEN_OUT: usize, const LEN_RESPOND: usize> LedgerRepr
    for EventRecord<WORDS, LEN_OUT, LEN_RESPOND>
{
    fn atoms() -> Vec<AlignmentAtom> {
        SignBidirectionalEvent::<Public, WORDS, LEN_OUT, LEN_RESPOND>::atoms()
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
        EventRecord(limbs)
    }
}

/// `constructSignBidirectionalEvent(...)` — assembles the record and
/// asserts `keyVersion >= 1` (for a `Uint<8>`: `keyVersion != 0`).
#[allow(clippy::too_many_arguments)]
pub fn construct_sign_bidirectional_event<
    V: Vis,
    const WORDS: usize,
    const LEN_OUT: usize,
    const LEN_RESPOND: usize,
>(
    c: &mut Circuit,
    sender: ContractAddress<V>,
    request_nonce: Wire<FieldT, V>,
    key_version: Wire<FieldT, V>,
    path: SigningPath<V>,
    tx_params: EvmType2TxParams<V, WORDS>,
    caip2_id: Caip2Id<V>,
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
    V: Vis,
    const WORDS: usize,
    const LEN_OUT: usize,
    const LEN_RESPOND: usize,
>(
    c: &mut Circuit,
    request: &SignBidirectionalEvent<V, WORDS, LEN_OUT, LEN_RESPOND>,
) -> RequestId<V> {
    request_id_of(c, &request.limbs())
}

// ---- attestation verify -----------------------------------------------------

/// `calculateSignetAttestationDigest(requestId, serializedOutput)` —
/// `upgradeFromTransient(transientHash([requestId, serializedOutput]))`
/// (signet-midnight `fff3421c`): Poseidon over the tuple's field-aligned
/// limbs — the id's `[hi, lo]` then the output's limbs — as the MPC's
/// `compact-hashing::compute_response_hash` recomputes it. `output_limbs`
/// are the serialized output's FAB limbs for `LEN_OUTPUT` bytes ([`BytesN`]
/// slot order; the settle circuits' 1/5/8-byte outputs are one limb).
pub fn calculate_attestation_digest<V: Vis, const LEN_OUTPUT: usize>(
    c: &mut Circuit,
    request_id: &RequestId<V>,
    output_limbs: &[Wire<FieldT, V>],
) -> B32<V> {
    c.region("signet: attestation digest (transientHash)", |c| {
        let mut limbs = vec![request_id.bytes().hi, request_id.bytes().lo];
        limbs.extend_from_slice(output_limbs);
        let f = c.transient_hash(&limbs);
        upgrade_from_transient(c, f)
    })
}

/// `verifyRespondBidirectionalEvent(requestId, serializedOutput, event,
/// mpcResponseKey)` — recompute the attestation digest and verify the
/// event's ECDSA signature over it. Only `bigR.x` and `s` enter
/// verification, little-endian ([`Secp256k1SigLimbs`]).
pub fn verify_respond_bidirectional_event<V: Vis, const LEN_OUTPUT: usize>(
    c: &mut Circuit,
    request_id: &RequestId<V>,
    output_limbs: &[Wire<FieldT, V>],
    sig: &Secp256k1SigLimbs<V>,
    mpc_response_key: minocrab::Wire<minocrab::Secp256k1PointT, V>,
) -> Wire<FieldT, V> {
    let digest = calculate_attestation_digest::<V, LEN_OUTPUT>(c, request_id, output_limbs);
    verify_attestation_signature(c, &digest, sig, mpc_response_key)
}

/// `calculateSignetAttestationDigest(requestId, output)` where the output is
/// a typed Borsh value.
///
/// The preimage is `borsh({ request_id: [u8; 32], output: T })`: a Borsh
/// struct is the concatenation of its fields, so this is the request id's 32
/// bytes followed by `borsh(output)`. What is hashed is Poseidon over limbs,
/// and the limbs are the MPC's (`compact-hashing::compute_response_hash`,
/// `signet_sim::hashing`): the id's `[hi, lo]` slot pair, then the serialized
/// output packed as one byte string in FAB's 31-byte limbing, slot order —
/// exactly what [`calculate_attestation_digest`] takes as `output_limbs`.
///
/// Not one limb per Borsh leaf (`limbs_of(output).transient_hash`): that
/// agrees with the MPC only under
/// keccak / persistentHash — where the hash is over bytes and the two limb
/// splits are the same bytes — and not under the protocol's
/// `transientHash`: Poseidon absorbs field elements, so a kind
/// byte and a payload as two limbs is a different preimage from the two
/// bytes as one limb (notes/signet-async.org §10).
///
/// Cost: the segment packing (`Serializer::finish_limbs`) — constant-weight
/// mul/add per leaf, one `div_mod` only where a leaf straddles a 31-byte
/// boundary, which no shipped output does. The Serializer's precondition —
/// every leaf already range-constrained, or the packing is not injective —
/// is discharged by the caller: the output is a circuit argument
/// (`Succeeded` / `Failed` tickets), constrained at entry by
/// `CircuitArg::constrain`, and `Pending::complete` asserts its kind besides.
pub fn calculate_attestation_digest_borsh<V: Vis, T: CircuitBorsh<V>>(
    c: &mut Circuit,
    request_id: &RequestId<V>,
    output: &T,
) -> B32<V> {
    c.region("signet: attestation digest (transientHash)", |c| {
        let f = attestation_transient_hash_borsh(c, request_id, output);
        upgrade_from_transient(c, f)
    })
}

/// [`calculate_attestation_digest_borsh`] before the `upgradeFromTransient`
/// — the raw Poseidon output — for a settle that hashes more than one
/// candidate preimage and selects between them before upgrading
/// (`Pending::refund`: the MPC's failure output is the kind byte alone, the
/// call's own output is the kind byte and the return value). Same limbs as
/// the digest: `[id.hi, id.lo]` then the output packed as one byte string.
pub fn attestation_transient_hash_borsh<V: Vis, T: CircuitBorsh<V>>(
    c: &mut Circuit,
    request_id: &RequestId<V>,
    output: &T,
) -> Wire<FieldT, V> {
    let mut out = Serializer::new();
    output.push_segments(&mut out);
    let packed = out.finish_limbs(c, T::LEN);
    assert_eq!(
        packed.len(),
        T::LEN.div_ceil(31),
        "the packed output is {} bytes in FAB slot order",
        T::LEN
    );
    let mut limbs = vec![request_id.bytes().hi, request_id.bytes().lo];
    limbs.extend(packed);
    c.transient_hash(&limbs)
}

/// [`verify_respond_bidirectional_event`] over a typed Borsh output.
/// Same signature check, same MPC key, a digest whose preimage
/// carries the response kind.
pub fn verify_respond_bidirectional_event_borsh<V: Vis, T: CircuitBorsh<V>>(
    c: &mut Circuit,
    request_id: &RequestId<V>,
    output: &T,
    sig: &Secp256k1SigLimbs<V>,
    mpc_response_key: minocrab::Wire<minocrab::Secp256k1PointT, V>,
) -> Wire<FieldT, V> {
    let digest = calculate_attestation_digest_borsh(c, request_id, output);
    verify_attestation_signature(c, &digest, sig, mpc_response_key)
}

// ---- ABI calldata word utilities --------------------------------------------

/// `slice<20>(word, 12)` — the low 20 bytes of an ABI word as the
/// `Bytes<20>` single limb (the vault reads token addresses back out of
/// stored calldata words).
pub fn abi_word_low20<V: Vis>(c: &mut Circuit, word: &B32<V>) -> Wire<FieldT, V> {
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

    fn bytes(length: u32) -> AlignmentAtom {
        AlignmentAtom::Bytes { length }
    }

    /// A zero-filled record of the given instantiation — only its shape
    /// (atom widths, limb count) is under test.
    fn zero_event<const WORDS: usize, const LEN_OUT: usize, const LEN_RESPOND: usize>(
        c: &mut Circuit,
    ) -> SignBidirectionalEvent<Public, WORDS, LEN_OUT, LEN_RESPOND> {
        let zero = c.constant(0u64);
        let b32 = B32 { hi: zero, lo: zero };
        let zeros = |n: usize| vec![zero; n];
        SignBidirectionalEvent {
            sender: ContractAddress(b32),
            request_nonce: zero,
            key_version: zero,
            path: SigningPath(b32),
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
            caip2_id: Caip2Id(b32),
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
        let mut c = Circuit::new();
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
        let mut c = Circuit::new();
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

    /// The stage-7 record, both instantiations: the record's atoms are the deployed
    /// record's with a `bytes<1>` version in front and a `bytes<1>` kind where
    /// the two schema atoms were — stated against the deployed list rather
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

    /// The stage-7 records' shapes as numbers: 24 atoms / 31 limbs / 338
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
        let mut c = Circuit::new();
        let z = c.constant(0u64);
        let b32 = B32 { hi: z, lo: z };
        let ev = SignBidirectionalEventV2::<Public, 2> {
            format_version: z,
            sender: ContractAddress(b32),
            request_nonce: z,
            key_version: z,
            path: SigningPath(b32),
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
            caip2_id: Caip2Id(b32),
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
