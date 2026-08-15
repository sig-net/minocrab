//! "Today's protocol is already Borsh" — with a test behind it (M11
//! stage 0, notes/borsh-format.org §Phasing).
//!
//! No circuit changes and no new encoder: every byte string on the DEPLOYED
//! side of an assertion here is produced by the protocol's own code — the
//! FAB `binary_repr` the keccak chips consume, the `Misc` envelope the
//! singleton logs, the reference model M10's differential suite pins to the
//! compactc artifacts. Every byte string on the SPEC side is produced by
//! borsh's and serde+bincode's derives over the declarations in
//! `serialization::spec_types`.
//!
//! The four properties of the stage, in the order the design of record lists
//! them:
//!
//! a. DUAL ORACLE — `borsh::to_vec(v) == bincode-fixint(v)` for every spec
//!    type over generated values. Together with (b) this is the subset
//!    checker; `subset_boundary` below pins the three known-bad shapes and
//!    which of the two properties catches each.
//! b. FIXED WIDTH — `borsh::object_length(v) == T::LEN` for all v, and
//!    `T::LEN` equals the deployed FAB alignment's own `bin_len`. No
//!    value-dependent branching, so every offset is a compile-time constant.
//! c. THE HEADLINE — byte-equality against the deployed protocol's actual
//!    bytes: the two request records (and so the request IDs), the four
//!    attestation digest preimages, and the singleton's three Misc payloads,
//!    the last checked by handing the bytes to the CORPUS ARTIFACT itself.
//! d. SCHEMA DRIFT — the Borsh schema walked into a frozen `(path, kind,
//!    offset, width)` table, the seed of stage 8's published offset tables.
//!
//! Case counts scale with `PROPTEST_CASES` (see `vault::gen::config`).

mod serialization;
mod support;
mod vault;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use minocrab::Fr;
use minocrab_contracts::{erc20_vault, signet_contract};
use minocrab_sim::v3::simulate;
use proptest::prelude::*;
use proptest::test_runner::TestRunner;
use serde::Serialize;
use sha3::{Digest, Keccak256};

use serialization::deployed;
use serialization::oracle::{bincode_fixint_bytes, borsh_bytes, layout_rows, schema_len, Row};
use serialization::records;
use serialization::spec_types;
use serialization::spec_types::*;
use vault::artifact::Art;
use vault::gen;
use vault::prims::b32_slots;

// ---- (a) + (b): the dual oracle and the fixed width --------------------------

/// Assert everything that holds of a spec-type VALUE regardless of where it
/// came from: the two oracles agree, the width is the type's constant, and
/// the encoding round-trips (bijective on the subset — there is nothing to
/// choose between two encodings of the same value).
fn assert_conformant<T>(value: &T)
where
    T: BorshSerialize + BorshDeserialize + BorshSchema + Serialize + FixedLen + PartialEq + std::fmt::Debug,
{
    let borsh = borsh_bytes(value);
    let bincode = bincode_fixint_bytes(value);
    assert_eq!(
        borsh, bincode,
        "the two oracles disagree — {} has left the circuit-safe subset",
        std::any::type_name::<T>()
    );
    assert_eq!(
        borsh::object_length(value).expect("spec types measure infallibly"),
        T::LEN,
        "{} is not fixed-width at this value",
        std::any::type_name::<T>()
    );
    assert_eq!(borsh.len(), T::LEN);
    let back = T::try_from_slice(&borsh).expect("the encoding decodes");
    assert_eq!(&back, value, "{} does not round-trip", std::any::type_name::<T>());
}

/// A `[u8; N]` for any N (proptest's blanket array impls stop at 32, as
/// serde's do).
fn byte_array<const N: usize>() -> impl Strategy<Value = [u8; N]> {
    proptest::collection::vec(any::<u8>(), N).prop_map(|v| v.try_into().expect("N bytes in, N out"))
}

fn calldata2() -> impl Strategy<Value = EvmCalldata2> {
    (byte_array::<4>(), any::<u16>(), byte_array::<32>(), byte_array::<32>()).prop_map(
        |(selector, no_words, w0, w1)| EvmCalldata2 {
            selector,
            no_words,
            words: [w0, w1],
        },
    )
}

fn calldata7() -> impl Strategy<Value = EvmCalldata7> {
    (
        byte_array::<4>(),
        any::<u16>(),
        proptest::collection::vec(byte_array::<32>(), 7),
    )
        .prop_map(|(selector, no_words, words)| EvmCalldata7 {
            selector,
            no_words,
            words: words.try_into().expect("seven words in, seven out"),
        })
}

/// The seven scalar fields every `EvmType2TxParams` instantiation shares.
type TxHeader = (u64, u64, u128, u128, u64, [u8; 20], u128);

fn tx_header() -> impl Strategy<Value = TxHeader> {
    (
        any::<u64>(),
        any::<u64>(),
        any::<u128>(),
        any::<u128>(),
        any::<u64>(),
        byte_array::<20>(),
        any::<u128>(),
    )
}

fn tx_params2() -> impl Strategy<Value = EvmType2TxParams2> {
    (tx_header(), any::<bool>(), calldata2(), any::<u8>()).prop_map(
        |((chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value),
          is_some,
          calldata,
          access_list_entry_count)| EvmType2TxParams2 {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            calldata: Flagged { is_some, value: calldata },
            access_list_entry_count,
        },
    )
}

fn tx_params7() -> impl Strategy<Value = EvmType2TxParams7> {
    (tx_header(), any::<bool>(), calldata7(), any::<u8>()).prop_map(
        |((chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value),
          is_some,
          calldata,
          access_list_entry_count)| EvmType2TxParams7 {
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            calldata: Flagged { is_some, value: calldata },
            access_list_entry_count,
        },
    )
}

/// The record header every instantiation shares.
type RecordHeader = ([u8; 32], u64, u8, [u8; 32], u8, u8, [u8; 64], u8, [u8; 32]);

fn record_header() -> impl Strategy<Value = RecordHeader> {
    (
        byte_array::<32>(),
        any::<u64>(),
        any::<u8>(),
        byte_array::<32>(),
        any::<u8>(),
        any::<u8>(),
        byte_array::<64>(),
        any::<u8>(),
        byte_array::<32>(),
    )
}

fn vault_event() -> impl Strategy<Value = VaultEvent> {
    (
        record_header(),
        tx_params2(),
        byte_array::<34>(),
        byte_array::<34>(),
    )
        .prop_map(
            |((sender, request_nonce, key_version, path, algo, dest, params, tx_param_type, caip2_id),
              tx_params,
              out_schema,
              respond_schema)| VaultEvent {
                sender,
                request_nonce,
                key_version,
                path,
                algo,
                dest,
                params: ByteArray(params),
                tx_param_type,
                tx_params,
                caip2_id,
                output_deserialization_schema: ByteArray(out_schema),
                respond_serialization_schema: ByteArray(respond_schema),
            },
        )
}

fn swap_event() -> impl Strategy<Value = SwapEvent> {
    (
        record_header(),
        tx_params7(),
        byte_array::<38>(),
        byte_array::<37>(),
    )
        .prop_map(
            |((sender, request_nonce, key_version, path, algo, dest, params, tx_param_type, caip2_id),
              tx_params,
              out_schema,
              respond_schema)| SwapEvent {
                sender,
                request_nonce,
                key_version,
                path,
                algo,
                dest,
                params: ByteArray(params),
                tx_param_type,
                tx_params,
                caip2_id,
                output_deserialization_schema: ByteArray(out_schema),
                respond_serialization_schema: ByteArray(respond_schema),
            },
        )
}

fn sign_bidirectional_misc() -> impl Strategy<Value = SignBidirectionalMisc> {
    (any::<u8>(), byte_array::<32>(), byte_array::<128>()).prop_map(|(version, request_id, payload)| {
        SignBidirectionalMisc {
            version,
            request_id,
            payload: ByteArray(payload),
        }
    })
}

fn respond_misc() -> impl Strategy<Value = RespondMisc> {
    (
        byte_array::<32>(),
        byte_array::<32>(),
        byte_array::<32>(),
        byte_array::<32>(),
        any::<u8>(),
    )
        .prop_map(|(request_id, big_r_x, big_r_y, s, recovery_id)| RespondMisc {
            request_id,
            big_r_x,
            big_r_y,
            s,
            recovery_id,
        })
}

proptest! {
    #![proptest_config(gen::config())]

    /// (a) + (b) for the two request records.
    #[test]
    fn records_are_conformant(vault in vault_event(), swap in swap_event()) {
        assert_conformant(&vault);
        assert_conformant(&swap);
    }

    /// (a) + (b) for the four attested outputs and their digest preimages.
    #[test]
    fn attested_outputs_are_conformant(
        request_id in byte_array::<32>(),
        success in any::<u8>(),
        failure in byte_array::<5>(),
        amount_in in any::<u64>(),
    ) {
        let claim = ClaimOutput { success };
        let complete_withdraw = CompleteWithdrawOutput { success };
        let refund = RefundOutput { failure };
        let complete_swap = CompleteSwapOutput { amount_in };
        assert_conformant(&claim);
        assert_conformant(&complete_withdraw);
        assert_conformant(&refund);
        assert_conformant(&complete_swap);
        assert_conformant(&AttestationPreimage { request_id, output: claim });
        assert_conformant(&AttestationPreimage { request_id, output: complete_withdraw });
        assert_conformant(&AttestationPreimage { request_id, output: refund });
        assert_conformant(&AttestationPreimage { request_id, output: complete_swap });
    }

    /// (a) + (b) for the singleton's three Misc payloads (`respond` and
    /// `respondBidirectional` share one shape).
    #[test]
    fn misc_payloads_are_conformant(
        sign in sign_bidirectional_misc(),
        respond in respond_misc(),
    ) {
        assert_conformant(&sign);
        assert_conformant(&respond);
    }
}

/// (b), the other half: each `LEN` is the DEPLOYED shape's own width, not an
/// arithmetic claim of ours. `Alignment::bin_len` is what the ledger and the
/// hash chips size the preimage by.
#[test]
fn lens_match_the_deployed_alignments() {
    assert_eq!(
        VaultEvent::LEN,
        deployed::fab_len(&records::vault_record_atoms()),
        "vault record width"
    );
    assert_eq!(
        SwapEvent::LEN,
        deployed::fab_len(&records::swap_record_atoms()),
        "swap record width"
    );
    // The design of record's stage-7 arithmetic is built on this number.
    assert_eq!(SwapEvent::LEN, 571);
    assert_eq!(VaultEvent::LEN, 404);

    assert_eq!(ClaimOutput::LEN, 1);
    assert_eq!(CompleteWithdrawOutput::LEN, 1);
    assert_eq!(RefundOutput::LEN, erc20_vault::MPC_FAILURE_OUTPUT.len());
    assert_eq!(CompleteSwapOutput::LEN, 8);
    assert_eq!(AttestationPreimage::<ClaimOutput>::LEN, 33);
    assert_eq!(AttestationPreimage::<CompleteSwapOutput>::LEN, 40);

    // M11 stage 5's shapes, and the digest preimages they define. These are
    // THE SPEC — the MPC has never settled on Midnight, so there is nothing
    // deployed to compare them against; what pins them is borsh's own
    // encoder, borsh's own schema, and the circuit that hashes them.
    assert_eq!(VaultResponse::LEN, 2);
    assert_eq!(SwapResponse::LEN, 9);
    assert_eq!(FailureResponse::LEN, 1);
    assert_eq!(AttestationPreimage::<VaultResponse>::LEN, 34);
    assert_eq!(AttestationPreimage::<SwapResponse>::LEN, 41);
    assert_eq!(AttestationPreimage::<FailureResponse>::LEN, 33);

    // The Misc payloads sit inside `Bytes<256>` after the 32-byte name.
    assert_eq!(SignBidirectionalMisc::LEN, 161);
    assert_eq!(RespondMisc::LEN, 129);
    const { assert!(SignBidirectionalMisc::LEN + 32 <= minocrab_contracts::events::MISC_SIZE) };
    const { assert!(RespondMisc::LEN + 32 <= minocrab_contracts::events::MISC_SIZE) };
}

/// (b), the third half: the schema walk's own width agrees with `LEN`, so
/// the frozen offset table and the encoder cannot drift apart.
#[test]
fn schema_widths_match_the_lens() {
    let expected: Vec<(&str, usize)> = vec![
        ("VaultEvent", VaultEvent::LEN),
        ("SwapEvent", SwapEvent::LEN),
        ("ClaimOutput", ClaimOutput::LEN),
        ("CompleteWithdrawOutput", CompleteWithdrawOutput::LEN),
        ("RefundOutput", RefundOutput::LEN),
        ("CompleteSwapOutput", CompleteSwapOutput::LEN),
        ("AttestationPreimage<ClaimOutput>", AttestationPreimage::<ClaimOutput>::LEN),
        (
            "AttestationPreimage<CompleteWithdrawOutput>",
            AttestationPreimage::<CompleteWithdrawOutput>::LEN,
        ),
        ("AttestationPreimage<RefundOutput>", AttestationPreimage::<RefundOutput>::LEN),
        (
            "AttestationPreimage<CompleteSwapOutput>",
            AttestationPreimage::<CompleteSwapOutput>::LEN,
        ),
        ("VaultResponse", VaultResponse::LEN),
        ("SwapResponse", SwapResponse::LEN),
        ("FailureResponse", FailureResponse::LEN),
        (
            "AttestationPreimage<VaultResponse>",
            AttestationPreimage::<VaultResponse>::LEN,
        ),
        (
            "AttestationPreimage<SwapResponse>",
            AttestationPreimage::<SwapResponse>::LEN,
        ),
        (
            "AttestationPreimage<FailureResponse>",
            AttestationPreimage::<FailureResponse>::LEN,
        ),
        ("SignBidirectionalMisc", SignBidirectionalMisc::LEN),
        ("RespondMisc", RespondMisc::LEN),
    ];
    let containers = spec_types::schema_containers();
    assert_eq!(containers.len(), expected.len(), "a spec type is missing a LEN check");
    for ((name, container), (expected_name, len)) in containers.iter().zip(expected) {
        assert_eq!(*name, expected_name, "schema container list out of order");
        assert_eq!(schema_len(container), len, "{name}: schema width vs LEN");
    }
}

// ---- (c) THE HEADLINE: the deployed bytes ------------------------------------

proptest! {
    #![proptest_config(gen::config())]

    /// The 2-word request record — `deposit`, `approveRouter` and
    /// `withdraw` all write this shape.
    ///
    /// LEFT: the bytes the deployed circuit hashes. `calculateRequestId`
    /// hands `keccak256` the record's FAB limbs under
    /// `erc20_vault::VaultEvent::atoms()`; the chip packs them, which
    /// off-circuit is `parse_field_repr` + `binary_repr` — the reference
    /// model's `request_id()`, the one M10's differential suite pins to
    /// compactc's artifact.
    ///
    /// RIGHT: `borsh::to_vec` of the spec type at the same field values.
    #[test]
    fn vault_record_bytes_are_canonical_borsh(
        deposit in gen::deposit(),
        approve in gen::approve(),
        withdraw in gen::withdraw(),
    ) {
        let atoms = records::vault_record_atoms();
        for (name, limbs, spec) in [
            ("deposit", deposit.event_limbs(), records::deposit_event(&deposit)),
            ("approveRouter", approve.event_limbs(), records::approve_event(&approve)),
            ("withdraw", withdraw.event_limbs(), records::withdraw_event(&withdraw)),
        ] {
            prop_assert_eq!(limbs.len(), records::VAULT_RECORD_LIMBS);
            let on_chain = deployed::fab_bytes(&atoms, &limbs);
            let spec_bytes = borsh_bytes(&spec);
            prop_assert_eq!(&on_chain, &spec_bytes, "{}: record bytes differ", name);
            prop_assert_eq!(bincode_fixint_bytes(&spec), on_chain.clone(), "{}", name);
        }
        // …and therefore the request id the vault stores IS
        // keccak256(borsh(record)).
        let digest: [u8; 32] = Keccak256::digest(borsh_bytes(&records::deposit_event(&deposit))).into();
        prop_assert_eq!(digest, deposit.request_id());
        let digest: [u8; 32] = Keccak256::digest(borsh_bytes(&records::withdraw_event(&withdraw))).into();
        prop_assert_eq!(digest, withdraw.request_id());
        let digest: [u8; 32] = Keccak256::digest(borsh_bytes(&records::approve_event(&approve))).into();
        prop_assert_eq!(digest, approve.request_id());
    }

    /// The 7-word swap record — the 571-byte one stage 7 wants to shrink.
    #[test]
    fn swap_record_bytes_are_canonical_borsh(swap in gen::swap()) {
        let limbs = swap.event_limbs();
        prop_assert_eq!(limbs.len(), records::SWAP_RECORD_LIMBS);
        let on_chain = deployed::fab_bytes(&records::swap_record_atoms(), &limbs);
        let spec = records::swap_event(&swap);
        prop_assert_eq!(&on_chain, &borsh_bytes(&spec));
        prop_assert_eq!(bincode_fixint_bytes(&spec), on_chain.clone());
        let digest: [u8; 32] = Keccak256::digest(borsh_bytes(&spec)).into();
        prop_assert_eq!(digest, swap.request_id());
    }

    /// The attestation digest preimages of all four settle circuits.
    ///
    /// LEFT: `calculateSignetAttestationDigest`'s own alignment,
    /// `[Bytes<32>, Bytes<LEN_OUTPUT>]`, over the request id's slot pair
    /// and the output's limbs.
    #[test]
    fn attestation_preimages_are_canonical_borsh(
        claim in gen::claim(),
        complete_withdraw in gen::complete_withdraw(),
        refund in gen::refund(),
        complete_swap in gen::complete_swap(),
    ) {
        // claim: Bytes<1>
        let rid = claim.d.request_id();
        let spec = AttestationPreimage { request_id: rid, output: ClaimOutput { success: claim.serialized_output } };
        let on_chain = deployed::attestation_preimage_bytes(
            &rid, 1, &[Fr::from(u64::from(claim.serialized_output))],
        );
        prop_assert_eq!(&on_chain, &borsh_bytes(&spec));
        // …and the digest the MPC signed is keccak256 of exactly that.
        let digest: [u8; 32] = Keccak256::digest(borsh_bytes(&spec)).into();
        prop_assert_eq!(digest, claim.attestation_digest());

        // completeWithdraw: Bytes<1>
        let rid = complete_withdraw.w.request_id();
        let spec = AttestationPreimage {
            request_id: rid,
            output: CompleteWithdrawOutput { success: complete_withdraw.outcome },
        };
        let on_chain = deployed::attestation_preimage_bytes(
            &rid, 1, &[Fr::from(u64::from(complete_withdraw.outcome))],
        );
        prop_assert_eq!(&on_chain, &borsh_bytes(&spec));

        // refund: Bytes<5>
        let rid = refund.request_id();
        let spec = AttestationPreimage {
            request_id: rid,
            output: RefundOutput { failure: refund.serialized_output },
        };
        let limb = Fr::from_le_bytes(&refund.serialized_output).expect("5 bytes fit");
        let on_chain = deployed::attestation_preimage_bytes(&rid, 5, &[limb]);
        prop_assert_eq!(&on_chain, &borsh_bytes(&spec));

        // completeSwap: Bytes<8>, already a Borsh u64.
        let rid = complete_swap.s.request_id();
        let spec = AttestationPreimage {
            request_id: rid,
            output: CompleteSwapOutput { amount_in: complete_swap.amount_in },
        };
        let on_chain = deployed::attestation_preimage_bytes(
            &rid, 8, &[Fr::from(complete_swap.amount_in)],
        );
        prop_assert_eq!(&on_chain, &borsh_bytes(&spec));
    }

    /// M11 STAGE 5: the BORSH artifact's attestation digest preimages.
    ///
    /// Nothing deployed to compare against — this is the format the MPC will
    /// implement — so the pin is the other way round: LEFT is what the
    /// reference model hands the signer for `Art::Borsh`, and RIGHT is
    /// `borsh::to_vec` of the spec twin. That matters because the borsh
    /// circuits verify an ECDSA signature over `keccak256(LEFT)` and reject
    /// unless their OWN keccak preimage — built by `CircuitBorsh::push_limbs`
    /// out of the declared fields — reproduces it exactly. So this equality
    /// plus the spec harness's acceptance agreement says the circuits hash
    /// canonical Borsh of the declared types, at every generated case.
    #[test]
    fn borsh_attestation_preimages_are_canonical_borsh(
        claim in gen::claim(),
        complete_withdraw in gen::complete_withdraw(),
        refund in gen::refund(),
        complete_swap in gen::complete_swap(),
    ) {
        let claim = claim.with_art(Art::Borsh);
        let complete_withdraw = complete_withdraw.with_art(Art::Borsh);
        let refund = refund.with_art(Art::Borsh);
        let complete_swap = complete_swap.with_art(Art::Borsh);

        // claim / completeWithdraw: {kind: u8, success: bool}. A generated
        // success byte above 1 has NO canonical Borsh value — that is the
        // 0x02 hazard, and the borsh circuit rejects it — so the equality is
        // stated where the type exists.
        if claim.serialized_output <= 1 {
            let rid = claim.d.request_id();
            let spec = AttestationPreimage {
                request_id: rid,
                output: VaultResponse {
                    kind: claim.response_kind,
                    success: claim.serialized_output == 1,
                },
            };
            let mut model = rid.to_vec();
            model.extend(claim.attested_output_bytes());
            prop_assert_eq!(&model, &borsh_bytes(&spec));
            // …and the digest the MPC signs is keccak256 of exactly that.
            let digest: [u8; 32] = Keccak256::digest(borsh_bytes(&spec)).into();
            prop_assert_eq!(digest, claim.attestation_digest());
        }
        if complete_withdraw.outcome <= 1 {
            let rid = complete_withdraw.w.request_id();
            let spec = AttestationPreimage {
                request_id: rid,
                output: VaultResponse {
                    kind: complete_withdraw.response_kind,
                    success: complete_withdraw.outcome == 1,
                },
            };
            let mut model = rid.to_vec();
            model.extend(complete_withdraw.attested_output_bytes());
            prop_assert_eq!(&model, &borsh_bytes(&spec));
        }

        // refund: {kind: u8} — one byte, whatever the kind.
        let rid = refund.request_id();
        let spec = AttestationPreimage {
            request_id: rid,
            output: FailureResponse { kind: refund.response_kind },
        };
        let mut model = rid.to_vec();
        model.extend(refund.attested_output_bytes());
        prop_assert_eq!(&model, &borsh_bytes(&spec));

        // completeSwap: {kind: u8, amount_in: u64}.
        let rid = complete_swap.s.request_id();
        let spec = AttestationPreimage {
            request_id: rid,
            output: SwapResponse {
                kind: complete_swap.response_kind,
                amount_in: complete_swap.amount_in,
            },
        };
        let mut model = rid.to_vec();
        model.extend(complete_swap.attested_output_bytes());
        prop_assert_eq!(&model, &borsh_bytes(&spec));
    }
}

/// The Signet singleton's `signBidirectional` Misc payload.
///
/// The strong form: the bytes are not compared against a second Rust
/// construction of them, they are handed to the PINNED COMPACTC ARTIFACT as
/// the logged transcript. The corpus circuit accepts the borsh envelope, and
/// rejects it as soon as any single byte moves — including a byte of the
/// zero pad, which is the padding rule ("bytes 0..LEN are the payload,
/// LEN..N MUST be zero") enforced in-circuit.
///
/// Written against `TestRunner` rather than `proptest!` so the two artifacts
/// are built and parsed ONCE rather than per case.
#[test]
fn sign_bidirectional_misc_bytes_are_canonical_borsh() {
    let ours = signet_contract::sign_bidirectional().ir;
    let theirs = deployed::corpus_signet_zkir("signBidirectional");
    let strategy = (
        sign_bidirectional_misc(),
        0usize..minocrab_contracts::events::MISC_SIZE,
    );
    TestRunner::new(gen::config())
        .run(&strategy, |(payload, tamper)| {
            let envelope = deployed::misc_envelope(
                signet_contract::SIGN_BIDIRECTIONAL_EVENT,
                &borsh_bytes(&payload),
            );
            let (hi, lo) = b32_slots(&payload.request_id);
            let mut inputs = vec![hi, lo, Fr::from(u64::from(payload.version))];
            inputs.extend(deployed::b128_limbs(&payload.payload.0));

            let pi = deployed::misc_preimage(inputs.clone(), &envelope);
            prop_assert!(
                simulate(&theirs, &pi).is_ok(),
                "the corpus artifact rejects the Borsh encoding"
            );
            prop_assert!(simulate(&ours, &pi).is_ok(), "our artifact rejects the Borsh encoding");

            let mut tampered = envelope.clone();
            tampered[tamper] ^= 0x01;
            let pi = deployed::misc_preimage(inputs, &tampered);
            prop_assert!(
                simulate(&theirs, &pi).is_err(),
                "the corpus artifact accepts byte {tamper} moved"
            );
            prop_assert!(
                simulate(&ours, &pi).is_err(),
                "our artifact accepts byte {tamper} moved"
            );
            Ok(())
        })
        .expect("signBidirectional's Misc payload is canonical Borsh");
}

/// `respond` and `respondBidirectional` — the same payload shape under two
/// event names, each checked against its own corpus artifact.
#[test]
fn respond_misc_bytes_are_canonical_borsh() {
    let circuits = [
        (
            "respond",
            signet_contract::SIGNATURE_RESPONDED_EVENT,
            signet_contract::respond().ir,
            deployed::corpus_signet_zkir("respond"),
        ),
        (
            "respondBidirectional",
            signet_contract::RESPOND_BIDIRECTIONAL_EVENT,
            signet_contract::respond_bidirectional().ir,
            deployed::corpus_signet_zkir("respondBidirectional"),
        ),
    ];
    let strategy = (respond_misc(), 0usize..minocrab_contracts::events::MISC_SIZE);
    TestRunner::new(gen::config())
        .run(&strategy, |(payload, tamper)| {
            let mut inputs = Vec::new();
            for b32 in [&payload.request_id, &payload.big_r_x, &payload.big_r_y, &payload.s] {
                let (hi, lo) = b32_slots(b32);
                inputs.extend([hi, lo]);
            }
            inputs.push(Fr::from(u64::from(payload.recovery_id)));

            for (circuit, name, ours, theirs) in &circuits {
                let envelope = deployed::misc_envelope(name, &borsh_bytes(&payload));
                let pi = deployed::misc_preimage(inputs.clone(), &envelope);
                prop_assert!(
                    simulate(theirs, &pi).is_ok(),
                    "{circuit}: the corpus artifact rejects the Borsh encoding"
                );
                prop_assert!(simulate(ours, &pi).is_ok(), "{circuit}: ours rejects the Borsh encoding");

                let mut tampered = envelope.clone();
                tampered[tamper] ^= 0x01;
                let pi = deployed::misc_preimage(inputs.clone(), &tampered);
                prop_assert!(
                    simulate(theirs, &pi).is_err(),
                    "{circuit}: the corpus artifact accepts byte {tamper} moved"
                );
                prop_assert!(
                    simulate(ours, &pi).is_err(),
                    "{circuit}: ours accepts byte {tamper} moved"
                );
            }
            Ok(())
        })
        .expect("the respond circuits' Misc payloads are canonical Borsh");
}

// ---- the wrapper's transparency ----------------------------------------------

/// [`ByteArray`] exists only because serde's blanket `[T; N]` impls stop at
/// N = 32 and borsh's derived schema declaration would drop the length. It
/// must add NOTHING to either encoding — checked at the N where the native
/// impls exist and can be compared against.
#[test]
fn byte_array_wrapper_is_transparent() {
    macro_rules! check {
        ($($n:literal),+) => {$({
            let bytes: [u8; $n] = std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
            assert_eq!(borsh_bytes(&ByteArray(bytes)), borsh_bytes(&bytes), "borsh, N={}", $n);
            assert_eq!(
                bincode_fixint_bytes(&ByteArray(bytes)),
                bincode_fixint_bytes(&bytes),
                "bincode, N={}", $n
            );
            assert_eq!(borsh_bytes(&ByteArray(bytes)).len(), $n);
            assert_eq!(
                <ByteArray<$n> as BorshSchema>::declaration(),
                <[u8; $n] as BorshSchema>::declaration(),
                "schema declaration, N={}", $n
            );
        })+};
    }
    check!(1, 2, 5, 20, 31, 32);
}

// ---- the subset boundary ------------------------------------------------------

/// The three shapes the design of record excludes, and WHICH property
/// catches each. Without these the conformance suite could be vacuous: they
/// are the negative controls.
mod subset_boundary {
    use super::*;

    #[derive(BorshSerialize, Serialize)]
    enum FieldlessEnum {
        _First,
        Second,
    }

    /// A Rust `enum` — the shape the design of record's leaf table calls
    /// `Tag<K>`. CAUGHT BY THE DUAL ORACLE: borsh writes a 1-byte
    /// discriminant, bincode-fixint writes a 4-byte variant index. Hence
    /// every tag in `spec_types` is a `u8`, which is what Compact's `Tag`
    /// already is.
    #[test]
    fn fieldless_enum_leaves_the_subset() {
        assert_eq!(borsh_bytes(&FieldlessEnum::Second), vec![1]);
        assert_eq!(bincode_fixint_bytes(&FieldlessEnum::Second), vec![1, 0, 0, 0]);
    }

    /// A `Vec` — CAUGHT BY THE DUAL ORACLE: borsh prefixes a `u32` length,
    /// bincode-fixint a `u64` one. (Either way the layout would be
    /// value-dependent, which is the deeper reason it is excluded; the
    /// record uses `[T; K]` plus a separate `noWords` count instead.)
    #[test]
    fn vec_leaves_the_subset() {
        let v: Vec<u8> = vec![7, 8];
        assert_eq!(borsh_bytes(&v), vec![2, 0, 0, 0, 7, 8]);
        assert_eq!(bincode_fixint_bytes(&v), vec![2, 0, 0, 0, 0, 0, 0, 0, 7, 8]);
    }

    /// An `Option` — NOT caught by the dual oracle: both write a 1-byte tag
    /// and then the payload, so the two agree byte for byte. It is caught by
    /// the FIXED-WIDTH property instead, because borsh omits the payload on
    /// `None` and the width becomes value-dependent. This is why the design
    /// of record insists on `Flagged` (1-byte tag, payload ALWAYS present)
    /// and why the suite runs both properties rather than just the oracle.
    #[test]
    fn option_is_caught_by_the_width_property_not_the_oracle() {
        assert_eq!(borsh_bytes(&Some(9u8)), bincode_fixint_bytes(&Some(9u8)));
        assert_eq!(borsh_bytes(&Option::<u8>::None), bincode_fixint_bytes(&Option::<u8>::None));

        assert_eq!(borsh::object_length(&Some(9u8)).unwrap(), 2);
        assert_eq!(borsh::object_length(&Option::<u8>::None).unwrap(), 1);

        // Flagged, the replacement, is fixed-width at both values.
        let some = Flagged { is_some: true, value: 9u8 };
        let none = Flagged { is_some: false, value: 0u8 };
        assert_eq!(borsh::object_length(&some).unwrap(), Flagged::<u8>::LEN);
        assert_eq!(borsh::object_length(&none).unwrap(), Flagged::<u8>::LEN);
        assert_eq!(borsh_bytes(&some), bincode_fixint_bytes(&some));
    }
}

// ---- (d) the schema drift alarm -----------------------------------------------

/// Every spec type's layout, walked out of `borsh::schema_container_of` into
/// `(type, path, kind, offset, width)` and frozen. This table is the seed of
/// stage 8's published per-record offset tables — the artifact the TS and
/// MPC sides implement against — so a silent move here is exactly the
/// failure that would desynchronise them.
///
/// To regenerate after an INTENTIONAL layout change:
/// `cargo test --release -p minocrab-contracts --test serialization_conformance -- \
///      --ignored --nocapture print_layout_snapshot`
const LAYOUT_SNAPSHOT: &[(&str, &str, &str, usize, usize)] = &[
    ("VaultEvent", "sender", "[u8; 32]", 0, 32),
    ("VaultEvent", "request_nonce", "u64", 32, 8),
    ("VaultEvent", "key_version", "u8", 40, 1),
    ("VaultEvent", "path", "[u8; 32]", 41, 32),
    ("VaultEvent", "algo", "u8", 73, 1),
    ("VaultEvent", "dest", "u8", 74, 1),
    ("VaultEvent", "params", "[u8; 64]", 75, 64),
    ("VaultEvent", "tx_param_type", "u8", 139, 1),
    ("VaultEvent", "tx_params.chain_id", "u64", 140, 8),
    ("VaultEvent", "tx_params.nonce", "u64", 148, 8),
    ("VaultEvent", "tx_params.max_priority_fee_per_gas", "u128", 156, 16),
    ("VaultEvent", "tx_params.max_fee_per_gas", "u128", 172, 16),
    ("VaultEvent", "tx_params.gas_limit", "u64", 188, 8),
    ("VaultEvent", "tx_params.to", "[u8; 20]", 196, 20),
    ("VaultEvent", "tx_params.value", "u128", 216, 16),
    ("VaultEvent", "tx_params.calldata.is_some", "bool", 232, 1),
    ("VaultEvent", "tx_params.calldata.value.selector", "[u8; 4]", 233, 4),
    ("VaultEvent", "tx_params.calldata.value.no_words", "u16", 237, 2),
    ("VaultEvent", "tx_params.calldata.value.words[0]", "[u8; 32]", 239, 32),
    ("VaultEvent", "tx_params.calldata.value.words[1]", "[u8; 32]", 271, 32),
    ("VaultEvent", "tx_params.access_list_entry_count", "u8", 303, 1),
    ("VaultEvent", "caip2_id", "[u8; 32]", 304, 32),
    ("VaultEvent", "output_deserialization_schema", "[u8; 34]", 336, 34),
    ("VaultEvent", "respond_serialization_schema", "[u8; 34]", 370, 34),
    ("SwapEvent", "sender", "[u8; 32]", 0, 32),
    ("SwapEvent", "request_nonce", "u64", 32, 8),
    ("SwapEvent", "key_version", "u8", 40, 1),
    ("SwapEvent", "path", "[u8; 32]", 41, 32),
    ("SwapEvent", "algo", "u8", 73, 1),
    ("SwapEvent", "dest", "u8", 74, 1),
    ("SwapEvent", "params", "[u8; 64]", 75, 64),
    ("SwapEvent", "tx_param_type", "u8", 139, 1),
    ("SwapEvent", "tx_params.chain_id", "u64", 140, 8),
    ("SwapEvent", "tx_params.nonce", "u64", 148, 8),
    ("SwapEvent", "tx_params.max_priority_fee_per_gas", "u128", 156, 16),
    ("SwapEvent", "tx_params.max_fee_per_gas", "u128", 172, 16),
    ("SwapEvent", "tx_params.gas_limit", "u64", 188, 8),
    ("SwapEvent", "tx_params.to", "[u8; 20]", 196, 20),
    ("SwapEvent", "tx_params.value", "u128", 216, 16),
    ("SwapEvent", "tx_params.calldata.is_some", "bool", 232, 1),
    ("SwapEvent", "tx_params.calldata.value.selector", "[u8; 4]", 233, 4),
    ("SwapEvent", "tx_params.calldata.value.no_words", "u16", 237, 2),
    ("SwapEvent", "tx_params.calldata.value.words[0]", "[u8; 32]", 239, 32),
    ("SwapEvent", "tx_params.calldata.value.words[1]", "[u8; 32]", 271, 32),
    ("SwapEvent", "tx_params.calldata.value.words[2]", "[u8; 32]", 303, 32),
    ("SwapEvent", "tx_params.calldata.value.words[3]", "[u8; 32]", 335, 32),
    ("SwapEvent", "tx_params.calldata.value.words[4]", "[u8; 32]", 367, 32),
    ("SwapEvent", "tx_params.calldata.value.words[5]", "[u8; 32]", 399, 32),
    ("SwapEvent", "tx_params.calldata.value.words[6]", "[u8; 32]", 431, 32),
    ("SwapEvent", "tx_params.access_list_entry_count", "u8", 463, 1),
    ("SwapEvent", "caip2_id", "[u8; 32]", 464, 32),
    ("SwapEvent", "output_deserialization_schema", "[u8; 38]", 496, 38),
    ("SwapEvent", "respond_serialization_schema", "[u8; 37]", 534, 37),
    ("ClaimOutput", "success", "u8", 0, 1),
    ("CompleteWithdrawOutput", "success", "u8", 0, 1),
    ("RefundOutput", "failure", "[u8; 5]", 0, 5),
    ("CompleteSwapOutput", "amount_in", "u64", 0, 8),
    ("AttestationPreimage<ClaimOutput>", "request_id", "[u8; 32]", 0, 32),
    ("AttestationPreimage<ClaimOutput>", "output.success", "u8", 32, 1),
    ("AttestationPreimage<CompleteWithdrawOutput>", "request_id", "[u8; 32]", 0, 32),
    ("AttestationPreimage<CompleteWithdrawOutput>", "output.success", "u8", 32, 1),
    ("AttestationPreimage<RefundOutput>", "request_id", "[u8; 32]", 0, 32),
    ("AttestationPreimage<RefundOutput>", "output.failure", "[u8; 5]", 32, 5),
    ("AttestationPreimage<CompleteSwapOutput>", "request_id", "[u8; 32]", 0, 32),
    ("AttestationPreimage<CompleteSwapOutput>", "output.amount_in", "u64", 32, 8),
    ("VaultResponse", "kind", "u8", 0, 1),
    ("VaultResponse", "success", "bool", 1, 1),
    ("SwapResponse", "kind", "u8", 0, 1),
    ("SwapResponse", "amount_in", "u64", 1, 8),
    ("FailureResponse", "kind", "u8", 0, 1),
    ("AttestationPreimage<VaultResponse>", "request_id", "[u8; 32]", 0, 32),
    ("AttestationPreimage<VaultResponse>", "output.kind", "u8", 32, 1),
    ("AttestationPreimage<VaultResponse>", "output.success", "bool", 33, 1),
    ("AttestationPreimage<SwapResponse>", "request_id", "[u8; 32]", 0, 32),
    ("AttestationPreimage<SwapResponse>", "output.kind", "u8", 32, 1),
    ("AttestationPreimage<SwapResponse>", "output.amount_in", "u64", 33, 8),
    ("AttestationPreimage<FailureResponse>", "request_id", "[u8; 32]", 0, 32),
    ("AttestationPreimage<FailureResponse>", "output.kind", "u8", 32, 1),
    ("SignBidirectionalMisc", "version", "u8", 0, 1),
    ("SignBidirectionalMisc", "request_id", "[u8; 32]", 1, 32),
    ("SignBidirectionalMisc", "payload", "[u8; 128]", 33, 128),
    ("RespondMisc", "request_id", "[u8; 32]", 0, 32),
    ("RespondMisc", "big_r_x", "[u8; 32]", 32, 32),
    ("RespondMisc", "big_r_y", "[u8; 32]", 64, 32),
    ("RespondMisc", "s", "[u8; 32]", 96, 32),
    ("RespondMisc", "recovery_id", "u8", 128, 1),
];

fn snapshot_rows() -> Vec<(&'static str, Row)> {
    spec_types::schema_containers()
        .into_iter()
        .flat_map(|(name, container)| {
            layout_rows(&container).into_iter().map(move |row| (name, row))
        })
        .collect()
}

#[test]
fn layout_matches_its_frozen_table() {
    let rows = snapshot_rows();
    let frozen: Vec<(&str, Row)> = LAYOUT_SNAPSHOT
        .iter()
        .map(|&(ty, path, kind, offset, width)| {
            (
                ty,
                Row {
                    path: path.to_string(),
                    kind: kind.to_string(),
                    offset,
                    width,
                },
            )
        })
        .collect();
    assert_eq!(
        rows.len(),
        frozen.len(),
        "the frozen table has {} rows but the spec types walk to {} — \
         regenerate with the `print_layout_snapshot` test",
        frozen.len(),
        rows.len()
    );
    let mut failures = Vec::new();
    for ((ty, got), (frozen_ty, want)) in rows.iter().zip(&frozen) {
        if ty != frozen_ty || got != want {
            failures.push(format!("  {ty}.{got:?} != {frozen_ty}.{want:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "the serialization layout moved — every offset here is a wire \
         commitment:\n{}",
        failures.join("\n")
    );
}

// ---- (e) THE IN-CIRCUIT ENCODER against a deployed shape (M11 stage 1) ---------
//
// Stage 1 built `minocrab_std::v3::borsh` — the same Borsh subset, emitted by
// a circuit. Its own suite proves it against a twin of its own. Here it is
// pointed at a DEPLOYED payload shape, `RespondMisc`, whose bytes stage 0
// proved the pinned compactc artifact itself accepts: the circuit's packed
// output must equal `borsh::to_vec` of the spec type, and the circuit's
// layout table must equal the table walked out of borsh's own schema.

mod in_circuit {
    use super::*;

    use minocrab_std::v3::borsh::{to_bytes, CircuitBorsh};
    use minocrab_std::v3::{ArgPath, CircuitArg, Uint, Vis3, B32};

    use minocrab::v3::Circuit3;
    use minocrab::Private;
    use minocrab_zkir::v3::IrValue;

    /// [`RespondMisc`] over wires — ONE DERIVE for the circuit-argument
    /// family and the serialization, and `#[borsh(spec = …)]` for the
    /// generated cross-check against borsh's own schema of the spec type
    /// (`__minocrab_borsh_spec_RespondMiscCircuit` in this binary's test
    /// list).
    ///
    /// The field names are the SPEC type's, so the layout paths need no
    /// override; the argument labels are the mechanical camelCase ones, which
    /// nothing here is pinned to (this circuit is a test fixture, not a
    /// deployed interface).
    #[derive(CircuitBorsh)]
    #[borsh(spec = RespondMisc)]
    struct RespondMiscCircuit<V: Vis3> {
        request_id: B32<V>,
        big_r_x: B32<V>,
        big_r_y: B32<V>,
        s: B32<V>,
        recovery_id: Uint<8, V>,
    }

    /// A preimage for a circuit that is nothing but its arguments: no
    /// transcripts, no ledger operations.
    fn arg_preimage(inputs: Vec<Fr>) -> midnight_transient_crypto::proofs::ProofPreimage {
        midnight_transient_crypto::proofs::ProofPreimage {
            inputs,
            private_transcript: vec![],
            public_transcript_inputs: vec![],
            public_transcript_outputs: vec![],
            binding_input: 0.into(),
            communications_commitment: None,
            key_location: midnight_transient_crypto::proofs::KeyLocation(
                std::borrow::Cow::Borrowed("minocrab-contracts-test"),
            ),
        }
    }

    /// The packed bytes a circuit built through `CircuitBorsh` emits for the
    /// deployed `respond` payload ARE `borsh::to_vec` of the spec type.
    #[test]
    fn the_circuit_encoder_emits_the_spec_bytes() {
        let mut c = Circuit3::new();
        let value =
            <RespondMiscCircuit<Private> as CircuitArg>::declare(&mut c, &ArgPath::root("respond"));
        value.constrain(&mut c);
        let bytes = to_bytes::<{ RespondMisc::LEN }, _, _>(&mut c, &value);
        for (i, limb) in bytes.limbs().to_vec().into_iter().enumerate() {
            let public = c.disclose(limb, "payload limb");
            c.output(public, &format!("payload limb {i}"));
        }
        let ir = c.finish(false).ir;

        TestRunner::new(gen::config())
            .run(&respond_misc(), |payload| {
                let mut inputs = Vec::new();
                for b32 in [
                    &payload.request_id,
                    &payload.big_r_x,
                    &payload.big_r_y,
                    &payload.s,
                ] {
                    let (hi, lo) = b32_slots(b32);
                    inputs.extend([hi, lo]);
                }
                inputs.push(Fr::from(u64::from(payload.recovery_id)));

                let run = simulate(&ir, &arg_preimage(inputs)).expect("the encoder circuit accepts");
                let limbs: Vec<Fr> = run
                    .outputs
                    .iter()
                    .map(|v| match v {
                        IrValue::Native(fr) => *fr,
                        other => panic!("expected a native output, got {other:?}"),
                    })
                    .collect();

                // Slot 0 is the leftover (most significant) chunk, so string
                // order is the slots reversed.
                let mut bytes = Vec::with_capacity(RespondMisc::LEN);
                for (i, limb) in limbs.iter().enumerate().rev() {
                    let width =
                        minocrab_std::v3::BytesN::<Private, { RespondMisc::LEN }>::limb_len(i);
                    bytes.extend_from_slice(&limb.as_le_bytes()[..width]);
                }
                prop_assert_eq!(bytes, borsh_bytes(&payload));
                Ok(())
            })
            .expect("the in-circuit encoder emits canonical Borsh");
    }

    /// The generated cross-check is not vacuous: move one offset and it
    /// fires, naming the row.
    #[test]
    #[should_panic(expected = "is not its spec type's Borsh schema")]
    fn the_schema_cross_check_catches_a_moved_offset() {
        let mut ours = <RespondMiscCircuit<Private> as CircuitBorsh<Private>>::layout();
        ours[1].offset += 1;
        minocrab_std::v3::borsh::schema::assert_matches_schema::<RespondMisc>(
            "RespondMiscCircuit",
            &ours,
        );
    }

    /// The circuit type's layout table IS borsh's own schema walk of the spec
    /// type — same paths, same kinds, same offsets, same widths. (This is the
    /// cross-check `#[borsh(spec = …)]` generates in stage 3, done by hand for
    /// one deployed shape.)
    #[test]
    fn the_circuit_layout_is_the_schema_layout() {
        assert_eq!(
            <RespondMiscCircuit<Private> as CircuitBorsh<Private>>::LEN,
            RespondMisc::LEN
        );
        let ours: Vec<(String, String, usize, usize)> =
            <RespondMiscCircuit<Private> as CircuitBorsh<Private>>::layout()
                .into_iter()
                .map(|f| (f.path, f.kind, f.offset, f.width))
                .collect();
        let theirs: Vec<(String, String, usize, usize)> =
            layout_rows(&borsh::schema::BorshSchemaContainer::for_type::<RespondMisc>())
                .into_iter()
                .map(|r| (r.path, r.kind, r.offset, r.width))
                .collect();
        assert_eq!(ours, theirs);
    }
}

/// Regeneration helper: prints the `LAYOUT_SNAPSHOT` table body.
#[test]
#[ignore = "regeneration helper, not a check"]
fn print_layout_snapshot() {
    for (ty, row) in snapshot_rows() {
        println!(
            "    (\"{ty}\", \"{}\", \"{}\", {}, {}),",
            row.path, row.kind, row.offset, row.width
        );
    }
}
