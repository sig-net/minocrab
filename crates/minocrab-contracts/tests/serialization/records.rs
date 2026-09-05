//! The bridge between the reference model's scenarios and the spec types.
//!
//! Each function below reads a scenario's FIELD VALUES and fills in the
//! matching spec type. It is deliberately a second, independent statement of
//! the same record: the model produces the deployed bytes (FAB limbs →
//! `binary_repr`), the spec type produces the Borsh/bincode bytes, and the
//! conformance property asserts the two byte strings are equal. Neither side
//! is computed from the other.
//!
//! Read these side by side with `vault::model`'s `Req::limbs`: field for
//! field, in the same order, they must say the same thing.
//!
//! Since the protocol move (M28) the REQUEST ID is no longer a function of
//! these bytes: it is Poseidon over the record's field-aligned limbs
//! (`vault::prims::request_id_of`), which the byte encoding does not
//! determine. The byte-equality claims below stand; the id claim moved to
//! the model.

use minocrab::Public;
use minocrab_contracts::signet::{SignBidirectionalEvent, SignBidirectionalEventV2};
use minocrab_contracts::{erc20_vault, erc20_vault_pending};

use crate::serialization::spec_types;
use crate::serialization::spec_types::{
    ByteArray, EvmCalldata2, EvmCalldata7, EvmType2TxParams2, EvmType2TxParams7, Flagged,
    SwapEvent, SwapEventV2, VaultEvent, VaultEventV2,
};
use crate::vault::model::{
    ApproveRouterScenario, StartDepositScenario, StartSwapScenario, StartWithdrawScenario,
};
use crate::vault::prims::{abi_addr_word, abi_num_word, pad32};

/// A response-kind constant as the wire carries it: one Borsh byte.
pub fn kind(k: u32) -> u8 {
    u8::try_from(k).expect("a Borsh tag is one byte")
}

/// The FAB atoms of the deployed 2-word record — the SHIPPING definition
/// (`erc20_vault::VaultEvent`), i.e. the alignment `calculateRequestId`
/// hands to `keccak256` in-circuit.
pub fn vault_record_atoms() -> Vec<minocrab::AlignmentAtom> {
    erc20_vault::VaultEvent::<Public>::atoms()
}

/// The FAB atoms of the deployed 7-word swap record.
pub fn swap_record_atoms() -> Vec<minocrab::AlignmentAtom> {
    erc20_vault::SwapEvent::<Public>::atoms()
}

/// `MPCSignatureAlgorithm.ecdsa` / `MPCDestination.unused` /
/// `TxParamType.evmType2` — all first enum members, so all zero.
const TAG_FIRST_MEMBER: u8 = 0;

/// The fixed EIP-1559 fees the vault's non-deposit request circuits hard-code.
const FIXED_MAX_PRIORITY_FEE: u128 = 1_000_000_000;
const FIXED_MAX_FEE: u128 = 30_000_000_000;
const VAULT_GAS_LIMIT: u64 = 100_000;
const SWAP_GAS_LIMIT: u64 = 700_000;

/// `numericAbiWord(unlimitedAllowance())`.
fn max_allowance_word() -> [u8; 32] {
    abi_num_word(u128::MAX)
}

fn schema<const N: usize>(bytes: &[u8]) -> ByteArray<N> {
    ByteArray(bytes.try_into().expect("schema literal has its declared width"))
}

/// `deposit`'s record: a `transfer(vaultEvmAddress, amount)` request signed
/// under the depositor's own derived key (`path = userCommitment(sk)`).
pub fn deposit_event(d: &StartDepositScenario) -> VaultEvent {
    VaultEvent {
        sender: d.env.self_addr,
        request_nonce: d.env.request_nonce,
        key_version: d.key_version,
        path: d.commitment(),
        algo: TAG_FIRST_MEMBER,
        dest: TAG_FIRST_MEMBER,
        params: ByteArray::default(),
        tx_param_type: TAG_FIRST_MEMBER,
        tx_params: EvmType2TxParams2 {
            chain_id: d.env.chain_id,
            nonce: d.evm_nonce,
            max_priority_fee_per_gas: d.max_priority_fee_per_gas,
            max_fee_per_gas: d.max_fee_per_gas,
            gas_limit: d.gas_limit,
            to: d.erc20,
            value: 0,
            calldata: Flagged {
                is_some: true,
                value: EvmCalldata2 {
                    selector: erc20_vault::TRANSFER_SELECTOR,
                    no_words: 2,
                    words: [abi_addr_word(&d.env.vault_evm), abi_num_word(d.amount)],
                },
            },
            access_list_entry_count: 0,
        },
        caip2_id: d.env.caip2,
        output_deserialization_schema: schema(erc20_vault::VAULT_RESPONSE_SCHEMA),
        respond_serialization_schema: schema(erc20_vault::VAULT_RESPONSE_SCHEMA),
    }
}

/// `approveRouter`'s record: an `approve(router, 2^128 − 1)` request signed
/// under the vault's own path.
pub fn approve_event(a: &ApproveRouterScenario) -> VaultEvent {
    VaultEvent {
        sender: a.env.self_addr,
        request_nonce: a.env.request_nonce,
        key_version: a.key_version,
        path: pad32(erc20_vault::VAULT_PATH),
        algo: TAG_FIRST_MEMBER,
        dest: TAG_FIRST_MEMBER,
        params: ByteArray::default(),
        tx_param_type: TAG_FIRST_MEMBER,
        tx_params: EvmType2TxParams2 {
            chain_id: a.env.chain_id,
            nonce: a.evm_nonce,
            max_priority_fee_per_gas: FIXED_MAX_PRIORITY_FEE,
            max_fee_per_gas: FIXED_MAX_FEE,
            gas_limit: VAULT_GAS_LIMIT,
            to: a.erc20,
            value: 0,
            calldata: Flagged {
                is_some: true,
                value: EvmCalldata2 {
                    selector: erc20_vault::APPROVE_SELECTOR,
                    no_words: 2,
                    words: [abi_addr_word(&a.env.router), max_allowance_word()],
                },
            },
            access_list_entry_count: 0,
        },
        caip2_id: a.env.caip2,
        output_deserialization_schema: schema(erc20_vault::VAULT_RESPONSE_SCHEMA),
        respond_serialization_schema: schema(erc20_vault::VAULT_RESPONSE_SCHEMA),
    }
}

/// `withdraw`'s record: a `transfer(dest, amount)` request signed under the
/// vault's own path.
pub fn withdraw_event(w: &StartWithdrawScenario) -> VaultEvent {
    VaultEvent {
        sender: w.env.self_addr,
        request_nonce: w.env.request_nonce,
        key_version: w.key_version,
        path: pad32(erc20_vault::VAULT_PATH),
        algo: TAG_FIRST_MEMBER,
        dest: TAG_FIRST_MEMBER,
        params: ByteArray::default(),
        tx_param_type: TAG_FIRST_MEMBER,
        tx_params: EvmType2TxParams2 {
            chain_id: w.env.chain_id,
            nonce: w.evm_nonce,
            max_priority_fee_per_gas: FIXED_MAX_PRIORITY_FEE,
            max_fee_per_gas: FIXED_MAX_FEE,
            gas_limit: VAULT_GAS_LIMIT,
            to: w.erc20,
            value: 0,
            calldata: Flagged {
                is_some: true,
                value: EvmCalldata2 {
                    selector: erc20_vault::TRANSFER_SELECTOR,
                    no_words: 2,
                    words: [abi_addr_word(&w.dest), abi_num_word(w.amount)],
                },
            },
            access_list_entry_count: 0,
        },
        caip2_id: w.env.caip2,
        output_deserialization_schema: schema(erc20_vault::VAULT_RESPONSE_SCHEMA),
        respond_serialization_schema: schema(erc20_vault::VAULT_RESPONSE_SCHEMA),
    }
}

/// `swap`'s record: an `exactOutputSingle(...)` request, seven ABI words and
/// the two wider schemas.
pub fn swap_event(s: &StartSwapScenario) -> SwapEvent {
    SwapEvent {
        sender: s.env.self_addr,
        request_nonce: s.env.request_nonce,
        key_version: s.key_version,
        path: pad32(erc20_vault::VAULT_PATH),
        algo: TAG_FIRST_MEMBER,
        dest: TAG_FIRST_MEMBER,
        params: ByteArray::default(),
        tx_param_type: TAG_FIRST_MEMBER,
        tx_params: EvmType2TxParams7 {
            chain_id: s.env.chain_id,
            nonce: s.evm_nonce,
            max_priority_fee_per_gas: FIXED_MAX_PRIORITY_FEE,
            max_fee_per_gas: FIXED_MAX_FEE,
            gas_limit: SWAP_GAS_LIMIT,
            to: s.env.router,
            value: 0,
            calldata: Flagged {
                is_some: true,
                value: EvmCalldata7 {
                    selector: erc20_vault::EXACT_OUTPUT_SINGLE_SELECTOR,
                    no_words: 7,
                    words: [
                        abi_addr_word(&s.token_in),
                        abi_addr_word(&s.token_out),
                        abi_num_word(u128::from(s.fee)),
                        abi_addr_word(&s.env.vault_evm),
                        abi_num_word(s.amount_out),
                        abi_num_word(s.amount_in_max),
                        [0u8; 32],
                    ],
                },
            },
            access_list_entry_count: 0,
        },
        caip2_id: s.env.caip2,
        output_deserialization_schema: schema(erc20_vault::SWAP_OUTPUT_SCHEMA),
        respond_serialization_schema: schema(erc20_vault::SWAP_RESPOND_SCHEMA),
    }
}

/// The deployed records' limb counts, so a shape change here is loud.
pub const VAULT_RECORD_LIMBS: usize = SignBidirectionalEvent::<Public, 2, 34, 34>::LIMBS;
pub const SWAP_RECORD_LIMBS: usize = SignBidirectionalEvent::<Public, 7, 38, 37>::LIMBS;

// ---- M11 stage 7: the same records, versioned and kind-tagged ----------------

/// The FAB atoms of the stage-7 2-word record, from the SHIPPING definition.
pub fn vault_record_v2_atoms() -> Vec<minocrab::AlignmentAtom> {
    erc20_vault_pending::VaultEventV2::<Public>::atoms()
}

/// The FAB atoms of the stage-7 7-word swap record.
pub fn swap_record_v2_atoms() -> Vec<minocrab::AlignmentAtom> {
    erc20_vault_pending::SwapEventV2::<Public>::atoms()
}

/// The stage-7 records' limb counts (31 and 41, where the deployed pair is 33
/// and 43 — one limb gained at the head, four schema limbs traded for one).
pub const VAULT_RECORD_V2_LIMBS: usize = SignBidirectionalEventV2::<Public, 2>::LIMBS;
pub const SWAP_RECORD_V2_LIMBS: usize = SignBidirectionalEventV2::<Public, 7>::LIMBS;

/// The stage-7 twin of a deployed 2-word record: the same middle, a format
/// version in front, a response kind instead of the two schema strings.
///
/// Written as a field-for-field rebuild of the deployed value rather than as a
/// third statement of the middle — the middle is what stage 7 does NOT change,
/// and saying it twice would let the two drift while both stayed green.
fn vault_v2(e: VaultEvent, response_kind: u32) -> VaultEventV2 {
    VaultEventV2 {
        format_version: spec_types::RECORD_FORMAT_VERSION,
        sender: e.sender,
        request_nonce: e.request_nonce,
        key_version: e.key_version,
        path: e.path,
        algo: e.algo,
        dest: e.dest,
        params: e.params,
        tx_param_type: e.tx_param_type,
        tx_params: e.tx_params,
        caip2_id: e.caip2_id,
        response_kind: kind(response_kind),
    }
}

/// `deposit`'s stage-7 record — response kind CLAIM.
pub fn deposit_event_v2(d: &StartDepositScenario) -> VaultEventV2 {
    vault_v2(deposit_event(d), erc20_vault_pending::RESPONSE_KIND_CLAIM)
}

/// `approveRouter`'s stage-7 record — response kind APPROVE, the one kind no
/// settle circuit accepts.
pub fn approve_event_v2(a: &ApproveRouterScenario) -> VaultEventV2 {
    vault_v2(approve_event(a), erc20_vault_pending::RESPONSE_KIND_APPROVE)
}

/// `withdraw`'s stage-7 record — response kind WITHDRAW.
pub fn withdraw_event_v2(w: &StartWithdrawScenario) -> VaultEventV2 {
    vault_v2(withdraw_event(w), erc20_vault_pending::RESPONSE_KIND_WITHDRAW)
}

/// `swap`'s stage-7 record — response kind SWAP.
pub fn swap_event_v2(s: &StartSwapScenario) -> SwapEventV2 {
    let e = swap_event(s);
    SwapEventV2 {
        format_version: spec_types::RECORD_FORMAT_VERSION,
        sender: e.sender,
        request_nonce: e.request_nonce,
        key_version: e.key_version,
        path: e.path,
        algo: e.algo,
        dest: e.dest,
        params: e.params,
        tx_param_type: e.tx_param_type,
        tx_params: e.tx_params,
        caip2_id: e.caip2_id,
        response_kind: kind(erc20_vault_pending::RESPONSE_KIND_SWAP),
    }
}
