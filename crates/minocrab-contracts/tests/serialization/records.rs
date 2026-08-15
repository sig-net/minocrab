//! The bridge between the reference model's scenarios and the spec types.
//!
//! Each function below reads a scenario's FIELD VALUES and fills in the
//! matching spec type. It is deliberately a second, independent statement of
//! the same record: the model produces the deployed bytes (FAB limbs →
//! `binary_repr` → keccak256), the spec type produces the Borsh/bincode
//! bytes, and the conformance property asserts the two byte strings are
//! equal. Neither side is computed from the other.
//!
//! Read these side by side with `vault::model`'s `event_limbs`: field for
//! field, in the same order, they must say the same thing.

use minocrab::Public;
use minocrab_contracts::erc20_vault;
use minocrab_contracts::signet::SignBidirectionalEvent;

use crate::serialization::spec_types::{
    ByteArray, EvmCalldata2, EvmCalldata7, EvmType2TxParams2, EvmType2TxParams7, Flagged,
    SwapEvent, VaultEvent,
};
use crate::vault::model::{ApproveScenario, DepositScenario, SwapScenario, WithdrawScenario};
use crate::vault::prims::{abi_addr_word, abi_num_word, pad32, user_commitment};

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

fn schema<const N: usize>(bytes: &[u8]) -> ByteArray<N> {
    ByteArray(bytes.try_into().expect("schema literal has its declared width"))
}

/// `deposit`'s record: a `transfer(vaultEvmAddress, amount)` request signed
/// under the depositor's own derived key (`path = userCommitment(sk)`).
pub fn deposit_event(d: &DepositScenario) -> VaultEvent {
    VaultEvent {
        sender: d.self_addr,
        request_nonce: d.request_nonce,
        key_version: d.key_version,
        path: user_commitment(d.art, &d.sk),
        algo: TAG_FIRST_MEMBER,
        dest: TAG_FIRST_MEMBER,
        params: ByteArray::default(),
        tx_param_type: TAG_FIRST_MEMBER,
        tx_params: EvmType2TxParams2 {
            chain_id: d.chain_id,
            nonce: d.evm_nonce,
            max_priority_fee_per_gas: u128::from(d.max_priority_fee_per_gas),
            max_fee_per_gas: u128::from(d.max_fee_per_gas),
            gas_limit: d.gas_limit,
            to: d.erc20,
            value: 0,
            calldata: Flagged {
                is_some: true,
                value: EvmCalldata2 {
                    selector: erc20_vault::TRANSFER_SELECTOR,
                    no_words: 2,
                    words: [d.word0(), d.word1()],
                },
            },
            access_list_entry_count: 0,
        },
        caip2_id: d.caip2,
        output_deserialization_schema: schema(erc20_vault::VAULT_RESPONSE_SCHEMA),
        respond_serialization_schema: schema(erc20_vault::VAULT_RESPONSE_SCHEMA),
    }
}

/// `approveRouter`'s record: an `approve(router, 2^128 − 1)` request signed
/// under the vault's own path.
pub fn approve_event(a: &ApproveScenario) -> VaultEvent {
    VaultEvent {
        sender: a.self_addr,
        request_nonce: a.request_nonce,
        key_version: a.key_version,
        path: pad32(erc20_vault::VAULT_PATH),
        algo: TAG_FIRST_MEMBER,
        dest: TAG_FIRST_MEMBER,
        params: ByteArray::default(),
        tx_param_type: TAG_FIRST_MEMBER,
        tx_params: EvmType2TxParams2 {
            chain_id: a.chain_id,
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
                    words: [a.word0(), a.word1()],
                },
            },
            access_list_entry_count: 0,
        },
        caip2_id: a.caip2,
        output_deserialization_schema: schema(erc20_vault::VAULT_RESPONSE_SCHEMA),
        respond_serialization_schema: schema(erc20_vault::VAULT_RESPONSE_SCHEMA),
    }
}

/// `withdraw`'s record: a `transfer(dest, amount)` request signed under the
/// vault's own path.
pub fn withdraw_event(w: &WithdrawScenario) -> VaultEvent {
    VaultEvent {
        sender: w.self_addr,
        request_nonce: w.request_nonce,
        key_version: w.key_version,
        path: pad32(erc20_vault::VAULT_PATH),
        algo: TAG_FIRST_MEMBER,
        dest: TAG_FIRST_MEMBER,
        params: ByteArray::default(),
        tx_param_type: TAG_FIRST_MEMBER,
        tx_params: EvmType2TxParams2 {
            chain_id: w.chain_id,
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
        caip2_id: w.caip2,
        output_deserialization_schema: schema(erc20_vault::VAULT_RESPONSE_SCHEMA),
        respond_serialization_schema: schema(erc20_vault::VAULT_RESPONSE_SCHEMA),
    }
}

/// `swap`'s record: an `exactOutputSingle(...)` request, seven ABI words and
/// the two wider schemas.
pub fn swap_event(s: &SwapScenario) -> SwapEvent {
    SwapEvent {
        sender: s.self_addr,
        request_nonce: s.request_nonce,
        key_version: s.key_version,
        path: pad32(erc20_vault::VAULT_PATH),
        algo: TAG_FIRST_MEMBER,
        dest: TAG_FIRST_MEMBER,
        params: ByteArray::default(),
        tx_param_type: TAG_FIRST_MEMBER,
        tx_params: EvmType2TxParams7 {
            chain_id: s.chain_id,
            nonce: s.evm_nonce,
            max_priority_fee_per_gas: FIXED_MAX_PRIORITY_FEE,
            max_fee_per_gas: FIXED_MAX_FEE,
            gas_limit: SWAP_GAS_LIMIT,
            to: s.router,
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
                        abi_addr_word(&s.vault_evm),
                        abi_num_word(s.amount_out),
                        abi_num_word(s.amount_in_max),
                        [0u8; 32],
                    ],
                },
            },
            access_list_entry_count: 0,
        },
        caip2_id: s.caip2,
        output_deserialization_schema: schema(erc20_vault::SWAP_OUTPUT_SCHEMA),
        respond_serialization_schema: schema(erc20_vault::SWAP_RESPOND_SCHEMA),
    }
}

/// The deployed records' limb counts, so a shape change here is loud.
pub const VAULT_RECORD_LIMBS: usize = SignBidirectionalEvent::<Public, 2, 34, 34>::LIMBS;
pub const SWAP_RECORD_LIMBS: usize = SignBidirectionalEvent::<Public, 7, 38, 37>::LIMBS;
