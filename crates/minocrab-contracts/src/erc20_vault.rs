//! `erc20-vault` (signet-midnight-examples) — THE benchmark target: the
//! shielded cross-chain ERC-20 vault. Ported circuit by circuit; each port
//! carries a differential test against compactc's artifact.
//!
//! So far: `initialize` (Setup step 4 — one-shot, deployer-gated
//! post-deploy configuration).
//!
//! Compact original (fields in declaration order):
//! ```text
//! export ledger signBidirectionalEventMap: …;           // field 0
//! sealed ledger signetSigner: SignetSigner;             // field 1
//! export ledger mpcResponseKey: Secp256k1Point;         // field 2
//! export ledger signetRequestNonce: Counter;            // field 3
//! export ledger initialized: Counter;                   // field 4
//! export ledger vaultEvmAddress: Bytes<20>;             // field 5
//! export ledger evmChainId: Uint<64>;                   // field 6
//! export ledger caip2Id: Bytes<32>;                     // field 7
//! sealed ledger deployer: Bytes<32>;                    // field 8
//! export ledger refundCommitment: Map<RequestId, Bytes<32>>; // field 9
//! export ledger uniswapRouter: Bytes<20>;               // field 10
//! export ledger swapEventMap: …;                        // field 11
//! export ledger swapRefundCommitment: Map<…>;           // field 12
//!
//! witness callerSecretKey(): Bytes<32>;
//!
//! initialize(vaultEvm: Bytes<20>, swapRouter: Bytes<20>, chainId: Uint<64>,
//!            chainCaip2Id: Bytes<32>, responseKey: Secp256k1Point):
//!     assert(initialized == 0, "Already initialized");
//!     assert(userCommitment(callerSecretKey()) == deployer, "Not the deployer");
//!     assert(chainId > 0 as Uint<64>, "Chain ID must be positive");
//!     assert(swapRouter as Field != 0 as Field, "Router cannot be zero");
//!     initialized.increment(1);
//!     vaultEvmAddress = disclose(vaultEvm);
//!     uniswapRouter = disclose(swapRouter);
//!     evmChainId = disclose(chainId);
//!     caip2Id = disclose(chainCaip2Id);
//!     mpcResponseKey = disclose(responseKey);
//! ```
//! with `userCommitment(sk) =
//! persistentHash<Vector<2, Bytes<32>>>([pad(32, "vault:user:"), sk])`.

use minocrab::v3::{Circuit3, Compiled3, FieldT, Secp256k1PointT, Wire3};
use minocrab::{Alignment, AlignmentAtom, AlignmentSegment, Private, Public};
use minocrab_ledger::{
    cell_read, cell_write, counter_increment, counter_read, contract_call, emit, kernel_self,
    map_insert, map_lookup, map_member, map_remove, ImpactElem, LedgerValue,
};
use minocrab_std::v3::{own_public_key_guarded, BytesN, CoinRecipient, B32};

use crate::common;
use crate::signet;

/// Ledger field indices, in declaration order.
pub const SIGN_BIDIRECTIONAL_EVENT_MAP: u8 = 0;
pub const SIGNET_SIGNER: u8 = 1;
pub const MPC_RESPONSE_KEY: u8 = 2;
pub const SIGNET_REQUEST_NONCE: u8 = 3;
pub const INITIALIZED: u8 = 4;
pub const VAULT_EVM_ADDRESS: u8 = 5;
pub const EVM_CHAIN_ID: u8 = 6;
pub const CAIP2_ID: u8 = 7;
pub const DEPLOYER: u8 = 8;
pub const REFUND_COMMITMENT: u8 = 9;
pub const UNISWAP_ROUTER: u8 = 10;
pub const SWAP_EVENT_MAP: u8 = 11;
pub const SWAP_REFUND_COMMITMENT: u8 = 12;

/// The domain-separation prefix of `userCommitment`.
pub const USER_PAD: &str = "vault:user:";

/// The domain-separation prefix of `vaultTokenDomainSeparator`.
pub const TOKEN_PAD: &str = "erc20:vault:";

/// `vaultResponseSchema()` — the exact-width 34-byte ABI schema string.
pub const VAULT_RESPONSE_SCHEMA: &[u8] = b"[{\"name\":\"success\",\"type\":\"bool\"}]";

/// `transfer(address,uint256)`'s selector.
pub const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

/// `approve(address,uint256)`'s selector.
pub const APPROVE_SELECTOR: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];

/// The vault's own MPC key-derivation path, `pad(32, "vault")`.
pub const VAULT_PATH: &str = "vault";

/// The domain-separation prefix of `withdrawRefundCommitment`.
pub const REFUND_PAD: &str = "vault:refund:";

/// `swapOutputSchema()` (38 bytes) and `swapRespondSchema()` (37 bytes).
pub const SWAP_OUTPUT_SCHEMA: &[u8] = b"[{\"name\":\"amountIn\",\"type\":\"uint256\"}]";
pub const SWAP_RESPOND_SCHEMA: &[u8] = b"[{\"name\":\"amountIn\",\"type\":\"uint64\"}]";

/// `exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))`.
pub const EXACT_OUTPUT_SINGLE_SELECTOR: [u8; 4] = [0x50, 0x23, 0xb4, 0xdf];

pub use crate::common::secp256k1_point_atoms;

/// `export circuit initialize(vaultEvm, swapRouter, chainId, chainCaip2Id,
/// responseKey): []`
pub fn initialize() -> Compiled3 {
    let mut c = Circuit3::new();
    // Arguments in source order, FAB-flattened: Bytes<20> = 1 limb
    // (160 bits), Uint<64> = 1 limb, Bytes<32> = [hi, lo].
    let vault_evm = c.arg::<FieldT>("vaultEvm");
    let swap_router = c.arg::<FieldT>("swapRouter");
    let chain_id = c.arg::<FieldT>("chainId");
    let caip2 = B32 {
        hi: c.arg::<FieldT>("chainCaip2Id_hi"),
        lo: c.arg::<FieldT>("chainCaip2Id_lo"),
    };
    let response_key = c.arg::<Secp256k1PointT>("responseKey");
    c.assert_bits(vault_evm, 160);
    c.assert_bits(swap_router, 160);
    c.assert_bits(chain_id, 64);
    caip2.constrain_input(&mut c);

    let one = c.constant(1u64);
    let zero = c.constant(0u64);

    // assert(initialized == 0, "Already initialized")
    c.region("initialized gate", |c| {
        common::assert_counter_zero(c, one, INITIALIZED);
    });

    // assert(userCommitment(callerSecretKey()) == deployer, "Not the deployer")
    c.region("deployer gate", |c| {
        common::assert_deployer(c, one, USER_PAD, DEPLOYER);
    });

    // assert(chainId > 0, "Chain ID must be positive")
    let positive = c.less_than(zero, chain_id, 64);
    c.assert(positive);

    // assert(swapRouter as Field != 0, "Router cannot be zero")
    let router_zero = c.test_eq(swap_router, zero);
    let router_nonzero = c.not(router_zero);
    c.assert(router_nonzero);

    // initialized.increment(1)
    emit(&mut c, one, &counter_increment(INITIALIZED, 1));

    // The five configuration writes, in source order.
    c.region("configuration writes", |c| {
        let vault_evm = c.disclose(vault_evm, "the vault's derived EVM address");
        let b20 = |w| LedgerValue::bytes(20, vec![ImpactElem::Wire(w)]);
        emit(c, one, &cell_write(VAULT_EVM_ADDRESS, &b20(vault_evm)));

        let swap_router = c.disclose(swap_router, "the Uniswap router address");
        emit(c, one, &cell_write(UNISWAP_ROUTER, &b20(swap_router)));

        let chain_id = c.disclose(chain_id, "the EVM chain id");
        let chain_val = LedgerValue::bytes(8, vec![ImpactElem::Wire(chain_id)]);
        emit(c, one, &cell_write(EVM_CHAIN_ID, &chain_val));

        let caip2_hi = c.disclose(caip2.hi, "the CAIP-2 chain id (hi)");
        let caip2_lo = c.disclose(caip2.lo, "the CAIP-2 chain id (lo)");
        let caip2_val = LedgerValue::bytes(
            32,
            vec![ImpactElem::Wire(caip2_hi), ImpactElem::Wire(caip2_lo)],
        );
        emit(c, one, &cell_write(CAIP2_ID, &caip2_val));

        let pk = c.disclose(response_key, "the MPC response key");
        let limbs = c.encode(pk);
        let pk_val = LedgerValue::new(
            common::secp256k1_point_atoms(),
            limbs.iter().map(|&w| ImpactElem::Wire(w)).collect(),
        );
        emit(c, one, &cell_write(MPC_RESPONSE_KEY, &pk_val));
    });

    c.finish(true)
}

/// `assert(initialized >= 1, "Not initialized")` — a Counter read + `0 <
/// initialized`.
fn assert_initialized(c: &mut Circuit3, one: Wire3<FieldT, Public>) {
    let init = counter_read(c, one, INITIALIZED);
    let zero = c.constant(0u64);
    let positive = c.less_than(zero, init, 64);
    c.assert(positive);
}

/// `export circuit deposit(evmNonce: Uint<64>, gasLimit: Uint<64>,
/// maxFeePerGas: Uint<128>, maxPriorityFeePerGas: Uint<128>, keyVersion:
/// Uint<8>, depositRequest: DepositRequest): []` — Runtime step 1 of a
/// deposit: record the `transfer(vaultEvmAddress, amount)` request under
/// the caller's identity commitment and notify the MPC through the Signet
/// singleton (deposit.zkir; the read order is the PI contract:
/// initialized, vaultEvmAddress, evmChainId, signetRequestNonce,
/// kernel.self, caip2Id, map member, signetSigner, kernel.self).
pub fn deposit() -> Compiled3 {
    let mut c = Circuit3::new();
    let evm_nonce = c.arg::<FieldT>("evmNonce");
    let gas_limit = c.arg::<FieldT>("gasLimit");
    let max_fee_per_gas = c.arg::<FieldT>("maxFeePerGas");
    let max_priority_fee_per_gas = c.arg::<FieldT>("maxPriorityFeePerGas");
    let key_version = c.arg::<FieldT>("keyVersion");
    let erc20_address = c.arg::<FieldT>("depositRequest_erc20Address");
    let amount = c.arg::<FieldT>("depositRequest_amount");
    c.assert_bits(evm_nonce, 64);
    c.assert_bits(gas_limit, 64);
    c.assert_bits(max_fee_per_gas, 128);
    c.assert_bits(max_priority_fee_per_gas, 128);
    c.assert_bits(key_version, 8);
    c.assert_bits(erc20_address, 160);
    c.assert_bits(amount, 128);

    let one = c.constant(1u64);
    let zero = c.constant(0u64);

    // assert(initialized >= 1, "Not initialized")
    c.region("guards", |c| {
        assert_initialized(c, one);

        // assert(erc20Address as Field != 0)
        let erc20_zero = c.test_eq(erc20_address, zero.private());
        let erc20_nonzero = c.not(erc20_zero);
        c.assert(erc20_nonzero);

        // assert(amount > 0)
        let amount_positive = c.less_than(zero.private(), amount, 128);
        c.assert(amount_positive);

        // assert(amount <= u64::MAX) — claims mint via a Uint<64> API.
        let u64_max = c.constant(u64::MAX);
        let too_big = c.less_than(u64_max.private(), amount, 128);
        let fits = c.not(too_big);
        c.assert(fits);

        // assert(gasLimit > 0)
        let gas_positive = c.less_than(zero.private(), gas_limit, 64);
        c.assert(gas_positive);
    });

    // const caller = disclose(userCommitment(callerSecretKey()))
    let sk = common::witness_sk(&mut c);
    let caller_priv = common::commitment(&mut c, USER_PAD, &sk);
    let caller = B32 {
        hi: c.disclose(caller_priv.hi, "depositor identity commitment (hi)"),
        lo: c.disclose(caller_priv.lo, "depositor identity commitment (lo)"),
    };

    // Contract-enforced calldata: transfer(vaultEvmAddress, amount).
    let vault_evm = cell_read(
        &mut c,
        one,
        VAULT_EVM_ADDRESS,
        vec![AlignmentAtom::Bytes { length: 20 }],
    )[0];
    let word0 = signet::evm_address_abi_word(&mut c, vault_evm.private());
    let word1 = signet::numeric_abi_word(&mut c, amount);
    let selector = c.constant(minocrab::Fr::from_le_bytes(&TRANSFER_SELECTOR).unwrap());
    let two = c.constant(2u64);
    let calldata = signet::EvmCalldata::<Private> {
        selector: selector.private(),
        no_words: two.private(),
        words: vec![word0, word1],
    };

    // The full transaction the MPC will sign.
    let chain_id = cell_read(
        &mut c,
        one,
        EVM_CHAIN_ID,
        vec![AlignmentAtom::Bytes { length: 8 }],
    )[0];
    let tx_params = signet::EvmType2TxParams::<Private> {
        chain_id: chain_id.private(),
        nonce: evm_nonce,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
        to: erc20_address,
        value: zero.private(),
        calldata_is_some: one.private(),
        calldata,
        access_list_entry_count: zero.private(),
    };

    // constructSignBidirectionalEvent(kernel.self(), requestNonce,
    // keyVersion, caller, ecdsa, unused, pad(64, ""), evmType2, txParams,
    // caip2Id, schema, schema)
    let request_nonce = counter_read(&mut c, one, SIGNET_REQUEST_NONCE);
    let sender = kernel_self(&mut c, one);
    let sender = B32 {
        hi: sender[0].private(),
        lo: sender[1].private(),
    };
    let caip2 = cell_read(
        &mut c,
        one,
        CAIP2_ID,
        vec![AlignmentAtom::Bytes { length: 32 }],
    );
    let caip2 = B32 {
        hi: caip2[0].private(),
        lo: caip2[1].private(),
    };
    let schema = BytesN::<Private>::literal(&mut c, VAULT_RESPONSE_SCHEMA);
    let request = signet::construct_sign_bidirectional_event(
        &mut c,
        sender,
        request_nonce.private(),
        key_version,
        B32 {
            hi: caller.hi.private(),
            lo: caller.lo.private(),
        },
        tx_params,
        caip2,
        schema.clone(),
        schema,
    );

    record_and_notify(&mut c, one, &request, 34, 34, SIGN_BIDIRECTIONAL_EVENT_MAP, [0, 0, 0, 0]);

    c.finish(true)
}

/// `requestId = disclose(calculateRequestId(request))` +
/// `assert(!map.member(requestId), "Request already exists")`. Returns the
/// disclosed id and its ledger-value form.
fn check_fresh_request(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    request: &signet::SignBidirectionalEvent<Private>,
    len_out: u32,
    len_respond: u32,
    map_field: u8,
) -> (B32<Public>, LedgerValue) {
    let request_id_priv = signet::calculate_request_id(c, request, len_out, len_respond);
    c.region("record: freshness", |c| {
        let request_id = B32 {
            hi: c.disclose(request_id_priv.hi, "request id (hi)"),
            lo: c.disclose(request_id_priv.lo, "request id (lo)"),
        };
        let request_id_val = LedgerValue::bytes(
            32,
            vec![
                ImpactElem::Wire(request_id.hi),
                ImpactElem::Wire(request_id.lo),
            ],
        );
        let exists = map_member(c, one, map_field, &request_id_val);
        let fresh = c.not(exists);
        c.assert(fresh);
        (request_id, request_id_val)
    })
}

/// `signetRequestNonce.increment(1)` + `map.insert(requestId,
/// disclose(request))`.
fn insert_request(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    request: &signet::SignBidirectionalEvent<Private>,
    len_out: u32,
    len_respond: u32,
    map_field: u8,
    request_id_val: &LedgerValue,
) {
    c.region("record: insert", |c| {
        emit(c, one, &counter_increment(SIGNET_REQUEST_NONCE, 1));
        let event_atoms = request.atoms(len_out, len_respond);
        let event_limbs: Vec<ImpactElem> = request
            .limbs()
            .into_iter()
            .map(|w| ImpactElem::Wire(c.disclose(w, "request record")))
            .collect();
        let event_val = LedgerValue::new(event_atoms, event_limbs);
        emit(c, one, &map_insert(map_field, request_id_val, &event_val));
    });
}

/// `signetSigner.signBidirectional(requestId,
/// constructSignBidirectionalEventNotificationV1(kernel.self(), 1, path))`
/// — the signer read, the caller's own address, the notification, and the
/// cross-contract call.
fn notify_signet(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    request_id: &B32<Public>,
    notify_path: [u8; 4],
) {
    c.region("xcall: notify signet", |c| {
        let signer = cell_read(
            c,
            one,
            SIGNET_SIGNER,
            vec![AlignmentAtom::Bytes { length: 32 }],
        );
        let me = kernel_self(c, one);
        let me = B32 { hi: me[0], lo: me[1] };
        let (version, payload) = signet::construct_notification_v1::<Public>(c, &me, 1, notify_path);
        let mut args = vec![request_id.hi, request_id.lo, version];
        args.extend(payload.limbs.iter().copied());
        contract_call(c, one, [signer[0], signer[1]], &args, &[]);
    });
}

/// The contiguous tail deposit/approveRouter share: freshness check,
/// record, notify.
fn record_and_notify(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    request: &signet::SignBidirectionalEvent<Private>,
    len_out: u32,
    len_respond: u32,
    map_field: u8,
    notify_path: [u8; 4],
) -> B32<Public> {
    let (request_id, request_id_val) =
        check_fresh_request(c, one, request, len_out, len_respond, map_field);
    insert_request(c, one, request, len_out, len_respond, map_field, &request_id_val);
    notify_signet(c, one, &request_id, notify_path);
    request_id
}

/// `withdrawRefundCommitment(sk, requestId)` —
/// `persistentHash<Vector<3, Bytes<32>>>([pad(32, "vault:refund:"), sk,
/// requestId])`.
fn withdraw_refund_commitment(
    c: &mut Circuit3,
    sk: &B32<Private>,
    request_id: &B32<Private>,
) -> B32<Private> {
    c.region("refund commitment hash", |c| {
        let pad = B32::pad(c, REFUND_PAD);
        let alignment = Alignment(vec![
            AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
            AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
            AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
        ]);
        let digest = c.persistent_hash(
            alignment,
            &[
                pad.hi.private().erase(),
                pad.lo.private().erase(),
                sk.hi.erase(),
                sk.lo.erase(),
                request_id.hi.erase(),
                request_id.lo.erase(),
            ],
        );
        B32::from_typed(c, digest)
    })
}

/// `export circuit withdraw(evmNonce: Uint<64>, keyVersion: Uint<8>,
/// withdrawRequest: WithdrawRequest, coin: ShieldedCoinInfo): []` —
/// Runtime step 1 of a withdrawal: burn the surrendered vault coin,
/// record `transfer(destEvmAddress, amount)` signed with the VAULT's
/// account under a contract-fixed gas envelope, pin the withdrawer's
/// refund commitment, and notify the MPC (withdraw.zkir; reads:
/// initialized, kernel.self ×5, evmChainId, signetRequestNonce, caip2Id,
/// member, signetSigner).
pub fn withdraw() -> Compiled3 {
    let mut c = Circuit3::new();
    let evm_nonce = c.arg::<FieldT>("evmNonce");
    let key_version = c.arg::<FieldT>("keyVersion");
    let erc20_address = c.arg::<FieldT>("withdrawRequest_erc20Address");
    let amount = c.arg::<FieldT>("withdrawRequest_amount");
    let dest_evm_address = c.arg::<FieldT>("withdrawRequest_destEvmAddress");
    let coin_nonce = B32 {
        hi: c.arg::<FieldT>("coin_nonce_hi"),
        lo: c.arg::<FieldT>("coin_nonce_lo"),
    };
    let coin_color = B32 {
        hi: c.arg::<FieldT>("coin_color_hi"),
        lo: c.arg::<FieldT>("coin_color_lo"),
    };
    let coin_value = c.arg::<FieldT>("coin_value");
    c.assert_bits(evm_nonce, 64);
    c.assert_bits(key_version, 8);
    c.assert_bits(erc20_address, 160);
    c.assert_bits(amount, 128);
    c.assert_bits(dest_evm_address, 160);
    coin_nonce.constrain_input(&mut c);
    coin_color.constrain_input(&mut c);
    c.assert_bits(coin_value, 128);

    let one = c.constant(1u64);
    let zero = c.constant(0u64);

    c.region("guards", |c| {
        assert_initialized(c, one);
        let erc20_zero = c.test_eq(erc20_address, zero.private());
        let erc20_nonzero = c.not(erc20_zero);
        c.assert(erc20_nonzero);
        let amount_positive = c.less_than(zero.private(), amount, 128);
        c.assert(amount_positive);
        let u64_max = c.constant(u64::MAX);
        let too_big = c.less_than(u64_max.private(), amount, 128);
        let fits = c.not(too_big);
        c.assert(fits);
    });

    // The coin must be the vault token for THIS erc20, of exactly amount.
    let erc20_address = c.disclose(erc20_address, "the withdrawn ERC20");
    let domain_sep = vault_token_domain_separator(&mut c, erc20_address);
    let me = kernel_self(&mut c, one);
    let me = B32 { hi: me[0], lo: me[1] };
    let color = minocrab_std::v3::token_type(&mut c, &domain_sep, &me);
    let color_hi_ok = c.test_eq(coin_color.hi, color.hi.private());
    let color_lo_ok = c.test_eq(coin_color.lo, color.lo.private());
    let color_ok = c.mul(color_hi_ok, color_lo_ok);
    c.assert(color_ok);
    let value_ok = c.test_eq(coin_value, amount);
    c.assert(value_ok);

    // Contract-enforced calldata: transfer(destEvmAddress, amount).
    let word0 = signet::evm_address_abi_word(&mut c, dest_evm_address);
    let word1 = signet::numeric_abi_word(&mut c, amount);
    let selector = c.constant(minocrab::Fr::from_le_bytes(&TRANSFER_SELECTOR).unwrap());
    let two = c.constant(2u64);
    let calldata = signet::EvmCalldata::<Private> {
        selector: selector.private(),
        no_words: two.private(),
        words: vec![word0, word1],
    };

    // Contract-FIXED gas envelope (the vault's account pays).
    let chain_id = cell_read(
        &mut c,
        one,
        EVM_CHAIN_ID,
        vec![AlignmentAtom::Bytes { length: 8 }],
    )[0];
    let priority_fee = c.constant(1_000_000_000u64);
    let max_fee = c.constant(30_000_000_000u64);
    let gas = c.constant(100_000u64);
    let tx_params = signet::EvmType2TxParams::<Private> {
        chain_id: chain_id.private(),
        nonce: evm_nonce,
        max_priority_fee_per_gas: priority_fee.private(),
        max_fee_per_gas: max_fee.private(),
        gas_limit: gas.private(),
        to: erc20_address.private(),
        value: zero.private(),
        calldata_is_some: one.private(),
        calldata,
        access_list_entry_count: zero.private(),
    };

    // The event, keyed under the vault's OWN derivation path.
    let request_nonce = counter_read(&mut c, one, SIGNET_REQUEST_NONCE);
    let sender = kernel_self(&mut c, one);
    let sender = B32 {
        hi: sender[0].private(),
        lo: sender[1].private(),
    };
    let caip2 = cell_read(
        &mut c,
        one,
        CAIP2_ID,
        vec![AlignmentAtom::Bytes { length: 32 }],
    );
    let caip2 = B32 {
        hi: caip2[0].private(),
        lo: caip2[1].private(),
    };
    let path = B32::pad(&mut c, VAULT_PATH);
    let path = B32::<Private> {
        hi: path.hi.private(),
        lo: path.lo.private(),
    };
    let schema = BytesN::<Private>::literal(&mut c, VAULT_RESPONSE_SCHEMA);
    let request = signet::construct_sign_bidirectional_event(
        &mut c,
        sender,
        request_nonce.private(),
        key_version,
        path,
        tx_params,
        caip2,
        schema.clone(),
        schema,
    );

    let (request_id, request_id_val) =
        check_fresh_request(&mut c, one, &request, 34, 34, SIGN_BIDIRECTIONAL_EVENT_MAP);

    // The surrendered value is BURNED: receiveShielded (custody) then
    // sendImmediateShielded to the burn address.
    let coin = minocrab_std::v3::ShieldedCoinInfo3 {
        nonce: B32 {
            hi: c.disclose(coin_nonce.hi, "surrendered coin nonce (hi)"),
            lo: c.disclose(coin_nonce.lo, "surrendered coin nonce (lo)"),
        },
        color: B32 {
            hi: c.disclose(coin_color.hi, "surrendered coin color (hi)"),
            lo: c.disclose(coin_color.lo, "surrendered coin color (lo)"),
        },
        value: c.disclose(coin_value, "surrendered coin value"),
    };
    common::receive_shielded(&mut c, one, &coin);
    common::burn_coin(&mut c, one, &coin);

    insert_request(
        &mut c,
        one,
        &request,
        34,
        34,
        SIGN_BIDIRECTIONAL_EVENT_MAP,
        &request_id_val,
    );

    // refundCommitment.insert(requestId,
    //   disclose(withdrawRefundCommitment(callerSecretKey(), requestId)))
    let sk = common::witness_sk(&mut c);
    let rid_priv = B32 {
        hi: request_id.hi.private(),
        lo: request_id.lo.private(),
    };
    let rc = withdraw_refund_commitment(&mut c, &sk, &rid_priv);
    let rc = B32 {
        hi: c.disclose(rc.hi, "withdrawer refund commitment (hi)"),
        lo: c.disclose(rc.lo, "withdrawer refund commitment (lo)"),
    };
    let rc_val = LedgerValue::bytes(32, vec![ImpactElem::Wire(rc.hi), ImpactElem::Wire(rc.lo)]);
    emit(
        &mut c,
        one,
        &map_insert(REFUND_COMMITMENT, &request_id_val, &rc_val),
    );

    notify_signet(&mut c, one, &request_id, [0, 0, 0, 0]);

    c.finish(true)
}

/// `export circuit swap(evmNonce: Uint<64>, keyVersion: Uint<8>,
/// swapRequest: SwapRequest, coin: ShieldedCoinInfo): []` — starts a swap
/// optimistically: burn the surrendered tokenIn coin (amountInMaximum)
/// and record `exactOutputSingle` on the pinned router, signed with the
/// VAULT's account (swap.zkir; reads: initialized, kernel.self,
/// vaultEvmAddress, evmChainId, uniswapRouter, signetRequestNonce,
/// kernel.self, caip2Id, member(11), kernel.self ×2, signetSigner,
/// kernel.self).
pub fn swap() -> Compiled3 {
    let mut c = Circuit3::new();
    let evm_nonce = c.arg::<FieldT>("evmNonce");
    let key_version = c.arg::<FieldT>("keyVersion");
    let token_in = c.arg::<FieldT>("swapRequest_tokenIn");
    let token_out = c.arg::<FieldT>("swapRequest_tokenOut");
    let fee = c.arg::<FieldT>("swapRequest_fee");
    let amount_out = c.arg::<FieldT>("swapRequest_amountOut");
    let amount_in_max = c.arg::<FieldT>("swapRequest_amountInMaximum");
    let coin_nonce = B32 {
        hi: c.arg::<FieldT>("coin_nonce_hi"),
        lo: c.arg::<FieldT>("coin_nonce_lo"),
    };
    let coin_color = B32 {
        hi: c.arg::<FieldT>("coin_color_hi"),
        lo: c.arg::<FieldT>("coin_color_lo"),
    };
    let coin_value = c.arg::<FieldT>("coin_value");
    c.assert_bits(evm_nonce, 64);
    c.assert_bits(key_version, 8);
    c.assert_bits(token_in, 160);
    c.assert_bits(token_out, 160);
    c.assert_bits(fee, 24);
    c.assert_bits(amount_out, 128);
    c.assert_bits(amount_in_max, 128);
    coin_nonce.constrain_input(&mut c);
    coin_color.constrain_input(&mut c);
    c.assert_bits(coin_value, 128);

    let one = c.constant(1u64);
    let zero = c.constant(0u64);

    c.region("guards", |c| {
        assert_initialized(c, one);
        let in_zero = c.test_eq(token_in, zero.private());
        let in_nonzero = c.not(in_zero);
        c.assert(in_nonzero);
        let out_zero = c.test_eq(token_out, zero.private());
        let out_nonzero = c.not(out_zero);
        c.assert(out_nonzero);
        let out_positive = c.less_than(zero.private(), amount_out, 128);
        c.assert(out_positive);
        let in_positive = c.less_than(zero.private(), amount_in_max, 128);
        c.assert(in_positive);
        let u64_max = c.constant(u64::MAX);
        let out_big = c.less_than(u64_max.private(), amount_out, 128);
        let out_fits = c.not(out_big);
        c.assert(out_fits);
        let in_big = c.less_than(u64_max.private(), amount_in_max, 128);
        let in_fits = c.not(in_big);
        c.assert(in_fits);
    });

    // The surrendered coin must be the vault token for tokenIn, of exactly
    // amountInMaximum.
    let token_in = c.disclose(token_in, "the sold ERC20");
    let domain_sep = vault_token_domain_separator(&mut c, token_in);
    let me = kernel_self(&mut c, one);
    let me = B32 { hi: me[0], lo: me[1] };
    let color = minocrab_std::v3::token_type(&mut c, &domain_sep, &me);
    let color_hi_ok = c.test_eq(coin_color.hi, color.hi.private());
    let color_lo_ok = c.test_eq(coin_color.lo, color.lo.private());
    let color_ok = c.mul(color_hi_ok, color_lo_ok);
    c.assert(color_ok);
    let value_ok = c.test_eq(coin_value, amount_in_max);
    c.assert(value_ok);

    // exactOutputSingle((tokenIn, tokenOut, fee, vault, amountOut,
    // amountInMaximum, 0)).
    let token_out = c.disclose(token_out, "the bought ERC20");
    let word0 = signet::evm_address_abi_word(&mut c, token_in.private());
    let word1 = signet::evm_address_abi_word(&mut c, token_out.private());
    let word2 = signet::numeric_abi_word(&mut c, fee);
    let vault_evm = cell_read(
        &mut c,
        one,
        VAULT_EVM_ADDRESS,
        vec![AlignmentAtom::Bytes { length: 20 }],
    )[0];
    let word3 = signet::evm_address_abi_word(&mut c, vault_evm.private());
    let word4 = signet::numeric_abi_word(&mut c, amount_out);
    let word5 = signet::numeric_abi_word(&mut c, amount_in_max);
    let word6 = B32::<Private> {
        hi: zero.private(),
        lo: zero.private(),
    };
    let selector = c.constant(minocrab::Fr::from_le_bytes(&EXACT_OUTPUT_SINGLE_SELECTOR).unwrap());
    let seven = c.constant(7u64);
    let calldata = signet::EvmCalldata::<Private> {
        selector: selector.private(),
        no_words: seven.private(),
        words: vec![word0, word1, word2, word3, word4, word5, word6],
    };

    // Contract-FIXED gas envelope; to = the pinned router.
    let chain_id = cell_read(
        &mut c,
        one,
        EVM_CHAIN_ID,
        vec![AlignmentAtom::Bytes { length: 8 }],
    )[0];
    let router = cell_read(
        &mut c,
        one,
        UNISWAP_ROUTER,
        vec![AlignmentAtom::Bytes { length: 20 }],
    )[0];
    let priority_fee = c.constant(1_000_000_000u64);
    let max_fee = c.constant(30_000_000_000u64);
    let gas = c.constant(700_000u64);
    let tx_params = signet::EvmType2TxParams::<Private> {
        chain_id: chain_id.private(),
        nonce: evm_nonce,
        max_priority_fee_per_gas: priority_fee.private(),
        max_fee_per_gas: max_fee.private(),
        gas_limit: gas.private(),
        to: router.private(),
        value: zero.private(),
        calldata_is_some: one.private(),
        calldata,
        access_list_entry_count: zero.private(),
    };

    let request_nonce = counter_read(&mut c, one, SIGNET_REQUEST_NONCE);
    let sender = kernel_self(&mut c, one);
    let sender = B32 {
        hi: sender[0].private(),
        lo: sender[1].private(),
    };
    let caip2 = cell_read(
        &mut c,
        one,
        CAIP2_ID,
        vec![AlignmentAtom::Bytes { length: 32 }],
    );
    let caip2 = B32 {
        hi: caip2[0].private(),
        lo: caip2[1].private(),
    };
    let path = B32::pad(&mut c, VAULT_PATH);
    let path = B32::<Private> {
        hi: path.hi.private(),
        lo: path.lo.private(),
    };
    let output_schema = BytesN::<Private>::literal(&mut c, SWAP_OUTPUT_SCHEMA);
    let respond_schema = BytesN::<Private>::literal(&mut c, SWAP_RESPOND_SCHEMA);
    let request = signet::construct_sign_bidirectional_event(
        &mut c,
        sender,
        request_nonce.private(),
        key_version,
        path,
        tx_params,
        caip2,
        output_schema,
        respond_schema,
    );

    let (request_id, request_id_val) =
        check_fresh_request(&mut c, one, &request, 38, 37, SWAP_EVENT_MAP);

    // Burn the surrendered amountInMaximum of tokenIn.
    let coin = minocrab_std::v3::ShieldedCoinInfo3 {
        nonce: B32 {
            hi: c.disclose(coin_nonce.hi, "surrendered coin nonce (hi)"),
            lo: c.disclose(coin_nonce.lo, "surrendered coin nonce (lo)"),
        },
        color: B32 {
            hi: c.disclose(coin_color.hi, "surrendered coin color (hi)"),
            lo: c.disclose(coin_color.lo, "surrendered coin color (lo)"),
        },
        value: c.disclose(coin_value, "surrendered coin value"),
    };
    common::receive_shielded(&mut c, one, &coin);
    common::burn_coin(&mut c, one, &coin);

    insert_request(&mut c, one, &request, 38, 37, SWAP_EVENT_MAP, &request_id_val);

    // swapRefundCommitment.insert(requestId, disclose(...))
    let sk = common::witness_sk(&mut c);
    let rid_priv = B32 {
        hi: request_id.hi.private(),
        lo: request_id.lo.private(),
    };
    let rc = withdraw_refund_commitment(&mut c, &sk, &rid_priv);
    let rc = B32 {
        hi: c.disclose(rc.hi, "swapper refund commitment (hi)"),
        lo: c.disclose(rc.lo, "swapper refund commitment (lo)"),
    };
    let rc_val = LedgerValue::bytes(32, vec![ImpactElem::Wire(rc.hi), ImpactElem::Wire(rc.lo)]);
    emit(
        &mut c,
        one,
        &map_insert(SWAP_REFUND_COMMITMENT, &request_id_val, &rc_val),
    );

    notify_signet(&mut c, one, &request_id, [11, 0, 0, 0]);

    c.finish(true)
}

/// `export circuit approveRouter(erc20Address: Bytes<20>, evmNonce:
/// Uint<64>, keyVersion: Uint<8>): []` — records
/// `approve(uniswapRouter, 2^128−1)` on the ERC20, signed with the
/// VAULT's account (path "vault"), contract-fixed gas envelope
/// (approveRouter.zkir; reads: initialized, uniswapRouter, evmChainId,
/// signetRequestNonce, kernel.self, caip2Id, member, signer, self).
pub fn approve_router() -> Compiled3 {
    let mut c = Circuit3::new();
    let erc20_address = c.arg::<FieldT>("erc20Address");
    let evm_nonce = c.arg::<FieldT>("evmNonce");
    let key_version = c.arg::<FieldT>("keyVersion");
    c.assert_bits(erc20_address, 160);
    c.assert_bits(evm_nonce, 64);
    c.assert_bits(key_version, 8);

    let one = c.constant(1u64);
    let zero = c.constant(0u64);

    c.region("guards", |c| {
        assert_initialized(c, one);
        let erc20_zero = c.test_eq(erc20_address, zero.private());
        let erc20_nonzero = c.not(erc20_zero);
        c.assert(erc20_nonzero);
    });

    // approve(uniswapRouter, 2^128−1): the spender is the pinned router.
    let router = cell_read(
        &mut c,
        one,
        UNISWAP_ROUTER,
        vec![AlignmentAtom::Bytes { length: 20 }],
    )[0];
    let word0 = signet::evm_address_abi_word(&mut c, router.private());
    // numericAbiWord(2^128−1): 16 zero bytes then 16 0xff bytes.
    let mut max_word = [0u8; 32];
    max_word[16..].copy_from_slice(&[0xff; 16]);
    let word1 = B32::<Private> {
        hi: c.constant(minocrab::Fr::from(u64::from(max_word[31]))).private(),
        lo: c
            .constant(minocrab::Fr::from_le_bytes(&max_word[..31]).unwrap())
            .private(),
    };
    let selector = c.constant(minocrab::Fr::from_le_bytes(&APPROVE_SELECTOR).unwrap());
    let two = c.constant(2u64);
    let calldata = signet::EvmCalldata::<Private> {
        selector: selector.private(),
        no_words: two.private(),
        words: vec![word0, word1],
    };

    // Contract-FIXED gas envelope; `to` is the (disclosed) ERC20 itself.
    let chain_id = cell_read(
        &mut c,
        one,
        EVM_CHAIN_ID,
        vec![AlignmentAtom::Bytes { length: 8 }],
    )[0];
    let priority_fee = c.constant(1_000_000_000u64);
    let max_fee = c.constant(30_000_000_000u64);
    let gas = c.constant(100_000u64);
    let erc20_address = c.disclose(erc20_address, "the approved ERC20");
    let tx_params = signet::EvmType2TxParams::<Private> {
        chain_id: chain_id.private(),
        nonce: evm_nonce,
        max_priority_fee_per_gas: priority_fee.private(),
        max_fee_per_gas: max_fee.private(),
        gas_limit: gas.private(),
        to: erc20_address.private(),
        value: zero.private(),
        calldata_is_some: one.private(),
        calldata,
        access_list_entry_count: zero.private(),
    };

    // Signed by the VAULT account: path = pad(32, "vault").
    let request_nonce = counter_read(&mut c, one, SIGNET_REQUEST_NONCE);
    let sender = kernel_self(&mut c, one);
    let sender = B32 {
        hi: sender[0].private(),
        lo: sender[1].private(),
    };
    let caip2 = cell_read(
        &mut c,
        one,
        CAIP2_ID,
        vec![AlignmentAtom::Bytes { length: 32 }],
    );
    let caip2 = B32 {
        hi: caip2[0].private(),
        lo: caip2[1].private(),
    };
    let path = B32::pad(&mut c, VAULT_PATH);
    let path = B32::<Private> {
        hi: path.hi.private(),
        lo: path.lo.private(),
    };
    let schema = BytesN::<Private>::literal(&mut c, VAULT_RESPONSE_SCHEMA);
    let request = signet::construct_sign_bidirectional_event(
        &mut c,
        sender,
        request_nonce.private(),
        key_version,
        path,
        tx_params,
        caip2,
        schema.clone(),
        schema,
    );

    record_and_notify(&mut c, one, &request, 34, 34, SIGN_BIDIRECTIONAL_EVENT_MAP, [0, 0, 0, 0]);

    c.finish(true)
}

/// `vaultTokenDomainSeparator(erc20Address)` —
/// `persistentHash<Vector<2, Bytes<32>>>([pad(32, "erc20:vault:"),
/// erc20Address as Field as Bytes<32>])`. The address is a `Bytes<20>`
/// limb, so its `Bytes<32>` rendering is `[hi: 0, lo: addr]`.
fn vault_token_domain_separator(
    c: &mut Circuit3,
    erc20_address: Wire3<FieldT, Public>,
) -> B32<Public> {
    c.region("token domain separator", |c| {
        let pad = B32::pad(c, TOKEN_PAD);
        let zero = c.constant(0u64);
        let alignment = Alignment(vec![
            AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
            AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
        ]);
        let digest = c.persistent_hash(
            alignment,
            &[
                pad.hi.erase(),
                pad.lo.erase(),
                zero.erase(),
                erc20_address.erase(),
            ],
        );
        B32::from_typed(c, digest)
    })
}

/// The shared argument block of the settle circuits: requestId, the
/// attestation event, and the mint nonce; `serializedOutput` is declared
/// by the caller (its width differs per circuit).
struct SettleArgs {
    request_id: B32<Private>,
    big_r_x: B32<Private>,
    sig_s: B32<Private>,
    mint_nonce: B32<Private>,
}

/// Declare + constrain the settle argument block around a caller-declared
/// `serializedOutput`; `declare_output` runs between the event and
/// mintNonce declarations to keep source argument order.
fn settle_args<F>(c: &mut Circuit3, declare_output: F) -> (SettleArgs, Vec<Wire3<FieldT, Private>>)
where
    F: FnOnce(&mut Circuit3) -> Vec<Wire3<FieldT, Private>>,
{
    let request_id = B32 {
        hi: c.arg::<FieldT>("requestId_hi"),
        lo: c.arg::<FieldT>("requestId_lo"),
    };
    let big_r_x = B32 {
        hi: c.arg::<FieldT>("respond_bigR_x_hi"),
        lo: c.arg::<FieldT>("respond_bigR_x_lo"),
    };
    let big_r_y = B32 {
        hi: c.arg::<FieldT>("respond_bigR_y_hi"),
        lo: c.arg::<FieldT>("respond_bigR_y_lo"),
    };
    let sig_s = B32 {
        hi: c.arg::<FieldT>("respond_s_hi"),
        lo: c.arg::<FieldT>("respond_s_lo"),
    };
    let recovery_id = c.arg::<FieldT>("respond_recoveryId");
    let output = declare_output(c);
    let mint_nonce = B32 {
        hi: c.arg::<FieldT>("mintNonce_hi"),
        lo: c.arg::<FieldT>("mintNonce_lo"),
    };
    request_id.constrain_input(c);
    big_r_x.constrain_input(c);
    big_r_y.constrain_input(c);
    sig_s.constrain_input(c);
    c.assert_bits(recovery_id, 8);
    mint_nonce.constrain_input(c);
    (
        SettleArgs {
            request_id,
            big_r_x,
            sig_s,
            mint_nonce,
        },
        output,
    )
}

/// The settle circuits' shared preamble: disclose the request id, gate on
/// initialization, and verify the MPC attestation over the presented
/// output. Returns the disclosed id.
fn verify_attestation(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    args: &SettleArgs,
    output_limbs: &[Wire3<FieldT, Private>],
    len_output: u32,
) -> B32<Public> {
    let request_id = B32 {
        hi: c.disclose(args.request_id.hi, "settle request id (hi)"),
        lo: c.disclose(args.request_id.lo, "settle request id (lo)"),
    };
    assert_initialized(c, one);
    let mpc_key = common::cell_read_point(c, one, MPC_RESPONSE_KEY);
    let rid_priv = B32 {
        hi: request_id.hi.private(),
        lo: request_id.lo.private(),
    };
    let valid = signet::verify_respond_bidirectional_event(
        c,
        &rid_priv,
        output_limbs,
        len_output,
        &args.big_r_x,
        &args.sig_s,
        mpc_key.private(),
    );
    c.assert(valid);
    request_id
}

/// `refundSurrenderedValue(disclosedRequestId, signatureRequest,
/// mintNonce)` under the branch guard (completeWithdraw.zkir:286-512):
/// the withdrawer gate (guarded sk witnesses vs the guarded
/// refundCommitment.lookup), the calldata reads, and the guarded re-mint
/// to `left(ownPublicKey())`.
fn refund_surrendered_value(
    c: &mut Circuit3,
    guard: Wire3<FieldT, Public>,
    request_id: &B32<Public>,
    request_id_val: &LedgerValue,
    ev: &[Wire3<FieldT, Public>],
    mint_nonce: &B32<Public>,
) {
    // assert(withdrawRefundCommitment(callerSecretKey(), requestId)
    //   == refundCommitment.lookup(requestId), "Not the withdrawer")
    c.region("withdrawer gate", |c| {
        let sk = common::witness_sk_guarded(c, guard);
        let rid_priv = B32 {
            hi: request_id.hi.private(),
            lo: request_id.lo.private(),
        };
        let rc = withdraw_refund_commitment(c, &sk, &rid_priv);
        let stored = minocrab_ledger::map_lookup_guarded(
            c,
            guard,
            REFUND_COMMITMENT,
            request_id_val,
            vec![AlignmentAtom::Bytes { length: 32 }],
        );
        let eq_hi = c.test_eq(rc.hi, stored[0].private());
        let eq_lo = c.test_eq(rc.lo, stored[1].private());
        let is_withdrawer = c.mul(eq_hi, eq_lo);
        common::assert_if(c, guard.private(), is_withdrawer);
    });

    // assert(signatureRequest.txParams.calldata.is_some)
    common::assert_if(c, guard, ev[signet::event_limb::CALLDATA_IS_SOME]);

    // const amount = abiWordToUint128(calldata.words[1])
    let word1 = B32 {
        hi: ev[signet::event_limb::word_hi(1)],
        lo: ev[signet::event_limb::word_lo(1)],
    };
    let amount = signet::abi_word_to_uint128_guarded(c, guard, &word1);

    // Re-mint to the withdrawer's own wallet key.
    let domain_sep = vault_token_domain_separator(c, ev[signet::event_limb::TO]);
    let own_pk = minocrab_std::v3::own_public_key_guarded(c, guard);
    let own_pk = B32 {
        hi: c.disclose(own_pk.hi, "own public key as refund recipient (hi)"),
        lo: c.disclose(own_pk.lo, "own public key as refund recipient (lo)"),
    };
    common::mint_shielded_token_to_key_guarded(c, guard, &domain_sep, amount, mint_nonce, &own_pk);
}

/// `export circuit completeWithdraw(requestId, respondBidirectionalEvent,
/// serializedOutput: Bytes<1>, mintNonce): []` — Runtime step 5 of a
/// withdrawal that EXECUTED: verify the attestation, consume the pending
/// withdrawal, and on an attested `false` return re-mint the surrendered
/// value to the withdrawer (completeWithdraw.zkir; reads: initialized,
/// mpcResponseKey, refundCommitment member, event lookup, then the
/// guarded branch's refundCommitment lookup + kernel.self).
pub fn complete_withdraw() -> Compiled3 {
    let mut c = Circuit3::new();
    let (args, output) = settle_args(&mut c, |c| {
        let w = c.arg::<FieldT>("serializedOutput");
        vec![w]
    });
    c.assert_bits(output[0], 8);

    let one = c.constant(1u64);

    let request_id = verify_attestation(&mut c, one, &args, &output, 1);
    let request_id_val = LedgerValue::bytes(
        32,
        vec![
            ImpactElem::Wire(request_id.hi),
            ImpactElem::Wire(request_id.lo),
        ],
    );

    // assert(refundCommitment.member(requestId), "Withdrawal not found")
    // const signatureRequest = signBidirectionalEventMap.lookup(requestId);
    // signBidirectionalEventMap.remove(requestId)
    let ev = c.region("event map consume", |c| {
        let pending = map_member(c, one, REFUND_COMMITMENT, &request_id_val);
        c.assert(pending);
        let ev = map_lookup(
            c,
            one,
            SIGN_BIDIRECTIONAL_EVENT_MAP,
            &request_id_val,
            signet::event_atoms(2, 34, 34),
        );
        emit(
            c,
            one,
            &map_remove(SIGN_BIDIRECTIONAL_EVENT_MAP, &request_id_val),
        );
        ev
    });

    // const succeeded = disclose(deserialize<VaultResponse, 1>(output).success)
    let succeeded = c.test_eq(output[0], one.private());
    let succeeded = c.disclose(succeeded, "withdrawal EVM outcome");

    // if (!succeeded) { refundSurrenderedValue(...) }
    let refunding = c.not(succeeded);
    let mint_nonce = B32 {
        hi: c.disclose(args.mint_nonce.hi, "refund mint nonce (hi)"),
        lo: c.disclose(args.mint_nonce.lo, "refund mint nonce (lo)"),
    };
    refund_surrendered_value(
        &mut c,
        refunding,
        &request_id,
        &request_id_val,
        &ev,
        &mint_nonce,
    );

    // refundCommitment.remove(requestId)
    emit(&mut c, one, &map_remove(REFUND_COMMITMENT, &request_id_val));

    c.finish(true)
}

/// `export circuit completeSwap(requestId, respondBidirectionalEvent,
/// serializedOutput: Bytes<8>, mintNonce): []` — settles a SUCCESSFUL
/// swap: verify the attested amountIn, consume the pending swap
/// (swapper-only), mint the exact amountOut of tokenOut plus the unspent
/// tokenIn as change (completeSwap.zkir; reads: initialized,
/// mpcResponseKey, member(12), lookup(11), lookup(12), kernel.self ×2).
pub fn complete_swap() -> Compiled3 {
    let mut c = Circuit3::new();
    let (args, output) = settle_args(&mut c, |c| {
        let w = c.arg::<FieldT>("serializedOutput");
        vec![w]
    });
    c.assert_bits(output[0], 64);

    let one = c.constant(1u64);

    let request_id = verify_attestation(&mut c, one, &args, &output, 8);
    let request_id_val = LedgerValue::bytes(
        32,
        vec![
            ImpactElem::Wire(request_id.hi),
            ImpactElem::Wire(request_id.lo),
        ],
    );

    // assert(swapRefundCommitment.member(requestId), "Swap not found")
    // const signatureRequest = swapEventMap.lookup(requestId); remove.
    let ev = c.region("event map consume", |c| {
        let pending = map_member(c, one, SWAP_REFUND_COMMITMENT, &request_id_val);
        c.assert(pending);
        let ev = map_lookup(
            c,
            one,
            SWAP_EVENT_MAP,
            &request_id_val,
            signet::event_atoms(7, 38, 37),
        );
        emit(c, one, &map_remove(SWAP_EVENT_MAP, &request_id_val));
        ev
    });

    // Swapper gate.
    c.region("swapper gate", |c| {
        let sk = common::witness_sk(c);
        let rid_priv = B32 {
            hi: request_id.hi.private(),
            lo: request_id.lo.private(),
        };
        let rc = withdraw_refund_commitment(c, &sk, &rid_priv);
        let stored = map_lookup(
            c,
            one,
            SWAP_REFUND_COMMITMENT,
            &request_id_val,
            vec![AlignmentAtom::Bytes { length: 32 }],
        );
        let eq_hi = c.test_eq(rc.hi, stored[0].private());
        let eq_lo = c.test_eq(rc.lo, stored[1].private());
        let is_swapper = c.mul(eq_hi, eq_lo);
        c.assert(is_swapper);
        emit(c, one, &map_remove(SWAP_REFUND_COMMITMENT, &request_id_val));
    });

    // assert(signatureRequest.txParams.calldata.is_some)
    c.assert(ev[signet::event_limb::CALLDATA_IS_SOME]);
    let recipient = minocrab_std::v3::own_public_key(&mut c);
    let recipient = B32 {
        hi: c.disclose(recipient.hi, "own public key as swap recipient (hi)"),
        lo: c.disclose(recipient.lo, "own public key as swap recipient (lo)"),
    };

    // Mint the EXACT amountOut of tokenOut: word 4 of tokenOut (word 1).
    let word4 = B32 {
        hi: ev[signet::event_limb::word_hi(4)],
        lo: ev[signet::event_limb::word_lo(4)],
    };
    let amount_out = signet::abi_word_to_uint128(&mut c, &word4);
    let word1 = B32 {
        hi: ev[signet::event_limb::word_hi(1)],
        lo: ev[signet::event_limb::word_lo(1)],
    };
    let token_out = signet::abi_word_low20(&mut c, &word1);
    let ds_out = vault_token_domain_separator(&mut c, token_out);
    let mint_nonce = B32 {
        hi: c.disclose(args.mint_nonce.hi, "swap mint nonce (hi)"),
        lo: c.disclose(args.mint_nonce.lo, "swap mint nonce (lo)"),
    };
    common::mint_shielded_token_to_key(&mut c, one, &ds_out, amount_out, &mint_nonce, &recipient);

    // Change: amountInMaximum (word 5) − attested amountIn, of tokenIn
    // (word 0), under a nonce derived from mintNonce.
    let amount_in = c.disclose(output[0], "attested amountIn spent");
    let word5 = B32 {
        hi: ev[signet::event_limb::word_hi(5)],
        lo: ev[signet::event_limb::word_lo(5)],
    };
    let amount_in_max = signet::abi_word_to_uint128(&mut c, &word5);
    let overspent = c.less_than(amount_in_max, amount_in, 128);
    let ok = c.not(overspent);
    c.assert(ok);
    let neg_in = c.neg(amount_in);
    let change = c.add(amount_in_max, neg_in);
    let word0 = B32 {
        hi: ev[signet::event_limb::word_hi(0)],
        lo: ev[signet::event_limb::word_lo(0)],
    };
    let token_in = signet::abi_word_low20(&mut c, &word0);
    let ds_in = vault_token_domain_separator(&mut c, token_in);
    // changeNonce = persistentHash([mintNonce, pad(32, "change")])
    let change_pad = B32::pad(&mut c, "change");
    let alignment = Alignment(vec![
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
    ]);
    let change_nonce = c.persistent_hash(
        alignment,
        &[
            mint_nonce.hi.erase(),
            mint_nonce.lo.erase(),
            change_pad.hi.erase(),
            change_pad.lo.erase(),
        ],
    );
    let change_nonce = B32::from_typed(&mut c, change_nonce);
    common::mint_shielded_token_to_key(&mut c, one, &ds_in, change, &change_nonce, &recipient);

    c.finish(true)
}

/// The MPC's fixed failure output: 0xdeadbeef ‖ 0x01, 5 bytes.
pub const MPC_FAILURE_OUTPUT: [u8; 5] = [0xde, 0xad, 0xbe, 0xef, 0x01];

/// `export circuit refund(requestId, respondBidirectionalEvent,
/// serializedOutput: Bytes<5>, mintNonce): []` — settles a withdrawal OR
/// swap whose transaction NEVER EXECUTED (the MPC attested the fixed
/// 5-byte failure output), routing on which pending marker holds the id:
/// the withdrawal branch re-runs refundSurrenderedValue, the swap branch
/// re-mints the surrendered amountInMaximum of tokenIn to the swapper
/// (refund.zkir; both branches fully guarded, complementary guards).
pub fn refund() -> Compiled3 {
    let mut c = Circuit3::new();
    let (args, output) = settle_args(&mut c, |c| {
        let w = c.arg::<FieldT>("serializedOutput");
        vec![w]
    });
    c.assert_bits(output[0], 40);

    let one = c.constant(1u64);

    let request_id = verify_attestation(&mut c, one, &args, &output, 5);
    let request_id_val = LedgerValue::bytes(
        32,
        vec![
            ImpactElem::Wire(request_id.hi),
            ImpactElem::Wire(request_id.lo),
        ],
    );

    // assert(serializedOutput == 0xdeadbeef01, "Not the MPC failure output")
    let failure = c.constant(minocrab::Fr::from_le_bytes(&MPC_FAILURE_OUTPUT).unwrap());
    let is_failure = c.test_eq(output[0], failure.private());
    c.assert(is_failure);

    // Route on which pending marker holds the id (public branch).
    // The member result is already Public; disclosure is the source's
    // explicit `disclose(...)` on the branch condition, a no-op here.
    let is_withdrawal = map_member(&mut c, one, REFUND_COMMITMENT, &request_id_val);
    let mint_nonce = B32 {
        hi: c.disclose(args.mint_nonce.hi, "refund mint nonce (hi)"),
        lo: c.disclose(args.mint_nonce.lo, "refund mint nonce (lo)"),
    };

    // Withdrawal branch: completeWithdraw's failure path verbatim.
    let ev = c.region("event map consume", |c| {
        let ev = minocrab_ledger::map_lookup_guarded(
            c,
            is_withdrawal,
            SIGN_BIDIRECTIONAL_EVENT_MAP,
            &request_id_val,
            signet::event_atoms(2, 34, 34),
        );
        emit(
            c,
            is_withdrawal,
            &map_remove(SIGN_BIDIRECTIONAL_EVENT_MAP, &request_id_val),
        );
        ev
    });
    refund_surrendered_value(
        &mut c,
        is_withdrawal,
        &request_id,
        &request_id_val,
        &ev,
        &mint_nonce,
    );
    emit(
        &mut c,
        is_withdrawal,
        &map_remove(REFUND_COMMITMENT, &request_id_val),
    );

    // Swap branch: re-mint the surrendered amountInMaximum of tokenIn.
    let swapping = c.not(is_withdrawal);
    let ev7 = c.region("event map consume", |c| {
        let swap_pending = minocrab_ledger::map_member_guarded(
            c,
            swapping,
            SWAP_REFUND_COMMITMENT,
            &request_id_val,
        );
        common::assert_if(c, swapping, swap_pending);
        let ev7 = minocrab_ledger::map_lookup_guarded(
            c,
            swapping,
            SWAP_EVENT_MAP,
            &request_id_val,
            signet::event_atoms(7, 38, 37),
        );
        emit(
            c,
            swapping,
            &map_remove(SWAP_EVENT_MAP, &request_id_val),
        );
        ev7
    });
    c.region("swapper gate", |c| {
        let sk = common::witness_sk_guarded(c, swapping);
        let rid_priv = B32 {
            hi: request_id.hi.private(),
            lo: request_id.lo.private(),
        };
        let rc = withdraw_refund_commitment(c, &sk, &rid_priv);
        let stored = minocrab_ledger::map_lookup_guarded(
            c,
            swapping,
            SWAP_REFUND_COMMITMENT,
            &request_id_val,
            vec![AlignmentAtom::Bytes { length: 32 }],
        );
        let eq_hi = c.test_eq(rc.hi, stored[0].private());
        let eq_lo = c.test_eq(rc.lo, stored[1].private());
        let is_swapper = c.mul(eq_hi, eq_lo);
        common::assert_if(c, swapping.private(), is_swapper);
        emit(
            c,
            swapping,
            &map_remove(SWAP_REFUND_COMMITMENT, &request_id_val),
        );
    });
    common::assert_if(&mut c, swapping, ev7[signet::event_limb::CALLDATA_IS_SOME]);
    let word5 = B32 {
        hi: ev7[signet::event_limb::word_hi(5)],
        lo: ev7[signet::event_limb::word_lo(5)],
    };
    let amount_in_max = signet::abi_word_to_uint128_guarded(&mut c, swapping, &word5);
    let word0 = B32 {
        hi: ev7[signet::event_limb::word_hi(0)],
        lo: ev7[signet::event_limb::word_lo(0)],
    };
    let token_in = signet::abi_word_low20(&mut c, &word0);
    let ds_in = vault_token_domain_separator(&mut c, token_in);
    let own_pk = minocrab_std::v3::own_public_key_guarded(&mut c, swapping);
    let own_pk = B32 {
        hi: c.disclose(own_pk.hi, "own public key as swap-refund recipient (hi)"),
        lo: c.disclose(own_pk.lo, "own public key as swap-refund recipient (lo)"),
    };
    common::mint_shielded_token_to_key_guarded(
        &mut c,
        swapping,
        &ds_in,
        amount_in_max,
        &mint_nonce,
        &own_pk,
    );

    c.finish(true)
}

/// `export circuit claim(requestId: RequestId, respondBidirectionalEvent:
/// RespondBidirectionalEvent, serializedOutput: Bytes<1>, mintNonce:
/// Bytes<32>, recipient: Maybe<Either<ZswapCoinPublicKey,
/// ContractAddress>>): []` — Runtime step 5 of a deposit: verify the
/// MPC's attestation over the presented output, consume the stored
/// request (depositor-only), and mint the deposited amount as shielded
/// vault tokens (claim.zkir; reads: initialized, mpcResponseKey, map
/// member, map lookup, kernel.self, then the auto-receive branch's
/// guarded kernel.self).
pub fn claim() -> Compiled3 {
    let mut c = Circuit3::new();
    let request_id = B32 {
        hi: c.arg::<FieldT>("requestId_hi"),
        lo: c.arg::<FieldT>("requestId_lo"),
    };
    let big_r_x = B32 {
        hi: c.arg::<FieldT>("respond_bigR_x_hi"),
        lo: c.arg::<FieldT>("respond_bigR_x_lo"),
    };
    let big_r_y = B32 {
        hi: c.arg::<FieldT>("respond_bigR_y_hi"),
        lo: c.arg::<FieldT>("respond_bigR_y_lo"),
    };
    let sig_s = B32 {
        hi: c.arg::<FieldT>("respond_s_hi"),
        lo: c.arg::<FieldT>("respond_s_lo"),
    };
    let recovery_id = c.arg::<FieldT>("respond_recoveryId");
    let serialized_output = c.arg::<FieldT>("serializedOutput");
    let mint_nonce = B32 {
        hi: c.arg::<FieldT>("mintNonce_hi"),
        lo: c.arg::<FieldT>("mintNonce_lo"),
    };
    let rec_is_some = c.arg::<FieldT>("recipient_is_some");
    let rec_is_left = c.arg::<FieldT>("recipient_is_left");
    let rec_left = B32 {
        hi: c.arg::<FieldT>("recipient_left_hi"),
        lo: c.arg::<FieldT>("recipient_left_lo"),
    };
    let rec_right = B32 {
        hi: c.arg::<FieldT>("recipient_right_hi"),
        lo: c.arg::<FieldT>("recipient_right_lo"),
    };
    request_id.constrain_input(&mut c);
    big_r_x.constrain_input(&mut c);
    big_r_y.constrain_input(&mut c);
    sig_s.constrain_input(&mut c);
    c.assert_bits(recovery_id, 8);
    c.assert_bits(serialized_output, 8);
    mint_nonce.constrain_input(&mut c);
    c.assert_boolean(rec_is_some);
    c.assert_boolean(rec_is_left);
    rec_left.constrain_input(&mut c);
    rec_right.constrain_input(&mut c);

    let one = c.constant(1u64);
    let zero = c.constant(0u64);

    // const disclosedRequestId = disclose(requestId)
    let request_id = B32 {
        hi: c.disclose(request_id.hi, "claim request id (hi)"),
        lo: c.disclose(request_id.lo, "claim request id (lo)"),
    };

    // assert(initialized >= 1, "Not initialized")
    assert_initialized(&mut c, one);

    // const response = deserialize<VaultResponse, 1>(serializedOutput);
    // assert(response.success) — the packed Boolean is (byte == 1).
    let success = c.test_eq(serialized_output, one.private());
    c.assert(success);

    // assert(verifyRespondBidirectionalEvent<1>(requestId,
    //   serializedOutput, event, mpcResponseKey))
    let mpc_key = common::cell_read_point(&mut c, one, MPC_RESPONSE_KEY);
    let rid_priv = B32 {
        hi: request_id.hi.private(),
        lo: request_id.lo.private(),
    };
    let valid = signet::verify_respond_bidirectional_event(
        &mut c,
        &rid_priv,
        &[serialized_output],
        1,
        &big_r_x,
        &sig_s,
        mpc_key.private(),
    );
    c.assert(valid);

    // Double-claim protection: member + lookup + remove.
    let request_id_val = LedgerValue::bytes(
        32,
        vec![
            ImpactElem::Wire(request_id.hi),
            ImpactElem::Wire(request_id.lo),
        ],
    );
    let ev = c.region("event map consume", |c| {
        let found = map_member(c, one, SIGN_BIDIRECTIONAL_EVENT_MAP, &request_id_val);
        c.assert(found);
        let ev = map_lookup(
            c,
            one,
            SIGN_BIDIRECTIONAL_EVENT_MAP,
            &request_id_val,
            signet::event_atoms(2, 34, 34),
        );
        emit(
            c,
            one,
            &map_remove(SIGN_BIDIRECTIONAL_EVENT_MAP, &request_id_val),
        );
        ev
    });

    // Depositor gate: userCommitment(callerSecretKey()) == request.path.
    c.region("depositor gate", |c| {
        let sk = common::witness_sk(c);
        let caller = common::commitment(c, USER_PAD, &sk);
        let eq_hi = c.test_eq(caller.hi, ev[signet::event_limb::PATH_HI].private());
        let eq_lo = c.test_eq(caller.lo, ev[signet::event_limb::PATH_LO].private());
        let is_depositor = c.mul(eq_hi, eq_lo);
        c.assert(is_depositor);
    });

    // assert(request.txParams.calldata.is_some)
    c.assert(ev[signet::event_limb::CALLDATA_IS_SOME]);

    // const amount = abiWordToUint128(calldata.words[1])
    let word1 = B32 {
        hi: ev[signet::event_limb::word_hi(1)],
        lo: ev[signet::event_limb::word_lo(1)],
    };
    let amount = signet::abi_word_to_uint128(&mut c, &word1);

    // const domainSep = vaultTokenDomainSeparator(request.txParams.to)
    let domain_sep = vault_token_domain_separator(&mut c, ev[signet::event_limb::TO]);

    // const claimRecipient = disclose(recipient).is_some
    //   ? disclose(recipient).value : left(ownPublicKey())
    let recipient = c.region("recipient select", |c| {
        let rec_is_some = c.disclose(rec_is_some, "claim recipient tag");
        let rec_is_left = c.disclose(rec_is_left, "claim recipient side");
        let not_some = c.not(rec_is_some);
        let own_pk = own_public_key_guarded(c, not_some);
        let own_pk = B32 {
            hi: c.disclose(own_pk.hi, "own public key as claim recipient (hi)"),
            lo: c.disclose(own_pk.lo, "own public key as claim recipient (lo)"),
        };
        let rec_left = B32 {
            hi: c.disclose(rec_left.hi, "claim recipient key (hi)"),
            lo: c.disclose(rec_left.lo, "claim recipient key (lo)"),
        };
        let rec_right = B32 {
            hi: c.disclose(rec_right.hi, "claim recipient contract (hi)"),
            lo: c.disclose(rec_right.lo, "claim recipient contract (lo)"),
        };
        let is_left = c.cond_select(rec_is_some, rec_is_left, one);
        let left = B32 {
            hi: c.cond_select(rec_is_some, rec_left.hi, own_pk.hi),
            lo: c.cond_select(rec_is_some, rec_left.lo, own_pk.lo),
        };
        let right = B32 {
            hi: c.cond_select(rec_is_some, rec_right.hi, zero),
            lo: c.cond_select(rec_is_some, rec_right.lo, zero),
        };
        CoinRecipient { is_left, left, right }
    });

    // mintShieldedToken(domainSep, amount as Uint<64>, disclose(mintNonce),
    //   claimRecipient)
    let mint_nonce = B32 {
        hi: c.disclose(mint_nonce.hi, "claim mint nonce (hi)"),
        lo: c.disclose(mint_nonce.lo, "claim mint nonce (lo)"),
    };
    common::mint_shielded_token(&mut c, one, &domain_sep, amount, &mint_nonce, &recipient);

    c.finish(true)
}
