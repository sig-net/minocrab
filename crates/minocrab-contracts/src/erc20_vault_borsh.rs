//! `erc20-vault`, BORSH (M11 §Phasing stage 4) — the third artifact.
//!
//! This module is a fork of [`crate::erc20_vault_opt`], not a variant of it,
//! and it stands to the optimized vault exactly as that one stands to the
//! direct ports: `erc20_vault` is the COMPATIBILITY reference (PI-equal to
//! compactc), `erc20_vault_opt` carries M10's measured row work and never
//! moves for M11, and everything M11 changes about the WIRE FORMAT lands
//! here. The chain of trust is one link longer: `compactc ≡ port ≡ opt ≡
//! borsh`, with `tests/erc20_vault_borsh_fork.rs` asserting the last link
//! circuit by circuit and `vault::artifact::borsh_fork_status` recording
//! where it has been deliberately cut.
//!
//! At the forking commit the nine circuits are BYTE-IDENTICAL to the
//! optimized fork, so the row and interface snapshots carry the same numbers
//! three times and the borsh artifact inherits, transitively, both of the
//! earlier links. Each later commit is a one-change diff.
//!
//! What is NOT copied, exactly as at M10's fork: the protocol-pinned
//! constants, the record types and the shared helpers (`common`, `signet`)
//! are IMPORTED, so the vault's wire contract and Compact's standard library
//! cannot drift between artifacts. Copied: the nine circuit functions and the
//! private helpers they call — including M10's, which is what makes this a
//! fork of the OPTIMIZED vault rather than of the port. Those copies are not
//! left to trust: while a circuit's `borsh_fork_status` entry says
//! `Identical` the fork test proves it is byte-identical ZKIR, so a helper
//! that drifted would fail the build.
//!
//! Deviations from the optimized fork, newest last (the deviation log; the
//! design and the safety argument for each is in notes/borsh-format.org):
//!
//! - (stage 4) none — byte-identical fork.
//!
//! M10's own deviations (from the direct port) are inherited verbatim and are
//! documented on [`crate::erc20_vault_opt`]: the deduplicated `kernel.self()`
//! read, the derived `changeNonce`, the encoded `vaultTokenDomainSeparator`,
//! the single-claimed-spend burn, the one-block `userCommitment` and the
//! Poseidon refund commitment.

use minocrab::v3::{Circuit3, Compiled3, FieldT, Secp256k1PointT, Wire3};
use minocrab::{AlignmentAtom, Private, Public};
use minocrab_ledger::{
    cell_read, cell_write, counter_increment, counter_read, contract_call, emit, kernel_self,
    map_insert, map_lookup, map_member, map_remove, ImpactElem, LedgerValue,
};
use minocrab_std::v3::{
    circuit, own_public_key_guarded, Bytes, BytesN, CircuitArg, CoinRecipient, Either, Maybe, Uint,
    B32,
};

use crate::common;
use crate::erc20_vault::{
    SwapEvent, SwapRecord, VaultEvent, VaultRecord, APPROVE_SELECTOR, CAIP2_ID, DEPLOYER,
    EVM_CHAIN_ID, EXACT_OUTPUT_SINGLE_SELECTOR, INITIALIZED, MPC_FAILURE_OUTPUT, MPC_RESPONSE_KEY,
    REFUND_COMMITMENT, REFUND_PAD, SIGNET_REQUEST_NONCE, SIGNET_SIGNER,
    SIGN_BIDIRECTIONAL_EVENT_MAP, SWAP_EVENT_MAP, SWAP_OUTPUT_LEN, SWAP_OUTPUT_SCHEMA,
    SWAP_REFUND_COMMITMENT, SWAP_RESPOND_LEN, SWAP_RESPOND_SCHEMA, SWAP_WORDS,
    TRANSFER_SELECTOR, UNISWAP_ROUTER, VAULT_EVM_ADDRESS, VAULT_PATH, VAULT_RESPONSE_SCHEMA,
    VAULT_SCHEMA_LEN, VAULT_WORDS,
};
use crate::signet;

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
    // — the SHORT one-block userCommitment (rung 5(i-userCommit), avenue 1).
    c.region("deployer gate", |c| {
        common::assert_deployer_short(c, one, DEPLOYER);
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

/// `struct DepositRequest { erc20Address: Bytes<20>, amount: Uint<128> }`
/// — the vault-specific arguments of a deposit. Field order is the wire
/// contract; the labels are `depositRequest_erc20Address` /
/// `depositRequest_amount`.
#[derive(CircuitArg)]
struct DepositRequest {
    erc20_address: Bytes<20>,
    amount: Uint<128>,
}

/// `export circuit deposit(evmNonce: Uint<64>, gasLimit: Uint<64>,
/// maxFeePerGas: Uint<128>, maxPriorityFeePerGas: Uint<128>, keyVersion:
/// Uint<8>, depositRequest: DepositRequest): []` — Runtime step 1 of a
/// deposit: record the `transfer(vaultEvmAddress, amount)` request under
/// the caller's identity commitment and notify the MPC through the Signet
/// singleton (deposit.zkir; the read order is the PI contract:
/// initialized, vaultEvmAddress, evmChainId, signetRequestNonce,
/// kernel.self, caip2Id, map member, signetSigner, kernel.self).
///
/// The parameters after `c` are the Compact parameter list, in declaration
/// order — which is the wire contract.
#[circuit]
pub fn deposit(
    c: &mut Circuit3,
    evm_nonce: Uint<64>,
    gas_limit: Uint<64>,
    max_fee_per_gas: Uint<128>,
    max_priority_fee_per_gas: Uint<128>,
    key_version: Uint<8>,
    deposit_request: DepositRequest,
) {
    let evm_nonce = evm_nonce.field();
    let gas_limit = gas_limit.field();
    let max_fee_per_gas = max_fee_per_gas.field();
    let max_priority_fee_per_gas = max_priority_fee_per_gas.field();
    let key_version = key_version.field();
    let erc20_address = deposit_request.erc20_address.field();
    let amount = deposit_request.amount.field();

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

    // const caller = disclose(userCommitment(callerSecretKey())) — the SHORT
    // one-block userCommitment (rung 5(i-userCommit), avenue 1).
    let sk = common::witness_sk(c);
    let caller_priv = common::commitment_short(c, &sk);
    let caller = B32 {
        hi: c.disclose(caller_priv.hi, "depositor identity commitment (hi)"),
        lo: c.disclose(caller_priv.lo, "depositor identity commitment (lo)"),
    };

    // Contract-enforced calldata: transfer(vaultEvmAddress, amount).
    let vault_evm = cell_read(
        c,
        one,
        VAULT_EVM_ADDRESS,
        vec![AlignmentAtom::Bytes { length: 20 }],
    )[0];
    let word0 = signet::evm_address_abi_word(c, vault_evm.private());
    let word1 = signet::numeric_abi_word(c, amount);
    let selector = c.constant(minocrab::Fr::from_le_bytes(&TRANSFER_SELECTOR).unwrap());
    let two = c.constant(2u64);
    let calldata = signet::EvmCalldata::<Private, VAULT_WORDS> {
        selector: selector.private(),
        no_words: two.private(),
        words: [word0, word1],
    };

    // The full transaction the MPC will sign.
    let chain_id = cell_read(
        c,
        one,
        EVM_CHAIN_ID,
        vec![AlignmentAtom::Bytes { length: 8 }],
    )[0];
    let tx_params = signet::EvmType2TxParams::<Private, VAULT_WORDS> {
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
    let request_nonce = counter_read(c, one, SIGNET_REQUEST_NONCE);
    // ONE kernel.self read: the event's sender and the notification's
    // callerAddress are the same address (rung i).
    let me = kernel_self(c, one);
    let me = B32 { hi: me[0], lo: me[1] };
    let sender = B32 {
        hi: me.hi.private(),
        lo: me.lo.private(),
    };
    let caip2 = cell_read(
        c,
        one,
        CAIP2_ID,
        vec![AlignmentAtom::Bytes { length: 32 }],
    );
    let caip2 = B32 {
        hi: caip2[0].private(),
        lo: caip2[1].private(),
    };
    let schema = BytesN::<Private, VAULT_SCHEMA_LEN>::literal(c, VAULT_RESPONSE_SCHEMA);
    let request: VaultEvent<Private> = signet::construct_sign_bidirectional_event(
        c,
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

    record_and_notify(c, one, me, &request, SIGN_BIDIRECTIONAL_EVENT_MAP, [0, 0, 0, 0]);
}

/// `requestId = disclose(calculateRequestId(request))` +
/// `assert(!map.member(requestId), "Request already exists")`. Returns the
/// disclosed id and its ledger-value form.
fn check_fresh_request<const WORDS: usize, const LEN_OUT: usize, const LEN_RESPOND: usize>(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    request: &signet::SignBidirectionalEvent<Private, WORDS, LEN_OUT, LEN_RESPOND>,
    map_field: u8,
) -> (B32<Public>, LedgerValue) {
    let request_id_priv = signet::calculate_request_id(c, request);
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
fn insert_request<const WORDS: usize, const LEN_OUT: usize, const LEN_RESPOND: usize>(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    request: &signet::SignBidirectionalEvent<Private, WORDS, LEN_OUT, LEN_RESPOND>,
    map_field: u8,
    request_id_val: &LedgerValue,
) {
    c.region("record: insert", |c| {
        emit(c, one, &counter_increment(SIGNET_REQUEST_NONCE, 1));
        let event_atoms =
            signet::SignBidirectionalEvent::<Private, WORDS, LEN_OUT, LEN_RESPOND>::atoms();
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
    me: B32<Public>,
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
        let (version, payload) = signet::construct_notification_v1::<Public>(c, &me, 1, notify_path);
        let mut args = vec![request_id.hi, request_id.lo, version];
        args.extend(payload.limbs().iter().copied());
        contract_call(c, one, [signer[0], signer[1]], &args, &[]);
    });
}

/// The contiguous tail deposit/approveRouter share: freshness check,
/// record, notify.
fn record_and_notify<const WORDS: usize, const LEN_OUT: usize, const LEN_RESPOND: usize>(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    me: B32<Public>,
    request: &signet::SignBidirectionalEvent<Private, WORDS, LEN_OUT, LEN_RESPOND>,
    map_field: u8,
    notify_path: [u8; 4],
) -> B32<Public> {
    let (request_id, request_id_val) = check_fresh_request(c, one, request, map_field);
    insert_request(c, one, request, map_field, &request_id_val);
    notify_signet(c, one, me, &request_id, notify_path);
    request_id
}

/// `withdrawRefundCommitment(sk, requestId)` — rung 5(v), avenue 3:
/// `transientHash<Vector<3, Bytes<32>>>([pad(32, "vault:refund:"), sk,
/// requestId])`, POSEIDON over the six field limbs, replacing the port's
/// `persistentHash` (SHA-256 over 96 bytes, ~3,760 measured rows) — the
/// same construction `swapRefundCommitment` uses.
///
/// DURABILITY (notes/vault-optimization.org §"Q3"/§"Q4", CLEARED): Poseidon
/// (`transientHash`) is curve-stable-EXEMPT — Midnight may change it on a
/// hard fork (transient-crypto/src/hash.rs:75-81) whereas `persistentHash`
/// is SHA and "guaranteed for long-term support" (base-crypto/src/hash.rs
/// :92-95). That mutability is HARMLESS here because this commitment is
/// vault-INTERNAL and SHORT-LIVED: `withdraw`/`swap` write it, exactly one
/// settle circuit (`completeWithdraw`/`refund`/`completeSwap`) recomputes it
/// from the same `(sk, requestId)` and compares one transaction later, and
/// it never leaves the contract or spans a fork of the hash — the whole
/// round trip is inside one deployment's lifetime with no recompute-later
/// exposure. (Contrast `userCommitment`, which stays SHA because it is the
/// MPC's key-derivation path and a hash change would strand funds — §"Q4".)
///
/// The Poseidon digest is a `Field`; the map value is kept `Bytes<32>` (the
/// `Map<_, Field>` value-typing of §"Q5" is deferred — see the deviation
/// log), so the field is split into the stored `[hi, lo]` slot pair exactly
/// as `b32_slots` reconstructs it off-circuit: `lo = f mod 2^248` (the low
/// 31 bytes) and `hi = f >> 248` (byte 31, `< 2^7` since a BLS12-381 scalar
/// is `< 2^255`).
fn withdraw_refund_commitment(
    c: &mut Circuit3,
    sk: &B32<Private>,
    request_id: &B32<Private>,
) -> B32<Private> {
    c.region("refund commitment hash", |c| {
        let pad = B32::pad(c, REFUND_PAD);
        let f = c.transient_hash(&[
            pad.hi.private(),
            pad.lo.private(),
            sk.hi,
            sk.lo,
            request_id.hi,
            request_id.lo,
        ]);
        let (hi, lo) = c.div_mod_power_of_two(f, 248);
        B32 { hi, lo }
    })
}

/// `struct WithdrawRequest { erc20Address: Bytes<20>, amount: Uint<128>,
/// destEvmAddress: Bytes<20> }` — which token, how much of it, and the EVM
/// account it is sent to.
#[derive(CircuitArg)]
struct WithdrawRequest {
    erc20_address: Bytes<20>,
    amount: Uint<128>,
    dest_evm_address: Bytes<20>,
}

/// `struct ShieldedCoinInfo { nonce: Bytes<32>, color: Bytes<32>,
/// value: Uint<128> }` as an argument: the typed twin of
/// [`minocrab_std::v3::ShieldedCoinInfo3`], whose fields are raw wires
/// because the body handles the coin after disclosing it.
#[derive(CircuitArg)]
struct ShieldedCoinArg {
    nonce: B32<Private>,
    color: B32<Private>,
    value: Uint<128>,
}

/// `export circuit withdraw(evmNonce: Uint<64>, keyVersion: Uint<8>,
/// withdrawRequest: WithdrawRequest, coin: ShieldedCoinInfo): []` —
/// Runtime step 1 of a withdrawal: burn the surrendered vault coin,
/// record `transfer(destEvmAddress, amount)` signed with the VAULT's
/// account under a contract-fixed gas envelope, pin the withdrawer's
/// refund commitment, and notify the MPC (withdraw.zkir; reads:
/// initialized, kernel.self ×5, evmChainId, signetRequestNonce, caip2Id,
/// member, signetSigner).
///
/// The parameters after `c` are the Compact parameter list, in declaration
/// order — which is the wire contract.
#[circuit]
pub fn withdraw(
    c: &mut Circuit3,
    evm_nonce: Uint<64>,
    key_version: Uint<8>,
    withdraw_request: WithdrawRequest,
    coin: ShieldedCoinArg,
) {
    let evm_nonce = evm_nonce.field();
    let key_version = key_version.field();
    let erc20_address = withdraw_request.erc20_address.field();
    let amount = withdraw_request.amount.field();
    let dest_evm_address = withdraw_request.dest_evm_address.field();
    let coin_nonce = coin.nonce;
    let coin_color = coin.color;
    let coin_value = coin.value.field();

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
    let domain_sep = vault_token_domain_separator(c, erc20_address);
    // THE kernel.self read of this circuit (rung i): the colour derivation,
    // the event's sender, the receive, the burn and the notification all
    // want the same address, and the port read it five times.
    let me = kernel_self(c, one);
    let me = B32 { hi: me[0], lo: me[1] };
    let color = minocrab_std::v3::token_type(c, &domain_sep, &me);
    let color_hi_ok = c.test_eq(coin_color.hi, color.hi.private());
    let color_lo_ok = c.test_eq(coin_color.lo, color.lo.private());
    let color_ok = c.mul(color_hi_ok, color_lo_ok);
    c.assert(color_ok);
    let value_ok = c.test_eq(coin_value, amount);
    c.assert(value_ok);

    // Contract-enforced calldata: transfer(destEvmAddress, amount).
    let word0 = signet::evm_address_abi_word(c, dest_evm_address);
    let word1 = signet::numeric_abi_word(c, amount);
    let selector = c.constant(minocrab::Fr::from_le_bytes(&TRANSFER_SELECTOR).unwrap());
    let two = c.constant(2u64);
    let calldata = signet::EvmCalldata::<Private, VAULT_WORDS> {
        selector: selector.private(),
        no_words: two.private(),
        words: [word0, word1],
    };

    // Contract-FIXED gas envelope (the vault's account pays).
    let chain_id = cell_read(
        c,
        one,
        EVM_CHAIN_ID,
        vec![AlignmentAtom::Bytes { length: 8 }],
    )[0];
    let priority_fee = c.constant(1_000_000_000u64);
    let max_fee = c.constant(30_000_000_000u64);
    let gas = c.constant(100_000u64);
    let tx_params = signet::EvmType2TxParams::<Private, VAULT_WORDS> {
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
    let request_nonce = counter_read(c, one, SIGNET_REQUEST_NONCE);
    let sender = B32 {
        hi: me.hi.private(),
        lo: me.lo.private(),
    };
    let caip2 = cell_read(
        c,
        one,
        CAIP2_ID,
        vec![AlignmentAtom::Bytes { length: 32 }],
    );
    let caip2 = B32 {
        hi: caip2[0].private(),
        lo: caip2[1].private(),
    };
    let path = B32::pad(c, VAULT_PATH);
    let path = B32::<Private> {
        hi: path.hi.private(),
        lo: path.lo.private(),
    };
    let schema = BytesN::<Private, VAULT_SCHEMA_LEN>::literal(c, VAULT_RESPONSE_SCHEMA);
    let request: VaultEvent<Private> = signet::construct_sign_bidirectional_event(
        c,
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
        check_fresh_request(c, one, &request, SIGN_BIDIRECTIONAL_EVENT_MAP);

    // The surrendered value is BURNED (rung vi, avenue 6): a SINGLE claimed
    // shielded spend of the burn-address output — no receive custody claim,
    // no nullifier. See [`common::burn_spend`].
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
    common::burn_spend(c, one, &coin);

    insert_request(c, one, &request, SIGN_BIDIRECTIONAL_EVENT_MAP, &request_id_val);

    // refundCommitment.insert(requestId,
    //   disclose(withdrawRefundCommitment(callerSecretKey(), requestId)))
    let sk = common::witness_sk(c);
    let rid_priv = B32 {
        hi: request_id.hi.private(),
        lo: request_id.lo.private(),
    };
    let rc = withdraw_refund_commitment(c, &sk, &rid_priv);
    let rc = B32 {
        hi: c.disclose(rc.hi, "withdrawer refund commitment (hi)"),
        lo: c.disclose(rc.lo, "withdrawer refund commitment (lo)"),
    };
    let rc_val = LedgerValue::bytes(32, vec![ImpactElem::Wire(rc.hi), ImpactElem::Wire(rc.lo)]);
    emit(
        c,
        one,
        &map_insert(REFUND_COMMITMENT, &request_id_val, &rc_val),
    );

    notify_signet(c, one, me, &request_id, [0, 0, 0, 0]);
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
    // THE kernel.self read of this circuit (rung i) — as in `withdraw`, the
    // port read the same address five times.
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
    let calldata = signet::EvmCalldata::<Private, SWAP_WORDS> {
        selector: selector.private(),
        no_words: seven.private(),
        words: [word0, word1, word2, word3, word4, word5, word6],
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
    let tx_params = signet::EvmType2TxParams::<Private, SWAP_WORDS> {
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
    let sender = B32 {
        hi: me.hi.private(),
        lo: me.lo.private(),
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
    let output_schema = BytesN::<Private, SWAP_OUTPUT_LEN>::literal(&mut c, SWAP_OUTPUT_SCHEMA);
    let respond_schema = BytesN::<Private, SWAP_RESPOND_LEN>::literal(&mut c, SWAP_RESPOND_SCHEMA);
    let request: SwapEvent<Private> = signet::construct_sign_bidirectional_event(
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

    let (request_id, request_id_val) = check_fresh_request(&mut c, one, &request, SWAP_EVENT_MAP);

    // Burn the surrendered amountInMaximum of tokenIn (rung vi, avenue 6): a
    // SINGLE claimed shielded spend of the burn-address output — no receive
    // custody claim, no nullifier. See [`common::burn_spend`].
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
    common::burn_spend(&mut c, one, &coin);

    insert_request(&mut c, one, &request, SWAP_EVENT_MAP, &request_id_val);

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

    notify_signet(&mut c, one, me, &request_id, [11, 0, 0, 0]);

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
    let calldata = signet::EvmCalldata::<Private, VAULT_WORDS> {
        selector: selector.private(),
        no_words: two.private(),
        words: [word0, word1],
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
    let tx_params = signet::EvmType2TxParams::<Private, VAULT_WORDS> {
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
    // ONE kernel.self read (rung i): sender and callerAddress coincide.
    let me = kernel_self(&mut c, one);
    let me = B32 { hi: me[0], lo: me[1] };
    let sender = B32 {
        hi: me.hi.private(),
        lo: me.lo.private(),
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
    let schema = BytesN::<Private, VAULT_SCHEMA_LEN>::literal(&mut c, VAULT_RESPONSE_SCHEMA);
    let request: VaultEvent<Private> = signet::construct_sign_bidirectional_event(
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

    record_and_notify(&mut c, one, me, &request, SIGN_BIDIRECTIONAL_EVENT_MAP, [0, 0, 0, 0]);

    c.finish(true)
}

/// `vaultTokenDomainSeparator(erc20Address)` (rung iii, avenue 2): the
/// INJECTIVE ENCODING `0x01 ‖ 0x00 × 11 ‖ erc20[20]`, replacing the port's
/// `persistentHash([pad(32, "erc20:vault:"), erc20])` — 3,739 measured
/// rows per use, at nine uses across the vault.
///
/// Exactly one byte layout, and it is the whole specification:
///
/// | byte(s) | 0..19          | 20..30 | 31   |
/// |---------|----------------|--------|------|
/// | content | erc20, LE limb | zero   | 0x01 |
///
/// which is the `Bytes<32>` slot pair `[hi = 0x01, lo = erc20]` — the
/// address limb carried VERBATIM, so the map `erc20 ↦ separator` is the
/// identity in its low limb and injective by inspection, with no
/// collision-resistance assumption anywhere. Byte 31 is a version/kind tag:
/// `0x01` = "the vault token of an EVM ERC-20". A future vault that wants
/// another token family gives it another tag rather than another hash.
///
/// Why this is safe to change at all:
///
/// - The separator is a PRE-TOKEN, not a colour. The ledger derives the
///   colour itself — `tokenType(sep, self) = SHA-256([pad(32,
///   "midnight:derive_token"), sep, self])`, coin-structure/src/contract.rs
///   :58-68, used at ledger/src/verify.rs:856-865 — and accepts an
///   ARBITRARY 32-byte pre-token (verified at the pinned rev; see
///   notes/vault-optimization.org §"(c) SPEC-DISCRETIONARY"). The
///   contract's own address is inside that derivation, so two contracts
///   using the same separator still mint different colours.
/// - Distinct ERC-20s therefore still get distinct colours: injective
///   separator, then a collision-resistant `tokenType`.
/// - No new disclosure. The separator already travels in the clear in
///   `kernel.mintShielded(domain_sep, value)`, and the ERC-20 address is
///   already public in the stored request record. It was never secret, so
///   the hash was never hiding it; preimage resistance bought nothing.
/// - The colour of the optimized vault's tokens differs from the port's,
///   which is correct: this is a separate deployment with its own address
///   and its own verifier key, and its tokens are its own.
///
/// The address argument is range-constrained to 160 bits where it enters
/// the circuit, but injectivity does not lean on that: the low limb is
/// carried through untouched, so distinct limbs give distinct separators
/// whatever their width. The table above is the layout for a well-formed
/// (on-chain-accepted) address.
fn vault_token_domain_separator(
    c: &mut Circuit3,
    erc20_address: Wire3<FieldT, Public>,
) -> B32<Public> {
    c.region("token domain separator", |c| B32 {
        hi: c.constant(u64::from(VAULT_TOKEN_TAG)),
        lo: erc20_address,
    })
}

/// Byte 31 of [`vault_token_domain_separator`]'s encoding: the kind tag of
/// "the vault token of an EVM ERC-20".
pub const VAULT_TOKEN_TAG: u8 = 0x01;

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
fn verify_attestation<const LEN_OUTPUT: usize>(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    args: &SettleArgs,
    output_limbs: &[Wire3<FieldT, Private>],
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
    let valid = signet::verify_respond_bidirectional_event::<Private, LEN_OUTPUT>(
        c,
        &rid_priv,
        output_limbs,
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
/// to `left(ownPublicKey())`, its `kernel.self()` read under the same
/// guard. `completeWithdraw` is the sole caller (`refund` merged its
/// withdrawal route into a shared mint at rung 5(iv), avenue 4), and it
/// reads `kernel.self()` exactly once, so the guarded read is correct:
/// nothing is available to share it with, and an unguarded read would put
/// an answer in the transcript on the success path, which needs none.
fn refund_surrendered_value(
    c: &mut Circuit3,
    guard: Wire3<FieldT, Public>,
    request_id: &B32<Public>,
    request_id_val: &LedgerValue,
    ev: &VaultRecord,
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
    common::assert_if(c, guard, ev.calldata_is_some());

    // const amount = abiWordToUint128(calldata.words[1])
    let word1 = ev.word(1);
    let amount = signet::abi_word_to_uint128_guarded(c, guard, &word1);

    // Re-mint to the withdrawer's own wallet key.
    let domain_sep = vault_token_domain_separator(c, ev.to());
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

    let request_id = verify_attestation::<1>(&mut c, one, &args, &output);
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
        let ev = VaultRecord::from_lookup(map_lookup(
            c,
            one,
            SIGN_BIDIRECTIONAL_EVENT_MAP,
            &request_id_val,
            VaultRecord::atoms(),
        ));
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

    let request_id = verify_attestation::<8>(&mut c, one, &args, &output);
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
        let ev = SwapRecord::from_lookup(map_lookup(
            c,
            one,
            SWAP_EVENT_MAP,
            &request_id_val,
            SwapRecord::atoms(),
        ));
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
    c.assert(ev.calldata_is_some());
    // ONE kernel.self read for BOTH mints (rung i).
    let me = kernel_self(&mut c, one);
    let me = B32 { hi: me[0], lo: me[1] };
    let recipient = minocrab_std::v3::own_public_key(&mut c);
    let recipient = B32 {
        hi: c.disclose(recipient.hi, "own public key as swap recipient (hi)"),
        lo: c.disclose(recipient.lo, "own public key as swap recipient (lo)"),
    };

    // Mint the EXACT amountOut of tokenOut: word 4 of tokenOut (word 1).
    let word4 = ev.word(4);
    let amount_out = signet::abi_word_to_uint128(&mut c, &word4);
    let word1 = ev.word(1);
    let token_out = signet::abi_word_low20(&mut c, &word1);
    let ds_out = vault_token_domain_separator(&mut c, token_out);
    let mint_nonce = B32 {
        hi: c.disclose(args.mint_nonce.hi, "swap mint nonce (hi)"),
        lo: c.disclose(args.mint_nonce.lo, "swap mint nonce (lo)"),
    };
    common::mint_shielded_token_to_key_with(
        &mut c, one, me, &ds_out, amount_out, &mint_nonce, &recipient,
    );

    // Change: amountInMaximum (word 5) − attested amountIn, of tokenIn
    // (word 0), under a nonce derived from mintNonce.
    let amount_in = c.disclose(output[0], "attested amountIn spent");
    let word5 = ev.word(5);
    let amount_in_max = signet::abi_word_to_uint128(&mut c, &word5);
    let overspent = c.less_than(amount_in_max, amount_in, 128);
    let ok = c.not(overspent);
    c.assert(ok);
    let neg_in = c.neg(amount_in);
    let change = c.add(amount_in_max, neg_in);
    let word0 = ev.word(0);
    let token_in = signet::abi_word_low20(&mut c, &word0);
    let ds_in = vault_token_domain_separator(&mut c, token_in);
    let change_nonce = change_nonce(&mut c, &mint_nonce);
    common::mint_shielded_token_to_key_with(
        &mut c, one, me, &ds_in, change, &change_nonce, &recipient,
    );

    c.finish(true)
}

/// completeSwap's change-coin nonce (rung ii, avenue 5): the mint nonce
/// with its top byte complemented, `[255 − hi, lo]`, replacing the port's
/// `persistentHash([mintNonce, pad(32, "change")])` — a 64-byte SHA-256,
/// 3,739 measured rows, for three field operations.
///
/// What a nonce here has to do, and why this does it:
///
/// 1. WITHIN THE CALL the two minted coins must not share a commitment.
///    `coinCommitment` covers (nonce, colour, value, recipient), and both
///    mints go to the same recipient — so when `tokenIn == tokenOut` and
///    the change happens to equal `amountOut`, the nonce is the ONLY thing
///    keeping them apart. A collision would not be caught: the effects'
///    spend claims are a map keyed by commitment, so two identical
///    commitments collapse into one entry and a coin is silently lost.
///    `255 − hi` has no fixed point over the integers, and `mintNonce.hi`
///    is range-constrained to 8 bits where it is declared
///    (`settle_args`), so the two nonces differ in their top byte for
///    EVERY caller-supplied mint nonce — unconditionally, with no guard.
/// 2. ACROSS CALLS the map must not merge distinct requests' change coins.
///    `hi ↦ 255 − hi` is a bijection on `[0, 255]`, so distinct mint
///    nonces still give distinct change nonces: the freshness burden stays
///    exactly where the port already put it — on the caller-chosen mint
///    nonce — and zswap's global `CommitmentAlreadyPresent` remains the
///    backstop, unchanged.
/// 3. CANONICITY: `hi ∈ [0, 255] ⟹ 255 − hi ∈ [0, 255]`, so the result is
///    a well-formed `Bytes<32>` for every input. `mintNonce + 1` — the
///    other candidate the analysis names — is NOT total in that sense: it
///    can carry a 248-bit low limb out of range.
/// 4. NOTHING IS DISCLOSED that was not disclosed before. `mintNonce` is a
///    circuit argument that both artifacts publish into the transcript
///    (the port discloses both limbs for the out-coin mint), so an
///    observer could always compute the hashed change nonce too. The
///    SHA-256 was never buying preimage resistance over a secret; it was
///    domain separation between two public values, which an injective,
///    fixed-point-free map provides just as well.
fn change_nonce(c: &mut Circuit3, mint_nonce: &B32<Public>) -> B32<Public> {
    c.region("change nonce", |c| {
        let max_byte = c.constant(255u64);
        let neg_hi = c.neg(mint_nonce.hi);
        B32 {
            hi: c.add(max_byte, neg_hi),
            lo: mint_nonce.lo,
        }
    })
}

/// `export circuit refund(requestId, respondBidirectionalEvent,
/// serializedOutput: Bytes<5>, mintNonce): []` — settles a withdrawal OR
/// swap whose transaction NEVER EXECUTED (the MPC attested the fixed
/// 5-byte failure output), routing on which pending marker holds the id.
///
/// # Rung 5(iv), avenue 4 — the branch merge
///
/// The port (and the pre-merge opt fork) ran the surrendered-value re-mint
/// TWICE: `refundSurrenderedValue` for the withdrawal route and an inline
/// re-mint for the swap route. Because guards gate only PI EMISSION and not
/// in-circuit computation, BOTH copies cost their full rows — a duplicated
/// `withdrawRefundCommitment(sk, requestId)` hash and a duplicated
/// `domainSep → tokenType → coinCommitment → mint` block, ~9,430 rows of
/// dead work (notes/vault-optimization.org §"(c) SPEC-DISCRETIONARY").
///
/// This body computes each ONCE. The branch-varying INPUTS — the token
/// address and the refunded amount — are `cond_select`ed on the route, and
/// the recipient key and refund commitment are route-independent, so a
/// SINGLE mint block and a SINGLE commitment hash serve both routes. The
/// ledger EFFECT ops stay guarded PER ROUTE (the two event-map lookups and
/// all four map removes carry their branch guard), exactly as before; only
/// the in-circuit arithmetic is shared. The single mint emits unguarded
/// because an accepted refund ALWAYS mints exactly once (see below).
///
/// ## Why neither route's authorisation weakens (the deliverable)
///
/// Authorisation is `withdrawRefundCommitment(callerSecretKey(), requestId)
/// == storedCommitment`, where `storedCommitment` is looked up from the map
/// that HOLDS the pending marker. The merge keeps that map route-specific:
/// `stored = cond_select(isWithdrawal, refundCommitment[id],
/// swapRefundCommitment[id])`, then one `assert(rc == stored)`.
/// - The route is decided by `refundCommitment.member(id)` ALONE (as in the
///   port), and the swap route additionally asserts
///   `swapRefundCommitment.member(id)`. An id lives in at most one of the
///   two commitment maps (each was inserted by exactly one of withdraw/swap,
///   under a keccak-derived id that pins the record's kind), so the routing
///   is total and disjoint.
/// - On the withdrawal route (`isWithdrawal = 1`) the guarded
///   `swapRefundCommitment` lookup emits nothing and its garbage default is
///   discarded by the `cond_select`; the gate compares against
///   `refundCommitment[id]` — the value `withdraw` stored, openable only by
///   the original withdrawer's `sk`. The swap route is symmetric against
///   `swapRefundCommitment[id]`.
/// - Therefore a WITHDRAWAL-route id can never be settled through the swap
///   comparison (it routes `isWithdrawal = 1`, so `stored` is the
///   refundCommitment value and the swap map/removes are guarded off), and a
///   SWAP-route id can never be settled through the withdrawal comparison.
///   This is bit-for-bit the port's authorisation, re-expressed with one
///   shared hash; the cross-route traps in `gen`/`model` (id in both maps,
///   id in neither, a swap id offered on the withdrawal route) stay green.
///
/// (refund.zkir; the port's two guarded branches, merged.)
pub fn refund() -> Compiled3 {
    let mut c = Circuit3::new();
    let (args, output) = settle_args(&mut c, |c| {
        let w = c.arg::<FieldT>("serializedOutput");
        vec![w]
    });
    c.assert_bits(output[0], 40);

    let one = c.constant(1u64);

    let request_id = verify_attestation::<5>(&mut c, one, &args, &output);
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
    let swapping = c.not(is_withdrawal);
    // ONE UNGUARDED kernel.self read dominating both branches (rung i).
    // Exactly one branch runs, so the transcript still carries exactly one
    // kernel.self answer — but the circuit now carries one read, not two.
    let me = kernel_self(&mut c, one);
    let me = B32 { hi: me[0], lo: me[1] };
    let mint_nonce = B32 {
        hi: c.disclose(args.mint_nonce.hi, "refund mint nonce (hi)"),
        lo: c.disclose(args.mint_nonce.lo, "refund mint nonce (lo)"),
    };

    // Withdrawal-route record consume (guarded): the VaultRecord and its
    // removal from the request map.
    let ev = c.region("event map consume", |c| {
        let ev = VaultRecord::from_lookup(minocrab_ledger::map_lookup_guarded(
            c,
            is_withdrawal,
            SIGN_BIDIRECTIONAL_EVENT_MAP,
            &request_id_val,
            VaultRecord::atoms(),
        ));
        emit(
            c,
            is_withdrawal,
            &map_remove(SIGN_BIDIRECTIONAL_EVENT_MAP, &request_id_val),
        );
        ev
    });

    // Swap-route record consume (guarded): the pending-swap marker assert,
    // the SwapRecord, and its removal from the swap request map.
    let ev7 = c.region("event map consume", |c| {
        let swap_pending = minocrab_ledger::map_member_guarded(
            c,
            swapping,
            SWAP_REFUND_COMMITMENT,
            &request_id_val,
        );
        common::assert_if(c, swapping, swap_pending);
        let ev7 = SwapRecord::from_lookup(minocrab_ledger::map_lookup_guarded(
            c,
            swapping,
            SWAP_EVENT_MAP,
            &request_id_val,
            SwapRecord::atoms(),
        ));
        emit(
            c,
            swapping,
            &map_remove(SWAP_EVENT_MAP, &request_id_val),
        );
        ev7
    });

    // Unified claimant gate (avenue 4): the refund commitment is computed
    // ONCE, and the expected value is `cond_select`ed from the route's own
    // commitment map — see the circuit doc comment for why this is exactly
    // the port's per-route authorisation.
    c.region("claimant gate", |c| {
        let sk = common::witness_sk(c);
        let rid_priv = B32 {
            hi: request_id.hi.private(),
            lo: request_id.lo.private(),
        };
        let rc = withdraw_refund_commitment(c, &sk, &rid_priv);
        let wd_stored = minocrab_ledger::map_lookup_guarded(
            c,
            is_withdrawal,
            REFUND_COMMITMENT,
            &request_id_val,
            vec![AlignmentAtom::Bytes { length: 32 }],
        );
        let sw_stored = minocrab_ledger::map_lookup_guarded(
            c,
            swapping,
            SWAP_REFUND_COMMITMENT,
            &request_id_val,
            vec![AlignmentAtom::Bytes { length: 32 }],
        );
        let stored_hi = c.cond_select(is_withdrawal, wd_stored[0], sw_stored[0]);
        let stored_lo = c.cond_select(is_withdrawal, wd_stored[1], sw_stored[1]);
        let eq_hi = c.test_eq(rc.hi, stored_hi.private());
        let eq_lo = c.test_eq(rc.lo, stored_lo.private());
        let is_claimant = c.mul(eq_hi, eq_lo);
        c.assert(is_claimant);
    });

    // The commitment-map removes, guarded per route (ledger EFFECT ops).
    emit(
        &mut c,
        is_withdrawal,
        &map_remove(REFUND_COMMITMENT, &request_id_val),
    );
    emit(
        &mut c,
        swapping,
        &map_remove(SWAP_REFUND_COMMITMENT, &request_id_val),
    );

    // Unified re-mint (avenue 4): cond_select the branch-varying token and
    // amount, then run ONE domainSep → tokenType → coinCommitment → mint.
    // The withdrawal route mints `abiWordToUint128(word1)` of the record's
    // `to` token; the swap route mints `abiWordToUint128(word5)` (the
    // surrendered amountInMaximum) of `word0`'s low-20 token. The unused
    // decode is guarded off (no canonicity assert on the garbage record) or
    // assert-free (`abi_word_low20`).
    common::assert_if(&mut c, is_withdrawal, ev.calldata_is_some());
    common::assert_if(&mut c, swapping, ev7.calldata_is_some());
    let word1 = ev.word(1);
    let amount_wd = signet::abi_word_to_uint128_guarded(&mut c, is_withdrawal, &word1);
    let word5 = ev7.word(5);
    let amount_sw = signet::abi_word_to_uint128_guarded(&mut c, swapping, &word5);
    let amount = c.cond_select(is_withdrawal, amount_wd, amount_sw);
    let word0 = ev7.word(0);
    let token_sw = signet::abi_word_low20(&mut c, &word0);
    let token = c.cond_select(is_withdrawal, ev.to(), token_sw);
    let domain_sep = vault_token_domain_separator(&mut c, token);
    let own_pk = minocrab_std::v3::own_public_key(&mut c);
    let own_pk = B32 {
        hi: c.disclose(own_pk.hi, "own public key as refund recipient (hi)"),
        lo: c.disclose(own_pk.lo, "own public key as refund recipient (lo)"),
    };
    common::mint_shielded_token_to_key_with(
        &mut c, one, me, &domain_sep, amount, &mint_nonce, &own_pk,
    );

    c.finish(true)
}

/// `struct Secp256k1Point { x: Bytes<32>, y: Bytes<32> }` — the `bigR`
/// nonce point of an ECDSA signature.
#[derive(CircuitArg)]
struct BigR {
    x: B32<Private>,
    y: B32<Private>,
}

/// `struct Secp256k1EcdsaSignature { bigR: Secp256k1Point, s: Bytes<32>,
/// recoveryId: Uint<8> }` — the MPC's attestation. Compact wraps it in a
/// one-field `RespondBidirectionalEvent { signature }`; the hand-written
/// argument labels (frozen in the interface snapshot) never carried that
/// wrapper, so the port keeps the signature's fields directly under the
/// head [`claim`]'s parameter gives them.
#[derive(CircuitArg)]
struct RespondSignature {
    big_r: BigR,
    s: B32<Private>,
    recovery_id: Uint<8>,
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
///
/// The parameters after `c` are the Compact parameter list, in declaration
/// order — which is the wire contract. The mechanical label for the second
/// one would be `respondBidirectionalEvent_…`; `#[arg(name = "respond")]`
/// keeps the hand-written abbreviation the interface snapshot froze
/// (`respond_bigR_x_hi`, …). Renaming is a phase-5 decision, not this
/// port's.
#[circuit]
pub fn claim(
    c: &mut Circuit3,
    request_id: B32<Private>,
    #[arg(name = "respond")] respond_bidirectional_event: RespondSignature,
    serialized_output: Bytes<1>,
    mint_nonce: B32<Private>,
    recipient: Maybe<Either<B32<Private>, B32<Private>>>,
) {
    // bigR.y and recoveryId are part of the attestation's wire shape —
    // declared and range-constrained like every other slot — but the
    // verification reads neither, exactly as in the Compact original.
    let big_r_x = respond_bidirectional_event.big_r.x;
    let sig_s = respond_bidirectional_event.s;
    let serialized_output = serialized_output.field();
    let rec_is_some = recipient.is_some.field();
    let rec_is_left = recipient.value.is_left.field();
    let rec_left = recipient.value.left;
    let rec_right = recipient.value.right;

    let one = c.constant(1u64);
    let zero = c.constant(0u64);

    // const disclosedRequestId = disclose(requestId)
    let request_id = B32 {
        hi: c.disclose(request_id.hi, "claim request id (hi)"),
        lo: c.disclose(request_id.lo, "claim request id (lo)"),
    };

    // assert(initialized >= 1, "Not initialized")
    assert_initialized(c, one);

    // const response = deserialize<VaultResponse, 1>(serializedOutput);
    // assert(response.success) — the packed Boolean is (byte == 1).
    let success = c.test_eq(serialized_output, one.private());
    c.assert(success);

    // assert(verifyRespondBidirectionalEvent<1>(requestId,
    //   serializedOutput, event, mpcResponseKey))
    let mpc_key = common::cell_read_point(c, one, MPC_RESPONSE_KEY);
    let rid_priv = B32 {
        hi: request_id.hi.private(),
        lo: request_id.lo.private(),
    };
    let valid = signet::verify_respond_bidirectional_event::<Private, 1>(
        c,
        &rid_priv,
        &[serialized_output],
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
        let ev = VaultRecord::from_lookup(map_lookup(
            c,
            one,
            SIGN_BIDIRECTIONAL_EVENT_MAP,
            &request_id_val,
            VaultRecord::atoms(),
        ));
        emit(
            c,
            one,
            &map_remove(SIGN_BIDIRECTIONAL_EVENT_MAP, &request_id_val),
        );
        ev
    });

    // Depositor gate: userCommitment(callerSecretKey()) == request.path — the
    // SHORT one-block userCommitment (rung 5(i-userCommit), avenue 1).
    c.region("depositor gate", |c| {
        let sk = common::witness_sk(c);
        let caller = common::commitment_short(c, &sk);
        let path = ev.path();
        let eq_hi = c.test_eq(caller.hi, path.hi.private());
        let eq_lo = c.test_eq(caller.lo, path.lo.private());
        let is_depositor = c.mul(eq_hi, eq_lo);
        c.assert(is_depositor);
    });

    // assert(request.txParams.calldata.is_some)
    c.assert(ev.calldata_is_some());

    // const amount = abiWordToUint128(calldata.words[1])
    let word1 = ev.word(1);
    let amount = signet::abi_word_to_uint128(c, &word1);

    // const domainSep = vaultTokenDomainSeparator(request.txParams.to)
    let domain_sep = vault_token_domain_separator(c, ev.to());

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
    common::mint_shielded_token(c, one, &domain_sep, amount, &mint_nonce, &recipient);
}
