//! `erc20-vault`, OPTIMIZED (M10 §Sequencing step 4) — the second artifact.
//!
//! This module is a fork of [`crate::erc20_vault`], not a variant of it: the
//! direct ports there are the COMPATIBILITY reference and never move again
//! (their frozen rows and their compactc PI-equality differentials are the
//! first link of M10's chain of trust). Every optimization lands here.
//!
//! At the forking commit the nine circuits are BYTE-IDENTICAL to the ports —
//! `tests/erc20_vault_opt_fork.rs` asserts exactly that, circuit by circuit,
//! and the row/interface snapshots carry identical numbers for both sides.
//! Each later commit is therefore a one-optimization diff, and the fork test's
//! divergence ledger is where a circuit stops being covered by the compactc
//! differential and starts being covered by the spec harness instead.
//!
//! What is NOT copied: the protocol-pinned constants, the record types and
//! the shared helpers (`common`, `signet`). Those are the vault's wire
//! contract and Compact's standard library — imported, so a change to either
//! cannot silently apply to one artifact and not the other. Copied: exactly
//! the nine circuit functions and the private helpers they call, because
//! those are what M10 changes.
//!
//! Deviations from the port, newest last (the deviation log; the safety
//! argument for each is in notes/vault-optimization.org §"As built —
//! steps 4+5(i-iii)"):
//!
//! - (step 4) none — byte-identical fork.
//! - (rung i, avenue 7) `kernel.self()` is read ONCE per circuit and
//!   threaded, instead of once per stdlib call site. The value is the
//!   contract's own address, constant for the whole transaction, and each
//!   emitted read still reconciles against the ledger — so how many are
//!   emitted is compactc's framing, not the protocol's
//!   (notes/vault-optimization.org §"(b) COMPACTC-FRAMING-ONLY"). In
//!   `refund` the two branches' guarded reads become one UNGUARDED read
//!   dominating both: exactly one branch runs, so the transcript still
//!   carries exactly one kernel.self answer, and the circuit carries one
//!   read instead of two.
//! - (rung ii, avenue 5) completeSwap's `changeNonce` is
//!   `[255 − mintNonce.hi, mintNonce.lo]` instead of
//!   `persistentHash([mintNonce, pad(32, "change")])`. See
//!   [`change_nonce`] for the uniqueness argument.
//! - (rung iii, avenue 2) `vaultTokenDomainSeparator(erc20)` is the
//!   injective encoding `0x01 ‖ zeros ‖ erc20[20]` instead of
//!   `persistentHash([pad(32, "erc20:vault:"), erc20])`, at all nine uses.
//!   See [`vault_token_domain_separator`].
//! - (rung vi, avenue 6) `withdraw` and `swap` BURN the surrendered coin with
//!   a SINGLE claimed shielded spend of the burn-address output, instead of
//!   `receiveShielded` (custody) + `sendImmediateShielded` (nullifier +
//!   output). The user funds the burn Output directly, so the receive
//!   coinCommitment and the nullifier — two SHA-256 pair hashes, ~11,280 rows
//!   each in withdraw and swap — are removed; the evolved-nonce output
//!   commitment is kept byte-identical. See [`common::burn_spend`]; its
//!   well-formedness against the pinned ledger is proven in
//!   tests/erc20_vault_opt_burn_wellformed.rs.

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{AlignmentAtom, Private, Public};
use minocrab_ledger::{
    cell_read, cell_write, counter_increment, counter_read, emit, ImpactElem,
    LedgerValue, XcallCommitment, XcallEntryPointHash,
};
use minocrab_std::v3::kernel;
use minocrab_std::v3::ContractAddress;
use minocrab_std::v3::{
    circuit, label, le, ne, own_public_key_guarded, Bytes, BytesN, CircuitArg, CoinRecipient,
    Disclose, Discloses, Either, LedgerMap, LedgerRepr, Maybe, Secp256k1Point, Uint, B32,
};

use signet_signer_interface::notification::construct_notification_v1;
use signet_signer_interface::SignetSigner;

use crate::common;
use crate::erc20_vault::{
    SwapEvent, VaultEvent, VaultRecord, APPROVE_SELECTOR, CAIP2_ID, DEPLOYER,
    EVM_CHAIN_ID, EXACT_OUTPUT_SINGLE_SELECTOR, INITIALIZED, MPC_FAILURE_OUTPUT, MPC_RESPONSE_KEY,
    REFUND_PAD, SIGNET_REQUEST_NONCE, SIGNET_SIGNER, SWAP_OUTPUT_LEN, SWAP_OUTPUT_SCHEMA,
    SWAP_RESPOND_LEN, SWAP_RESPOND_SCHEMA, SWAP_WORDS, TRANSFER_SELECTOR, UNISWAP_ROUTER,
    VAULT, VAULT_EVM_ADDRESS, VAULT_PATH, VAULT_RESPONSE_SCHEMA, VAULT_SCHEMA_LEN, VAULT_WORDS,
};
use crate::signet;

// What each circuit discloses, one zero-sized type per logical value. The
// strings are the labels the hand-written `disclose` calls carried, minus
// the `(hi)`/`(lo)` suffixes: a `Bytes<32>` is ONE disclosure now, under
// one symbol that its circuit's signature also names.
label! {
    VaultEvmAddress = "the vault's derived EVM address";
    UniswapRouter = "the Uniswap router address";
    EvmChainId = "the EVM chain id";
    Caip2Id = "the CAIP-2 chain id";
    MpcResponseKey = "the MPC response key";
    DepositorCommitment = "depositor identity commitment";
    RequestId = "request id";
    RequestRecord = "request record";
    WithdrawnErc20 = "the withdrawn ERC20";
    SurrenderedCoinNonce = "surrendered coin nonce";
    SurrenderedCoinColor = "surrendered coin color";
    SurrenderedCoinValue = "surrendered coin value";
    WithdrawerRefundCommitment = "withdrawer refund commitment";
    SoldErc20 = "the sold ERC20";
    BoughtErc20 = "the bought ERC20";
    SwapperRefundCommitment = "swapper refund commitment";
    ApprovedErc20 = "the approved ERC20";
    SettleRequestId = "settle request id";
    WithdrawalOutcome = "withdrawal EVM outcome";
    RefundMintNonce = "refund mint nonce";
    RefundRecipient = "own public key as refund recipient";
    SwapRecipient = "own public key as swap recipient";
    SwapMintNonce = "swap mint nonce";
    AttestedAmountIn = "attested amountIn spent";
    ClaimRequestId = "claim request id";
    ClaimRecipientTag = "claim recipient tag";
    ClaimRecipientSide = "claim recipient side";
    ClaimRecipientOwnKey = "own public key as claim recipient";
    ClaimRecipientKey = "claim recipient key";
    ClaimRecipientContract = "claim recipient contract";
    ClaimMintNonce = "claim mint nonce";
}

/// `export circuit initialize(vaultEvm: Bytes<20>, swapRouter: Bytes<20>,
/// chainId: Uint<64>, chainCaip2Id: Bytes<32>, responseKey:
/// Secp256k1Point): []`
///
/// The parameters after `c` are the Compact parameter list, in declaration
/// order — which is the wire contract. `responseKey` is the corpus's only
/// curve-point argument: one slot, no range constraint (see
/// [`minocrab_std::v3::Secp256k1Point`]).
#[circuit]
pub fn initialize(
    c: &mut Circuit3,
    vault_evm: Bytes<20>,
    swap_router: Bytes<20>,
    chain_id: Uint<64>,
    chain_caip2_id: B32<Private>,
    response_key: Secp256k1Point,
) -> Discloses<(VaultEvmAddress, UniswapRouter, EvmChainId, Caip2Id, MpcResponseKey)> {
    let vault_evm = vault_evm.field();
    // `swapRouter` and `chainId` stay TYPED until the guards have run: the
    // width a comparison runs at comes from the operand's type.
    let caip2 = chain_caip2_id;
    let response_key = response_key.point();

    let one = c.constant(1u64);

    // assert(initialized == 0, "Already initialized")
    c.region("initialized gate", |c| {
        common::assert_counter_zero(c, one, INITIALIZED);
    });

    // assert(userCommitment(callerSecretKey()) == deployer, "Not the deployer")
    // — the SHORT one-block userCommitment (rung 5(i-userCommit), avenue 1).
    c.region("deployer gate", |c| {
        common::assert_deployer_short(c, one, DEPLOYER);
    });

    // assert(chainId > 0 as Uint<64>, "Chain ID must be positive")
    c.assert(chain_id.gt(0u64).message("Chain ID must be positive"));

    // assert(swapRouter as Field != 0 as Field, "Router cannot be zero")
    c.assert(swap_router.ne(0u64).message("Router cannot be zero"));

    let swap_router = swap_router.field();
    let chain_id = chain_id.field();

    // initialized.increment(1)
    emit(c, one, &counter_increment(INITIALIZED, 1));

    // The five configuration writes, in source order.
    c.region("configuration writes", |c| {
        let vault_evm = vault_evm.disclose_as::<VaultEvmAddress>(c);
        let b20 = |w| LedgerValue::bytes(20, vec![ImpactElem::Wire(w)]);
        emit(c, one, &cell_write(VAULT_EVM_ADDRESS, &b20(vault_evm)));

        let swap_router = swap_router.disclose_as::<UniswapRouter>(c);
        emit(c, one, &cell_write(UNISWAP_ROUTER, &b20(swap_router)));

        let chain_id = chain_id.disclose_as::<EvmChainId>(c);
        let chain_val = LedgerValue::bytes(8, vec![ImpactElem::Wire(chain_id)]);
        emit(c, one, &cell_write(EVM_CHAIN_ID, &chain_val));

        let caip2 = caip2.disclose_as::<Caip2Id>(c);
        let caip2_val = LedgerValue::bytes(
            32,
            vec![ImpactElem::Wire(caip2.hi), ImpactElem::Wire(caip2.lo)],
        );
        emit(c, one, &cell_write(CAIP2_ID, &caip2_val));

        let pk = response_key.disclose_as::<MpcResponseKey>(c);
        let limbs = c.encode(pk);
        let pk_val = LedgerValue::new(
            common::secp256k1_point_atoms(),
            limbs.iter().map(|&w| ImpactElem::Wire(w)).collect(),
        );
        emit(c, one, &cell_write(MPC_RESPONSE_KEY, &pk_val));
    });

    Discloses::of(())
}

/// `assert(initialized >= 1, "Not initialized")` — a Counter read + `0 <
/// initialized`.
fn assert_initialized(c: &mut Circuit3) {
    let init = VAULT.initialized.read(c);
    c.assert(init.gt(0u64).message("Not initialized"));
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
) -> Discloses<(
    DepositorCommitment,
    RequestId,
    RequestRecord,
    XcallEntryPointHash,
    XcallCommitment,
)> {
    let evm_nonce = evm_nonce.field();
    let max_fee_per_gas = max_fee_per_gas.field();
    let max_priority_fee_per_gas = max_priority_fee_per_gas.field();
    let key_version = key_version.field();
    // Typed through the guards (the widths are the types'), wires after.
    let erc20_address = deposit_request.erc20_address;
    let amount = deposit_request.amount;

    let one = c.constant(1u64);
    let zero = c.constant(0u64);

    // assert(initialized >= 1, "Not initialized")
    c.region("guards", |c| {
        assert_initialized(c);

        // assert(erc20Address as Field != 0)
        c.assert(erc20_address.ne(zero.private()));

        // assert(amount > 0)
        c.assert(amount.gt(zero.private()));

        // assert(amount <= u64::MAX) — claims mint via a Uint<64> API.
        c.assert(le(amount, u64::MAX));

        // assert(gasLimit > 0)
        c.assert(gas_limit.gt(zero.private()));
    });

    let gas_limit = gas_limit.field();
    let erc20_address = erc20_address.field();
    let amount = amount.field();

    // const caller = disclose(userCommitment(callerSecretKey())) — the SHORT
    // one-block userCommitment (rung 5(i-userCommit), avenue 1).
    let sk = common::witness_sk(c);
    let caller_priv = common::commitment_packed_tag(c, &sk);
    let caller = caller_priv.disclose_as::<DepositorCommitment>(c);

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
    let me = kernel::self_address(c);
    let sender = B32 {
        hi: me.bytes().hi.private(),
        lo: me.bytes().lo.private(),
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

    record_and_notify(
        c,
        one,
        me,
        &request,
        &VAULT.sign_bidirectional_event_map,
        [0, 0, 0, 0],
    );

    Discloses::of(())
}

/// `requestId = disclose(calculateRequestId(request))` +
/// `assert(!map.member(requestId), "Request already exists")`. Returns the
/// disclosed id and its ledger-value form.
fn check_fresh_request<const WORDS: usize, const LEN_OUT: usize, const LEN_RESPOND: usize>(
    c: &mut Circuit3,
    request: &signet::SignBidirectionalEvent<Private, WORDS, LEN_OUT, LEN_RESPOND>,
    map: &LedgerMap<signet::RequestId<Public>, signet::EventRecord<WORDS, LEN_OUT, LEN_RESPOND>>,
) -> signet::RequestId<Public> {
    let request_id_priv = signet::calculate_request_id(c, request);
    c.region("record: freshness", |c| {
        let request_id = request_id_priv.disclose_as::<RequestId>(c);
        let exists = map.member(c, &request_id);
        let fresh = c.not(exists.field());
        c.assert_with(fresh, Some("Request already exists"));
        request_id
    })
}

/// `signetRequestNonce.increment(1)` + `map.insert(requestId,
/// disclose(request))`.
fn insert_request<const WORDS: usize, const LEN_OUT: usize, const LEN_RESPOND: usize>(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    request: &signet::SignBidirectionalEvent<Private, WORDS, LEN_OUT, LEN_RESPOND>,
    map: &LedgerMap<signet::RequestId<Public>, signet::EventRecord<WORDS, LEN_OUT, LEN_RESPOND>>,
    request_id: &signet::RequestId<Public>,
) {
    c.region("record: insert", |c| {
        emit(c, one, &counter_increment(SIGNET_REQUEST_NONCE, 1));
        // The record's atoms come from its TYPE — there is no atom list here
        // to disagree with the one the settle circuits look it up with.
        let record = signet::EventRecord::from_limbs(request.limbs().disclose_as::<RequestRecord>(c));
        map.insert(c, request_id, &record);
    });
}

/// `signetSigner.signBidirectional(requestId,
/// constructSignBidirectionalEventNotificationV1(kernel.self(), 1, path))`
/// — the signer read, the caller's own address, the notification, and the
/// cross-contract call.
fn notify_signet(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    me: ContractAddress<Public>,
    request_id: &signet::RequestId<Public>,
    notify_path: [u8; 4],
) {
    c.region("xcall: notify signet", |c| {
        // compactc evaluates a call's RECEIVER before its argument
        // expressions, so the sealed-cell read is pinned FIRST — exactly
        // where compactc's own stream puts it — rather than resolved
        // inside `call`, which is where Rust's argument-first evaluation
        // would otherwise land it.
        let signer = SignetSigner::at_field(SIGNET_SIGNER).pin(c, one);
        let notification = construct_notification_v1::<Public>(c, &me.bytes(), 1, notify_path);
        signer.sign_bidirectional(c, one, *request_id, notification);
    });
}

/// The contiguous tail deposit/approveRouter share: freshness check,
/// record, notify.
fn record_and_notify<const WORDS: usize, const LEN_OUT: usize, const LEN_RESPOND: usize>(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    me: ContractAddress<Public>,
    request: &signet::SignBidirectionalEvent<Private, WORDS, LEN_OUT, LEN_RESPOND>,
    map: &LedgerMap<signet::RequestId<Public>, signet::EventRecord<WORDS, LEN_OUT, LEN_RESPOND>>,
    notify_path: [u8; 4],
) -> signet::RequestId<Public> {
    let request_id = check_fresh_request(c, request, map);
    insert_request(c, one, request, map, &request_id);
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
    request_id: &signet::RequestId<Private>,
) -> B32<Private> {
    c.region("refund commitment hash", |c| {
        let pad = B32::pad(c, REFUND_PAD);
        let f = c.transient_hash(&[
            pad.hi.private(),
            pad.lo.private(),
            sk.hi,
            sk.lo,
            request_id.bytes().hi,
            request_id.bytes().lo,
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
) -> Discloses<(
    WithdrawnErc20,
    RequestId,
    SurrenderedCoinNonce,
    SurrenderedCoinColor,
    SurrenderedCoinValue,
    RequestRecord,
    WithdrawerRefundCommitment,
    XcallEntryPointHash,
    XcallCommitment,
)> {
    let evm_nonce = evm_nonce.field();
    let key_version = key_version.field();
    let erc20_address = withdraw_request.erc20_address;
    let amount = withdraw_request.amount;
    let dest_evm_address = withdraw_request.dest_evm_address.field();
    let coin_nonce = coin.nonce;
    let coin_color = coin.color;
    let coin_value = coin.value.field();

    let one = c.constant(1u64);
    let zero = c.constant(0u64);

    c.region("guards", |c| {
        assert_initialized(c);
        c.assert(erc20_address.ne(zero.private()));
        c.assert(amount.gt(zero.private()));
        c.assert(le(amount, u64::MAX));
    });

    let erc20_address = erc20_address.field();
    let amount = amount.field();

    // The coin must be the vault token for THIS erc20, of exactly amount.
    let erc20_address = erc20_address.disclose_as::<WithdrawnErc20>(c);
    let domain_sep = vault_token_domain_separator(c, erc20_address);
    // THE kernel.self read of this circuit (rung i): the colour derivation,
    // the event's sender, the receive, the burn and the notification all
    // want the same address, and the port read it five times.
    let me = kernel::self_address(c);
    let color = minocrab_std::v3::token_type(c, &domain_sep, &me.bytes());
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
        hi: me.bytes().hi.private(),
        lo: me.bytes().lo.private(),
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

    let request_id = check_fresh_request(c, &request, &VAULT.sign_bidirectional_event_map);

    // The surrendered value is BURNED (rung vi, avenue 6): a SINGLE claimed
    // shielded spend of the burn-address output — no receive custody claim,
    // no nullifier. See [`common::burn_spend`].
    let coin = minocrab_std::v3::ShieldedCoinInfo3 {
        nonce: coin_nonce.disclose_as::<SurrenderedCoinNonce>(c),
        color: coin_color.disclose_as::<SurrenderedCoinColor>(c),
        value: coin_value.disclose_as::<SurrenderedCoinValue>(c),
    };
    common::burn_spend(c, one, &coin);

    insert_request(
        c,
        one,
        &request,
        &VAULT.sign_bidirectional_event_map,
        &request_id,
    );

    // refundCommitment.insert(requestId,
    //   disclose(withdrawRefundCommitment(callerSecretKey(), requestId)))
    let sk = common::witness_sk(c);
    let rid_priv = request_id.private();
    let rc = withdraw_refund_commitment(c, &sk, &rid_priv);
    let rc = rc.disclose_as::<WithdrawerRefundCommitment>(c);
    VAULT.refund_commitment.insert(c, &request_id, &rc);

    notify_signet(c, one, me, &request_id, [0, 0, 0, 0]);

    Discloses::of(())
}

/// `struct SwapRequest { tokenIn: Bytes<20>, tokenOut: Bytes<20>, fee:
/// Uint<24>, amountOut: Uint<128>, amountInMaximum: Uint<128> }` — the
/// Uniswap `exactOutputSingle` parameters the vault will sign.
#[derive(CircuitArg)]
struct SwapRequest {
    token_in: Bytes<20>,
    token_out: Bytes<20>,
    fee: Uint<24>,
    amount_out: Uint<128>,
    amount_in_maximum: Uint<128>,
}

/// `export circuit swap(evmNonce: Uint<64>, keyVersion: Uint<8>,
/// swapRequest: SwapRequest, coin: ShieldedCoinInfo): []` — starts a swap
/// optimistically: burn the surrendered tokenIn coin (amountInMaximum)
/// and record `exactOutputSingle` on the pinned router, signed with the
/// VAULT's account (swap.zkir; reads: initialized, kernel.self,
/// vaultEvmAddress, evmChainId, uniswapRouter, signetRequestNonce,
/// kernel.self, caip2Id, member(11), kernel.self ×2, signetSigner,
/// kernel.self).
///
/// The parameters after `c` are the Compact parameter list, in declaration
/// order — which is the wire contract.
#[circuit]
pub fn swap(
    c: &mut Circuit3,
    evm_nonce: Uint<64>,
    key_version: Uint<8>,
    swap_request: SwapRequest,
    coin: ShieldedCoinArg,
) -> Discloses<(
    SoldErc20,
    BoughtErc20,
    RequestId,
    SurrenderedCoinNonce,
    SurrenderedCoinColor,
    SurrenderedCoinValue,
    RequestRecord,
    SwapperRefundCommitment,
    XcallEntryPointHash,
    XcallCommitment,
)> {
    let evm_nonce = evm_nonce.field();
    let key_version = key_version.field();
    let token_in = swap_request.token_in.field();
    let token_out = swap_request.token_out.field();
    let fee = swap_request.fee.field();
    let amount_out = swap_request.amount_out;
    let amount_in_max = swap_request.amount_in_maximum;
    let coin_nonce = coin.nonce;
    let coin_color = coin.color;
    let coin_value = coin.value.field();

    let one = c.constant(1u64);
    let zero = c.constant(0u64);

    c.region("guards", |c| {
        assert_initialized(c);
        // `tokenIn`/`tokenOut` are already wires here (the body discloses
        // them next), and an EQUALITY needs no width — so these two are the
        // free-function surface rather than the method one.
        c.assert(ne(token_in, zero.private()));
        c.assert(ne(token_out, zero.private()));
        c.assert(amount_out.gt(zero.private()));
        c.assert(amount_in_max.gt(zero.private()));
        c.assert(le(amount_out, u64::MAX));
        c.assert(le(amount_in_max, u64::MAX));
    });

    let amount_out = amount_out.field();
    let amount_in_max = amount_in_max.field();

    // The surrendered coin must be the vault token for tokenIn, of exactly
    // amountInMaximum.
    let token_in = token_in.disclose_as::<SoldErc20>(c);
    let domain_sep = vault_token_domain_separator(c, token_in);
    // THE kernel.self read of this circuit (rung i) — as in `withdraw`, the
    // port read the same address five times.
    let me = kernel::self_address(c);
    let color = minocrab_std::v3::token_type(c, &domain_sep, &me.bytes());
    let color_hi_ok = c.test_eq(coin_color.hi, color.hi.private());
    let color_lo_ok = c.test_eq(coin_color.lo, color.lo.private());
    let color_ok = c.mul(color_hi_ok, color_lo_ok);
    c.assert(color_ok);
    let value_ok = c.test_eq(coin_value, amount_in_max);
    c.assert(value_ok);

    // exactOutputSingle((tokenIn, tokenOut, fee, vault, amountOut,
    // amountInMaximum, 0)).
    let token_out = token_out.disclose_as::<BoughtErc20>(c);
    let word0 = signet::evm_address_abi_word(c, token_in.private());
    let word1 = signet::evm_address_abi_word(c, token_out.private());
    let word2 = signet::numeric_abi_word(c, fee);
    let vault_evm = cell_read(
        c,
        one,
        VAULT_EVM_ADDRESS,
        vec![AlignmentAtom::Bytes { length: 20 }],
    )[0];
    let word3 = signet::evm_address_abi_word(c, vault_evm.private());
    let word4 = signet::numeric_abi_word(c, amount_out);
    let word5 = signet::numeric_abi_word(c, amount_in_max);
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
        c,
        one,
        EVM_CHAIN_ID,
        vec![AlignmentAtom::Bytes { length: 8 }],
    )[0];
    let router = cell_read(
        c,
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

    let request_nonce = counter_read(c, one, SIGNET_REQUEST_NONCE);
    let sender = B32 {
        hi: me.bytes().hi.private(),
        lo: me.bytes().lo.private(),
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
    let output_schema = BytesN::<Private, SWAP_OUTPUT_LEN>::literal(c, SWAP_OUTPUT_SCHEMA);
    let respond_schema = BytesN::<Private, SWAP_RESPOND_LEN>::literal(c, SWAP_RESPOND_SCHEMA);
    let request: SwapEvent<Private> = signet::construct_sign_bidirectional_event(
        c,
        sender,
        request_nonce.private(),
        key_version,
        path,
        tx_params,
        caip2,
        output_schema,
        respond_schema,
    );

    let request_id = check_fresh_request(c, &request, &VAULT.swap_event_map);

    // Burn the surrendered amountInMaximum of tokenIn (rung vi, avenue 6): a
    // SINGLE claimed shielded spend of the burn-address output — no receive
    // custody claim, no nullifier. See [`common::burn_spend`].
    let coin = minocrab_std::v3::ShieldedCoinInfo3 {
        nonce: coin_nonce.disclose_as::<SurrenderedCoinNonce>(c),
        color: coin_color.disclose_as::<SurrenderedCoinColor>(c),
        value: coin_value.disclose_as::<SurrenderedCoinValue>(c),
    };
    common::burn_spend(c, one, &coin);

    insert_request(c, one, &request, &VAULT.swap_event_map, &request_id);

    // swapRefundCommitment.insert(requestId, disclose(...))
    let sk = common::witness_sk(c);
    let rid_priv = request_id.private();
    let rc = withdraw_refund_commitment(c, &sk, &rid_priv);
    let rc = rc.disclose_as::<SwapperRefundCommitment>(c);
    VAULT.swap_refund_commitment.insert(c, &request_id, &rc);

    notify_signet(c, one, me, &request_id, [11, 0, 0, 0]);

    Discloses::of(())
}

/// `export circuit approveRouter(erc20Address: Bytes<20>, evmNonce:
/// Uint<64>, keyVersion: Uint<8>): []` — records
/// `approve(uniswapRouter, 2^128−1)` on the ERC20, signed with the
/// VAULT's account (path "vault"), contract-fixed gas envelope
/// (approveRouter.zkir; reads: initialized, uniswapRouter, evmChainId,
/// signetRequestNonce, kernel.self, caip2Id, member, signer, self).
///
/// The parameters after `c` are the Compact parameter list, in declaration
/// order — which is the wire contract.
#[circuit]
pub fn approve_router(
    c: &mut Circuit3,
    erc20_address: Bytes<20>,
    evm_nonce: Uint<64>,
    key_version: Uint<8>,
) -> Discloses<(
    ApprovedErc20,
    RequestId,
    RequestRecord,
    XcallEntryPointHash,
    XcallCommitment,
)> {
    let evm_nonce = evm_nonce.field();
    let key_version = key_version.field();

    let one = c.constant(1u64);
    let zero = c.constant(0u64);

    c.region("guards", |c| {
        assert_initialized(c);
        c.assert(erc20_address.ne(zero.private()));
    });

    let erc20_address = erc20_address.field();

    // approve(uniswapRouter, 2^128−1): the spender is the pinned router.
    let router = cell_read(
        c,
        one,
        UNISWAP_ROUTER,
        vec![AlignmentAtom::Bytes { length: 20 }],
    )[0];
    let word0 = signet::evm_address_abi_word(c, router.private());
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
        c,
        one,
        EVM_CHAIN_ID,
        vec![AlignmentAtom::Bytes { length: 8 }],
    )[0];
    let priority_fee = c.constant(1_000_000_000u64);
    let max_fee = c.constant(30_000_000_000u64);
    let gas = c.constant(100_000u64);
    let erc20_address = erc20_address.disclose_as::<ApprovedErc20>(c);
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
    let request_nonce = counter_read(c, one, SIGNET_REQUEST_NONCE);
    // ONE kernel.self read (rung i): sender and callerAddress coincide.
    let me = kernel::self_address(c);
    let sender = B32 {
        hi: me.bytes().hi.private(),
        lo: me.bytes().lo.private(),
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

    record_and_notify(
        c,
        one,
        me,
        &request,
        &VAULT.sign_bidirectional_event_map,
        [0, 0, 0, 0],
    );

    Discloses::of(())
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

/// The settle circuits' shared argument block, as the three of them hand it
/// to [`verify_attestation`]: the request id, the two signature limbs the
/// verification reads, and the mint nonce.
///
/// It is no longer a DECLARER — each settle circuit declares the Compact
/// parameter list itself, through `#[circuit]` — so what is left is the
/// selection those parameters have in common (`respond.bigR.y` and
/// `respond.recoveryId` are part of the wire shape and read by nothing, as
/// in the Compact original).
struct SettleArgs {
    request_id: signet::RequestId<Private>,
    big_r_x: B32<Private>,
    sig_s: B32<Private>,
    mint_nonce: B32<Private>,
}

/// The settle circuits' shared preamble: disclose the request id, gate on
/// initialization, and verify the MPC attestation over the presented
/// output. Returns the disclosed id.
fn verify_attestation<const LEN_OUTPUT: usize>(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    args: &SettleArgs,
    output_limbs: &[Wire3<FieldT, Private>],
) -> signet::RequestId<Public> {
    let request_id = args.request_id.disclose_as::<SettleRequestId>(c);
    assert_initialized(c);
    let mpc_key = common::cell_read_point(c, one, MPC_RESPONSE_KEY);
    let rid_priv = request_id.private();
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
    request_id: &signet::RequestId<Public>,
    ev: &VaultRecord,
    mint_nonce: &B32<Public>,
) {
    // assert(withdrawRefundCommitment(callerSecretKey(), requestId)
    //   == refundCommitment.lookup(requestId), "Not the withdrawer")
    c.region("withdrawer gate", |c| {
        let sk = common::witness_sk(c);
        let rid_priv = request_id.private();
        let rc = withdraw_refund_commitment(c, &sk, &rid_priv);
        let stored = VAULT.refund_commitment.lookup(c, request_id);
        let eq_hi = c.test_eq(rc.hi, stored.hi.private());
        let eq_lo = c.test_eq(rc.lo, stored.lo.private());
        let is_withdrawer = c.mul(eq_hi, eq_lo);
        c.assert_with(is_withdrawer, Some("Not the withdrawer"));
    });

    // assert(signatureRequest.txParams.calldata.is_some)
    c.assert(ev.calldata_is_some());

    // const amount = abiWordToUint128(calldata.words[1])
    let word1 = ev.word(1);
    let amount = signet::abi_word_to_uint128(c, &word1);

    // Re-mint to the withdrawer's own wallet key.
    let domain_sep = vault_token_domain_separator(c, ev.to());
    let own_pk = minocrab_std::v3::own_public_key(c);
    let own_pk = own_pk.disclose_as::<RefundRecipient>(c);
    // The `Uint<64>` claim here is justified by REQUEST-TIME bounds, not
    // locally (notes/api-safety-survey.org §B4's correction) — first in
    // line for `from_field_checked` once there's a spec-anchored artifact.
    common::mint_shielded_token_to_key(c, &domain_sep, Uint::<64, Public>::from_field_unchecked(amount), mint_nonce, &own_pk);
}

/// `export circuit completeWithdraw(requestId, respondBidirectionalEvent,
/// serializedOutput: Bytes<1>, mintNonce): []` — Runtime step 5 of a
/// withdrawal that EXECUTED: verify the attestation, consume the pending
/// withdrawal, and on an attested `false` return re-mint the surrendered
/// value to the withdrawer (completeWithdraw.zkir; reads: initialized,
/// mpcResponseKey, refundCommitment member, event lookup, then the
/// guarded branch's refundCommitment lookup + kernel.self).
///
/// The parameters after `c` are the Compact parameter list, in declaration
/// order — which is the wire contract, with `#[arg(name = "respond")]`
/// keeping the abbreviation the interface snapshot froze (see [`claim`]).
#[circuit]
pub fn complete_withdraw(
    c: &mut Circuit3,
    request_id: signet::RequestId<Private>,
    #[arg(name = "respond")] respond_bidirectional_event: RespondSignature,
    serialized_output: Bytes<1>,
    mint_nonce: B32<Private>,
) -> Discloses<(SettleRequestId, WithdrawalOutcome, RefundMintNonce, RefundRecipient)> {
    let args = SettleArgs {
        request_id,
        big_r_x: respond_bidirectional_event.big_r.x,
        sig_s: respond_bidirectional_event.s,
        mint_nonce,
    };
    let output = [serialized_output.field()];

    let one = c.constant(1u64);

    let request_id = verify_attestation::<1>(c, one, &args, &output);
    // assert(refundCommitment.member(requestId), "Withdrawal not found")
    // const signatureRequest = signBidirectionalEventMap.lookup(requestId);
    // signBidirectionalEventMap.remove(requestId)
    let ev = c.region("event map consume", |c| {
        let pending = VAULT.refund_commitment.member(c, &request_id);
        c.assert_with(pending.field(), Some("Withdrawal not found"));
        let ev = VAULT
            .sign_bidirectional_event_map
            .lookup(c, &request_id);
        VAULT
            .sign_bidirectional_event_map
            .remove(c, &request_id);
        ev
    });

    // const succeeded = disclose(deserialize<VaultResponse, 1>(output).success)
    let succeeded = c.test_eq(output[0], one.private());
    let succeeded = succeeded.disclose_as::<WithdrawalOutcome>(c);

    // if (!succeeded) { refundSurrenderedValue(...) }
    let refunding = c.not(succeeded);
    let mint_nonce = args.mint_nonce.disclose_as::<RefundMintNonce>(c);
    c.when(refunding, |c| {
        refund_surrendered_value(c, &request_id, &ev, &mint_nonce)
    });

    // refundCommitment.remove(requestId)
    VAULT.refund_commitment.remove(c, &request_id);

    Discloses::of(())
}

/// `export circuit completeSwap(requestId, respondBidirectionalEvent,
/// serializedOutput: Bytes<8>, mintNonce): []` — settles a SUCCESSFUL
/// swap: verify the attested amountIn, consume the pending swap
/// (swapper-only), mint the exact amountOut of tokenOut plus the unspent
/// tokenIn as change (completeSwap.zkir; reads: initialized,
/// mpcResponseKey, member(12), lookup(11), lookup(12), kernel.self ×2).
///
/// The parameters after `c` are the Compact parameter list, in declaration
/// order — which is the wire contract (see [`complete_withdraw`] for the
/// `respond` abbreviation).
#[circuit]
pub fn complete_swap(
    c: &mut Circuit3,
    request_id: signet::RequestId<Private>,
    #[arg(name = "respond")] respond_bidirectional_event: RespondSignature,
    serialized_output: Bytes<8>,
    mint_nonce: B32<Private>,
) -> Discloses<(SettleRequestId, SwapRecipient, SwapMintNonce, AttestedAmountIn)> {
    let args = SettleArgs {
        request_id,
        big_r_x: respond_bidirectional_event.big_r.x,
        sig_s: respond_bidirectional_event.s,
        mint_nonce,
    };
    let output = [serialized_output.field()];

    let one = c.constant(1u64);

    let request_id = verify_attestation::<8>(c, one, &args, &output);
    // assert(swapRefundCommitment.member(requestId), "Swap not found")
    // const signatureRequest = swapEventMap.lookup(requestId); remove.
    let ev = c.region("event map consume", |c| {
        let pending = VAULT.swap_refund_commitment.member(c, &request_id);
        c.assert_with(pending.field(), Some("Swap not found"));
        let ev = VAULT.swap_event_map.lookup(c, &request_id);
        VAULT.swap_event_map.remove(c, &request_id);
        ev
    });

    // Swapper gate.
    c.region("swapper gate", |c| {
        let sk = common::witness_sk(c);
        let rid_priv = request_id.private();
        let rc = withdraw_refund_commitment(c, &sk, &rid_priv);
        let stored = VAULT.swap_refund_commitment.lookup(c, &request_id);
        let eq_hi = c.test_eq(rc.hi, stored.hi.private());
        let eq_lo = c.test_eq(rc.lo, stored.lo.private());
        let is_swapper = c.mul(eq_hi, eq_lo);
        c.assert(is_swapper);
        VAULT.swap_refund_commitment.remove(c, &request_id);
    });

    // assert(signatureRequest.txParams.calldata.is_some)
    c.assert(ev.calldata_is_some());
    // ONE kernel.self read for BOTH mints (rung i).
    let me = kernel::self_address(c);
    let recipient = minocrab_std::v3::own_public_key(c);
    let recipient = recipient.disclose_as::<SwapRecipient>(c);

    // Mint the EXACT amountOut of tokenOut: word 4 of tokenOut (word 1).
    let word4 = ev.word(4);
    let amount_out = signet::abi_word_to_uint128(c, &word4);
    let word1 = ev.word(1);
    let token_out = signet::abi_word_low20(c, &word1);
    let ds_out = vault_token_domain_separator(c, token_out);
    let mint_nonce = args.mint_nonce.disclose_as::<SwapMintNonce>(c);
    // The `Uint<64>` claim here is justified by REQUEST-TIME bounds, not
    // locally (notes/api-safety-survey.org §B4's correction) — first in
    // line for `from_field_checked` once there's a spec-anchored artifact.
    common::mint_shielded_token_to_key_with(
        c, one, me, &ds_out, Uint::<64, Public>::from_field_unchecked(amount_out), &mint_nonce, &recipient,
    );

    // Change: amountInMaximum (word 5) − attested amountIn, of tokenIn
    // (word 0), under a nonce derived from mintNonce.
    let amount_in = output[0].disclose_as::<AttestedAmountIn>(c);
    let word5 = ev.word(5);
    let amount_in_max = signet::abi_word_to_uint128(c, &word5);
    // The port's hand-written underflow guard, now the one `Uint::sub` emits
    // — same instructions in the same order at the same width, which is what
    // the unchanged dump proves against compactc's own artifact
    // (notes/api-safety-survey.org §B1).
    let change = Uint::<128, Public>::from_field_unchecked(amount_in_max)
        .sub(c, Uint::<128, Public>::from_field_unchecked(amount_in))
        .field();
    let word0 = ev.word(0);
    let token_in = signet::abi_word_low20(c, &word0);
    let ds_in = vault_token_domain_separator(c, token_in);
    let change_nonce = change_nonce(c, &mint_nonce);
    // The `Uint<64>` claim here is justified by REQUEST-TIME bounds, not
    // locally (notes/api-safety-survey.org §B4's correction) — first in
    // line for `from_field_checked` once there's a spec-anchored artifact.
    common::mint_shielded_token_to_key_with(
        c, one, me, &ds_in, Uint::<64, Public>::from_field_unchecked(change), &change_nonce, &recipient,
    );

    Discloses::of(())
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
        let neg_hi = c.neg(mint_nonce.hi);
        B32 {
            hi: c.add(255u64, neg_hi),
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
///
/// The parameters after `c` are the Compact parameter list, in declaration
/// order — which is the wire contract (see [`complete_withdraw`] for the
/// `respond` abbreviation).
#[circuit]
pub fn refund(
    c: &mut Circuit3,
    request_id: signet::RequestId<Private>,
    #[arg(name = "respond")] respond_bidirectional_event: RespondSignature,
    serialized_output: Bytes<5>,
    mint_nonce: B32<Private>,
) -> Discloses<(SettleRequestId, RefundMintNonce, RefundRecipient)> {
    let args = SettleArgs {
        request_id,
        big_r_x: respond_bidirectional_event.big_r.x,
        sig_s: respond_bidirectional_event.s,
        mint_nonce,
    };
    let output = [serialized_output.field()];

    let one = c.constant(1u64);

    let request_id = verify_attestation::<5>(c, one, &args, &output);
    // assert(serializedOutput == 0xdeadbeef01, "Not the MPC failure output")
    let is_failure = c.test_eq(
        output[0],
        minocrab::Fr::from_le_bytes(&MPC_FAILURE_OUTPUT).unwrap(),
    );
    c.assert(is_failure);

    // Route on which pending marker holds the id (public branch).
    // The member result is already Public; disclosure is the source's
    // explicit `disclose(...)` on the branch condition, a no-op here.
    let is_withdrawal = VAULT
        .refund_commitment
        .member(c, &request_id)
        .field();
    let swapping = c.not(is_withdrawal);
    // ONE UNGUARDED kernel.self read dominating both branches (rung i).
    // Exactly one branch runs, so the transcript still carries exactly one
    // kernel.self answer — but the circuit now carries one read, not two.
    let me = kernel::self_address(c);
    let mint_nonce = args.mint_nonce.disclose_as::<RefundMintNonce>(c);

    // Withdrawal-route record consume (guarded): the VaultRecord and its
    // removal from the request map.
    let ev = c.region("event map consume", |c| {
        let ev = VAULT
            .sign_bidirectional_event_map
            .lookup_guarded(c, is_withdrawal, &request_id).or_default();
        VAULT
            .sign_bidirectional_event_map
            .remove_under(c, is_withdrawal, &request_id);
        ev
    });

    // Swap-route record consume (guarded): the pending-swap marker assert,
    // the SwapRecord, and its removal from the swap request map.
    let ev7 = c.region("event map consume", |c| {
        let swap_pending = VAULT
            .swap_refund_commitment
            .member_guarded(c, swapping, &request_id).or_default()
            .field();
        common::assert_if(c, swapping, swap_pending);
        let ev7 = VAULT
            .swap_event_map
            .lookup_guarded(c, swapping, &request_id).or_default();
        VAULT.swap_event_map.remove_under(c, swapping, &request_id);
        ev7
    });

    // Unified claimant gate (avenue 4): the refund commitment is computed
    // ONCE, and the expected value is `cond_select`ed from the route's own
    // commitment map — see the circuit doc comment for why this is exactly
    // the port's per-route authorisation.
    c.region("claimant gate", |c| {
        let sk = common::witness_sk(c);
        let rid_priv = request_id.private();
        let rc = withdraw_refund_commitment(c, &sk, &rid_priv);
        let wd_stored = VAULT
            .refund_commitment
            .lookup_guarded(c, is_withdrawal, &request_id).or_default();
        let sw_stored = VAULT
            .swap_refund_commitment
            .lookup_guarded(c, swapping, &request_id).or_default();
        let stored_hi = c.cond_select(is_withdrawal, wd_stored.hi, sw_stored.hi);
        let stored_lo = c.cond_select(is_withdrawal, wd_stored.lo, sw_stored.lo);
        let eq_hi = c.test_eq(rc.hi, stored_hi.private());
        let eq_lo = c.test_eq(rc.lo, stored_lo.private());
        let is_claimant = c.mul(eq_hi, eq_lo);
        c.assert(is_claimant);
    });

    // The commitment-map removes, guarded per route (ledger EFFECT ops).
    VAULT
        .refund_commitment
        .remove_under(c, is_withdrawal, &request_id);
    VAULT
        .swap_refund_commitment
        .remove_under(c, swapping, &request_id);

    // Unified re-mint (avenue 4): cond_select the branch-varying token and
    // amount, then run ONE domainSep → tokenType → coinCommitment → mint.
    // The withdrawal route mints `abiWordToUint128(word1)` of the record's
    // `to` token; the swap route mints `abiWordToUint128(word5)` (the
    // surrendered amountInMaximum) of `word0`'s low-20 token. The unused
    // decode is guarded off (no canonicity assert on the garbage record) or
    // assert-free (`abi_word_low20`).
    common::assert_if(c, is_withdrawal, ev.calldata_is_some());
    common::assert_if(c, swapping, ev7.calldata_is_some());
    let word1 = ev.word(1);
    let amount_wd = signet::abi_word_to_uint128_guarded(c, is_withdrawal, &word1);
    let word5 = ev7.word(5);
    let amount_sw = signet::abi_word_to_uint128_guarded(c, swapping, &word5);
    let amount = c.cond_select(is_withdrawal, amount_wd, amount_sw);
    let word0 = ev7.word(0);
    let token_sw = signet::abi_word_low20(c, &word0);
    let token = c.cond_select(is_withdrawal, ev.to(), token_sw);
    let domain_sep = vault_token_domain_separator(c, token);
    let own_pk = minocrab_std::v3::own_public_key(c);
    let own_pk = own_pk.disclose_as::<RefundRecipient>(c);
    // The `Uint<64>` claim here is justified by REQUEST-TIME bounds, not
    // locally (notes/api-safety-survey.org §B4's correction) — first in
    // line for `from_field_checked` once there's a spec-anchored artifact.
    common::mint_shielded_token_to_key_with(
        c, one, me, &domain_sep, Uint::<64, Public>::from_field_unchecked(amount), &mint_nonce, &own_pk,
    );

    Discloses::of(())
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
    request_id: signet::RequestId<Private>,
    #[arg(name = "respond")] respond_bidirectional_event: RespondSignature,
    serialized_output: Bytes<1>,
    mint_nonce: B32<Private>,
    recipient: Maybe<Either<B32<Private>, B32<Private>>>,
) -> Discloses<(
    ClaimRequestId,
    ClaimRecipientTag,
    ClaimRecipientSide,
    ClaimRecipientOwnKey,
    ClaimRecipientKey,
    ClaimRecipientContract,
    ClaimMintNonce,
)> {
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

    // const disclosedRequestId = disclose(requestId)
    let request_id = request_id.disclose_as::<ClaimRequestId>(c);

    // assert(initialized >= 1, "Not initialized")
    assert_initialized(c);

    // const response = deserialize<VaultResponse, 1>(serializedOutput);
    // assert(response.success) — the packed Boolean is (byte == 1).
    let success = c.test_eq(serialized_output, one.private());
    c.assert(success);

    // assert(verifyRespondBidirectionalEvent<1>(requestId,
    //   serializedOutput, event, mpcResponseKey))
    let mpc_key = common::cell_read_point(c, one, MPC_RESPONSE_KEY);
    let rid_priv = request_id.private();
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
    let ev = c.region("event map consume", |c| {
        let found = VAULT
            .sign_bidirectional_event_map
            .member(c, &request_id);
        c.assert(found.field());
        let ev = VAULT
            .sign_bidirectional_event_map
            .lookup(c, &request_id);
        VAULT
            .sign_bidirectional_event_map
            .remove(c, &request_id);
        ev
    });

    // Depositor gate: userCommitment(callerSecretKey()) == request.path — the
    // SHORT one-block userCommitment (rung 5(i-userCommit), avenue 1).
    c.region("depositor gate", |c| {
        let sk = common::witness_sk(c);
        let caller = common::commitment_packed_tag(c, &sk);
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
        let rec_is_some = rec_is_some.disclose_as::<ClaimRecipientTag>(c);
        let rec_is_left = rec_is_left.disclose_as::<ClaimRecipientSide>(c);
        let not_some = c.not(rec_is_some);
        let own_pk = own_public_key_guarded(c, not_some).or_default();
        let own_pk = own_pk.disclose_as::<ClaimRecipientOwnKey>(c);
        let rec_left = rec_left.disclose_as::<ClaimRecipientKey>(c);
        let rec_right = rec_right.disclose_as::<ClaimRecipientContract>(c);
        let is_left = c.cond_select(rec_is_some, rec_is_left, one);
        let left = B32 {
            hi: c.cond_select(rec_is_some, rec_left.hi, own_pk.hi),
            lo: c.cond_select(rec_is_some, rec_left.lo, own_pk.lo),
        };
        let right = B32 {
            hi: c.cond_select(rec_is_some, rec_right.hi, 0u64),
            lo: c.cond_select(rec_is_some, rec_right.lo, 0u64),
        };
        CoinRecipient { is_left, left, right }
    });

    // mintShieldedToken(domainSep, amount as Uint<64>, disclose(mintNonce),
    //   claimRecipient)
    let mint_nonce = mint_nonce.disclose_as::<ClaimMintNonce>(c);
    // The `Uint<64>` claim here is justified by REQUEST-TIME bounds, not
    // locally (notes/api-safety-survey.org §B4's correction) — first in
    // line for `from_field_checked` once there's a spec-anchored artifact.
    common::mint_shielded_token(c, one, &domain_sep, Uint::<64, Public>::from_field_unchecked(amount), &mint_nonce, &recipient);

    Discloses::of(())
}
