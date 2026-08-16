//! `erc20-vault`, THE SHOWCASE TWIN (M9 phase 8) — the fourth artifact.
//!
//! The same contract as [`crate::erc20_vault_borsh`], written the way the M9
//! API wants it written. It exists BESIDE the three direct ports, not instead
//! of them: `erc20_vault` is the compatibility reference (byte-identical to
//! nothing but PI-equal to compactc), `erc20_vault_opt` carries M10's
//! measured row work, `erc20_vault_borsh` carries M11's wire format — and all
//! three are pinned to a stream, so every ergonomic spelling that moves an
//! instruction is unavailable to them. This one is pinned to a STATEMENT
//! instead, and that is the whole point of it.
//!
//! WHAT MAKES THAT HONEST rather than a demo (notes/contract-api.org
//! §"Showcase twin"): the equivalence criterion this project has used since
//! M3 is the typed I/O schema plus `pis`/`pi_skips` on a shared
//! `ProofPreimage` — the INSTRUCTION STREAM is free. So the twin is checked
//! against the borsh fork on exactly that criterion (`tests/
//! erc20_vault_modern_fork.rs`: same preimage, same PI vector, byte-different
//! stream, asserted in both directions per circuit), and against the spec
//! harness at scale like every other artifact (`Art::Modern` in
//! `tests/vault/`), with its own row and interface snapshot entries and its
//! deltas reported rather than hidden.
//!
//! WHAT IS IMPORTED, exactly as at the two earlier forks: the protocol
//! constants, the ledger block [`VAULT`], the record types, the Borsh
//! response types of M11 stage 5, and the shared helpers (`common`,
//! `signet`). Copied: the nine circuit functions and the private helpers they
//! call, which is what makes this a fork of the BORSH artifact and not of the
//! port.
//!
//! # What the modern spelling is
//!
//! | phase | in the ports | here |
//! |-------|--------------|------|
//! | 4 | `#[circuit]` + derived argument structs | the same — the ports are already modern here |
//! | 6 | `-> Discloses<(..)>` + `.disclose_as::<L>(c)` | the same |
//! | 7 | `#[derive(Ledger)]`, `map.member(c, one, &k)` | `map.member(c, &k)` — no `one`, anywhere |
//! | 7 | `cell_read(c, one, CAIP2_ID, vec![atom])` | `VAULT.caip2_id.read(c)` — a `B32<Public>`, atoms from the type |
//! | 7 | `c.assert(x.gt(0u64).message(..))` | the same, plus [`is_true`] and `.when(guard)` for the boolean and in-branch checks the ports had to spell as `assert_with`/`assert_if` |
//! | 8 | `common::cell_read_point(c, one, MPC_RESPONSE_KEY)` | `VAULT.mpc_response_key.read(c)` — a typed `Secp256k1Point` |
//!
//! The visible consequences: no LEDGER operation in this file takes a guard,
//! there is not one `AlignmentAtom`, `LedgerValue` or field-index constant in
//! it, and `minocrab_ledger` is imported for `kernel_self` alone. What still
//! names a `let one = c.constant(1u64)` is the two places a `1` is a VALUE
//! rather than a guard — a limb of the signed transaction record
//! (`calldata_is_some`) and of a coin commitment (`shieldedBurnAddress()`'s
//! `is_left`) — plus the cross-contract call, whose guard is still a wire
//! because M12's calling layer takes one (recorded for dmd; widening it is
//! the same zero-cost change phase 8 made to the ledger ops).
//!
//! # What it deliberately does NOT change
//!
//! The semantics. Every guard, every effect, every disclosure and every
//! transcript read is the borsh fork's, in the borsh fork's order — which is
//! what lets the shared reference model build ONE preimage that both
//! artifacts accept, and lets `Art::Modern` reuse every `Art::Borsh` arm of
//! the spec's concretization. A twin that also changed the contract would
//! prove nothing about the API.

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Private, Public};
// The ONLY ledger import: `kernel.self()` is a context read, not a field of
// this contract's ledger block, so it has no typed slot to live on.
use minocrab_ledger::{XcallCommitment, XcallEntryPointHash};
// `CircuitBorsh` names both the trait and the derive macro (different
// namespaces, one path), as `serde::Serialize` does.
use minocrab_std::v3::kernel;
use minocrab_std::v3::borsh::{CircuitBorsh, Tag};
use minocrab_std::v3::{
    circuit, eq, is_true, label, not, own_public_key, own_public_key_guarded, Bool, Bytes, BytesN,
    Check, CircuitArg, CoinRecipient, Disclose, Discloses, Either, LedgerMap, LedgerRepr, Maybe,
    Secp256k1Point, Uint, B32,
};

use signet_signer_interface::notification::construct_notification_v1;
use signet_signer_interface::SignetSigner;

use crate::common;
// The protocol constants and the ledger block. The field-index constants the
// three ports still need are NOT here: every ledger operation in this file
// goes through `VAULT`'s typed slots, so the only index in the file is the
// sealed signer handle's, which the interface crate takes.
use crate::erc20_vault::{
    SwapEvent, VaultEvent, VaultRecord, APPROVE_SELECTOR, EXACT_OUTPUT_SINGLE_SELECTOR, REFUND_PAD,
    SIGNET_SIGNER, SWAP_OUTPUT_LEN, SWAP_OUTPUT_SCHEMA, SWAP_RESPOND_LEN, SWAP_RESPOND_SCHEMA,
    SWAP_WORDS, TRANSFER_SELECTOR, VAULT, VAULT_PATH, VAULT_RESPONSE_SCHEMA, VAULT_SCHEMA_LEN,
    VAULT_WORDS,
};
// The wire format is M11 stage 5's, imported rather than restated: the twin
// changes how the contract is WRITTEN, never what it says on the wire.
pub use crate::erc20_vault_borsh::{
    FailureResponse, SwapResponse, VaultResponse, RESPONSE_KINDS, RESPONSE_KIND_CLAIM,
    RESPONSE_KIND_FAILURE, RESPONSE_KIND_SWAP, RESPONSE_KIND_WITHDRAW, VAULT_TOKEN_TAG,
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
    // NOTHING is unwrapped here. The arguments stay TYPED all the way to the
    // ledger: the guards read their widths off the types, and the writes read
    // their FAB atoms off the same types (`vaultEvmAddress` is a
    // `LedgerCell<Bytes<20, Public>>`, so `Bytes<20>` is what it takes).

    // assert(initialized == 0, "Already initialized")
    c.region("initialized gate", |c| {
        let count = VAULT.initialized.read(c);
        c.assert(count.eq(0u64).message("Already initialized"));
    });

    // assert(userCommitment(callerSecretKey()) == deployer, "Not the deployer")
    // — the SHORT one-block userCommitment (rung 5(i-userCommit), avenue 1).
    c.region("deployer gate", assert_deployer);

    // assert(chainId > 0 as Uint<64>, "Chain ID must be positive")
    c.assert(chain_id.gt(0u64).message("Chain ID must be positive"));

    // assert(swapRouter as Field != 0 as Field, "Router cannot be zero")
    c.assert(swap_router.ne(0u64).message("Router cannot be zero"));

    // initialized.increment(1)
    VAULT.initialized.increment(c, 1);

    // The five configuration writes, in source order. Each is one line
    // because the slot knows the type and the type knows its atoms.
    c.region("configuration writes", |c| {
        let vault_evm = vault_evm.disclose_as::<VaultEvmAddress>(c);
        VAULT.vault_evm_address.write(c, &vault_evm);

        let swap_router = swap_router.disclose_as::<UniswapRouter>(c);
        VAULT.uniswap_router.write(c, &swap_router);

        let chain_id = chain_id.disclose_as::<EvmChainId>(c);
        VAULT.evm_chain_id.write(c, &chain_id);

        let caip2 = chain_caip2_id.disclose_as::<Caip2Id>(c);
        VAULT.caip2_id.write(c, &caip2);

        let response_key = response_key.disclose_as::<MpcResponseKey>(c);
        VAULT.mpc_response_key.write(c, &response_key);
    });

    Discloses::of(())
}

/// `assert(initialized >= 1, "Not initialized")` — a Counter read + `0 <
/// initialized`.
fn assert_initialized(c: &mut Circuit3) {
    let init = VAULT.initialized.read(c);
    c.assert(init.gt(0u64).message("Not initialized"));
}

/// `assert(userCommitment(callerSecretKey()) == deployer, "Not the deployer")`
/// — the SHORT one-block userCommitment (rung 5(i-userCommit), avenue 1).
///
/// The ports call `common::assert_deployer_short`, which takes the field
/// INDEX and a guard wire. Here the deployer is a typed cell, so the gate is
/// the read and the predicate.
fn assert_deployer(c: &mut Circuit3) {
    let sk = common::witness_sk(c);
    let digest = common::commitment_packed_tag(c, &sk);
    let stored = VAULT.deployer.read(c);
    c.assert(b32_eq(&digest, &stored.private()).message("Not the deployer"));
}

/// `a == b` on a `Bytes<32>` pair, as ONE predicate: two `test_eq`s and the
/// `mul` that ands them — the same three instructions the ports write out,
/// with the difference that the result can carry a message and compose
/// (`.when(guard)` for the in-branch gates below).
///
/// An equality needs no width, which is why both sides may be raw limbs.
fn b32_eq(a: &B32<Private>, b: &B32<Private>) -> Check<Private> {
    eq(a.hi, b.hi).and(eq(a.lo, b.lo))
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
    // The two field constants this circuit needs as WIRES: they are limbs of
    // the signed transaction record, not operands, so an immediate will not
    // do. Everything else that used to want a `one` — every ledger operation
    // — takes none.
    let one = c.constant(1u64);
    let zero = c.constant(0u64);

    c.region("guards", |c| {
        // assert(initialized >= 1, "Not initialized")
        assert_initialized(c);
        // assert(erc20Address as Field != 0)
        c.assert(deposit_request.erc20_address.ne(0u64));
        // assert(amount > 0)
        c.assert(deposit_request.amount.gt(0u64));
        // assert(amount <= u64::MAX) — claims mint via a Uint<64> API.
        c.assert(deposit_request.amount.le(u64::MAX));
        // assert(gasLimit > 0)
        c.assert(gas_limit.gt(0u64));
    });

    let erc20_address = deposit_request.erc20_address.field();
    let amount = deposit_request.amount.field();

    // const caller = disclose(userCommitment(callerSecretKey())) — the SHORT
    // one-block userCommitment (rung 5(i-userCommit), avenue 1).
    let sk = common::witness_sk(c);
    let caller_priv = common::commitment_packed_tag(c, &sk);
    let caller = caller_priv.disclose_as::<DepositorCommitment>(c);

    // Contract-enforced calldata: transfer(vaultEvmAddress, amount).
    let vault_evm = VAULT.vault_evm_address.read(c);
    let word0 = signet::evm_address_abi_word(c, vault_evm.field().private());
    let word1 = signet::numeric_abi_word(c, amount);
    let selector = c.constant(minocrab::Fr::from_le_bytes(&TRANSFER_SELECTOR).unwrap());
    let two = c.constant(2u64);
    let calldata = signet::EvmCalldata::<Private, VAULT_WORDS> {
        selector: selector.private(),
        no_words: two.private(),
        words: [word0, word1],
    };

    // The full transaction the MPC will sign. The gas envelope is the
    // CALLER's here (a deposit spends the depositor's EVM account), which is
    // why this is the one circuit that does not use [`FixedGas`].
    let tx_params = signet::EvmType2TxParams::<Private, VAULT_WORDS> {
        chain_id: VAULT.evm_chain_id.read(c).field().private(),
        nonce: evm_nonce.field(),
        max_priority_fee_per_gas: max_priority_fee_per_gas.field(),
        max_fee_per_gas: max_fee_per_gas.field(),
        gas_limit: gas_limit.field(),
        to: erc20_address,
        value: zero.private(),
        calldata_is_some: one.private(),
        calldata,
        access_list_entry_count: zero.private(),
    };

    // constructSignBidirectionalEvent(kernel.self(), requestNonce,
    // keyVersion, caller, ecdsa, unused, pad(64, ""), evmType2, txParams,
    // caip2Id, schema, schema)
    let request_nonce = VAULT.signet_request_nonce.read(c);
    // ONE kernel.self read: the event's sender and the notification's
    // callerAddress are the same address (rung i).
    let me = kernel::self_address(c).bytes();
    let caip2 = VAULT.caip2_id.read(c);
    let schema = BytesN::<Private, VAULT_SCHEMA_LEN>::literal(c, VAULT_RESPONSE_SCHEMA);
    let request: VaultEvent<Private> = signet::construct_sign_bidirectional_event(
        c,
        me.private(),
        request_nonce.field().private(),
        key_version.field(),
        caller.private(),
        tx_params,
        caip2.private(),
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

/// `kernel.self()` as a `Bytes<32>` — the one ledger read with no typed slot
/// to hang off, since it reads the transaction CONTEXT rather than a field of
/// this contract.
///
/// The gas limit of a vault-signed ERC-20 call (`transfer`, `approve`).
const ERC20_CALL_GAS: u64 = 100_000;

/// The gas limit of a vault-signed Uniswap `exactOutputSingle`.
const SWAP_GAS: u64 = 700_000;

/// The contract-FIXED gas envelope every vault-signed transaction carries,
/// as a const-generic family: the priority fee and the fee cap are the same
/// in all three of `withdraw`, `swap` and `approveRouter`, and the LIMIT is
/// the only thing that differs (100,000 for an ERC-20 call, 700,000 for a
/// Uniswap swap).
///
/// A Rust `const` parameter is the right shape for it because the value is
/// part of the CONTRACT, not of the call: `FixedGas::<700_000>` names the
/// swap envelope once, and a circuit cannot accidentally pass a caller-chosen
/// limit where a fixed one belongs. Zero cost — the three `Copy`s are the
/// same three the ports emit, in the same order.
struct FixedGas<const LIMIT: u64>;

impl<const LIMIT: u64> FixedGas<LIMIT> {
    /// The vault's standard priority fee, 1 gwei.
    const PRIORITY_FEE: u64 = 1_000_000_000;
    /// The vault's standard fee cap, 30 gwei.
    const MAX_FEE: u64 = 30_000_000_000;

    /// `(maxPriorityFeePerGas, maxFeePerGas, gasLimit)` as private wires, in
    /// the order the ports emit them.
    fn wires(c: &mut Circuit3) -> [Wire3<FieldT, Private>; 3] {
        let priority_fee = c.constant(Self::PRIORITY_FEE);
        let max_fee = c.constant(Self::MAX_FEE);
        let gas = c.constant(LIMIT);
        [
            priority_fee.private(),
            max_fee.private(),
            gas.private(),
        ]
    }
}

/// `requestId = disclose(calculateRequestId(request))` +
/// `assert(!map.member(requestId), "Request already exists")`. Returns the
/// disclosed id.
///
/// No `one` and no `map_field: u8`: the map is the typed slot itself, and
/// `member` is straight-line. The freshness check is a PREDICATE now — the
/// ports have to drop to `c.assert_with(fresh, Some(..))`, because a map
/// `member` result is a boolean rather than a comparison, which is exactly
/// the gap [`is_true`] closes.
fn check_fresh_request<const WORDS: usize, const LEN_OUT: usize, const LEN_RESPOND: usize>(
    c: &mut Circuit3,
    request: &signet::SignBidirectionalEvent<Private, WORDS, LEN_OUT, LEN_RESPOND>,
    map: &LedgerMap<B32<Public>, signet::EventRecord<WORDS, LEN_OUT, LEN_RESPOND>>,
) -> B32<Public> {
    let request_id_priv = signet::calculate_request_id(c, request);
    c.region("record: freshness", |c| {
        let request_id = request_id_priv.disclose_as::<RequestId>(c);
        let exists = map.member(c, &request_id);
        c.assert(not(is_true(exists)).message("Request already exists"));
        request_id
    })
}

/// `signetRequestNonce.increment(1)` + `map.insert(requestId,
/// disclose(request))`.
fn insert_request<const WORDS: usize, const LEN_OUT: usize, const LEN_RESPOND: usize>(
    c: &mut Circuit3,
    request: &signet::SignBidirectionalEvent<Private, WORDS, LEN_OUT, LEN_RESPOND>,
    map: &LedgerMap<B32<Public>, signet::EventRecord<WORDS, LEN_OUT, LEN_RESPOND>>,
    request_id: &B32<Public>,
) {
    c.region("record: insert", |c| {
        VAULT.signet_request_nonce.increment(c, 1);
        // The record's atoms come from its TYPE — there is no atom list here
        // to disagree with the one the settle circuits look it up with.
        let record =
            signet::EventRecord::from_limbs(request.limbs().disclose_as::<RequestRecord>(c));
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
    me: B32<Public>,
    request_id: &B32<Public>,
    notify_path: [u8; 4],
) {
    c.region("xcall: notify signet", |c| {
        // compactc evaluates a call's RECEIVER before its argument
        // expressions, so the sealed-cell read is pinned FIRST — exactly
        // where compactc's own stream puts it — rather than resolved
        // inside `call`, which is where Rust's argument-first evaluation
        // would otherwise land it.
        let signer = SignetSigner::at_field(SIGNET_SIGNER).pin(c, one);
        let notification = construct_notification_v1::<Public>(c, &me, 1, notify_path);
        signer.sign_bidirectional(c, one, *request_id, notification);
    });
}

/// The contiguous tail deposit/approveRouter share: freshness check,
/// record, notify.
fn record_and_notify<const WORDS: usize, const LEN_OUT: usize, const LEN_RESPOND: usize>(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    me: B32<Public>,
    request: &signet::SignBidirectionalEvent<Private, WORDS, LEN_OUT, LEN_RESPOND>,
    map: &LedgerMap<B32<Public>, signet::EventRecord<WORDS, LEN_OUT, LEN_RESPOND>>,
    notify_path: [u8; 4],
) -> B32<Public> {
    let request_id = check_fresh_request(c, request, map);
    insert_request(c, request, map, &request_id);
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
    let one = c.constant(1u64);
    let zero = c.constant(0u64);

    c.region("guards", |c| {
        assert_initialized(c);
        c.assert(withdraw_request.erc20_address.ne(0u64));
        c.assert(withdraw_request.amount.gt(0u64));
        c.assert(withdraw_request.amount.le(u64::MAX));
    });

    let amount = withdraw_request.amount.field();

    // The coin must be the vault token for THIS erc20, of exactly amount.
    let erc20_address = withdraw_request
        .erc20_address
        .field()
        .disclose_as::<WithdrawnErc20>(c);
    let domain_sep = vault_token_domain_separator(c, erc20_address);
    // THE kernel.self read of this circuit (rung i): the colour derivation,
    // the event's sender, the receive, the burn and the notification all
    // want the same address, and the port read it five times.
    let me = kernel::self_address(c).bytes();
    let color = minocrab_std::v3::token_type(c, &domain_sep, &me);
    c.assert(b32_eq(&coin.color, &color.private()));
    c.assert(eq(coin.value.field(), amount));

    // Contract-enforced calldata: transfer(destEvmAddress, amount).
    let word0 = signet::evm_address_abi_word(c, withdraw_request.dest_evm_address.field());
    let word1 = signet::numeric_abi_word(c, amount);
    let selector = c.constant(minocrab::Fr::from_le_bytes(&TRANSFER_SELECTOR).unwrap());
    let two = c.constant(2u64);
    let calldata = signet::EvmCalldata::<Private, VAULT_WORDS> {
        selector: selector.private(),
        no_words: two.private(),
        words: [word0, word1],
    };

    // Contract-FIXED gas envelope (the vault's account pays).
    let chain_id = VAULT.evm_chain_id.read(c);
    let [priority_fee, max_fee, gas] = FixedGas::<ERC20_CALL_GAS>::wires(c);
    let tx_params = signet::EvmType2TxParams::<Private, VAULT_WORDS> {
        chain_id: chain_id.field().private(),
        nonce: evm_nonce.field(),
        max_priority_fee_per_gas: priority_fee,
        max_fee_per_gas: max_fee,
        gas_limit: gas,
        to: erc20_address.private(),
        value: zero.private(),
        calldata_is_some: one.private(),
        calldata,
        access_list_entry_count: zero.private(),
    };

    // The event, keyed under the vault's OWN derivation path.
    let request_nonce = VAULT.signet_request_nonce.read(c);
    let caip2 = VAULT.caip2_id.read(c);
    let path = B32::pad(c, VAULT_PATH).private();
    let schema = BytesN::<Private, VAULT_SCHEMA_LEN>::literal(c, VAULT_RESPONSE_SCHEMA);
    let request: VaultEvent<Private> = signet::construct_sign_bidirectional_event(
        c,
        me.private(),
        request_nonce.field().private(),
        key_version.field(),
        path,
        tx_params,
        caip2.private(),
        schema.clone(),
        schema,
    );

    let request_id = check_fresh_request(c, &request, &VAULT.sign_bidirectional_event_map);

    // The surrendered value is BURNED (rung vi, avenue 6): a SINGLE claimed
    // shielded spend of the burn-address output — no receive custody claim,
    // no nullifier. See [`common::burn_spend`].
    let coin = minocrab_std::v3::ShieldedCoinInfo3 {
        nonce: coin.nonce.disclose_as::<SurrenderedCoinNonce>(c),
        color: coin.color.disclose_as::<SurrenderedCoinColor>(c),
        value: coin.value.field().disclose_as::<SurrenderedCoinValue>(c),
    };
    common::burn_spend(c, one, &coin);

    insert_request(c, &request, &VAULT.sign_bidirectional_event_map, &request_id);

    // refundCommitment.insert(requestId,
    //   disclose(withdrawRefundCommitment(callerSecretKey(), requestId)))
    let sk = common::witness_sk(c);
    let rc = withdraw_refund_commitment(c, &sk, &request_id.private());
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
    let one = c.constant(1u64);
    let zero = c.constant(0u64);

    c.region("guards", |c| {
        assert_initialized(c);
        c.assert(swap_request.token_in.ne(0u64));
        c.assert(swap_request.token_out.ne(0u64));
        c.assert(swap_request.amount_out.gt(0u64));
        c.assert(swap_request.amount_in_maximum.gt(0u64));
        c.assert(swap_request.amount_out.le(u64::MAX));
        c.assert(swap_request.amount_in_maximum.le(u64::MAX));
    });

    let amount_out = swap_request.amount_out.field();
    let amount_in_max = swap_request.amount_in_maximum.field();

    // The surrendered coin must be the vault token for tokenIn, of exactly
    // amountInMaximum.
    let token_in = swap_request.token_in.field().disclose_as::<SoldErc20>(c);
    let domain_sep = vault_token_domain_separator(c, token_in);
    // THE kernel.self read of this circuit (rung i) — as in `withdraw`, the
    // port read the same address five times.
    let me = kernel::self_address(c).bytes();
    let color = minocrab_std::v3::token_type(c, &domain_sep, &me);
    c.assert(b32_eq(&coin.color, &color.private()));
    c.assert(eq(coin.value.field(), amount_in_max));

    // exactOutputSingle((tokenIn, tokenOut, fee, vault, amountOut,
    // amountInMaximum, 0)).
    let token_out = swap_request.token_out.field().disclose_as::<BoughtErc20>(c);
    let word0 = signet::evm_address_abi_word(c, token_in.private());
    let word1 = signet::evm_address_abi_word(c, token_out.private());
    let word2 = signet::numeric_abi_word(c, swap_request.fee.field());
    let vault_evm = VAULT.vault_evm_address.read(c);
    let word3 = signet::evm_address_abi_word(c, vault_evm.field().private());
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
    let chain_id = VAULT.evm_chain_id.read(c);
    let router = VAULT.uniswap_router.read(c);
    let [priority_fee, max_fee, gas] = FixedGas::<SWAP_GAS>::wires(c);
    let tx_params = signet::EvmType2TxParams::<Private, SWAP_WORDS> {
        chain_id: chain_id.field().private(),
        nonce: evm_nonce.field(),
        max_priority_fee_per_gas: priority_fee,
        max_fee_per_gas: max_fee,
        gas_limit: gas,
        to: router.field().private(),
        value: zero.private(),
        calldata_is_some: one.private(),
        calldata,
        access_list_entry_count: zero.private(),
    };

    let request_nonce = VAULT.signet_request_nonce.read(c);
    let caip2 = VAULT.caip2_id.read(c);
    let path = B32::pad(c, VAULT_PATH).private();
    let output_schema = BytesN::<Private, SWAP_OUTPUT_LEN>::literal(c, SWAP_OUTPUT_SCHEMA);
    let respond_schema = BytesN::<Private, SWAP_RESPOND_LEN>::literal(c, SWAP_RESPOND_SCHEMA);
    let request: SwapEvent<Private> = signet::construct_sign_bidirectional_event(
        c,
        me.private(),
        request_nonce.field().private(),
        key_version.field(),
        path,
        tx_params,
        caip2.private(),
        output_schema,
        respond_schema,
    );

    let request_id = check_fresh_request(c, &request, &VAULT.swap_event_map);

    // Burn the surrendered amountInMaximum of tokenIn (rung vi, avenue 6): a
    // SINGLE claimed shielded spend of the burn-address output — no receive
    // custody claim, no nullifier. See [`common::burn_spend`].
    let coin = minocrab_std::v3::ShieldedCoinInfo3 {
        nonce: coin.nonce.disclose_as::<SurrenderedCoinNonce>(c),
        color: coin.color.disclose_as::<SurrenderedCoinColor>(c),
        value: coin.value.field().disclose_as::<SurrenderedCoinValue>(c),
    };
    common::burn_spend(c, one, &coin);

    insert_request(c, &request, &VAULT.swap_event_map, &request_id);

    // swapRefundCommitment.insert(requestId, disclose(...))
    let sk = common::witness_sk(c);
    let rc = withdraw_refund_commitment(c, &sk, &request_id.private());
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
    let one = c.constant(1u64);
    let zero = c.constant(0u64);

    c.region("guards", |c| {
        assert_initialized(c);
        c.assert(erc20_address.ne(0u64));
    });

    // approve(uniswapRouter, 2^128−1): the spender is the pinned router.
    let router = VAULT.uniswap_router.read(c);
    let word0 = signet::evm_address_abi_word(c, router.field().private());
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
    let chain_id = VAULT.evm_chain_id.read(c);
    let [priority_fee, max_fee, gas] = FixedGas::<ERC20_CALL_GAS>::wires(c);
    let erc20_address = erc20_address.field().disclose_as::<ApprovedErc20>(c);
    let tx_params = signet::EvmType2TxParams::<Private, VAULT_WORDS> {
        chain_id: chain_id.field().private(),
        nonce: evm_nonce.field(),
        max_priority_fee_per_gas: priority_fee,
        max_fee_per_gas: max_fee,
        gas_limit: gas,
        to: erc20_address.private(),
        value: zero.private(),
        calldata_is_some: one.private(),
        calldata,
        access_list_entry_count: zero.private(),
    };

    // Signed by the VAULT account: path = pad(32, "vault").
    let request_nonce = VAULT.signet_request_nonce.read(c);
    // ONE kernel.self read (rung i): sender and callerAddress coincide.
    let me = kernel::self_address(c).bytes();
    let caip2 = VAULT.caip2_id.read(c);
    let path = B32::pad(c, VAULT_PATH).private();
    let schema = BytesN::<Private, VAULT_SCHEMA_LEN>::literal(c, VAULT_RESPONSE_SCHEMA);
    let request: VaultEvent<Private> = signet::construct_sign_bidirectional_event(
        c,
        me.private(),
        request_nonce.field().private(),
        key_version.field(),
        path,
        tx_params,
        caip2.private(),
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

/// `assert(response.kind == expected)` — the anti-replay check, once per
/// settle circuit.
///
/// This is also what discharges the tag's Borsh canonicity bound: equality
/// with a specific variant is strictly stronger than `tag < K`, so
/// `CircuitBorsh::constrain_canonical`'s `less_than` is NOT emitted on top of
/// it (the byte-width constraint that the digest's injectivity needs is
/// emitted by `CircuitArg::constrain`, with every other argument). Every
/// settle circuit accepts exactly one kind, so there is no site where the
/// weaker bound would be the right one.
fn assert_kind(c: &mut Circuit3, kind: Tag<RESPONSE_KINDS>, expected: u32) {
    c.assert(eq(kind.field(), u64::from(expected)).message("Wrong response kind"));
}

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
    request_id: B32<Private>,
    big_r_x: B32<Private>,
    sig_s: B32<Private>,
    mint_nonce: B32<Private>,
}

/// The settle circuits' shared preamble: disclose the request id, gate on
/// initialization, and verify the MPC attestation over the presented typed
/// output. Returns the disclosed id.
///
/// SOUNDNESS, in four lines (notes/borsh-format.org §"The deserializer"): the
/// Borsh packing is injective on range-constrained inputs (disjoint powers of
/// 256); the MPC signed the digest of the packed bytes; this circuit
/// constrains the bytes to BE the serialization of the declared fields, with
/// the fields in range (`settle_args` emits the argument constraints, and the
/// keccak chip's own per-limb byte decomposition enforces the widths a second
/// time); therefore the fields ARE what the MPC encoded. Declaring the fields
/// and running the serializer forwards is the whole deserialization — which is
/// why no vault circuit uses `BorshReader`.
fn verify_attestation<T: CircuitBorsh<Private>>(
    c: &mut Circuit3,
    args: &SettleArgs,
    output: &T,
) -> B32<Public> {
    let request_id = args.request_id.disclose_as::<SettleRequestId>(c);
    assert_initialized(c);
    // The MPC key is a TYPED cell (M9 phase 8): one `Secp256k1Point`, not a
    // field index plus a hand-written five-atom list plus an `encode` at the
    // call site. `LedgerRepr for Secp256k1Point` owns that shape.
    let mpc_key = VAULT.mpc_response_key.read(c);
    let valid = signet::verify_respond_bidirectional_event_borsh(
        c,
        &request_id.private(),
        output,
        &args.big_r_x,
        &args.sig_s,
        mpc_key.point().private(),
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
    request_id: &B32<Public>,
    ev: &VaultRecord,
    mint_nonce: &B32<Public>,
) {
    // assert(withdrawRefundCommitment(callerSecretKey(), requestId)
    //   == refundCommitment.lookup(requestId), "Not the withdrawer")
    c.region("withdrawer gate", |c| {
        let sk = common::witness_sk(c);
        let rc = withdraw_refund_commitment(c, &sk, &request_id.private());
        let stored = VAULT.refund_commitment.lookup(c, request_id);
        // The AMBIENT guard is the in-branch assert: this whole function runs
        // inside `c.when(refunding, ..)`, so the condition binds only where
        // the branch is taken and nothing here names the guard.
        c.assert(b32_eq(&rc, &stored.private()).message("Not the withdrawer"));
    });

    // assert(signatureRequest.txParams.calldata.is_some)
    c.assert(is_true(Bool::from_field(ev.calldata_is_some())));

    // const amount = abiWordToUint128(calldata.words[1])
    let word1 = ev.word(1);
    let amount = signet::abi_word_to_uint128(c, &word1);

    // Re-mint to the withdrawer's own wallet key.
    let domain_sep = vault_token_domain_separator(c, ev.to());
    let own_pk = own_public_key(c);
    let own_pk = own_pk.disclose_as::<RefundRecipient>(c);
    common::mint_shielded_token_to_key(c, &domain_sep, amount, mint_nonce, &own_pk);
}

/// `export circuit completeWithdraw(requestId, respondBidirectionalEvent,
/// serializedOutput: VaultResponse, mintNonce): []` — Runtime step 5 of a
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
    request_id: B32<Private>,
    #[arg(name = "respond")] respond_bidirectional_event: RespondSignature,
    serialized_output: VaultResponse,
    mint_nonce: B32<Private>,
) -> Discloses<(SettleRequestId, WithdrawalOutcome, RefundMintNonce, RefundRecipient)> {
    let args = SettleArgs {
        request_id,
        big_r_x: respond_bidirectional_event.big_r.x,
        sig_s: respond_bidirectional_event.s,
        mint_nonce,
    };
    let output = serialized_output;

    let request_id = verify_attestation(c, &args, &output);
    assert_kind(c, output.kind, RESPONSE_KIND_WITHDRAW);
    // assert(refundCommitment.member(requestId), "Withdrawal not found")
    // const signatureRequest = signBidirectionalEventMap.lookup(requestId);
    // signBidirectionalEventMap.remove(requestId)
    let ev = c.region("event map consume", |c| {
        let pending = VAULT.refund_commitment.member(c, &request_id);
        c.assert(is_true(pending).message("Withdrawal not found"));
        let ev = VAULT.sign_bidirectional_event_map.lookup(c, &request_id);
        VAULT.sign_bidirectional_event_map.remove(c, &request_id);
        ev
    });

    // const succeeded = disclose(output.success) — a Borsh `bool` IS the
    // branch condition, so there is no `== 1` test to get wrong: the wire is
    // 0 or 1 by `assert_boolean` (emitted with the argument constraints), and
    // anything else makes the transaction unprovable instead of routing it to
    // the refund branch. THIS is the 0x02 hazard closing.
    let succeeded = output.success.field().disclose_as::<WithdrawalOutcome>(c);

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
/// serializedOutput: SwapResponse, mintNonce): []` — settles a SUCCESSFUL
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
    request_id: B32<Private>,
    #[arg(name = "respond")] respond_bidirectional_event: RespondSignature,
    serialized_output: SwapResponse,
    mint_nonce: B32<Private>,
) -> Discloses<(SettleRequestId, SwapRecipient, SwapMintNonce, AttestedAmountIn)> {
    let args = SettleArgs {
        request_id,
        big_r_x: respond_bidirectional_event.big_r.x,
        sig_s: respond_bidirectional_event.s,
        mint_nonce,
    };
    let output = serialized_output;

    let request_id = verify_attestation(c, &args, &output);
    assert_kind(c, output.kind, RESPONSE_KIND_SWAP);
    // assert(swapRefundCommitment.member(requestId), "Swap not found")
    // const signatureRequest = swapEventMap.lookup(requestId); remove.
    let ev = c.region("event map consume", |c| {
        let pending = VAULT.swap_refund_commitment.member(c, &request_id);
        c.assert(is_true(pending).message("Swap not found"));
        let ev = VAULT.swap_event_map.lookup(c, &request_id);
        VAULT.swap_event_map.remove(c, &request_id);
        ev
    });

    // Swapper gate.
    c.region("swapper gate", |c| {
        let sk = common::witness_sk(c);
        let rc = withdraw_refund_commitment(c, &sk, &request_id.private());
        let stored = VAULT.swap_refund_commitment.lookup(c, &request_id);
        c.assert(b32_eq(&rc, &stored.private()).message("Not the swapper"));
        VAULT.swap_refund_commitment.remove(c, &request_id);
    });

    // assert(signatureRequest.txParams.calldata.is_some)
    c.assert(ev.calldata_is_some());
    // ONE kernel.self read for BOTH mints (rung i).
    let me = kernel::self_address(c).bytes();
    let recipient = own_public_key(c).disclose_as::<SwapRecipient>(c);

    // Mint the EXACT amountOut of tokenOut: word 4 of tokenOut (word 1).
    let word4 = ev.word(4);
    let amount_out = signet::abi_word_to_uint128(c, &word4);
    let word1 = ev.word(1);
    let token_out = signet::abi_word_low20(c, &word1);
    let ds_out = vault_token_domain_separator(c, token_out);
    let mint_nonce = args.mint_nonce.disclose_as::<SwapMintNonce>(c);
    common::mint_shielded_token_to_key_with(
        c, 1u64, me, &ds_out, amount_out, &mint_nonce, &recipient,
    );

    // Change: amountInMaximum (word 5) − attested amountIn, of tokenIn
    // (word 0), under a nonce derived from mintNonce.
    let amount_in = output.amount_in.field().disclose_as::<AttestedAmountIn>(c);
    let word5 = ev.word(5);
    let amount_in_max = signet::abi_word_to_uint128(c, &word5);
    // The subtraction's guard, and the most dangerous arithmetic in the
    // contract: the attested spend cannot exceed what was surrendered.
    // Both sides are `Uint<128>` by construction (`abiWordToUint128`), so
    // the 128 is the TYPE's, not a number typed at the call site.
    let amount_in_max_u = Uint::<128, Public>::from_field(amount_in_max);
    let amount_in_u = Uint::<128, Public>::from_field(amount_in);
    c.assert(
        amount_in_u
            .le(amount_in_max_u)
            .message("Attested amountIn exceeds amountInMaximum"),
    );
    let neg_in = c.neg(amount_in);
    let change = c.add(amount_in_max, neg_in);
    let word0 = ev.word(0);
    let token_in = signet::abi_word_low20(c, &word0);
    let ds_in = vault_token_domain_separator(c, token_in);
    let change_nonce = change_nonce(c, &mint_nonce);
    common::mint_shielded_token_to_key_with(
        c, 1u64, me, &ds_in, change, &change_nonce, &recipient,
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
/// serializedOutput: FailureResponse, mintNonce): []` — settles a withdrawal
/// OR swap whose transaction NEVER EXECUTED (the MPC attested the FAILURE
/// KIND), routing on which pending marker holds the id.
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
    request_id: B32<Private>,
    #[arg(name = "respond")] respond_bidirectional_event: RespondSignature,
    serialized_output: FailureResponse,
    mint_nonce: B32<Private>,
) -> Discloses<(SettleRequestId, RefundMintNonce, RefundRecipient)> {
    let args = SettleArgs {
        request_id,
        big_r_x: respond_bidirectional_event.big_r.x,
        sig_s: respond_bidirectional_event.s,
        mint_nonce,
    };
    let output = serialized_output;

    let request_id = verify_attestation(c, &args, &output);
    // assert(serializedOutput.kind == FAILURE, "Not the MPC failure output")
    // — the same single equality the 5-byte `0xdeadbeef01` sentinel bought,
    // against a byte that means the same thing in every response type.
    assert_kind(c, output.kind, RESPONSE_KIND_FAILURE);

    // Route on which pending marker holds the id (public branch).
    // The member result is already Public; disclosure is the source's
    // explicit `disclose(...)` on the branch condition, a no-op here.
    let is_withdrawal = VAULT.refund_commitment.member(c, &request_id).field();
    let swapping = c.not(is_withdrawal);
    // ONE UNGUARDED kernel.self read dominating both branches (rung i).
    // Exactly one branch runs, so the transcript still carries exactly one
    // kernel.self answer — but the circuit now carries one read, not two.
    let me = kernel::self_address(c).bytes();
    let mint_nonce = args.mint_nonce.disclose_as::<RefundMintNonce>(c);

    // Withdrawal-route record consume (guarded): the VaultRecord and its
    // removal from the request map.
    let ev = c.region("event map consume", |c| {
        let ev = VAULT
            .sign_bidirectional_event_map
            .lookup_guarded(c, is_withdrawal, &request_id);
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
            .member_guarded(c, swapping, &request_id);
        c.assert(is_true(swap_pending).when(swapping).message("Swap not found"));
        let ev7 = VAULT.swap_event_map.lookup_guarded(c, swapping, &request_id);
        VAULT.swap_event_map.remove_under(c, swapping, &request_id);
        ev7
    });

    // Unified claimant gate (avenue 4): the refund commitment is computed
    // ONCE, and the expected value is `cond_select`ed from the route's own
    // commitment map — see the circuit doc comment for why this is exactly
    // the port's per-route authorisation.
    c.region("claimant gate", |c| {
        let sk = common::witness_sk(c);
        let rc = withdraw_refund_commitment(c, &sk, &request_id.private());
        let wd_stored = VAULT
            .refund_commitment
            .lookup_guarded(c, is_withdrawal, &request_id);
        let sw_stored = VAULT
            .swap_refund_commitment
            .lookup_guarded(c, swapping, &request_id);
        let stored = B32::cond_select(c, is_withdrawal, &wd_stored, &sw_stored);
        c.assert(b32_eq(&rc, &stored.private()).message("Not the claimant"));
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
    c.assert(is_true(Bool::from_field(ev.calldata_is_some())).when(is_withdrawal));
    c.assert(is_true(Bool::from_field(ev7.calldata_is_some())).when(swapping));
    let word1 = ev.word(1);
    let amount_wd = signet::abi_word_to_uint128_guarded(c, is_withdrawal, &word1);
    let word5 = ev7.word(5);
    let amount_sw = signet::abi_word_to_uint128_guarded(c, swapping, &word5);
    let amount = c.cond_select(is_withdrawal, amount_wd, amount_sw);
    let word0 = ev7.word(0);
    let token_sw = signet::abi_word_low20(c, &word0);
    let token = c.cond_select(is_withdrawal, ev.to(), token_sw);
    let domain_sep = vault_token_domain_separator(c, token);
    let own_pk = own_public_key(c).disclose_as::<RefundRecipient>(c);
    common::mint_shielded_token_to_key_with(
        c, 1u64, me, &domain_sep, amount, &mint_nonce, &own_pk,
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
/// RespondBidirectionalEvent, serializedOutput: VaultResponse, mintNonce:
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
    serialized_output: VaultResponse,
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

    let one = c.constant(1u64);

    // const disclosedRequestId = disclose(requestId)
    let request_id = request_id.disclose_as::<ClaimRequestId>(c);

    // assert(initialized >= 1, "Not initialized")
    assert_initialized(c);

    // assert(serializedOutput.kind == CLAIM) — the response was issued for a
    // deposit, not for a withdrawal, a swap or a failure.
    assert_kind(c, serialized_output.kind, RESPONSE_KIND_CLAIM);

    // assert(serializedOutput.success) — the wire is a Borsh `bool`, so
    // `assert_boolean` (emitted with the argument constraints) has already
    // ruled out every byte but 0 and 1 and this is the whole check. The port
    // spells the same thing `byte == 1`, which is where its 0x02 hazard lives.
    c.assert(is_true(serialized_output.success).message("The MPC attested a failure"));

    // assert(verifyRespondBidirectionalEvent(requestId, serializedOutput,
    //   event, mpcResponseKey))
    let mpc_key = VAULT.mpc_response_key.read(c);
    let valid = signet::verify_respond_bidirectional_event_borsh(
        c,
        &request_id.private(),
        &serialized_output,
        &big_r_x,
        &sig_s,
        mpc_key.point().private(),
    );
    c.assert(valid);

    // Double-claim protection: member + lookup + remove.
    let ev = c.region("event map consume", |c| {
        let found = VAULT.sign_bidirectional_event_map.member(c, &request_id);
        c.assert(is_true(found).message("Request not found"));
        let ev = VAULT.sign_bidirectional_event_map.lookup(c, &request_id);
        VAULT.sign_bidirectional_event_map.remove(c, &request_id);
        ev
    });

    // Depositor gate: userCommitment(callerSecretKey()) == request.path — the
    // SHORT one-block userCommitment (rung 5(i-userCommit), avenue 1).
    c.region("depositor gate", |c| {
        let sk = common::witness_sk(c);
        let caller = common::commitment_packed_tag(c, &sk);
        c.assert(b32_eq(&caller, &ev.path().private()).message("Not the depositor"));
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
        let rec_is_some = recipient
            .is_some
            .field()
            .disclose_as::<ClaimRecipientTag>(c);
        let rec_is_left = recipient
            .value
            .is_left
            .field()
            .disclose_as::<ClaimRecipientSide>(c);
        let not_some = c.not(rec_is_some);
        let own_pk = own_public_key_guarded(c, not_some).disclose_as::<ClaimRecipientOwnKey>(c);
        let rec_left = recipient.value.left.disclose_as::<ClaimRecipientKey>(c);
        let rec_right = recipient
            .value
            .right
            .disclose_as::<ClaimRecipientContract>(c);
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
    common::mint_shielded_token(c, one, &domain_sep, amount, &mint_nonce, &recipient);

    Discloses::of(())
}
