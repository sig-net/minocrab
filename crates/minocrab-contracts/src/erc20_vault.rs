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

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Alignment, AlignmentAtom, AlignmentSegment, Private, Public};
use minocrab_ledger::{
    cell_read, cell_write, counter_increment, counter_read, emit, ImpactElem,
    LedgerValue, XcallCommitment, XcallEntryPointHash,
};
use minocrab_std::v3::kernel;
use minocrab_std::v3::{
    CoinColor, CoinNonce, TokenDomainSeparator,
    circuit, label, le, ne, own_public_key_guarded, Bytes, BytesN, CircuitArg, CoinRecipient,
    Disclose, Discloses, Either, Ledger, LedgerCell, LedgerCounter, LedgerField,
    LedgerMap, LedgerRepr, Maybe, Secp256k1Point, Uint, B32,
};

use signet_signer_interface::notification::construct_notification_v1;
use signet_signer_interface::SignetSigner;

use crate::common;
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
    SwapRefundRecipient = "own public key as swap-refund recipient";
    ClaimRequestId = "claim request id";
    ClaimRecipientTag = "claim recipient tag";
    ClaimRecipientSide = "claim recipient side";
    ClaimRecipientOwnKey = "own public key as claim recipient";
    ClaimRecipientKey = "claim recipient key";
    ClaimRecipientContract = "claim recipient contract";
    ClaimMintNonce = "claim mint nonce";
}

/// THE LEDGER BLOCK — the Compact `export ledger` declarations above, as
/// types. Declaration order IS the field index, so the numbering is stated
/// once, here, by the order the fields are written; `#[derive(Ledger)]`
/// turns it into `Vault::new()`, whose whole body is `<FieldTy>::at(i)`.
///
/// The typed slots also carry what the value IS: a
/// `LedgerMap<signet::RequestId<Public>, VaultRecord>` knows the key's and the record's
/// FAB atoms, so no call site writes an atom list, and a lookup hands back a
/// `VaultRecord` rather than a `Vec` of limbs the caller must interpret.
/// [`LedgerField`] is the honest spelling for the one field this layer does
/// not model — `signetSigner`, a sealed handle read through the interface
/// crate's own `SignetSigner::at_field` rather than as a value. (The
/// curve-point cell and the sealed `deployer` were `LedgerField`s until M9
/// phase 8 gave `LedgerRepr` a `&mut Circuit3`; the direct ports still call
/// `common::cell_read_point` and `common::assert_deployer_short`, which take
/// a raw index, so the derived index constants below stay.)
///
/// All three forks share this block: the vault's state layout is its wire
/// contract, so `erc20_vault_opt` and `erc20_vault_borsh` IMPORT [`VAULT`]
/// rather than re-declaring it, exactly as they import the record types.
#[derive(Ledger)]
pub struct Vault {
    pub sign_bidirectional_event_map: LedgerMap<signet::RequestId<Public>, VaultRecord>,
    /// `sealed ledger signetSigner: SignetSigner` — read through the
    /// interface crate's own `SignetSigner::at_field`.
    pub signet_signer: LedgerField,
    /// `export ledger mpcResponseKey: Secp256k1Point` — a curve-point cell,
    /// whose limbs are produced by an `encode` INSTRUCTION rather than read
    /// off the value. Typed since M9 phase 8: `LedgerRepr for Secp256k1Point`
    /// owns both directions of that crossing, so the cell is an ordinary
    /// [`LedgerCell`] and only the direct ports still spell the ops out
    /// (`common::cell_read_point`).
    pub mpc_response_key: LedgerCell<Secp256k1Point<Public>>,
    pub signet_request_nonce: LedgerCounter,
    pub initialized: LedgerCounter,
    pub vault_evm_address: LedgerCell<Bytes<20, Public>>,
    pub evm_chain_id: LedgerCell<Uint<64, Public>>,
    pub caip2_id: LedgerCell<common::Caip2Id<Public>>,
    /// `sealed ledger deployer: Bytes<32>`. Sealed means write-once at
    /// deployment; the READ is an ordinary cell read, so the slot is typed.
    pub deployer: LedgerCell<common::UserCommitment<Public>>,
    pub refund_commitment: LedgerMap<signet::RequestId<Public>, common::RefundCommitment<Public>>,
    pub uniswap_router: LedgerCell<Bytes<20, Public>>,
    pub swap_event_map: LedgerMap<signet::RequestId<Public>, SwapRecord>,
    pub swap_refund_commitment: LedgerMap<signet::RequestId<Public>, common::RefundCommitment<Public>>,
}

/// The vault's ledger block. A `const`: the whole thing is field indices, so
/// it exists at compile time and costs nothing at run time.
pub const VAULT: Vault = Vault::new();

/// Ledger field indices, in declaration order — now READ OFF [`VAULT`], so
/// the index a call site uses and the field it was declared as cannot drift.
/// They remain `pub const u8`s because the ledger operations this layer does
/// not model yet (the point cell, the sealed cells, `cell_read`/`cell_write`)
/// still take a raw index, and the reference model in `tests/vault` keys its
/// state by it.
pub const SIGN_BIDIRECTIONAL_EVENT_MAP: u8 = VAULT.sign_bidirectional_event_map.index();
pub const SIGNET_SIGNER: u8 = VAULT.signet_signer.index();
pub const MPC_RESPONSE_KEY: u8 = VAULT.mpc_response_key.index();
pub const SIGNET_REQUEST_NONCE: u8 = VAULT.signet_request_nonce.index();
pub const INITIALIZED: u8 = VAULT.initialized.index();
pub const VAULT_EVM_ADDRESS: u8 = VAULT.vault_evm_address.index();
pub const EVM_CHAIN_ID: u8 = VAULT.evm_chain_id.index();
pub const CAIP2_ID: u8 = VAULT.caip2_id.index();
pub const DEPLOYER: u8 = VAULT.deployer.index();
pub const REFUND_COMMITMENT: u8 = VAULT.refund_commitment.index();
pub const UNISWAP_ROUTER: u8 = VAULT.uniswap_router.index();
pub const SWAP_EVENT_MAP: u8 = VAULT.swap_event_map.index();
pub const SWAP_REFUND_COMMITMENT: u8 = VAULT.swap_refund_commitment.index();

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

/// The ABI word counts of the two calldata shapes the vault signs:
/// `transfer`/`approve` take (address, uint256), `exactOutputSingle` takes
/// the seven-field struct.
pub const VAULT_WORDS: usize = 2;
pub const SWAP_WORDS: usize = 7;

/// The schema widths ARE the schema literals' lengths, so an event type
/// and the schema bytes it carries cannot drift apart.
pub const VAULT_SCHEMA_LEN: usize = VAULT_RESPONSE_SCHEMA.len();
pub const SWAP_OUTPUT_LEN: usize = SWAP_OUTPUT_SCHEMA.len();
pub const SWAP_RESPOND_LEN: usize = SWAP_RESPOND_SCHEMA.len();

/// The vault's two Signet event instantiations: the transfer/approve
/// request recorded in `signBidirectionalEventMap`, and the swap request
/// recorded in `swapEventMap`.
pub type VaultEvent<V> =
    signet::SignBidirectionalEvent<V, VAULT_WORDS, VAULT_SCHEMA_LEN, VAULT_SCHEMA_LEN>;
pub type SwapEvent<V> =
    signet::SignBidirectionalEvent<V, SWAP_WORDS, SWAP_OUTPUT_LEN, SWAP_RESPOND_LEN>;

/// The same two records read back out of their maps by the settle
/// circuits — distinct types, so `refund`'s two branches cannot cross.
pub type VaultRecord = signet::EventRecord<VAULT_WORDS, VAULT_SCHEMA_LEN, VAULT_SCHEMA_LEN>;
pub type SwapRecord = signet::EventRecord<SWAP_WORDS, SWAP_OUTPUT_LEN, SWAP_RESPOND_LEN>;

pub use crate::common::secp256k1_point_atoms;

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
    c.region("deployer gate", |c| {
        common::assert_deployer(c, one, USER_PAD, DEPLOYER);
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

    // const caller = disclose(userCommitment(callerSecretKey()))
    let sk = common::witness_sk(c);
    let caller_priv = common::commitment_padded_tag(c, USER_PAD, &sk);
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
    let sender = kernel::self_address(c).private();
    let caip2 = cell_read(
        c,
        one,
        CAIP2_ID,
        vec![AlignmentAtom::Bytes { length: 32 }],
    );
    let caip2 = common::Caip2Id(B32 {
        hi: caip2[0].private(),
        lo: caip2[1].private(),
    });
    let schema = BytesN::<Private, VAULT_SCHEMA_LEN>::literal(c, VAULT_RESPONSE_SCHEMA);
    let request: VaultEvent<Private> = signet::construct_sign_bidirectional_event(
        c,
        sender,
        request_nonce.private(),
        key_version,
        common::SigningPath::from(caller.private()),
        tx_params,
        caip2,
        schema.clone(),
        schema,
    );

    record_and_notify(
        c,
        one,
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
        let me = kernel::self_address(c);
        let notification =
            construct_notification_v1::<Public>(c, &me.bytes(), 1, notify_path);
        signer.sign_bidirectional(c, one, *request_id, notification);
    });
}

/// The contiguous tail deposit/approveRouter share: freshness check,
/// record, notify.
fn record_and_notify<const WORDS: usize, const LEN_OUT: usize, const LEN_RESPOND: usize>(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    request: &signet::SignBidirectionalEvent<Private, WORDS, LEN_OUT, LEN_RESPOND>,
    map: &LedgerMap<signet::RequestId<Public>, signet::EventRecord<WORDS, LEN_OUT, LEN_RESPOND>>,
    notify_path: [u8; 4],
) -> signet::RequestId<Public> {
    let request_id = check_fresh_request(c, request, map);
    insert_request(c, one, request, map, &request_id);
    notify_signet(c, one, &request_id, notify_path);
    request_id
}

/// `withdrawRefundCommitment(sk, requestId)` —
/// `persistentHash<Vector<3, Bytes<32>>>([pad(32, "vault:refund:"), sk,
/// requestId])`.
fn withdraw_refund_commitment(
    c: &mut Circuit3,
    sk: &common::SecretKey<Private>,
    request_id: &signet::RequestId<Private>,
) -> common::RefundCommitment<Private> {
    let sk = sk.bytes();
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
                request_id.bytes().hi.erase(),
                request_id.bytes().lo.erase(),
            ],
        );
        common::RefundCommitment(B32::from_typed(c, digest))
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
    nonce: CoinNonce<Private>,
    color: CoinColor<Private>,
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
    let me = kernel::self_address(c);
    let color = minocrab_std::v3::token_type(c, &domain_sep, &me.bytes());
    let color_hi_ok = c.test_eq(coin_color.bytes().hi, color.bytes().hi.private());
    let color_lo_ok = c.test_eq(coin_color.bytes().lo, color.bytes().lo.private());
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
    let sender = kernel::self_address(c).private();
    let caip2 = cell_read(
        c,
        one,
        CAIP2_ID,
        vec![AlignmentAtom::Bytes { length: 32 }],
    );
    let caip2 = common::Caip2Id(B32 {
        hi: caip2[0].private(),
        lo: caip2[1].private(),
    });
    let path = common::SigningPath::vault_path(c).private();
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

    // The surrendered value is BURNED: receiveShielded (custody) then
    // sendImmediateShielded to the burn address.
    let coin = minocrab_std::v3::ShieldedCoinInfo3 {
        nonce: coin_nonce.disclose_as::<SurrenderedCoinNonce>(c),
        color: coin_color.disclose_as::<SurrenderedCoinColor>(c),
        value: coin_value.disclose_as::<SurrenderedCoinValue>(c),
    };
    common::receive_shielded(c, one, &coin);
    common::burn_coin(c, one, &coin);

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

    notify_signet(c, one, &request_id, [0, 0, 0, 0]);

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
    let me = kernel::self_address(c);
    let color = minocrab_std::v3::token_type(c, &domain_sep, &me.bytes());
    let color_hi_ok = c.test_eq(coin_color.bytes().hi, color.bytes().hi.private());
    let color_lo_ok = c.test_eq(coin_color.bytes().lo, color.bytes().lo.private());
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
    let sender = kernel::self_address(c).private();
    let caip2 = cell_read(
        c,
        one,
        CAIP2_ID,
        vec![AlignmentAtom::Bytes { length: 32 }],
    );
    let caip2 = common::Caip2Id(B32 {
        hi: caip2[0].private(),
        lo: caip2[1].private(),
    });
    let path = common::SigningPath::vault_path(c).private();
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

    // Burn the surrendered amountInMaximum of tokenIn.
    let coin = minocrab_std::v3::ShieldedCoinInfo3 {
        nonce: coin_nonce.disclose_as::<SurrenderedCoinNonce>(c),
        color: coin_color.disclose_as::<SurrenderedCoinColor>(c),
        value: coin_value.disclose_as::<SurrenderedCoinValue>(c),
    };
    common::receive_shielded(c, one, &coin);
    common::burn_coin(c, one, &coin);

    insert_request(c, one, &request, &VAULT.swap_event_map, &request_id);

    // swapRefundCommitment.insert(requestId, disclose(...))
    let sk = common::witness_sk(c);
    let rid_priv = request_id.private();
    let rc = withdraw_refund_commitment(c, &sk, &rid_priv);
    let rc = rc.disclose_as::<SwapperRefundCommitment>(c);
    VAULT.swap_refund_commitment.insert(c, &request_id, &rc);

    notify_signet(c, one, &request_id, [11, 0, 0, 0]);

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
    let sender = kernel::self_address(c).private();
    let caip2 = cell_read(
        c,
        one,
        CAIP2_ID,
        vec![AlignmentAtom::Bytes { length: 32 }],
    );
    let caip2 = common::Caip2Id(B32 {
        hi: caip2[0].private(),
        lo: caip2[1].private(),
    });
    let path = common::SigningPath::vault_path(c).private();
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
        &request,
        &VAULT.sign_bidirectional_event_map,
        [0, 0, 0, 0],
    );

    Discloses::of(())
}

/// `vaultTokenDomainSeparator(erc20Address)` —
/// `persistentHash<Vector<2, Bytes<32>>>([pad(32, "erc20:vault:"),
/// erc20Address as Field as Bytes<32>])`. The address is a `Bytes<20>`
/// limb, so its `Bytes<32>` rendering is `[hi: 0, lo: addr]`.
fn vault_token_domain_separator(
    c: &mut Circuit3,
    erc20_address: Wire3<FieldT, Public>,
) -> TokenDomainSeparator<Public> {
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
        TokenDomainSeparator(B32::from_typed(c, digest))
    })
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
    request_id: signet::RequestId<Private>,
    big_r_x: B32<Private>,
    sig_s: B32<Private>,
    mint_nonce: CoinNonce<Private>,
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
        &signet::Secp256k1SigLimbs { big_r_x: args.big_r_x, s: args.sig_s },
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
    request_id: &signet::RequestId<Public>,
    ev: &VaultRecord,
    mint_nonce: &CoinNonce<Public>,
) {
    // assert(withdrawRefundCommitment(callerSecretKey(), requestId)
    //   == refundCommitment.lookup(requestId), "Not the withdrawer")
    c.region("withdrawer gate", |c| {
        let sk = common::witness_sk(c);
        let rid_priv = request_id.private();
        let rc = withdraw_refund_commitment(c, &sk, &rid_priv);
        let stored = VAULT.refund_commitment.lookup(c, request_id);
        let eq_hi = c.test_eq(rc.bytes().hi, stored.bytes().hi.private());
        let eq_lo = c.test_eq(rc.bytes().lo, stored.bytes().lo.private());
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
    mint_nonce: CoinNonce<Private>,
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
    mint_nonce: CoinNonce<Private>,
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
        let eq_hi = c.test_eq(rc.bytes().hi, stored.bytes().hi.private());
        let eq_lo = c.test_eq(rc.bytes().lo, stored.bytes().lo.private());
        let is_swapper = c.mul(eq_hi, eq_lo);
        c.assert(is_swapper);
        VAULT.swap_refund_commitment.remove(c, &request_id);
    });

    // assert(signatureRequest.txParams.calldata.is_some)
    c.assert(ev.calldata_is_some());
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
    common::mint_shielded_token_to_key(c, &ds_out, Uint::<64, Public>::from_field_unchecked(amount_out), &mint_nonce, &recipient);

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
    // changeNonce = persistentHash([mintNonce, pad(32, "change")])
    let change_pad = B32::pad(c, "change");
    let alignment = Alignment(vec![
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
    ]);
    let change_nonce = c.persistent_hash(
        alignment,
        &[
            mint_nonce.bytes().hi.erase(),
            mint_nonce.bytes().lo.erase(),
            change_pad.hi.erase(),
            change_pad.lo.erase(),
        ],
    );
    let change_nonce = CoinNonce(B32::from_typed(c, change_nonce));
    // The `Uint<64>` claim here is justified by REQUEST-TIME bounds, not
    // locally (notes/api-safety-survey.org §B4's correction) — first in
    // line for `from_field_checked` once there's a spec-anchored artifact.
    common::mint_shielded_token_to_key(c, &ds_in, Uint::<64, Public>::from_field_unchecked(change), &change_nonce, &recipient);

    Discloses::of(())
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
    mint_nonce: CoinNonce<Private>,
) -> Discloses<(SettleRequestId, RefundMintNonce, RefundRecipient, SwapRefundRecipient)> {
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
    let mint_nonce = args.mint_nonce.disclose_as::<RefundMintNonce>(c);

    // Withdrawal branch: completeWithdraw's failure path verbatim. The whole
    // branch is ONE scope, so the reads, the witnesses and the asserts inside
    // it carry `is_withdrawal` without any of them naming it.
    c.when(is_withdrawal, |c| {
        let ev = c.region("event map consume", |c| {
            let ev = VAULT.sign_bidirectional_event_map.lookup(c, &request_id);
            VAULT.sign_bidirectional_event_map.remove(c, &request_id);
            ev
        });
        refund_surrendered_value(c, &request_id, &ev, &mint_nonce);
        VAULT.refund_commitment.remove(c, &request_id);
    });

    // Swap branch: re-mint the surrendered amountInMaximum of tokenIn.
    let swapping = c.not(is_withdrawal);
    c.when(swapping, |c| {
        let ev7 = c.region("event map consume", |c| {
            let swap_pending = VAULT.swap_refund_commitment.member(c, &request_id);
            c.assert(swap_pending);
            let ev7 = VAULT.swap_event_map.lookup(c, &request_id);
            VAULT.swap_event_map.remove(c, &request_id);
            ev7
        });
        c.region("swapper gate", |c| {
            let sk = common::witness_sk(c);
            let rid_priv = request_id.private();
            let rc = withdraw_refund_commitment(c, &sk, &rid_priv);
            let stored = VAULT.swap_refund_commitment.lookup(c, &request_id);
            let eq_hi = c.test_eq(rc.bytes().hi, stored.bytes().hi.private());
            let eq_lo = c.test_eq(rc.bytes().lo, stored.bytes().lo.private());
            let is_swapper = c.mul(eq_hi, eq_lo);
            c.assert(is_swapper);
            VAULT.swap_refund_commitment.remove(c, &request_id);
        });
        c.assert(ev7.calldata_is_some());
        let word5 = ev7.word(5);
        let amount_in_max = signet::abi_word_to_uint128(c, &word5);
        let word0 = ev7.word(0);
        let token_in = signet::abi_word_low20(c, &word0);
        let ds_in = vault_token_domain_separator(c, token_in);
        let own_pk = minocrab_std::v3::own_public_key(c);
        let own_pk = own_pk.disclose_as::<SwapRefundRecipient>(c);
        // The `Uint<64>` claim here is justified by REQUEST-TIME bounds, not
        // locally (notes/api-safety-survey.org §B4's correction) — first in
        // line for `from_field_checked` once there's a spec-anchored artifact.
        common::mint_shielded_token_to_key(c, &ds_in, Uint::<64, Public>::from_field_unchecked(amount_in_max), &mint_nonce, &own_pk);
    });

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
    mint_nonce: CoinNonce<Private>,
    recipient: Maybe<Either<minocrab_std::v3::ZswapCoinPublicKey<Private>, minocrab_std::v3::ContractAddress<Private>, Private>>,
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
        &signet::Secp256k1SigLimbs { big_r_x, s: sig_s },
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

    // Depositor gate: userCommitment(callerSecretKey()) == request.path.
    c.region("depositor gate", |c| {
        let sk = common::witness_sk(c);
        let caller = common::commitment_padded_tag(c, USER_PAD, &sk).bytes();
        let path = ev.path();
        let eq_hi = c.test_eq(caller.hi, path.bytes().hi.private());
        let eq_lo = c.test_eq(caller.lo, path.bytes().lo.private());
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
        let left = minocrab_std::v3::ZswapCoinPublicKey(B32 {
            hi: c.cond_select(rec_is_some, rec_left.bytes().hi, own_pk.bytes().hi),
            lo: c.cond_select(rec_is_some, rec_left.bytes().lo, own_pk.bytes().lo),
        });
        let right = minocrab_std::v3::ContractAddress(B32 {
            hi: c.cond_select(rec_is_some, rec_right.bytes().hi, 0u64),
            lo: c.cond_select(rec_is_some, rec_right.bytes().lo, 0u64),
        });
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
