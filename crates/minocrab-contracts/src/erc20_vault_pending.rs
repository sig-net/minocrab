//! The erc20-vault on [`crate::signet_flow`] — M35 rung C: the same
//! contract as [`crate::erc20_vault_modern`], with every Sig Network
//! suspension owned by a [`Pending`] slot instead of spelled out per
//! circuit.
//!
//! WHAT THIS LINEAGE IS. A NEW DEPLOYMENT LAYOUT, not a byte-twin: its
//! ledger block declares seventeen fields (so compactc-style segmentation
//! is live — every path is two elements), its request records and
//! environments sit in `Pending` slots, and its settle circuits take one
//! `Settle` ticket each. It has no compactc twin to differential against;
//! the spec harness's shared model is the oracle for it, as for the opt
//! lineage (that extension is tracked in M35 C).
//!
//! WHAT MOVED OUT OF THE CIRCUITS, and where it went
//! (notes/signet-async.org §7's table, realised):
//!
//! | invariant                        | now                                   |
//! |----------------------------------|---------------------------------------|
//! | response kind byte               | `Response::KIND` on four types        |
//! | record format version            | inside `settle`                       |
//! | notification depth + path bytes  | derived from the slot                 |
//! | request map / env map / nonce    | one `Pending` slot + one `Signet`     |
//! | amount, token for settle         | typed `Env` fields                    |
//! | verify → kind → lookup → remove  | one `settle` / `settle_failed`        |
//! | refund commitment hash + gate    | `Commit::to` / `Commit::open`         |
//!
//! WHAT STAYED, deliberately: the initialization gate, the deployer gate,
//! the business guards, the coin burns and mints, and every authorization
//! with a FRESH witness (`witness_sk` in `claim`, `complete_withdraw`,
//! `complete_swap`, both refunds).
//!
//! ONE DEVIATION IN CIRCUIT COUNT: `refund` routed a failure over BOTH
//! request maps in one circuit with guarded lookups; a `Pending` slot
//! settles its own entries, so there are two refund circuits here
//! (`refund_withdrawal`, `refund_swap`), each a plain `settle_failed`. Ten
//! circuits, not nine. And `approveRouter` files into a [`Fired`] slot: a
//! request-only shape with no settle method at all.

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Private, Public};
use minocrab_std::v3::borsh::CircuitBorsh;
use minocrab_std::v3::kernel;
use minocrab_std::v3::{
    circuit, eq, is_true, label, own_public_key, own_public_key_guarded, Bool, Bytes, Check,
    CircuitArg, CoinColor, CoinNonce, CoinRecipient, Disclose, Discloses, Either, Ledger,
    LedgerCell, LedgerCounter, LedgerRepr, Maybe, Secp256k1Point, TokenDomainSeparator, Uint,
    B32,
};

use crate::common;
use crate::erc20_vault::{
    APPROVE_SELECTOR, EXACT_OUTPUT_SINGLE_SELECTOR, REFUND_PAD, SWAP_WORDS, TRANSFER_SELECTOR,
    VAULT_WORDS,
};
use crate::erc20_vault_borsh::{
    RESPONSE_KIND_APPROVE, RESPONSE_KIND_CLAIM, RESPONSE_KIND_FAILURE, RESPONSE_KIND_SWAP,
    RESPONSE_KIND_WITHDRAW, VAULT_TOKEN_TAG,
};
use crate::signet;
use crate::signet_flow::{
    Commit, EvmTx, FailureResponse, Fired, Pending, Requested, Response, Settle, Settled,
    SignRequest, Signet,
};

// ---- the wire: response types --------------------------------------------------------

/// `{ kind: 0, success: bool }` — a deposit's attested transfer.
#[derive(CircuitBorsh)]
pub struct ClaimResponse {
    pub success: Bool,
}
impl Response for ClaimResponse {
    const KIND: u8 = RESPONSE_KIND_CLAIM as u8;
}

/// `{ kind: 1, success: bool }` — a withdrawal's attested transfer.
#[derive(CircuitBorsh)]
pub struct WithdrawResponse {
    pub success: Bool,
}
impl Response for WithdrawResponse {
    const KIND: u8 = RESPONSE_KIND_WITHDRAW as u8;
}

/// `{ kind: 2, amountIn: u64 }` — a swap's attested spend.
#[derive(CircuitBorsh)]
pub struct SwapResponse {
    pub amount_in: Uint<64>,
}
impl Response for SwapResponse {
    const KIND: u8 = RESPONSE_KIND_SWAP as u8;
}

/// `{ kind: 3 }` — "never executed", one byte, no body.
#[derive(CircuitBorsh)]
pub struct Failure {}
impl Response for Failure {
    const KIND: u8 = RESPONSE_KIND_FAILURE as u8;
}
impl FailureResponse for Failure {}

/// `{ kind: 4, success: bool }` — an approve's attested call. REQUEST-ONLY:
/// no circuit settles it; the kind exists so an approve attestation is a
/// kind no settle circuit accepts.
#[derive(CircuitBorsh)]
pub struct ApproveResponse {
    pub success: Bool,
}
impl Response for ApproveResponse {
    const KIND: u8 = RESPONSE_KIND_APPROVE as u8;
}

// ---- the environments -------------------------------------------------------------------

/// What `claim` needs back: who may claim, which token, how much.
#[derive(LedgerRepr)]
pub struct DepositEnv {
    pub depositor: common::UserCommitment<Public>,
    pub erc20: Bytes<20, Public>,
    pub amount: Uint<64, Public>,
}

/// What `complete_withdraw` / `refund_withdrawal` need back: the withdrawer
/// as a commitment (opened with a fresh witness), and what to re-mint on
/// failure.
#[derive(LedgerRepr)]
pub struct WithdrawEnv {
    pub withdrawer: Commit<common::SecretKey<Private>>,
    pub erc20: Bytes<20, Public>,
    pub amount: Uint<64, Public>,
}

/// What `complete_swap` / `refund_swap` need back.
#[derive(LedgerRepr)]
pub struct SwapEnv {
    pub swapper: Commit<common::SecretKey<Private>>,
    pub token_in: Bytes<20, Public>,
    pub token_out: Bytes<20, Public>,
    pub amount_out: Uint<64, Public>,
    pub amount_in_maximum: Uint<64, Public>,
}

// ---- the ledger block ---------------------------------------------------------------------

/// Sixteen ledger fields from nine declarations — SEGMENTED by compactc's
/// rule (past fifteen), so every path here is two elements and every cell
/// write is nested, as the upstream vault's own block is since its lending
/// extension (M28). The layout is this lineage's own.
#[derive(Ledger)]
pub struct Vault {
    pub initialized: LedgerCounter,
    /// `sealed ledger deployer: Bytes<32>` — write-once at deployment.
    pub deployer: LedgerCell<common::UserCommitment<Public>>,
    pub vault_evm_address: LedgerCell<Bytes<20, Public>>,
    pub uniswap_router: LedgerCell<Bytes<20, Public>>,
    /// signer, mpcResponseKey, requestNonce, caip2Id, evmChainId.
    pub signet: Signet,
    pub deposits: Pending<DepositEnv, ClaimResponse, VAULT_WORDS>,
    pub withdrawals: Pending<WithdrawEnv, WithdrawResponse, VAULT_WORDS>,
    pub swaps: Pending<SwapEnv, SwapResponse, SWAP_WORDS>,
    /// Request-only: no settle exists for it.
    pub approvals: Fired<ApproveResponse, VAULT_WORDS>,
}

pub const VAULT: Vault = Vault::new();

label! {
    VaultEvmAddress = "the vault's derived EVM address";
    UniswapRouter = "the Uniswap router address";
    EvmChainId = "the EVM chain id";
    Caip2Id = "the CAIP-2 chain id";
    MpcResponseKey = "the MPC response key";
    DepositorCommitment = "depositor identity commitment";
    DepositedErc20 = "the deposited ERC20";
    DepositedAmount = "the deposited amount";
    WithdrawnErc20 = "the withdrawn ERC20";
    WithdrawnAmount = "the withdrawn amount";
    SurrenderedCoinNonce = "surrendered coin nonce";
    SurrenderedCoinColor = "surrendered coin color";
    SurrenderedCoinValue = "surrendered coin value";
    WithdrawerRefundCommitment = "withdrawer refund commitment";
    SoldErc20 = "the sold ERC20";
    BoughtErc20 = "the bought ERC20";
    SwapAmountOut = "the swap's amountOut";
    SwapAmountInMaximum = "the swap's amountInMaximum";
    SwapperRefundCommitment = "swapper refund commitment";
    ApprovedErc20 = "the approved ERC20";
    WithdrawalOutcome = "withdrawal EVM outcome";
    RefundMintNonce = "refund mint nonce";
    RefundRecipient = "own public key as refund recipient";
    SwapRecipient = "own public key as swap recipient";
    SwapMintNonce = "swap mint nonce";
    AttestedAmountIn = "attested amountIn spent";
    ClaimRecipientTag = "claim recipient tag";
    ClaimRecipientSide = "claim recipient side";
    ClaimRecipientOwnKey = "own public key as claim recipient";
    ClaimRecipientKey = "claim recipient key";
    ClaimRecipientContract = "claim recipient contract";
    ClaimMintNonce = "claim mint nonce";
}

// ---- shared pieces ------------------------------------------------------------------------

fn assert_initialized(c: &mut Circuit3) {
    let init = VAULT.initialized.read(c);
    c.assert(init.gt(0u64).message("Not initialized"));
}

fn b32_eq(a: &B32<Private>, b: &B32<Private>) -> Check<Private> {
    eq(a.hi, b.hi).and(eq(a.lo, b.lo))
}

fn assert_deployer(c: &mut Circuit3) {
    let sk = common::witness_sk(c);
    let digest = common::commitment_packed_tag(c, &sk);
    let stored = VAULT.deployer.read(c);
    c.assert(b32_eq(&digest.bytes(), &stored.private().bytes()).message("Not the deployer"));
}

/// The vault token's pre-token for an ERC-20 (see
/// `erc20_vault_modern::vault_token_domain_separator`).
fn vault_token_domain_separator(
    c: &mut Circuit3,
    erc20_address: Wire3<FieldT, Public>,
) -> TokenDomainSeparator<Public> {
    c.region("token domain separator", |c| {
        TokenDomainSeparator(B32 {
            hi: c.constant(u64::from(VAULT_TOKEN_TAG)),
            lo: erc20_address,
        })
    })
}

const ERC20_CALL_GAS: u64 = 100_000;
const SWAP_GAS: u64 = 700_000;

/// The contract-FIXED gas envelope: 1 gwei priority, 30 gwei cap, a
/// per-call limit.
struct FixedGas<const LIMIT: u64>;

impl<const LIMIT: u64> FixedGas<LIMIT> {
    const PRIORITY_FEE: u64 = 1_000_000_000;
    const MAX_FEE: u64 = 30_000_000_000;

    fn wires(c: &mut Circuit3) -> [Wire3<FieldT, Private>; 3] {
        let priority_fee = c.constant(Self::PRIORITY_FEE);
        let max_fee = c.constant(Self::MAX_FEE);
        let gas = c.constant(LIMIT);
        [priority_fee.private(), max_fee.private(), gas.private()]
    }
}

/// A two-word ERC-20 call (`transfer` / `approve`) as an [`EvmTx`].
fn erc20_call(
    c: &mut Circuit3,
    selector: &[u8; 4],
    to: Wire3<FieldT, Private>,
    words: [B32<Private>; 2],
    nonce: Wire3<FieldT, Private>,
    gas: [Wire3<FieldT, Private>; 3],
) -> EvmTx<VAULT_WORDS> {
    let zero = c.constant(0u64).private();
    let one = c.constant(1u64).private();
    let two = c.constant(2u64).private();
    let selector = c.constant(minocrab::Fr::from_le_bytes(selector).unwrap()).private();
    EvmTx {
        nonce,
        max_priority_fee_per_gas: gas[0],
        max_fee_per_gas: gas[1],
        gas_limit: gas[2],
        to,
        value: zero,
        calldata_is_some: one,
        calldata: signet::EvmCalldata {
            selector,
            no_words: two,
            words,
        },
    }
}

/// `struct ShieldedCoinInfo { nonce, color, value }` as an argument.
#[derive(CircuitArg)]
struct ShieldedCoinArg {
    nonce: CoinNonce<Private>,
    color: CoinColor<Private>,
    value: Uint<128>,
}

/// The surrendered coin must be the vault token for `erc20` of exactly
/// `amount`; then it is burned. Returns nothing: the checks assert.
fn burn_vault_coin(
    c: &mut Circuit3,
    one: Wire3<FieldT, Public>,
    erc20: Wire3<FieldT, Public>,
    amount: Wire3<FieldT, Private>,
    coin: ShieldedCoinArg,
) {
    let domain_sep = vault_token_domain_separator(c, erc20);
    let me = kernel::cache_self_address(c);
    let color = minocrab_std::v3::token_type(c, &domain_sep, &me.bytes());
    c.assert(b32_eq(&coin.color.bytes(), &color.private().bytes()));
    c.assert(eq(coin.value.field(), amount));
    let coin = minocrab_std::v3::ShieldedCoinInfo3 {
        nonce: coin.nonce.disclose_as::<SurrenderedCoinNonce>(c),
        color: coin.color.disclose_as::<SurrenderedCoinColor>(c),
        value: coin.value.field().disclose_as::<SurrenderedCoinValue>(c),
    };
    common::burn_spend(c, one, &coin);
}

/// completeSwap's change-coin nonce: `[255 − hi, lo]` (see
/// `erc20_vault_modern::change_nonce`).
fn change_nonce(c: &mut Circuit3, mint_nonce: &CoinNonce<Public>) -> CoinNonce<Public> {
    c.region("change nonce", |c| {
        let neg_hi = c.neg(mint_nonce.bytes().hi);
        CoinNonce(B32 {
            hi: c.add(255u64, neg_hi),
            lo: mint_nonce.bytes().lo,
        })
    })
}

// ---- initialize ---------------------------------------------------------------------------------

/// `initialize(vaultEvm, swapRouter, chainId, chainCaip2Id, responseKey)`.
#[circuit]
pub fn initialize(
    c: &mut Circuit3,
    vault_evm: Bytes<20>,
    swap_router: Bytes<20>,
    chain_id: Uint<64>,
    chain_caip2_id: common::Caip2Id<Private>,
    response_key: Secp256k1Point,
) -> Discloses<(VaultEvmAddress, UniswapRouter, EvmChainId, Caip2Id, MpcResponseKey)> {
    c.region("initialized gate", |c| {
        let count = VAULT.initialized.read(c);
        c.assert(count.eq(0u64).message("Already initialized"));
    });
    c.region("deployer gate", assert_deployer);
    c.assert(chain_id.gt(0u64).message("Chain ID must be positive"));
    c.assert(swap_router.ne(0u64).message("Router cannot be zero"));
    // An identity key authenticates anything; extracting coordinates IS
    // the check (external review §4.5).
    c.region("response key is a point", |c| {
        let _ = c.into_coordinates(response_key.point());
    });

    VAULT.initialized.increment(c, 1);

    c.region("configuration writes", |c| {
        let vault_evm = vault_evm.disclose_as::<VaultEvmAddress>(c);
        VAULT.vault_evm_address.write(c, &vault_evm);
        let swap_router = swap_router.disclose_as::<UniswapRouter>(c);
        VAULT.uniswap_router.write(c, &swap_router);
        let chain_id = chain_id.disclose_as::<EvmChainId>(c);
        let caip2 = chain_caip2_id.disclose_as::<Caip2Id>(c);
        let response_key = response_key.disclose_as::<MpcResponseKey>(c);
        VAULT.signet.initialize(c, &response_key, &caip2, &chain_id);
    });
    Discloses::of(())
}

// ---- deposit / claim ------------------------------------------------------------------------

/// `struct DepositRequest { erc20Address: Bytes<20>, amount: Uint<128> }`.
#[derive(CircuitArg)]
struct DepositRequest {
    erc20_address: Bytes<20>,
    amount: Uint<128>,
}

/// `deposit(evmNonce, gasLimit, maxFeePerGas, maxPriorityFeePerGas,
/// keyVersion, depositRequest)`: file `transfer(vaultEvmAddress, amount)`
/// under the depositor's identity commitment and notify the MPC.
#[circuit]
pub fn deposit(
    c: &mut Circuit3,
    evm_nonce: Uint<64>,
    gas_limit: Uint<64>,
    max_fee_per_gas: Uint<128>,
    max_priority_fee_per_gas: Uint<128>,
    key_version: Uint<8>,
    deposit_request: DepositRequest,
) -> Discloses<(DepositorCommitment, DepositedErc20, DepositedAmount, Requested)> {
    c.region("guards", |c| {
        assert_initialized(c);
        c.assert(deposit_request.erc20_address.ne(0u64));
        c.assert(deposit_request.amount.gt(0u64));
        c.assert(deposit_request.amount.le(u64::MAX));
        c.assert(gas_limit.gt(0u64));
    });

    let sk = common::witness_sk(c);
    let caller = common::commitment_packed_tag(c, &sk).disclose_as::<DepositorCommitment>(c);

    // transfer(vaultEvmAddress, amount), paid from the DEPOSITOR's account:
    // the gas envelope is the caller's.
    let vault_evm = VAULT.vault_evm_address.read(c);
    let word0 = signet::evm_address_abi_word(c, vault_evm.field().private());
    let word1 = signet::numeric_abi_word(c, deposit_request.amount.field());
    let tx = erc20_call(
        c,
        &TRANSFER_SELECTOR,
        deposit_request.erc20_address.field(),
        [word0, word1],
        evm_nonce.field(),
        [
            max_priority_fee_per_gas.field(),
            max_fee_per_gas.field(),
            gas_limit.field(),
        ],
    );

    let erc20 = deposit_request.erc20_address.disclose_as::<DepositedErc20>(c);
    let amount = deposit_request.amount.field().disclose_as::<DepositedAmount>(c);
    VAULT.deposits.request(
        c,
        &VAULT.signet,
        SignRequest {
            key_version,
            path: common::SigningPath::from(caller.private()),
            tx,
        },
        |_, _| DepositEnv {
            depositor: caller,
            erc20,
            amount: Uint::from_field_unchecked(amount),
        },
    );
    Discloses::of(())
}

/// `claim(ticket, mintNonce, recipient)`: settle a deposit — the attested
/// transfer succeeded — and mint the deposited amount as shielded vault
/// tokens to the recipient (depositor-only).
#[circuit]
pub fn claim(
    c: &mut Circuit3,
    ticket: Settle<DepositEnv, ClaimResponse>,
    mint_nonce: CoinNonce<Private>,
    recipient: Maybe<
        Either<
            minocrab_std::v3::ZswapCoinPublicKey<Private>,
            minocrab_std::v3::ContractAddress<Private>,
            Private,
        >,
    >,
) -> Discloses<(
    Settled,
    ClaimRecipientTag,
    ClaimRecipientSide,
    ClaimRecipientOwnKey,
    ClaimRecipientKey,
    ClaimRecipientContract,
    ClaimMintNonce,
)> {
    let one = c.constant(1u64);
    assert_initialized(c);
    let outcome = VAULT.deposits.settle(c, &VAULT.signet, ticket);
    c.assert(is_true(outcome.output.success).message("The MPC attested a failure"));

    // Depositor gate: a FRESH witness against the filed commitment.
    c.region("depositor gate", |c| {
        let sk = common::witness_sk(c);
        let caller = common::commitment_packed_tag(c, &sk).bytes();
        c.assert(
            b32_eq(&caller, &outcome.env.depositor.private().bytes()).message("Not the depositor"),
        );
    });

    let domain_sep = vault_token_domain_separator(c, outcome.env.erc20.field());
    let recipient = c.region("recipient select", |c| {
        let rec_is_some = recipient.is_some.field().disclose_as::<ClaimRecipientTag>(c);
        let rec_is_left = recipient.value.is_left.field().disclose_as::<ClaimRecipientSide>(c);
        let not_some = c.not(rec_is_some);
        let own_pk = own_public_key_guarded(c, not_some)
            .or_default()
            .disclose_as::<ClaimRecipientOwnKey>(c);
        let rec_left = recipient.value.left.disclose_as::<ClaimRecipientKey>(c);
        let rec_right = recipient.value.right.disclose_as::<ClaimRecipientContract>(c);
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

    let mint_nonce = mint_nonce.disclose_as::<ClaimMintNonce>(c);
    common::mint_shielded_token(c, one, &domain_sep, outcome.env.amount, &mint_nonce, &recipient);
    Discloses::of(())
}

// ---- withdraw / completeWithdraw / refundWithdrawal ---------------------------------

/// `struct WithdrawRequest { erc20Address, amount, destEvmAddress }`.
#[derive(CircuitArg)]
struct WithdrawRequest {
    erc20_address: Bytes<20>,
    amount: Uint<128>,
    dest_evm_address: Bytes<20>,
}

/// `withdraw(evmNonce, keyVersion, withdrawRequest, coin)`: burn the
/// surrendered vault tokens and file `transfer(destEvmAddress, amount)`
/// signed by the VAULT's account, the withdrawer kept as a commitment.
#[circuit]
pub fn withdraw(
    c: &mut Circuit3,
    evm_nonce: Uint<64>,
    key_version: Uint<8>,
    withdraw_request: WithdrawRequest,
    coin: ShieldedCoinArg,
) -> Discloses<(
    WithdrawnErc20,
    WithdrawnAmount,
    SurrenderedCoinNonce,
    SurrenderedCoinColor,
    SurrenderedCoinValue,
    WithdrawerRefundCommitment,
    Requested,
)> {
    let one = c.constant(1u64);
    c.region("guards", |c| {
        assert_initialized(c);
        c.assert(withdraw_request.erc20_address.ne(0u64));
        c.assert(withdraw_request.amount.gt(0u64));
        c.assert(withdraw_request.amount.le(u64::MAX));
    });

    let erc20 = withdraw_request.erc20_address.disclose_as::<WithdrawnErc20>(c);
    let amount = withdraw_request.amount.field();
    burn_vault_coin(c, one, erc20.field(), amount, coin);

    let word0 = signet::evm_address_abi_word(c, withdraw_request.dest_evm_address.field());
    let word1 = signet::numeric_abi_word(c, amount);
    let gas = FixedGas::<ERC20_CALL_GAS>::wires(c);
    let tx = erc20_call(c, &TRANSFER_SELECTOR, erc20.field().private(), [word0, word1], evm_nonce.field(), gas);

    let sk = common::witness_sk(c);
    let amount = amount.disclose_as::<WithdrawnAmount>(c);
    let vault_path = common::SigningPath::vault_path(c).private();
    VAULT.withdrawals.request(
        c,
        &VAULT.signet,
        SignRequest {
            key_version,
            path: vault_path,
            tx,
        },
        |c, id| WithdrawEnv {
            withdrawer: Commit::to::<WithdrawerRefundCommitment>(c, REFUND_PAD, &sk, id),
            erc20,
            amount: Uint::from_field_unchecked(amount),
        },
    );
    Discloses::of(())
}

/// `completeWithdraw(ticket, mintNonce)`: the withdrawal EXECUTED; on an
/// attested `false` return, re-mint the surrendered value to the
/// withdrawer (fresh witness against the commitment).
#[circuit]
pub fn complete_withdraw(
    c: &mut Circuit3,
    ticket: Settle<WithdrawEnv, WithdrawResponse>,
    mint_nonce: CoinNonce<Private>,
) -> Discloses<(Settled, WithdrawalOutcome, RefundMintNonce, RefundRecipient)> {
    assert_initialized(c);
    let outcome = VAULT.withdrawals.settle(c, &VAULT.signet, ticket);
    let succeeded = outcome.output.success.field().disclose_as::<WithdrawalOutcome>(c);
    let refunding = c.not(succeeded);
    let mint_nonce = mint_nonce.disclose_as::<RefundMintNonce>(c);
    c.when(refunding, |c| {
        let sk = common::witness_sk(c);
        outcome.env.withdrawer.open(c, REFUND_PAD, &sk, outcome.request_id, "Not the withdrawer");
        let domain_sep = vault_token_domain_separator(c, outcome.env.erc20.field());
        let own_pk = own_public_key(c).disclose_as::<RefundRecipient>(c);
        common::mint_shielded_token_to_key(c, &domain_sep, outcome.env.amount, &mint_nonce, &own_pk);
    });
    Discloses::of(())
}

/// `refundWithdrawal(ticket, mintNonce)`: the withdrawal NEVER EXECUTED
/// (the MPC's failure kind); re-mint the surrendered value to the
/// withdrawer.
#[circuit]
pub fn refund_withdrawal(
    c: &mut Circuit3,
    ticket: Settle<WithdrawEnv, Failure>,
    mint_nonce: CoinNonce<Private>,
) -> Discloses<(Settled, RefundMintNonce, RefundRecipient)> {
    assert_initialized(c);
    let outcome = VAULT.withdrawals.settle_failed(c, &VAULT.signet, ticket);
    let sk = common::witness_sk(c);
    outcome.env.withdrawer.open(c, REFUND_PAD, &sk, outcome.request_id, "Not the withdrawer");
    let mint_nonce = mint_nonce.disclose_as::<RefundMintNonce>(c);
    let domain_sep = vault_token_domain_separator(c, outcome.env.erc20.field());
    let own_pk = own_public_key(c).disclose_as::<RefundRecipient>(c);
    common::mint_shielded_token_to_key(c, &domain_sep, outcome.env.amount, &mint_nonce, &own_pk);
    Discloses::of(())
}

// ---- swap / completeSwap / refundSwap ----------------------------------------------------

/// `struct SwapRequest { tokenIn, tokenOut, fee: Uint<24>, amountOut,
/// amountInMaximum }`.
#[derive(CircuitArg)]
struct SwapRequest {
    token_in: Bytes<20>,
    token_out: Bytes<20>,
    fee: Uint<24>,
    amount_out: Uint<128>,
    amount_in_maximum: Uint<128>,
}

/// `swap(evmNonce, keyVersion, swapRequest, coin)`: burn the surrendered
/// tokenIn (amountInMaximum) and file `exactOutputSingle` on the pinned
/// router, signed by the VAULT's account.
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
    SwapAmountOut,
    SwapAmountInMaximum,
    SurrenderedCoinNonce,
    SurrenderedCoinColor,
    SurrenderedCoinValue,
    SwapperRefundCommitment,
    Requested,
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
    let token_in = swap_request.token_in.disclose_as::<SoldErc20>(c);
    burn_vault_coin(c, one, token_in.field(), amount_in_max, coin);

    // exactOutputSingle((tokenIn, tokenOut, fee, vault, amountOut,
    // amountInMaximum, 0)).
    let token_out = swap_request.token_out.disclose_as::<BoughtErc20>(c);
    let word0 = signet::evm_address_abi_word(c, token_in.field().private());
    let word1 = signet::evm_address_abi_word(c, token_out.field().private());
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
    let router = VAULT.uniswap_router.read(c);
    let [priority_fee, max_fee, gas] = FixedGas::<SWAP_GAS>::wires(c);
    let tx = EvmTx::<SWAP_WORDS> {
        nonce: evm_nonce.field(),
        max_priority_fee_per_gas: priority_fee,
        max_fee_per_gas: max_fee,
        gas_limit: gas,
        to: router.field().private(),
        value: zero.private(),
        calldata_is_some: one.private(),
        calldata: signet::EvmCalldata {
            selector: selector.private(),
            no_words: seven.private(),
            words: [word0, word1, word2, word3, word4, word5, word6],
        },
    };

    let sk = common::witness_sk(c);
    let amount_out = amount_out.disclose_as::<SwapAmountOut>(c);
    let amount_in_max = amount_in_max.disclose_as::<SwapAmountInMaximum>(c);
    let vault_path = common::SigningPath::vault_path(c).private();
    VAULT.swaps.request(
        c,
        &VAULT.signet,
        SignRequest {
            key_version,
            path: vault_path,
            tx,
        },
        |c, id| SwapEnv {
            swapper: Commit::to::<SwapperRefundCommitment>(c, REFUND_PAD, &sk, id),
            token_in,
            token_out,
            amount_out: Uint::from_field_unchecked(amount_out),
            amount_in_maximum: Uint::from_field_unchecked(amount_in_max),
        },
    );
    Discloses::of(())
}

/// `completeSwap(ticket, mintNonce)`: the swap EXECUTED; mint the exact
/// amountOut of tokenOut and the unspent tokenIn as change, to the swapper
/// (fresh witness against the commitment).
#[circuit]
pub fn complete_swap(
    c: &mut Circuit3,
    ticket: Settle<SwapEnv, SwapResponse>,
    mint_nonce: CoinNonce<Private>,
) -> Discloses<(Settled, SwapRecipient, SwapMintNonce, AttestedAmountIn)> {
    assert_initialized(c);
    let outcome = VAULT.swaps.settle(c, &VAULT.signet, ticket);
    let sk = common::witness_sk(c);
    outcome.env.swapper.open(c, REFUND_PAD, &sk, outcome.request_id, "Not the swapper");

    kernel::cache_self_address(c);
    let recipient = own_public_key(c).disclose_as::<SwapRecipient>(c);
    let mint_nonce = mint_nonce.disclose_as::<SwapMintNonce>(c);

    let ds_out = vault_token_domain_separator(c, outcome.env.token_out.field());
    common::mint_shielded_token_to_key(c, &ds_out, outcome.env.amount_out, &mint_nonce, &recipient);

    // Change: amountInMaximum − attested amountIn, guarded against
    // underflow by `sub_with` (the most dangerous arithmetic in the contract).
    let amount_in = outcome.output.amount_in.disclose_as::<AttestedAmountIn>(c);
    let change = outcome
        .env
        .amount_in_maximum
        .sub_with(c, amount_in, "Attested amountIn exceeds amountInMaximum");
    let ds_in = vault_token_domain_separator(c, outcome.env.token_in.field());
    let change_nonce = change_nonce(c, &mint_nonce);
    common::mint_shielded_token_to_key(c, &ds_in, change, &change_nonce, &recipient);
    Discloses::of(())
}

/// `refundSwap(ticket, mintNonce)`: the swap NEVER EXECUTED; re-mint the
/// surrendered amountInMaximum of tokenIn to the swapper.
#[circuit]
pub fn refund_swap(
    c: &mut Circuit3,
    ticket: Settle<SwapEnv, Failure>,
    mint_nonce: CoinNonce<Private>,
) -> Discloses<(Settled, RefundMintNonce, RefundRecipient)> {
    assert_initialized(c);
    let outcome = VAULT.swaps.settle_failed(c, &VAULT.signet, ticket);
    let sk = common::witness_sk(c);
    outcome.env.swapper.open(c, REFUND_PAD, &sk, outcome.request_id, "Not the swapper");
    let mint_nonce = mint_nonce.disclose_as::<RefundMintNonce>(c);
    let domain_sep = vault_token_domain_separator(c, outcome.env.token_in.field());
    let own_pk = own_public_key(c).disclose_as::<RefundRecipient>(c);
    common::mint_shielded_token_to_key(c, &domain_sep, outcome.env.amount_in_maximum, &mint_nonce, &own_pk);
    Discloses::of(())
}

// ---- approveRouter ---------------------------------------------------------------------------

/// `approveRouter(erc20Address, evmNonce, keyVersion)`: file
/// `approve(uniswapRouter, 2^128−1)` signed by the VAULT's account.
/// Request-only.
#[circuit]
pub fn approve_router(
    c: &mut Circuit3,
    erc20_address: Bytes<20>,
    evm_nonce: Uint<64>,
    key_version: Uint<8>,
) -> Discloses<(ApprovedErc20, Requested)> {
    c.region("guards", |c| {
        assert_initialized(c);
        c.assert(erc20_address.ne(0u64));
    });

    let router = VAULT.uniswap_router.read(c);
    let word0 = signet::evm_address_abi_word(c, router.field().private());
    let mut max_word = [0u8; 32];
    max_word[16..].copy_from_slice(&[0xff; 16]);
    let word1 = B32::<Private> {
        hi: c.constant(minocrab::Fr::from(u64::from(max_word[31]))).private(),
        lo: c.constant(minocrab::Fr::from_le_bytes(&max_word[..31]).unwrap()).private(),
    };
    let erc20 = erc20_address.disclose_as::<ApprovedErc20>(c);
    let gas = FixedGas::<ERC20_CALL_GAS>::wires(c);
    let tx = erc20_call(c, &APPROVE_SELECTOR, erc20.field().private(), [word0, word1], evm_nonce.field(), gas);

    let vault_path = common::SigningPath::vault_path(c).private();
    VAULT.approvals.request(
        c,
        &VAULT.signet,
        SignRequest {
            key_version,
            path: vault_path,
            tx,
        },
    );
    Discloses::of(())
}
