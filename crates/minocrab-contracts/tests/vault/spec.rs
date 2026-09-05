//! The erc20-vault SPEC: each circuit as a total function from a scenario to
//! an [`Outcome`] — which guard rejects, or which ledger effects are
//! declared — in ordinary Rust, independent of the circuits and of the op
//! streams the model emits.
//!
//! [`check_effects`] closes the loop the other way: the declared effects
//! are compared against what Midnight's own VM computed when it ran the
//! model's op stream (`exec::run`), field by field and claim by claim.
//!
//! Since M28 there is ONE concretization (every commitment Poseidon, as the
//! source has it), so effects carry concrete bytes rather than symbolic
//! terms; the injectivity of the constructions is swept separately in the
//! adversarial suite.

use midnight_base_crypto::fab::AlignedValue;
use minocrab::Fr;

use super::exec::{self, Executed, PreState};
use super::model::*;
use super::prims::*;

/// Which assertion rejected. The identity is the Compact source's own
/// assert message, so a guard cannot be renamed without noticing.
///
/// `simulate` reports only "the circuit rejected", never which assert, so
/// acceptance agreement is checked on the boolean and the guard id is the
/// spec's own explanation of why — verified by construction of the case,
/// not by matching against the circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardId {
    // initialise
    AlreadyInitialised,
    NotTheDeployer,
    ChainIdMustBePositive,
    RouterCannotBeZero,
    StataUnderlyingCannotBeZero,
    StataTokenCannotBeZero,
    // request circuits
    NotInitialised,
    Erc20AddressCannotBeZero,
    AmountMustBePositive,
    AmountExceedsUint64Max,
    GasLimitMustBePositive,
    /// `Signet.compact` — inside `constructSignBidirectionalEvent`.
    KeyVersionMustBeGe1,
    RequestAlreadyExists,
    CoinIsNotTheVaultToken,
    CoinValueMustEqualAmount,
    TokenInCannotBeZero,
    TokenOutCannotBeZero,
    AmountOutMustBePositive,
    AmountInMaximumMustBePositive,
    AmountOutExceedsUint64Max,
    AmountInMaximumExceedsUint64Max,
    SharesMustBePositive,
    SharesExceedUint64Max,
    // settle circuits
    Erc20TransferReturnedFalse,
    DepositNotFound,
    NotTheDepositor,
    WithdrawalNotFound,
    NotTheWithdrawer,
    NotTheMpcFailureOutput,
    SwapNotFound,
    NotTheSwapper,
    ChangeNonceMustDiffer,
    /// completeSwap's `amountInMaximum - amountIn`: Compact's unsigned
    /// subtraction asserts no underflow. The most dangerous arithmetic in
    /// the contract.
    ChangeUnderflow,
    SupplyNotFound,
    NotTheSupplier,
    RedeemNotFound,
    NotTheRedeemer,
}

/// One declared state change or ledger claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    CounterInc { field: u8, by: u64 },
    MapInsert { field: u8, key: [u8; 32], value: AlignedValue },
    MapRemove { field: u8, key: [u8; 32] },
    CellWrite { field: u8, value: AlignedValue },
    MintShielded { domain_sep: [u8; 32], value: u64 },
    ClaimSpend([u8; 32]),
    ClaimReceive([u8; 32]),
    ClaimNullifier([u8; 32]),
    ClaimContractCall { addr: [u8; 32], ep: [u8; 32], comm: Fr },
}

/// What a circuit does with one call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Reject(GuardId),
    Accept(Vec<Effect>),
}

impl Outcome {
    pub fn accepts(&self) -> bool {
        matches!(self, Outcome::Accept(_))
    }
    pub fn guard(&self) -> Option<GuardId> {
        match self {
            Outcome::Reject(g) => Some(*g),
            _ => None,
        }
    }
    pub fn effects(&self) -> &[Effect] {
        match self {
            Outcome::Accept(effects) => effects,
            _ => &[],
        }
    }
}

const U64_MAX_U128: u128 = u64::MAX as u128;

// ---- shared pieces ------------------------------------------------------------

/// The effects every request circuit declares: the nonce increment, the
/// record, the settle view, the notification call.
fn request_effects(env: &Env, map: u8, req: &Req, view: Option<(u8, AlignedValue)>, cc_rand: Fr) -> Vec<Effect> {
    let rid = req.request_id(env);
    let mut effects = vec![
        Effect::CounterInc {
            field: SIGNET_REQUEST_NONCE,
            by: 1,
        },
        Effect::MapInsert {
            field: map,
            key: rid,
            value: req.av(env),
        },
    ];
    if let Some((field, value)) = view {
        effects.push(Effect::MapInsert { field, key: rid, value });
    }
    effects.push(Effect::ClaimContractCall {
        addr: env.signer_addr,
        ep: env.ep,
        comm: midnight_transient_crypto::hash::transient_commit(&env.call_args(map, &rid)[..], cc_rand),
    });
    effects
}

/// The three claims a surrendered coin's burn makes.
fn burn_effects(env: &Env, coin_nonce: &[u8; 32], color: &[u8; 32], value: u128) -> Vec<Effect> {
    let nonce = b32_slots(coin_nonce);
    vec![
        Effect::ClaimReceive(coin_commitment_of(&nonce, color, value, false, &env.self_addr)),
        Effect::ClaimNullifier(coin_nullifier_of(&nonce, color, value, &env.self_addr)),
        Effect::ClaimSpend(coin_commitment_of(&evolved_nonce(coin_nonce), color, value, true, &[0u8; 32])),
    ]
}

/// A mint of `amount` of the vault token for `erc20` to `left(pk)`.
fn mint_effects(env: &Env, erc20: &[u8; 20], amount: u64, nonce: &[u8; 32], pk: &[u8; 32]) -> Vec<Effect> {
    let color = vault_color(erc20, &env.self_addr);
    vec![
        Effect::MintShielded {
            domain_sep: vault_domain_sep(erc20),
            value: amount,
        },
        Effect::ClaimSpend(coin_commitment_of(&b32_slots(nonce), &color, u128::from(amount), true, pk)),
    ]
}

/// The guards a surrendered coin passes: the vault token's colour, and the
/// exact value.
fn coin_guards(coin_color: [u8; 32], vault_color: [u8; 32], coin_value: u128, amount: u128) -> Option<GuardId> {
    if coin_color != vault_color {
        return Some(GuardId::CoinIsNotTheVaultToken);
    }
    if coin_value != amount {
        return Some(GuardId::CoinValueMustEqualAmount);
    }
    None
}

// ---- the seventeen circuits ----------------------------------------------------

pub fn spec_initialise(s: &InitialiseScenario) -> Outcome {
    if s.env.initialised != 0 {
        return Outcome::Reject(GuardId::AlreadyInitialised);
    }
    if user_commitment(&s.sk) != s.env.deployer() {
        return Outcome::Reject(GuardId::NotTheDeployer);
    }
    if s.chain_id == 0 {
        return Outcome::Reject(GuardId::ChainIdMustBePositive);
    }
    if s.swap_router == [0u8; 20] {
        return Outcome::Reject(GuardId::RouterCannotBeZero);
    }
    if s.stata_underlying == [0u8; 20] {
        return Outcome::Reject(GuardId::StataUnderlyingCannotBeZero);
    }
    if s.stata_token == [0u8; 20] {
        return Outcome::Reject(GuardId::StataTokenCannotBeZero);
    }
    Outcome::Accept(vec![
        Effect::CounterInc {
            field: INITIALISED,
            by: 1,
        },
        Effect::CellWrite {
            field: VAULT_EVM_ADDRESS,
            value: bytesn_value(20, &s.vault_evm),
        },
        Effect::CellWrite {
            field: UNISWAP_ROUTER,
            value: bytesn_value(20, &s.swap_router),
        },
        Effect::CellWrite {
            field: STATA_UNDERLYING,
            value: bytesn_value(20, &s.stata_underlying),
        },
        Effect::CellWrite {
            field: STATA_TOKEN,
            value: bytesn_value(20, &s.stata_token),
        },
        Effect::CellWrite {
            field: EVM_CHAIN_ID,
            value: bytesn_value(8, &s.chain_id.to_le_bytes()),
        },
        Effect::CellWrite {
            field: CAIP2_ID,
            value: bytesn_value(32, &s.caip2),
        },
        Effect::CellWrite {
            field: MPC_RESPONSE_KEY,
            value: point_av(&s.point),
        },
    ])
}

pub fn spec_approve_stata(s: &ApproveStataScenario) -> Outcome {
    if s.env.initialised < 1 {
        return Outcome::Reject(GuardId::NotInitialised);
    }
    if s.key_version == 0 {
        return Outcome::Reject(GuardId::KeyVersionMustBeGe1);
    }
    if s.request_exists {
        return Outcome::Reject(GuardId::RequestAlreadyExists);
    }
    Outcome::Accept(request_effects(&s.env, SIGN_BIDIRECTIONAL_EVENT_MAP, &s.req(), None, s.cc_rand))
}

pub fn spec_approve_router(s: &ApproveRouterScenario) -> Outcome {
    if s.env.initialised < 1 {
        return Outcome::Reject(GuardId::NotInitialised);
    }
    if s.erc20 == [0u8; 20] {
        return Outcome::Reject(GuardId::Erc20AddressCannotBeZero);
    }
    if s.key_version == 0 {
        return Outcome::Reject(GuardId::KeyVersionMustBeGe1);
    }
    if s.request_exists {
        return Outcome::Reject(GuardId::RequestAlreadyExists);
    }
    Outcome::Accept(request_effects(&s.env, SIGN_BIDIRECTIONAL_EVENT_MAP, &s.req(), None, s.cc_rand))
}

pub fn spec_start_deposit(s: &StartDepositScenario) -> Outcome {
    if s.env.initialised < 1 {
        return Outcome::Reject(GuardId::NotInitialised);
    }
    if s.erc20 == [0u8; 20] {
        return Outcome::Reject(GuardId::Erc20AddressCannotBeZero);
    }
    if s.amount == 0 {
        return Outcome::Reject(GuardId::AmountMustBePositive);
    }
    if s.amount > U64_MAX_U128 {
        return Outcome::Reject(GuardId::AmountExceedsUint64Max);
    }
    if s.gas_limit == 0 {
        return Outcome::Reject(GuardId::GasLimitMustBePositive);
    }
    if s.key_version == 0 {
        return Outcome::Reject(GuardId::KeyVersionMustBeGe1);
    }
    if s.request_exists {
        return Outcome::Reject(GuardId::RequestAlreadyExists);
    }
    Outcome::Accept(request_effects(
        &s.env,
        DEPOSIT_EVENT_MAP,
        &s.req(),
        Some((DEPOSIT_SETTLE_VIEWS, s.view_av())),
        s.cc_rand,
    ))
}

pub fn spec_complete_deposit(s: &CompleteDepositScenario) -> Outcome {
    let env = s.env();
    if env.initialised < 1 {
        return Outcome::Reject(GuardId::NotInitialised);
    }
    // deserialize<VaultResponse, 1>(output).success is `byte == 1`.
    if s.serialized_output != 1 {
        return Outcome::Reject(GuardId::Erc20TransferReturnedFalse);
    }
    if !s.settle.pending {
        return Outcome::Reject(GuardId::DepositNotFound);
    }
    if user_commitment(&s.settle.sk(&s.d.sk)) != s.d.commitment() {
        return Outcome::Reject(GuardId::NotTheDepositor);
    }
    let rid = s.d.request_id();
    let cm = s.coin_commitment();
    let mut effects = vec![
        Effect::MapRemove {
            field: DEPOSIT_EVENT_MAP,
            key: rid,
        },
        Effect::MapRemove {
            field: DEPOSIT_SETTLE_VIEWS,
            key: rid,
        },
        Effect::MintShielded {
            domain_sep: vault_domain_sep(&s.d.erc20),
            value: s.d.amount_u64(),
        },
        Effect::ClaimSpend(cm),
    ];
    // The stdlib's auto-receive: minting to a contract that IS this one.
    if s.auto_receive() {
        effects.push(Effect::ClaimReceive(cm));
    }
    Outcome::Accept(effects)
}

pub fn spec_start_withdraw(s: &StartWithdrawScenario) -> Outcome {
    if s.env.initialised < 1 {
        return Outcome::Reject(GuardId::NotInitialised);
    }
    if s.erc20 == [0u8; 20] {
        return Outcome::Reject(GuardId::Erc20AddressCannotBeZero);
    }
    if s.amount == 0 {
        return Outcome::Reject(GuardId::AmountMustBePositive);
    }
    if s.amount > U64_MAX_U128 {
        return Outcome::Reject(GuardId::AmountExceedsUint64Max);
    }
    if let Some(g) = coin_guards(s.coin_color(), s.vault_color(), s.coin_value(), s.amount) {
        return Outcome::Reject(g);
    }
    if s.key_version == 0 {
        return Outcome::Reject(GuardId::KeyVersionMustBeGe1);
    }
    if s.request_exists {
        return Outcome::Reject(GuardId::RequestAlreadyExists);
    }
    let mut effects = burn_effects(&s.env, &s.coin_nonce, &s.coin_color(), s.coin_value());
    effects.extend(request_effects(
        &s.env,
        SIGN_BIDIRECTIONAL_EVENT_MAP,
        &s.req(),
        Some((WITHDRAW_SETTLE_VIEWS, s.view_av())),
        s.cc_rand,
    ));
    Outcome::Accept(effects)
}

/// NOTE the branch condition: `deserialize<VaultResponse, 1>(o).success`
/// is `o == 1`, NOT a canonicity-checked decode, so ANY attested byte other
/// than `0x01` routes to the refund path (the M10 harness finding, kept by
/// upstream).
pub fn spec_complete_withdraw(s: &CompleteWithdrawScenario) -> Outcome {
    let env = s.env();
    if env.initialised < 1 {
        return Outcome::Reject(GuardId::NotInitialised);
    }
    if !s.settle.pending {
        return Outcome::Reject(GuardId::WithdrawalNotFound);
    }
    let rid = s.w.request_id();
    let refunding = s.refunding();
    if refunding && refund_commitment(&s.settle.sk(&s.w.sk), &rid) != s.w.refund_commitment() {
        return Outcome::Reject(GuardId::NotTheWithdrawer);
    }
    let mut effects = vec![Effect::MapRemove {
        field: SIGN_BIDIRECTIONAL_EVENT_MAP,
        key: rid,
    }];
    if refunding {
        effects.extend(mint_effects(env, &s.w.erc20, s.w.amount_u64(), &s.settle.mint_nonce, &s.settle.own_pk));
    }
    effects.push(Effect::MapRemove {
        field: WITHDRAW_SETTLE_VIEWS,
        key: rid,
    });
    Outcome::Accept(effects)
}

/// The failure gate shared by the four refund circuits: initialised, then
/// the attested output must be the fixed 5-byte failure sentinel.
fn failure_gate(env: &Env, output: &[u8; 5]) -> Option<GuardId> {
    if env.initialised < 1 {
        return Some(GuardId::NotInitialised);
    }
    if *output != minocrab_contracts::erc20_vault::MPC_FAILURE_OUTPUT {
        return Some(GuardId::NotTheMpcFailureOutput);
    }
    None
}

pub fn spec_refund_withdraw(s: &RefundWithdrawScenario) -> Outcome {
    let env = s.env();
    if let Some(g) = failure_gate(env, &s.serialized_output) {
        return Outcome::Reject(g);
    }
    if !s.settle.pending {
        return Outcome::Reject(GuardId::WithdrawalNotFound);
    }
    let rid = s.w.request_id();
    if refund_commitment(&s.settle.sk(&s.w.sk), &rid) != s.w.refund_commitment() {
        return Outcome::Reject(GuardId::NotTheWithdrawer);
    }
    let mut effects = vec![
        Effect::MapRemove {
            field: SIGN_BIDIRECTIONAL_EVENT_MAP,
            key: rid,
        },
        Effect::MapRemove {
            field: WITHDRAW_SETTLE_VIEWS,
            key: rid,
        },
    ];
    effects.extend(mint_effects(env, &s.w.erc20, s.w.amount_u64(), &s.settle.mint_nonce, &s.settle.own_pk));
    Outcome::Accept(effects)
}

pub fn spec_start_swap(s: &StartSwapScenario) -> Outcome {
    if s.env.initialised < 1 {
        return Outcome::Reject(GuardId::NotInitialised);
    }
    if s.token_in == [0u8; 20] {
        return Outcome::Reject(GuardId::TokenInCannotBeZero);
    }
    if s.token_out == [0u8; 20] {
        return Outcome::Reject(GuardId::TokenOutCannotBeZero);
    }
    if s.amount_out == 0 {
        return Outcome::Reject(GuardId::AmountOutMustBePositive);
    }
    if s.amount_in_max == 0 {
        return Outcome::Reject(GuardId::AmountInMaximumMustBePositive);
    }
    if s.amount_out > U64_MAX_U128 {
        return Outcome::Reject(GuardId::AmountOutExceedsUint64Max);
    }
    if s.amount_in_max > U64_MAX_U128 {
        return Outcome::Reject(GuardId::AmountInMaximumExceedsUint64Max);
    }
    if let Some(g) = coin_guards(s.coin_color(), s.vault_color(), s.coin_value(), s.amount_in_max) {
        return Outcome::Reject(g);
    }
    if s.key_version == 0 {
        return Outcome::Reject(GuardId::KeyVersionMustBeGe1);
    }
    if s.request_exists {
        return Outcome::Reject(GuardId::RequestAlreadyExists);
    }
    let mut effects = burn_effects(&s.env, &s.coin_nonce, &s.coin_color(), s.coin_value());
    effects.extend(request_effects(
        &s.env,
        SWAP_EVENT_MAP,
        &s.req(),
        Some((SWAP_SETTLE_VIEWS, s.view_av())),
        s.cc_rand,
    ));
    Outcome::Accept(effects)
}

pub fn spec_complete_swap(s: &CompleteSwapScenario) -> Outcome {
    let env = s.env();
    if env.initialised < 1 {
        return Outcome::Reject(GuardId::NotInitialised);
    }
    if s.change_nonce == s.settle.mint_nonce {
        return Outcome::Reject(GuardId::ChangeNonceMustDiffer);
    }
    if !s.settle.pending {
        return Outcome::Reject(GuardId::SwapNotFound);
    }
    let rid = s.s.request_id();
    if refund_commitment(&s.settle.sk(&s.s.sk), &rid) != s.s.refund_commitment() {
        return Outcome::Reject(GuardId::NotTheSwapper);
    }
    let Some(change) = s.change() else {
        return Outcome::Reject(GuardId::ChangeUnderflow);
    };
    let mut effects = vec![
        Effect::MapRemove {
            field: SWAP_EVENT_MAP,
            key: rid,
        },
        Effect::MapRemove {
            field: SWAP_SETTLE_VIEWS,
            key: rid,
        },
    ];
    effects.extend(mint_effects(env, &s.s.token_out, s.s.amount_out_u64(), &s.settle.mint_nonce, &s.settle.own_pk));
    effects.extend(mint_effects(env, &s.s.token_in, change, &s.change_nonce, &s.settle.own_pk));
    Outcome::Accept(effects)
}

pub fn spec_refund_swap(s: &RefundSwapScenario) -> Outcome {
    let env = s.env();
    if let Some(g) = failure_gate(env, &s.serialized_output) {
        return Outcome::Reject(g);
    }
    if !s.settle.pending {
        return Outcome::Reject(GuardId::SwapNotFound);
    }
    let rid = s.s.request_id();
    if refund_commitment(&s.settle.sk(&s.s.sk), &rid) != s.s.refund_commitment() {
        return Outcome::Reject(GuardId::NotTheSwapper);
    }
    let mut effects = vec![
        Effect::MapRemove {
            field: SWAP_EVENT_MAP,
            key: rid,
        },
        Effect::MapRemove {
            field: SWAP_SETTLE_VIEWS,
            key: rid,
        },
    ];
    effects.extend(mint_effects(env, &s.s.token_in, s.s.amount_in_max_u64(), &s.settle.mint_nonce, &s.settle.own_pk));
    Outcome::Accept(effects)
}

pub fn spec_start_supply(s: &StartSupplyScenario) -> Outcome {
    if s.env.initialised < 1 {
        return Outcome::Reject(GuardId::NotInitialised);
    }
    if s.amount == 0 {
        return Outcome::Reject(GuardId::AmountMustBePositive);
    }
    if s.amount > U64_MAX_U128 {
        return Outcome::Reject(GuardId::AmountExceedsUint64Max);
    }
    if let Some(g) = coin_guards(s.coin_color(), s.vault_color(), s.coin_value(), s.amount) {
        return Outcome::Reject(g);
    }
    if s.key_version == 0 {
        return Outcome::Reject(GuardId::KeyVersionMustBeGe1);
    }
    if s.request_exists {
        return Outcome::Reject(GuardId::RequestAlreadyExists);
    }
    let mut effects = burn_effects(&s.env, &s.coin_nonce, &s.coin_color(), s.coin_value());
    effects.extend(request_effects(
        &s.env,
        SUPPLY_EVENT_MAP,
        &s.req(),
        Some((SUPPLY_SETTLE_VIEWS, s.view_av())),
        s.cc_rand,
    ));
    Outcome::Accept(effects)
}

pub fn spec_complete_supply(s: &CompleteSupplyScenario) -> Outcome {
    let env = s.env();
    if env.initialised < 1 {
        return Outcome::Reject(GuardId::NotInitialised);
    }
    if !s.settle.pending {
        return Outcome::Reject(GuardId::SupplyNotFound);
    }
    let rid = s.s.request_id();
    if refund_commitment(&s.settle.sk(&s.s.sk), &rid) != s.s.refund_commitment() {
        return Outcome::Reject(GuardId::NotTheSupplier);
    }
    let mut effects = vec![
        Effect::MapRemove {
            field: SUPPLY_EVENT_MAP,
            key: rid,
        },
        Effect::MapRemove {
            field: SUPPLY_SETTLE_VIEWS,
            key: rid,
        },
    ];
    effects.extend(mint_effects(env, &env.stata_token, s.shares, &s.settle.mint_nonce, &s.settle.own_pk));
    Outcome::Accept(effects)
}

pub fn spec_refund_supply(s: &RefundSupplyScenario) -> Outcome {
    let env = s.env();
    if let Some(g) = failure_gate(env, &s.serialized_output) {
        return Outcome::Reject(g);
    }
    if !s.settle.pending {
        return Outcome::Reject(GuardId::SupplyNotFound);
    }
    let rid = s.s.request_id();
    if refund_commitment(&s.settle.sk(&s.s.sk), &rid) != s.s.refund_commitment() {
        return Outcome::Reject(GuardId::NotTheSupplier);
    }
    let mut effects = vec![
        Effect::MapRemove {
            field: SUPPLY_EVENT_MAP,
            key: rid,
        },
        Effect::MapRemove {
            field: SUPPLY_SETTLE_VIEWS,
            key: rid,
        },
    ];
    effects.extend(mint_effects(env, &env.stata_underlying, s.s.amount_u64(), &s.settle.mint_nonce, &s.settle.own_pk));
    Outcome::Accept(effects)
}

pub fn spec_start_redeem(s: &StartRedeemScenario) -> Outcome {
    if s.env.initialised < 1 {
        return Outcome::Reject(GuardId::NotInitialised);
    }
    if s.shares == 0 {
        return Outcome::Reject(GuardId::SharesMustBePositive);
    }
    if s.shares > U64_MAX_U128 {
        return Outcome::Reject(GuardId::SharesExceedUint64Max);
    }
    if let Some(g) = coin_guards(s.coin_color(), s.vault_color(), s.coin_value(), s.shares) {
        return Outcome::Reject(g);
    }
    if s.key_version == 0 {
        return Outcome::Reject(GuardId::KeyVersionMustBeGe1);
    }
    if s.request_exists {
        return Outcome::Reject(GuardId::RequestAlreadyExists);
    }
    let mut effects = burn_effects(&s.env, &s.coin_nonce, &s.coin_color(), s.coin_value());
    effects.extend(request_effects(
        &s.env,
        REDEEM_EVENT_MAP,
        &s.req(),
        Some((REDEEM_SETTLE_VIEWS, s.view_av())),
        s.cc_rand,
    ));
    Outcome::Accept(effects)
}

pub fn spec_complete_redeem(s: &CompleteRedeemScenario) -> Outcome {
    let env = s.env();
    if env.initialised < 1 {
        return Outcome::Reject(GuardId::NotInitialised);
    }
    if !s.settle.pending {
        return Outcome::Reject(GuardId::RedeemNotFound);
    }
    let rid = s.s.request_id();
    if refund_commitment(&s.settle.sk(&s.s.sk), &rid) != s.s.refund_commitment() {
        return Outcome::Reject(GuardId::NotTheRedeemer);
    }
    let mut effects = vec![
        Effect::MapRemove {
            field: REDEEM_EVENT_MAP,
            key: rid,
        },
        Effect::MapRemove {
            field: REDEEM_SETTLE_VIEWS,
            key: rid,
        },
    ];
    effects.extend(mint_effects(env, &env.stata_underlying, s.assets, &s.settle.mint_nonce, &s.settle.own_pk));
    Outcome::Accept(effects)
}

pub fn spec_refund_redeem(s: &RefundRedeemScenario) -> Outcome {
    let env = s.env();
    if let Some(g) = failure_gate(env, &s.serialized_output) {
        return Outcome::Reject(g);
    }
    if !s.settle.pending {
        return Outcome::Reject(GuardId::RedeemNotFound);
    }
    let rid = s.s.request_id();
    if refund_commitment(&s.settle.sk(&s.s.sk), &rid) != s.s.refund_commitment() {
        return Outcome::Reject(GuardId::NotTheRedeemer);
    }
    let mut effects = vec![
        Effect::MapRemove {
            field: REDEEM_EVENT_MAP,
            key: rid,
        },
        Effect::MapRemove {
            field: REDEEM_SETTLE_VIEWS,
            key: rid,
        },
    ];
    effects.extend(mint_effects(env, &env.stata_token, s.s.shares_u64(), &s.settle.mint_nonce, &s.settle.own_pk));
    Outcome::Accept(effects)
}

// ---- checking a spec against what the reference VM produced -------------------

fn pre_counter(pre: &PreState, field: u8) -> u64 {
    match field {
        SIGNET_REQUEST_NONCE => pre.request_nonce,
        INITIALISED => pre.initialised,
        other => panic!("field {other} is not a counter"),
    }
}

/// Every declared effect holds of the executed run, and the run declares
/// nothing beyond them: counters advanced by exactly `by`, inserted keys
/// present with the declared value, removed keys absent, cells holding the
/// declared bytes, and the four kernel claim sets plus the mint totals equal
/// as SETS to the declared ones.
pub fn check_effects(effects: &[Effect], pre: &PreState, ex: &Executed) -> Result<(), String> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut want_nul: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut want_recv: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut want_spend: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut want_mint: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    let mut want_calls: BTreeSet<(u64, [u8; 32], [u8; 32], Fr)> = BTreeSet::new();
    let mut call_seq: u64 = 0;

    for e in effects {
        match e {
            Effect::CounterInc { field, by } => {
                let want = pre_counter(pre, *field) + by;
                let got = exec::counter(&ex.post, *field)
                    .ok_or_else(|| format!("field {field} is not a counter cell after the run"))?;
                if got != want {
                    return Err(format!("counter {field}: want {want}, got {got}"));
                }
            }
            Effect::MapInsert { field, key, value } => {
                let got = exec::map_get(&ex.post, *field, key)
                    .ok_or_else(|| format!("map {field} lacks the inserted key"))?;
                if &got != value {
                    return Err(format!("map {field}: inserted value differs"));
                }
            }
            Effect::MapRemove { field, key } => {
                if exec::map_member(&ex.post, *field, key) {
                    return Err(format!("map {field}: key survived the removal"));
                }
            }
            Effect::CellWrite { field, value } => {
                let got = exec::cell_bytes(&ex.post, *field)
                    .ok_or_else(|| format!("field {field} is not a cell after the run"))?;
                let want = value.value.0.first().map(|a| a.0.clone()).unwrap_or_default();
                if got != want {
                    return Err(format!("cell {field}: want {want:?}, got {got:?}"));
                }
            }
            Effect::MintShielded { domain_sep, value } => {
                *want_mint.entry(*domain_sep).or_insert(0) += value;
            }
            Effect::ClaimSpend(cm) => {
                want_spend.insert(*cm);
            }
            Effect::ClaimReceive(cm) => {
                want_recv.insert(*cm);
            }
            Effect::ClaimNullifier(n) => {
                want_nul.insert(*n);
            }
            Effect::ClaimContractCall { addr, ep, comm } => {
                want_calls.insert((call_seq, *addr, *ep, *comm));
                call_seq += 1;
            }
        }
    }

    let got_nul: BTreeSet<[u8; 32]> = ex.effects.claimed_nullifiers.iter().map(|n| n.0 .0).collect();
    let got_recv: BTreeSet<[u8; 32]> = ex.effects.claimed_shielded_receives.iter().map(|c| c.0 .0).collect();
    let got_spend: BTreeSet<[u8; 32]> = ex.effects.claimed_shielded_spends.iter().map(|c| c.0 .0).collect();
    let got_mint: BTreeMap<[u8; 32], u64> = ex.effects.shielded_mints.iter().map(|kv| (kv.0 .0, *kv.1)).collect();
    let got_calls: BTreeSet<(u64, [u8; 32], [u8; 32], Fr)> = ex
        .effects
        .claimed_contract_calls
        .iter()
        .map(|c| {
            let (seq, addr, ep, comm) = c.into_inner();
            (seq, addr.0 .0, ep.0, comm)
        })
        .collect();

    if got_nul != want_nul {
        return Err(format!("nullifiers: want {want_nul:?}, got {got_nul:?}"));
    }
    if got_recv != want_recv {
        return Err(format!("receives: want {want_recv:?}, got {got_recv:?}"));
    }
    if got_spend != want_spend {
        return Err(format!("spends: want {want_spend:?}, got {got_spend:?}"));
    }
    if got_mint != want_mint {
        return Err(format!("mints: want {want_mint:?}, got {got_mint:?}"));
    }
    if got_calls != want_calls {
        return Err(format!("calls: want {want_calls:?}, got {got_calls:?}"));
    }
    // The vault touches no unshielded balance at all.
    if !ex.effects.unshielded_mints.is_empty()
        || !ex.effects.unshielded_inputs.is_empty()
        || !ex.effects.unshielded_outputs.is_empty()
        || !ex.effects.claimed_unshielded_spends.is_empty()
    {
        return Err("unexpected unshielded effects".into());
    }
    Ok(())
}
