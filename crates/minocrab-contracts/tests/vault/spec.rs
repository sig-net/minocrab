//! The erc20-vault SPEC: nine total functions, one per circuit, from
//! (pre-state, arguments, witnesses) to an [`Outcome`].
//!
//! Written from `corpus/src/signet-midnight-examples/examples/erc20-vault/
//! contract/src/erc20-vault.compact` and the `Signet.compact` helpers it
//! calls — the Compact source is the authority, not the port and not the
//! notes. Where the two disagreed the disagreements are recorded in
//! notes/vault-optimization.org §"As built — step 1".
//!
//! # Why the effects are symbolic
//!
//! An [`Effect`] names a state change; a [`Term`] names a VALUE by what it
//! *is* (`UserCommit`, `DomainSep`, `RefundCommit`, `RequestId`,
//! `TokenType`, `CoinCm`) rather than by how this artifact hashes it. The
//! compat port concretises `UserCommit` as SHA-256 over a 64-byte preimage
//! ([`Term::concretize`], which delegates to [`super::prims`]); an
//! optimized artifact that swaps it for Poseidon supplies a different
//! concretization and reuses THIS spec unchanged. The set of
//! concretization choices IS the deviation log
//! (notes/vault-optimization.org §"Specs").
//!
//! # What the spec does and does not decide
//!
//! It decides: which guards hold, which branch runs, which fields change,
//! which coins are minted/spent/received, and with which amounts. It does
//! NOT re-derive the protocol-pinned encodings (the 33/43-limb request
//! record, the FAB binary the request id hashes) — those come from the
//! shared concretization in [`super::model`]/[`super::prims`], and are
//! independently pinned by the differential suite's PI-equality against
//! compactc's artifacts. Chain of trust, not circular reasoning: the
//! record layout is anchored one link up.
//!
//! # The attestation guard
//!
//! `verifyRespondBidirectionalEvent` is a real guard, but the scenarios
//! construct valid signatures by construction, so under generation it is
//! always satisfied. Its failure mode is exercised where it belongs — the
//! adversarial sweeps, which corrupt `r`/`s`/the digest directly.

use midnight_base_crypto::fab::AlignedValue;
use midnight_coin_structure::coin::{Commitment as CoinCommitment, Nullifier};
use midnight_base_crypto::hash::HashOutput;
use midnight_onchain_state::state::StateValue;
use minocrab::Fr;
use minocrab_contracts::erc20_vault as v;

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
    // initialize
    AlreadyInitialized,
    NotTheDeployer,
    ChainIdMustBePositive,
    RouterCannotBeZero,
    // request circuits
    NotInitialized,
    Erc20AddressCannotBeZero,
    AmountMustBePositive,
    AmountExceedsUint64Max,
    GasLimitMustBePositive,
    /// `Signet.compact:149` — inside `constructSignBidirectionalEvent`.
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
    // settle circuits
    Erc20TransferReturnedFalse,
    InvalidAttestationSignature,
    RequestNotFound,
    NotTheDepositor,
    RequestHasNoCalldata,
    /// `Signet.compact:438` — inside `abiWordToUint128`.
    AbiWordExceedsUint128,
    WithdrawalNotFound,
    NotTheWithdrawer,
    NotTheMpcFailureOutput,
    SwapNotFound,
    NotTheSwapper,
    /// completeSwap's `amountInMaximum - amountIn`: Compact's unsigned
    /// subtraction asserts no underflow, and the port spells that out as
    /// an explicit `!(amountInMaximum < amountIn)` (erc20_vault.rs:1323).
    /// The most dangerous arithmetic in the contract.
    ChangeUnderflow,
}

/// A value the contract derives, named by WHAT it is.
///
/// The variants that are hash constructions (`UserCommit`, `RefundCommit`,
/// `DomainSep`, `ChangeNonce`) are exactly the M10 deviation surface; the
/// rest (`RequestId`, `TokenType`, `CoinCm`, `CoinNul`, `EvolvedNonce`) are
/// protocol-pinned and must concretise identically in every artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Term {
    /// A value the contract does not derive (an argument, a stored byte
    /// string, a literal).
    Const([u8; 32]),
    /// `userCommitment(sk)` — DISCRETIONARY.
    UserCommit { sk: [u8; 32] },
    /// `withdrawRefundCommitment(sk, requestId)` — DISCRETIONARY.
    RefundCommit {
        sk: [u8; 32],
        request_id: Box<Term>,
    },
    /// `vaultTokenDomainSeparator(erc20)` — DISCRETIONARY.
    DomainSep { erc20: [u8; 20] },
    /// `persistentHash([mintNonce, pad("change")])` — DISCRETIONARY.
    ChangeNonce { mint_nonce: Box<Term> },
    /// `calculateRequestId(record)` — PINNED (keccak over the record's
    /// FAB binary; the MPC decodes the record from raw ledger state).
    RequestId { record: AlignedValue },
    /// `tokenType(domainSep, addr)` — PINNED (the ledger derives the
    /// colour itself, coin-structure/src/contract.rs:58-68).
    TokenType { sep: Box<Term>, addr: [u8; 32] },
    /// `coinCommitment(coin, recipient)` — PINNED (zswap's preimage).
    CoinCm {
        nonce: Box<Term>,
        color: Box<Term>,
        value: u64,
        is_left: bool,
        data: [u8; 32],
    },
    /// `coinNullifier(coin, contractAddress)` — PINNED.
    CoinNul {
        nonce: Box<Term>,
        color: Box<Term>,
        value: u64,
        addr: [u8; 32],
    },
    /// The kernel's nonce evolution before a spend — PINNED.
    EvolvedNonce { nonce: Box<Term> },
}

impl Term {
    pub fn c(bytes: [u8; 32]) -> Term {
        Term::Const(bytes)
    }

    /// CONCRETIZE: realise the term as the 32 bytes `art`'s circuits
    /// actually compute. THE artifact-swap point — the discretionary
    /// variants delegate to [`super::prims`], whose `Art::Opt` arms are the
    /// deviation log; the pinned ones ignore `art` by construction.
    pub fn concretize(&self, art: Art) -> [u8; 32] {
        match self {
            Term::Const(b) => *b,
            Term::UserCommit { sk } => user_commitment(art, sk),
            Term::RefundCommit { sk, request_id } => {
                refund_commitment(art, sk, &request_id.concretize(art))
            }
            Term::DomainSep { erc20 } => vault_domain_sep(art, erc20),
            Term::ChangeNonce { mint_nonce } => change_nonce(art, &mint_nonce.concretize(art)),
            Term::RequestId { record } => {
                use midnight_base_crypto::repr::BinaryHashRepr;
                use midnight_transient_crypto::fab::ValueReprAlignedValue;
                use sha2::Digest;
                let mut repr = Vec::new();
                ValueReprAlignedValue(record.clone()).binary_repr(&mut repr);
                sha3::Keccak256::digest(&repr).into()
            }
            Term::TokenType { sep, addr } => {
                let (d_hi, d_lo) = b32_slots(&sep.concretize(art));
                let (t_hi, t_lo) = b32_slots(&pad32("midnight:derive_token"));
                let (s_hi, s_lo) = b32_slots(addr);
                fab_sha256(
                    vec![atom(32), atom(32), atom(32)],
                    &[t_hi, t_lo, d_hi, d_lo, s_hi, s_lo],
                )
            }
            Term::CoinCm {
                nonce,
                color,
                value,
                is_left,
                data,
            } => coin_commitment_of(
                &b32_slots(&nonce.concretize(art)),
                &color.concretize(art),
                *value,
                *is_left,
                data,
            ),
            Term::CoinNul {
                nonce,
                color,
                value,
                addr,
            } => coin_nullifier_of(
                &b32_slots(&nonce.concretize(art)),
                &color.concretize(art),
                *value,
                addr,
            ),
            Term::EvolvedNonce { nonce } => {
                let (_hi, lo) = evolved_nonce(&nonce.concretize(art));
                let mut out = [0u8; 32];
                out[..31].copy_from_slice(&lo.as_le_bytes()[..31]);
                out
            }
        }
    }
}

/// A map value: either a derived term or a protocol-pinned record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Val {
    Term(Term),
    Record(AlignedValue),
}

/// One declared state change or ledger claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    CounterInc { field: u8, by: u64 },
    MapInsert { field: u8, key: Term, value: Val },
    MapRemove { field: u8, key: Term },
    CellWrite { field: u8, value: AlignedValue },
    MintShielded { domain_sep: Term, value: u64 },
    ClaimSpend(Term),
    ClaimReceive(Term),
    ClaimNullifier(Term),
    ClaimContractCall { addr: [u8; 32], ep: [u8; 32], comm: Fr },
}

/// What a circuit does with one call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Reject(GuardId),
    Accept {
        effects: Vec<Effect>,
        /// The values the circuit `disclose()`s. Carried by hand until M9
        /// phase 6's disclosure declarations can machine-check them
        /// (notes/vault-optimization.org §Sequencing).
        disclosures: Vec<&'static str>,
    },
}

impl Outcome {
    pub fn accepts(&self) -> bool {
        matches!(self, Outcome::Accept { .. })
    }
    pub fn guard(&self) -> Option<GuardId> {
        match self {
            Outcome::Reject(g) => Some(*g),
            _ => None,
        }
    }
    pub fn effects(&self) -> &[Effect] {
        match self {
            Outcome::Accept { effects, .. } => effects,
            _ => &[],
        }
    }
}

/// `accept` with no disclosures declared yet.
fn accept(effects: Vec<Effect>) -> Outcome {
    Outcome::Accept {
        effects,
        disclosures: Vec::new(),
    }
}

fn accept_d(effects: Vec<Effect>, disclosures: Vec<&'static str>) -> Outcome {
    Outcome::Accept {
        effects,
        disclosures,
    }
}

const U64_MAX_U128: u128 = u64::MAX as u128;

// --- the nine circuits --------------------------------------------------------

/// `initialize(vaultEvm, swapRouter, chainId, chainCaip2Id, responseKey)`
/// with `initialized == count` (erc20-vault.compact:216-233).
pub fn spec_initialize(s: &Scenario, count: u64) -> Outcome {
    if count != 0 {
        return Outcome::Reject(GuardId::AlreadyInitialized);
    }
    if user_commitment(s.art, &s.sk) != s.commitment() {
        return Outcome::Reject(GuardId::NotTheDeployer);
    }
    if s.chain_id == 0 {
        return Outcome::Reject(GuardId::ChainIdMustBePositive);
    }
    if s.swap_router == [0u8; 20] {
        return Outcome::Reject(GuardId::RouterCannotBeZero);
    }
    accept_d(
        vec![
            Effect::CounterInc {
                field: v::INITIALIZED,
                by: 1,
            },
            Effect::CellWrite {
                field: v::VAULT_EVM_ADDRESS,
                value: bytesn_value(20, &s.vault_evm),
            },
            Effect::CellWrite {
                field: v::UNISWAP_ROUTER,
                value: bytesn_value(20, &s.swap_router),
            },
            Effect::CellWrite {
                field: v::EVM_CHAIN_ID,
                value: bytesn_value(8, &s.chain_id.to_le_bytes()),
            },
            Effect::CellWrite {
                field: v::CAIP2_ID,
                value: bytesn_value(32, &s.caip2),
            },
            Effect::CellWrite {
                field: v::MPC_RESPONSE_KEY,
                value: s.point_av(),
            },
        ],
        vec![
            "vaultEvmAddress",
            "uniswapRouter",
            "evmChainId",
            "caip2Id",
            "mpcResponseKey",
        ],
    )
}

/// `deposit(...)` (erc20-vault.compact:251-334).
pub fn spec_deposit(s: &DepositScenario) -> Outcome {
    if s.initialized < 1 {
        return Outcome::Reject(GuardId::NotInitialized);
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
    let rid = Term::RequestId {
        record: s.event_av(),
    };
    accept_d(
        vec![
            Effect::CounterInc {
                field: v::SIGNET_REQUEST_NONCE,
                by: 1,
            },
            Effect::MapInsert {
                field: v::SIGN_BIDIRECTIONAL_EVENT_MAP,
                key: rid,
                value: Val::Record(s.event_av()),
            },
            Effect::ClaimContractCall {
                addr: s.signer_addr,
                ep: s.ep,
                comm: midnight_transient_crypto::hash::transient_commit(
                    &s.call_args()[..],
                    s.cc_rand,
                ),
            },
        ],
        vec!["depositor identity commitment", "request id", "request record"],
    )
}

/// `approveRouter(erc20Address, evmNonce, keyVersion)`
/// (erc20-vault.compact:696-762).
pub fn spec_approve_router(s: &ApproveScenario) -> Outcome {
    if s.initialized < 1 {
        return Outcome::Reject(GuardId::NotInitialized);
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
    accept_d(
        vec![
            Effect::CounterInc {
                field: v::SIGNET_REQUEST_NONCE,
                by: 1,
            },
            Effect::MapInsert {
                field: v::SIGN_BIDIRECTIONAL_EVENT_MAP,
                key: Term::RequestId {
                    record: s.event_av(),
                },
                value: Val::Record(s.event_av()),
            },
            Effect::ClaimContractCall {
                addr: s.signer_addr,
                ep: s.ep,
                comm: midnight_transient_crypto::hash::transient_commit(
                    &s.call_args()[..],
                    s.cc_rand,
                ),
            },
        ],
        vec!["approved ERC20", "request id", "request record"],
    )
}

/// `withdraw(evmNonce, keyVersion, withdrawRequest, coin)`
/// (erc20-vault.compact:420-517).
pub fn spec_withdraw(s: &WithdrawScenario) -> Outcome {
    if s.initialized < 1 {
        return Outcome::Reject(GuardId::NotInitialized);
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
    // The coin's colour and value are model invariants (it is built as the
    // vault token for `erc20` of exactly `amount`); the two guards below
    // are exercised by the adversarial suite's input mutations.
    if s.key_version == 0 {
        return Outcome::Reject(GuardId::KeyVersionMustBeGe1);
    }
    if s.request_exists {
        return Outcome::Reject(GuardId::RequestAlreadyExists);
    }
    let value = s.amount_u64();
    let color = Term::TokenType {
        sep: Box::new(Term::DomainSep { erc20: s.erc20 }),
        addr: s.self_addr,
    };
    let nonce = Term::c(s.coin_nonce);
    let rid = Term::RequestId {
        record: s.event_av(),
    };
    // The burn. The compat port takes custody (receiveShielded) then spends
    // (sendImmediateShielded: nullifier + evolved-nonce output). The optimized
    // artifact (rung vi, avenue 6) claims a SINGLE shielded spend of the
    // burn-output commitment and NOTHING else — the receive and nullifier are
    // gone (the user funds the burn Output directly). check_effects asserts
    // this multiset EXACTLY, so on the opt side the empty receive/nullifier
    // sets are obligation (1) and the constrained-colour/value burn commitment
    // is obligation (2), both enforced per generated case.
    let mut effects = Vec::new();
    if s.art == Art::Compat {
        effects.push(Effect::ClaimReceive(Term::CoinCm {
            nonce: Box::new(nonce.clone()),
            color: Box::new(color.clone()),
            value,
            is_left: false,
            data: s.self_addr,
        }));
        effects.push(Effect::ClaimNullifier(Term::CoinNul {
            nonce: Box::new(nonce.clone()),
            color: Box::new(color.clone()),
            value,
            addr: s.self_addr,
        }));
    }
    effects.push(Effect::ClaimSpend(Term::CoinCm {
        nonce: Box::new(Term::EvolvedNonce {
            nonce: Box::new(nonce),
        }),
        color: Box::new(color),
        value,
        is_left: true,
        data: [0u8; 32],
    }));
    effects.extend([
        Effect::CounterInc {
            field: v::SIGNET_REQUEST_NONCE,
            by: 1,
        },
        Effect::MapInsert {
            field: v::SIGN_BIDIRECTIONAL_EVENT_MAP,
            key: rid.clone(),
            value: Val::Record(s.event_av()),
        },
        Effect::MapInsert {
            field: v::REFUND_COMMITMENT,
            key: rid.clone(),
            value: Val::Term(Term::RefundCommit {
                sk: s.sk,
                request_id: Box::new(rid),
            }),
        },
        Effect::ClaimContractCall {
            addr: s.signer_addr,
            ep: s.ep,
            comm: midnight_transient_crypto::hash::transient_commit(
                &s.call_args()[..],
                s.cc_rand,
            ),
        },
    ]);
    accept_d(
        effects,
        vec![
            "the withdrawn ERC20",
            "surrendered coin",
            "request id",
            "request record",
            "withdrawer refund commitment",
        ],
    )
}

/// `swap(evmNonce, keyVersion, swapRequest, coin)`
/// (erc20-vault.compact:787-886).
pub fn spec_swap(s: &SwapScenario) -> Outcome {
    if s.initialized < 1 {
        return Outcome::Reject(GuardId::NotInitialized);
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
    if s.key_version == 0 {
        return Outcome::Reject(GuardId::KeyVersionMustBeGe1);
    }
    if s.request_exists {
        return Outcome::Reject(GuardId::RequestAlreadyExists);
    }
    let value = s.amount_in_max_u64();
    let color = Term::TokenType {
        sep: Box::new(Term::DomainSep { erc20: s.token_in }),
        addr: s.self_addr,
    };
    let nonce = Term::c(s.coin_nonce);
    let rid = Term::RequestId {
        record: s.event_av(),
    };
    // The burn — as in withdraw. Compat: receive + nullifier + evolved-nonce
    // output spend. Opt (rung vi, avenue 6): a SINGLE claimed shielded spend
    // of the burn-output commitment, obligations (1) and (2) enforced by
    // check_effects' exact-multiset comparison.
    let mut effects = Vec::new();
    if s.art == Art::Compat {
        effects.push(Effect::ClaimReceive(Term::CoinCm {
            nonce: Box::new(nonce.clone()),
            color: Box::new(color.clone()),
            value,
            is_left: false,
            data: s.self_addr,
        }));
        effects.push(Effect::ClaimNullifier(Term::CoinNul {
            nonce: Box::new(nonce.clone()),
            color: Box::new(color.clone()),
            value,
            addr: s.self_addr,
        }));
    }
    effects.push(Effect::ClaimSpend(Term::CoinCm {
        nonce: Box::new(Term::EvolvedNonce {
            nonce: Box::new(nonce),
        }),
        color: Box::new(color),
        value,
        is_left: true,
        data: [0u8; 32],
    }));
    effects.extend([
        Effect::CounterInc {
            field: v::SIGNET_REQUEST_NONCE,
            by: 1,
        },
        Effect::MapInsert {
            field: v::SWAP_EVENT_MAP,
            key: rid.clone(),
            value: Val::Record(s.event_av()),
        },
        Effect::MapInsert {
            field: v::SWAP_REFUND_COMMITMENT,
            key: rid.clone(),
            value: Val::Term(Term::RefundCommit {
                sk: s.sk,
                request_id: Box::new(rid),
            }),
        },
        Effect::ClaimContractCall {
            addr: s.signer_addr,
            ep: s.ep,
            comm: midnight_transient_crypto::hash::transient_commit(
                &s.call_args()[..],
                s.cc_rand,
            ),
        },
    ]);
    accept_d(
        effects,
        vec![
            "the sold ERC20",
            "the bought ERC20",
            "surrendered coin",
            "request id",
            "request record",
            "swapper refund commitment",
        ],
    )
}

/// `claim(requestId, respondBidirectionalEvent, serializedOutput,
/// mintNonce, recipient)` (erc20-vault.compact:344-397).
pub fn spec_claim(s: &ClaimScenario) -> Outcome {
    if s.d.initialized < 1 {
        return Outcome::Reject(GuardId::NotInitialized);
    }
    // deserialize<VaultResponse, 1>(output).success is `byte == 1`.
    if s.serialized_output != 1 {
        return Outcome::Reject(GuardId::Erc20TransferReturnedFalse);
    }
    if !s.found {
        return Outcome::Reject(GuardId::RequestNotFound);
    }
    if user_commitment(s.art(), &s.claimant_sk()) != user_commitment(s.art(), &s.d.sk) {
        return Outcome::Reject(GuardId::NotTheDepositor);
    }
    let amount = s.d.amount_u64();
    let (is_left, data) = s.recipient_data();
    let color = Term::TokenType {
        sep: Box::new(Term::DomainSep { erc20: s.d.erc20 }),
        addr: s.d.self_addr,
    };
    let cm = Term::CoinCm {
        nonce: Box::new(Term::c(s.mint_nonce)),
        color: Box::new(color),
        value: amount,
        is_left,
        data,
    };
    let mut effects = vec![
        Effect::MapRemove {
            field: v::SIGN_BIDIRECTIONAL_EVENT_MAP,
            key: Term::RequestId {
                record: s.d.event_av(),
            },
        },
        Effect::MintShielded {
            domain_sep: Term::DomainSep { erc20: s.d.erc20 },
            value: amount,
        },
        Effect::ClaimSpend(cm.clone()),
    ];
    // The stdlib's auto-receive: minting to a contract that IS this one.
    if s.auto_receive() {
        effects.push(Effect::ClaimReceive(cm));
    }
    accept_d(
        effects,
        vec!["request id", "claim recipient", "claim mint nonce"],
    )
}

/// `completeWithdraw(requestId, respondBidirectionalEvent,
/// serializedOutput, mintNonce)` (erc20-vault.compact:560-605).
///
/// NOTE the branch condition: `deserialize<VaultResponse, 1>(o).success`
/// is `o == 1`, NOT a canonicity-checked decode, so ANY attested byte
/// other than `0x01` routes to the refund path. See the disagreement note
/// in notes/vault-optimization.org §"As built — step 1".
pub fn spec_complete_withdraw(s: &CompleteWithdrawScenario) -> Outcome {
    if s.w.initialized < 1 {
        return Outcome::Reject(GuardId::NotInitialized);
    }
    if !s.pending {
        return Outcome::Reject(GuardId::WithdrawalNotFound);
    }
    let refunding = s.outcome != 1;
    let presented = Term::RefundCommit {
        sk: s.claimant_sk(),
        request_id: Box::new(Term::c(s.w.request_id())),
    }
    .concretize(s.art());
    if refunding && presented != s.w.refund_commitment() {
        return Outcome::Reject(GuardId::NotTheWithdrawer);
    }
    let mut effects = vec![Effect::MapRemove {
        field: v::SIGN_BIDIRECTIONAL_EVENT_MAP,
        key: Term::c(s.w.request_id()),
    }];
    if refunding {
        let amount = s.w.amount_u64();
        effects.push(Effect::MintShielded {
            domain_sep: Term::DomainSep { erc20: s.w.erc20 },
            value: amount,
        });
        effects.push(Effect::ClaimSpend(Term::CoinCm {
            nonce: Box::new(Term::c(s.mint_nonce)),
            color: Box::new(Term::TokenType {
                sep: Box::new(Term::DomainSep { erc20: s.w.erc20 }),
                addr: s.w.self_addr,
            }),
            value: amount,
            is_left: true,
            data: s.own_pk,
        }));
    }
    effects.push(Effect::MapRemove {
        field: v::REFUND_COMMITMENT,
        key: Term::c(s.w.request_id()),
    });
    accept_d(
        effects,
        vec!["request id", "withdrawal EVM outcome", "refund mint nonce"],
    )
}

/// `completeSwap(requestId, respondBidirectionalEvent, serializedOutput,
/// mintNonce)` (erc20-vault.compact:895-951).
pub fn spec_complete_swap(s: &CompleteSwapScenario) -> Outcome {
    if s.s.initialized < 1 {
        return Outcome::Reject(GuardId::NotInitialized);
    }
    if !s.pending {
        return Outcome::Reject(GuardId::SwapNotFound);
    }
    let presented = Term::RefundCommit {
        sk: s.claimant_sk(),
        request_id: Box::new(Term::c(s.s.request_id())),
    }
    .concretize(s.art());
    if presented != s.s.refund_commitment() {
        return Outcome::Reject(GuardId::NotTheSwapper);
    }
    // THE dangerous arithmetic: `change = amountInMaximum - amountIn` over
    // Uint<128>. Compact's unsigned `-` asserts no underflow; the port
    // spells it as `!(amountInMaximum < amountIn)`. The attested amountIn
    // is a uint64 the MPC repacked, and amountInMaximum was bounded to
    // uint64 at request time, so the whole comparison lives in u64 — but
    // an attestation over amountIn > amountInMaximum is entirely
    // constructible by a misbehaving MPC, and MUST reject rather than
    // wrap into a ~2^128 change mint.
    let amount_in_max = s.s.amount_in_max_u64();
    if s.amount_in > amount_in_max {
        return Outcome::Reject(GuardId::ChangeUnderflow);
    }
    let change = amount_in_max - s.amount_in;
    let amount_out = s.s.amount_out_u64();
    accept_d(
        vec![
            Effect::MapRemove {
                field: v::SWAP_EVENT_MAP,
                key: Term::c(s.s.request_id()),
            },
            Effect::MapRemove {
                field: v::SWAP_REFUND_COMMITMENT,
                key: Term::c(s.s.request_id()),
            },
            Effect::MintShielded {
                domain_sep: Term::DomainSep {
                    erc20: s.s.token_out,
                },
                value: amount_out,
            },
            Effect::ClaimSpend(Term::CoinCm {
                nonce: Box::new(Term::c(s.mint_nonce)),
                color: Box::new(Term::TokenType {
                    sep: Box::new(Term::DomainSep {
                        erc20: s.s.token_out,
                    }),
                    addr: s.s.self_addr,
                }),
                value: amount_out,
                is_left: true,
                data: s.own_pk,
            }),
            Effect::MintShielded {
                domain_sep: Term::DomainSep {
                    erc20: s.s.token_in,
                },
                value: change,
            },
            Effect::ClaimSpend(Term::CoinCm {
                nonce: Box::new(Term::ChangeNonce {
                    mint_nonce: Box::new(Term::c(s.mint_nonce)),
                }),
                color: Box::new(Term::TokenType {
                    sep: Box::new(Term::DomainSep {
                        erc20: s.s.token_in,
                    }),
                    addr: s.s.self_addr,
                }),
                value: change,
                is_left: true,
                data: s.own_pk,
            }),
        ],
        vec![
            "request id",
            "attested amountIn spent",
            "swap mint nonce",
            "swap recipient",
        ],
    )
}

/// `refund(requestId, respondBidirectionalEvent, serializedOutput,
/// mintNonce)` (erc20-vault.compact:617-678) — routes on which pending
/// marker holds the id.
pub fn spec_refund(s: &RefundScenario) -> Outcome {
    if s.initialized < 1 {
        return Outcome::Reject(GuardId::NotInitialized);
    }
    if s.serialized_output != v::MPC_FAILURE_OUTPUT {
        return Outcome::Reject(GuardId::NotTheMpcFailureOutput);
    }
    let rid = s.request_id();
    let want = Term::RefundCommit {
        sk: s.claimant_sk(),
        request_id: Box::new(Term::c(rid)),
    }
    .concretize(s.art());
    match &s.route {
        RefundRoute::Withdrawal(w) => {
            if want != w.refund_commitment() {
                return Outcome::Reject(GuardId::NotTheWithdrawer);
            }
            let amount = w.amount_u64();
            accept_d(
                vec![
                    Effect::MapRemove {
                        field: v::SIGN_BIDIRECTIONAL_EVENT_MAP,
                        key: Term::c(rid),
                    },
                    Effect::MintShielded {
                        domain_sep: Term::DomainSep { erc20: w.erc20 },
                        value: amount,
                    },
                    Effect::ClaimSpend(Term::CoinCm {
                        nonce: Box::new(Term::c(s.mint_nonce)),
                        color: Box::new(Term::TokenType {
                            sep: Box::new(Term::DomainSep { erc20: w.erc20 }),
                            addr: w.self_addr,
                        }),
                        value: amount,
                        is_left: true,
                        data: s.own_pk,
                    }),
                    Effect::MapRemove {
                        field: v::REFUND_COMMITMENT,
                        key: Term::c(rid),
                    },
                ],
                vec!["request id", "refund mint nonce"],
            )
        }
        RefundRoute::Swap(sw) => {
            if want != sw.refund_commitment() {
                return Outcome::Reject(GuardId::NotTheSwapper);
            }
            let amount = sw.amount_in_max_u64();
            accept_d(
                vec![
                    Effect::MapRemove {
                        field: v::SWAP_EVENT_MAP,
                        key: Term::c(rid),
                    },
                    Effect::MapRemove {
                        field: v::SWAP_REFUND_COMMITMENT,
                        key: Term::c(rid),
                    },
                    Effect::MintShielded {
                        domain_sep: Term::DomainSep { erc20: sw.token_in },
                        value: amount,
                    },
                    Effect::ClaimSpend(Term::CoinCm {
                        nonce: Box::new(Term::c(s.mint_nonce)),
                        color: Box::new(Term::TokenType {
                            sep: Box::new(Term::DomainSep { erc20: sw.token_in }),
                            addr: sw.self_addr,
                        }),
                        value: amount,
                        is_left: true,
                        data: s.own_pk,
                    }),
                ],
                vec!["request id", "refund mint nonce"],
            )
        }
    }
}

// --- checking a spec against what the reference VM produced -------------------

fn cell_bytes(state: &StateValue, field: usize) -> Option<Vec<u8>> {
    let StateValue::Array(arr) = state else {
        return None;
    };
    let StateValue::Cell(av) = arr.get(field)? else {
        return None;
    };
    Some(av.value.0.first()?.0.clone())
}

fn map_get(state: &StateValue, field: usize, key: &[u8; 32]) -> Option<AlignedValue> {
    use std::ops::Deref;
    let StateValue::Array(arr) = state else {
        return None;
    };
    let StateValue::Map(m) = arr.get(field)? else {
        return None;
    };
    let entry = m.get(&bytesn_value(32, key))?;
    let StateValue::Cell(av) = entry.deref() else {
        return None;
    };
    Some(av.deref().clone())
}

fn pre_counter(pre: &PreState, field: u8) -> u64 {
    match field {
        v::SIGNET_REQUEST_NONCE => pre.request_nonce,
        v::INITIALIZED => pre.initialized,
        _ => panic!("field {field} is not a counter"),
    }
}

/// Assert that `effects` — the spec's declaration — is EXACTLY what the
/// reference VM produced: the same post-state changes, and the same ledger
/// `Effects` (equality, not containment, so an undeclared claim fails).
pub fn check_effects(
    art: Art,
    effects: &[Effect],
    pre: &PreState,
    ex: &Executed,
) -> Result<(), String> {
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
                let got = exec::counter(&ex.post, usize::from(*field))
                    .ok_or_else(|| format!("field {field} is not a counter cell after the run"))?;
                if got != want {
                    return Err(format!("counter {field}: want {want}, got {got}"));
                }
            }
            Effect::MapInsert { field, key, value } => {
                let k = key.concretize(art);
                let got = map_get(&ex.post, usize::from(*field), &k)
                    .ok_or_else(|| format!("map {field} lacks the inserted key"))?;
                let want = match value {
                    Val::Record(av) => av.clone(),
                    Val::Term(t) => bytesn_value(32, &t.concretize(art)),
                };
                if got != want {
                    return Err(format!("map {field}: inserted value differs"));
                }
            }
            Effect::MapRemove { field, key } => {
                if exec::map_member(&ex.post, usize::from(*field), &key.concretize(art)) {
                    return Err(format!("map {field}: key survived the removal"));
                }
            }
            Effect::CellWrite { field, value } => {
                let got = cell_bytes(&ex.post, usize::from(*field))
                    .ok_or_else(|| format!("field {field} is not a cell after the run"))?;
                let want = value.value.0.first().map(|a| a.0.clone()).unwrap_or_default();
                if got != want {
                    return Err(format!("cell {field}: want {want:?}, got {got:?}"));
                }
            }
            Effect::MintShielded { domain_sep, value } => {
                *want_mint.entry(domain_sep.concretize(art)).or_insert(0) += value;
            }
            Effect::ClaimSpend(t) => {
                want_spend.insert(t.concretize(art));
            }
            Effect::ClaimReceive(t) => {
                want_recv.insert(t.concretize(art));
            }
            Effect::ClaimNullifier(t) => {
                want_nul.insert(t.concretize(art));
            }
            Effect::ClaimContractCall { addr, ep, comm } => {
                want_calls.insert((call_seq, *addr, *ep, *comm));
                call_seq += 1;
            }
        }
    }

    let got_nul: BTreeSet<[u8; 32]> = ex
        .effects
        .claimed_nullifiers
        .iter()
        .map(|n| n.0 .0)
        .collect();
    let got_recv: BTreeSet<[u8; 32]> = ex
        .effects
        .claimed_shielded_receives
        .iter()
        .map(|c| c.0 .0)
        .collect();
    let got_spend: BTreeSet<[u8; 32]> = ex
        .effects
        .claimed_shielded_spends
        .iter()
        .map(|c| c.0 .0)
        .collect();
    let got_mint: BTreeMap<[u8; 32], u64> = ex
        .effects
        .shielded_mints
        .iter()
        .map(|kv| (kv.0 .0, *kv.1))
        .collect();
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

/// Marker used by [`CoinCommitment`]/[`Nullifier`] round-tripping in the
/// adversarial injectivity sweep: both artifacts' concretizations are
/// SHA-256/keccak at this rung, so injectivity of the term → bytes map is
/// hash-injectivity on the generated corpus.
pub fn coin_types_are_hash_outputs() -> (CoinCommitment, Nullifier) {
    (
        CoinCommitment(HashOutput([0u8; 32])),
        Nullifier(HashOutput([0u8; 32])),
    )
}
