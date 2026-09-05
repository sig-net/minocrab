//! erc20-vault: call-compatibility with the corpus artifacts per
//! notes/ledger-abi.org §6 — the benchmark target running on MinoCrab,
//! plus acceptance agreement on guard failures and tampering.
//!
//! Seventeen circuits since M28 (signet-midnight-examples `0d9c1660`):
//! for each, PI-equality on the reference model's preimage against
//! compactc's own artifact, the guard failures both artifacts must reject,
//! and the tamper sweep (every transcript and witness element perturbed;
//! zero acceptance disagreements). The per-circuit scenario builders live in
//! `tests/vault/model.rs` — the reference model the property harness and
//! the adversarial sweeps share.

use minocrab::Fr;
use minocrab_sim::v3::{assert_call_compatible, simulate};
use minocrab_zkir::v3::IrSource;

mod support;
mod vault;

use vault::artifact::Circuit;
use vault::model::*;
use vault::tamper;

/// Both artifacts must REJECT this preimage.
fn both_reject(circuit: Circuit, pi: &midnight_transient_crypto::proofs::ProofPreimage, why: &str) {
    assert!(simulate(&circuit.ir(), pi).is_err(), "ours accepts: {why}");
    assert!(simulate(circuit.corpus(), pi).is_err(), "corpus accepts: {why}");
}

/// PI-equality on the reference preimage, dumped for the bench.
fn matches(circuit: Circuit, pi: &midnight_transient_crypto::proofs::ProofPreimage) {
    support::dump_preimage(circuit.zkir_name(), pi);
    assert_call_compatible(&circuit.ir(), circuit.corpus(), pi);
}

fn ours(circuit: Circuit) -> IrSource {
    circuit.ir()
}

// ==== initialise ===========================================================================

#[test]
fn initialise_matches_corpus() {
    matches(Circuit::Initialise, &InitialiseScenario::new().preimage());
}

#[test]
fn initialise_rejects_guard_failures() {
    // Already initialised: the counter reads back 1.
    let mut s = InitialiseScenario::new();
    s.env.initialised = 1;
    both_reject(Circuit::Initialise, &s.preimage(), "already initialised");

    // Wrong deployer secret.
    let mut s = InitialiseScenario::new();
    s.sk[0] ^= 1;
    both_reject(Circuit::Initialise, &s.preimage(), "wrong secret");

    // Zero chain id.
    let mut s = InitialiseScenario::new();
    s.chain_id = 0;
    both_reject(Circuit::Initialise, &s.preimage(), "zero chain id");

    // Zero router / underlying / wrapper.
    for i in 0..3 {
        let mut s = InitialiseScenario::new();
        match i {
            0 => s.swap_router = [0u8; 20],
            1 => s.stata_underlying = [0u8; 20],
            _ => s.stata_token = [0u8; 20],
        }
        both_reject(Circuit::Initialise, &s.preimage(), "zero address");
    }
}

#[test]
fn initialise_rejects_tampering() {
    let c = Circuit::Initialise;
    tamper::assert_full_sweep(&ours(c), c.corpus(), &InitialiseScenario::new().preimage());
}

// ==== the allowances =======================================================================

#[test]
fn approve_stata_matches_corpus() {
    matches(Circuit::ApproveStata, &ApproveStataScenario::new().preimage());
}

#[test]
fn approve_stata_rejects_guard_failures() {
    let mut s = ApproveStataScenario::new();
    s.env.initialised = 0;
    both_reject(Circuit::ApproveStata, &s.preimage(), "not initialised");

    let mut s = ApproveStataScenario::new();
    s.key_version = 0;
    both_reject(Circuit::ApproveStata, &s.preimage(), "keyVersion 0");

    let mut s = ApproveStataScenario::new();
    s.request_exists = true;
    both_reject(Circuit::ApproveStata, &s.preimage(), "request exists");
}

#[test]
fn approve_stata_rejects_tampering() {
    let c = Circuit::ApproveStata;
    tamper::assert_full_sweep(&ours(c), c.corpus(), &ApproveStataScenario::new().preimage());
}

#[test]
fn approve_router_matches_corpus() {
    matches(Circuit::ApproveRouter, &ApproveRouterScenario::new().preimage());
}

#[test]
fn approve_router_rejects_guard_failures() {
    let mut s = ApproveRouterScenario::new();
    s.env.initialised = 0;
    both_reject(Circuit::ApproveRouter, &s.preimage(), "not initialised");

    let mut s = ApproveRouterScenario::new();
    s.erc20 = [0u8; 20];
    both_reject(Circuit::ApproveRouter, &s.preimage(), "zero erc20");

    let mut s = ApproveRouterScenario::new();
    s.key_version = 0;
    both_reject(Circuit::ApproveRouter, &s.preimage(), "keyVersion 0");

    let mut s = ApproveRouterScenario::new();
    s.request_exists = true;
    both_reject(Circuit::ApproveRouter, &s.preimage(), "request exists");
}

#[test]
fn approve_router_rejects_tampering() {
    let c = Circuit::ApproveRouter;
    tamper::assert_full_sweep(&ours(c), c.corpus(), &ApproveRouterScenario::new().preimage());
}

// ==== deposit ==============================================================================

#[test]
fn start_deposit_matches_corpus() {
    matches(Circuit::StartDeposit, &StartDepositScenario::new().preimage());
}

#[test]
fn start_deposit_rejects_guard_failures() {
    let c = Circuit::StartDeposit;
    let mut s = StartDepositScenario::new();
    s.env.initialised = 0;
    both_reject(c, &s.preimage(), "not initialised");

    let mut s = StartDepositScenario::new();
    s.erc20 = [0u8; 20];
    both_reject(c, &s.preimage(), "zero erc20");

    let mut s = StartDepositScenario::new();
    s.amount = 0;
    both_reject(c, &s.preimage(), "zero amount");

    let mut s = StartDepositScenario::new();
    s.amount = u128::from(u64::MAX) + 1;
    both_reject(c, &s.preimage(), "amount above u64");

    let mut s = StartDepositScenario::new();
    s.gas_limit = 0;
    both_reject(c, &s.preimage(), "zero gas limit");

    let mut s = StartDepositScenario::new();
    s.key_version = 0;
    both_reject(c, &s.preimage(), "keyVersion 0");

    let mut s = StartDepositScenario::new();
    s.request_exists = true;
    both_reject(c, &s.preimage(), "request exists");
}

#[test]
fn start_deposit_rejects_tampering() {
    let c = Circuit::StartDeposit;
    tamper::assert_full_sweep(&ours(c), c.corpus(), &StartDepositScenario::new().preimage());
}

#[test]
fn complete_deposit_matches_corpus() {
    matches(Circuit::CompleteDeposit, &CompleteDepositScenario::new().preimage());
}

/// recipient = some(right(vault)) — the auto-receive branch FIRES: the
/// guarded kernel.self read and the receive claim join the transcript.
#[test]
fn complete_deposit_matches_corpus_recipient_self() {
    let mut s = CompleteDepositScenario::new();
    s.recipient = ClaimRecipient::Contract(s.env().self_addr);
    assert!(s.auto_receive());
    matches(Circuit::CompleteDeposit, &s.preimage());
}

/// recipient = some(right(other-contract)) — branch off, but the guarded
/// kernel.self read still fires (its guard is only !is_left).
#[test]
fn complete_deposit_matches_corpus_recipient_other_contract() {
    let mut s = CompleteDepositScenario::new();
    s.recipient = ClaimRecipient::Contract(tagged32(b"other-ct", 0));
    assert!(!s.auto_receive());
    matches(Circuit::CompleteDeposit, &s.preimage());
}

/// recipient = none — mint to left(ownPublicKey()): the guarded witnesses
/// are consumed, the branch is off.
#[test]
fn complete_deposit_matches_corpus_recipient_none() {
    let mut s = CompleteDepositScenario::new();
    s.recipient = ClaimRecipient::None(tagged32(b"own-pk", 0x43));
    matches(Circuit::CompleteDeposit, &s.preimage());
}

#[test]
fn complete_deposit_rejects_guard_failures() {
    let c = Circuit::CompleteDeposit;
    // Failed EVM transfer: serializedOutput 0x00.
    let mut s = CompleteDepositScenario::new();
    s.serialized_output = 0;
    both_reject(c, &s.preimage(), "transfer failed");

    // Bad attestation signature (s + 1).
    let s = CompleteDepositScenario::new();
    let mut pi = s.preimage();
    pi.inputs[7] = pi.inputs[7] + Fr::from(1u64);
    both_reject(c, &pi, "bad signature");

    // Request not found (member reads back 0).
    let mut s = CompleteDepositScenario::new();
    s.settle.pending = false;
    both_reject(c, &s.preimage(), "deposit not found");

    // Not the depositor: wrong secret key.
    let mut s = CompleteDepositScenario::new();
    s.settle.claimant_sk = Some(tagged32(b"someone-else", 0x99));
    both_reject(c, &s.preimage(), "not the depositor");

    // Not initialised.
    let mut s = CompleteDepositScenario::new();
    s.d.env.initialised = 0;
    both_reject(c, &s.preimage(), "not initialised");
}

#[test]
fn complete_deposit_rejects_tampering() {
    let c = Circuit::CompleteDeposit;
    tamper::assert_full_sweep(&ours(c), c.corpus(), &CompleteDepositScenario::new().preimage());
}

// ==== withdraw =============================================================================

#[test]
fn start_withdraw_matches_corpus() {
    matches(Circuit::StartWithdraw, &StartWithdrawScenario::new().preimage());
}

#[test]
fn start_withdraw_rejects_guard_failures() {
    let c = Circuit::StartWithdraw;
    let mut s = StartWithdrawScenario::new();
    s.env.initialised = 0;
    both_reject(c, &s.preimage(), "not initialised");

    let mut s = StartWithdrawScenario::new();
    s.erc20 = [0u8; 20];
    both_reject(c, &s.preimage(), "zero erc20");

    let mut s = StartWithdrawScenario::new();
    s.amount = 0;
    both_reject(c, &s.preimage(), "zero amount");

    let mut s = StartWithdrawScenario::new();
    s.amount = u128::from(u64::MAX) + 1;
    both_reject(c, &s.preimage(), "amount above u64");

    // Wrong coin colour: not the vault token for this ERC20.
    let mut s = StartWithdrawScenario::new();
    s.coin_color = Some(tagged32(b"other-color", 0x01));
    both_reject(c, &s.preimage(), "wrong colour");

    // Coin value != amount.
    let mut s = StartWithdrawScenario::new();
    s.coin_value = Some(s.amount + 1);
    both_reject(c, &s.preimage(), "coin value mismatch");

    let mut s = StartWithdrawScenario::new();
    s.key_version = 0;
    both_reject(c, &s.preimage(), "keyVersion 0");

    let mut s = StartWithdrawScenario::new();
    s.request_exists = true;
    both_reject(c, &s.preimage(), "request exists");
}

#[test]
fn start_withdraw_rejects_tampering() {
    let c = Circuit::StartWithdraw;
    tamper::assert_full_sweep(&ours(c), c.corpus(), &StartWithdrawScenario::new().preimage());
}

#[test]
fn complete_withdraw_success_matches_corpus() {
    matches(Circuit::CompleteWithdraw, &CompleteWithdrawScenario::new(1).preimage());
}

#[test]
fn complete_withdraw_refund_matches_corpus() {
    matches(Circuit::CompleteWithdraw, &CompleteWithdrawScenario::new(0).preimage());
}

#[test]
fn complete_withdraw_rejects_guard_failures() {
    let c = Circuit::CompleteWithdraw;
    // Bad signature.
    let s = CompleteWithdrawScenario::new(1);
    let mut pi = s.preimage();
    pi.inputs[7] = pi.inputs[7] + Fr::from(1u64);
    both_reject(c, &pi, "bad signature");

    // Withdrawal not found.
    let mut s = CompleteWithdrawScenario::new(1);
    s.settle.pending = false;
    both_reject(c, &s.preimage(), "withdrawal not found");

    // On the refund branch, not the withdrawer.
    let mut s = CompleteWithdrawScenario::new(0);
    s.settle.claimant_sk = Some(tagged32(b"someone-else", 0x99));
    both_reject(c, &s.preimage(), "not the withdrawer");

    // On the SUCCESS branch anyone may settle: a stranger's secret is fine.
    let mut s = CompleteWithdrawScenario::new(1);
    s.settle.claimant_sk = Some(tagged32(b"someone-else", 0x99));
    matches(c, &s.preimage());

    let mut s = CompleteWithdrawScenario::new(1);
    s.w.env.initialised = 0;
    both_reject(c, &s.preimage(), "not initialised");
}

/// On the SUCCESS branch the caller's secret is witnessed (the commitment
/// is hoisted out of the `if`) but asserted by nothing — anyone may settle
/// a succeeded withdrawal — so a perturbed secret is accepted by BOTH
/// artifacts and only the transcript sweep applies there. The refund
/// branch reads every witness, and takes the full sweep.
#[test]
fn complete_withdraw_rejects_tampering() {
    let c = Circuit::CompleteWithdraw;
    tamper::assert_transcript_sweep(&ours(c), c.corpus(), &CompleteWithdrawScenario::new(1).preimage());
    tamper::assert_full_sweep(&ours(c), c.corpus(), &CompleteWithdrawScenario::new(0).preimage());
}

#[test]
fn refund_withdraw_matches_corpus() {
    matches(Circuit::RefundWithdraw, &RefundWithdrawScenario::new().preimage());
}

#[test]
fn refund_withdraw_rejects_guard_failures() {
    let c = Circuit::RefundWithdraw;
    // A success-shaped output is not the MPC failure output.
    let mut s = RefundWithdrawScenario::new();
    s.serialized_output = [0, 0, 0, 0, 1];
    both_reject(c, &s.preimage(), "not the failure output");

    let mut s = RefundWithdrawScenario::new();
    s.settle.pending = false;
    both_reject(c, &s.preimage(), "withdrawal not found");

    let mut s = RefundWithdrawScenario::new();
    s.settle.claimant_sk = Some(tagged32(b"someone-else", 0x99));
    both_reject(c, &s.preimage(), "not the withdrawer");

    let s = RefundWithdrawScenario::new();
    let mut pi = s.preimage();
    pi.inputs[7] = pi.inputs[7] + Fr::from(1u64);
    both_reject(c, &pi, "bad signature");
}

#[test]
fn refund_withdraw_rejects_tampering() {
    let c = Circuit::RefundWithdraw;
    tamper::assert_full_sweep(&ours(c), c.corpus(), &RefundWithdrawScenario::new().preimage());
}

// ==== swap =================================================================================

#[test]
fn start_swap_matches_corpus() {
    matches(Circuit::StartSwap, &StartSwapScenario::new().preimage());
}

#[test]
fn start_swap_rejects_guard_failures() {
    let c = Circuit::StartSwap;
    let mut s = StartSwapScenario::new();
    s.env.initialised = 0;
    both_reject(c, &s.preimage(), "not initialised");

    let mut s = StartSwapScenario::new();
    s.token_in = [0u8; 20];
    both_reject(c, &s.preimage(), "zero tokenIn");

    let mut s = StartSwapScenario::new();
    s.token_out = [0u8; 20];
    both_reject(c, &s.preimage(), "zero tokenOut");

    let mut s = StartSwapScenario::new();
    s.amount_out = 0;
    both_reject(c, &s.preimage(), "zero amountOut");

    let mut s = StartSwapScenario::new();
    s.amount_in_max = 0;
    both_reject(c, &s.preimage(), "zero amountInMaximum");

    let mut s = StartSwapScenario::new();
    s.amount_out = u128::from(u64::MAX) + 1;
    both_reject(c, &s.preimage(), "amountOut above u64");

    let mut s = StartSwapScenario::new();
    s.amount_in_max = u128::from(u64::MAX) + 1;
    both_reject(c, &s.preimage(), "amountInMaximum above u64");

    let mut s = StartSwapScenario::new();
    s.coin_color = Some(tagged32(b"other-color", 0x01));
    both_reject(c, &s.preimage(), "wrong colour");

    let mut s = StartSwapScenario::new();
    s.coin_value = Some(s.amount_in_max - 1);
    both_reject(c, &s.preimage(), "coin value mismatch");

    let mut s = StartSwapScenario::new();
    s.request_exists = true;
    both_reject(c, &s.preimage(), "request exists");
}

#[test]
fn start_swap_rejects_tampering() {
    let c = Circuit::StartSwap;
    tamper::assert_full_sweep(&ours(c), c.corpus(), &StartSwapScenario::new().preimage());
}

#[test]
fn complete_swap_matches_corpus() {
    matches(Circuit::CompleteSwap, &CompleteSwapScenario::new().preimage());
}

/// An exact spend mints a zero-value change coin.
#[test]
fn complete_swap_exact_spend_matches_corpus() {
    let mut s = CompleteSwapScenario::new();
    s.amount_in = s.s.amount_in_max_u64();
    assert_eq!(s.change(), Some(0));
    matches(Circuit::CompleteSwap, &s.preimage());
}

#[test]
fn complete_swap_rejects_guard_failures() {
    let c = Circuit::CompleteSwap;
    // The most dangerous arithmetic in the contract: amountIn above the cap.
    let mut s = CompleteSwapScenario::new();
    s.amount_in = s.s.amount_in_max_u64() + 1;
    both_reject(c, &s.preimage(), "change underflow");

    // changeNonce == mintNonce.
    let mut s = CompleteSwapScenario::new();
    s.change_nonce = s.settle.mint_nonce;
    both_reject(c, &s.preimage(), "change nonce equals mint nonce");

    let mut s = CompleteSwapScenario::new();
    s.settle.pending = false;
    both_reject(c, &s.preimage(), "swap not found");

    let mut s = CompleteSwapScenario::new();
    s.settle.claimant_sk = Some(tagged32(b"someone-else", 0x99));
    both_reject(c, &s.preimage(), "not the swapper");

    let s = CompleteSwapScenario::new();
    let mut pi = s.preimage();
    pi.inputs[7] = pi.inputs[7] + Fr::from(1u64);
    both_reject(c, &pi, "bad signature");
}

#[test]
fn complete_swap_rejects_tampering() {
    let c = Circuit::CompleteSwap;
    tamper::assert_full_sweep(&ours(c), c.corpus(), &CompleteSwapScenario::new().preimage());
}

#[test]
fn refund_swap_matches_corpus() {
    matches(Circuit::RefundSwap, &RefundSwapScenario::new().preimage());
}

#[test]
fn refund_swap_rejects_guard_failures() {
    let c = Circuit::RefundSwap;
    let mut s = RefundSwapScenario::new();
    s.serialized_output = [0, 0, 0, 0, 1];
    both_reject(c, &s.preimage(), "not the failure output");

    let mut s = RefundSwapScenario::new();
    s.settle.pending = false;
    both_reject(c, &s.preimage(), "swap not found");

    let mut s = RefundSwapScenario::new();
    s.settle.claimant_sk = Some(tagged32(b"someone-else", 0x99));
    both_reject(c, &s.preimage(), "not the swapper");
}

#[test]
fn refund_swap_rejects_tampering() {
    let c = Circuit::RefundSwap;
    tamper::assert_full_sweep(&ours(c), c.corpus(), &RefundSwapScenario::new().preimage());
}

// ==== supply ===============================================================================

#[test]
fn start_supply_matches_corpus() {
    matches(Circuit::StartSupply, &StartSupplyScenario::new().preimage());
}

#[test]
fn start_supply_rejects_guard_failures() {
    let c = Circuit::StartSupply;
    let mut s = StartSupplyScenario::new();
    s.env.initialised = 0;
    both_reject(c, &s.preimage(), "not initialised");

    let mut s = StartSupplyScenario::new();
    s.amount = 0;
    both_reject(c, &s.preimage(), "zero amount");

    let mut s = StartSupplyScenario::new();
    s.amount = u128::from(u64::MAX) + 1;
    both_reject(c, &s.preimage(), "amount above u64");

    let mut s = StartSupplyScenario::new();
    s.coin_color = Some(tagged32(b"other-color", 0x01));
    both_reject(c, &s.preimage(), "wrong colour");

    let mut s = StartSupplyScenario::new();
    s.coin_value = Some(s.amount + 1);
    both_reject(c, &s.preimage(), "coin value mismatch");

    let mut s = StartSupplyScenario::new();
    s.request_exists = true;
    both_reject(c, &s.preimage(), "request exists");
}

#[test]
fn start_supply_rejects_tampering() {
    let c = Circuit::StartSupply;
    tamper::assert_full_sweep(&ours(c), c.corpus(), &StartSupplyScenario::new().preimage());
}

#[test]
fn complete_supply_matches_corpus() {
    matches(Circuit::CompleteSupply, &CompleteSupplyScenario::new().preimage());
}

#[test]
fn complete_supply_rejects_guard_failures() {
    let c = Circuit::CompleteSupply;
    let mut s = CompleteSupplyScenario::new();
    s.settle.pending = false;
    both_reject(c, &s.preimage(), "supply not found");

    let mut s = CompleteSupplyScenario::new();
    s.settle.claimant_sk = Some(tagged32(b"someone-else", 0x99));
    both_reject(c, &s.preimage(), "not the supplier");

    let s = CompleteSupplyScenario::new();
    let mut pi = s.preimage();
    pi.inputs[7] = pi.inputs[7] + Fr::from(1u64);
    both_reject(c, &pi, "bad signature");
}

#[test]
fn complete_supply_rejects_tampering() {
    let c = Circuit::CompleteSupply;
    tamper::assert_full_sweep(&ours(c), c.corpus(), &CompleteSupplyScenario::new().preimage());
}

#[test]
fn refund_supply_matches_corpus() {
    matches(Circuit::RefundSupply, &RefundSupplyScenario::new().preimage());
}

#[test]
fn refund_supply_rejects_guard_failures() {
    let c = Circuit::RefundSupply;
    let mut s = RefundSupplyScenario::new();
    s.serialized_output = [0, 0, 0, 0, 1];
    both_reject(c, &s.preimage(), "not the failure output");

    let mut s = RefundSupplyScenario::new();
    s.settle.pending = false;
    both_reject(c, &s.preimage(), "supply not found");

    let mut s = RefundSupplyScenario::new();
    s.settle.claimant_sk = Some(tagged32(b"someone-else", 0x99));
    both_reject(c, &s.preimage(), "not the supplier");
}

#[test]
fn refund_supply_rejects_tampering() {
    let c = Circuit::RefundSupply;
    tamper::assert_full_sweep(&ours(c), c.corpus(), &RefundSupplyScenario::new().preimage());
}

// ==== redeem ===============================================================================

#[test]
fn start_redeem_matches_corpus() {
    matches(Circuit::StartRedeem, &StartRedeemScenario::new().preimage());
}

#[test]
fn start_redeem_rejects_guard_failures() {
    let c = Circuit::StartRedeem;
    let mut s = StartRedeemScenario::new();
    s.env.initialised = 0;
    both_reject(c, &s.preimage(), "not initialised");

    let mut s = StartRedeemScenario::new();
    s.shares = 0;
    both_reject(c, &s.preimage(), "zero shares");

    let mut s = StartRedeemScenario::new();
    s.shares = u128::from(u64::MAX) + 1;
    both_reject(c, &s.preimage(), "shares above u64");

    let mut s = StartRedeemScenario::new();
    s.coin_color = Some(tagged32(b"other-color", 0x01));
    both_reject(c, &s.preimage(), "wrong colour");

    let mut s = StartRedeemScenario::new();
    s.coin_value = Some(s.shares + 1);
    both_reject(c, &s.preimage(), "coin value mismatch");

    let mut s = StartRedeemScenario::new();
    s.request_exists = true;
    both_reject(c, &s.preimage(), "request exists");
}

#[test]
fn start_redeem_rejects_tampering() {
    let c = Circuit::StartRedeem;
    tamper::assert_full_sweep(&ours(c), c.corpus(), &StartRedeemScenario::new().preimage());
}

#[test]
fn complete_redeem_matches_corpus() {
    matches(Circuit::CompleteRedeem, &CompleteRedeemScenario::new().preimage());
}

#[test]
fn complete_redeem_rejects_guard_failures() {
    let c = Circuit::CompleteRedeem;
    let mut s = CompleteRedeemScenario::new();
    s.settle.pending = false;
    both_reject(c, &s.preimage(), "redeem not found");

    let mut s = CompleteRedeemScenario::new();
    s.settle.claimant_sk = Some(tagged32(b"someone-else", 0x99));
    both_reject(c, &s.preimage(), "not the redeemer");

    let s = CompleteRedeemScenario::new();
    let mut pi = s.preimage();
    pi.inputs[7] = pi.inputs[7] + Fr::from(1u64);
    both_reject(c, &pi, "bad signature");
}

#[test]
fn complete_redeem_rejects_tampering() {
    let c = Circuit::CompleteRedeem;
    tamper::assert_full_sweep(&ours(c), c.corpus(), &CompleteRedeemScenario::new().preimage());
}

#[test]
fn refund_redeem_matches_corpus() {
    matches(Circuit::RefundRedeem, &RefundRedeemScenario::new().preimage());
}

#[test]
fn refund_redeem_rejects_guard_failures() {
    let c = Circuit::RefundRedeem;
    let mut s = RefundRedeemScenario::new();
    s.serialized_output = [0, 0, 0, 0, 1];
    both_reject(c, &s.preimage(), "not the failure output");

    let mut s = RefundRedeemScenario::new();
    s.settle.pending = false;
    both_reject(c, &s.preimage(), "redeem not found");

    let mut s = RefundRedeemScenario::new();
    s.settle.claimant_sk = Some(tagged32(b"someone-else", 0x99));
    both_reject(c, &s.preimage(), "not the redeemer");
}

#[test]
fn refund_redeem_rejects_tampering() {
    let c = Circuit::RefundRedeem;
    tamper::assert_full_sweep(&ours(c), c.corpus(), &RefundRedeemScenario::new().preimage());
}

/// Every one of the seventeen corpus artifacts has a twin here, and the
/// input schemas agree — the cheap check that runs before any preimage.
#[test]
fn every_circuit_has_a_corpus_twin_with_the_same_schema() {
    for c in Circuit::ALL {
        let types = |ir: &IrSource| {
            serde_json::to_value(&ir.inputs)
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(|ti| ti["type"].clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(types(&c.ir()), types(c.corpus()), "{}: input schema", c.zkir_name());
    }
}
