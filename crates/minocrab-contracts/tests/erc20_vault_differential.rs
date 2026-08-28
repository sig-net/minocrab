//! erc20-vault: call-compatibility with the corpus artifacts per
//! notes/ledger-abi.org §6 — the benchmark target running on MinoCrab,
//! plus acceptance agreement on guard failures and tampering.
//!
//! The per-circuit scenario builders this file grew live in `tests/vault/`
//! since M10 step 1: they are the reference model the property harness
//! (`erc20_vault_spec.rs`) and the adversarial sweeps
//! (`erc20_vault_adversarial.rs`) share. Nothing about the assertions here
//! changed in that move.

use midnight_onchain_vm::ops::Op;
use midnight_transient_crypto::repr::FieldRepr;
use minocrab::Fr;
use minocrab_contracts::erc20_vault;
use minocrab_sim::v3::{assert_call_compatible, simulate};

mod support;
mod vault;

use vault::model::*;
use vault::tamper;
use vault::prims::*;

#[test]
fn claim_matches_corpus() {
    let theirs = corpus_zkir_named("claim");
    let ours = erc20_vault::claim().ir;
    let s = ClaimScenario::new();
    let pi = s.preimage();
    support::dump_preimage("claim", &pi);
    assert_call_compatible(&ours, &theirs, &pi);
}

/// recipient = some(right(vault)) — the auto-receive branch FIRES: the
/// guarded kernel.self read and the receive claim join the transcript.
#[test]
fn claim_matches_corpus_recipient_self() {
    let theirs = corpus_zkir_named("claim");
    let ours = erc20_vault::claim().ir;
    let mut s = ClaimScenario::new();
    s.recipient = ClaimRecipient::Contract(s.d.self_addr);
    assert!(s.auto_receive());
    assert_call_compatible(&ours, &theirs, &s.preimage());
}

/// recipient = some(right(other-contract)) — branch off, but the guarded
/// kernel.self read still fires (its guard is only !is_left).
#[test]
fn claim_matches_corpus_recipient_other_contract() {
    let theirs = corpus_zkir_named("claim");
    let ours = erc20_vault::claim().ir;
    let mut s = ClaimScenario::new();
    let mut other = [0u8; 32];
    other[..8].copy_from_slice(b"other-ct");
    s.recipient = ClaimRecipient::Contract(other);
    assert!(!s.auto_receive());
    assert_call_compatible(&ours, &theirs, &s.preimage());
}

/// recipient = none — mint to left(ownPublicKey()): the guarded witnesses
/// are consumed, the branch is off.
#[test]
fn claim_matches_corpus_recipient_none() {
    let theirs = corpus_zkir_named("claim");
    let ours = erc20_vault::claim().ir;
    let mut s = ClaimScenario::new();
    let mut own_pk = [0u8; 32];
    own_pk[..6].copy_from_slice(b"own-pk");
    own_pk[31] = 0x43;
    s.recipient = ClaimRecipient::None(own_pk);
    assert_call_compatible(&ours, &theirs, &s.preimage());
}

/// Guard failures must be rejected by BOTH artifacts.
#[test]
fn claim_rejects_guard_failures() {
    let theirs = corpus_zkir_named("claim");
    let ours = erc20_vault::claim().ir;

    // Failed EVM transfer: serializedOutput 0x00.
    let s = ClaimScenario::new();
    let mut pi = s.preimage();
    pi.inputs[9] = Fr::from(0u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: transfer failed");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: transfer failed");

    // Bad attestation signature (s + 1).
    let s = ClaimScenario::new();
    let mut pi = s.preimage();
    pi.inputs[7] = pi.inputs[7] + Fr::from(1u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: bad signature");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: bad signature");

    // Request not found (member reads back 0).
    let s = ClaimScenario::new();
    let pi = s.preimage_with_member(0);
    assert!(simulate(&ours, &pi).is_err(), "ours: request not found");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: request not found");

    // Not the depositor: wrong secret key.
    let s = ClaimScenario::new();
    let mut pi = s.preimage();
    pi.private_transcript[0] = pi.private_transcript[0] + Fr::from(1u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: not the depositor");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: not the depositor");
}

/// Tampering with any transcript element must be rejected by both
/// artifacts, with zero acceptance disagreements.
#[test]
fn claim_rejects_tampering() {
    let theirs = corpus_zkir_named("claim");
    let ours = erc20_vault::claim().ir;
    let s = ClaimScenario::new();

    tamper::assert_transcript_sweep(&ours, &theirs, &s.preimage());
}
#[test]
fn withdraw_matches_corpus() {
    let theirs = corpus_zkir_named("withdraw");
    let ours = erc20_vault::withdraw().ir;
    let s = WithdrawScenario::new();
    let pi = s.preimage();
    support::dump_preimage("withdraw", &pi);
    assert_call_compatible(&ours, &theirs, &pi);
}

#[test]
fn withdraw_rejects_guard_failures() {
    let theirs = corpus_zkir_named("withdraw");
    let ours = erc20_vault::withdraw().ir;

    // Wrong coin color: not the vault token for this ERC20.
    let s = WithdrawScenario::new();
    let mut pi = s.preimage();
    pi.inputs[7] = pi.inputs[7] + Fr::from(1u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: wrong color");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: wrong color");

    // Coin value != amount.
    let s = WithdrawScenario::new();
    let mut pi = s.preimage();
    pi.inputs[9] = pi.inputs[9] + Fr::from(1u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: value mismatch");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: value mismatch");

    // Zero amount.
    let mut s = WithdrawScenario::new();
    s.amount = 0;
    let pi = s.preimage();
    assert!(simulate(&ours, &pi).is_err(), "ours: zero amount");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: zero amount");
}

/// Tampering with any transcript element or witness must be rejected by
/// both artifacts, with zero acceptance disagreements.
#[test]
fn withdraw_rejects_tampering() {
    let theirs = corpus_zkir_named("withdraw");
    let ours = erc20_vault::withdraw().ir;
    let s = WithdrawScenario::new();

    tamper::assert_full_sweep(&ours, &theirs, &s.preimage());
}
/// Attested success: no refund, cleanup only.
#[test]
fn complete_withdraw_success_matches_corpus() {
    let theirs = corpus_zkir_named("completeWithdraw");
    let ours = erc20_vault::complete_withdraw().ir;
    let s = CompleteWithdrawScenario::new(1);
    let pi = s.preimage();
    support::dump_preimage("completeWithdraw", &pi);
    assert_call_compatible(&ours, &theirs, &pi);
}

/// Attested false return: the guarded refund branch fires.
#[test]
fn complete_withdraw_refund_matches_corpus() {
    let theirs = corpus_zkir_named("completeWithdraw");
    let ours = erc20_vault::complete_withdraw().ir;
    let s = CompleteWithdrawScenario::new(0);
    assert_call_compatible(&ours, &theirs, &s.preimage());
}

#[test]
fn complete_withdraw_rejects_guard_failures() {
    let theirs = corpus_zkir_named("completeWithdraw");
    let ours = erc20_vault::complete_withdraw().ir;

    // Bad attestation signature.
    let s = CompleteWithdrawScenario::new(1);
    let mut pi = s.preimage();
    pi.inputs[7] = pi.inputs[7] + Fr::from(1u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: bad signature");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: bad signature");

    // Not the withdrawer: wrong secret on the refund path.
    let s = CompleteWithdrawScenario::new(0);
    let mut pi = s.preimage();
    pi.private_transcript[0] = pi.private_transcript[0] + Fr::from(1u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: not the withdrawer");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: not the withdrawer");
}

/// Tamper sweep over the refund-path transcript.
#[test]
fn complete_withdraw_rejects_tampering() {
    let theirs = corpus_zkir_named("completeWithdraw");
    let ours = erc20_vault::complete_withdraw().ir;
    let s = CompleteWithdrawScenario::new(0);

    tamper::assert_transcript_sweep(&ours, &theirs, &s.preimage());
}
#[test]
fn swap_matches_corpus() {
    let theirs = corpus_zkir_named("swap");
    let ours = erc20_vault::swap().ir;
    let s = SwapScenario::new();
    let pi = s.preimage();
    support::dump_preimage("swap", &pi);
    assert_call_compatible(&ours, &theirs, &pi);
}

#[test]
fn swap_rejects_guard_failures() {
    let theirs = corpus_zkir_named("swap");
    let ours = erc20_vault::swap().ir;

    // Wrong coin color: not the tokenIn vault token.
    let s = SwapScenario::new();
    let mut pi = s.preimage();
    pi.inputs[9] = pi.inputs[9] + Fr::from(1u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: wrong color");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: wrong color");

    // Coin value != amountInMaximum.
    let s = SwapScenario::new();
    let mut pi = s.preimage();
    pi.inputs[11] = pi.inputs[11] + Fr::from(1u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: value mismatch");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: value mismatch");

    // Zero amountOut.
    let mut s = SwapScenario::new();
    s.amount_out = 0;
    let pi = s.preimage();
    assert!(simulate(&ours, &pi).is_err(), "ours: zero amountOut");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: zero amountOut");
}
#[test]
fn complete_swap_matches_corpus() {
    let theirs = corpus_zkir_named("completeSwap");
    let ours = erc20_vault::complete_swap().ir;
    let s = CompleteSwapScenario::new();
    let pi = s.preimage();
    support::dump_preimage("completeSwap", &pi);
    assert_call_compatible(&ours, &theirs, &pi);
}

/// Exact spend: change is 0 (a harmless 0-value coin).
#[test]
fn complete_swap_exact_spend_matches_corpus() {
    let theirs = corpus_zkir_named("completeSwap");
    let ours = erc20_vault::complete_swap().ir;
    let mut s = CompleteSwapScenario::new();
    s.amount_in = s.s.amount_in_max_u64();
    assert_call_compatible(&ours, &theirs, &s.preimage());
}

#[test]
fn complete_swap_rejects_guard_failures() {
    let theirs = corpus_zkir_named("completeSwap");
    let ours = erc20_vault::complete_swap().ir;

    // Bad attestation signature.
    let s = CompleteSwapScenario::new();
    let mut pi = s.preimage();
    pi.inputs[7] = pi.inputs[7] + Fr::from(1u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: bad signature");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: bad signature");

    // Not the swapper.
    let s = CompleteSwapScenario::new();
    let mut pi = s.preimage();
    pi.private_transcript[0] = pi.private_transcript[0] + Fr::from(1u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: not the swapper");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: not the swapper");
}

/// Tamper sweep.
#[test]
fn complete_swap_rejects_tampering() {
    let theirs = corpus_zkir_named("completeSwap");
    let ours = erc20_vault::complete_swap().ir;
    let s = CompleteSwapScenario::new();

    tamper::assert_transcript_sweep(&ours, &theirs, &s.preimage());
}
#[test]
fn refund_withdrawal_matches_corpus() {
    let theirs = corpus_zkir_named("refund");
    let ours = erc20_vault::refund().ir;
    let s = RefundScenario::new(RefundRoute::Withdrawal(WithdrawScenario::new()));
    let pi = s.preimage();
    support::dump_preimage("refund", &pi);
    assert_call_compatible(&ours, &theirs, &pi);
}

#[test]
fn refund_swap_matches_corpus() {
    let theirs = corpus_zkir_named("refund");
    let ours = erc20_vault::refund().ir;
    let s = RefundScenario::new(RefundRoute::Swap(SwapScenario::new()));
    assert_call_compatible(&ours, &theirs, &s.preimage());
}

#[test]
fn refund_rejects_guard_failures() {
    let theirs = corpus_zkir_named("refund");
    let ours = erc20_vault::refund().ir;

    // Not the MPC failure output (an attested 5-byte non-failure value).
    let s = RefundScenario::new(RefundRoute::Withdrawal(WithdrawScenario::new()));
    let mut pi = s.preimage();
    pi.inputs[9] = Fr::from(0x0102030405u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: not the failure output");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: not the failure output");

    // Not the withdrawer.
    let s = RefundScenario::new(RefundRoute::Withdrawal(WithdrawScenario::new()));
    let mut pi = s.preimage();
    pi.private_transcript[0] = pi.private_transcript[0] + Fr::from(1u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: not the withdrawer");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: not the withdrawer");

    // Not the swapper.
    let s = RefundScenario::new(RefundRoute::Swap(SwapScenario::new()));
    let mut pi = s.preimage();
    pi.private_transcript[0] = pi.private_transcript[0] + Fr::from(1u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: not the swapper");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: not the swapper");
}

/// Tamper sweep over both routes' transcripts.
#[test]
fn refund_rejects_tampering() {
    let theirs = corpus_zkir_named("refund");
    let ours = erc20_vault::refund().ir;

    for route in [
        RefundScenario::new(RefundRoute::Withdrawal(WithdrawScenario::new())),
        RefundScenario::new(RefundRoute::Swap(SwapScenario::new())),
    ] {
        tamper::assert_transcript_sweep(&ours, &theirs, &route.preimage());
    }
}

#[test]
fn approve_router_matches_corpus() {
    let theirs = corpus_zkir_named("approveRouter");
    let ours = erc20_vault::approve_router().ir;
    let s = ApproveScenario::new();
    let pi = s.preimage();
    support::dump_preimage("approveRouter", &pi);
    assert_call_compatible(&ours, &theirs, &pi);
}

#[test]
fn approve_router_rejects_guard_failures() {
    let theirs = corpus_zkir_named("approveRouter");
    let ours = erc20_vault::approve_router().ir;

    // Not initialized.
    let mut s = ApproveScenario::new();
    s.initialized = 0;
    let pi = s.preimage();
    assert!(simulate(&ours, &pi).is_err(), "ours: not initialized");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: not initialized");

    // Zero ERC20.
    let mut s = ApproveScenario::new();
    s.erc20 = [0u8; 20];
    let pi = s.preimage();
    assert!(simulate(&ours, &pi).is_err(), "ours: zero erc20");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: zero erc20");
}

#[test]
fn deposit_matches_corpus() {
    let theirs = corpus_zkir_named("deposit");
    let ours = erc20_vault::deposit().ir;
    let s = DepositScenario::new();
    let pi = s.preimage();
    support::dump_preimage("deposit", &pi);
    assert_call_compatible(&ours, &theirs, &pi);
}

/// Guard failures must be rejected by BOTH artifacts.
#[test]
fn deposit_rejects_guard_failures() {
    let theirs = corpus_zkir_named("deposit");
    let ours = erc20_vault::deposit().ir;

    // Not initialized.
    let mut s = DepositScenario::new();
    s.initialized = 0;
    let pi = s.preimage();
    assert!(simulate(&ours, &pi).is_err(), "ours: not initialized");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: not initialized");

    // Zero ERC20 address.
    let mut s = DepositScenario::new();
    s.erc20 = [0u8; 20];
    let pi = s.preimage();
    assert!(simulate(&ours, &pi).is_err(), "ours: zero erc20");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: zero erc20");

    // Zero amount.
    let mut s = DepositScenario::new();
    s.amount = 0;
    let pi = s.preimage();
    assert!(simulate(&ours, &pi).is_err(), "ours: zero amount");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: zero amount");

    // Zero gas limit.
    let mut s = DepositScenario::new();
    s.gas_limit = 0;
    let pi = s.preimage();
    assert!(simulate(&ours, &pi).is_err(), "ours: zero gas limit");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: zero gas limit");

    // keyVersion 0.
    let mut s = DepositScenario::new();
    s.key_version = 0;
    let pi = s.preimage();
    assert!(simulate(&ours, &pi).is_err(), "ours: keyVersion 0");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: keyVersion 0");

    // Request already exists (member reads back true).
    let s = DepositScenario::new();
    let mut pi = s.preimage();
    // The member popeq result is output element index 6 in read order:
    // init(1) + vaultEvm(1) + chainId(1) + nonce(1) + self(2) + caip2(2) = 8.
    assert_eq!(pi.public_transcript_outputs[8], Fr::from(0u64));
    pi.public_transcript_outputs[8] = Fr::from(1u64);
    // The transcript's member popeq must agree with the flipped output.
    let mut s2 = DepositScenario::new();
    s2.initialized = s.initialized;
    let mut transcript = Vec::new();
    let mut ops = s2.ops();
    for op in &mut ops {
        if let Op::Popeq { result, .. } = op {
            if *result == bytesn_value(1, &[0]) {
                *result = bytesn_value(1, &[1]);
            }
        }
        op.field_repr(&mut transcript);
    }
    pi.public_transcript_inputs = transcript;
    assert!(simulate(&ours, &pi).is_err(), "ours: request exists");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: request exists");
}

/// Tampering with any transcript element or witness must be rejected by
/// both artifacts, with zero acceptance disagreements.
#[test]
fn deposit_rejects_tampering() {
    let theirs = corpus_zkir_named("deposit");
    let ours = erc20_vault::deposit().ir;
    let s = DepositScenario::new();

    tamper::assert_full_sweep(&ours, &theirs, &s.preimage());
}

#[test]
fn initialize_matches_corpus() {
    let theirs = corpus_zkir();
    let ours = erc20_vault::initialize().ir;
    let s = Scenario::new();
    let pi = s.preimage(0);
    support::dump_preimage("initialize", &pi);
    assert_call_compatible(&ours, &theirs, &pi);
}

/// Criterion 3 (same acceptance): each guard failure must be rejected by
/// BOTH artifacts.
#[test]
fn initialize_rejects_guard_failures() {
    let theirs = corpus_zkir();
    let ours = erc20_vault::initialize().ir;

    // Already initialized: the counter reads back 1.
    let s = Scenario::new();
    let pi = s.preimage(1);
    assert!(simulate(&ours, &pi).is_err(), "ours: already initialized");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: already initialized");

    // Wrong deployer secret.
    let s = Scenario::new();
    let mut pi = s.preimage(0);
    let mut wrong_sk = s.sk;
    wrong_sk[0] ^= 1;
    let (hi, lo) = b32_slots(&wrong_sk);
    pi.private_transcript = vec![hi, lo];
    assert!(simulate(&ours, &pi).is_err(), "ours: wrong secret");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: wrong secret");

    // Zero chain id.
    let mut s = Scenario::new();
    s.chain_id = 0;
    let pi = s.preimage(0);
    assert!(simulate(&ours, &pi).is_err(), "ours: zero chain id");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: zero chain id");

    // Zero router address.
    let mut s = Scenario::new();
    s.swap_router = [0u8; 20];
    let pi = s.preimage(0);
    assert!(simulate(&ours, &pi).is_err(), "ours: zero router");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: zero router");
}
