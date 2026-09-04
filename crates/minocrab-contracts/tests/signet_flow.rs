//! `signet_flow::Pending` on a toy contract: the smallest request/settle
//! pair, built through the public API alone.
//!
//! What this file pins: the block layout the derive computes over the
//! multi-field slots, the notification path derived from it, the label sets
//! `request` and `settle` publish (the `#[circuit]` disclosure gate does
//! that one), and that each circuit builds at a finite cost. The
//! round-trip through a simulated MPC is M35 rung D's.

use minocrab::v3::Circuit3;
use minocrab::{Private, Public};
use minocrab_contracts::common::{witness_sk, SecretKey, SigningPath};
use minocrab_contracts::signet::EvmCalldata;
use minocrab_contracts::signet_flow::{
    Commit, EvmTx, FailureResponse, Pending, Requested, Response, Settle, Settled, SignRequest,
    Signet,
};
use minocrab_sim::v3::cost;
use minocrab_std::v3::borsh::CircuitBorsh;
use minocrab_std::v3::{
    circuit, is_true, label, Bool, Disclose, Discloses, Ledger, LedgerCounter, LedgerRepr, Uint,
    B32,
};

// ---- the contract's own types -------------------------------------------------

/// What `claim` needs back: public by construction.
#[derive(LedgerRepr)]
struct DepositEnv {
    amount: Uint<64, Public>,
}

/// A withdrawal's environment: the amount, and a COMMITMENT to the
/// withdrawer's key — the one thing that survives privately.
#[derive(LedgerRepr)]
struct WithdrawEnv {
    amount: Uint<64, Public>,
    withdrawer: Commit<SecretKey<Private>>,
}

const WITHDRAWER_DOMAIN: &str = "toy:withdrawer:";

/// `{ success: bool }`, kind 0.
#[derive(CircuitBorsh)]
struct ClaimResponse {
    success: Bool,
}
impl Response for ClaimResponse {
    const KIND: u8 = 0;
}

/// `{ success: bool }`, kind 1 — the same shape, a different kind.
#[derive(CircuitBorsh)]
struct WithdrawResponse {
    success: Bool,
}
impl Response for WithdrawResponse {
    const KIND: u8 = 1;
}

/// The MPC's "never executed" output, kind 3, shared by every flow.
#[derive(CircuitBorsh)]
struct Failure {
    _unused: Uint<8>,
}
impl Response for Failure {
    const KIND: u8 = 3;
}
impl FailureResponse for Failure {}

/// The ledger block: seven fields from three declarations.
#[derive(Ledger)]
struct Toy {
    initialized: LedgerCounter,
    signet: Signet,
    deposits: Pending<DepositEnv, ClaimResponse>,
    withdrawals: Pending<WithdrawEnv, WithdrawResponse>,
}

const TOY: Toy = Toy::new();

label! {
    Amount = "amount";
    WithdrawerCommitment = "withdrawer commitment";
}

fn evm_tx(c: &mut Circuit3, amount: minocrab::v3::Wire3<minocrab::v3::FieldT, Private>) -> EvmTx<2> {
    let zero = c.constant(0u64).private();
    let one = c.constant(1u64).private();
    let two = c.constant(2u64).private();
    let to = c.constant(0x42u64).private();
    let word = B32 { hi: zero, lo: amount };
    EvmTx {
        nonce: zero,
        max_priority_fee_per_gas: one,
        max_fee_per_gas: two,
        gas_limit: c.constant(100_000u64).private(),
        to,
        value: zero,
        calldata_is_some: one,
        calldata: EvmCalldata {
            selector: c.constant(0xa9059cbbu64).private(),
            no_words: two,
            words: [word, word],
        },
    }
}

// ---- the circuits ------------------------------------------------------------------

#[circuit]
fn deposit(c: &mut Circuit3, key_version: Uint<8>, amount: Uint<64>) -> Discloses<(Amount, Requested)> {
    let amount_pub = amount.field().disclose_as::<Amount>(c);
    let tx = evm_tx(c, amount.field());
    let path = SigningPath(B32 {
        hi: c.constant(7u64).private(),
        lo: c.constant(9u64).private(),
    });
    TOY.deposits.request(c, &TOY.signet, SignRequest { key_version, path, tx }, |_, _| {
        DepositEnv { amount: Uint::from_field_unchecked(amount_pub) }
    });
    Discloses::of(())
}

#[circuit]
fn withdraw(
    c: &mut Circuit3,
    key_version: Uint<8>,
    amount: Uint<64>,
) -> Discloses<(Amount, WithdrawerCommitment, Requested)> {
    let amount_pub = amount.field().disclose_as::<Amount>(c);
    let tx = evm_tx(c, amount.field());
    let path = SigningPath::vault_path(c).private();
    let sk = witness_sk(c);
    TOY.withdrawals.request(c, &TOY.signet, SignRequest { key_version, path, tx }, |c, id| {
        WithdrawEnv {
            amount: Uint::from_field_unchecked(amount_pub),
            withdrawer: Commit::to::<WithdrawerCommitment>(c, WITHDRAWER_DOMAIN, &sk, id),
        }
    });
    Discloses::of(())
}

#[circuit]
fn claim(c: &mut Circuit3, ticket: Settle<DepositEnv, ClaimResponse>) -> Discloses<Settled> {
    let outcome = TOY.deposits.settle(c, &TOY.signet, ticket);
    c.assert(is_true(outcome.output.success).message("The MPC attested a failure"));
    let _amount = outcome.env.amount;
    Discloses::of(())
}

#[circuit]
fn refund_withdrawal(c: &mut Circuit3, ticket: Settle<WithdrawEnv, Failure>) -> Discloses<Settled> {
    let outcome = TOY.withdrawals.settle_failed(c, &TOY.signet, ticket);
    // The withdrawer gate: a FRESH witness against the stored commitment.
    let sk = witness_sk(c);
    outcome
        .env
        .withdrawer
        .open(c, WITHDRAWER_DOMAIN, &sk, outcome.request_id, "Not the withdrawer");
    let _amount = outcome.env.amount;
    Discloses::of(())
}

// ---- the tests ----------------------------------------------------------------------

/// `initialized` is field 0, `signet` fields 1..6, `deposits` 6 and 7,
/// `withdrawals` 8 and 9 — a block of ten, so still one-element paths.
#[test]
fn the_block_is_laid_out_by_slot_width() {
    assert_eq!(TOY.initialized.index(), 0);
    assert_eq!(TOY.signet.signer.index(), 1);
    assert_eq!(TOY.signet.evm_chain_id.index(), 5);
    assert_eq!(TOY.deposits.record_path().as_slice(), &[6]);
    assert_eq!(TOY.withdrawals.record_path().as_slice(), &[8]);
    assert_eq!(TOY.withdrawals.record_path().depth(), 1);
}

/// Each circuit builds, and at a cost a settle's secp256k1 verification
/// dominates (the vault's settle circuits sit at k = 13-14).
#[test]
fn the_circuits_build_at_a_finite_cost() {
    let (k_req, rows_req) = cost(&deposit().ir);
    let (k_wd, _) = cost(&withdraw().ir);
    let (k_claim, rows_claim) = cost(&claim().ir);
    let (k_ref, _) = cost(&refund_withdrawal().ir);
    assert!(rows_req > 0 && rows_claim > rows_req, "{rows_req} {rows_claim}");
    assert!(k_req <= 14 && k_wd <= 14 && k_claim <= 15 && k_ref <= 15, "{k_req} {k_wd} {k_claim} {k_ref}");
}
