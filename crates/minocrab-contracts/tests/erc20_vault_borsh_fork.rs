//! THE SECOND FORK GATE (M11 stage 4): what the Borsh vault owes the
//! optimized one, circuit by circuit.
//!
//! M10 built a chain of trust `compactc ≡ direct port ≡ optimized artifact`
//! and `tests/erc20_vault_opt_fork.rs` gates its second link. M11 adds a
//! third artifact and therefore a third link, `optimized ≡ borsh`, gated
//! here on exactly the same discipline:
//!
//! - while a borsh circuit is BYTE-IDENTICAL to its optimized twin it
//!   inherits everything the twin has. WHAT THAT IS, AT THIS POINT IN THE
//!   CHAIN, IS NOT COMPACTC: M10 diverged all nine circuits, so `fork_status`
//!   says `Diverged` for every one of them and the compactc differential has
//!   already been replaced — by the spec harness, PI-equality re-anchored to
//!   the optimized reference model, and the adversarial sweeps. The borsh
//!   artifact inherits exactly that, and this file is deliberately NOT a
//!   compactc differential (a `doubly identical` test would be vacuous today
//!   and would stay vacuous, since M10's ledger is closed and entries only
//!   ever move one way);
//! - once an M11 stage moves a circuit, the optimized artifact has no
//!   opinion about it any more. The gate becomes the spec harness
//!   (`erc20_vault_spec.rs`, which runs every case against all three
//!   artifacts with each one's own reference model) plus the adversarial
//!   sweeps.
//!
//! `vault::artifact::borsh_fork_status` is the ledger, and BOTH directions
//! are asserted: an `Identical` entry must really be byte-identical, a
//! `Diverged` entry must really differ. A stage that moves a circuit without
//! moving its ledger entry fails the build, and a stale `Diverged` entry
//! cannot claim a divergence that is not there.

use midnight_transient_crypto::proofs::ProofPreimage;
use minocrab_sim::v3::simulate;
use minocrab_zkir::v3::to_zkir_string;

mod support;
mod vault;

use vault::artifact::{Art, Circuit, Fork};
use vault::model::*;

/// One borsh circuit and a preimage of it the reference model built.
fn preimages() -> Vec<(Circuit, ProofPreimage)> {
    let borsh = Art::Borsh;
    vec![
        (
            Circuit::Initialize,
            Scenario::new().with_art(borsh).preimage(0),
        ),
        (
            Circuit::Deposit,
            DepositScenario::new().with_art(borsh).preimage(),
        ),
        (
            Circuit::Claim,
            ClaimScenario::new().with_art(borsh).preimage(),
        ),
        (
            Circuit::ApproveRouter,
            ApproveScenario::new().with_art(borsh).preimage(),
        ),
        (
            Circuit::Withdraw,
            WithdrawScenario::new().with_art(borsh).preimage(),
        ),
        (
            Circuit::CompleteWithdraw,
            CompleteWithdrawScenario::new(1).with_art(borsh).preimage(),
        ),
        (
            Circuit::Refund,
            RefundScenario::new(RefundRoute::Withdrawal(WithdrawScenario::new()))
                .with_art(borsh)
                .preimage(),
        ),
        (Circuit::Swap, SwapScenario::new().with_art(borsh).preimage()),
        (
            Circuit::CompleteSwap,
            CompleteSwapScenario::new().with_art(borsh).preimage(),
        ),
    ]
}

/// Every circuit the borsh ledger calls `Identical` really is byte-identical
/// to its optimized twin — same ZKIR, instruction for instruction.
#[test]
fn identical_circuits_are_byte_identical_to_the_optimized_vault() {
    for circuit in Circuit::ALL {
        let Fork::Identical = vault::artifact::borsh_fork_status(circuit) else {
            continue;
        };
        let opt = to_zkir_string(&circuit.ir(Art::Opt)).expect("the opt artifact serializes");
        let borsh = to_zkir_string(&circuit.ir(Art::Borsh)).expect("the borsh artifact serializes");
        assert_eq!(
            opt,
            borsh,
            "{}: the borsh divergence ledger calls this circuit identical to \
             the optimized vault, but the two artifacts differ. If an M11 \
             stage moved it, move its `borsh_fork_status` entry to \
             `Fork::Diverged` in the same commit — that edit is the record \
             that the circuit has left the optimized artifact's coverage and \
             now relies on the spec harness alone.",
            circuit.zkir_name()
        );
    }
}

/// ...and every circuit the borsh ledger calls `Diverged` really has moved.
#[test]
fn diverged_circuits_really_differ_from_the_optimized_vault() {
    for circuit in Circuit::ALL {
        let Fork::Diverged { rung, why } = vault::artifact::borsh_fork_status(circuit) else {
            continue;
        };
        let opt = to_zkir_string(&circuit.ir(Art::Opt)).expect("the opt artifact serializes");
        let borsh = to_zkir_string(&circuit.ir(Art::Borsh)).expect("the borsh artifact serializes");
        assert_ne!(
            opt,
            borsh,
            "{}: the ledger says this circuit diverged at {rung} ({why}), but \
             it is byte-identical to the optimized vault — delete the stale entry",
            circuit.zkir_name()
        );
    }
}

/// Every borsh circuit accepts the preimage its own reference model builds.
///
/// The reference model is the SAME model, told `Art::Borsh` — so this is
/// also the statement that the borsh artifact's own model concretizes to
/// something the circuit accepts, which is what the spec harness then sweeps
/// at scale. Stage 4 deliberately did not bench this artifact; the stage-7
/// record change then crossed swap k16→k15, which is exactly the kind of
/// movement the benchmark exists to publish — so this test now also dumps
/// the side's preimages (a no-op unless `MINOCRAB_DUMP_PREIMAGES` is set;
/// see bench.sh), superseding that decision.
#[test]
fn borsh_circuits_accept_their_reference_preimages() {
    for (circuit, pi) in preimages() {
        let ir = circuit.ir(Art::Borsh);
        simulate(&ir, &pi).unwrap_or_else(|e| {
            panic!(
                "the borsh {} rejects its own reference preimage: {e}",
                circuit.zkir_name()
            )
        });
        support::dump_preimage_in(Some("borsh"), circuit.zkir_name(), &pi);
    }
}
