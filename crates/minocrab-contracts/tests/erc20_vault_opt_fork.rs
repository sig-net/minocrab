//! The FORK GATE (M10 §Sequencing step 4): what the optimized vault owes
//! the compatibility reference, circuit by circuit.
//!
//! M10's chain of trust starts `compactc ≡ direct port` and continues
//! `direct port ≡ optimized artifact`. The second link is not one property
//! but two, and which one applies depends on how far a circuit has moved:
//!
//! - while an opt circuit is BYTE-IDENTICAL to its port it inherits the
//!   port's compactc PI-equality differential outright, and this file says
//!   so out loud — it runs the opt artifact against compactc's golden on the
//!   reference model's preimage, exactly as `erc20_vault_differential.rs`
//!   runs the port;
//! - once a rung moves it, compactc has no opinion about the circuit any
//!   more. The gate becomes the spec harness (`erc20_vault_spec.rs`:
//!   acceptance agreement, ledger effects, PI-equality re-anchored to the
//!   OPT reference model) plus the adversarial sweeps.
//!
//! `vault::artifact::fork_status` is the ledger of which circuit is in
//! which state, and both directions are asserted here: an `Identical` entry
//! must really be byte-identical, and a `Diverged` entry must really
//! differ. So a rung cannot quietly drop a circuit out of compactc's
//! coverage (the identity assertion fails until the ledger is updated), and
//! a stale `Diverged` entry cannot quietly claim coverage it does not need
//! (the difference assertion fails). The ledger edit is the record of the
//! trade.
//!
//! This file also dumps the optimized side's `ProofPreimage`s for the
//! benchmark harness (`preimages/opt/`), for the same reason the
//! differential suite dumps the shared ones: a benchmarked preimage should
//! be one a test has already accepted.

use midnight_transient_crypto::proofs::ProofPreimage;
use minocrab_sim::v3::{assert_call_compatible, simulate};
use minocrab_zkir::v3::{to_zkir_string, IrSource};

mod support;
mod vault;

use vault::artifact::{Art, Circuit, Fork};
use vault::model::*;
use vault::prims::corpus_zkir_named;

/// One optimized circuit and a preimage of it the reference model built.
fn preimages() -> Vec<(Circuit, ProofPreimage)> {
    let opt = Art::Opt;
    vec![
        (Circuit::Initialize, Scenario::new().with_art(opt).preimage(0)),
        (Circuit::Deposit, DepositScenario::new().with_art(opt).preimage()),
        (Circuit::Claim, ClaimScenario::new().with_art(opt).preimage()),
        (
            Circuit::ApproveRouter,
            ApproveScenario::new().with_art(opt).preimage(),
        ),
        (
            Circuit::Withdraw,
            WithdrawScenario::new().with_art(opt).preimage(),
        ),
        (
            Circuit::CompleteWithdraw,
            CompleteWithdrawScenario::new(1).with_art(opt).preimage(),
        ),
        (
            Circuit::Refund,
            RefundScenario::new(RefundRoute::Withdrawal(WithdrawScenario::new()))
                .with_art(opt)
                .preimage(),
        ),
        (Circuit::Swap, SwapScenario::new().with_art(opt).preimage()),
        (
            Circuit::CompleteSwap,
            CompleteSwapScenario::new().with_art(opt).preimage(),
        ),
    ]
}

/// compactc's golden accepts the same preimage with the same PI vector —
/// THE comparator (`minocrab_sim::v3::assert_call_compatible`), applied to
/// the opt side. This used to be a local copy that had drifted weaker (no
/// schema check, no `theirs.check`); the external review's §3.8 caught it.
fn assert_pi_equal_to_corpus(ours: &IrSource, theirs: &IrSource, pi: &ProofPreimage) {
    assert_call_compatible(ours, theirs, pi);
}

/// Every circuit the ledger calls `Identical` really is byte-identical to
/// its direct port — same ZKIR, instruction for instruction.
#[test]
fn identical_circuits_are_byte_identical_to_the_port() {
    for circuit in Circuit::ALL {
        let Fork::Identical = vault::artifact::fork_status(circuit) else {
            continue;
        };
        let port = to_zkir_string(&circuit.ir(Art::Compat)).expect("the port serializes");
        let opt = to_zkir_string(&circuit.ir(Art::Opt)).expect("the opt artifact serializes");
        assert_eq!(
            port,
            opt,
            "{}: the divergence ledger calls this circuit identical to the \
             port, but the two artifacts differ. If a rung moved it, move its \
             `fork_status` entry to `Fork::Diverged` in the same commit — that \
             edit is the record that the circuit has left compactc's coverage \
             and now relies on the spec harness alone.",
            circuit.zkir_name()
        );
    }
}

/// ...and every circuit the ledger calls `Diverged` really has moved. A
/// stale entry would claim the spec harness is carrying a circuit that
/// compactc still covers — harmless for soundness, but a lie about where
/// the assurance comes from, which is the one thing this file exists to
/// keep honest.
#[test]
fn diverged_circuits_really_differ_from_the_port() {
    for circuit in Circuit::ALL {
        let Fork::Diverged { rung, why } = vault::artifact::fork_status(circuit) else {
            continue;
        };
        let port = to_zkir_string(&circuit.ir(Art::Compat)).expect("the port serializes");
        let opt = to_zkir_string(&circuit.ir(Art::Opt)).expect("the opt artifact serializes");
        assert_ne!(
            port,
            opt,
            "{}: the ledger says this circuit diverged at {rung} ({why}), but \
             it is byte-identical to the port — delete the stale entry",
            circuit.zkir_name()
        );
    }
}

/// While a circuit is byte-identical, compactc's PI-equality differential
/// covers the optimized artifact too. Asserted rather than assumed: this is
/// the whole content of "byte-identical fork", and it is the last commit at
/// which some of these circuits will have it.
#[test]
fn identical_circuits_are_still_pi_equal_to_compactc() {
    for (circuit, pi) in preimages() {
        let Fork::Identical = vault::artifact::fork_status(circuit) else {
            continue;
        };
        let theirs = corpus_zkir_named(circuit.zkir_name());
        assert_pi_equal_to_corpus(&circuit.ir(Art::Opt), &theirs, &pi);
    }
}

/// The optimized side's preimages, for the three-way benchmark. Every one
/// is a preimage the artifact accepts — checked here, not assumed by the
/// harness. (A no-op unless `MINOCRAB_DUMP_PREIMAGES` is set; see bench.sh.)
#[test]
fn optimized_preimages_are_accepted_and_dumped() {
    for (circuit, pi) in preimages() {
        let ir = circuit.ir(Art::Opt);
        simulate(&ir, &pi).unwrap_or_else(|e| {
            panic!(
                "the optimized {} rejects its own reference preimage: {e}",
                circuit.zkir_name()
            )
        });
        support::dump_preimage_in(Some("opt"), circuit.zkir_name(), &pi);
    }
}
