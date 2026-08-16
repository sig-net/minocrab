//! THE TWIN'S GATE (M9 phase 8): what the showcase artifact owes the borsh
//! fork, circuit by circuit — and it is not byte-identity.
//!
//! The two earlier fork tests (`erc20_vault_opt_fork.rs`,
//! `erc20_vault_borsh_fork.rs`) gate a chain whose links are byte-identity
//! until a rung deliberately cuts one. This link was different in kind: the
//! twin rewrites ALL NINE circuits on purpose, and what it claimed was not
//! that the streams agree but that the STATEMENTS do.
//!
//! That claim is the project's own equivalence criterion, unchanged since M3
//! (notes/ledger-abi.org §6, and the comparator
//! `erc20_vault_differential.rs`): same typed I/O schema, same `pis` and
//! `pi_skips` on a SHARED `ProofPreimage`. The instruction stream is free
//! under it — which is exactly why an ergonomics rewrite can be checked
//! rather than merely admired, and why the twin inherits the borsh fork's
//! coverage (the spec harness, the adversarial sweeps, and transitively
//! whatever covers those) instead of needing a coverage story of its own.
//!
//! SINCE THE CONSTANT-FOLDING PASS (notes/ir-passes.org §2 ii) the claim is
//! stronger than that, and the ledger says so: all nine entries are
//! `Identical`. Phase 8's rewrite differed from the borsh fork in exactly one
//! class of instruction — the `Copy`s that NAMED a constant — and the pass
//! inlines every one of them on both sides. The M9 API's ergonomics are free
//! at the IR level, not merely PI-equivalent. The PI-equality test below is
//! kept, because it is the claim that would still hold if a future rewrite
//! did move an instruction.
//!
//! `vault::artifact::modern_fork_status` is the ledger and BOTH directions
//! are asserted, one assertion per [`Twin`] variant:
//!
//! - `Identical` — really identical, instruction for instruction, up to the
//!   naming of values (the fold removes a different number of named constants
//!   on each side, so four of the nine agree only after canonicalizing names);
//! - `PiEqual` — really DIFFERENT, and really PI-equal on the reference
//!   model's preimage. Both halves matter: the first says the entry is not
//!   stale, the second is the whole warrant for the inheritance. Unused today,
//!   and the first rewrite that genuinely moves an instruction has to come
//!   back and use it;
//! - `SpecAnchored` — really PI-different. Unused today, and asserted to be
//!   unused: a rewrite that moved a public input would have to say so here,
//!   in this file's failure, before it could be committed.
//!
//! The interface snapshot carries the other half of the criterion (the typed
//! I/O schema, argument by argument), and `tests/erc20_vault_spec.rs` runs
//! every generated case against `Art::Modern` like every other artifact.

use midnight_transient_crypto::proofs::ProofPreimage;
use minocrab_sim::v3::simulate;
use minocrab_zkir::v3::to_zkir_string;

mod vault;

use vault::artifact::{Art, Circuit, Twin};
use vault::model::*;

/// One circuit and a preimage of it the BORSH reference model built — the
/// same preimage both artifacts are asked to accept, which is what makes the
/// PI comparison a comparison of statements rather than of two models.
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

/// Serialized ZKIR with every `%name.index` identifier canonicalized — the
/// same renaming the instruction-for-instruction differentials use.
///
/// Needed here because the fold removes a different number of named constants
/// on each side (a removed `Copy` still consumed its number), so four of the
/// nine twins are identical in every instruction and differ only in the
/// numeric suffix of names. A name is not a lowering.
fn canonical(ir: &minocrab_zkir::v3::IrSource) -> String {
    let text = to_zkir_string(ir).expect("serializes");
    let mut renames: Vec<(String, String)> = Vec::new();
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(at) = rest.find('%') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let end = rest[1..]
            .find(|ch: char| !(ch.is_alphanumeric() || ch == '_' || ch == '.'))
            .map(|i| i + 1)
            .unwrap_or(rest.len());
        let name = &rest[..end];
        let next = renames.len();
        let canon = match renames.iter().find(|(from, _)| from == name) {
            Some((_, to)) => to.clone(),
            None => {
                let to = format!("%{next}");
                renames.push((name.to_string(), to.clone()));
                to
            }
        };
        out.push_str(&canon);
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// A circuit the ledger calls `Identical` really is identical — instruction
/// for instruction, up to the naming of values.
#[test]
fn identical_circuits_are_identical_to_the_borsh_fork() {
    for circuit in Circuit::ALL {
        let Twin::Identical = vault::artifact::modern_fork_status(circuit) else {
            continue;
        };
        assert_eq!(
            canonical(&circuit.ir(Art::Borsh)),
            canonical(&circuit.ir(Art::Modern)),
            "{}: the twin's ledger calls this circuit identical to the borsh \
             fork, but the two artifacts differ — move its entry to \
             `Twin::PiEqual` with the reason",
            circuit.zkir_name()
        );
    }
}

/// A circuit the ledger calls `PiEqual` really has been rewritten: the
/// streams differ. (The stale-entry direction — this is what stops the ledger
/// claiming a rewrite that never happened.)
#[test]
fn pi_equal_circuits_really_differ_from_the_borsh_fork() {
    for circuit in Circuit::ALL {
        let Twin::PiEqual { why } = vault::artifact::modern_fork_status(circuit) else {
            continue;
        };
        assert_ne!(
            canonical(&circuit.ir(Art::Borsh)),
            canonical(&circuit.ir(Art::Modern)),
            "{}: the ledger says the twin rewrote this circuit ({why}), but it \
             is byte-identical to the borsh fork — record it as \
             `Twin::Identical` instead",
            circuit.zkir_name()
        );
    }
}

/// ...and it proves the SAME STATEMENT: the borsh fork's own preimage is
/// accepted by the twin, with the same `pis` and the same `pi_skips`.
///
/// THIS IS THE PHASE'S CLAIM. Everything else in the file is bookkeeping
/// around it.
#[test]
fn pi_equal_circuits_prove_the_same_statement() {
    for (circuit, pi) in preimages() {
        let Twin::PiEqual { .. } = vault::artifact::modern_fork_status(circuit) else {
            continue;
        };
        let name = circuit.zkir_name();
        let theirs = simulate(&circuit.ir(Art::Borsh), &pi)
            .unwrap_or_else(|e| panic!("the borsh {name} rejects its own reference preimage: {e}"));
        let ours = simulate(&circuit.ir(Art::Modern), &pi).unwrap_or_else(|e| {
            panic!("the twin's {name} rejects the borsh fork's reference preimage: {e}")
        });
        assert_eq!(
            theirs.pi_skips, ours.pi_skips,
            "{name}: pi_skips differ between the borsh fork and the twin"
        );
        assert_eq!(
            theirs.pis, ours.pis,
            "{name}: the PI vectors differ between the borsh fork and the twin \
             — the rewrite changed the STATEMENT, not just the stream, and the \
             ledger entry has to become `Twin::SpecAnchored`"
        );
    }
}

/// A circuit the ledger calls `SpecAnchored` really has moved its PIs. No
/// circuit does today; the test exists so that the day one does, the claim
/// above fails first and this one becomes the record of the trade.
#[test]
fn spec_anchored_circuits_really_moved_their_public_inputs() {
    for (circuit, pi) in preimages() {
        let Twin::SpecAnchored { why } = vault::artifact::modern_fork_status(circuit) else {
            continue;
        };
        let name = circuit.zkir_name();
        let theirs = simulate(&circuit.ir(Art::Borsh), &pi).ok();
        let ours = simulate(&circuit.ir(Art::Modern), &pi).ok();
        let same = match (theirs, ours) {
            (Some(t), Some(o)) => t.pis == o.pis && t.pi_skips == o.pi_skips,
            _ => false,
        };
        assert!(
            !same,
            "{name}: the ledger says this circuit left the borsh fork's \
             coverage ({why}), but it is still PI-equal to it — record it as \
             `Twin::PiEqual`, which is the stronger statement"
        );
    }
}

/// The twin's instruction streams are SHORTER, and by exactly the `Copy`s
/// that named the Impact guards and the constants that were named only to be
/// compared. Reported per circuit rather than asserted to a number: this is
/// the phase's delta, and notes/contract-api.org §"Phase 8" carries the
/// table. Run with `--ignored --nocapture` to print it.
#[test]
#[ignore = "reporting, not gating — prints the twin's instruction delta"]
fn print_the_instruction_deltas() {
    println!("{:<18} {:>9} {:>9} {:>7}", "circuit", "borsh", "modern", "delta");
    for circuit in Circuit::ALL {
        let borsh = circuit.build(Art::Borsh).ir.instructions.len();
        let modern = circuit.build(Art::Modern).ir.instructions.len();
        println!(
            "{:<18} {borsh:>9} {modern:>9} {:>7}",
            circuit.zkir_name(),
            modern as i64 - borsh as i64
        );
    }
}
