//! The tamper machinery, factored out of `erc20_vault_differential.rs` so
//! the differential suite and the adversarial sweeps share one
//! implementation rather than two copies that can drift.
//!
//! Two distinct properties live here and they must not be conflated:
//!
//! - [`sweep`] is the SOUNDNESS property: perturbing any single element of
//!   a preimage must make OUR artifact reject. A circuit that accepts a
//!   perturbed transcript is proving something weaker than its transcript
//!   claims.
//! - the `disagreements` count [`sweep`] returns is the COMPATIBILITY
//!   property: compactc's artifact must reject exactly the same
//!   perturbations. It is only meaningful when a corpus artifact is
//!   supplied, and is what the differential suite asserts is zero.

use midnight_transient_crypto::proofs::ProofPreimage;
use minocrab::Fr;
use minocrab_sim::v3::simulate;
use minocrab_zkir::v3::IrSource;

/// Which part of a preimage a sweep perturbs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part {
    /// The public transcript inputs — the ledger op stream's `field_repr`.
    Transcript,
    /// The private transcript — the witnesses.
    Witness,
    /// The circuit arguments.
    Inputs,
}

fn slot<'a>(pi: &'a mut ProofPreimage, part: Part) -> &'a mut Vec<Fr> {
    match part {
        Part::Transcript => &mut pi.public_transcript_inputs,
        Part::Witness => &mut pi.private_transcript,
        Part::Inputs => &mut pi.inputs,
    }
}

fn len(pi: &ProofPreimage, part: Part) -> usize {
    match part {
        Part::Transcript => pi.public_transcript_inputs.len(),
        Part::Witness => pi.private_transcript.len(),
        Part::Inputs => pi.inputs.len(),
    }
}

/// Perturb every element of `part` in turn by `+1`.
///
/// Asserts `ours` rejects each perturbation. Returns how many of them
/// `theirs` (when given) disagreed about — the differential suite's
/// acceptance-agreement count.
pub fn sweep(ours: &IrSource, theirs: Option<&IrSource>, pi: &ProofPreimage, part: Part) -> usize {
    let mut disagreements = 0;
    for i in 0..len(pi, part) {
        let mut t = pi.clone();
        slot(&mut t, part)[i] = slot(&mut t, part)[i] + Fr::from(1u64);
        let ours_rejects = simulate(ours, &t).is_err();
        assert!(
            ours_rejects,
            "ours accepts a tampered {part:?} element {i}"
        );
        if let Some(theirs) = theirs {
            if ours_rejects != simulate(theirs, &t).is_err() {
                disagreements += 1;
            }
        }
    }
    disagreements
}

/// [`sweep`] over the public transcript, the compatibility assertion
/// included — the shape every differential `*_rejects_tampering` test
/// wants.
pub fn assert_transcript_sweep(ours: &IrSource, theirs: &IrSource, pi: &ProofPreimage) {
    assert_eq!(
        sweep(ours, Some(theirs), pi, Part::Transcript),
        0,
        "acceptance disagreement on tampering"
    );
}

/// [`assert_transcript_sweep`] plus the witness sweep.
pub fn assert_full_sweep(ours: &IrSource, theirs: &IrSource, pi: &ProofPreimage) {
    let mut d = sweep(ours, Some(theirs), pi, Part::Transcript);
    d += sweep(ours, Some(theirs), pi, Part::Witness);
    assert_eq!(d, 0, "acceptance disagreement on tampering");
}

/// Replace one element outright (rather than nudging it) and report
/// whether the circuit still accepts. The malleability sweeps need this:
/// "set `s` to zero", not "add one to `s`".
pub fn accepts_with(ir: &IrSource, pi: &ProofPreimage, part: Part, i: usize, v: Fr) -> bool {
    let mut t = pi.clone();
    slot(&mut t, part)[i] = v;
    simulate(ir, &t).is_ok()
}

/// As [`accepts_with`] but keeping the rejection reason, so a test can
/// distinguish "the assert failed" from "the instruction aborted".
pub fn run_with(ir: &IrSource, pi: &ProofPreimage, part: Part, i: usize, v: Fr) -> Result<(), String> {
    let mut t = pi.clone();
    slot(&mut t, part)[i] = v;
    simulate(ir, &t).map(|_| ()).map_err(|e| e.to_string())
}

/// Re-derive a preimage's communications commitment after its arguments
/// were changed.
///
/// EVERY circuit argument is bound by `do_communications_commitment`:
/// `comm = transient_commit(inputs, rand)` is PI #2, so perturbing any
/// argument — even one the circuit never reads — makes the simulator
/// reject on the commitment alone. To ask whether a particular argument is
/// genuinely unread, the commitment has to be re-derived; otherwise the
/// test only re-proves that the commitment binds.
///
/// (Note what this does NOT mean: the ledger pushes the commitment
/// VERBATIM out of the `ContractCall` and never recomputes it from the FAB
/// inputs — `ledger/src/verify.rs:1946-1948` — so for a ROOT call the
/// commitment does not imply argument canonicity on chain. That is why the
/// `constrain_bits` range checks have to stay; see
/// notes/vault-optimization.org §"constrain_bits dedup".)
pub fn rebind_comm(pi: &mut ProofPreimage) {
    if let Some((_, rand)) = pi.communications_commitment {
        let comm = midnight_transient_crypto::hash::transient_commit(&pi.inputs[..], rand);
        pi.communications_commitment = Some((comm, rand));
    }
}

/// [`accepts_with`] on an argument, with the commitment re-derived — i.e.
/// "is this argument actually read?".
pub fn accepts_with_rebound_input(ir: &IrSource, pi: &ProofPreimage, i: usize, v: Fr) -> bool {
    let mut t = pi.clone();
    t.inputs[i] = v;
    rebind_comm(&mut t);
    simulate(ir, &t).is_ok()
}
