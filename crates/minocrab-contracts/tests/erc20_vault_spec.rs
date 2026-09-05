//! M10 step 1: the erc20-vault PROPERTY HARNESS — spec ≡ circuit ≡ ledger,
//! at scale, for all nine circuits.
//!
//! Each generated case is checked on four independent links
//! (notes/vault-optimization.org §"Binding circuit ≡ spec"):
//!
//! 1. **Acceptance agreement.** The spec is a total function; the circuit
//!    either accepts the witness or does not. They must agree, both ways.
//!    This is the link that catches "the circuit proves a different
//!    statement than we think".
//! 2. **PI-equality, re-anchored.** The differential suite pins our PI
//!    vector to compactc's. Here it is pinned to OUR reference op stream
//!    instead — `Op::field_repr` of the model's `Vec<Op>` — so the check
//!    survives an artifact that deliberately deviates from compactc.
//! 3. **Ledger execution.** The same op stream runs through the real
//!    Impact VM against a real pre-state, and the `Effects` it produces
//!    must be exactly the ones the spec declared. That is the equality
//!    `ledger/src/semantics.rs:1441` enforces on chain.
//! 4. **Reference VM.** Every accepted run is re-validated by
//!    `IrSource::check`, so a MinoCrab simulator bug cannot hide a circuit
//!    bug.
//!
//! Since M10 step 4 every property runs BOTH artifacts on each generated
//! case: the direct port and the optimized fork, each against its own
//! reference model (`Scenario::with_art`) and its own concretization. The
//! spec itself is shared and unchanged — that sharing is the honest
//! statement of "same contract, different constructions", and re-anchoring
//! PI-equality to the opt reference model is what replaces the compactc
//! differential once a circuit diverges (see
//! `tests/erc20_vault_opt_fork.rs`).
//!
//! Case count: `PROPTEST_CASES=1000000 cargo test --release` for the
//! gating run; the default is deliberately modest because the four settle
//! circuits simulate an in-circuit secp256k1 verification per case.

use midnight_transient_crypto::proofs::{ProofPreimage, Zkir};
use midnight_transient_crypto::repr::FieldRepr;
use minocrab_contracts::erc20_vault;
use minocrab_sim::v3::{assert_call_compatible, simulate};
use minocrab_zkir::v3::IrSource;
use proptest::prelude::*;

mod vault;

use vault::artifact::{Art, Circuit, ARTS};
use vault::exec::{self, PreState};
use vault::gen;
use vault::prims::VmOp;
use vault::spec::{self, Effect, Outcome};

/// Would applying the spec's counter increments overflow a `u64`?
///
/// The vault has NO counter-overflow guard: `signetRequestNonce` at
/// `u64::MAX` still passes every circuit assert, and it is the Impact VM
/// that refuses (`OnchainProgramError::ArithmeticOverflow`) when `Addi`
/// runs. Circuit-level acceptance and ledger-level acceptance genuinely
/// differ there, so the harness models the split rather than papering
/// over it. (Reaching it needs 2^64 requests; recorded, not a finding.)
fn counter_would_overflow(effects: &[Effect], pre: &PreState) -> bool {
    effects.iter().any(|e| match e {
        Effect::CounterInc { field, by } => {
            let cur = match *field {
                erc20_vault::SIGNET_REQUEST_NONCE => pre.request_nonce,
                erc20_vault::INITIALIZED => pre.initialized,
                _ => 0,
            };
            cur.checked_add(*by).is_none()
        }
        _ => false,
    })
}

/// The whole per-case check. Returns `Err(reason)` so proptest reports the
/// failing scenario rather than panicking inside a helper.
/// compactc's own artifact for `circuit`, parsed once — the fifth link's
/// oracle for the port lineage.
fn corpus_twin(circuit: Circuit) -> &'static IrSource {
    use std::collections::HashMap;
    use std::sync::OnceLock;
    static TWINS: OnceLock<HashMap<&'static str, IrSource>> = OnceLock::new();
    &TWINS.get_or_init(|| {
        Circuit::ALL
            .iter()
            .map(|c| (c.zkir_name(), vault::prims::corpus_zkir_named(c.zkir_name())))
            .collect()
    })[circuit.zkir_name()]
}

// The per-case check takes the case's every part by name; a struct for them
// would be one more list to keep complete beside the scenario types.
#[allow(clippy::too_many_arguments)]
fn check_case(
    circuit: Circuit,
    art: Art,
    ir: &IrSource,
    outcome: &Outcome,
    pre: &PreState,
    self_addr: &[u8; 32],
    ops: &[VmOp],
    pi: &ProofPreimage,
) -> Result<(), String> {
    // --- 1. acceptance agreement ---------------------------------------
    let run = simulate(ir, pi);
    let circuit_accepts = run.is_ok();
    if circuit_accepts != outcome.accepts() {
        return Err(format!(
            "acceptance disagreement: spec {:?}, circuit accepts = {circuit_accepts}{}",
            outcome.guard(),
            match &run {
                Err(e) => format!(" ({e})"),
                Ok(_) => String::new(),
            }
        ));
    }
    let Ok(run) = run else {
        return Ok(());
    };

    // --- 4. reference VM on every accepted run --------------------------
    let skips = ir
        .check(pi)
        .map_err(|e| format!("simulator accepted but the reference VM rejected: {e}"))?;
    if skips != run.pi_skips {
        return Err("reference VM and simulator disagree on pi_skips".into());
    }

    // --- 5. compactc, on the PORT: the generated preimage through THE
    // comparator against compactc's own artifact (external review §3.2 /
    // §7.5: the property scale used to run only against our own spec and
    // op stream). The optimised lineages have no compactc twin — that is
    // what the fork ledgers record — so for them the spec stays the oracle.
    if let Art::Compat = art {
        assert_call_compatible(ir, corpus_twin(circuit), pi);
    }

    // --- 2. PI-equality, re-anchored to OUR op stream -------------------
    // `simulate` already checks each TAKEN Impact's inputs elementwise
    // against `pi.public_transcript_inputs`, which is `field_repr(ops)`;
    // what it does not check is that the transcript holds nothing BEYOND
    // what the circuit consumed. Length closure does: every transcript
    // element is consumed by exactly one taken Impact input, and every
    // skipped Impact contributes exactly its count of zeros.
    let mut expected = Vec::new();
    for op in ops {
        op.field_repr(&mut expected);
    }
    if expected != pi.public_transcript_inputs {
        return Err("the preimage's transcript is not field_repr of the reference ops".into());
    }
    let skipped: usize = run.pi_skips.iter().flatten().sum();
    let prefix = 1 + usize::from(run.comm_comm.is_some());
    if run.pis.len() != prefix + expected.len() + skipped {
        return Err(format!(
            "PI vector length {} != {prefix} + transcript {} + skipped zeros {skipped}",
            run.pis.len(),
            expected.len()
        ));
    }

    // --- 3. ledger execution: declared effects == computed effects ------
    match exec::run(pre, self_addr, ops) {
        Ok(ex) => spec::check_effects(art, outcome.effects(), pre, &ex),
        Err(e) => {
            if counter_would_overflow(outcome.effects(), pre) {
                Ok(())
            } else {
                Err(format!("the Impact VM rejected the reference op stream: {e}"))
            }
        }
    }
}

proptest! {
    #![proptest_config(gen::config())]

    #[test]
    fn initialize_matches_spec((s, count) in gen::initialize()) {
        for art in ARTS {
            let s = s.clone().with_art(art);
            let ir = Circuit::Initialize.ir(art);
            let outcome = spec::spec_initialize(&s, count);
            // initialize reads no kernel.self, so the address is arbitrary.
            let r = check_case(Circuit::Initialize, art, &ir, &outcome, &s.pre_state(count), &[0u8; 32], &s.ops(count), &s.preimage(count));
            prop_assert!(r.is_ok(), "{art:?}: {r:?}");
        }
    }

    #[test]
    fn deposit_matches_spec(d in gen::deposit()) {
        for art in ARTS {
            let d = d.clone().with_art(art);
            let ir = Circuit::Deposit.ir(art);
            let outcome = spec::spec_deposit(&d);
            let r = check_case(Circuit::Deposit, art, &ir, &outcome, &d.pre_state(), &d.self_addr, &d.ops(), &d.preimage());
            prop_assert!(r.is_ok(), "{art:?}: {r:?}");
        }
    }

    #[test]
    fn approve_router_matches_spec(a in gen::approve()) {
        for art in ARTS {
            let a = a.clone().with_art(art);
            let ir = Circuit::ApproveRouter.ir(art);
            let outcome = spec::spec_approve_router(&a);
            let r = check_case(Circuit::ApproveRouter, art, &ir, &outcome, &a.pre_state(), &a.self_addr, &a.ops(), &a.preimage());
            prop_assert!(r.is_ok(), "{art:?}: {r:?}");
        }
    }

    #[test]
    fn withdraw_matches_spec(w in gen::withdraw()) {
        for art in ARTS {
            let w = w.clone().with_art(art);
            let ir = Circuit::Withdraw.ir(art);
            let outcome = spec::spec_withdraw(&w);
            let r = check_case(Circuit::Withdraw, art, &ir, &outcome, &w.pre_state(), &w.self_addr, &w.ops(), &w.preimage());
            prop_assert!(r.is_ok(), "{art:?}: {r:?}");
        }
    }

    #[test]
    fn swap_matches_spec(s in gen::swap()) {
        for art in ARTS {
            let s = s.clone().with_art(art);
            let ir = Circuit::Swap.ir(art);
            let outcome = spec::spec_swap(&s);
            let r = check_case(Circuit::Swap, art, &ir, &outcome, &s.pre_state(), &s.self_addr, &s.ops(), &s.preimage());
            prop_assert!(r.is_ok(), "{art:?}: {r:?}");
        }
    }

    #[test]
    fn claim_matches_spec(c in gen::claim()) {
        for art in ARTS {
            let c = c.clone().with_art(art);
            let ir = Circuit::Claim.ir(art);
            let outcome = spec::spec_claim(&c);
            let ops = c.ops(u8::from(c.found));
            let pi = c.preimage_with_member(u8::from(c.found));
            let r = check_case(Circuit::Claim, art, &ir, &outcome, &c.pre_state(), &c.d.self_addr, &ops, &pi);
            prop_assert!(r.is_ok(), "{art:?}: {r:?}");
        }
    }

    #[test]
    fn complete_withdraw_matches_spec(c in gen::complete_withdraw()) {
        for art in ARTS {
            let c = c.clone().with_art(art);
            let ir = Circuit::CompleteWithdraw.ir(art);
            let outcome = spec::spec_complete_withdraw(&c);
            let r = check_case(Circuit::CompleteWithdraw, art, &ir, &outcome, &c.pre_state(), &c.w.self_addr, &c.ops(), &c.preimage());
            prop_assert!(r.is_ok(), "{art:?}: {r:?}");
        }
    }

    #[test]
    fn complete_swap_matches_spec(c in gen::complete_swap()) {
        for art in ARTS {
            let c = c.clone().with_art(art);
            let ir = Circuit::CompleteSwap.ir(art);
            let outcome = spec::spec_complete_swap(&c);
            let r = check_case(Circuit::CompleteSwap, art, &ir, &outcome, &c.pre_state(), &c.s.self_addr, &c.ops(), &c.preimage());
            prop_assert!(r.is_ok(), "{art:?}: {r:?}");
        }
    }

    #[test]
    fn refund_matches_spec(r in gen::refund()) {
        for art in ARTS {
            let r = r.clone().with_art(art);
            let ir = Circuit::Refund.ir(art);
            let outcome = spec::spec_refund(&r);
            let self_addr = r.self_addr();
            let res = check_case(Circuit::Refund, art, &ir, &outcome, &r.pre_state(), &self_addr, &r.ops(), &r.preimage());
            prop_assert!(res.is_ok(), "{art:?}: {res:?}");
        }
    }
}
