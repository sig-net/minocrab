//! THE EXECUTOR GATE (M35 rung 1): the transcript the executor derives from
//! ledger state is byte-for-byte the transcript the vault harness's hand
//! model writes.
//!
//! `minocrab_sim::v3::exec` produces a call's public transcript by running
//! the ZKIR walk against a live `StateValue` through Midnight's own Impact
//! VM in `ResultModeGather`. The `erc20_vault_pending` harness produces the
//! same transcript from a 3.8k-line reference model that knows every read's
//! answer by hand. They are completely independent routes to the same
//! bytes, which is what makes this a gate and not a tautology — and the
//! harness is the ORACLE, so any disagreement is the executor's fault until
//! shown otherwise.
//!
//! Per generated case, on the SEVENTEEN circuits of the Pending lineage:
//!
//! 1. **The op stream.** `Executed::ops` equals the model's `ops()` op for
//!    op — including each `popeq`'s expected `AlignedValue`, which the
//!    executor read out of the state and the model wrote down.
//! 2. **Both public halves.** `public_transcript_inputs` and
//!    `public_transcript_outputs` of the produced preimage equal the
//!    model's, and so does the communications commitment.
//! 3. **The reference VM still accepts.** `IrSource::check` on the produced
//!    preimage — the executor did not merely agree with the model, it
//!    produced something upstream will prove.
//! 4. **The post-state.** The executor's `post` is what
//!    `exec::run(pre, ops)` computes, so the state-driving half of M35 D
//!    can chain calls through it.
//! 5. **The negative control.** A case the spec REJECTS is rejected by the
//!    executor too, as `ExecError::Rejected` at an `Assert` — the same
//!    failure the hand model's `Guard` names.

use midnight_transient_crypto::proofs::Zkir;
use minocrab_contracts::erc20_vault_pending as pending;
use minocrab_sim::v3::exec::{self, Call, ExecError};
use minocrab_zkir::v3::IrSource;
use proptest::prelude::*;

mod vault_pending;

use vault_pending::exec as harness;
use vault_pending::gen;
use vault_pending::model::*;
use vault_pending::spec::{self, Outcome};

/// Run one generated case through the executor and check it against the
/// hand model.
fn check_case(
    ir: &IrSource,
    outcome: &Outcome,
    pre: &harness::PreState,
    self_addr: &[u8; 32],
    model_ops: &[vault_pending::prims::VmOp],
    model_pi: &midnight_transient_crypto::proofs::ProofPreimage,
) -> Result<(), String> {
    let ctx = exec::context(pre.state(), *self_addr);
    let mut call = Call::new(&model_pi.inputs, &model_pi.private_transcript)
        .with_key_location(model_pi.key_location.clone());
    call.binding_input = model_pi.binding_input;
    if let Some((_, rand)) = model_pi.communications_commitment {
        call = call.with_comm_rand(rand);
    }

    let produced = exec::execute(ir, &call, &ctx);

    if !outcome.accepts() {
        // --- 5. the negative control ------------------------------------
        return match produced {
            Err(ExecError::Rejected { .. }) => Ok(()),
            // A rejected case may also be one the ledger itself refuses
            // (a counter at u64::MAX has no post-state); the model's own
            // `exec::run` refuses it identically, which is what is checked.
            Err(ExecError::NotApplied { .. }) if harness::run(pre, self_addr, model_ops).is_err() => {
                Ok(())
            }
            Err(e) => Err(format!(
                "the spec rejects ({:?}) but the executor failed differently: {e}",
                outcome.guard()
            )),
            Ok(_) => Err(format!(
                "the spec rejects ({:?}) but the executor accepted",
                outcome.guard()
            )),
        };
    }

    // An accepted case whose transcript the LEDGER will not apply is the
    // `counter_would_overflow` case `erc20_vault_pending_spec.rs` carves
    // out: the circuit is satisfied, the state has no room. The model's own
    // op stream is refused identically.
    if let Err(ExecError::NotApplied { .. }) = produced {
        return match harness::run(pre, self_addr, model_ops) {
            Err(_) => Ok(()),
            Ok(_) => Err("the executor's transcript does not apply but the model's does".into()),
        };
    }
    let produced = produced.map_err(|e| format!("the executor rejected an accepted case: {e}"))?;

    // --- 1. the op stream ------------------------------------------------
    if produced.ops != model_ops {
        let at = produced
            .ops
            .iter()
            .zip(model_ops.iter())
            .position(|(a, b)| a != b);
        return Err(match at {
            Some(i) => format!(
                "op {i} differs: executor {:?}, model {:?}",
                produced.ops[i], model_ops[i]
            ),
            None => format!(
                "op count differs: executor {}, model {}",
                produced.ops.len(),
                model_ops.len()
            ),
        });
    }

    // --- 2. both public halves, and the commitment -----------------------
    if produced.preimage.public_transcript_inputs != model_pi.public_transcript_inputs {
        return Err("public_transcript_inputs differ".into());
    }
    if produced.preimage.public_transcript_outputs != model_pi.public_transcript_outputs {
        return Err("public_transcript_outputs differ".into());
    }
    if produced.preimage.communications_commitment != model_pi.communications_commitment {
        return Err("the communications commitment differs".into());
    }

    // --- 3. the reference VM still accepts -------------------------------
    ir.check(&produced.preimage)
        .map_err(|e| format!("the reference VM rejected the executor's preimage: {e}"))?;

    // --- 4. the post-state -----------------------------------------------
    let by_hand = harness::run(pre, self_addr, model_ops)
        .map_err(|e| format!("the model's own op stream does not run: {e}"))?;
    if produced.post != by_hand.post {
        return Err("the executor's post-state differs from the model's".into());
    }
    Ok(())
}

macro_rules! executor_gate {
    ($name:ident, $ir:expr, $gen:expr, $spec:expr, |$s:ident| $env:expr) => {
        proptest! {
            #![proptest_config(gen::config())]
            #[test]
            fn $name($s in $gen) {
                let outcome = $spec(&$s);
                let env: &Env = $env;
                let ir = $ir;
                let r = check_case(
                    &ir,
                    &outcome,
                    &$s.pre_state(),
                    &env.self_addr,
                    &$s.ops(),
                    &$s.preimage(),
                );
                prop_assert!(r.is_ok(), "{r:?}");
            }
        }
    };
}

executor_gate!(initialize, pending::Vault::initialize().ir, gen::initialize(), spec::spec_initialize, |s| &s.env);
executor_gate!(approve_router, pending::Vault::approve_router().ir, gen::approve_router(), spec::spec_approve_router, |s| &s.env);
executor_gate!(approve_stata, pending::Vault::approve_stata().ir, gen::approve_stata(), spec::spec_approve_stata, |s| &s.env);
executor_gate!(deposit, pending::Vault::deposit().ir, gen::start_deposit(), spec::spec_start_deposit, |s| &s.env);
executor_gate!(claim, pending::Vault::claim().ir, gen::claim(), spec::spec_claim, |s| &s.d.env);
executor_gate!(claim_auto_receive, pending::Vault::claim().ir, gen::claim_auto_receive(), spec::spec_claim, |s| &s.d.env);
executor_gate!(withdraw, pending::Vault::withdraw().ir, gen::start_withdraw(), spec::spec_start_withdraw, |s| &s.env);
executor_gate!(complete_withdraw, pending::Vault::complete_withdraw().ir, gen::complete_withdraw(), spec::spec_complete_withdraw, |s| &s.w.env);
executor_gate!(refund_withdrawal, pending::Vault::refund_withdrawal().ir, gen::refund_withdrawal(), spec::spec_refund_withdrawal, |s| &s.w.env);
executor_gate!(swap, pending::Vault::swap().ir, gen::start_swap(), spec::spec_start_swap, |s| &s.env);
executor_gate!(complete_swap, pending::Vault::complete_swap().ir, gen::complete_swap(), spec::spec_complete_swap, |s| &s.s.env);
executor_gate!(refund_swap, pending::Vault::refund_swap().ir, gen::refund_swap(), spec::spec_refund_swap, |s| &s.s.env);
executor_gate!(supply, pending::Vault::supply().ir, gen::start_supply(), spec::spec_start_supply, |s| &s.env);
executor_gate!(complete_supply, pending::Vault::complete_supply().ir, gen::complete_supply(), spec::spec_complete_supply, |s| &s.s.env);
executor_gate!(refund_supply, pending::Vault::refund_supply().ir, gen::refund_supply(), spec::spec_refund_supply, |s| &s.s.env);
executor_gate!(redeem, pending::Vault::redeem().ir, gen::start_redeem(), spec::spec_start_redeem, |s| &s.env);
executor_gate!(complete_redeem, pending::Vault::complete_redeem().ir, gen::complete_redeem(), spec::spec_complete_redeem, |s| &s.s.env);
executor_gate!(refund_redeem, pending::Vault::refund_redeem().ir, gen::refund_redeem(), spec::spec_refund_redeem, |s| &s.s.env);
