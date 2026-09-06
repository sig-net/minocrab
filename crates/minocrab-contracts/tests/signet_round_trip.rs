//! M35 rung D, THE STATE-DRIVING HALF: request → post → respond, chained on
//! a real `StateValue` through the Impact VM under plain `cargo test`.
//!
//! Rung D built the responder (`crates/signet-sim`) but could not chain it,
//! because nothing produced a circuit's transcript from ledger state. The
//! executor (`minocrab_sim::v3::exec`) does, so this file closes the loop as
//! far as it goes:
//!
//! 1. a request circuit runs against a real pre-state; the executor derives
//!    its transcript FROM that state and the Impact VM applies it;
//! 2. the singleton's notification is built from the slot's OWN declared
//!    path (`Pending::record_path`, the one the artifact-agreement gate pins
//!    against the compiled contract-info);
//! 3. `SigNetSim` — the MPC's own reader, translated — walks the POST state
//!    by that path, finds the record the circuit filed, recomputes its id
//!    from the bytes it decoded, and signs. Nothing is handed to it: every
//!    byte it reads was written by the circuit into a `StateValue`.
//!
//! It also chains the pairs THROUGH state: a request circuit's post-state is
//! the state its settle circuit reads, with nothing carried between them but
//! a `StateValue`. That is what M35 D's `cargo test` speed asks for, and it
//! is the first time a settle in this workspace has read a record it was not
//! handed.
//!
//! The adversarial responders live here too, each hitting the reader's own
//! drop reason by name.
//!
//! WHAT IS NOT HERE, and why: the last link, `respond → settle`, does not
//! close. `the_typed_settle_digest_is_not_the_digest_the_mpc_signs` pins
//! why, in one assertion — it is a protocol disagreement, not a gap in this
//! file. See notes/signet-async.org §10.

use midnight_onchain_state::state::StateValue;
use midnight_transient_crypto::proofs::Zkir;
use minocrab::Fr;
use minocrab_contracts::erc20_vault_pending::{self as pending, RESPONSE_KIND_CLAIM, RESPONSE_KIND_FAILURE};
use minocrab_sim::v3::exec::{self, Call};
use signet_sim::reader::MISC_PAYLOAD_LEN;
use signet_sim::{EvmOutcome, Refusal, Responder, SigNetSim};

mod vault_pending;
use vault_pending::model::*;
use vault_pending::prims::{b32_slots, transient_upgrade};

/// The singleton's `Misc` payload for a request: `version(1) ‖
/// requestId(32) ‖ callerAddress(32) ‖ pathDepth(1) ‖ path(4) ‖ zeros`.
///
/// Built from the SLOT's declared path, not from a constant — the same
/// bytes `Pending::request` derives, so a layout change moves both.
fn notification(request_id: &[u8; 32], caller: &[u8; 32], path: &[u8]) -> [u8; MISC_PAYLOAD_LEN] {
    let mut out = [0u8; MISC_PAYLOAD_LEN];
    out[0] = 1;
    out[1..33].copy_from_slice(request_id);
    out[33..65].copy_from_slice(caller);
    out[65] = path.len() as u8;
    out[66..66 + path.len()].copy_from_slice(path);
    out
}

/// Run a request circuit against `pre` and return the state it leaves.
fn post_state_of(
    ir: &minocrab_zkir::v3::IrSource,
    scenario_inputs: &[Fr],
    scenario_witnesses: &[Fr],
    comm_rand: Fr,
    pre: &vault_pending::exec::PreState,
    self_addr: &[u8; 32],
) -> StateValue<midnight_storage::db::InMemoryDB> {
    let ctx = exec::context(pre.state(), *self_addr);
    let call = Call::new(scenario_inputs, scenario_witnesses).with_comm_rand(comm_rand);
    let run = exec::execute(ir, &call, &ctx).expect("the request circuit runs against the state");
    run.post
}

/// A deposit filed by the circuit, and the state it left behind.
fn filed_deposit() -> (StartDepositScenario, StateValue<midnight_storage::db::InMemoryDB>) {
    let s = StartDepositScenario::new();
    let pi = s.preimage();
    let comm_rand = pi.communications_commitment.expect("a request commits").1;
    let post = post_state_of(
        &pending::Vault::deposit().ir,
        &pi.inputs,
        &pi.private_transcript,
        comm_rand,
        &s.pre_state(),
        &s.env.self_addr,
    );
    (s, post)
}

fn deposits_path() -> Vec<u8> {
    pending::VAULT.deposits.record_path().as_slice().to_vec()
}

// ---- the chain -------------------------------------------------------------

/// THE ROUND TRIP, as far as it goes: the record the MPC signs over was
/// written into the ledger by the circuit, found by the MPC's own path walk,
/// and its id recomputed from the bytes as filed.
#[test]
fn the_mpc_resolves_the_record_the_request_circuit_filed() {
    let (s, post) = filed_deposit();
    let rid = s.request_id();
    let mut sim = SigNetSim::from_seed(b"minocrab round trip", RESPONSE_KIND_FAILURE as u8);
    let payload = notification(&rid, &s.env.self_addr, &deposits_path());

    let attestation = sim
        .respond(&payload, &post, EvmOutcome::Executed { body: vec![1u8] })
        .expect("the MPC resolves the filed record");

    assert_eq!(attestation.request_id, rid, "the id the MPC signs is the filed one");
    assert_eq!(
        attestation.output,
        vec![RESPONSE_KIND_CLAIM as u8, 1u8],
        "the output is the record's own response kind then the EVM body"
    );
    // The record the reader decoded is the one the circuit's arguments
    // describe — the drift gate of signet_flow.rs, now driven by STATE
    // rather than by a hand-built cell.
    assert_eq!(attestation.record.request_nonce, s.env.request_nonce);
    assert_eq!(attestation.record.caip2_id, s.env.caip2);
    assert_eq!(attestation.record.response_kind, RESPONSE_KIND_CLAIM as u8);
}

/// A failed destination-chain call: the MPC's failure output, built exactly
/// as `node/respond_bidirectional.rs` builds it — one kind byte.
#[test]
fn a_never_executed_call_attests_the_failure_kind() {
    let (s, post) = filed_deposit();
    let mut sim = SigNetSim::from_seed(b"minocrab round trip", RESPONSE_KIND_FAILURE as u8);
    let payload = notification(&s.request_id(), &s.env.self_addr, &deposits_path());
    let attestation = sim
        .respond(&payload, &post, EvmOutcome::NeverExecuted)
        .expect("a failure is still an attestation");
    assert_eq!(attestation.output, vec![RESPONSE_KIND_FAILURE as u8]);
}

// ---- the adversarial responders --------------------------------------------

/// An id that was never filed: the reader drops it, and no signature exists
/// for it at all. This is the "unfiled id" responder — it cannot even reach
/// the settle circuit.
#[test]
fn an_unfiled_id_is_refused_by_the_reader() {
    let (s, post) = filed_deposit();
    let mut sim = SigNetSim::from_seed(b"minocrab round trip", RESPONSE_KIND_FAILURE as u8);
    let payload = notification(&[0xabu8; 32], &s.env.self_addr, &deposits_path());
    assert!(matches!(
        sim.respond(&payload, &post, EvmOutcome::Executed { body: vec![1] }),
        Err(Refusal::Absent)
    ));
}

/// The notification points at the ENV map rather than the record map: the
/// walk lands on a map whose values are not records.
#[test]
fn a_wrong_path_is_refused_by_the_reader() {
    let (s, post) = filed_deposit();
    let mut sim = SigNetSim::from_seed(b"minocrab round trip", RESPONSE_KIND_FAILURE as u8);
    let mut path = deposits_path();
    *path.last_mut().expect("a non-empty path") += 1;
    let payload = notification(&s.request_id(), &s.env.self_addr, &path);
    assert!(
        sim.respond(&payload, &post, EvmOutcome::Executed { body: vec![1] })
            .is_err(),
        "the neighbouring field is not the request index"
    );
}

/// A depth outside 1..=4, and an unsupported version: the reader fails
/// closed on the notification before it touches state.
#[test]
fn a_malformed_notification_is_refused_by_the_reader() {
    let (s, post) = filed_deposit();
    let mut sim = SigNetSim::from_seed(b"minocrab round trip", RESPONSE_KIND_FAILURE as u8);

    let mut bad_depth = notification(&s.request_id(), &s.env.self_addr, &deposits_path());
    bad_depth[65] = 9;
    assert!(matches!(
        sim.respond(&bad_depth, &post, EvmOutcome::Executed { body: vec![1] }),
        Err(Refusal::Notification(_))
    ));

    let mut bad_version = notification(&s.request_id(), &s.env.self_addr, &deposits_path());
    bad_version[0] = 2;
    assert!(matches!(
        sim.respond(&bad_version, &post, EvmOutcome::Executed { body: vec![1] }),
        Err(Refusal::Notification(_))
    ));
}

/// A responder with a DIFFERENT root: it resolves the record and signs, but
/// under a key the vault's `mpcResponseKey` is not. The two attestations
/// differ in the signature and in nothing else, which is the property the
/// settle circuit's verification rests on.
#[test]
fn a_wrong_key_attests_the_same_bytes_under_a_different_signature() {
    let (s, post) = filed_deposit();
    let payload = notification(&s.request_id(), &s.env.self_addr, &deposits_path());
    let outcome = EvmOutcome::Executed { body: vec![1u8] };

    let mut honest = SigNetSim::from_seed(b"minocrab round trip", RESPONSE_KIND_FAILURE as u8);
    let mut rogue = SigNetSim::from_seed(b"a different cluster", RESPONSE_KIND_FAILURE as u8);
    let a = honest.respond(&payload, &post, outcome.clone()).expect("honest");
    let b = rogue.respond(&payload, &post, outcome).expect("rogue");

    assert_eq!(a.request_id, b.request_id);
    assert_eq!(a.output, b.output);
    assert_ne!(a.signature, b.signature, "a different root signs differently");
    assert_ne!(
        honest.response_key(u32::from(a.record.key_version), &s.env.self_addr),
        rogue.response_key(u32::from(b.record.key_version), &s.env.self_addr),
        "and the key the vault stored is not the rogue's"
    );
}

/// Replay and double response are the same thing at this boundary: the
/// responder is PURE, so the second call returns the identical attestation.
/// Nothing in the MPC stops a replay — the settle circuit's `remove` does,
/// which is why `consume` is not idempotent.
#[test]
fn a_replay_produces_the_identical_attestation() {
    let (s, post) = filed_deposit();
    let mut sim = SigNetSim::from_seed(b"minocrab round trip", RESPONSE_KIND_FAILURE as u8);
    let payload = notification(&s.request_id(), &s.env.self_addr, &deposits_path());
    let once = sim
        .respond(&payload, &post, EvmOutcome::Executed { body: vec![1] })
        .expect("first");
    let twice = sim
        .respond(&payload, &post, EvmOutcome::Executed { body: vec![1] })
        .expect("second");
    assert_eq!(once, twice, "the responder is a function of its inputs");
}

// ---- the link that does not close -------------------------------------------

/// THE FINDING (2026-09-06, for dmd): the digest a typed `Pending` settle
/// verifies is NOT the digest the MPC signs, since the protocol moved to
/// Poseidon.
///
/// `signet::calculate_attestation_digest_borsh` — what `Pending::settle`
/// uses — hashes `[requestId.hi, requestId.lo]` then ONE FIELD ELEMENT PER
/// BORSH LEAF: the kind byte is one limb, the payload another. The MPC's
/// `compact-hashing::compute_response_hash` (translated verbatim in
/// `signet_sim::hashing`, pinned by the MPC's own golden vectors) hashes
/// `[requestId.hi, requestId.lo]` then the serialized output as a BYTE
/// STRING in FAB's 31-byte packing — for the vault's two-byte output, ONE
/// limb carrying both bytes.
///
/// Under the OLD construction the two agreed: keccak/persistentHash hash the
/// BINARY representation, where "one leaf per field" and "one packed byte
/// string" are the same bytes — which is what notes/borsh-format.org §1
/// established ("the attestation digest (= borsh of {[u8;32], [u8;N]})").
/// Poseidon does not hash bytes; it hashes limbs, and the two limb splits
/// differ. The non-typed `calculate_attestation_digest::<_, LEN_OUTPUT>`
/// still agrees, because it takes the output as a single `BytesN` value.
///
/// This test asserts the disagreement rather than papering over it, so the
/// day the digest is fixed it fails and says so.
#[test]
fn the_typed_settle_digest_is_not_the_digest_the_mpc_signs() {
    let rid = [0x5au8; 32];
    let kind = RESPONSE_KIND_CLAIM as u8;
    let success = 1u8;

    // What the circuit verifies (the model mirrors it; the spec harness
    // holds the two together).
    let per_leaf = attestation_digest_v2(&rid, kind, &[Fr::from(u64::from(success))]);
    // What the MPC signs.
    let mpc = signet_sim::hashing::compute_response_hash(&rid, &[kind, success]);
    // …and the rule that produces it: the two bytes as ONE packed limb.
    let (hi, lo) = b32_slots(&rid);
    let packed = transient_upgrade(&[
        hi,
        lo,
        Fr::from(u64::from(kind) + (u64::from(success) << 8)),
    ]);

    assert_eq!(packed, mpc, "the MPC's rule is FAB's 31-byte packing of the output");
    assert_ne!(
        per_leaf, mpc,
        "if this now holds, the typed digest has been reconciled with the MPC — \
         re-read notes/signet-async.org §10 and close the round trip"
    );
}

// ---- the pairs, chained through state ---------------------------------------

/// Run `request_ir` against `pre`, then `settle_ir` against the state that
/// left behind, and check the settle's transcript against the model's.
///
/// Nothing crosses between the halves but a `StateValue`: the settle's
/// reads — the record, the environment, the response key — are answered out
/// of what the request wrote, not out of a scenario the test built.
fn chain(
    request_ir: &minocrab_zkir::v3::IrSource,
    request_pi: &midnight_transient_crypto::proofs::ProofPreimage,
    request_pre: &vault_pending::exec::PreState,
    settle_ir: &minocrab_zkir::v3::IrSource,
    settle_pi: &midnight_transient_crypto::proofs::ProofPreimage,
    settle_ops: &[vault_pending::prims::VmOp],
    self_addr: &[u8; 32],
) {
    let post = post_state_of(
        request_ir,
        &request_pi.inputs,
        &request_pi.private_transcript,
        request_pi
            .communications_commitment
            .expect("a request commits")
            .1,
        request_pre,
        self_addr,
    );

    let ctx = exec::context(post, *self_addr);
    let mut call = Call::new(&settle_pi.inputs, &settle_pi.private_transcript);
    if let Some((_, rand)) = settle_pi.communications_commitment {
        call = call.with_comm_rand(rand);
    }
    let settled = exec::execute(settle_ir, &call, &ctx)
        .expect("the settle circuit accepts the state its request left");

    assert_eq!(
        settled.ops, settle_ops,
        "the settle's transcript against the REQUEST's post-state is the model's"
    );
    assert_eq!(
        settled.preimage.public_transcript_outputs, settle_pi.public_transcript_outputs,
        "and every value it read came out of that state"
    );
    settle_ir
        .check(&settled.preimage)
        .expect("the reference VM accepts the chained settle");
}

#[test]
fn deposit_then_claim_chains_through_state() {
    let c = ClaimScenario::new();
    chain(
        &pending::Vault::deposit().ir,
        &c.d.preimage(),
        &c.d.pre_state(),
        &pending::Vault::claim().ir,
        &c.preimage(),
        &c.ops(),
        &c.d.env.self_addr,
    );
}

#[test]
fn withdraw_then_complete_chains_through_state() {
    let c = CompleteWithdrawScenario::new();
    chain(
        &pending::Vault::withdraw().ir,
        &c.w.preimage(),
        &c.w.pre_state(),
        &pending::Vault::complete_withdraw().ir,
        &c.preimage(),
        &c.ops(),
        &c.w.env.self_addr,
    );
}

#[test]
fn swap_then_complete_chains_through_state() {
    let c = CompleteSwapScenario::new();
    chain(
        &pending::Vault::swap().ir,
        &c.s.preimage(),
        &c.s.pre_state(),
        &pending::Vault::complete_swap().ir,
        &c.preimage(),
        &c.ops(),
        &c.s.env.self_addr,
    );
}

#[test]
fn supply_then_complete_chains_through_state() {
    let c = CompleteSupplyScenario::new();
    chain(
        &pending::Vault::supply().ir,
        &c.s.preimage(),
        &c.s.pre_state(),
        &pending::Vault::complete_supply().ir,
        &c.preimage(),
        &c.ops(),
        &c.s.env.self_addr,
    );
}

#[test]
fn redeem_then_complete_chains_through_state() {
    let c = CompleteRedeemScenario::new();
    chain(
        &pending::Vault::redeem().ir,
        &c.s.preimage(),
        &c.s.pre_state(),
        &pending::Vault::complete_redeem().ir,
        &c.preimage(),
        &c.ops(),
        &c.s.env.self_addr,
    );
}

/// The refund half of the same pair: an attested failure consumes the very
/// record the withdrawal filed, out of the same post-state.
#[test]
fn withdraw_then_refund_chains_through_state() {
    let c = RefundWithdrawalScenario::new();
    chain(
        &pending::Vault::withdraw().ir,
        &c.w.preimage(),
        &c.w.pre_state(),
        &pending::Vault::refund_withdrawal().ir,
        &c.preimage(),
        &c.ops(),
        &c.w.env.self_addr,
    );
}
