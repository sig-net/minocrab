//! M30 rung B's gates that do not prove: the disk resolver, and
//! build → sign → seal → `well_formed` → `apply` on the M29 D fixtures.
//!
//! `tests/real_proof.rs` is the same pipeline WITH the proof, under
//! `--release` and `#[ignore]`. Everything here runs in the ordinary
//! `cargo test` loop, because everything here is cheap: no keygen, no
//! proving, and the proof-preimage marker's `proof_verify` is a no-op.

use midnight_base_crypto::time::Timestamp;
use midnight_ledger::events::EventDetails;
use midnight_ledger::semantics::TransactionResult;
use midnight_storage::db::InMemoryDB;
use midnight_transient_crypto::curve::Fr;
use midnight_transient_crypto::proofs::{KeyLocation, ProvingKeyMaterial, Resolver, VerifierKey};
use minocrab_contracts::events::MISC_SIZE;
use minocrab_contracts::signet_contract::SIGNATURE_RESPONDED_EVENT;
use minocrab_publisher::call::{ContractKeyLocation, RESPOND, SIGNER_CIRCUITS};
use minocrab_publisher::intent::calls_of;
use minocrab_publisher::publish::{build, seal, sign, FundingKeys};
use minocrab_publisher::{ManagedDir, PublishError};
use rand::rngs::StdRng;
use rand::SeedableRng;

mod support;

use support::{
    chain_context, deploy_singleton, golden_emission, signature_of, singleton_contract_state,
    tx_context, ttl, unbalanced_strictness, COMM_RAND,
};

/// M29 D's fixture: a real, finalized `respond` transaction from the capture
/// chain, reached by path from this crate's tests. Reaching into another
/// crate's fixtures rather than copying them is deliberate — one copy of a
/// captured artifact in the repo, with one README recording its provenance
/// (`crates/minocrab-contracts/tests/fixtures/mpc/README.md`).
const RESPOND_TX_161: &[u8] =
    include_bytes!("../../minocrab-contracts/tests/fixtures/mpc/respond-tx-161.mn");
const RESPOND_TX_161_SHA256: &str =
    "9444aa6304257d0ae278531a3c70ee0baa508c197369024fb14463f987b06745";

/// The COMMITTED managed directory (M29 A): verifier keys and `.zkir`, but
/// deliberately no `.prover` or `.bzkir`.
fn committed_managed() -> ManagedDir {
    ManagedDir::new(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../signet-artifacts/managed"),
    )
}

fn managed_verifier_key(circuit: &str) -> VerifierKey {
    committed_managed().verifier_key(circuit).expect("a committed verifier key")
}

// ---- the managed directory -------------------------------------------------

/// The hashes the crate derives from the committed verifier keys are the ones
/// `expectedVk.json` records — one function, `signet_artifacts::
/// hash_verifier_key`, feeding both the artifact table and a publisher's
/// `Deployment`.
#[test]
fn the_verifier_key_hashes_are_the_committed_expected_vk_table() {
    let managed = committed_managed();
    let json = std::fs::read_to_string(managed.root().join("expectedVk.json"))
        .expect("the committed expectedVk.json");
    for circuit in SIGNER_CIRCUITS {
        let hash = managed.verifier_key_hash(circuit).expect("a committed verifier key");
        assert_eq!(hash.len(), 64);
        assert!(
            json.contains(&format!("\"{circuit}\": \"{hash}\"")),
            "{circuit}: {hash} is not the hash expectedVk.json records"
        );
    }
}

/// The committed directory carries verifier keys and NOTHING ELSE a prover
/// needs, and the resolver says so by resolving nothing — rather than half-
/// resolving a circuit and failing somewhere deeper in the prover.
#[test]
fn the_committed_managed_dir_cannot_prove() {
    let managed = committed_managed();
    for circuit in SIGNER_CIRCUITS {
        assert!(managed.verifier_key_path(circuit).exists(), "{circuit}: no committed .verifier");
        assert!(!managed.prover_key_path(circuit).exists(), "{circuit}: a .prover is committed?");
        assert!(
            managed.key_material(circuit).expect("readable").is_none(),
            "{circuit}: key material resolved without a prover key"
        );
    }
}

/// THE `expectedVk` GATE, in both directions: a singleton deployed under our
/// committed keys passes, and one whose operations carry each OTHER circuit's
/// key is caught — by the hash, not by the name.
///
/// This is the check `sig-net/mpc`'s `prover.ts` makes before it will prove,
/// and notes/mpc-publisher.org §5.2 turns on: it is why a lying RPC endpoint
/// can waste a publisher's time but not make it sign against the wrong
/// deployment.
#[test]
fn the_expected_vk_gate_catches_a_deployment_carrying_other_keys() {
    let address = deploy_singleton(
        singleton_contract_state(|c| Some(managed_verifier_key(c))),
        Timestamp::from_secs(0),
    )
    .1;
    let deployment =
        committed_managed().deployment(address, &SIGNER_CIRCUITS).expect("the expectedVk table");

    deployment
        .check_deployed(&singleton_contract_state(|c| Some(managed_verifier_key(c))))
        .expect("the committed keys are the expected ones");

    // Each circuit's operation carrying the NEXT circuit's key.
    let permuted = |circuit: &str| {
        let i = SIGNER_CIRCUITS.iter().position(|c| *c == circuit).expect("a signer circuit");
        Some(managed_verifier_key(SIGNER_CIRCUITS[(i + 1) % SIGNER_CIRCUITS.len()]))
    };
    let err = deployment
        .check_deployed(&singleton_contract_state(permuted))
        .expect_err("a permuted deployment must be caught");
    assert!(matches!(err, PublishError::VerifierKeyMismatch { .. }), "{err}");

    // And a deployment with no verifier key at all is not "close enough".
    let err = deployment
        .check_deployed(&singleton_contract_state(|_| None))
        .expect_err("an unkeyed deployment must be caught");
    assert!(matches!(err, PublishError::VerifierKeyMismatch { .. }), "{err}");
}

/// The resolver answers to the bare circuit id AND to compact-js's encoded
/// contract key location, so it can stand in for the sidecar's resolver
/// without re-spelling any preimage.
#[test]
fn the_resolver_answers_to_both_spellings_of_a_key_location() {
    let root = std::env::temp_dir().join(format!(
        "minocrab-publisher-keys-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time moves forward")
            .as_nanos()
    ));
    let managed = ManagedDir::new(&root);
    std::fs::create_dir_all(root.join("keys")).expect("mkdir keys");
    std::fs::create_dir_all(root.join("zkir")).expect("mkdir zkir");
    // Not real keys — this test is about which FILES a key location selects,
    // which is a question the prover never gets to ask if the answer is wrong.
    let material = ProvingKeyMaterial {
        prover_key: b"prover".to_vec(),
        verifier_key: b"verifier".to_vec(),
        ir_source: b"ir".to_vec(),
    };
    std::fs::write(managed.prover_key_path(RESPOND), &material.prover_key).expect("write prover");
    std::fs::write(managed.verifier_key_path(RESPOND), &material.verifier_key)
        .expect("write verifier");
    std::fs::write(managed.ir_path(RESPOND), &material.ir_source).expect("write ir");

    let hash = managed.verifier_key_hash(RESPOND).expect("hashable");
    let address = deploy_singleton(
        singleton_contract_state(|c| Some(managed_verifier_key(c))),
        Timestamp::from_secs(0),
    )
    .1;
    let encoded = ContractKeyLocation::new(address, RESPOND, hash)
        .expect("a well-formed key location")
        .encode();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a current-thread runtime");
    let resolve = |raw: &str| {
        runtime
            .block_on(
                managed.resolve_key(KeyLocation(std::borrow::Cow::Owned(raw.to_string()))),
            )
            .expect("readable")
    };
    let bare = resolve(RESPOND).expect("the bare circuit id resolves");
    let full = resolve(&encoded).expect("the encoded key location resolves");
    assert_eq!(bare.prover_key, material.prover_key);
    assert_eq!(bare.verifier_key, material.verifier_key);
    assert_eq!(bare.ir_source, material.ir_source);
    assert_eq!(full.prover_key, bare.prover_key);
    assert!(resolve("transfer").is_none(), "an unknown circuit must not resolve");

    std::fs::remove_dir_all(&root).expect("clean up");
}

// ---- build → sign → seal → well_formed → apply -----------------------------

/// The publisher's steps, on a REAL request id and a REAL signature taken off
/// the capture chain's own respond transaction: the transaction is well
/// formed against a singleton deployed under our verifier keys, it applies,
/// and the 288 bytes the ledger recorded while applying it are the 288 bytes
/// the captured transaction carried.
///
/// The proof is the one thing missing (`tests/real_proof.rs` adds it): under
/// the proof-preimage marker `ProofKind::proof_verify` is a no-op.
#[test]
fn a_respond_publish_applies_and_emits_the_captured_bytes() {
    let tblock = Timestamp::from_secs(0);
    let golden = golden_emission(RESPOND_TX_161, RESPOND_TX_161_SHA256, "respond-tx-161");
    let (request_id, signature) = signature_of(&golden);

    let (ledger, address) =
        deploy_singleton(singleton_contract_state(|c| Some(managed_verifier_key(c))), tblock);
    let managed = committed_managed();
    let deployment = managed.deployment(address, &SIGNER_CIRCUITS).expect("the expectedVk table");
    let call = minocrab_publisher::respond::<InMemoryDB>(&deployment, &request_id, &signature)
        .expect("respond builds");

    let ctx = chain_context(tblock);
    let mut rng = StdRng::seed_from_u64(0x5055_424c_4953_4800);
    let built = build(&ctx, &call, Fr::from(COMM_RAND), ttl(tblock), &mut rng)
        .expect("the singleton's Push+Log program partitions");

    // No unshielded offer and no dust registration, so signing has nothing to
    // sign — asserted rather than skipped, because the step is in the pipeline
    // and M30 C's dust registrations will make it do work.
    let signed = sign(built.clone(), &FundingKeys::default(), &mut rng).expect("signing");
    let sealed = seal(&signed, StdRng::seed_from_u64(0x5345_414c));

    let vtx = sealed
        .well_formed(&ledger, unbalanced_strictness(), tblock)
        .expect("the published transaction is well formed");
    let (_after, result) = ledger.apply(&vtx, &tx_context(&ledger, tblock));
    let events = match &result {
        TransactionResult::Success(events) => events.clone(),
        other => panic!("the published transaction did not apply: {other:?}"),
    };

    let mut emitted = None;
    for event in &events {
        if let EventDetails::ContractLog { address: at, entry_point, logged_item } = &event.content
        {
            assert_eq!(*at, address);
            assert_eq!(entry_point.as_ref(), RESPOND.as_bytes());
            emitted = Some(support::emission_of(logged_item, "ours"));
        }
    }
    let emitted = emitted.expect("applying the call emitted a ContractLog");
    assert_eq!(emitted, golden, "the emitted Misc bytes are not the captured ones");

    // And the envelope the builder produced is the same 288 bytes, so a caller
    // can check them without applying anything.
    let mut expected = [0u8; MISC_SIZE];
    expected[..32].copy_from_slice(&golden.name);
    expected[32..].copy_from_slice(&golden.payload);
    assert_eq!(call.misc, expected);
    assert_eq!(
        &golden.name[..SIGNATURE_RESPONDED_EVENT.len()],
        SIGNATURE_RESPONDED_EVENT.as_bytes()
    );
}

/// The intent carries the TTL it was given, at the segment it was given, with
/// one call whose key location is the circuit id.
#[test]
fn the_intent_carries_the_ttl_the_segment_and_one_call() {
    let tblock = Timestamp::from_secs(1_000);
    let (_ledger, address) =
        deploy_singleton(singleton_contract_state(|c| Some(managed_verifier_key(c))), tblock);
    let deployment =
        committed_managed().deployment(address, &SIGNER_CIRCUITS).expect("the expectedVk table");
    let golden = golden_emission(RESPOND_TX_161, RESPOND_TX_161_SHA256, "respond-tx-161");
    let (request_id, signature) = signature_of(&golden);
    let call = minocrab_publisher::respond::<InMemoryDB>(&deployment, &request_id, &signature)
        .expect("respond builds");

    let ctx = chain_context(tblock);
    let mut rng = StdRng::seed_from_u64(0x5454_4c00);
    let tx = build(&ctx, &call, Fr::from(COMM_RAND), ttl(tblock), &mut rng).expect("built");
    let midnight_ledger::structure::Transaction::Standard(stx) = &tx else {
        panic!("a publish builds a standard transaction");
    };
    let intents: Vec<_> = stx.intents.iter().collect();
    assert_eq!(intents.len(), 1, "one intent");
    let intent = &intents[0];
    assert_eq!(*intent.0, support::SEGMENT);
    assert_eq!(intent.1.ttl, ttl(tblock));
    let calls = calls_of(&intent.1);
    assert_eq!(calls.len(), 1, "one call");
    assert_eq!(calls[0].entry_point.as_ref(), RESPOND.as_bytes());
    assert!(calls[0].fallible_transcript.is_none(), "mpc's reader drops fallible singleton calls");
}

/// A deployment whose table has no entry for a circuit cannot build a call
/// for it — the failure is at build time, with a name, rather than at proving
/// time inside an `anyhow::Error`.
#[test]
fn a_circuit_the_deployment_does_not_declare_cannot_be_called() {
    let (_ledger, address) = deploy_singleton(singleton_contract_state(|c| Some(managed_verifier_key(c))), Timestamp::from_secs(0));
    let deployment = committed_managed().deployment(address, &[RESPOND]).expect("respond only");
    let err = minocrab_publisher::sign_bidirectional::<InMemoryDB>(
        &deployment,
        &[0u8; 32],
        &minocrab_publisher::Notification { version: 1, payload: [0u8; 128] },
    )
    .expect_err("signBidirectional is not in this deployment's table");
    assert!(matches!(err, PublishError::UnknownCircuit(_)), "{err}");
}
