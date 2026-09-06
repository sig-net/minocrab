//! M30 rung B's exit gate: a respond intent goes build → prove → sign → seal
//! → `well_formed` WITH PROOFS VERIFIED, in one process, with no network once
//! the KZG parameters are on disk.
//!
//! `#[ignore]`d and meant for `--release`, like M29 E's:
//!
//! ```console
//! cargo test --release -p minocrab-publisher --test real_proof -- --ignored --nocapture
//! ```
//!
//! What this adds to M29 E (`minocrab-contracts`' `tests/signet_real_proof.rs`,
//! which proves all three circuits with a provider defined inside the test):
//! the proof here goes through the PUBLISHER — `minocrab_publisher::publish`,
//! `InProcessProver`, and a `ManagedDir` resolver reading key files off disk —
//! so what is exercised is the library mpc will link, not a test's own
//! transcription of it. And the values are the capture chain's own: the
//! request id and signature come out of M29 D's `respond-tx-161.mn`.
//!
//! The keys are written to a temp managed directory by keygen at the top of
//! the test, because this repo commits the `.verifier` but not the 56 MB
//! `.prover` or the `.bzkir` (M29 A). The verifier key that comes out is
//! asserted byte-identical to the committed one, so the directory the
//! resolver reads is the artifact M29 A ships and not a look-alike.
//!
//! # What it does NOT prove
//!
//! No fee is paid: `enforce_balancing` and `enforce_limits` are off, and the
//! dust seam is [`NoDust`]. Nothing is submitted. And the deployed key is
//! ours by construction.

use std::time::Instant;

use midnight_base_crypto::data_provider::MidnightDataProvider;
use midnight_base_crypto::time::Timestamp;
use midnight_coin_structure::contract::ContractAddress;
use midnight_ledger::semantics::TransactionResult;
use midnight_ledger::verify::ProofVerificationMode;
use midnight_storage::db::InMemoryDB;
use midnight_transient_crypto::curve::Fr;
use midnight_transient_crypto::proofs::{VerifierKey, Zkir};
use minocrab_contracts::signet_contract::SignetContract;
use minocrab_publisher::call::{RESPOND, SIGNER_CIRCUITS};
use minocrab_publisher::prove::{params_provider, warm_params, InProcessProver, SignerResolver};
use minocrab_publisher::publish::{publish, ChainContext, FundingKeys};
use minocrab_publisher::{EcdsaSignature, ManagedDir, NoDust, SealedTx};
use rand::rngs::StdRng;
use rand::SeedableRng;

mod support;

use support::{
    chain_context, deploy_singleton, golden_emission, signature_of, singleton_contract_state,
    tx_context, ttl, unbalanced_strictness, COMM_RAND,
};

const RESPOND_TX_161: &[u8] =
    include_bytes!("../../minocrab-contracts/tests/fixtures/mpc/respond-tx-161.mn");
const RESPOND_TX_161_SHA256: &str =
    "9444aa6304257d0ae278531a3c70ee0baa508c197369024fb14463f987b06745";

fn committed_managed() -> ManagedDir {
    ManagedDir::new(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../signet-artifacts/managed"),
    )
}

fn managed_verifier_key(circuit: &str) -> VerifierKey {
    committed_managed().verifier_key(circuit).expect("a committed verifier key")
}

/// Each circuit's operation carrying the NEXT circuit's verifier key — the
/// negative control's deployment.
fn permuted_key(circuit: &str) -> VerifierKey {
    let i = SIGNER_CIRCUITS.iter().position(|c| *c == circuit).expect("a signer circuit");
    managed_verifier_key(SIGNER_CIRCUITS[(i + 1) % SIGNER_CIRCUITS.len()])
}

/// Peak RSS of this process, in bytes — `getrusage(RUSAGE_SELF)`, the same
/// measurement `crates/minocrab-bench` and M29 E report. Process-wide and
/// MONOTONIC.
fn peak_rss_bytes() -> u64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    assert_eq!(rc, 0, "getrusage failed");
    let raw = ru.ru_maxrss as u64;
    // macOS reports bytes, Linux kilobytes.
    if cfg!(target_os = "macos") { raw } else { raw * 1024 }
}

/// One publish, end to end, against the singleton at `address` — the whole
/// point of the crate, in eight arguments because every one of them is an
/// input the chain or the operator supplies rather than something the
/// publisher invents.
#[allow(clippy::too_many_arguments)]
async fn publish_respond(
    ctx: &ChainContext<InMemoryDB>,
    managed: &ManagedDir,
    resolver: &SignerResolver,
    params: &MidnightDataProvider,
    address: ContractAddress,
    request_id: &[u8; 32],
    signature: &EcdsaSignature,
    ttl: Timestamp,
) -> SealedTx<InMemoryDB> {
    let deployment =
        managed.deployment(address, &[RESPOND]).expect("the expectedVk table for respond");
    let call = minocrab_publisher::respond::<InMemoryDB>(&deployment, request_id, signature)
        .expect("respond builds");
    let prover = InProcessProver {
        rng: StdRng::seed_from_u64(0x5052_4f56_45),
        resolver,
        params,
    };
    publish(
        ctx,
        &call,
        Fr::from(COMM_RAND),
        ttl,
        prover,
        &mut NoDust,
        &FundingKeys::default(),
        StdRng::seed_from_u64(0x5055_424c_4953_4800),
    )
    .await
    .expect("the publish succeeds")
}

#[test]
#[ignore = "real proving: run under --release, and it needs the KZG params on disk"]
fn a_respond_intent_publishes_and_verifies() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a tokio runtime");
    runtime.block_on(async {
        let baseline_rss = peak_rss_bytes();
        println!("baseline peak RSS: {:.1} MB", baseline_rss as f64 / 1e6);
        let params = params_provider().expect("the KZG parameter provider");
        let tblock = Timestamp::from_secs(0);

        // 1. Keygen from OUR IR into a temp managed directory, laid out the
        // way the sidecar's package lays it out.
        let root = std::env::temp_dir().join(format!(
            "minocrab-publisher-proof-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time moves forward")
                .as_nanos()
        ));
        let managed = ManagedDir::new(&root);
        std::fs::create_dir_all(root.join("keys")).expect("mkdir keys");
        std::fs::create_dir_all(root.join("zkir")).expect("mkdir zkir");

        let ir = SignetContract::respond().ir;
        let model = ir.model();
        let k = model.k();
        warm_params(&params, k).await.expect("KZG params for this k");
        let t = Instant::now();
        let (pk, vk) = ir.keygen(&params).await.expect("keygen");
        let keygen_s = t.elapsed().as_secs_f64();

        let ser = |value: &dyn Fn(&mut Vec<u8>)| {
            let mut buf = Vec::new();
            value(&mut buf);
            buf
        };
        let vk_bytes = ser(&|buf: &mut Vec<u8>| {
            midnight_serialize::tagged_serialize(&vk, buf).expect("vk serializes")
        });
        let pk_bytes = ser(&|buf: &mut Vec<u8>| {
            midnight_serialize::tagged_serialize(&pk, buf).expect("pk serializes")
        });
        let ir_bytes = ser(&|buf: &mut Vec<u8>| {
            midnight_serialize::tagged_serialize(&ir, buf).expect("ir serializes")
        });
        // 2. The key this gate proves under is the COMMITTED artifact.
        assert_eq!(
            vk_bytes,
            committed_managed().verifier_key_bytes(RESPOND).expect("the committed verifier key"),
            "keygen from our IR did not reproduce the COMMITTED managed verifier key"
        );
        std::fs::write(managed.prover_key_path(RESPOND), &pk_bytes).expect("write prover");
        std::fs::write(managed.verifier_key_path(RESPOND), &vk_bytes).expect("write verifier");
        std::fs::write(managed.ir_path(RESPOND), &ir_bytes).expect("write ir");
        // `ManagedDir::deployment` reads `expectedVk.json` (M30 C2); this
        // directory is built fresh by keygen above rather than by
        // `signet-artifacts::generate`, so nothing has written one yet. The
        // hash matches the key just written by construction — step 2 already
        // asserted `vk_bytes` IS the committed verifier key.
        std::fs::write(
            managed.expected_vk_path(),
            format!("{{\"{RESPOND}\": \"{}\"}}", signet_protocol::hash_verifier_key(&vk_bytes)),
        )
        .expect("write expectedVk.json");
        println!(
            "respond: k={k}, rows={}, keygen {keygen_s:.3} s, prover key {:.1} MB",
            model.rows(),
            pk_bytes.len() as f64 / 1e6
        );

        // 3. Deploy the singleton under the committed keys, and a permuted-key
        // twin for the negative control.
        let (ledger, address) =
            deploy_singleton(singleton_contract_state(|c| Some(managed_verifier_key(c))), tblock);
        let (wrong_ledger, wrong_address) =
            deploy_singleton(singleton_contract_state(|c| Some(permuted_key(c))), tblock);

        // 4. The call: the capture chain's own request id and signature.
        let golden = golden_emission(RESPOND_TX_161, RESPOND_TX_161_SHA256, "respond-tx-161");
        let (request_id, signature) = signature_of(&golden);
        let ctx = chain_context(tblock);
        let resolver = SignerResolver::new(managed.clone());

        let mut strict = unbalanced_strictness();
        strict.verify_contract_proofs = true;
        strict.proof_verification_mode = ProofVerificationMode::Real;

        // 5. build → prove → (no dust) → sign → seal.
        let t = Instant::now();
        let sealed = publish_respond(
            &ctx,
            &managed,
            &resolver,
            &params,
            address,
            &request_id,
            &signature,
            ttl(tblock),
        )
        .await;
        let publish_s = t.elapsed().as_secs_f64();

        // 6. well_formed with proofs VERIFIED against the deployed key, then
        // apply.
        let t = Instant::now();
        let vtx = sealed
            .well_formed(&ledger, strict, tblock)
            .expect("the published transaction is rejected");
        let verify_s = t.elapsed().as_secs_f64();
        let (_after, result) = ledger.apply(&vtx, &tx_context(&ledger, tblock));
        assert!(
            matches!(result, TransactionResult::Success(_)),
            "the published transaction did not apply: {result:?}"
        );

        let rss = peak_rss_bytes();
        println!(
            "respond: publish (build+prove+sign+seal) {publish_s:.3} s, \
             well_formed(verify) {verify_s:.3} s, peak RSS {:.1} MB (+{:.1} MB over baseline)",
            rss as f64 / 1e6,
            rss.saturating_sub(baseline_rss) as f64 / 1e6
        );

        // 7. The negative control: the same publish, offered to a singleton
        // whose respond operation carries ANOTHER circuit's verifier key.
        // Without this, step 6 passing would be consistent with nothing being
        // verified at all.
        let wrong = publish_respond(
            &ctx,
            &managed,
            &resolver,
            &params,
            wrong_address,
            &request_id,
            &signature,
            ttl(tblock),
        )
        .await;
        assert!(
            wrong.well_formed(&wrong_ledger, strict, tblock).is_err(),
            "a proof was accepted against another circuit's verifier key — \
             verification is not actually happening"
        );
        println!("respond: the permuted-key deployment rejects, as it must");
        println!("run peak RSS: {:.1} MB", peak_rss_bytes() as f64 / 1e6);

        std::fs::remove_dir_all(&root).expect("clean up");
    });
}
