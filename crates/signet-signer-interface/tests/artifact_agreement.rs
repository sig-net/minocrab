//! This crate's claim, checked.
//!
//! `src/lib.rs` asserts that a contract deployed from
//! `signet-midnight-integration`'s `signet-signer` package exports one
//! circuit, `signBidirectional`, with exactly this argument layout (the
//! respond circuits moved to the responder at v0.26, and its interface is
//! `signet-responder-interface`). Everything needed to
//! settle that assertion is committed beside it — `artifact/`'s
//! `contract-info.json` (the callee's own typed schema, as compactc wrote
//! it) and `pin.json` (the distilled, hash-pinned facts of the compiled
//! `.zkir`s) — so drift is a test failure here rather than a surprise at
//! somebody's call site.
//!
//! Four positive tests and a mutation suite:
//!
//! - the committed `pin.json` IS the distillation of the source artifact
//!   (so re-pinning is a diff, never a hand edit);
//! - the committed digests match the bytes;
//! - every declared circuit passes all six checks, including the compiled
//!   `.zkir`'s constraint prefix slot for slot;
//! - the published ABI equals its frozen snapshot;
//! - and [`mutation`] proves the checker bites: nine ways to be wrong,
//!   nine failures.

use std::path::PathBuf;

use minocrab::Public;
use minocrab_abi::{circuit_schema, Artifact, Pin};
use signet_signer_interface::{RequestId, SignBidirectionalEventNotification, SignetSigner};

/// Where the artifact came from, relative to the workspace root. The same
/// string `pin.json` carries.
const SOURCE: &str = "corpus/zkir/signet-midnight-integration-v026/packages/signet-signer/src/signet-signer";

/// A circuit of the same deployment's other contract, the responder, for
/// the swapped-circuit mutation: the signer exports only one circuit.
const RESPONDER_RESPOND_ZKIR: &str =
    "corpus/zkir/signet-midnight-integration-v026/packages/signet-responder/src/signet-responder/zkir/respond.zkir";

/// The circuit's argument list, as the interface declares it.
type SignBidirectional = (RequestId<Public>, SignBidirectionalEventNotification<Public>);

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_root() -> PathBuf {
    crate_dir().join("../..").canonicalize().expect("workspace root")
}

fn artifact() -> Artifact {
    Artifact::open(crate_dir()).expect("the pinned artifact opens")
}

/// The frozen published ABI, rendered from the types alone.
fn schema() -> String {
    let mut out = String::from(
        "# The published ABI of `signet-signer-interface`, derived from the\n\
         # declarations in src/lib.rs. A DIFF HERE IS A SEMVER DECISION:\n\
         # every line below feeds the communications commitment the ledger\n\
         # matches, so any change breaks deployed callers (major).\n\
         # Regenerate: cargo test -p signet-signer-interface -- --ignored\n\n",
    );
    out.push_str(&circuit_schema::<SignBidirectional, ()>(SignetSigner::SIGN_BIDIRECTIONAL));
    out
}

/// The committed pin is the distillation of the source artifact, not a
/// hand-maintained file: re-pinning is `--ignored` plus a diff.
#[test]
fn the_committed_pin_is_the_artifacts_distillation() {
    let distilled = Pin::distill(&workspace_root().join(SOURCE), SOURCE).expect("distills");
    let committed = Pin::parse(
        &std::fs::read_to_string(crate_dir().join("artifact/pin.json")).expect("pin.json reads"),
    )
    .expect("pin.json parses");
    assert_eq!(
        committed, distilled,
        "artifact/pin.json is not the distillation of {SOURCE}"
    );
}

/// The committed `contract-info.json` and every reachable `.zkir` hash to
/// what the pin says.
#[test]
fn the_pinned_digests_match_the_bytes() {
    let artifact = artifact();
    assert!(artifact.zkir_dir.is_some(), "the .zkir tree should be reachable in-workspace");
    if let Err(problems) = artifact.verify_pin() {
        panic!("the pin does not match its artifact:\n{problems}");
    }
}

/// The six checks, per circuit. This is the test an interface crate exists
/// to have.
#[test]
fn every_declared_circuit_matches_the_artifact() {
    let artifact = artifact();
    artifact.assert_interface_matches::<SignBidirectional, ()>(SignetSigner::SIGN_BIDIRECTIONAL);
}

/// The published ABI, frozen. Its diff is the semver decision.
#[test]
fn the_published_abi_is_frozen() {
    let committed = std::fs::read_to_string(crate_dir().join("artifact/interface-schema.txt"))
        .expect("interface-schema.txt reads");
    assert_eq!(
        schema(),
        committed,
        "the published ABI moved — see notes/interface-crates.org §Versioning and publishing"
    );
}

/// Rewrite `artifact/pin.json` and `artifact/interface-schema.txt`.
/// `cargo test -p signet-signer-interface -- --ignored`.
#[test]
#[ignore]
fn regenerate_pin_and_schema() {
    let pin = Pin::distill(&workspace_root().join(SOURCE), SOURCE).expect("distills");
    std::fs::write(crate_dir().join("artifact/pin.json"), pin.to_json()).expect("pin.json writes");
    std::fs::write(crate_dir().join("artifact/interface-schema.txt"), schema())
        .expect("interface-schema.txt writes");
}

/// The checker has to bite, or the four tests above are decoration.
///
/// Each case takes the real artifact, breaks one thing, and asserts the
/// check fails with a message naming it. The last two are the interesting
/// ones: they forge `pin.json` to agree with the damage, and the compiled
/// `.zkir` catches them anyway — which is why check 6 reads the instruction
/// stream rather than trusting the distillation.
mod mutation {
    use super::*;
    use minocrab_abi::info::{CompactType, ContractInfo};

    /// The real artifact's parts, ready to be damaged.
    fn parts() -> (ContractInfo, Pin, Option<PathBuf>) {
        let real = artifact();
        (real.info.clone(), real.pin.clone(), real.zkir_dir.clone())
    }

    fn rebuilt(info: ContractInfo, pin: Pin, zkir: Option<PathBuf>) -> Artifact {
        Artifact::from_parts(info, pin, zkir)
    }

    /// The unmutated parts pass, so every failure below is the mutation's.
    #[test]
    fn the_control_passes() {
        let (info, pin, zkir) = parts();
        rebuilt(info, pin, zkir)
            .check::<SignBidirectional, ()>(SignetSigner::SIGN_BIDIRECTIONAL)
            .expect("the unmutated artifact matches");
    }

    fn expect_failure(artifact: &Artifact, wanted: &str) {
        let problems = artifact
            .check::<SignBidirectional, ()>(SignetSigner::SIGN_BIDIRECTIONAL)
            .expect_err("the mutation must be caught");
        assert!(
            problems.0.iter().any(|p| p.contains(wanted)),
            "expected a problem mentioning {wanted:?}, got:\n{problems}"
        );
    }

    /// The callee renamed the circuit.
    #[test]
    fn a_renamed_circuit_is_caught() {
        let (mut info, pin, zkir) = parts();
        info.circuits[0].name = "signBidirectionalV2".into();
        expect_failure(&rebuilt(info, pin, zkir), "exports no circuit");
    }

    /// The callee is not proved — the `Signet` module's actual situation.
    #[test]
    fn a_proofless_circuit_is_caught() {
        let (mut info, pin, zkir) = parts();
        info.circuits[0].proof = false;
        expect_failure(&rebuilt(info, pin, zkir), "proof: false");
    }

    /// The callee reordered its arguments. Same slots, same widths, a
    /// different commitment — the change the semver rule calls major.
    #[test]
    fn a_reordered_argument_list_is_caught() {
        let (mut info, pin, zkir) = parts();
        info.circuits[0].arguments.swap(0, 1);
        expect_failure(&rebuilt(info, pin, zkir), "argument slots");
    }

    /// The callee widened a field.
    #[test]
    fn a_retyped_field_is_caught() {
        let (mut info, pin, zkir) = parts();
        set_payload_length(&mut info, 96);
        expect_failure(&rebuilt(info, pin, zkir), "argument");
    }

    /// The callee started returning something.
    #[test]
    fn a_new_result_is_caught() {
        let (mut info, pin, zkir) = parts();
        info.circuits[0].result_type = CompactType::Bytes { length: 32 };
        expect_failure(&rebuilt(info, pin, zkir), "result slots");
    }

    /// A callee that compiles no communications commitment cannot be
    /// called at all.
    #[test]
    fn a_missing_communications_commitment_is_caught() {
        let (info, mut pin, _) = parts();
        pin.circuits.get_mut("signBidirectional").unwrap().do_communications_commitment = false;
        // Without the `.zkir` to contradict it, the distilled fact is all
        // there is — and it is enough.
        expect_failure(&rebuilt(info, pin, None), "communications commitment");
    }

    /// A pin that disagrees with the interface about the constraint run.
    #[test]
    fn a_drifted_constraint_prefix_is_caught() {
        let (info, mut pin, zkir) = parts();
        pin.circuits.get_mut("signBidirectional").unwrap().constraints[0] = "bits:16".into();
        expect_failure(&rebuilt(info, pin, zkir), "constraint");
    }

    /// The `.zkir` is an independent oracle, case 1: `contract-info.json`
    /// and `pin.json` are left correct, so checks 1-5 all pass; only the
    /// compiled circuit is swapped for another of the same deployment's
    /// (the responder's `respond`, since the signer has one circuit). A
    /// deployment that shipped the wrong circuit under this name is
    /// exactly the drift nothing else here can see.
    #[test]
    fn the_zkir_catches_a_swapped_circuit() {
        let (info, pin, zkir) = parts();
        assert!(zkir.is_some(), "the .zkir tree should be reachable in-workspace");
        let other = std::fs::read_to_string(workspace_root().join(RESPONDER_RESPOND_ZKIR)).unwrap();
        let dir = forged_zkir_dir("swapped", &other);
        expect_failure(&rebuilt(info, pin, Some(dir)), ".zkir declares 9 inputs");
    }

    /// Case 2: one constraint widened in the compiled circuit alone. Every
    /// offline check still agrees; the instruction stream does not.
    #[test]
    fn the_zkir_catches_a_widened_constraint() {
        let (info, pin, zkir) = parts();
        let real = zkir.expect("the .zkir tree should be reachable in-workspace");
        let text = std::fs::read_to_string(real.join("signBidirectional.zkir")).unwrap();
        let forged = text.replacen(
            r#"{ "op": "constrain_bits", "val": "%notification.2", "bits": 8 }"#,
            r#"{ "op": "constrain_bits", "val": "%notification.2", "bits": 16 }"#,
            1,
        );
        assert_ne!(forged, text, "the constraint to widen was not found");
        expect_failure(&rebuilt(info, pin, Some(forged_zkir_dir("widened", &forged))), ".zkir slot 2");
    }

    /// A scratch `zkir/` holding one forged `signBidirectional.zkir`.
    fn forged_zkir_dir(case: &str, contents: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("minocrab-abi-mutation-{case}"));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        std::fs::write(dir.join("signBidirectional.zkir"), contents).expect("forged zkir writes");
        dir
    }

    fn notification(info: &mut ContractInfo) -> &mut CompactType {
        &mut info.circuits[0].arguments[1].ty
    }

    fn set_payload_length(info: &mut ContractInfo, length: usize) {
        let CompactType::Struct { elements, .. } = notification(info) else {
            panic!("the notification is a struct")
        };
        elements[1].ty = CompactType::Bytes { length };
    }
}
