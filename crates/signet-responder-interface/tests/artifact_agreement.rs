//! This crate's claim, checked.
//!
//! `src/lib.rs` asserts that a contract deployed from
//! `signet-midnight-integration`'s `signet-responder` package exports two
//! circuits, `respond` and `respondBidirectional`, with exactly these
//! argument layouts. Everything needed to settle that assertion is committed
//! beside it: `artifact/`'s `contract-info.json` (the callee's own typed
//! schema, as compactc wrote it) and `pin.json` (the distilled, hash-pinned
//! facts of the compiled `.zkir`s).
//!
//! The same four positive tests as `signet-signer-interface`'s suite, and a
//! mutation suite that proves the checker bites on this artifact too.

use std::path::PathBuf;

use minocrab::Public;
use minocrab_abi::{circuit_schema, Artifact, Pin};
use signet_responder_interface::{
    RespondBidirectionalEventV1, SignatureRespondedEventV1, SignetResponder,
};

/// Where the artifact came from, relative to the workspace root. The same
/// string `pin.json` carries.
const SOURCE: &str = "corpus/zkir/signet-midnight-integration-v026/packages/signet-responder/src/signet-responder";

/// The two circuits' argument lists, as the interface declares them.
type Respond = (SignatureRespondedEventV1<Public>,);
type RespondBidirectional = (RespondBidirectionalEventV1<Public>,);

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
        "# The published ABI of `signet-responder-interface`, derived from the\n\
         # declarations in src/lib.rs. A DIFF HERE IS A SEMVER DECISION:\n\
         # every line below feeds the communications commitment the ledger\n\
         # matches, so any change breaks deployed callers (major).\n\
         # Regenerate: cargo test -p signet-responder-interface -- --ignored\n\n",
    );
    out.push_str(&circuit_schema::<Respond, ()>(SignetResponder::RESPOND));
    out.push('\n');
    out.push_str(&circuit_schema::<RespondBidirectional, ()>(
        SignetResponder::RESPOND_BIDIRECTIONAL,
    ));
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

/// The six checks, per circuit.
#[test]
fn every_declared_circuit_matches_the_artifact() {
    let artifact = artifact();
    artifact.assert_interface_matches::<Respond, ()>(SignetResponder::RESPOND);
    artifact.assert_interface_matches::<RespondBidirectional, ()>(
        SignetResponder::RESPOND_BIDIRECTIONAL,
    );
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
/// `cargo test -p signet-responder-interface -- --ignored`.
#[test]
#[ignore]
fn regenerate_pin_and_schema() {
    let pin = Pin::distill(&workspace_root().join(SOURCE), SOURCE).expect("distills");
    std::fs::write(crate_dir().join("artifact/pin.json"), pin.to_json()).expect("pin.json writes");
    std::fs::write(crate_dir().join("artifact/interface-schema.txt"), schema())
        .expect("interface-schema.txt writes");
}

/// The checker has to bite on this artifact as well: each case breaks one
/// thing of `respond` and asserts the check names it. The last two forge
/// the compiled `.zkir` while leaving `contract-info.json` and `pin.json`
/// correct.
mod mutation {
    use super::*;
    use minocrab_abi::info::{CompactType, ContractInfo};

    fn parts() -> (ContractInfo, Pin, Option<PathBuf>) {
        let real = artifact();
        (real.info.clone(), real.pin.clone(), real.zkir_dir.clone())
    }

    fn rebuilt(info: ContractInfo, pin: Pin, zkir: Option<PathBuf>) -> Artifact {
        Artifact::from_parts(info, pin, zkir)
    }

    /// `respond`'s index in `contract-info.json`.
    fn respond_index(info: &ContractInfo) -> usize {
        info.circuits.iter().position(|c| c.name == "respond").expect("respond is exported")
    }

    #[test]
    fn the_control_passes() {
        let (info, pin, zkir) = parts();
        rebuilt(info, pin, zkir)
            .check::<Respond, ()>(SignetResponder::RESPOND)
            .expect("the unmutated artifact matches");
    }

    fn expect_failure(artifact: &Artifact, wanted: &str) {
        let problems = artifact
            .check::<Respond, ()>(SignetResponder::RESPOND)
            .expect_err("the mutation must be caught");
        assert!(
            problems.0.iter().any(|p| p.contains(wanted)),
            "expected a problem mentioning {wanted:?}, got:\n{problems}"
        );
    }

    #[test]
    fn a_renamed_circuit_is_caught() {
        let (mut info, pin, zkir) = parts();
        let i = respond_index(&info);
        info.circuits[i].name = "respondV2".into();
        expect_failure(&rebuilt(info, pin, zkir), "exports no circuit");
    }

    #[test]
    fn a_proofless_circuit_is_caught() {
        let (mut info, pin, zkir) = parts();
        let i = respond_index(&info);
        info.circuits[i].proof = false;
        expect_failure(&rebuilt(info, pin, zkir), "proof: false");
    }

    /// The callee narrowed the recovery id's field.
    #[test]
    fn a_retyped_field_is_caught() {
        let (mut info, pin, zkir) = parts();
        let i = respond_index(&info);
        let CompactType::Struct { elements, .. } = &mut info.circuits[i].arguments[0].ty else {
            panic!("the event is a struct")
        };
        elements[0].ty = CompactType::Bytes { length: 31 };
        expect_failure(&rebuilt(info, pin, zkir), "argument");
    }

    #[test]
    fn a_new_result_is_caught() {
        let (mut info, pin, zkir) = parts();
        let i = respond_index(&info);
        info.circuits[i].result_type = CompactType::Bytes { length: 32 };
        expect_failure(&rebuilt(info, pin, zkir), "result slots");
    }

    #[test]
    fn a_missing_communications_commitment_is_caught() {
        let (info, mut pin, _) = parts();
        pin.circuits.get_mut("respond").unwrap().do_communications_commitment = false;
        expect_failure(&rebuilt(info, pin, None), "communications commitment");
    }

    #[test]
    fn a_drifted_constraint_prefix_is_caught() {
        let (info, mut pin, zkir) = parts();
        pin.circuits.get_mut("respond").unwrap().constraints[0] = "bits:16".into();
        expect_failure(&rebuilt(info, pin, zkir), "constraint");
    }

    /// The compiled circuit swapped for the contract's other one.
    #[test]
    fn the_zkir_catches_a_swapped_circuit() {
        let (info, pin, zkir) = parts();
        let real = zkir.expect("the .zkir tree should be reachable in-workspace");
        let other = std::fs::read_to_string(real.join("respondBidirectional.zkir")).unwrap();
        expect_failure(&rebuilt(info, pin, Some(forged_zkir_dir("swapped", &other))), ".zkir declares 16 inputs");
    }

    /// One constraint widened in the compiled circuit alone.
    #[test]
    fn the_zkir_catches_a_widened_constraint() {
        let (info, pin, zkir) = parts();
        let real = zkir.expect("the .zkir tree should be reachable in-workspace");
        let text = std::fs::read_to_string(real.join("respond.zkir")).unwrap();
        let forged = text.replacen(
            r#"{ "op": "constrain_bits", "val": "%signatureRespondedEvent.2", "bits": 8 }"#,
            r#"{ "op": "constrain_bits", "val": "%signatureRespondedEvent.2", "bits": 16 }"#,
            1,
        );
        assert_ne!(forged, text, "the constraint to widen was not found");
        expect_failure(&rebuilt(info, pin, Some(forged_zkir_dir("widened", &forged))), ".zkir slot 2");
    }

    /// A scratch `zkir/` holding one forged `respond.zkir`.
    fn forged_zkir_dir(case: &str, contents: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("minocrab-abi-responder-mutation-{case}"));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        std::fs::write(dir.join("respond.zkir"), contents).expect("forged zkir writes");
        dir
    }
}
