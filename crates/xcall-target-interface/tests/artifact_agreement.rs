//! The same agreement suite `signet-signer-interface` carries, for a
//! contract NOBODY PORTED.
//!
//! Nothing in this workspace implements the xcall target in MinoCrab; the
//! only thing we have is what compactc left behind, and that was enough to
//! generate the crate and is enough to check it. That is the
//! Compact-interop claim of M12: any deployed Midnight contract becomes
//! importable, and stays checked.
//!
//! The mutation suite lives with the other crate — the checker is the same
//! code, and proving it bites once is proving it bites.

use std::path::PathBuf;

use minocrab::Public;
use minocrab_abi::{circuit_schema, Artifact, Pin};
use minocrab_std::v3::{BytesN, Uint, B32};
use xcall_target_interface::XcallTarget;

const SOURCE: &str = "corpus/zkir/signet-midnight-experiments/experiments/xcall/contract/src/target";

/// The three circuits' argument lists, as the interface declares them.
type Deposit = (B32<Public>, Uint<128, Public>);
type DepositBig = (BytesN<Public, 256>,);

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_root() -> PathBuf {
    crate_dir().join("../..").canonicalize().expect("workspace root")
}

fn artifact() -> Artifact {
    Artifact::open(crate_dir()).expect("the pinned artifact opens")
}

fn schema() -> String {
    let mut out = String::from(
        "# The published ABI of `xcall-target-interface`, derived from the\n\
         # declarations in src/lib.rs. A DIFF HERE IS A SEMVER DECISION:\n\
         # every line below feeds the communications commitment the ledger\n\
         # matches, so any change breaks deployed callers (major).\n\
         # Regenerate: cargo test -p xcall-target-interface -- --ignored\n\n",
    );
    out.push_str(&circuit_schema::<Deposit, ()>(XcallTarget::DEPOSIT));
    out.push('\n');
    out.push_str(&circuit_schema::<Deposit, ()>(XcallTarget::DEPOSIT_EMIT));
    out.push('\n');
    out.push_str(&circuit_schema::<DepositBig, ()>(XcallTarget::DEPOSIT_BIG));
    out
}

#[test]
fn the_committed_pin_is_the_artifacts_distillation() {
    let distilled = Pin::distill(&workspace_root().join(SOURCE), SOURCE).expect("distills");
    let committed = Pin::parse(
        &std::fs::read_to_string(crate_dir().join("artifact/pin.json")).expect("pin.json reads"),
    )
    .expect("pin.json parses");
    assert_eq!(committed, distilled, "artifact/pin.json is not the distillation of {SOURCE}");
}

#[test]
fn the_pinned_digests_match_the_bytes() {
    let artifact = artifact();
    assert!(artifact.zkir_dir.is_some(), "the .zkir tree should be reachable in-workspace");
    if let Err(problems) = artifact.verify_pin() {
        panic!("the pin does not match its artifact:\n{problems}");
    }
}

/// `deposit` and `depositEmit` have the SAME argument layout and different
/// entry points — honest limit #1 of notes/interface-crates.org seen from
/// the artifact side: what distinguishes the two calls is the claimed
/// entry-point hash, not anything in either circuit.
#[test]
fn every_declared_circuit_matches_the_artifact() {
    let artifact = artifact();
    artifact.assert_interface_matches::<Deposit, ()>(XcallTarget::DEPOSIT);
    artifact.assert_interface_matches::<Deposit, ()>(XcallTarget::DEPOSIT_EMIT);
    artifact.assert_interface_matches::<DepositBig, ()>(XcallTarget::DEPOSIT_BIG);
}

#[test]
fn the_published_abi_is_frozen() {
    let committed = std::fs::read_to_string(crate_dir().join("artifact/interface-schema.txt"))
        .expect("interface-schema.txt reads");
    assert_eq!(schema(), committed, "the published ABI moved");
}

/// `cargo test -p xcall-target-interface -- --ignored`.
#[test]
#[ignore]
fn regenerate_pin_and_schema() {
    let pin = Pin::distill(&workspace_root().join(SOURCE), SOURCE).expect("distills");
    std::fs::write(crate_dir().join("artifact/pin.json"), pin.to_json()).expect("pin.json writes");
    std::fs::write(crate_dir().join("artifact/interface-schema.txt"), schema())
        .expect("interface-schema.txt writes");
}
