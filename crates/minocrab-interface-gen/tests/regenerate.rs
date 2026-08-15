//! `--check`, WIRED AS A TEST: every generated interface crate in the
//! workspace is regenerated from its own committed artifact and compared
//! byte for byte against its committed `src/lib.rs`.
//!
//! This is the codegen snapshot guard. Editing a generated file by hand, or
//! re-pinning an artifact without regenerating, fails here — which is what
//! makes "generated source is committed and reviewable" safe rather than a
//! source of quiet drift.
//!
//! `signet-signer-interface` is also the generator's ACCEPTANCE TEST: that
//! crate was hand-authored in M12 stage 4, before this generator existed,
//! and the generator now reproduces its every declaration. See
//! notes/interface-crates.org §"As built — stage 5" for which side moved.

use std::path::PathBuf;

use minocrab_interface_gen::{check_crate, first_difference, Error};

/// Every crate carrying an `artifact/generator.json`.
const GENERATED: &[&str] = &["signet-signer-interface", "xcall-target-interface"];

fn crates_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

#[test]
fn every_generated_crate_is_what_its_artifact_generates() {
    for name in GENERATED {
        match check_crate(&crates_dir().join(name)) {
            Ok(()) => {}
            Err(Error::Drift { path, expected, found }) => panic!(
                "{path} is not what `{name}`'s artifact generates:\n{}\n\n\
                 Rerun: cargo run -p minocrab-interface-gen -- --crate crates/{name}",
                first_difference(&expected, &found)
            ),
            Err(e) => panic!("checking {name}: {e}"),
        }
    }
}
