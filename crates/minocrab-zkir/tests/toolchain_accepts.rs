//! M1 exit criterion: a circuit built by hand through our bindings is
//! accepted by the pinned `zkir` toolchain binary (`zkir mock-compile`).
//!
//! Runs when `zkir` is on PATH (the nix dev shell provides the pinned one) or
//! `ZKIR_BIN` is set; skips otherwise so plain `cargo test` still works.

use std::process::Command;
use std::sync::Arc;

use minocrab_zkir::{Fr, Instruction, IrSource};

fn zkir_bin() -> Option<String> {
    if let Ok(bin) = std::env::var("ZKIR_BIN") {
        return Some(bin);
    }
    Command::new("zkir")
        .arg("--version")
        .output()
        .ok()
        .map(|_| "zkir".to_string())
}

#[test]
fn toolchain_accepts_hand_emitted_circuit() {
    let Some(zkir) = zkir_bin() else {
        eprintln!("skipping: no `zkir` on PATH and ZKIR_BIN unset");
        return;
    };

    // Minimal circuit in the shape compactc emits: load a constant true,
    // declare it as a public input, and close the group with a pi_skip
    // guarded on it.
    let ir = IrSource {
        num_inputs: 0,
        do_communications_commitment: false,
        instructions: Arc::new(vec![
            Instruction::LoadImm { imm: Fr::from(1) },
            Instruction::DeclarePubInput { var: 0 },
            Instruction::PiSkip {
                guard: Some(0),
                count: 1,
            },
        ]),
        ..Default::default()
    };

    let dir = std::env::temp_dir().join(format!("minocrab-zkir-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("hand_emitted.zkir");
    let file = std::fs::File::create(&path).unwrap();
    minocrab_zkir::write_zkir(&ir, file, "hand_emitted.zkir").unwrap();

    let output = Command::new(&zkir)
        .arg("mock-compile")
        .arg(&path)
        .output()
        .expect("failed to run zkir");
    assert!(
        output.status.success(),
        "zkir mock-compile rejected our output:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // And what we wrote must parse back to the same IR.
    assert_eq!(minocrab_zkir::read_zkir(&path).unwrap(), ir);
}
