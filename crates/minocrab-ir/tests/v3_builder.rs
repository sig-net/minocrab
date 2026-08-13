//! The v3 builder's output is accepted by the pinned `zkir-v3` toolchain
//! binary (`zkir-v3 mock-compile`) and round-trips through our bindings.
//!
//! Runs when `zkir-v3` is on PATH (the nix dev shell provides the pinned
//! one) or `ZKIR_V3_BIN` is set; skips otherwise so plain `cargo test`
//! still works.

use std::process::Command;

use minocrab_ir::v3::{Arg, Builder3, IrSource, IrType};

fn zkir_v3_bin() -> Option<String> {
    if let Ok(bin) = std::env::var("ZKIR_V3_BIN") {
        return Some(bin);
    }
    Command::new("zkir-v3")
        .arg("--version")
        .output()
        .ok()
        .map(|_| "zkir-v3".to_string())
}

/// A circuit exercising the typed surface: native arithmetic, a point
/// argument, coordinates, Bytes<32> decomposition, hashing, and an Impact
/// public-input block.
fn build_test_circuit() -> IrSource {
    let mut b = Builder3::new();
    let x = b.input("x", IrType::Native);
    let pk = b.input("pk", IrType::Secp256k1Point);
    let digest = b.input("digest", IrType::Bytes32);

    // Native arithmetic with an inline immediate.
    let x_plus_3 = b.add(x, 3u64);
    let hashed = b.transient_hash(&[Arg::from(x_plus_3)]);

    // Point → coordinates → 32-byte form → native low/high. (TestEq does
    // not support Bytes<32>: compare the native decompositions instead,
    // which is also how compactc handles Bytes<32> equality.)
    let (px, _py) = b.into_coordinates(pk);
    let px_bytes = b.into_bytes32(px);
    let (px_low, px_high) = b.bytes32_into_low_high(px_bytes);
    let (low, high) = b.bytes32_into_low_high(digest);
    b.constrain_bits(high, 8);
    let eq_low = b.test_eq(px_low, low);
    let eq_high = b.test_eq(px_high, high);
    let eq = b.mul(eq_low, eq_high);
    b.assert(eq);

    // Public-input block guarded on a constant-true.
    b.impact(1u64, &[Arg::from(hashed), Arg::from(low)]);

    b.output(&[Arg::from(hashed)]);
    b.finish(false)
}

#[test]
fn v3_builder_output_round_trips_and_toolchain_accepts() {
    let ir = build_test_circuit();

    // Round-trip through our serializer and parser.
    let json = minocrab_zkir::v3::to_zkir_string(&ir).unwrap();
    let parsed = minocrab_zkir::v3::parse_zkir(json.as_bytes(), "<test>").unwrap();
    assert_eq!(parsed, ir);

    let Some(zkir_v3) = zkir_v3_bin() else {
        eprintln!("skipping toolchain check: no `zkir-v3` on PATH and ZKIR_V3_BIN unset");
        return;
    };

    let dir = std::env::temp_dir().join(format!("minocrab-ir-v3-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("builder3.zkir");
    let file = std::fs::File::create(&path).unwrap();
    minocrab_zkir::v3::write_zkir(&ir, file, "builder3.zkir").unwrap();

    let output = Command::new(&zkir_v3)
        .arg("mock-compile")
        .arg(&path)
        .output()
        .expect("failed to run zkir-v3");
    assert!(
        output.status.success(),
        "zkir-v3 mock-compile rejected our output:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
#[should_panic(expected = "test_eq: operand types differ")]
fn type_mismatch_is_a_build_error() {
    let mut b = Builder3::new();
    let x = b.input("x", IrType::Native);
    let base = b.input("base", IrType::Secp256k1Base);
    b.test_eq(x, base);
}

#[test]
#[should_panic(expected = "test_eq: operand must be a field element or point")]
fn unsupported_type_is_a_build_error() {
    let mut b = Builder3::new();
    let a = b.input("a", IrType::Bytes32);
    let c = b.input("b", IrType::Bytes32);
    b.test_eq(a, c);
}
