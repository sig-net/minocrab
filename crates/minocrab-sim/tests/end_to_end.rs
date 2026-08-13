//! M2 exit criterion: a small contract written in the eDSL lowers to valid
//! ZKIR and simulates with a disclosure report — and the simulation is
//! cross-checked against Midnight's reference VM (`IrSource::check`) and,
//! when the pinned toolchain is on PATH, `zkir mock-compile`.

use midnight_transient_crypto::proofs::Zkir;
use minocrab::{Circuit, Fr};

/// Age gate: prove a witness age is >= a public threshold, disclosing only
/// the comparison result — the age itself stays private.
fn age_gate() -> minocrab::Compiled {
    let (mut c, _) = Circuit::new(0);
    let age = c.witness();
    let threshold = c.constant(18u64);
    // age < threshold, over 8-bit values
    let too_young = c.less_than(age, threshold, 8);
    let old_enough = c.not(too_young);
    c.assert(old_enough);
    let verdict = c.disclose(old_enough, "age >= 18 verdict (1 bit, not the age)");
    c.declare_public(verdict, "age-gate verdict");
    c.finish()
}

#[test]
fn simulates_with_disclosure_report() {
    let compiled = age_gate();

    let (run, report) =
        minocrab_sim::simulate_compiled(&compiled, &[], &[Fr::from(42u64)], &[]).unwrap();

    // The statement disclosed exactly one value: the verdict bit.
    assert_eq!(run.public_transcript_inputs, vec![Fr::from(1u64)]);
    assert_eq!(report.disclosures.len(), 2); // disclose() + declare_public()
    assert_eq!(report.witnesses_consumed, 1);
    assert!(report.disclosures[0].label.contains("not the age"));

    // Underage witness fails the in-circuit assertion.
    let err = minocrab_sim::simulate(&compiled.ir, &[], &[Fr::from(11u64)], &[]);
    assert!(err.is_err(), "11 < 18 must fail the assert");

    // Structured output is serializable (for tooling/CI).
    let json = serde_json::to_string_pretty(&report).unwrap();
    assert!(json.contains("age-gate verdict"));
}

#[test]
fn reference_vm_agrees() {
    let compiled = age_gate();
    let witness = [Fr::from(30u64)];
    let run = minocrab_sim::simulate(&compiled.ir, &[], &witness, &[]).unwrap();

    // Midnight's own VM must accept the exact preimage our simulator generated.
    let preimage = run.preimage(&witness, &[]);
    compiled
        .ir
        .check(&preimage)
        .expect("reference VM rejected a run our simulator accepted");

    // And reject a tampered statement.
    let mut bad = run.preimage(&witness, &[]);
    bad.public_transcript_inputs = vec![Fr::from(0u64)];
    assert!(compiled.ir.check(&bad).is_err());
}

#[test]
fn cost_model_reports() {
    let compiled = age_gate();
    let (k, rows) = minocrab_sim::cost(&compiled.ir);
    assert!(k > 0 && rows > 0);
}

#[test]
fn profiler_attributes_regions() {
    let (mut c, _) = Circuit::new(0);
    let (a, b) = c.region("load witnesses", |c| (c.witness(), c.witness()));
    let hash = c.region("hash", |c| c.transient_hash(&[a, b]));
    c.region("disclose", |c| {
        let h = c.disclose(hash, "commitment hash");
        c.declare_public(h, "commitment");
    });
    let compiled = c.finish();

    let profile = minocrab_sim::profile(&compiled);
    assert_eq!(profile.total_instructions as u32, 5); // 2 wit + hash + declare + pi_skip
    let labels: Vec<&str> = profile.regions.iter().map(|r| r.label.as_str()).collect();
    assert!(labels.contains(&"load witnesses"));
    assert!(labels.contains(&"hash"));
    assert!(labels.contains(&"disclose"));
    assert!(profile.k > 0);

    // Human-readable rendering exists and mentions every region.
    let shown = profile.to_string();
    assert!(shown.contains("load witnesses") && shown.contains("k="));
}

#[test]
fn toolchain_accepts_lowered_circuit() {
    let compiled = age_gate();

    let zkir_available = std::process::Command::new("zkir").arg("--version").output().is_ok();
    if !zkir_available {
        eprintln!("skipping: no `zkir` on PATH");
        return;
    }

    let dir = std::env::temp_dir().join(format!("minocrab-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("age_gate.zkir");
    let file = std::fs::File::create(&path).unwrap();
    minocrab_zkir::write_zkir(&compiled.ir, file, "age_gate.zkir").unwrap();

    let output = std::process::Command::new("zkir")
        .arg("mock-compile")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "zkir mock-compile rejected the lowered eDSL circuit:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
}
