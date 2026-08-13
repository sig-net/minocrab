//! Differential test: compactc's compiled `jubjubSchnorrVerify` (corpus
//! golden `verifySchnorrN3.zkir`, verdict at slot 21) vs our stdlib port,
//! same inputs, same verdict — for both valid and invalid signatures.
//!
//! Signature construction uses transient-crypto's own public API
//! (`EmbeddedGroupAffine * Fr` reduces the scalar mod the Jubjub order the
//! same way the VM's EcMul does), so validity is spec-level, not
//! circular.

use midnight_transient_crypto::curve::{EmbeddedFr, EmbeddedGroupAffine};
use midnight_transient_crypto::hash::transient_hash;
use minocrab::{Circuit, Fr, Private, Wire};
use minocrab_sim::simulate;
use minocrab_std::schnorr::{jubjub_schnorr_verify, JubjubSchnorrSignature};
use minocrab_std::types::JubjubPoint;

fn corpus_zkir(rel: &str) -> minocrab::IrSource {
    let path = format!("{}/../../corpus/zkir/{rel}", env!("CARGO_MANIFEST_DIR"));
    minocrab_zkir::read_zkir(&path).expect("corpus golden parses")
}

/// Slot of the verification verdict inside verifySchnorrN3.zkir (the
/// cond_select AND of the two coordinate test_eqs; see the golden).
const VERDICT_SLOT: usize = 21;

/// Inputs: [msg0, msg1, msg2, annX, annY, response, pkX, pkY].
fn compactc_verdict(inputs: &[Fr; 8]) -> Fr {
    let mut ir = corpus_zkir("compact/test-center/compact/schnorr/zkir/verifySchnorrN3.zkir");
    ir.do_communications_commitment = false; // value-level comparison only
    // One public-transcript read (the ledger `result` read-back).
    let run = simulate(&ir, inputs, &[], &[Fr::from(1u64)]).expect("golden simulates");
    run.memory[VERDICT_SLOT]
}

fn minocrab_verdict(inputs: &[Fr; 8]) -> Fr {
    let (mut c, _) = Circuit::new(0);
    let w: Vec<Wire<Private>> = (0..8).map(|_| c.witness()).collect();
    let sig = JubjubSchnorrSignature {
        announcement: JubjubPoint { x: w[3], y: w[4] },
        response: w[5],
    };
    let pk = JubjubPoint { x: w[6], y: w[7] };
    let verdict = jubjub_schnorr_verify(&mut c, &w[0..3], &sig, &pk);
    let public = c.disclose(verdict, "schnorr verdict");
    c.declare_public(public, "verdict");
    let compiled = c.finish();
    let run = simulate(&compiled.ir, &[], inputs, &[]).expect("our circuit simulates");
    run.public_transcript_inputs[0]
}

/// Schnorr-sign `msg` with secret scalar `x` and nonce `k` (both small
/// u64s for exact Fr↔EmbeddedFr lifting).
fn sign(msg: [Fr; 3], x: u64, k: u64) -> [Fr; 8] {
    let g = EmbeddedGroupAffine::generator();
    let pk = g * Fr::from(x);
    let ann = g * Fr::from(k);
    let (pk_x, pk_y) = (pk.x().unwrap(), pk.y().unwrap());
    let (ann_x, ann_y) = (ann.x().unwrap(), ann.y().unwrap());

    let c = transient_hash(&[ann_x, ann_y, pk_x, pk_y, msg[0], msg[1], msg[2]]);
    // Reduce the challenge mod the Jubjub scalar order (the same mod-r
    // reduction EcMul applies to its Fr scalar operand).
    let c_j = EmbeddedFr::from_le_bytes_wide(&c.as_le_bytes()).expect("wide reduction");
    let s_j = EmbeddedFr::from(k) + c_j * EmbeddedFr::from(x);
    let s = Fr::from_le_bytes(&s_j.as_le_bytes()).expect("s < r_jubjub < r_bls");

    [msg[0], msg[1], msg[2], ann_x, ann_y, s, pk_x, pk_y]
}

#[test]
fn schnorr_verdicts_match_compactc() {
    let msg = [Fr::from(11u64), Fr::from(22u64), Fr::from(33u64)];

    // Valid signature: both accept.
    let valid = sign(msg, 0xdead_beef, 0x1234_5678);
    assert_eq!(compactc_verdict(&valid), Fr::from(1u64));
    assert_eq!(minocrab_verdict(&valid), Fr::from(1u64));

    // Tampered response: both reject.
    let mut bad = valid;
    bad[5] = bad[5] + Fr::from(1u64);
    assert_eq!(compactc_verdict(&bad), Fr::from(0u64));
    assert_eq!(minocrab_verdict(&bad), Fr::from(0u64));

    // Wrong message: both reject.
    let mut wrong = valid;
    wrong[0] = Fr::from(99u64);
    assert_eq!(compactc_verdict(&wrong), minocrab_verdict(&wrong));
    assert_eq!(compactc_verdict(&wrong), Fr::from(0u64));

    // A different key pair still verifies its own signature.
    let valid2 = sign(msg, 7, 13);
    assert_eq!(compactc_verdict(&valid2), Fr::from(1u64));
    assert_eq!(minocrab_verdict(&valid2), Fr::from(1u64));
}
