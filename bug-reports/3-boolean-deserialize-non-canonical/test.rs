//! Self-contained test for the non-canonical-Boolean bug.
//!
//! It compiles `bool-deserialize.compact` (circuit `routeAssertFalse`, which
//! asserts the deserialized Boolean is FALSE) and runs Midnight's OWN
//! reference VM — `<IrSource as Zkir>::check`, i.e. the off-circuit
//! `preprocess` that evaluates every `assert` — over the single byte input,
//! for payload values 0x00, 0x01 and 0x02.
//!
//! Expected canonical behaviour: 0x02 is not a Boolean, so it should be
//! rejected. Actual behaviour: 0x02 is accepted and the assert `!b` holds,
//! i.e. 0x02 deserialized to `false`. The test asserts the buggy pattern so
//! that it will START FAILING once a `{0,1}` constraint is added — at which
//! point payload 0x02 will be rejected and the `accepts(2)` expectation
//! flips.
//!
//! The acceptance check uses only upstream `midnight-zkir-v3` and
//! `midnight-transient-crypto` (the crates the ledger tree already builds), so
//! it also drops straight into that repo's own zkir-v3 test suite. Here it
//! additionally cross-checks against `minocrab_sim::v3::simulate`, so the
//! demonstration never rests on a single interpreter.
//!
//! Run:
//!     cargo test -p minocrab-sim --test bool_deserialize_non_canonical
//!
//! The circuit source and the compiled `.zkir` it reads live next to the
//! writeup in `bug-reports/3-boolean-deserialize-non-canonical/`.

use std::borrow::Cow;

use midnight_transient_crypto::curve::Fr;
use midnight_transient_crypto::hash::transient_commit;
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage, Zkir};
use midnight_zkir_v3::ir::IrSource;

/// The compiled circuit. Regenerate with:
///   compactc --skip-zk --feature-zkir-v3 bool-deserialize.compact out
///   cp out/zkir/routeAssertFalse.zkir bool-deserialize.zkir
const ZKIR: &str = include_str!("bool-deserialize.zkir");

/// A preimage whose single scalar input is `payload`.
///
/// The circuit's `touched.increment(1)` lowers to three `impact` ops whose
/// operands are constants (the serialized ledger effect of the increment),
/// so the reference VM checks them against `public_transcript_inputs`. They
/// are the same for every payload; feeding them lets the VM reach the assert.
fn preimage_with_payload(byte: u8) -> ProofPreimage {
    let increment_effect: Vec<Fr> = [0x70u64, 0x01, 0x01, 0x00, 0x0e, 0x01, 0xa1]
        .into_iter()
        .map(Fr::from)
        .collect();
    // The circuit carries a communications commitment: transient_commit over
    // (inputs ++ outputs). Here that is just [payload] (no outputs). Pick any
    // randomness and commit to the actual input so the VM's in-circuit check
    // passes and acceptance is decided solely by the assert.
    let inputs = vec![Fr::from(byte as u64)];
    let randomness = Fr::from(0u64);
    let commitment = transient_commit(&inputs[..], randomness);
    ProofPreimage {
        inputs,
        private_transcript: vec![],
        public_transcript_inputs: increment_effect,
        public_transcript_outputs: vec![],
        binding_input: 0.into(),
        communications_commitment: Some((commitment, randomness)),
        key_location: KeyLocation(Cow::Borrowed("bool-deserialize")),
    }
}

/// True iff Midnight's reference VM accepts `payload = byte` (every assert
/// holds). Cross-checked against `minocrab_sim::v3::simulate` — the two VMs
/// must agree on acceptance, so the demonstration never rests on one
/// interpreter.
fn reference_vm_accepts(ir: &IrSource, byte: u8) -> bool {
    let pre = preimage_with_payload(byte);
    let upstream = ir.check(&pre).is_ok();
    let ours = minocrab_sim::v3::simulate(ir, &pre).is_ok();
    assert_eq!(
        upstream, ours,
        "reference VM and minocrab simulator disagree on payload {byte:#04x}",
    );
    upstream
}

#[test]
fn non_canonical_boolean_is_accepted_and_falsy() {
    // `IrSource::load` accepts compactc's on-disk `.zkir` form (it rewrites
    // the `{major, minor}` version header that a bare serde parse rejects).
    let ir = IrSource::load(ZKIR.as_bytes()).expect("parse .zkir");

    // 0x00 is a canonical `false`: assert(!b) holds -> accepted.
    assert!(
        reference_vm_accepts(&ir, 0x00),
        "0x00 should deserialize to false and be accepted",
    );

    // 0x01 is a canonical `true`: assert(!b) fails -> rejected.
    assert!(
        !reference_vm_accepts(&ir, 0x01),
        "0x01 should deserialize to true and be rejected by assert(!b)",
    );

    // THE BUG: 0x02 is not a Boolean, yet it is accepted, and the assert `!b`
    // holds — so `deserialize<Boolean,1>(0x02)` yielded `false`. A canonical
    // decoder (or a `{0,1}` constraint) would reject 0x02 outright, flipping
    // this to `!accepts`.
    assert!(
        reference_vm_accepts(&ir, 0x02),
        "REGRESSION-OR-FIX: 0x02 is no longer accepted as a Boolean \
         (the bug is fixed) — update this expectation",
    );
}

/// The control-flow core of the `redeem` exploit (see `redeem.compact`):
/// `assert(!b)` — the "b is false" / `else` branch — is satisfied by EVERY byte
/// except `0x01`. A gate that treats a deserialized bool as `false` therefore
/// admits 255 distinct byte encodings of `false`, not the one canonical `0x00`.
/// Hashed with a fixed `tag`, those 255 bytes mint 255 distinct nullifiers, so
/// one `tag` redeems 255 times.
#[test]
fn exactly_255_bytes_deserialize_to_false() {
    let ir = IrSource::load(ZKIR.as_bytes()).expect("parse .zkir");
    let falses = (0u16..=255)
        .filter(|&b| reference_vm_accepts(&ir, b as u8))
        .count();
    assert_eq!(falses, 255, "every byte except 0x01 is accepted as false");
}
