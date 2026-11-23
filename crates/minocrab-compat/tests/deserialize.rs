//! `deserialize::Packed` reads the values a packed struct holds, including a
//! field that straddles two limbs, and refuses what compactc refuses: a
//! Boolean byte above 1. Its shape is checked against compactc's artifacts
//! in `minocrab-contracts` (`attest_differential`, `serde_builtin_differential`);
//! this checks the values, by running the circuit through the simulator.

use std::borrow::Cow;

use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage};
use minocrab::{Circuit, Compiled};
use minocrab::{Fr, Private};
use minocrab_compat::deserialize::Packed;
use minocrab_std::BytesN;
use minocrab_zkir::IrValue;

/// `Bytes<64>` read as `{ flag: Boolean, a: Uint<128>, b: Uint<8>,
/// tag: Bytes<32>, c: Uint<64> @50 }`, plus `Uint<64>` at 25..33, which
/// spans the limb boundary at byte 31. Every value is returned.
fn circuit() -> Compiled {
    let mut c = Circuit::new();
    minocrab_compat::profile(&mut c);
    let bytes = BytesN::<Private, 64>::arg(&mut c, "bytes");
    bytes.constrain_input(&mut c);
    let packed = Packed::new(&bytes);
    let flag = packed.boolean::<0>(&mut c);
    let a = packed.uint::<1, 16>(&mut c);
    let b = packed.uint::<17, 1>(&mut c);
    let tag = packed.bytes32::<18>(&mut c);
    let straddle = packed.uint::<25, 8>(&mut c);
    let last = packed.uint::<50, 8>(&mut c);
    for (w, label) in
        [(flag, "flag"), (a, "a"), (b, "b"), (tag.hi, "tag hi"), (tag.lo, "tag lo"), (straddle, "straddle"), (last, "last")]
    {
        let w = c.disclose(w, label);
        c.output(w, label);
    }
    c.finish(false)
}

/// `Bytes<64>` limbs, slot order: the leftover bytes 62..64 first.
fn limbs(bytes: &[u8; 64]) -> Vec<Fr> {
    [&bytes[62..64], &bytes[31..62], &bytes[0..31]].iter().map(|l| Fr::from_le_bytes(l).unwrap()).collect()
}

fn run(compiled: &Compiled, bytes: &[u8; 64]) -> Option<Vec<Fr>> {
    let pi = ProofPreimage {
        inputs: limbs(bytes),
        private_transcript: vec![],
        public_transcript_inputs: vec![],
        public_transcript_outputs: vec![],
        binding_input: 0.into(),
        communications_commitment: None,
        key_location: KeyLocation(Cow::Borrowed("minocrab-compat-test")),
    };
    let run = minocrab_sim::simulate(&compiled.ir, &pi).ok()?;
    Some(
        run.outputs
            .iter()
            .map(|v| match v {
                IrValue::Native(f) => *f,
                other => panic!("a native output, got {other:?}"),
            })
            .collect(),
    )
}

fn le(bytes: &[u8]) -> Fr {
    Fr::from_le_bytes(bytes).unwrap()
}

#[test]
fn reads_each_field_and_refuses_a_boolean_above_one() {
    let compiled = circuit();
    let mut bytes = [0u8; 64];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37).wrapping_add(11);
    }
    bytes[62] = 0xff; // the leftover limb, read by nothing
    for flag in [0u8, 1] {
        bytes[0] = flag;
        let got = run(&compiled, &bytes).expect("accepts a 0/1 flag");
        let want = vec![
            Fr::from(u64::from(flag)),
            le(&bytes[1..17]),
            le(&bytes[17..18]),
            le(&bytes[49..50]),
            le(&bytes[18..49]),
            le(&bytes[25..33]),
            le(&bytes[50..58]),
        ];
        assert_eq!(got, want, "flag {flag}");
    }
    for flag in [2u8, 0xff] {
        bytes[0] = flag;
        assert!(run(&compiled, &bytes).is_none(), "flag {flag} must be refused");
    }
}
