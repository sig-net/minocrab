//! An out-of-range secp256k1 limb batch is a decode ERROR, not a panic.
//!
//! The simulator maps a `decode_offcircuit` failure to `Sim3Error::Inputs`
//! (src/v3.rs), and the Lean model of the emulated-field decode
//! (minocrab-zkir/lean/MinocrabZkir/Intrinsics/Secp256k1.lean) rejects a
//! first native at or above `2^192` or a second at or above `2^64`. Both rest
//! on midnight-circuits 7.2.4's `from_public_input` returning `None`; 7.2.2
//! panics in `bi_to_limbs` instead, so this pins the lockfile's choice.

use midnight_zkir_v3::ir_instructions::encode::decode_offcircuit;
use midnight_zkir_v3::ir_types::IrType;
use minocrab_zkir::Fr;

fn pow2(bits: u32) -> Fr {
    (0..bits).fold(Fr::from(1u64), |acc, _| acc * Fr::from(2u64))
}

fn rejects(raw: &[Fr], ty: &IrType) {
    let decoded = std::panic::catch_unwind(|| decode_offcircuit(raw, ty));
    match decoded {
        Ok(Err(_)) => {}
        Ok(Ok(v)) => panic!("{ty:?}: {raw:?} decoded to {v:?}"),
        Err(_) => panic!("{ty:?}: decoding {raw:?} panicked instead of failing"),
    }
}

#[test]
fn an_out_of_range_low_batch_is_rejected() {
    for ty in [IrType::Secp256k1Base, IrType::Secp256k1Scalar] {
        rejects(&[pow2(192), Fr::from(0u64)], &ty);
    }
}

#[test]
fn an_out_of_range_high_batch_is_rejected() {
    for ty in [IrType::Secp256k1Base, IrType::Secp256k1Scalar] {
        rejects(&[Fr::from(0u64), pow2(64)], &ty);
    }
}
