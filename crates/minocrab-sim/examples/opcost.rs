//! Row costs of the byte-plumbing instructions (M7 scoping): builds
//! minimal circuit variants and prints the marginal rows of each shape,
//! so optimisation targets rows rather than instruction counts.
//! Run: cargo run --release -p minocrab-sim --example opcost

use minocrab::v3::{Circuit3, FieldT};
use minocrab::Private;

fn rows(label: &str, build: impl FnOnce(&mut Circuit3)) {
    let mut c = Circuit3::new();
    build(&mut c);
    let compiled = c.finish(false);
    let model = compiled.ir.model();
    println!("{label:40} k={:2} rows={}", model.k(), model.rows());
}

fn main() {
    // Baseline: one constrained 248-bit arg, nothing else.
    rows("baseline (arg only)", |c| {
        let w = c.arg::<FieldT>("x");
        c.assert_bits(w, 248);
    });

    // One div_mod_power_of_two(_, 8) step off a 248-bit limb.
    rows("+ 1x div_mod(_, 8)", |c| {
        let w = c.arg::<FieldT>("x");
        c.assert_bits(w, 248);
        let _ = c.div_mod_power_of_two(w, 8);
    });

    // Full 31-byte explode of the limb (30 div_mod steps).
    rows("+ explode_limb(31)", |c| {
        let w = c.arg::<FieldT>("x");
        c.assert_bits(w, 248);
        let _ = minocrab_std::v3::explode_limb(c, w, 31);
    });

    // Explode + rebuild via reconstitute_field (the current reversal shape).
    rows("+ explode(31) + rebuild reconstitute", |c| {
        let w = c.arg::<FieldT>("x");
        c.assert_bits(w, 248);
        let bytes = minocrab_std::v3::explode_limb(c, w, 31);
        let rev: Vec<_> = bytes.into_iter().rev().collect();
        let _ = minocrab_std::v3::rebuild_limb(c, &rev);
    });

    // Explode + rebuild via plain mul/add fold (bytes already 8-bit
    // constrained by the explode side).
    rows("+ explode(31) + rebuild mul/add", |c| {
        let w = c.arg::<FieldT>("x");
        c.assert_bits(w, 248);
        let bytes = minocrab_std::v3::explode_limb(c, w, 31);
        let base = c.constant(256u64);
        let mut acc = *bytes.last().unwrap();
        for &b in bytes[..30].iter().rev() {
            let shifted = c.mul(acc, base);
            acc = c.add(shifted, b);
        }
    });

    // A lone reconstitute_field step (its range checks priced alone).
    rows("+ 1x reconstitute_field(_, _, 8)", |c| {
        let a = c.arg::<FieldT>("a");
        let b = c.arg::<FieldT>("b");
        c.assert_bits(a, 240);
        c.assert_bits(b, 8);
        let _ = c.reconstitute_field(a, b, 8);
    });

    // A lone mul + add pair.
    rows("+ 1x mul + add", |c| {
        let a = c.arg::<FieldT>("a");
        let b = c.arg::<FieldT>("b");
        c.assert_bits(a, 240);
        c.assert_bits(b, 8);
        let base = c.constant(256u64);
        let m = c.mul(a, base);
        let _ = c.add(m, b);
    });

    // Does div_mod's cost scale with the split position / operand width?
    for (bits, split) in [(248u32, 8u32), (248, 64), (248, 124), (248, 240), (64, 8), (16, 8)] {
        rows(&format!("div_mod split {split} of {bits}-bit arg"), |c| {
            let w = c.arg::<FieldT>("x");
            c.assert_bits(w, bits);
            let _ = c.div_mod_power_of_two(w, split);
        });
    }

    // Balanced-split tree explode of a 248-bit limb into 31 bytes:
    // div_mod at the byte-aligned midpoint, recurse.
    rows("tree explode_limb(31)", |c| {
        let w = c.arg::<FieldT>("x");
        c.assert_bits(w, 248);
        fn tree(
            c: &mut Circuit3,
            limb: minocrab::v3::Wire3<FieldT, Private>,
            nbytes: usize,
            out: &mut Vec<minocrab::v3::Wire3<FieldT, Private>>,
        ) {
            if nbytes == 1 {
                out.push(limb);
                return;
            }
            let low = nbytes / 2;
            let (hi, lo) = c.div_mod_power_of_two(limb, (low * 8) as u32);
            tree(c, lo, low, out);
            tree(c, hi, nbytes - low, out);
        }
        let mut bytes = Vec::new();
        tree(c, w, 31, &mut bytes);
    });

    // The native ZKIR ReverseBytes instruction on the same B32.
    rows("native reverse_bytes (typed)", |c| {
        let hi = c.arg::<FieldT>("hi");
        let lo = c.arg::<FieldT>("lo");
        c.assert_bits(hi, 8);
        c.assert_bits(lo, 248);
        let b = minocrab_std::v3::B32::<Private> { hi, lo };
        let typed = b.to_typed(c);
        let rev = c.reverse_bytes(typed);
        let _ = minocrab_std::v3::B32::from_typed(c, rev);
    });

    // Native reversal straight into a scalar import (the verify-path shape:
    // BE-stored Bytes<32> → Secp256k1Scalar). The secp256k1 chip is enabled
    // only when a secp type appears in the INPUT SCHEMA (`used_chips`,
    // ir_vm.rs:1246) — a `from_bytes32` alone does not do it, and the cost
    // model panics without the chip — so both this shape and its own
    // baseline declare an (unused) public key.
    rows("baseline (arg + secp pk)", |c| {
        let _pk = c.arg::<minocrab::v3::Secp256k1PointT>("pk");
        let hi = c.arg::<FieldT>("hi");
        let lo = c.arg::<FieldT>("lo");
        c.assert_bits(hi, 8);
        c.assert_bits(lo, 248);
    });
    rows("native reverse -> from_bytes32", |c| {
        let _pk = c.arg::<minocrab::v3::Secp256k1PointT>("pk");
        let hi = c.arg::<FieldT>("hi");
        let lo = c.arg::<FieldT>("lo");
        c.assert_bits(hi, 8);
        c.assert_bits(lo, 248);
        let b = minocrab_std::v3::B32::<Private> { hi, lo };
        let typed = b.to_typed(c);
        let rev = c.reverse_bytes(typed);
        let _: minocrab::v3::Wire3<minocrab::v3::Secp256k1ScalarT, Private> = c.from_bytes32(rev);
    });

    // The full current reverse_bytes32 shape on a B32 (explode lo, rebuild
    // both reversed limbs) as used per scalar import in the verify path.
    rows("full reverse_bytes32 round-trip", |c| {
        let hi = c.arg::<FieldT>("hi");
        let lo = c.arg::<FieldT>("lo");
        c.assert_bits(hi, 8);
        c.assert_bits(lo, 248);
        let b = minocrab_std::v3::B32::<Private> { hi, lo };
        let bytes = minocrab_std::v3::b32_to_bytes(c, &b);
        let rev: Vec<_> = bytes.into_iter().rev().collect();
        let _ = minocrab_std::v3::bytes_to_b32(c, &rev);
    });
}
