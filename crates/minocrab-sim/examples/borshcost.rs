//! Row cost of the two `BorshReader` modes (M11 stage 2,
//! notes/borsh-format.org §"The deserializer"): what it costs to READ a
//! fixed-width Borsh value back out of packed bytes, per leaf and per record,
//! in Split mode (one `div_mod` per field boundary interior to a limb) and in
//! WitnessCheck mode (witness each leaf, constrain it, re-pack and assert
//! limb equality).
//!
//! Everything is marginal over a per-mode baseline — the `Bytes<N>` argument,
//! its input constraint, and the mode's fixed cost with ZERO leaves read
//! (Split's pad assertion, WitnessCheck's empty re-pack and its limb
//! equalities) — so the numbers are the cost of the READS alone.
//!
//! Run: cargo run --release -p minocrab-sim --example borshcost

use minocrab::v3::Circuit3;
use minocrab::Private;
use minocrab_std::v3::borsh::{read_canonical, Flagged, Split, Tag, WitnessCheck};
use minocrab_std::v3::{Bool, Bytes, BytesN, Uint, B32};

/// Bytes of the buffer every measurement reads out of.
const N: usize = 204;

fn rows(build: impl FnOnce(&mut Circuit3)) -> usize {
    let mut c = Circuit3::new();
    build(&mut c);
    c.finish(false).ir.model().rows()
}

/// The buffer, constrained — what both baselines share.
fn buffer(c: &mut Circuit3) -> BytesN<Private, N> {
    let bytes = BytesN::<Private, N>::arg(c, "bytes");
    bytes.constrain_input(c);
    bytes
}

/// Split mode: read `f`'s leaves, then assert the pad is zero.
fn split(f: impl FnOnce(&mut Circuit3, &mut Split<Private>)) -> usize {
    rows(|c| {
        let bytes = buffer(c);
        let mut reader = Split::new(&bytes);
        f(c, &mut reader);
        reader.assert_pad_zero(c);
    })
}

/// WitnessCheck mode: read `f`'s leaves, then re-pack and assert equality.
fn witness_check(f: impl FnOnce(&mut Circuit3, &mut WitnessCheck<N>)) -> usize {
    rows(|c| {
        let bytes = buffer(c);
        let mut reader = WitnessCheck::<N>::new(&bytes);
        f(c, &mut reader);
        reader.finish(c);
    })
}

fn main() {
    let base_split = split(|_, _| {});
    let base_witness = witness_check(|_, _| {});
    println!("buffer: Bytes<{N}> argument, input-constrained");
    println!("baseline rows  Split {base_split:>6}   WitnessCheck {base_witness:>6}");
    println!("(baseline = the buffer + the mode's fixed cost at zero leaves)\n");
    println!("{:28} {:>10} {:>14} {:>8}", "leaf (read at offset 0)", "Split", "WitnessCheck", "ratio");

    macro_rules! leaf {
        ($ty:ty, $name:literal) => {{
            let s = split(|c, r| {
                let _: $ty = read_canonical(c, r);
            }) - base_split;
            let w = witness_check(|c, r| {
                let _: $ty = read_canonical(c, r);
            }) - base_witness;
            println!(
                "{:28} {:>10} {:>14} {:>8.1}",
                $name,
                s,
                w,
                s as f64 / w.max(1) as f64
            );
        }};
    }

    leaf!(Uint<8, Private>, "u8");
    leaf!(Uint<16, Private>, "u16");
    leaf!(Uint<32, Private>, "u32");
    leaf!(Uint<64, Private>, "u64");
    leaf!(Uint<128, Private>, "u128");
    leaf!(Bool<Private>, "bool");
    leaf!(Tag<4, Private>, "Tag<4>");
    leaf!(Bytes<20, Private>, "[u8; 20]");
    leaf!(B32<Private>, "[u8; 32]");
    leaf!(BytesN<Private, 64>, "[u8; 64]");
    leaf!([B32<Private>; 2], "[[u8; 32]; 2]");
    leaf!(Flagged<Uint<32, Private>, Private>, "Flagged<u32>");

    // The same leaf read at an offset that makes it straddle a 31-byte limb
    // boundary — Split's cost is a function of the LAYOUT, not just the type.
    println!("\n{:28} {:>10} {:>14}", "u64 at byte offset", "Split", "WitnessCheck");
    for skip in [0usize, 23, 27, 30] {
        let s = split(|c, r| {
            for _ in 0..skip {
                let _: Uint<8, Private> = read_canonical(c, r);
            }
            let _: Uint<64, Private> = read_canonical(c, r);
        });
        let w = witness_check(|c, r| {
            for _ in 0..skip {
                let _: Uint<8, Private> = read_canonical(c, r);
            }
            let _: Uint<64, Private> = read_canonical(c, r);
        });
        let s_skip = split(|c, r| {
            for _ in 0..skip {
                let _: Uint<8, Private> = read_canonical(c, r);
            }
        });
        let w_skip = witness_check(|c, r| {
            for _ in 0..skip {
                let _: Uint<8, Private> = read_canonical(c, r);
            }
        });
        println!("{skip:28} {:>10} {:>14}", s - s_skip, w - w_skip);
    }

    // A whole record: every leaf kind, 204 bytes, 16 reads.
    let whole_split = split(|c, r| {
        let _: Uint<8, Private> = read_canonical(c, r);
        let _: Bool<Private> = read_canonical(c, r);
        let _: Tag<4, Private> = read_canonical(c, r);
        let _: Uint<128, Private> = read_canonical(c, r);
        let _: Bytes<20, Private> = read_canonical(c, r);
        let _: B32<Private> = read_canonical(c, r);
        let _: BytesN<Private, 64> = read_canonical(c, r);
        let _: [B32<Private>; 2] = read_canonical(c, r);
        let _: Flagged<Uint<32, Private>, Private> = read_canonical(c, r);
    });
    let whole_witness = witness_check(|c, r| {
        let _: Uint<8, Private> = read_canonical(c, r);
        let _: Bool<Private> = read_canonical(c, r);
        let _: Tag<4, Private> = read_canonical(c, r);
        let _: Uint<128, Private> = read_canonical(c, r);
        let _: Bytes<20, Private> = read_canonical(c, r);
        let _: B32<Private> = read_canonical(c, r);
        let _: BytesN<Private, 64> = read_canonical(c, r);
        let _: [B32<Private>; 2] = read_canonical(c, r);
        let _: Flagged<Uint<32, Private>, Private> = read_canonical(c, r);
    });
    // 9 fields, 16 takes (a Bytes<32> is 2, the Bytes<64> is 3, Flagged is 2).
    println!("\nthe whole {N}-byte record (9 fields, 16 leaf reads):");
    println!("  total rows     Split {whole_split:>6}   WitnessCheck {whole_witness:>6}");
    println!(
        "  reads alone    Split {:>6}   WitnessCheck {:>6}   ratio {:.1}x",
        whole_split - base_split,
        whole_witness - base_witness,
        (whole_split - base_split) as f64 / (whole_witness - base_witness) as f64
    );
}
