//! First real differential test (M3/M4): compactc's compiled artifact vs
//! the same logic built from minocrab-std, same inputs, same results.
//!
//! `tiny.compact`'s `public_key(sk)` is
//! `persistentHash<Vector<2, Bytes<32>>>([pad(32, "lares:tiny:pk:"), sk])`,
//! and it is inlined into the corpus golden `set.zkir` with the digest at
//! slots 12 (hi limb) and 13 (lo limb) — pinned by the corpus rev. We run
//! the golden through the simulator and compare those slots against our
//! stdlib port's output. This exercises the whole stack: Bytes<32> limb
//! order, pad literals, FAB alignment, persistent_hash.

use minocrab::{Circuit, Fr, Private};
use minocrab_sim::simulate;
use minocrab_std::{persistent_hash, Bundle, Bytes32};

fn corpus_zkir(rel: &str) -> minocrab::IrSource {
    let path = format!("{}/../../corpus/zkir/{rel}", env!("CARGO_MANIFEST_DIR"));
    minocrab_zkir::read_zkir(&path).expect("corpus golden parses")
}

/// The digest slots persistent_hash writes in tiny's `set` circuit (see
/// module docs; verified against the instruction listing).
const SET_DIGEST_HI: usize = 12;
const SET_DIGEST_LO: usize = 13;

fn compactc_public_key(sk_hi: Fr, sk_lo: Fr) -> (Fr, Fr) {
    let mut ir = corpus_zkir("compact/examples/tiny/zkir/set.zkir");
    // The simulator doesn't model communications commitments (they affect
    // PI framing, not instruction semantics); drop the flag for this
    // value-level comparison.
    ir.do_communications_commitment = false;

    // set(v): argument v; witness = sk (2 limbs); the ledger `state` read
    // consumes one public-transcript output (0 = STATE.unset, so the
    // in_state assert passes).
    let run = simulate(&ir, &[Fr::from(7u64)], &[sk_hi, sk_lo], &[Fr::from(0u64)])
        .expect("corpus set.zkir simulates");
    (run.memory[SET_DIGEST_HI], run.memory[SET_DIGEST_LO])
}

fn minocrab_public_key(sk_hi: Fr, sk_lo: Fr) -> (Fr, Fr) {
    let (mut c, _) = Circuit::new(0);
    let sk = Bytes32::<Private>::from_limbs(vec![c.witness(), c.witness()]);
    sk.constrain_input(&mut c);
    let pad = Bytes32::pad(&mut c, "lares:tiny:pk:");
    let digest = persistent_hash(&mut c, &[pad, sk]);
    let hi = c.disclose(digest.hi(), "pk digest hi");
    let lo = c.disclose(digest.lo(), "pk digest lo");
    c.output(hi, "hi");
    c.output(lo, "lo");
    let compiled = c.finish();

    let run = simulate(&compiled.ir, &[], &[sk_hi, sk_lo], &[]).expect("our circuit simulates");
    (run.outputs[0], run.outputs[1])
}

#[test]
fn public_key_digest_matches_compactc() {
    // sk limb values: (hi ≤ 8 bits, lo ≤ 248 bits) per the Bytes<32> input
    // constraints, covering zero, small, and max-boundary cases.
    let max_lo = {
        // 2^248 - 1
        let bytes = [0xffu8; 31];
        Fr::from_le_bytes(&bytes).unwrap()
    };
    let cases = [
        (Fr::from(0u64), Fr::from(0u64)),
        (Fr::from(1u64), Fr::from(2u64)),
        (Fr::from(0xffu64), max_lo),
        (Fr::from(0x42u64), Fr::from(0xdeadbeefu64)),
    ];
    for (sk_hi, sk_lo) in cases {
        let theirs = compactc_public_key(sk_hi, sk_lo);
        let ours = minocrab_public_key(sk_hi, sk_lo);
        assert_eq!(ours, theirs, "digest mismatch for sk=({sk_hi:?}, {sk_lo:?})");
    }
}

#[test]
fn coin_preimage_alignment_matches_compact_declaration() {
    use minocrab::AlignmentAtom as A;
    // ShieldedCoinInfo = {nonce: Bytes<32>, color: Bytes<32>, value: Uint<128>}
    let mut atoms = Vec::new();
    minocrab_std::ShieldedCoinInfo::<Private>::push_atoms(&mut atoms);
    assert_eq!(
        atoms,
        vec![
            A::Bytes { length: 32 },
            A::Bytes { length: 32 },
            A::Bytes { length: 16 },
        ]
    );
}
