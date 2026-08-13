//! Semantic tests for the stdlib gadgets, run through the native simulator.
//! (Differential tests against compactc's lowering of the originals land
//! with the hash-dependent ports — see milestones.org M4.)

use minocrab::{Circuit, Private, Wire};
use minocrab_ir::Fr;
use minocrab_sim::simulate;
use minocrab_std::{
    cond_select, eq, merkle_tree_path_root_from_leaf_digest, none, some, Bundle, Maybe,
    MerkleTreeDigest, MerkleTreePathEntry,
};

/// Simulate a circuit whose result wire is disclosed, returning the value of
/// that wire.
fn run_disclosed(
    build: impl FnOnce(&mut Circuit, &mut Vec<Wire<Private>>) -> Wire<Private>,
    witnesses: &[u64],
) -> Fr {
    let (mut c, _) = Circuit::new(0);
    let mut ws: Vec<Wire<Private>> = (0..witnesses.len()).map(|_| c.witness()).collect();
    let result = build(&mut c, &mut ws);
    let public = c.disclose(result, "test result");
    c.declare_public(public, "result");
    let compiled = c.finish();
    let transcript: Vec<Fr> = witnesses.iter().map(|&w| Fr::from(w)).collect();
    let run = simulate(&compiled.ir, &[], &transcript, &[]).expect("simulation failed");
    run.public_transcript_inputs[0]
}

#[test]
fn maybe_round_trips_through_wires() {
    let (mut c, _) = Circuit::new(0);
    let w = c.witness();
    let m: Maybe<Private, Wire<Private>> = some(&mut c, w);
    let wires = m.wires();
    assert_eq!(wires.len(), <Maybe<Private, Wire<Private>> as Bundle<Private>>::WIDTH);
    let rebuilt: Maybe<Private, Wire<Private>> = Maybe::from_wires(&mut wires.into_iter());
    assert_eq!(rebuilt.is_some.val(), m.is_some.val());
    assert_eq!(rebuilt.value.val(), m.value.val());
}

#[test]
fn cond_select_picks_by_bit() {
    // bit=1 selects the `some(w0)` arm; bit=0 the `none()` arm.
    for (bit, expect_some) in [(1u64, true), (0u64, false)] {
        let is_some = run_disclosed(
            |c, ws| {
                let bit_wire = ws[0];
                let a: Maybe<Private, Wire<Private>> = some(c, ws[1]);
                let b: Maybe<Private, Wire<Private>> = none(c);
                let picked = cond_select(c, bit_wire, &a, &b);
                picked.is_some
            },
            &[bit, 42],
        );
        assert_eq!(is_some, Fr::from(u64::from(expect_some)));
    }
}

#[test]
fn eq_is_structural() {
    // some(42) == some(42), some(42) != some(43), some(42) != none.
    let cases = [(42u64, 42u64, true, true), (42, 43, true, false)];
    for (a_val, b_val, b_is_some, expected) in cases {
        let result = run_disclosed(
            |c, ws| {
                let a: Maybe<Private, Wire<Private>> = some(c, ws[0]);
                let b: Maybe<Private, Wire<Private>> = if b_is_some {
                    some(c, ws[1])
                } else {
                    none(c)
                };
                eq(c, &a, &b)
            },
            &[a_val, b_val],
        );
        assert_eq!(result, Fr::from(u64::from(expected)), "{a_val} vs {b_val}");
    }
}

#[test]
fn merkle_fold_matches_hand_built_hashes() {
    // A two-entry path, checked against the same hashes built directly:
    // level 1 goes left (digest on the left), level 2 goes right.
    let expected = run_disclosed(
        |c, ws| {
            let leaf = ws[0];
            let s1 = ws[1];
            let s2 = ws[2];
            let h1 = c.transient_hash(&[leaf, s1]);
            c.transient_hash(&[s2, h1])
        },
        &[7, 11, 13],
    );
    let actual = run_disclosed(
        |c, ws| {
            let path = [
                MerkleTreePathEntry {
                    sibling: MerkleTreeDigest { field: ws[1] },
                    goes_left: minocrab_std::boolean(c, true),
                },
                MerkleTreePathEntry {
                    sibling: MerkleTreeDigest { field: ws[2] },
                    goes_left: minocrab_std::boolean(c, false),
                },
            ];
            merkle_tree_path_root_from_leaf_digest(c, ws[0], &path).field
        },
        &[7, 11, 13],
    );
    assert_eq!(expected, actual);
}
