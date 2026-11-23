//! The simplification pass (notes/ir-passes.org §14) on random
//! `Circuit` programs, run through the simulator and upstream's own
//! `IrSource::check` with the pass off and on, on the same preimages.
//!
//! Each program draws from native arithmetic, comparisons, selects (on
//! wires and on the immediates 0, 1 and the never-satisfiable 2), `not`,
//! `inv`, `less_than`, `div_mod`, Poseidon, range constraints and asserts,
//! with a deliberate share of exact repeats (the merge rule's food) and of
//! results nothing reads (the dead-code rule's), some of them disclosed,
//! pushed through an Impact or returned. The inputs are drawn small, so
//! selectors are bits and comparisons fit their width only sometimes: a
//! good share of runs reject, and must keep rejecting.
//!
//! Per run: the same verdict from both builds under both walks; on accept,
//! the same public-input vector, skips, outputs, witnesses consumed and the
//! same disclosed values (which resolve by name, so a disclosure record
//! pointing at a deleted value would show as "<not computed>"); the same
//! assert messages. `Circuit::finish`'s debug checks re-prove every
//! surviving instruction's position, renames included, on every build. A
//! fixed seed, so a failure reproduces.

use std::borrow::Cow;

use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage, Zkir};
use minocrab::{Circuit, Compiled, FieldT, Lowering, Wire};
use minocrab::{Private, Public};
use minocrab_sim::{report, simulate, simulate_with, Mode};
use minocrab_zkir::Fr;

/// xorshift64, fixed seed (as `metadata`).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

type W = Wire<FieldT, Private>;

/// The op a step emitted, kept so a later step can repeat it exactly.
#[derive(Clone, Copy)]
enum Op {
    Add(W, W),
    Mul(W, W),
    Neg(W),
    TestEq(W, W),
    Select(W, W, W),
    /// A select on an immediate selector: 0 and 1 choose, 2 never holds.
    ConstSelect(u64, W, W),
    Not(W),
    Inv(W),
    Less(W, W, u32),
    DivMod(W, u32),
    Hash(W, W),
}

fn emit(c: &mut Circuit, op: Op) -> W {
    match op {
        Op::Add(a, b) => c.add(a, b),
        Op::Mul(a, b) => c.mul(a, b),
        Op::Neg(a) => c.neg(a),
        Op::TestEq(a, b) => c.test_eq(a, b),
        Op::Select(s, a, b) => c.cond_select(s, a, b),
        Op::ConstSelect(k, a, b) => c.cond_select(k, a, b),
        Op::Not(a) => c.not(a),
        Op::Inv(a) => c.inv(a),
        Op::Less(a, b, bits) => c.less_than(a, b, bits),
        Op::DivMod(a, bits) => c.div_mod_power_of_two(a, bits).1,
        Op::Hash(a, b) => c.transient_hash(&[a, b]),
    }
}

/// Build program `seed` with the pass `on` or off. Deterministic in the
/// seed, so the two builds are the same program.
fn build(seed: u64, nargs: usize, on: bool) -> Compiled {
    let mut r = Rng(seed);
    let mut c = Circuit::new();
    c.set_lowering(Lowering { simplify: on, ..c.lowering() });
    let mut pool: Vec<W> = (0..nargs).map(|k| c.arg::<FieldT>(&format!("a{k}"))).collect();
    let mut ops: Vec<Op> = Vec::new();
    let mut public: Vec<Wire<FieldT, Public>> = Vec::new();
    let steps = 4 + r.below(20);
    for step in 0..steps {
        let pick = |r: &mut Rng| pool[r.below(pool.len() as u64) as usize];
        let op = match r.below(15) {
            // An exact repeat of an earlier op.
            0..=2 if !ops.is_empty() => ops[r.below(ops.len() as u64) as usize],
            0..=3 => Op::Add(pick(&mut r), pick(&mut r)),
            4 => Op::Mul(pick(&mut r), pick(&mut r)),
            5 => Op::Neg(pick(&mut r)),
            6 => Op::TestEq(pick(&mut r), pick(&mut r)),
            7 => Op::Select(pick(&mut r), pick(&mut r), pick(&mut r)),
            8 => Op::Not(pick(&mut r)),
            9 => Op::Inv(pick(&mut r)),
            10 => Op::Less(pick(&mut r), pick(&mut r), [4, 8][r.below(2) as usize]),
            11 => Op::DivMod(pick(&mut r), [1, 3][r.below(2) as usize]),
            12 => Op::Hash(pick(&mut r), pick(&mut r)),
            13 => Op::ConstSelect([0, 1, 1, 0, 2][r.below(5) as usize], pick(&mut r), pick(&mut r)),
            _ => {
                // A statement on a pool value: an assert, or a range check.
                let w = pick(&mut r);
                if r.below(2) == 0 {
                    c.assert_with(w, Some(&format!("m{step}")));
                } else {
                    c.assert_bits(w, 2);
                }
                continue;
            }
        };
        ops.push(op);
        let w = c.region(&format!("r{step}"), |c| emit(c, op));
        // What becomes of the result: mostly a pool value later steps may
        // read; sometimes disclosed, pushed through an Impact, or returned;
        // sometimes nothing at all (dead unless something else reads it).
        match r.below(6) {
            0 => {
                public.push(c.disclose(w, &format!("d{step}")));
            }
            1 => {
                let p = c.disclose(w, &format!("i{step}"));
                c.impact(1u64, &[p]);
            }
            2 => {}
            _ => pool.push(w),
        }
    }
    for (k, p) in public.iter().enumerate() {
        if k % 2 == 0 {
            c.output(*p, &format!("o{k}"));
        }
    }
    c.finish(false)
}

fn preimage(inputs: &[Fr], public_transcript_inputs: Vec<Fr>) -> ProofPreimage {
    ProofPreimage {
        inputs: inputs.to_vec(),
        private_transcript: vec![],
        public_transcript_inputs,
        public_transcript_outputs: vec![],
        binding_input: 0.into(),
        communications_commitment: None,
        key_location: KeyLocation(Cow::Borrowed("minocrab-sim-v3")),
    }
}

/// The preimage the unsimplified circuit asks for on `inputs`: its Impact
/// inputs, gathered by the executor's walk (which records rather than
/// aborts on a failed assert, so a rejecting run still has a transcript).
fn gathered(ir: &minocrab_zkir::IrSource, inputs: &[Fr]) -> ProofPreimage {
    let transcript = simulate_with(ir, &preimage(inputs, vec![]), Mode::Gather)
        .map(|run| run.public_transcript_inputs)
        .unwrap_or_default();
    preimage(inputs, transcript)
}

#[test]
fn simplified_random_programs_accept_and_reject_the_same_preimages_with_the_same_public_inputs() {
    let mut seeds = Rng(0x5eed_0f_51_4d_11fe);
    let (mut runs, mut accepted, mut rejected, mut shrunk, mut deleted) = (0usize, 0usize, 0usize, 0usize, 0usize);
    for program in 0..3_000 {
        let seed = seeds.next() | 1;
        let nargs = 1 + (seed % 4) as usize;
        let off = build(seed, nargs, false);
        let on = build(seed, nargs, true);
        assert!(on.ir.instructions.len() <= off.ir.instructions.len(), "program {program}: the pass only deletes");
        let gone = off.ir.instructions.len() - on.ir.instructions.len();
        shrunk += usize::from(gone > 0);
        deleted += gone;
        assert_eq!(on.disclosures, off.disclosures, "program {program}: the records are untouched");
        let messages = |c: &Compiled| c.assert_messages.iter().map(|m| m.message.clone()).collect::<Vec<_>>();
        assert_eq!(messages(&on), messages(&off), "program {program}: no assert is deleted");
        assert_eq!(on.regions.len(), off.regions.len());
        for _ in 0..4 {
            let inputs: Vec<Fr> = (0..nargs)
                .map(|_| match seeds.below(8) {
                    0 => Fr::from(u64::MAX),
                    k => Fr::from(k % 4),
                })
                .collect();
            let pi = gathered(&off.ir, &inputs);
            runs += 1;
            let (a, b) = (simulate(&off.ir, &pi), simulate(&on.ir, &pi));
            let (ua, ub) = (off.ir.check(&pi), on.ir.check(&pi));
            assert_eq!(a.is_ok(), b.is_ok(), "program {program} {inputs:?}: simulator verdicts\n{a:?}\n{b:?}");
            assert_eq!(ua.is_ok(), ub.is_ok(), "program {program} {inputs:?}: upstream verdicts\n{ua:?}\n{ub:?}");
            assert_eq!(a.is_ok(), ua.is_ok(), "program {program} {inputs:?}: simulator vs upstream");
            match (a, b) {
                (Ok(a), Ok(b)) => {
                    accepted += 1;
                    assert_eq!(a.pis, b.pis, "program {program}: public inputs");
                    assert_eq!(a.pi_skips, b.pi_skips, "program {program}: skips");
                    assert_eq!(a.outputs, b.outputs, "program {program}: outputs");
                    assert_eq!(a.consumed_private, b.consumed_private);
                    assert_eq!(ua.unwrap(), ub.unwrap(), "program {program}: upstream skips");
                    let (ra, rb) = (report(&a, &off.disclosures), report(&b, &on.disclosures));
                    assert_eq!(format!("{:?}", ra.disclosures), format!("{:?}", rb.disclosures), "program {program}: disclosed values");
                    assert!(
                        rb.disclosures.iter().all(|d| d.values.iter().all(|v| v != "<not computed>")),
                        "program {program}: a disclosure names a deleted value"
                    );
                }
                (Err(_), Err(_)) => rejected += 1,
                _ => unreachable!(),
            }
        }
    }
    // The programs exercise both rules and both verdicts.
    assert!(shrunk > 1_000 && deleted > 3_000, "{shrunk} programs shrank, {deleted} instructions deleted");
    assert!(accepted > 1_000 && rejected > 1_000, "{runs} runs: {accepted} accepted, {rejected} rejected");
    println!("{runs} runs: {accepted} accepted, {rejected} rejected; {shrunk} programs shrank by {deleted} instructions");
}
