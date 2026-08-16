//! WHAT THE ZKIR BACKEND ALREADY FOLDS — the measurements our API design
//! rests on, pinned so they cannot rot silently.
//!
//! Every "optimisation" we might do above ZKIR is either duplicating the
//! backend's work or doing something it does not do, and the difference is
//! not guessable — it is Midnight's own cost model
//! (`minocrab_sim::v3::cost`, the same one `row_snapshot` and the benchmark
//! harness use). This file measures it directly: build a baseline circuit,
//! build it again with a redundancy added, and price the difference.
//!
//! THE TABLE, as measured (rows per redundant instruction):
//!
//! | pattern | rows each | backend folds it? |
//! |---|---|---|
//! | `copy` of an immediate | **0** | YES |
//! | linear op with a constant operand (`add x, 0`) | **0** | YES |
//! | unused pure instruction (dead code) | 1 | no |
//! | duplicated pure instruction (common subexpression) | 1 | no |
//! | repeated `constrain_bits` on the same wire | **2** | no |
//!
//! WHAT THAT DECIDES, and why this file is worth its weight:
//!
//! - Constant folding above ZKIR buys ZERO rows. Every API contortion we
//!   have made to avoid emitting a `copy` of an immediate — M9 phase 7's
//!   operand positions, M9 phase 8's inlined guard, M16's
//!   `AnyWire3::immediate`, M17's `UnshieldedToken` — was bought for
//!   DIFFERENTIAL FIDELITY with compactc, not for cost. Worth knowing
//!   before paying for a fifth.
//! - Dead code and common subexpressions are NOT folded, so they are real
//!   rows. Whether to remove them above ZKIR is a separate question (dead
//!   code elimination is unsound over effectful instructions; common
//!   subexpression elimination over ledger reads changes the transcript —
//!   notes/ir-passes.org).
//! - A repeated range constraint is the most expensive redundancy of the
//!   five, at TWICE a multiply. That is what makes "every gadget asserts
//!   its own preconditions" costly today, and it is the strongest argument
//!   for a deduplicating pass.
//!
//! If a toolchain bump changes any of these, this test fails and the
//! reasoning above has to be redone rather than quietly inherited.

use minocrab::v3::{Circuit3, FieldT};
use minocrab_sim::v3::cost;

/// Rows of a circuit built by `build`.
fn rows(build: impl FnOnce(&mut Circuit3)) -> usize {
    let mut c = Circuit3::new();
    build(&mut c);
    cost(&c.finish(true).ir).1
}

/// The baseline every case below adds to: two arguments and one multiply.
fn baseline(c: &mut Circuit3) -> (minocrab::v3::Wire3<FieldT, minocrab::Private>, minocrab::v3::Wire3<FieldT, minocrab::Private>) {
    (c.arg::<FieldT>("x"), c.arg::<FieldT>("y"))
}

const N: usize = 5;

#[test]
fn a_copy_of_an_immediate_is_free() {
    let base = rows(|c| {
        let (x, y) = baseline(c);
        let z = c.mul(x, y);
        c.assert(z);
    });
    let with = rows(|c| {
        let (x, y) = baseline(c);
        for _ in 0..N {
            let _ = c.constant(7u64);
        }
        let z = c.mul(x, y);
        c.assert(z);
    });
    assert_eq!(with, base, "{N} copies of an immediate should cost nothing");
}

#[test]
fn a_linear_op_with_a_constant_operand_is_free() {
    let base = rows(|c| {
        let (x, y) = baseline(c);
        let z = c.mul(x, y);
        c.assert(z);
    });
    let with = rows(|c| {
        let (x, y) = baseline(c);
        let mut w = x;
        for _ in 0..N {
            w = c.add(w, 0u64);
        }
        let z = c.mul(w, y);
        c.assert(z);
    });
    assert_eq!(with, base, "{N} add-zeroes should cost nothing");
}

#[test]
fn dead_code_is_not_eliminated() {
    let base = rows(|c| {
        let (x, y) = baseline(c);
        let z = c.mul(x, y);
        c.assert(z);
    });
    let with = rows(|c| {
        let (x, y) = baseline(c);
        for _ in 0..N {
            let _ = c.mul(x, y);
        }
        let z = c.mul(x, y);
        c.assert(z);
    });
    assert_eq!(
        with - base,
        N,
        "an unused multiply should cost one row — the backend does not drop it"
    );
}

#[test]
fn common_subexpressions_are_not_eliminated() {
    let base = rows(|c| {
        let (x, y) = baseline(c);
        let z = c.mul(x, y);
        c.assert(z);
    });
    let with = rows(|c| {
        let (x, y) = baseline(c);
        let mut acc = c.mul(x, y);
        for _ in 0..N {
            let m = c.mul(x, y);
            acc = c.add(acc, m);
        }
        c.assert(acc);
    });
    // N duplicate multiplies plus the N adds that keep them live.
    assert_eq!(
        with - base,
        2 * N,
        "identical multiplies should each cost a row — the backend does not dedupe them"
    );
}

#[test]
fn a_repeated_range_constraint_is_the_costliest_redundancy() {
    let base = rows(|c| {
        let (x, y) = baseline(c);
        let z = c.mul(x, y);
        c.assert(z);
    });
    let with = rows(|c| {
        let (x, y) = baseline(c);
        for _ in 0..N {
            c.assert_bits(x, 8);
        }
        let z = c.mul(x, y);
        c.assert(z);
    });
    assert_eq!(
        with - base,
        2 * N,
        "a repeated constrain_bits should cost two rows — twice a multiply, \
         and the reason gadgets cannot cheaply assert their own preconditions"
    );
}
