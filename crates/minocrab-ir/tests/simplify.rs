//! `passes::simplify` on hand-built streams: each rule, and each
//! refusal that keeps it sound (notes/ir-passes.org §14).
//!
//! The streams are written out instruction by instruction so the
//! expectation does not go through the code under test. Every name is a
//! `Native` circuit argument unless the stream defines it.

use minocrab_ir::passes::{simplify, simplify_with, Rules};
use minocrab_ir::{Builder, IrType};
use minocrab_zkir::{Identifier, Instruction as I, Operand};
use minocrab_zkir::Fr;

fn id(s: &str) -> Identifier {
    Identifier(s.to_string())
}

fn v(s: &str) -> Operand {
    Operand::Variable(id(s))
}

fn imm(x: u64) -> Operand {
    Operand::Immediate(Fr::from(x))
}

/// The dead-code rule alone.
fn drop_dead_pure(stream: Vec<I>, natives: &[Identifier], observed: &[Identifier]) -> Vec<I> {
    simplify_with(stream, natives, observed, Rules { dead_pure: true, ..Rules::NONE })
}

/// The merge rule alone; `determined` includes the instructions that also
/// constrain their operands.
fn merge_common_subexpressions(stream: Vec<I>, natives: &[Identifier], observed: &[Identifier], determined: bool) -> Vec<I> {
    simplify_with(stream, natives, observed, Rules { merge_pure: true, merge_determined: determined, ..Rules::NONE })
}

/// The constant-select rule alone.
fn constant_selects(stream: Vec<I>, observed: &[Identifier]) -> Vec<I> {
    simplify_with(stream, &natives(), observed, Rules { constant_selects: true, ..Rules::NONE })
}

/// The arguments every stream below may read, all `Native`.
fn natives() -> Vec<Identifier> {
    ["x", "y", "z"].into_iter().map(id).collect()
}

fn mul(a: Operand, b: Operand, out: &str) -> I {
    I::Mul { a, b, output: id(out) }
}

fn add(a: Operand, b: Operand, out: &str) -> I {
    I::Add { a, b, output: id(out) }
}

fn output(vals: &[&str]) -> I {
    I::Output { vals: vals.iter().map(|s| v(s)).collect() }
}

// ---- rule 1: dead pure instructions -----------------------------------------------

#[test]
fn a_pure_instruction_nothing_reads_is_dropped() {
    let stream = vec![mul(v("x"), v("y"), "m"), add(v("x"), imm(1), "dead"), output(&["m"])];
    let want = vec![mul(v("x"), v("y"), "m"), output(&["m"])];
    assert_eq!(drop_dead_pure(stream, &natives(), &[]), want);
}

#[test]
fn dead_code_is_dropped_to_a_fixed_point_in_one_call() {
    // `c` reads `b` reads `a`, and nothing reads `c`: all three go.
    let stream = vec![
        mul(v("x"), v("y"), "a"),
        add(v("a"), imm(1), "b"),
        mul(v("b"), v("b"), "c"),
        output(&["x"]),
    ];
    let once = drop_dead_pure(stream, &natives(), &[]);
    assert_eq!(once, vec![output(&["x"])]);
    assert_eq!(drop_dead_pure(once.clone(), &natives(), &[]), once, "idempotent");
}

#[test]
fn a_value_read_by_a_constraint_an_impact_an_assert_or_the_output_is_live() {
    let stream = vec![
        mul(v("x"), v("y"), "a"),
        mul(v("x"), v("z"), "b"),
        add(v("x"), imm(2), "c"),
        add(v("y"), imm(2), "d"),
        I::ConstrainBits { val: v("a"), bits: 8 },
        I::Impact { guard: imm(1), inputs: vec![imm(0x11), v("b")] },
        I::Assert { cond: v("c") },
        output(&["d"]),
    ];
    assert_eq!(drop_dead_pure(stream.clone(), &natives(), &[]), stream);
}

#[test]
fn a_disclosed_value_stays_defined_though_nothing_reads_it() {
    let stream = vec![mul(v("x"), v("y"), "secret"), output(&[])];
    assert_eq!(drop_dead_pure(stream.clone(), &natives(), &[id("secret")]), stream);
}

#[test]
fn an_unused_instruction_that_constrains_its_operands_is_kept() {
    // Each of these looks dead: no output is read. Each constrains an
    // operand, so deleting it would accept witnesses the circuit rejects.
    let stream = vec![
        // The selector must be a bit.
        I::CondSelect { bit: v("x"), a: v("y"), b: v("z"), output: id("s") },
        // The operand must be a bit.
        I::Not { a: v("x"), output: id("n") },
        // Both operands must fit 8 bits.
        I::LessThan { a: v("x"), b: v("y"), bits: 8, output: id("l") },
        // The operand must not be zero.
        I::Inv { a: v("z"), output: id("i") },
        // The halves must recompose below the modulus.
        I::ReconstituteField { divisor: v("x"), modulus: v("y"), bits: 8, output: id("r") },
        output(&[]),
    ];
    assert_eq!(drop_dead_pure(stream.clone(), &natives(), &[]), stream);
    assert_eq!(simplify(stream.clone(), &natives(), &[]), stream);
}

#[test]
fn transcript_reads_are_never_dropped() {
    let stream = vec![
        I::PrivateInput { guard: None, val_t: IrType::Native, output: id("w") },
        I::PublicInput { guard: None, val_t: IrType::Native, output: id("p") },
        output(&[]),
    ];
    assert_eq!(simplify(stream.clone(), &natives(), &[]), stream);
}

#[test]
fn arithmetic_on_a_value_not_known_to_be_native_is_left_alone() {
    // `q` is an argument the caller did not declare Native (a point, say):
    // `add` on points is not in the table, so it is kept.
    let stream = vec![add(v("q"), v("q"), "dead"), output(&[])];
    assert_eq!(simplify(stream.clone(), &natives(), &[]), stream);
    // Declared Native, the same instruction is dead.
    assert_eq!(simplify(stream, &[id("q")], &[]), vec![output(&[])]);
}

#[test]
fn an_unused_instruction_with_a_static_check_on_an_untracked_type_is_kept() {
    // `and` over a Native, `concat` of a Native, a zero-length slice: each
    // fails on every preimage. Deleted as dead, the circuit would accept.
    let stream = vec![
        I::And { inputs: vec![v("x")], output: id("a") },
        I::Concat { inputs: vec![v("x")], output: id("c") },
        I::Slice { bytes: v("x"), start: 0, len: 0, output: id("s") },
        I::DivModPowerOfTwo { val: v("x"), bits: 300, outputs: vec![id("hi"), id("lo")] },
        output(&[]),
    ];
    assert_eq!(drop_dead_pure(stream.clone(), &natives(), &[]), stream);
}

#[test]
fn a_dead_div_mod_is_dropped() {
    let stream = vec![
        I::DivModPowerOfTwo { val: v("x"), bits: 8, outputs: vec![id("hi"), id("lo")] },
        output(&[]),
    ];
    assert_eq!(drop_dead_pure(stream, &natives(), &[]), vec![output(&[])]);
}

#[test]
fn a_div_mod_with_one_used_output_stays() {
    let stream = vec![
        I::DivModPowerOfTwo { val: v("x"), bits: 8, outputs: vec![id("hi"), id("lo")] },
        output(&["lo"]),
    ];
    assert_eq!(drop_dead_pure(stream.clone(), &natives(), &[]), stream);
}

// ---- rule 2: common subexpressions --------------------------------------------------

#[test]
fn a_repeated_pure_instruction_is_merged_into_the_first() {
    let stream = vec![
        mul(v("x"), v("y"), "a"),
        mul(v("x"), v("y"), "b"),
        add(v("a"), v("b"), "s"),
        output(&["b", "s"]),
    ];
    let want = vec![mul(v("x"), v("y"), "a"), add(v("a"), v("a"), "s"), output(&["a", "s"])];
    assert_eq!(merge_common_subexpressions(stream, &natives(), &[], true), want);
}

#[test]
fn merging_is_transitive_through_renamed_operands() {
    // After `b` becomes `a`, `d = b + 1` is `c = a + 1` again.
    let stream = vec![
        mul(v("x"), v("y"), "a"),
        add(v("a"), imm(1), "c"),
        mul(v("x"), v("y"), "b"),
        add(v("b"), imm(1), "d"),
        output(&["d"]),
    ];
    let want = vec![mul(v("x"), v("y"), "a"), add(v("a"), imm(1), "c"), output(&["c"])];
    assert_eq!(merge_common_subexpressions(stream, &natives(), &[], true), want);
}

#[test]
fn different_operands_order_or_attributes_do_not_merge() {
    let stream = vec![
        add(v("x"), v("y"), "a"),
        add(v("y"), v("x"), "b"),
        I::LessThan { a: v("x"), b: v("y"), bits: 8, output: id("l8") },
        I::LessThan { a: v("x"), b: v("y"), bits: 16, output: id("l16") },
        output(&["a", "b", "l8", "l16"]),
    ];
    assert_eq!(merge_common_subexpressions(stream.clone(), &natives(), &[], true), stream);
}

#[test]
fn a_determined_instruction_merges_across_a_non_pure_one_because_its_twin_imposes_the_same_constraint() {
    // ZKIR has no control flow: every instruction is laid down, so the
    // assert between the two selects orders nothing. The first select
    // already constrains `x` to a bit; the second adds nothing.
    let stream = vec![
        I::CondSelect { bit: v("x"), a: v("y"), b: v("z"), output: id("s") },
        I::Assert { cond: v("y") },
        I::CondSelect { bit: v("x"), a: v("y"), b: v("z"), output: id("t") },
        output(&["t"]),
    ];
    let want = vec![
        I::CondSelect { bit: v("x"), a: v("y"), b: v("z"), output: id("s") },
        I::Assert { cond: v("y") },
        output(&["s"]),
    ];
    assert_eq!(merge_common_subexpressions(stream.clone(), &natives(), &[], true), want);
    // With determined instructions excluded, they stay apart.
    assert_eq!(merge_common_subexpressions(stream, &natives(), &[], false).len(), 4);
}

#[test]
fn reads_constraints_and_impacts_are_never_merged() {
    let stream = vec![
        I::PublicInput { guard: None, val_t: IrType::Native, output: id("p") },
        I::PublicInput { guard: None, val_t: IrType::Native, output: id("q") },
        I::PrivateInput { guard: None, val_t: IrType::Native, output: id("w") },
        I::PrivateInput { guard: None, val_t: IrType::Native, output: id("u") },
        I::ConstrainBits { val: v("x"), bits: 8 },
        I::ConstrainBits { val: v("x"), bits: 8 },
        I::Impact { guard: imm(1), inputs: vec![v("x")] },
        I::Impact { guard: imm(1), inputs: vec![v("x")] },
        I::Assert { cond: v("x") },
        I::Assert { cond: v("x") },
        output(&["p", "q", "w", "u"]),
    ];
    assert_eq!(simplify(stream.clone(), &natives(), &[]), stream);
}

#[test]
fn a_disclosed_duplicate_is_kept_under_its_own_name() {
    let stream = vec![mul(v("x"), v("y"), "a"), mul(v("x"), v("y"), "b"), output(&["a"])];
    assert_eq!(merge_common_subexpressions(stream.clone(), &natives(), &[id("b")], true), stream);
}

#[test]
fn simplify_merges_then_drops_what_merging_left_dead() {
    // Merging `b` into `a` leaves `b`'s consumer reading `a`; the stray
    // `dead` goes, and nothing else does.
    let stream = vec![
        mul(v("x"), v("y"), "a"),
        mul(v("x"), v("y"), "b"),
        add(v("a"), v("b"), "s"),
        add(v("x"), v("x"), "dead"),
        output(&["s"]),
    ];
    let want = vec![mul(v("x"), v("y"), "a"), add(v("a"), v("a"), "s"), output(&["s"])];
    let once = simplify(stream, &natives(), &[]);
    assert_eq!(once, want);
    assert_eq!(simplify(once.clone(), &natives(), &[]), once, "idempotent");
}

#[test]
fn natives_are_inferred_forward_from_the_definitions() {
    // `t` is a `test_eq` result, always Native; `p` a public input declared
    // Native. Arithmetic on them is in the table even though neither is an
    // argument.
    let stream = vec![
        I::TestEq { a: v("x"), b: v("y"), output: id("t") },
        I::PublicInput { guard: None, val_t: IrType::Native, output: id("p") },
        add(v("t"), v("p"), "a"),
        add(v("t"), v("p"), "b"),
        output(&["a", "b"]),
    ];
    let got = simplify(stream, &natives(), &[]);
    assert_eq!(got.len(), 4);
    assert_eq!(got[3], output(&["a", "a"]));
}

// ---- rule 3: a select on a constant selector --------------------------------------

fn select(bit: Operand, a: Operand, b: Operand, out: &str) -> I {
    I::CondSelect { bit, a, b, output: id(out) }
}

#[test]
fn a_select_on_one_is_its_first_arm_and_on_zero_its_second() {
    let stream = vec![
        select(imm(1), v("x"), v("y"), "s"),
        select(imm(0), v("x"), v("y"), "t"),
        add(v("s"), v("t"), "u"),
        output(&["u", "s"]),
    ];
    assert_eq!(constant_selects(stream, &[]), vec![add(v("x"), v("y"), "u"), output(&["u", "x"])]);
}

#[test]
fn a_select_on_any_other_immediate_can_never_be_satisfied_and_is_kept() {
    let stream = vec![select(imm(2), v("x"), v("y"), "s"), output(&["s"])];
    assert_eq!(simplify(stream.clone(), &natives(), &[]), stream);
}

#[test]
fn a_constant_select_choosing_an_immediate_or_a_disclosed_one_is_kept() {
    let stream = vec![
        select(imm(1), imm(5), v("y"), "s"),
        select(imm(0), v("x"), v("y"), "t"),
        output(&["s", "t"]),
    ];
    assert_eq!(constant_selects(stream.clone(), &[id("t")]), stream);
}

#[test]
fn a_select_on_a_variable_selector_is_not_a_constant_select() {
    // Even with equal arms: `cond_select g x x` is `x` only where `g` is a
    // bit, and deleting it would drop the constraint that makes it one.
    let stream = vec![select(v("z"), v("x"), v("x"), "s"), output(&["s"])];
    assert_eq!(simplify(stream.clone(), &natives(), &[]), stream);
}

// ---- through the builder ------------------------------------------------------------

/// `Builder::simplify` runs the rule after the fold and the true-assert
/// drop, and the map it composes sends each surviving instruction to where
/// it landed (the debug build re-checks every position, renames included).
#[test]
fn the_builder_runs_it_after_the_fold_and_maps_its_indices() {
    let mut b = Builder::new();
    let x = b.input("x", IrType::Native);
    let y = b.input("y", IrType::Native);
    let one = b.copy(minocrab_ir::Arg::Imm(Fr::from(1u64)));
    let m1 = b.mul(x, y);
    let m2 = b.mul(x, y);
    let _dead = b.add(x, one);
    let s = b.add(m1, m2);
    b.output(&[s.into()]);
    b.simplify(true, Vec::new());
    let (ir, kept) = b.finish_kept(false);
    // copy (folded), mul, mul (merged), add-one (dead), add, output.
    assert_eq!(ir.instructions.len(), 3);
    assert_eq!(kept.position(0), None);
    assert_eq!(kept.position(1), Some(0));
    assert_eq!(kept.position(2), None);
    assert_eq!(kept.position(3), None);
    assert_eq!(kept.position(4), Some(1));
    assert_eq!(kept.position(5), Some(2));
}

#[test]
fn the_builder_leaves_it_off_by_default() {
    let mut b = Builder::new();
    let x = b.input("x", IrType::Native);
    let _ = b.mul(x, x);
    let _ = b.mul(x, x);
    b.output(&[]);
    assert_eq!(b.finish(false).instructions.len(), 3);
}
