//! IR passes — the ones that buy API, per notes/ir-passes.org.
//!
//! The standing criterion (dmd, 2026-08-16) is that a pass earns its place by
//! letting us write SIMPLER code higher up, not by saving rows: the backend
//! already folds a `Copy` of an immediate to zero rows, measured in
//! `minocrab-contracts/tests/backend_folding.rs` and again in
//! `minocrab-sim/examples/opcost.rs` (100 `Copy`s cost 0 rows; 100
//! `cond_select`s cost 101).
//!
//! And the constraint no pass may break: our primary correctness warrant is
//! DIFFERENTIAL EQUALITY with compactc, instruction for instruction, for the
//! M14-M17 fixtures. A pass that converges on compactc is free; one that
//! diverges costs us that test and needs M10's warrant instead.

use std::collections::{HashMap, HashSet};

use minocrab_zkir::v3::{Identifier, Instruction, IrSource, Operand};

/// Fold every `Copy` of an immediate into its consumers and drop it.
///
/// This is what makes the named-immediate special cases unnecessary. Four
/// milestones running have added one — M9 phase 7's operand positions, M9
/// phase 8's inlined Impact guard, M16's `AnyWire3::immediate`, M17's
/// `UnshieldedToken` and `token_type` — each to stop a constant being NAMED
/// where compactc inlines it. None of them bought a row; all of them bought
/// differential fidelity, and a caller had to know which spelling to reach for.
/// With the fold, `c.constant(x)` and an inline `x` lower to the same stream.
///
/// # The one exception, and it is compactc's
///
/// A constant that a circuit RETURNS stays named. compactc's `Output`
/// terminator lists variables, never immediates — `sendShielded` returns the
/// zero high limb of an upgraded nonce as `%t.23`, having emitted `copy 0x00`
/// for it, and uses that same name in the commitment preimage. So the fold is
/// ALL-OR-NOTHING per copy: if any use is an output slot, the copy stays and
/// every use keeps the name. Folding it in the other positions only would
/// diverge from compactc in exactly the circuit that taught us the rule.
///
/// Immediates that reach an output slot directly (a caller writing
/// `c.output(..)` on something that was never named) are not this pass's
/// business — it only ever removes instructions it can prove are renames.
pub fn fold_immediate_copies(instructions: Vec<Instruction>) -> Vec<Instruction> {
    let named = immediate_copies(&instructions);
    if named.is_empty() {
        return instructions;
    }
    let returned = returned_identifiers(&instructions);

    // The foldable copies, chased through chains (`copy %a = 3; copy %b = %a`)
    // so that folding is a fixpoint rather than one step.
    let mut folded: HashMap<Identifier, Operand> = HashMap::new();
    for (id, imm) in &named {
        if !returned.contains(id) {
            folded.insert(id.clone(), imm.clone());
        }
    }

    let subst = |op: &mut Operand| {
        if let Operand::Variable(id) = op {
            if let Some(imm) = folded.get(id) {
                *op = imm.clone();
            }
        }
    };

    let mut out = Vec::with_capacity(instructions.len());
    for mut instruction in instructions {
        for op in operands_mut(&mut instruction) {
            subst(op);
        }
        // Drop the copy itself, now that nothing names it.
        if let Instruction::Copy { val: _, output } = &instruction {
            if folded.contains_key(output) {
                continue;
            }
        }
        out.push(instruction);
    }
    out
}

/// Drop every range constraint an earlier, equally tight or tighter one on
/// the same wire already implies.
///
/// OPT-IN, and it is the only pass here that is: this makes us strictly MORE
/// deduplicated than compactc, which re-emits. See [`crate::v3::Builder3::
/// dedup_range_constraints`] for the flag and notes/ir-passes.org §1 for why
/// it cannot be on by default.
///
/// # What it drops, and the one direction that is sound
///
/// Per IDENTIFIER, the tightest bound established so far: a
/// `ConstrainBits { bits: n }` establishes `val < 2^n`, a
/// `ConstrainToBoolean` establishes `val ∈ {0,1}` — bound 1. A later
/// constraint whose bound is `m >= n` is implied by the earlier one and is
/// removed; a later constraint that is TIGHTER (`m < n`) is new information
/// and is kept, becoming the bound from there on. The first constraint on a
/// wire is never dropped.
///
/// That is the same argument `Uint::widen` already makes for why widening
/// needs no new constraint, and it is sound in that direction only: `val <
/// 2^n` implies `val < 2^m` for `m >= n`, never the reverse.
///
/// ZKIR v3 is SSA, and more strongly than a rejecting check: upstream's
/// synthesis memory is a PUSH-ONLY `Vec` (`ir_vm.rs`, `mem_push` — an
/// instruction's output takes index `mem.len()` and no operation overwrites
/// an index), and our own `Builder3` mints a fresh identifier per output. A
/// rebinding is unrepresentable on both ends, so a bound established at one
/// point in the stream holds for the whole circuit, and "earlier" is only a
/// convention for which of two identical constraints survives.
///
/// # THE BOOLEAN FAMILY IS THE `bits = 1` FAMILY, and this was checked
///
/// The two instructions are different GADGETS and the same PREDICATE, which
/// is what a pass over a constraint system needs:
///
/// - `ConstrainToBoolean` lowers to `std.convert::<AssignedNative,
///   AssignedBit>` (`ir_vm.rs`, the arm carrying upstream's own "Yes, this
///   does insert a constraint") — an assigned bit the wire must equal, so
///   `val ∈ {0,1}`.
/// - `ConstrainBits { bits }` lowers, for the CURRENT IR minor version, to
///   `assert_lower_than_fixed(x, 2^bits)` (`ir_vm.rs`; the
///   `assigned_to_le_bits` decomposition is the V0-only arm beside it) — so
///   at `bits = 1`, `val < 2` i.e. `val ∈ {0,1}`. Both version arms enforce
///   the same set at 1 bit.
///
/// Upstream's own value semantics agree: `resolve_operand_bool` accepts 0 and
/// 1, `resolve_operand_bits(_, Some(1))` accepts exactly the values whose bits
/// above the first are zero. So the two constrain the same set and this pass
/// treats them as one family: a `ConstrainToBoolean` after a
/// `ConstrainBits(_, 1)` is dropped, and a `ConstrainBits(_, m >= 1)` after a
/// `ConstrainToBoolean` is dropped. That is not cosmetic — `Bool`'s argument
/// constraint IS `constrain_to_boolean` and its Borsh segment is one BYTE, so
/// the checked serializer's `constrain_bits(_, 8)` is dropped only across the
/// families.
///
/// # What it never touches
///
/// - An immediate operand. A constraint on a constant (possible after
///   [`fold_immediate_copies`]) names no wire, so there is nothing to key on
///   and it is left exactly where it is.
/// - Anything else at all: no reordering, no renaming, no other instruction
///   kind. Everything kept keeps its order.
pub fn dedup_range_constraints(instructions: Vec<Instruction>) -> Vec<Instruction> {
    // The tightest bound proven for each identifier so far, in bits.
    let mut bound: HashMap<Identifier, u32> = HashMap::new();
    let mut out = Vec::with_capacity(instructions.len());

    for instruction in instructions {
        let established = match &instruction {
            Instruction::ConstrainBits { val: Operand::Variable(id), bits } => Some((id, *bits)),
            Instruction::ConstrainToBoolean { val: Operand::Variable(id) } => Some((id, 1)),
            _ => None,
        };
        if let Some((id, bits)) = established {
            match bound.get(id) {
                // Already proven at least this tight: the constraint is
                // implied, so it carries no information the circuit lacks.
                Some(&proven) if proven <= bits => continue,
                // Tighter than anything proven (or the first): keep it, and
                // it is the bound from here on.
                _ => {
                    bound.insert(id.clone(), bits);
                }
            }
        }
        out.push(instruction);
    }
    out
}

/// [`fold_immediate_copies`] over a whole [`IrSource`] — the form the
/// instruction-for-instruction differentials need, because they must run the
/// SAME normalisation over compactc's artifact as our builder runs over ours.
///
/// Why that is not a weakening of those tests: the pass only ever removes a
/// `Copy` of an immediate, which is a rename with no rows (measured), no
/// public-input effect and no semantic content. Everything else — every
/// instruction, every operand, every order — is still compared exactly, and a
/// constant that either side NAMES for an output slot is still named on both.
pub fn folded(ir: &IrSource) -> IrSource {
    IrSource {
        instructions: std::sync::Arc::new(fold_immediate_copies(ir.instructions.to_vec())),
        ..ir.clone()
    }
}

/// The identifiers bound by a `Copy` of an immediate, with that immediate.
fn immediate_copies(instructions: &[Instruction]) -> HashMap<Identifier, Operand> {
    let mut named: HashMap<Identifier, Operand> = HashMap::new();
    for instruction in instructions {
        if let Instruction::Copy { val, output } = instruction {
            let value = match val {
                Operand::Immediate(_) => Some(val.clone()),
                // A copy of an already-folded copy is itself an immediate.
                Operand::Variable(id) => named.get(id).cloned(),
            };
            if let Some(value) = value {
                named.insert(output.clone(), value);
            }
        }
    }
    named
}

/// Identifiers that appear in the `Output` terminator — the one position where
/// compactc names a constant, and therefore where this pass leaves it named.
fn returned_identifiers(instructions: &[Instruction]) -> HashSet<Identifier> {
    let mut returned = HashSet::new();
    for instruction in instructions {
        for val in returned_operands(instruction) {
            if let Operand::Variable(id) = val {
                returned.insert(id.clone());
            }
        }
    }
    returned
}

/// The operand positions through which a value LEAVES the circuit named.
///
/// Exhaustive by construction, the same way [`operands_mut`] is, and for a
/// sharper reason: this list is what stops [`fold_immediate_copies`] folding
/// a constant compactc keeps named, so an upstream terminator this function
/// did not know about would make the fold do MORE, not less — the unsound
/// direction (notes/formal-verification-options.org §10). A new
/// output-carrying variant therefore has to break this match rather than fall
/// through a wildcard into silence.
fn returned_operands(instruction: &Instruction) -> &[Operand] {
    match instruction {
        Instruction::Output { vals } => vals,
        // Everything else: an ordinary instruction, whose operands are
        // consumed in-circuit and are the fold's whole business.
        Instruction::Encode { .. }
        | Instruction::Assert { .. }
        | Instruction::CondSelect { .. }
        | Instruction::ConstrainBits { .. }
        | Instruction::ConstrainEq { .. }
        | Instruction::ConstrainToBoolean { .. }
        | Instruction::Copy { .. }
        | Instruction::Impact { .. }
        | Instruction::EcMul { .. }
        | Instruction::EcMulGenerator { .. }
        | Instruction::HashToCurve { .. }
        | Instruction::IntoCoordinates { .. }
        | Instruction::FromCoordinates { .. }
        | Instruction::IntoBytes32 { .. }
        | Instruction::FromBytes32 { .. }
        | Instruction::Bytes32IntoLowHigh { .. }
        | Instruction::ReverseBytes { .. }
        | Instruction::Bytes32FromLowHigh { .. }
        | Instruction::DivModPowerOfTwo { .. }
        | Instruction::ReconstituteField { .. }
        | Instruction::TransientHash { .. }
        | Instruction::PersistentHash { .. }
        | Instruction::Keccak256 { .. }
        | Instruction::TestEq { .. }
        | Instruction::Add { .. }
        | Instruction::Mul { .. }
        | Instruction::Neg { .. }
        | Instruction::Inv { .. }
        | Instruction::Not { .. }
        | Instruction::LessThan { .. }
        | Instruction::JubjubScalarFromNative { .. }
        | Instruction::PublicInput { .. }
        | Instruction::PrivateInput { .. } => &[],
    }
}

/// Every operand position of an instruction, mutably.
///
/// Exhaustive by construction: a ZKIR instruction added upstream breaks this
/// match rather than silently escaping the pass.
fn operands_mut(instruction: &mut Instruction) -> Vec<&mut Operand> {
    match instruction {
        Instruction::Encode { input, .. } => vec![input],
        Instruction::Assert { cond } => vec![cond],
        Instruction::CondSelect { bit, a, b, .. } => vec![bit, a, b],
        Instruction::ConstrainBits { val, .. } => vec![val],
        Instruction::ConstrainEq { a, b } => vec![a, b],
        Instruction::ConstrainToBoolean { val } => vec![val],
        Instruction::Copy { val, .. } => vec![val],
        Instruction::Impact { guard, inputs } => {
            let mut ops = vec![guard];
            ops.extend(inputs.iter_mut());
            ops
        }
        Instruction::EcMul { a, scalar, .. } => vec![a, scalar],
        Instruction::EcMulGenerator { scalar, .. } => vec![scalar],
        Instruction::HashToCurve { inputs, .. } => inputs.iter_mut().collect(),
        Instruction::IntoCoordinates { point, .. } => vec![point],
        Instruction::FromCoordinates { inputs, .. } => vec![&mut inputs.0, &mut inputs.1],
        Instruction::IntoBytes32 { input, .. } => vec![input],
        Instruction::FromBytes32 { bytes, .. } => vec![bytes],
        Instruction::Bytes32IntoLowHigh { bytes, .. } => vec![bytes],
        Instruction::ReverseBytes { bytes, .. } => vec![bytes],
        Instruction::Bytes32FromLowHigh { inputs, .. } => vec![&mut inputs.0, &mut inputs.1],
        Instruction::DivModPowerOfTwo { val, .. } => vec![val],
        Instruction::ReconstituteField {
            divisor, modulus, ..
        } => vec![divisor, modulus],
        Instruction::TransientHash { inputs, .. } => inputs.iter_mut().collect(),
        Instruction::PersistentHash { inputs, .. } => inputs.iter_mut().collect(),
        Instruction::Keccak256 { inputs, .. } => inputs.iter_mut().collect(),
        Instruction::TestEq { a, b, .. } => vec![a, b],
        Instruction::Add { a, b, .. } => vec![a, b],
        Instruction::Mul { a, b, .. } => vec![a, b],
        Instruction::Neg { a, .. } => vec![a],
        Instruction::Inv { a, .. } => vec![a],
        Instruction::Not { a, .. } => vec![a],
        Instruction::LessThan { a, b, .. } => vec![a, b],
        Instruction::JubjubScalarFromNative { native, .. } => vec![native],
        Instruction::PublicInput { guard, .. } => guard.iter_mut().collect(),
        Instruction::PrivateInput { guard, .. } => guard.iter_mut().collect(),
        // NOT folded: see the pass's docs. The terminator's own operands are
        // left alone, which is what keeps a returned constant named.
        Instruction::Output { vals: _ } => vec![],
    }
}

// ============================================================================
// The `Pass` trait — third-party optimisation passes, à la carte (M24)
// ============================================================================
//
// notes/library-api.org §3. The two functions above are the reference passes;
// this trait is the stable-ish surface a third party implements to add their
// own and compose them, WITHOUT forking. It is ordinary Rust — a pass is a
// value, composition is a `Vec`, there is no plugin-loading machinery, which
// is the payoff of being library-first rather than a compiler binary.
//
// THE CONTRACT (notes/ir-passes.org §§1-4). The ACCEPTED class is UNIFORM
// transforms — guards, constants, range constraints. The REJECTED class —
// dead-code elimination and common-subexpression elimination — DIVERGES from
// compactc or is unsound-here, and a third party reaching for either needs a
// protocol argument this crate cannot make for them. Every pass MUST preserve
// the public-input / witness stream (PI-equality is the correctness oracle)
// and, until the verification hooks land, the author's own range constraints.
//
// DESIGNED FOR THE DEFERRED Kani/Lean VERIFICATION (notes/formal-verification-
// options.org): `transform` is PURE and TOTAL — same input, same output, no
// panics, no global state — so a machine check of "output PI stream ≡ input PI
// stream" and "only implied constraints dropped" can target it without any
// redesign here. That is the whole reason the shape is `IR -> IR` and nothing
// more.

/// What a pass did — always produced by [`Pass::run`].
///
/// OPTIONAL to consume but HIGHLY RECOMMENDED to read: people shoot themselves
/// in the foot, so the runner makes sure they were WARNED first. A VALID
/// optimisation can still raise a warning — [`dedup_range_constraints`]
/// legitimately drops implied range constraints, which trips the
/// instruction-drop warning below. The warnings are ADVISORY, not a verdict.
#[derive(Debug, Clone)]
pub struct PassReport {
    /// The pass's name.
    pub pass: &'static str,
    /// Instruction count before the pass.
    pub before: usize,
    /// Instruction count after the pass.
    pub after: usize,
    /// Advisory warnings — the pass's own, plus an auto-warning on any NET
    /// instruction drop, which is the most dangerous signal: dropping an
    /// instruction can move the PI/witness stream, and that is the oracle.
    pub warnings: Vec<String>,
}

/// A ZKIR optimisation pass — the à-la-carte extension point (M24).
///
/// Implement [`Pass::transform`] (the pure, total `IR -> IR`, returning any
/// advisory warnings); [`Pass::run`] is provided and wraps it with the report.
/// See the module header for the contract every pass must honour, and
/// notes/library-api.org for where this sits in the library surface.
pub trait Pass {
    /// This pass's name — for the report and the [`by_name`] registry.
    fn name(&self) -> &'static str;

    /// The pure, total transform: same input → same output, no panics, no
    /// global state. Returns the new instruction stream and any advisory
    /// warnings the pass wants to raise (empty is fine).
    fn transform(&self, ir: Vec<Instruction>) -> (Vec<Instruction>, Vec<String>);

    /// Run the pass and report. PROVIDED — do not override. The report is
    /// optional to consume but always produced, and it auto-warns on any net
    /// instruction drop even when the pass itself is silent, so a caller
    /// cannot be left un-warned about the one signal that matters.
    fn run(&self, ir: Vec<Instruction>) -> (Vec<Instruction>, PassReport) {
        let before = ir.len();
        let (out, mut warnings) = self.transform(ir);
        let after = out.len();
        if after < before {
            warnings.push(format!(
                "dropped {} instruction(s) — verify the public-input / witness \
                 stream is unchanged (PI-equality is the correctness oracle)",
                before - after,
            ));
        }
        (
            out,
            PassReport {
                pass: self.name(),
                before,
                after,
                warnings,
            },
        )
    }
}

/// [`fold_immediate_copies`] as a [`Pass`]. A fold is a RENAME — it removes
/// only instructions it can prove are `Copy`s of an immediate — so the
/// instruction-drop warning it trips is expected and benign.
pub struct FoldImmediateCopies;

impl Pass for FoldImmediateCopies {
    fn name(&self) -> &'static str {
        "fold_immediate_copies"
    }
    fn transform(&self, ir: Vec<Instruction>) -> (Vec<Instruction>, Vec<String>) {
        (fold_immediate_copies(ir), Vec::new())
    }
}

/// [`dedup_range_constraints`] as a [`Pass`]. It drops a range constraint only
/// where a tighter-or-equal bound was ALREADY proven, so the drop is sound on
/// any stream whose leaves are constrained at entry — the warning names the
/// one thing to check (an unconstrained source, where a dropped constraint
/// would be load-bearing). The canonical "valid optimisation that still warns".
pub struct DedupRangeConstraints;

impl Pass for DedupRangeConstraints {
    fn name(&self) -> &'static str {
        "dedup_range_constraints"
    }
    fn transform(&self, ir: Vec<Instruction>) -> (Vec<Instruction>, Vec<String>) {
        let before = ir.len();
        let out = dedup_range_constraints(ir);
        // Only warn when it actually dropped something — a warning names what
        // happened, not what could have. On a real drop this rides ALONGSIDE
        // the runner's generic "dropped N instructions" warning: generic says
        // the danger, this says why it is usually fine and what to check.
        let warnings = if out.len() < before {
            vec!["dropped only range constraints already implied by a \
                  tighter-or-equal proven bound; verify the source constrains \
                  its leaves at entry (an unconstrained leaf makes a dropped \
                  constraint load-bearing)"
                .to_string()]
        } else {
            Vec::new()
        };
        (out, warnings)
    }
}

/// Run passes left to right, threading the IR through and collecting one
/// report per pass. Composition is ordinary Rust — a convenience over a `for`
/// loop, not machinery; a third party's pipeline is just a `Vec` of their own
/// passes interleaved with these.
pub fn run_pipeline(
    passes: &[Box<dyn Pass>],
    mut ir: Vec<Instruction>,
) -> (Vec<Instruction>, Vec<PassReport>) {
    let mut reports = Vec::with_capacity(passes.len());
    for pass in passes {
        let (out, report) = pass.run(ir);
        ir = out;
        reports.push(report);
    }
    (ir, reports)
}

/// The BUILT-IN passes by name — what a CLI or a config names to run one à la
/// carte. A third party's own passes are their own values; this is only the
/// reference set. See [`builtin_names`] for the accepted names.
pub fn by_name(name: &str) -> Option<Box<dyn Pass>> {
    match name {
        "fold_immediate_copies" => Some(Box::new(FoldImmediateCopies)),
        "dedup_range_constraints" => Some(Box::new(DedupRangeConstraints)),
        _ => None,
    }
}

/// The names [`by_name`] accepts — for help text and discovery.
pub fn builtin_names() -> &'static [&'static str] {
    &["fold_immediate_copies", "dedup_range_constraints"]
}
