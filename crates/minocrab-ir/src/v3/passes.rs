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
        if let Instruction::Output { vals } = instruction {
            for val in vals {
                if let Operand::Variable(id) = val {
                    returned.insert(id.clone());
                }
            }
        }
    }
    returned
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
