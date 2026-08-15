//! The compiled `.zkir`, read for the two facts an interface crate can be
//! checked against: how many inputs the circuit declares, and the
//! CONSTRAINT PREFIX it opens with.
//!
//! compactc emits every argument's constraints first, in slot order, before
//! any other instruction (`emit-constraints-for` runs over the whole
//! flattened argument list at circuit entry). That prefix is therefore the
//! callee's argument ABI as the PROVER sees it — not as the compiler's JSON
//! describes it — so comparing it against
//! [`Prim::constraint`](minocrab::v3::Prim::constraint) run over an
//! interface crate's own types checks the interface against the artifact
//! that will actually be verified.

use midnight_zkir_v3::ir::Operand;
use minocrab::v3::LimbConstraint;
use minocrab_zkir::v3::{Instruction, IrSource};

/// One constraint of a circuit's opening prefix: the slot it constrains
/// (by declared input name) and the constraint itself, keyed for
/// comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixConstraint {
    /// The declared input the constraint is placed on.
    pub input: String,
    /// [`constraint_key`] of the constraint.
    pub key: String,
}

/// A `.zkir` reduced to what the agreement check needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZkirFacts {
    /// Declared inputs, in declaration order — the callee's native slots.
    pub inputs: Vec<String>,
    /// Whether the circuit compiles a communications commitment. A callee
    /// that does not cannot participate in a cross-contract call.
    pub do_communications_commitment: bool,
    /// The opening constraint run, in order.
    pub prefix: Vec<PrefixConstraint>,
}

/// The comparison key of a constraint. `LimbConstraint::None` has none —
/// an unconstrained slot emits no instruction, so it does not appear in a
/// prefix at all and the comparison skips it on both sides.
pub fn constraint_key(constraint: LimbConstraint) -> Option<String> {
    match constraint {
        LimbConstraint::None => None,
        LimbConstraint::Zero => Some("zero".to_string()),
        LimbConstraint::Boolean => Some("boolean".to_string()),
        LimbConstraint::Bits(bits) => Some(format!("bits:{bits}")),
        LimbConstraint::Bounded { bound, bits } => Some(format!("bounded:{bound}:{bits}")),
    }
}

impl ZkirFacts {
    /// Read a parsed v3 `.zkir`.
    pub fn of(ir: &IrSource) -> ZkirFacts {
        ZkirFacts {
            inputs: input_names(ir),
            do_communications_commitment: ir.do_communications_commitment,
            prefix: prefix(&ir.instructions),
        }
    }

    /// Read a `.zkir` file.
    pub fn read(path: &std::path::Path) -> Result<ZkirFacts, minocrab_zkir::Error> {
        Ok(ZkirFacts::of(&minocrab_zkir::v3::read_zkir(path)?))
    }
}

/// Input names, through serde — `TypedIdentifier`'s fields are private to
/// `midnight-zkir-v3`, and its serialized form is the on-disk one.
fn input_names(ir: &IrSource) -> Vec<String> {
    let value = serde_json::to_value(&ir.inputs).expect("zkir inputs serialize");
    value
        .as_array()
        .map(|inputs| {
            inputs
                .iter()
                .map(|input| input["name"].as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// The leading constraint instructions, stopping at the first instruction
/// that is not one.
fn prefix(instructions: &[Instruction]) -> Vec<PrefixConstraint> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < instructions.len() {
        let (key, operand, consumed) = match &instructions[i] {
            Instruction::ConstrainBits { val, bits } => (format!("bits:{bits}"), val, 1),
            Instruction::ConstrainToBoolean { val } => ("boolean".to_string(), val, 1),
            // `constrain_eq var 0` — the `Uint<0..0>` case. Either operand
            // may carry the immediate; compactc writes it second.
            Instruction::ConstrainEq { a, b } => match (immediate_is_zero(a), immediate_is_zero(b)) {
                (false, true) => ("zero".to_string(), a, 1),
                (true, false) => ("zero".to_string(), b, 1),
                _ => break,
            },
            // `less_than tmp var bound bits` immediately followed by
            // `assert tmp` — the non-power-of-two bound.
            Instruction::LessThan { a, b, bits, .. } => {
                let Some(bound) = immediate(b) else { break };
                if !matches!(instructions.get(i + 1), Some(Instruction::Assert { .. })) {
                    break;
                }
                (format!("bounded:{bound}:{bits}"), a, 2)
            }
            _ => break,
        };
        let Operand::Variable(id) = operand else { break };
        out.push(PrefixConstraint { input: id.0.clone(), key });
        i += consumed;
    }
    out
}

fn immediate(operand: &Operand) -> Option<u128> {
    match operand {
        Operand::Immediate(fr) => {
            let bytes = fr.as_le_bytes();
            if bytes.iter().skip(16).any(|&b| b != 0) {
                return None;
            }
            let mut buf = [0u8; 16];
            let n = bytes.len().min(16);
            buf[..n].copy_from_slice(&bytes[..n]);
            Some(u128::from_le_bytes(buf))
        }
        Operand::Variable(_) => None,
    }
}

fn immediate_is_zero(operand: &Operand) -> bool {
    immediate(operand) == Some(0)
}
