//! L1 — typed circuit builder over ZKIR instructions.
//!
//! ZKIR v2 executes a flat instruction list over an append-only value memory:
//! memory starts as the circuit's `num_inputs` arguments, and each
//! value-producing instruction appends its results. [`Val`] is a typed handle
//! to one memory slot; [`Builder`] tracks the arity of every instruction so
//! indices can never dangle. Optimisation passes (L4) will operate on this
//! layer. Semantics reference: `zkir/src/ir_vm.rs` in midnight-ledger.

use std::sync::Arc;

pub use midnight_base_crypto::fab::{Alignment, AlignmentAtom, AlignmentSegment};
pub use minocrab_zkir::{Fr, Instruction, IrSource};

pub mod v3;

/// A handle to one slot of circuit value memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Val(u32);

impl Val {
    /// The raw ZKIR memory index.
    pub fn index(self) -> u32 {
        self.0
    }
}

/// Builds a ZKIR instruction stream with statically-tracked value handles.
#[derive(Debug, Default)]
pub struct Builder {
    num_inputs: u32,
    mem_len: u32,
    instructions: Vec<Instruction>,
}

impl Builder {
    /// A builder for a circuit taking `num_inputs` field-element arguments.
    /// Returns the handles for those arguments.
    pub fn new(num_inputs: u32) -> (Self, Vec<Val>) {
        let builder = Builder {
            num_inputs,
            mem_len: num_inputs,
            instructions: Vec::new(),
        };
        let args = (0..num_inputs).map(Val).collect();
        (builder, args)
    }

    fn push(&mut self, ins: Instruction, outputs: u32) -> Val {
        let first = Val(self.mem_len);
        self.mem_len += outputs;
        self.instructions.push(ins);
        first
    }

    fn push2(&mut self, ins: Instruction) -> (Val, Val) {
        let first = self.push(ins, 2);
        (first, Val(first.0 + 1))
    }

    // --- value-producing instructions -------------------------------------

    /// Load a constant.
    pub fn load_imm(&mut self, imm: impl Into<Fr>) -> Val {
        self.push(Instruction::LoadImm { imm: imm.into() }, 1)
    }

    pub fn add(&mut self, a: Val, b: Val) -> Val {
        self.push(Instruction::Add { a: a.0, b: b.0 }, 1)
    }

    pub fn mul(&mut self, a: Val, b: Val) -> Val {
        self.push(Instruction::Mul { a: a.0, b: b.0 }, 1)
    }

    pub fn neg(&mut self, a: Val) -> Val {
        self.push(Instruction::Neg { a: a.0 }, 1)
    }

    /// Boolean not; the operand must hold 0 or 1.
    pub fn not(&mut self, a: Val) -> Val {
        self.push(Instruction::Not { a: a.0 }, 1)
    }

    /// 1 if equal, else 0.
    pub fn test_eq(&mut self, a: Val, b: Val) -> Val {
        self.push(Instruction::TestEq { a: a.0, b: b.0 }, 1)
    }

    /// `bit ? a : b`; `bit` must hold 0 or 1.
    pub fn cond_select(&mut self, bit: Val, a: Val, b: Val) -> Val {
        self.push(
            Instruction::CondSelect {
                bit: bit.0,
                a: a.0,
                b: b.0,
            },
            1,
        )
    }

    /// `a < b` over `bits`-bit values (also range-constrains both).
    pub fn less_than(&mut self, a: Val, b: Val, bits: u32) -> Val {
        self.push(
            Instruction::LessThan {
                a: a.0,
                b: b.0,
                bits,
            },
            1,
        )
    }

    pub fn copy(&mut self, var: Val) -> Val {
        self.push(Instruction::Copy { var: var.0 }, 1)
    }

    /// Read the next private-transcript (witness) value. If `guard` is given
    /// and false at runtime, yields 0 without consuming the transcript.
    pub fn private_input(&mut self, guard: Option<Val>) -> Val {
        self.push(
            Instruction::PrivateInput {
                guard: guard.map(|g| g.0),
            },
            1,
        )
    }

    /// Read the next public-transcript output value. If `guard` is given and
    /// false at runtime, yields 0 without consuming the transcript.
    pub fn public_input(&mut self, guard: Option<Val>) -> Val {
        self.push(
            Instruction::PublicInput {
                guard: guard.map(|g| g.0),
            },
            1,
        )
    }

    /// Split into `(var >> bits, var mod 2^bits)`.
    pub fn div_mod_power_of_two(&mut self, var: Val, bits: u32) -> (Val, Val) {
        self.push2(Instruction::DivModPowerOfTwo { var: var.0, bits })
    }

    /// `divisor * 2^bits + modulus`, checked against field overflow.
    pub fn reconstitute_field(&mut self, divisor: Val, modulus: Val, bits: u32) -> Val {
        self.push(
            Instruction::ReconstituteField {
                divisor: divisor.0,
                modulus: modulus.0,
                bits,
            },
            1,
        )
    }

    /// Poseidon-family in-circuit hash of field elements.
    pub fn transient_hash(&mut self, inputs: &[Val]) -> Val {
        self.push(
            Instruction::TransientHash {
                inputs: inputs.iter().map(|v| v.0).collect(),
            },
            1,
        )
    }

    /// SHA-256 persistent hash; the 32-byte output spans two field elements.
    pub fn persistent_hash(&mut self, alignment: Alignment, inputs: &[Val]) -> (Val, Val) {
        self.push2(Instruction::PersistentHash {
            alignment,
            inputs: inputs.iter().map(|v| v.0).collect(),
        })
    }

    /// Point addition on the embedded curve; returns (x, y).
    pub fn ec_add(&mut self, a: (Val, Val), b: (Val, Val)) -> (Val, Val) {
        self.push2(Instruction::EcAdd {
            a_x: a.0 .0,
            a_y: a.1 .0,
            b_x: b.0 .0,
            b_y: b.1 .0,
        })
    }

    /// Scalar multiplication on the embedded curve; returns (x, y).
    pub fn ec_mul(&mut self, point: (Val, Val), scalar: Val) -> (Val, Val) {
        self.push2(Instruction::EcMul {
            a_x: point.0 .0,
            a_y: point.1 .0,
            scalar: scalar.0,
        })
    }

    /// Generator multiplication on the embedded curve; returns (x, y).
    pub fn ec_mul_generator(&mut self, scalar: Val) -> (Val, Val) {
        self.push2(Instruction::EcMulGenerator { scalar: scalar.0 })
    }

    /// Hash field elements to a curve point; returns (x, y).
    pub fn hash_to_curve(&mut self, inputs: &[Val]) -> (Val, Val) {
        self.push2(Instruction::HashToCurve {
            inputs: inputs.iter().map(|v| v.0).collect(),
        })
    }

    // --- constraints and outputs (no value produced) -----------------------

    /// Constrain `cond` (must hold 0 or 1) to be 1.
    pub fn assert(&mut self, cond: Val) {
        self.push(Instruction::Assert { cond: cond.0 }, 0);
    }

    pub fn constrain_eq(&mut self, a: Val, b: Val) {
        self.push(Instruction::ConstrainEq { a: a.0, b: b.0 }, 0);
    }

    pub fn constrain_bits(&mut self, var: Val, bits: u32) {
        self.push(Instruction::ConstrainBits { var: var.0, bits }, 0);
    }

    pub fn constrain_to_boolean(&mut self, var: Val) {
        self.push(Instruction::ConstrainToBoolean { var: var.0 }, 0);
    }

    /// Declare `var` as one public input of the statement, closing the block
    /// immediately (every DeclarePubInput must be covered by a PiSkip).
    pub fn declare_pub_input(&mut self, var: Val) {
        self.push(Instruction::DeclarePubInput { var: var.0 }, 0);
        self.push(
            Instruction::PiSkip {
                guard: None,
                count: 1,
            },
            0,
        );
    }

    /// Declare a guarded block of public inputs at once.
    pub fn declare_pub_inputs_guarded(&mut self, vars: &[Val], guard: Option<Val>) {
        for var in vars {
            self.push(Instruction::DeclarePubInput { var: var.0 }, 0);
        }
        self.push(
            Instruction::PiSkip {
                guard: guard.map(|g| g.0),
                count: vars.len() as u32,
            },
            0,
        );
    }

    /// Emit `var` as a circuit output (return value).
    pub fn output(&mut self, var: Val) {
        self.push(Instruction::Output { var: var.0 }, 0);
    }

    // --- finishing ----------------------------------------------------------

    /// Number of instructions so far.
    pub fn len(&self) -> usize {
        self.instructions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// Finish into an [`IrSource`] ready for `zkir` or the simulator.
    pub fn finish(self, communications_commitment: bool) -> IrSource {
        IrSource {
            num_inputs: self.num_inputs,
            do_communications_commitment: communications_commitment,
            instructions: Arc::new(self.instructions),
            ..Default::default()
        }
    }
}
