//! L5 for ZKIR v3 — native simulator over the typed IR.
//!
//! A mechanical port of the off-circuit arm of midnight-ledger's zkir-v3
//! interpreter: `IrSource::preprocess` in `zkir-v3/src/ir_vm.rs` (rev
//! 04c9c5d9, line 185), which upstream keeps `pub(crate)`. Unlike the v2
//! simulator ([`crate::simulate`]), which *generates* the public transcript,
//! v3's reference semantics *verify* a complete `ProofPreimage`: circuit
//! arguments are decoded from `preimage.inputs` per the input schema, and
//! `Impact` public inputs are checked against
//! `preimage.public_transcript_inputs` as they accumulate. `Run3` surfaces
//! everything upstream's `Preprocessed` carries (memory, pis, pi_skips,
//! binding input, communications commitment) plus the circuit outputs and
//! the counters the v2 [`crate::Run`] tracks.
//!
//! Per-instruction value semantics are *not* re-implemented: zkir-v3
//! publishes its off-circuit helpers (`midnight_zkir_v3::ir_instructions`),
//! and this module calls them — `add_offcircuit`, `decode_offcircuit`,
//! `encode_offcircuit`, `native_to_jubjub_scalar`, … — alongside Midnight's
//! crypto (`transient_hash`, `hash_to_curve`, `transient_commit`, SHA-256 /
//! Keccak-256 over the FAB-aligned byte encoding), exactly as `preprocess`
//! does. The only upstream items mirrored rather than reused are three
//! `pub(crate)` one-liners: `IrValue::get_type` (ir_types.rs:161),
//! `IrValue::default` (ir_types.rs:182), and `TypedIdentifier`'s field
//! access (ir.rs:170, recovered through its serde form).
//!
//! Like the v2 simulator, this is never trusted alone: `tests/v3_end_to_end.rs`
//! cross-checks every run against upstream `IrSource::check`, which is
//! `preprocess(..)?.pi_skips` verbatim (zkir-v3/src/ir.rs:75-81).

use std::collections::BTreeMap;
#[cfg(feature = "unstable")]
use std::collections::HashMap;

pub mod rowcost;

#[cfg(feature = "unstable")]
use group::Group;
#[cfg(feature = "unstable")]
use midnight_base_crypto::repr::BinaryHashRepr;
#[cfg(feature = "unstable")]
use midnight_curves::{curve25519, k256, p256, Fr as JubjubFr, JubjubSubgroup};
#[cfg(feature = "unstable")]
use midnight_transient_crypto::curve::{Fr, FR_BITS, FR_BYTES_STORED};
#[cfg(feature = "unstable")]
use midnight_transient_crypto::fab::{AlignmentExt, ValueReprAlignedValue};
#[cfg(feature = "unstable")]
use midnight_transient_crypto::hash::{hash_to_curve, transient_commit, transient_hash};
#[cfg(feature = "unstable")]
use midnight_transient_crypto::proofs::ProofPreimage;
#[cfg(feature = "unstable")]
use midnight_zkir_v3::ir_instructions::add::add_offcircuit;
#[cfg(feature = "unstable")]
use midnight_zkir_v3::ir_instructions::constrain_eq::constrain_eq_offcircuit;
#[cfg(feature = "unstable")]
use midnight_zkir_v3::ir_instructions::ec_mul::ec_mul_offcircuit;
#[cfg(feature = "unstable")]
use midnight_zkir_v3::ir_instructions::encode::{
    decode_offcircuit, encode_offcircuit, native_to_jubjub_scalar,
};
#[cfg(feature = "unstable")]
use midnight_zkir_v3::ir_instructions::eq::test_eq_offcircuit;
#[cfg(feature = "unstable")]
use midnight_zkir_v3::ir_instructions::from_bytes32::from_bytes32_offcircuit;
#[cfg(feature = "unstable")]
use midnight_zkir_v3::ir_instructions::from_coordinates::from_coordinates_offcircuit;
#[cfg(feature = "unstable")]
use midnight_zkir_v3::ir_instructions::into_bytes32::into_bytes32_offcircuit;
#[cfg(feature = "unstable")]
use midnight_zkir_v3::ir_instructions::into_coordinates::into_coordinates_offcircuit;
#[cfg(feature = "unstable")]
use midnight_zkir_v3::ir_instructions::inv::inv_offcircuit;
#[cfg(feature = "unstable")]
use midnight_zkir_v3::ir_instructions::mul::mul_offcircuit;
#[cfg(feature = "unstable")]
use midnight_zkir_v3::ir_instructions::neg::neg_offcircuit;
#[cfg(feature = "unstable")]
use midnight_zkir_v3::ir_instructions::select::select_offcircuit;
use minocrab_zkir::v3::{Instruction as I, IrSource};

#[cfg(feature = "unstable")]
use minocrab_zkir::v3::{Identifier, IrType, IrValue, Operand};
#[cfg(feature = "unstable")]
use sha2::Sha256;
#[cfg(feature = "unstable")]
use sha3::{Digest, Keccak256};

#[cfg(feature = "unstable")]
#[derive(Debug, thiserror::Error)]
pub enum Sim3Error {
    #[error("instruction {at} ({op}): {message}")]
    Failed {
        at: usize,
        op: &'static str,
        message: String,
    },
    /// Argument decoding failed before any instruction ran (ir_vm.rs:191-211).
    #[error("inputs: {0}")]
    Inputs(String),
    /// A transcript was not consumed exactly (ir_vm.rs:648-661).
    #[error("transcripts not fully consumed: {0}")]
    Transcript(String),
    /// Communications-commitment handling failed (ir_vm.rs:214-221, 662-681).
    #[error("communications commitment: {0}")]
    CommCommitment(String),
}

#[cfg(feature = "unstable")]
fn fail(at: usize, op: &'static str, message: impl Into<String>) -> Sim3Error {
    Sim3Error::Failed {
        at,
        op,
        message: message.into(),
    }
}

#[cfg(feature = "unstable")]
/// The result of simulating one v3 circuit run — upstream's `Preprocessed`
/// (ir_vm.rs:71-77) with `pis` kept as [`Fr`] instead of unwrapped
/// `outer::Scalar`, plus outputs and run metrics.
#[derive(Debug, Clone)]
pub struct Run3 {
    /// Full typed value memory at the end of the run, by identifier.
    pub memory: HashMap<Identifier, IrValue>,
    /// The proof-system public-input vector: `binding_input`, then (when
    /// enabled) the communications commitment, then one element per
    /// `Impact` input — zeros where the guard was off.
    pub pis: Vec<Fr>,
    /// One entry per `Impact`: `None` if taken, `Some(count)` if its guard
    /// was off and `count` zeros were substituted in `pis`.
    pub pi_skips: Vec<Option<usize>>,
    /// The preimage's binding input (always `pis[0]`).
    pub binding_input: Fr,
    /// The preimage's `(commitment, randomness)`, if any.
    pub comm_comm: Option<(Fr, Fr)>,
    /// Values produced by the `Output` terminator (circuit return values).
    pub outputs: Vec<IrValue>,
    /// Raw `Fr` elements consumed from the private transcript.
    pub consumed_private: usize,
    /// Raw `Fr` elements consumed from the public transcript outputs.
    pub consumed_public: usize,
    /// Instruction execution counts by opcode.
    pub op_counts: BTreeMap<&'static str, u32>,
}

/// Opcode name of a v3 instruction (for metrics and error messages).
pub fn op_name(ins: &I) -> &'static str {
    match ins {
        I::Add { .. } => "add",
        I::Assert { .. } => "assert",
        I::Bytes32FromLowHigh { .. } => "bytes32_from_low_high",
        I::Bytes32IntoLowHigh { .. } => "bytes32_into_low_high",
        I::CondSelect { .. } => "cond_select",
        I::ConstrainBits { .. } => "constrain_bits",
        I::ConstrainEq { .. } => "constrain_eq",
        I::ConstrainToBoolean { .. } => "constrain_to_boolean",
        I::Copy { .. } => "copy",
        I::DivModPowerOfTwo { .. } => "div_mod_power_of_two",
        I::EcMul { .. } => "ec_mul",
        I::EcMulGenerator { .. } => "ec_mul_generator",
        I::Encode { .. } => "encode",
        I::FromBytes32 { .. } => "from_bytes32",
        I::FromCoordinates { .. } => "from_coordinates",
        I::HashToCurve { .. } => "hash_to_curve",
        I::Impact { .. } => "impact",
        I::IntoBytes32 { .. } => "into_bytes32",
        I::IntoCoordinates { .. } => "into_coordinates",
        I::Inv { .. } => "inv",
        I::JubjubScalarFromNative { .. } => "jubjub_scalar_from_native",
        I::Keccak256 { .. } => "keccak256",
        I::LessThan { .. } => "less_than",
        I::Mul { .. } => "mul",
        I::Neg { .. } => "neg",
        I::Not { .. } => "not",
        I::Output { .. } => "output",
        I::PersistentHash { .. } => "persistent_hash",
        I::PrivateInput { .. } => "private_input",
        I::PublicInput { .. } => "public_input",
        I::ReconstituteField { .. } => "reconstitute_field",
        I::ReverseBytes { .. } => "reverse_bytes",
        I::TestEq { .. } => "test_eq",
        I::TransientHash { .. } => "transient_hash",
    }
}

#[cfg(feature = "unstable")]
/// Runtime type of a value — mirror of the `pub(crate)`
/// `IrValue::get_type` (ir_types.rs:161-180).
fn ir_type_of(value: &IrValue) -> IrType {
    match value {
        IrValue::Native(_) => IrType::Native,
        IrValue::Bytes32(_) => IrType::Bytes32,
        IrValue::JubjubPoint(_) => IrType::JubjubPoint,
        IrValue::JubjubScalar(_) => IrType::JubjubScalar,
        IrValue::Secp256k1Point(_) => IrType::Secp256k1Point,
        IrValue::Secp256k1Base(_) => IrType::Secp256k1Base,
        IrValue::Secp256k1Scalar(_) => IrType::Secp256k1Scalar,
        IrValue::Secp256r1Point(_) => IrType::Secp256r1Point,
        IrValue::Secp256r1Base(_) => IrType::Secp256r1Base,
        IrValue::Secp256r1Scalar(_) => IrType::Secp256r1Scalar,
        IrValue::Curve25519Point(_) => IrType::Curve25519Point,
        IrValue::Curve25519Base(_) => IrType::Curve25519Base,
        IrValue::Curve25519Scalar(_) => IrType::Curve25519Scalar,
    }
}

#[cfg(feature = "unstable")]
/// Default (zero/identity) value of a type, produced by guarded-off
/// transcript reads — mirror of the `pub(crate)` `IrValue::default`
/// (ir_types.rs:182-203).
fn default_ir_value(val_t: &IrType) -> IrValue {
    match val_t {
        IrType::Native => IrValue::Native(Fr::default()),
        IrType::Bytes32 => IrValue::Bytes32([0u8; 32]),
        IrType::JubjubPoint => IrValue::JubjubPoint(JubjubSubgroup::default()),
        IrType::JubjubScalar => IrValue::JubjubScalar(JubjubFr::default()),
        IrType::Secp256k1Point => IrValue::Secp256k1Point(k256::K256::default()),
        IrType::Secp256k1Base => IrValue::Secp256k1Base(k256::Fp::default()),
        IrType::Secp256k1Scalar => IrValue::Secp256k1Scalar(k256::Fq::default()),
        IrType::Secp256r1Point => IrValue::Secp256r1Point(p256::P256::default()),
        IrType::Secp256r1Base => IrValue::Secp256r1Base(p256::Fp::default()),
        IrType::Secp256r1Scalar => IrValue::Secp256r1Scalar(p256::Fq::default()),
        IrType::Curve25519Point => {
            IrValue::Curve25519Point(curve25519::Curve25519Subgroup::default())
        }
        IrType::Curve25519Base => IrValue::Curve25519Base(curve25519::Fp::default()),
        IrType::Curve25519Scalar => IrValue::Curve25519Scalar(curve25519::Scalar::default()),
    }
}

#[cfg(feature = "unstable")]
/// One circuit argument: `TypedIdentifier`'s fields are `pub(crate)`
/// upstream, so recover them through its serde form (`{"name", "type"}`),
/// the same trick `minocrab_ir::v3::typed_identifier` uses to build them.
#[derive(serde::Deserialize)]
struct InputSchema {
    name: Identifier,
    #[serde(rename = "type")]
    val_t: IrType,
}

#[cfg(feature = "unstable")]
fn input_schema(ir: &IrSource) -> Result<Vec<InputSchema>, Sim3Error> {
    ir.inputs
        .iter()
        .map(|ti| {
            serde_json::to_value(ti)
                .and_then(serde_json::from_value)
                .map_err(|e| Sim3Error::Inputs(format!("cannot read input schema: {e}")))
        })
        .collect()
}

// --- operand resolution (ir_vm.rs:227-278) ---------------------------------------

#[cfg(feature = "unstable")]
fn get(
    memory: &HashMap<Identifier, IrValue>,
    id: &Identifier,
    at: usize,
    op: &'static str,
) -> Result<IrValue, Sim3Error> {
    memory
        .get(id)
        .cloned()
        .ok_or_else(|| fail(at, op, format!("variable not found: {id:?}")))
}

#[cfg(feature = "unstable")]
fn operand(
    memory: &HashMap<Identifier, IrValue>,
    o: &Operand,
    at: usize,
    op: &'static str,
) -> Result<IrValue, Sim3Error> {
    match o {
        Operand::Variable(id) => get(memory, id, at, op),
        Operand::Immediate(imm) => Ok(IrValue::Native(*imm)),
    }
}

#[cfg(feature = "unstable")]
fn operand_fr(
    memory: &HashMap<Identifier, IrValue>,
    o: &Operand,
    at: usize,
    op: &'static str,
) -> Result<Fr, Sim3Error> {
    operand(memory, o, at, op)?
        .try_into()
        .map_err(|e| fail(at, op, format!("{e}")))
}

#[cfg(feature = "unstable")]
fn operand_bool(
    memory: &HashMap<Identifier, IrValue>,
    o: &Operand,
    at: usize,
    op: &'static str,
) -> Result<bool, Sim3Error> {
    let val = operand_fr(memory, o, at, op)?;
    if val == 0.into() {
        Ok(false)
    } else if val == 1.into() {
        Ok(true)
    } else {
        Err(fail(at, op, format!("expected boolean, found: {val:?}")))
    }
}

#[cfg(feature = "unstable")]
fn bits_of(val: Fr) -> Vec<bool> {
    val.as_le_bytes()
        .into_iter()
        .flat_map(|byte| {
            [0x01u8, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]
                .into_iter()
                .map(move |mask| byte & mask != 0)
        })
        .collect()
}

#[cfg(feature = "unstable")]
fn operand_bits(
    memory: &HashMap<Identifier, IrValue>,
    o: &Operand,
    constrain: Option<u32>,
    at: usize,
    op: &'static str,
) -> Result<Vec<bool>, Sim3Error> {
    let val = operand_fr(memory, o, at, op)?;
    let mut bits = bits_of(val);
    if let Some(n) = constrain {
        if n as usize >= FR_BITS {
            return Err(fail(at, op, "excessive bit bound"));
        }
        if bits[n as usize..].iter().any(|b| *b) {
            return Err(fail(at, op, format!("bit bound failed: {val:?} is not {n}-bit")));
        }
        bits.truncate(n as usize);
    }
    Ok(bits)
}

#[cfg(feature = "unstable")]
fn from_bits(bits: impl DoubleEndedIterator<Item = bool>) -> Fr {
    bits.rev()
        .fold(Fr::from(0u64), |acc, bit| acc * Fr::from(2u64) + Fr::from(bit as u64))
}

#[cfg(feature = "unstable")]
/// Read `width` raw elements from a transcript, or fail. Upstream slices
/// unchecked (`&transcript[i..i + w]`, ir_vm.rs:359, 378) and therefore
/// *panics* on exhaustion; this is the one place the port surfaces an error
/// instead — same rejection, no panic.
fn take_raw<'t>(
    transcript: &'t [Fr],
    idx: usize,
    width: usize,
    at: usize,
    op: &'static str,
    what: &str,
) -> Result<&'t [Fr], Sim3Error> {
    transcript
        .get(idx..idx + width)
        .ok_or_else(|| fail(at, op, format!("ran out of {what}")))
}

#[cfg(feature = "unstable")]
/// Simulate one run of `ir` against a complete proof preimage, mirroring
/// `IrSource::preprocess` (ir_vm.rs:185-691) instruction for instruction.
///
/// `preimage.inputs` is the circuit's *encoded* argument list: each argument
/// occupies `IrType::encoded_len` consecutive raw `Fr` elements.
pub fn simulate(ir: &IrSource, preimage: &ProofPreimage) -> Result<Run3, Sim3Error> {
    let mut memory: HashMap<Identifier, IrValue> = HashMap::new();

    // Decode the flattened argument list per the input schema (ir_vm.rs:191-211).
    let mut idx = 0usize;
    for input in input_schema(ir)? {
        let w = input.val_t.encoded_len();
        if idx + w > preimage.inputs.len() {
            return Err(Sim3Error::Inputs(format!(
                "not enough raw inputs: ran out at index {idx} while decoding {:?}",
                input.name
            )));
        }
        let value = decode_offcircuit(&preimage.inputs[idx..idx + w], &input.val_t)
            .map_err(|e| Sim3Error::Inputs(format!("{e}")))?;
        memory.insert(input.name, value);
        idx += w;
    }
    if idx != preimage.inputs.len() {
        return Err(Sim3Error::Inputs(format!(
            "expected {idx} raw inputs, received {}",
            preimage.inputs.len()
        )));
    }

    // The PI vector opens with the binding input, then (when enabled) the
    // communications commitment (ir_vm.rs:213-221).
    let mut pis: Vec<Fr> = vec![preimage.binding_input];
    if ir.do_communications_commitment {
        pis.push(
            preimage
                .communications_commitment
                .ok_or_else(|| {
                    Sim3Error::CommCommitment("expected communications commitment".into())
                })?
                .0,
        );
    }
    let mut pi_skips: Vec<Option<usize>> = Vec::new();
    let mut public_transcript_inputs_idx = 0usize;
    let mut public_transcript_outputs_idx = 0usize;
    let mut private_transcript_idx = 0usize;
    let mut outputs: Vec<IrValue> = Vec::new();
    let mut op_counts: BTreeMap<&'static str, u32> = BTreeMap::new();

    for (at, ins) in ir.instructions.iter().enumerate() {
        let op = op_name(ins);
        *op_counts.entry(op).or_default() += 1;
        match ins {
            // ir_vm.rs:287-299
            I::Encode { input, outputs } => {
                let val = operand(&memory, input, at, op)?;
                let encoded = encode_offcircuit(&val);
                if encoded.len() != outputs.len() {
                    return Err(fail(
                        at,
                        op,
                        format!(
                            "unexpected output length of encode instruction: {:?}",
                            ir_type_of(&val)
                        ),
                    ));
                }
                for (out_id, enc_val) in outputs.iter().zip(encoded) {
                    memory.insert(out_id.clone(), enc_val);
                }
            }
            // ir_vm.rs:300-321 — typed arithmetic via zkir-v3's own helpers.
            I::Add { a, b, output } => {
                let a = operand(&memory, a, at, op)?;
                let b = operand(&memory, b, at, op)?;
                let result = add_offcircuit(&a, &b).map_err(|e| fail(at, op, format!("{e}")))?;
                memory.insert(output.clone(), result);
            }
            I::Mul { a, b, output } => {
                let a = operand(&memory, a, at, op)?;
                let b = operand(&memory, b, at, op)?;
                let result = mul_offcircuit(&a, &b).map_err(|e| fail(at, op, format!("{e}")))?;
                memory.insert(output.clone(), result);
            }
            I::Neg { a, output } => {
                let a = operand(&memory, a, at, op)?;
                let result = neg_offcircuit(&a).map_err(|e| fail(at, op, format!("{e}")))?;
                memory.insert(output.clone(), result);
            }
            I::Inv { a, output } => {
                let a = operand(&memory, a, at, op)?;
                let result = inv_offcircuit(&a).map_err(|e| fail(at, op, format!("{e}")))?;
                memory.insert(output.clone(), result);
            }
            // ir_vm.rs:322-325
            I::Not { a, output } => {
                let result = IrValue::Native(Fr::from(!operand_bool(&memory, a, at, op)? as u64));
                memory.insert(output.clone(), result);
            }
            // ir_vm.rs:326-330
            I::ConstrainEq { a, b } => {
                let a = operand(&memory, a, at, op)?;
                let b = operand(&memory, b, at, op)?;
                constrain_eq_offcircuit(&a, &b).map_err(|e| fail(at, op, format!("{e}")))?;
            }
            // ir_vm.rs:331-336
            I::CondSelect { bit, a, b, output } => {
                let bit_val = operand_bool(&memory, bit, at, op)?;
                let a_val = operand(&memory, a, at, op)?;
                let b_val = operand(&memory, b, at, op)?;
                let result = select_offcircuit(bit_val, &a_val, &b_val)
                    .map_err(|e| fail(at, op, format!("{e}")))?;
                memory.insert(output.clone(), result);
            }
            // ir_vm.rs:337-341
            I::Assert { cond } => {
                if !operand_bool(&memory, cond, at, op)? {
                    return Err(fail(at, op, "failed direct assertion"));
                }
            }
            // ir_vm.rs:342-347
            I::TestEq { a, b, output } => {
                let a = operand(&memory, a, at, op)?;
                let b = operand(&memory, b, at, op)?;
                let result =
                    test_eq_offcircuit(&a, &b).map_err(|e| fail(at, op, format!("{e}")))?;
                memory.insert(output.clone(), IrValue::Native(Fr::from(result as u64)));
            }
            // ir_vm.rs:348-366 — a guarded-off read yields the type's
            // default and consumes nothing.
            I::PublicInput {
                guard,
                val_t,
                output,
            } => {
                let val = match guard {
                    Some(guard) if !operand_bool(&memory, guard, at, op)? => {
                        default_ir_value(val_t)
                    }
                    _ => {
                        let w = val_t.encoded_len();
                        let raw = take_raw(
                            &preimage.public_transcript_outputs,
                            public_transcript_outputs_idx,
                            w,
                            at,
                            op,
                            "public transcript outputs",
                        )?;
                        public_transcript_outputs_idx += w;
                        decode_offcircuit(raw, val_t).map_err(|e| fail(at, op, format!("{e}")))?
                    }
                };
                memory.insert(output.clone(), val);
            }
            // ir_vm.rs:367-386
            I::PrivateInput {
                guard,
                val_t,
                output,
            } => {
                let val = match guard {
                    Some(guard) if !operand_bool(&memory, guard, at, op)? => {
                        default_ir_value(val_t)
                    }
                    _ => {
                        let w = val_t.encoded_len();
                        let raw = take_raw(
                            &preimage.private_transcript,
                            private_transcript_idx,
                            w,
                            at,
                            op,
                            "private transcript",
                        )?;
                        private_transcript_idx += w;
                        decode_offcircuit(raw, val_t).map_err(|e| fail(at, op, format!("{e}")))?
                    }
                };
                memory.insert(output.clone(), val);
            }
            // ir_vm.rs:387-390
            I::Copy { val, output } => {
                let val = operand(&memory, val, at, op)?;
                memory.insert(output.clone(), val);
            }
            // ir_vm.rs:391
            I::ConstrainToBoolean { val } => {
                operand_bool(&memory, val, at, op)?;
            }
            // ir_vm.rs:392-394
            I::ConstrainBits { val, bits } => {
                operand_bits(&memory, val, Some(*bits), at, op)?;
            }
            // ir_vm.rs:395-411
            I::DivModPowerOfTwo { val, bits, outputs } => {
                if outputs.len() != 2 {
                    return Err(fail(at, op, "DivModPowerOfTwo requires exactly 2 outputs"));
                }
                if *bits as usize > FR_BYTES_STORED * 8 {
                    return Err(fail(at, op, "excessive bit count"));
                }
                let val_bits = operand_bits(&memory, val, None, at, op)?;
                memory.insert(
                    outputs[0].clone(),
                    IrValue::Native(from_bits(val_bits[*bits as usize..].iter().copied())),
                );
                memory.insert(
                    outputs[1].clone(),
                    IrValue::Native(from_bits(val_bits[..*bits as usize].iter().copied())),
                );
            }
            // ir_vm.rs:412-453
            I::ReconstituteField {
                divisor,
                modulus,
                bits,
                output,
            } => {
                if *bits as usize > FR_BYTES_STORED * 8 {
                    return Err(fail(at, op, "excessive bit count"));
                }
                let max_bits = bits_of(Fr::from(-1i64));
                let modulus_bits = operand_bits(&memory, modulus, Some(*bits), at, op)?;
                let divisor_bits =
                    operand_bits(&memory, divisor, Some(FR_BITS as u32 - *bits), at, op)?;
                let cmp = modulus_bits
                    .iter()
                    .chain(divisor_bits.iter())
                    .rev()
                    .zip(max_bits[..FR_BITS].iter().rev())
                    .map(|(ab, max)| ab.cmp(max))
                    .fold(
                        std::cmp::Ordering::Equal,
                        |prefix, local| if prefix.is_eq() { local } else { prefix },
                    );
                if cmp.is_gt() {
                    return Err(fail(at, op, "reconstituted element overflows field"));
                }
                let power = (0..*bits).fold(Fr::from(1u64), |acc, _| Fr::from(2u64) * acc);
                let modulus = operand_fr(&memory, modulus, at, op)?;
                let divisor = operand_fr(&memory, divisor, at, op)?;
                memory.insert(output.clone(), IrValue::Native(power * divisor + modulus));
            }
            // ir_vm.rs:454-462
            I::LessThan { a, b, bits, output } => {
                let a = from_bits(operand_bits(&memory, a, Some(*bits), at, op)?.into_iter());
                let b = from_bits(operand_bits(&memory, b, Some(*bits), at, op)?.into_iter());
                memory.insert(output.clone(), IrValue::Native(Fr::from((a < b) as u64)));
            }
            // ir_vm.rs:463-467 — reduction mod the Jubjub scalar order.
            I::JubjubScalarFromNative { native, output } => {
                let x = operand_fr(&memory, native, at, op)?;
                memory.insert(
                    output.clone(),
                    IrValue::JubjubScalar(native_to_jubjub_scalar(&x)),
                );
            }
            // ir_vm.rs:468-477
            I::TransientHash { inputs, output } => {
                let vals = inputs
                    .iter()
                    .map(|i| operand_fr(&memory, i, at, op))
                    .collect::<Result<Vec<Fr>, _>>()?;
                memory.insert(output.clone(), IrValue::Native(transient_hash(&vals)));
            }
            // ir_vm.rs:478-506 — SHA-256 / Keccak-256 over the FAB-aligned
            // byte encoding of native inputs; result is Bytes<32>.
            I::PersistentHash {
                alignment,
                inputs,
                output,
            }
            | I::Keccak256 {
                alignment,
                inputs,
                output,
            } => {
                let inputs = inputs
                    .iter()
                    .map(|i| operand_fr(&memory, i, at, op))
                    .collect::<Result<Vec<Fr>, _>>()?;
                let value = alignment.parse_field_repr(&inputs).ok_or_else(|| {
                    fail(at, op, format!("inputs did not match alignment: {inputs:?}"))
                })?;
                let mut repr = Vec::new();
                ValueReprAlignedValue(value).binary_repr(&mut repr);
                let hash_output: [u8; 32] = match ins {
                    I::PersistentHash { .. } => Sha256::digest(&repr).into(),
                    _ => Keccak256::digest(&repr).into(),
                };
                memory.insert(output.clone(), IrValue::Bytes32(hash_output));
            }
            // ir_vm.rs:507-543 — v3's public-input block. A guarded-off
            // Impact still pushes `count` *zeros* into the PI vector
            // (matching the in-circuit `select(guard, x, 0)`) and records
            // the skip; a taken one pushes the values and checks them
            // against the preimage's declared public transcript inputs.
            I::Impact { guard, inputs } => {
                let count = inputs.len();
                if !operand_bool(&memory, guard, at, op)? {
                    for _ in inputs {
                        pis.push(Fr::from(0u64));
                    }
                    pi_skips.push(Some(count));
                } else {
                    for input in inputs {
                        let x = operand_fr(&memory, input, at, op)?;
                        pis.push(x);
                        public_transcript_inputs_idx += 1;
                    }
                    pi_skips.push(None);
                    for i in 0..count {
                        let idx = public_transcript_inputs_idx - count + i;
                        let expected = preimage.public_transcript_inputs.get(idx).copied();
                        let computed = Some(pis[pis.len() - count + i]);
                        if expected != computed {
                            return Err(fail(
                                at,
                                op,
                                format!(
                                    "public transcript input mismatch for input {idx}; \
                                     expected: {expected:?}, computed: {computed:?}"
                                ),
                            ));
                        }
                    }
                }
            }
            // ir_vm.rs:544-552
            I::HashToCurve { inputs, output } => {
                let vals = inputs
                    .iter()
                    .map(|i| operand_fr(&memory, i, at, op))
                    .collect::<Result<Vec<Fr>, _>>()?;
                memory.insert(output.clone(), IrValue::JubjubPoint(hash_to_curve(&vals).0));
            }
            // ir_vm.rs:553-558
            I::EcMul { a, scalar, output } => {
                let p = operand(&memory, a, at, op)?;
                let s = operand(&memory, scalar, at, op)?;
                let r = ec_mul_offcircuit(&p, &s).map_err(|e| fail(at, op, format!("{e}")))?;
                memory.insert(output.clone(), r);
            }
            // ir_vm.rs:559-568
            I::EcMulGenerator { scalar, output } => {
                let s = operand(&memory, scalar, at, op)?;
                let p = match ir_type_of(&s) {
                    IrType::JubjubScalar => IrValue::JubjubPoint(JubjubSubgroup::generator()),
                    IrType::Secp256k1Scalar => {
                        IrValue::Secp256k1Point(k256::K256::generator())
                    }
                    t => {
                        return Err(fail(
                            at,
                            op,
                            format!("unsupported EcMulGenerator for scalar of type {t:?}"),
                        ))
                    }
                };
                let r = ec_mul_offcircuit(&p, &s).map_err(|e| fail(at, op, format!("{e}")))?;
                memory.insert(output.clone(), r);
            }
            // ir_vm.rs:569-574
            I::IntoCoordinates { point, outputs } => {
                let p = operand(&memory, point, at, op)?;
                let coordinates =
                    into_coordinates_offcircuit(&p).map_err(|e| fail(at, op, format!("{e}")))?;
                memory.insert(outputs.0.clone(), coordinates.0);
                memory.insert(outputs.1.clone(), coordinates.1);
            }
            // ir_vm.rs:575-580
            I::FromCoordinates { inputs, output } => {
                let x = operand(&memory, &inputs.0, at, op)?;
                let y = operand(&memory, &inputs.1, at, op)?;
                let p = from_coordinates_offcircuit(&x, &y)
                    .map_err(|e| fail(at, op, format!("{e}")))?;
                memory.insert(output.clone(), p);
            }
            // ir_vm.rs:581-585
            I::IntoBytes32 { input, output } => {
                let x = operand(&memory, input, at, op)?;
                let bytes =
                    into_bytes32_offcircuit(&x).map_err(|e| fail(at, op, format!("{e}")))?;
                memory.insert(output.clone(), bytes);
            }
            // ir_vm.rs:586-595
            I::FromBytes32 {
                val_t,
                bytes,
                output,
            } => {
                let bytes = operand(&memory, bytes, at, op)?;
                let bytes: [u8; 32] =
                    bytes.try_into().map_err(|e| fail(at, op, format!("{e}")))?;
                let x = from_bytes32_offcircuit(val_t, &bytes)
                    .map_err(|e| fail(at, op, format!("{e}")))?;
                memory.insert(output.clone(), x);
            }
            // ir_vm.rs:596-601
            I::ReverseBytes { bytes, output } => {
                let bytes = operand(&memory, bytes, at, op)?;
                let mut bytes: [u8; 32] =
                    bytes.try_into().map_err(|e| fail(at, op, format!("{e}")))?;
                bytes.reverse();
                memory.insert(output.clone(), IrValue::Bytes32(bytes));
            }
            // ir_vm.rs:602-610 — low = first 31 bytes LE, high = last byte.
            I::Bytes32IntoLowHigh { bytes, outputs } => {
                let bytes = operand(&memory, bytes, at, op)?;
                let mut bytes: [u8; 32] =
                    bytes.try_into().map_err(|e| fail(at, op, format!("{e}")))?;
                let high = IrValue::Native(Fr::from(bytes[31] as u64));
                bytes[31] = 0;
                let low = from_bytes32_offcircuit(&IrType::Native, &bytes)
                    .map_err(|e| fail(at, op, format!("{e}")))?;
                memory.insert(outputs.0.clone(), low);
                memory.insert(outputs.1.clone(), high);
            }
            // ir_vm.rs:611-624
            I::Bytes32FromLowHigh { inputs, output } => {
                let low = operand(&memory, &inputs.0, at, op)?;
                let high = operand(&memory, &inputs.1, at, op)?;
                let bytes_low: [u8; 32] = into_bytes32_offcircuit(&low)
                    .and_then(TryInto::try_into)
                    .map_err(|e| fail(at, op, format!("{e}")))?;
                let bytes_high: [u8; 32] = into_bytes32_offcircuit(&high)
                    .and_then(TryInto::try_into)
                    .map_err(|e| fail(at, op, format!("{e}")))?;
                if bytes_low[31] != 0 || bytes_high[1..].iter().any(|b| *b != 0) {
                    return Err(fail(
                        at,
                        op,
                        "Bytes32FromLowHigh: low operand must fit in 31 bytes (be less than \
                         2^248) and high operand must fit in a single byte (be less than 256)",
                    ));
                }
                let mut out_bytes = bytes_low;
                out_bytes[31] = bytes_high[0];
                memory.insert(output.clone(), IrValue::Bytes32(out_bytes));
            }
            // ir_vm.rs:625-644 — outputs are type-checked against the
            // circuit's output signature.
            I::Output { vals } => {
                if vals.len() != ir.outputs.len() {
                    return Err(fail(
                        at,
                        op,
                        format!(
                            "Output: signature declares {} return values but instruction has {}",
                            ir.outputs.len(),
                            vals.len()
                        ),
                    ));
                }
                for (i, (val, expected_t)) in vals.iter().zip(ir.outputs.iter()).enumerate() {
                    let value = operand(&memory, val, at, op)?;
                    if ir_type_of(&value) != *expected_t {
                        return Err(fail(
                            at,
                            op,
                            format!(
                                "Output position {i}: signature declares {expected_t:?} but \
                                 operand has runtime type {:?}",
                                ir_type_of(&value)
                            ),
                        ));
                    }
                    outputs.push(value);
                }
            }
        }
    }

    // Every transcript must be consumed exactly (ir_vm.rs:648-661).
    if preimage.public_transcript_inputs.len() != public_transcript_inputs_idx
        || preimage.public_transcript_outputs.len() != public_transcript_outputs_idx
        || preimage.private_transcript.len() != private_transcript_idx
    {
        return Err(Sim3Error::Transcript(format!(
            "public inputs {}/{}, public outputs {}/{}, private {}/{}",
            public_transcript_inputs_idx,
            preimage.public_transcript_inputs.len(),
            public_transcript_outputs_idx,
            preimage.public_transcript_outputs.len(),
            private_transcript_idx,
            preimage.private_transcript.len(),
        )));
    }

    // Communications commitment: transient_commit over the *raw* preimage
    // inputs followed by the encoded outputs (ir_vm.rs:662-681). (The
    // in-circuit twin at ir_vm.rs:1184-1199 rebuilds the same list from
    // memory, skipping absent inputs — off-circuit every declared input was
    // decoded into memory above, so the lists coincide.)
    if ir.do_communications_commitment {
        let comm_comm = preimage.communications_commitment.ok_or_else(|| {
            Sim3Error::CommCommitment("expected communications randomness".into())
        })?;
        let mut comm_comm_inputs: Vec<Fr> = Vec::new();
        comm_comm_inputs.extend(preimage.inputs.iter());
        for value in outputs.iter() {
            for ir_val in encode_offcircuit(value) {
                comm_comm_inputs.push(
                    ir_val
                        .try_into()
                        .map_err(|e| Sim3Error::CommCommitment(format!("{e}")))?,
                );
            }
        }
        if comm_comm.0 != transient_commit(&comm_comm_inputs[..], comm_comm.1) {
            return Err(Sim3Error::CommCommitment(
                "communications commitment mismatch".into(),
            ));
        }
    }

    Ok(Run3 {
        memory,
        pis,
        pi_skips,
        binding_input: preimage.binding_input,
        comm_comm: preimage.communications_commitment,
        outputs,
        consumed_private: private_transcript_idx,
        consumed_public: public_transcript_outputs_idx,
        op_counts,
    })
}

// --- reporting -------------------------------------------------------------------

#[cfg(feature = "unstable")]
/// A resolved disclosure: what the circuit made public, by label and by the
/// value it took in this run — the v3 twin of [`crate::DisclosedValue`].
///
/// `values` is a list because a v3 disclosure record covers one *logical*
/// value, which may be several wires (a `Bytes<32>`'s `[hi, lo]`); see
/// [`minocrab::v3::Disclosure3`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct DisclosedValue3 {
    pub label: String,
    pub kind: &'static str,
    /// The concrete disclosed wires in this run, in wire order.
    pub values: Vec<String>,
}

#[cfg(feature = "unstable")]
/// Structured simulation report: what ran, what it cost, what it disclosed
/// — the v3 twin of [`crate::Report`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct Report3 {
    pub instructions_executed: u32,
    pub op_counts: BTreeMap<&'static str, u32>,
    pub witnesses_consumed: usize,
    pub outputs: Vec<String>,
    /// The proof system's public-input vector (v2's `public_statement` is
    /// the transcript; v3's statement IS `pis`).
    pub public_statement: Vec<String>,
    /// Everything this circuit disclosed, with the values of this run.
    pub disclosures: Vec<DisclosedValue3>,
}

#[cfg(feature = "unstable")]
fn value_display(value: &IrValue) -> String {
    match value {
        IrValue::Native(fr) => format!("{fr:?}"),
        other => format!("{other:?}"),
    }
}

#[cfg(feature = "unstable")]
/// Build the structured report for a v3 run — the v3 twin of
/// [`crate::report`].
///
/// A disclosed value is resolved through the run's memory by the
/// [`Identifier`] the record carries, or taken straight from the record when
/// it is a constant. `"<not computed>"` can only appear for a value the run
/// never produced, which for a completed run means a disclosure of a wire that
/// no instruction reached.
pub fn report(run: &Run3, disclosures: &[minocrab::v3::Disclosure3]) -> Report3 {
    Report3 {
        instructions_executed: run.op_counts.values().sum(),
        op_counts: run.op_counts.clone(),
        witnesses_consumed: run.consumed_private,
        outputs: run.outputs.iter().map(value_display).collect(),
        public_statement: run.pis.iter().map(|fr| format!("{fr:?}")).collect(),
        disclosures: disclosures
            .iter()
            .map(|d| DisclosedValue3 {
                label: d.label.clone(),
                kind: match d.kind {
                    minocrab::DisclosureKind::Disclosed => "disclosed",
                    minocrab::DisclosureKind::Statement => "statement",
                    minocrab::DisclosureKind::Output => "output",
                },
                values: d
                    .values
                    .iter()
                    .map(|value| match value {
                        minocrab::v3::DisclosedWire::Named(id) => run
                            .memory
                            .get(id)
                            .map(value_display)
                            .unwrap_or_else(|| "<not computed>".into()),
                        // A constant needs no run to resolve — see
                        // `DisclosedWire::Constant`.
                        minocrab::v3::DisclosedWire::Constant(imm) => format!("{imm:?}"),
                    })
                    .collect(),
            })
            .collect(),
    }
}

#[cfg(feature = "unstable")]
/// Simulate a compiled v3 circuit and produce the structured report — the
/// v3 twin of [`crate::simulate_compiled`].
pub fn simulate_compiled(
    compiled: &minocrab::v3::Compiled3,
    preimage: &ProofPreimage,
) -> Result<(Run3, Report3), Sim3Error> {
    let run = simulate(&compiled.ir, preimage).map_err(|e| name_the_failed_assert(compiled, e))?;
    let report = report(&run, &compiled.disclosures);
    Ok((run, report))
}

#[cfg(feature = "unstable")]
/// A failed `assert` that was written with a MESSAGE says what it meant.
///
/// ZKIR has nowhere to put Compact's `assert(cond, "message")` second
/// argument, so the frontend keeps it beside the stream
/// (`Compiled3::assert_messages`, one entry per assert that carries one) and
/// this is where it is spent: "instruction 41 (assert): failed direct
/// assertion" becomes "… : failed assertion: Chain ID must be positive".
fn name_the_failed_assert(compiled: &minocrab::v3::Compiled3, error: Sim3Error) -> Sim3Error {
    match error {
        Sim3Error::Failed {
            at,
            op: op @ "assert",
            message,
        } => Sim3Error::Failed {
            at,
            op,
            message: match compiled.assert_message(at) {
                Some(named) => format!("failed assertion: {named}"),
                None => message,
            },
        },
        other => other,
    }
}

// --- cost + profiling ------------------------------------------------------------

/// Static circuit cost via Midnight's own cost model (k = log2 rows needed)
/// — the v3 twin of [`crate::cost`].
pub fn cost(ir: &IrSource) -> (u8, usize) {
    let model = ir.model();
    (model.k(), model.rows())
}

/// The body of the test `#[circuit(max_k = N)]` generates: the circuit's
/// `k` against the budget its author declared.
///
/// A CEILING, not an equality. `k` is `log2` of the proving-table rows, so it
/// is what decides the proving key, the prover's RAM and the wall clock —
/// crossing a power of two is the event a budget exists to catch, and it is
/// invisible to `row_snapshot` for any circuit not in that table. Coming in
/// UNDER budget is a win and passes; the message says by how much, so the
/// declaration can be tightened deliberately rather than drifting.
///
/// Lives here rather than in the macro's expansion so that the wording is
/// one string with one place to fix, and so the expansion stays a call.
#[track_caller]
pub fn assert_max_k(circuit: &str, compiled: &minocrab::v3::Compiled3, budget: u8) {
    let (k, rows) = cost(&compiled.ir);
    assert!(
        k <= budget,
        "{circuit}: k={k} ({rows} rows) is over the declared budget of \
         max_k = {budget}. A circuit's k sets its proving key, its prover RAM \
         and its wall clock, so this is a cost REGRESSION, not a snapshot \
         drift: either take the rows back out, or raise the budget in the \
         same commit that explains why it moved."
    );
    if k < budget {
        println!(
            "{circuit}: k={k} ({rows} rows), {} under the declared budget of \
             max_k = {budget} — tighten it when the headroom is meant to stay",
            budget - k
        );
    }
}

/// Attribute each instruction to its innermost region and price the circuit
/// — the v3 twin of [`crate::profile`]. Instructions outside every region
/// land in "(top level)".
///
/// Regions are attributed twice: by instruction count, and by *estimated
/// rows* ([`rowcost`]) — the two disagree wildly wherever crypto lives, and
/// rows are what k, prove time and RAM track.
pub fn profile(compiled: &minocrab::v3::Compiled3) -> crate::Profile {
    let instructions = compiled.ir.instructions.as_slice();
    let (k, rows) = cost(&compiled.ir);
    let est = rowcost::est_rows(&compiled.ir);

    // regions are pushed on scope exit, so for nested regions the inner one
    // appears first — the first region containing an index is the innermost.
    let region_of = |idx: usize| -> &str {
        compiled
            .regions
            .iter()
            .find(|r| r.start <= idx && idx < r.end)
            .map(|r| r.label.as_str())
            .unwrap_or("(top level)")
    };

    let mut by_label: BTreeMap<&str, crate::RegionCost> = BTreeMap::new();
    for (idx, ins) in instructions.iter().enumerate() {
        let label = region_of(idx);
        let entry = by_label.entry(label).or_insert_with(|| crate::RegionCost {
            label: label.to_string(),
            instructions: 0,
            percent: 0.0,
            est_rows: Some(0),
            est_rows_percent: Some(0.0),
            op_counts: BTreeMap::new(),
        });
        entry.instructions += 1;
        *entry.est_rows.get_or_insert(0) += est[idx];
        *entry.op_counts.entry(op_name(ins)).or_default() += 1;
    }

    let total = instructions.len().max(1);
    let est_total: usize = est.iter().sum();
    let mut regions: Vec<crate::RegionCost> = by_label
        .into_values()
        .map(|mut r| {
            r.percent = r.instructions as f64 * 100.0 / total as f64;
            r.est_rows_percent =
                Some(r.est_rows.unwrap_or(0) as f64 * 100.0 / est_total.max(1) as f64);
            r
        })
        .collect();
    // Rows first: instruction count is the misleading order (a keccak is one
    // instruction and a tenth of the circuit).
    regions.sort_by(|a, b| {
        b.est_rows
            .cmp(&a.est_rows)
            .then(b.instructions.cmp(&a.instructions))
            .then(a.label.cmp(&b.label))
    });

    crate::Profile {
        k,
        rows,
        total_instructions: instructions.len(),
        est_rows_total: Some(est_total),
        regions,
    }
}
