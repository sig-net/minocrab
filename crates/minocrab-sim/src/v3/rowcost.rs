//! Estimated row cost per ZKIR v3 instruction — the model that turns a
//! region's instruction mix into its share of the *proving table*, which is
//! what k, prove time and RAM actually track.
//!
//! Why this exists: profiles attributed by instruction count invert the
//! picture. In the vault's `claim`, the ECDSA region is 12.6% of the
//! instructions and roughly half the rows, while the two Impact-heavy
//! regions are half the instructions and ~2% of the rows
//! (notes/vault-optimization.org, "Headline finding").
//!
//! Every constant below is a *marginal* cost measured by
//! `examples/cryptocost.rs` (`cargo run --release -p minocrab-sim --example
//! cryptocost`), which re-measures them and prints the deviation — run it
//! after any toolchain bump. Marginal means "one more of these in a circuit
//! that already has one": the first use of a hash or a curve additionally
//! stands up its chip (zkir-v3 enables chips per circuit, `used_chips`,
//! ir_vm.rs:1212), a fixed cost that belongs to no region and shows up as
//! the profile's unattributed residual.
//!
//! Costs are k-independent: `cryptocost` prices every shape twice, in a
//! minimal circuit and in one padded to ~35k rows, and the two columns
//! agree to a row or two (so a 248-bit range check is 62 rows at every
//! circuit size, not the ~17 the analysis guessed for k=16).

use std::collections::HashMap;

use midnight_transient_crypto::fab::AlignmentExt;
use minocrab_zkir::v3::{Identifier, Instruction as I, IrSource, IrType, Operand};

// --- measured constants -----------------------------------------------------------

/// SHA-256 per 64-byte block; blocks = `ceil((len + 9) / 64)`.
pub const SHA256_PER_BLOCK: usize = 1_879;
/// Keccak-256 per 136-byte block; blocks = `floor(len / 136) + 1`.
pub const KECCAK_PER_BLOCK: usize = 4_175;
/// Keccak-256's per-input-byte term (packing the FAB limbs into bytes).
pub const KECCAK_PER_BYTE: f64 = 0.25;
/// Poseidon (`transient_hash`) per permutation; the sponge absorbs
/// [`POSEIDON_RATE`] field elements per permutation.
pub const POSEIDON_PER_PERMUTATION: usize = 22;
pub const POSEIDON_RATE: usize = 2;
/// `hash_to_curve` (Poseidon + the Jubjub map-to-curve).
pub const HASH_TO_CURVE: usize = 237;

/// Scalar multiplication on a foreign curve (secp256k1/secp256r1/curve25519):
/// the dominant term of an ECDSA verification, two of them per verify.
pub const EC_MUL_FOREIGN: usize = 11_329;
/// Foreign-curve point addition.
pub const EC_ADD_FOREIGN: usize = 189;
/// Foreign base/scalar field arithmetic (emulated over the native field) —
/// cheap: the chip carries the field, the operations are lookups.
pub const FOREIGN_MUL: usize = 24;
pub const FOREIGN_INV: usize = 24;
pub const FOREIGN_EQ: usize = 31;
/// Foreign field element → `Bytes<32>` (canonical-form decomposition), and back.
pub const INTO_BYTES32_FOREIGN: usize = 396;
pub const FROM_BYTES32_FOREIGN: usize = 139;

/// Jubjub, the native embedded curve: two orders of magnitude under secp256k1.
pub const EC_MUL_JUBJUB: usize = 252;
pub const JUBJUB_SCALAR_FROM_NATIVE: usize = 394;

/// Native field element → `Bytes<32>` and `Bytes<32>` → (low, high): the
/// full-width decompositions cost ~143 rows, the recompositions ~8.
pub const DECOMPOSE_BYTES32: usize = 143;
pub const COMPOSE_BYTES32: usize = 8;
/// `reverse_bytes`: free — a permutation of already-decomposed bytes.
pub const REVERSE_BYTES: usize = 0;
/// `div_mod_power_of_two` on a full-width (248-bit) operand; narrower
/// operands cost 89-101 (examples/opcost.rs), which this model does not see
/// — the instruction carries the split, not the operand's width.
pub const DIV_MOD: usize = 143;
/// `less_than`: a small base plus a term in the compared width.
pub const LESS_THAN_BASE: usize = 6;

/// Everything without its own entry: native add/mul/select/assert, one
/// Impact element, one transcript read — 1-2 rows each.
pub const SIMPLE: usize = 1;

/// Rows a `bits`-wide range check (`constrain_bits`) costs: 4 bits per row,
/// flat in k (`nr_pow2range_cols = 4`, ir_vm.rs:1248).
pub fn range_check_rows(bits: u32) -> usize {
    (bits as usize).div_ceil(4)
}

/// Rows one `transient_hash` of `inputs` field elements costs.
pub fn poseidon_rows(inputs: usize) -> usize {
    inputs.max(1).div_ceil(POSEIDON_RATE) * POSEIDON_PER_PERMUTATION
}

/// SHA-256 blocks for a `len`-byte message (1-byte marker + 8-byte length).
pub fn sha256_blocks(len: usize) -> usize {
    (len + 9).div_ceil(64)
}

/// Keccak-256 blocks for a `len`-byte message (≥ 1 padding byte, 136-byte rate).
pub fn keccak_blocks(len: usize) -> usize {
    len / 136 + 1
}

/// Rows one `persistent_hash` over `len` bytes costs.
pub fn sha256_rows(len: usize) -> usize {
    sha256_blocks(len) * SHA256_PER_BLOCK
}

/// Rows one `keccak256` over `len` bytes costs.
pub fn keccak_rows(len: usize) -> usize {
    keccak_blocks(len) * KECCAK_PER_BLOCK + (KECCAK_PER_BYTE * len as f64) as usize
}

// --- type inference ---------------------------------------------------------------

/// Static value types by identifier, seeded from the circuit's input schema
/// and the typed transcript reads and propagated forward. ZKIR v3 is in SSA
/// form with a linear instruction list, so one forward pass suffices;
/// anything unresolved (an operand of an instruction we do not type) is
/// treated as `Native`, the cheap case.
fn infer_types(ir: &IrSource) -> HashMap<Identifier, IrType> {
    let mut types: HashMap<Identifier, IrType> = HashMap::new();
    for input in &ir.inputs {
        // `TypedIdentifier`'s fields are `pub(crate)`; recover them through
        // its serde form, as `super::input_schema` does.
        if let Ok(serde_json::Value::Object(obj)) = serde_json::to_value(input) {
            if let (Some(name), Some(val_t)) = (obj.get("name"), obj.get("type")) {
                if let (Ok(name), Ok(val_t)) = (
                    serde_json::from_value::<Identifier>(name.clone()),
                    serde_json::from_value::<IrType>(val_t.clone()),
                ) {
                    types.insert(name, val_t);
                }
            }
        }
    }

    let type_of = |types: &HashMap<Identifier, IrType>, o: &Operand| -> IrType {
        match o {
            Operand::Variable(id) => types.get(id).cloned().unwrap_or(IrType::Native),
            Operand::Immediate(_) => IrType::Native,
        }
    };

    for ins in ir.instructions.iter() {
        match ins {
            I::Add { a, b, output } => {
                // An immediate operand is native; the other one carries the type.
                let t = match type_of(&types, a) {
                    IrType::Native => type_of(&types, b),
                    t => t,
                };
                types.insert(output.clone(), t);
            }
            I::Mul { a, b, output } => {
                let t = match type_of(&types, a) {
                    IrType::Native => type_of(&types, b),
                    t => t,
                };
                types.insert(output.clone(), t);
            }
            I::Neg { a, output } | I::Inv { a, output } | I::Copy { val: a, output } => {
                let t = type_of(&types, a);
                types.insert(output.clone(), t);
            }
            I::CondSelect { a, b, output, .. } => {
                let t = match type_of(&types, a) {
                    IrType::Native => type_of(&types, b),
                    t => t,
                };
                types.insert(output.clone(), t);
            }
            I::PublicInput { val_t, output, .. } | I::PrivateInput { val_t, output, .. } => {
                types.insert(output.clone(), val_t.clone());
            }
            I::FromBytes32 { val_t, output, .. } => {
                types.insert(output.clone(), val_t.clone());
            }
            I::PersistentHash { output, .. }
            | I::Keccak256 { output, .. }
            | I::IntoBytes32 { output, .. }
            | I::ReverseBytes { output, .. }
            | I::Bytes32FromLowHigh { output, .. } => {
                types.insert(output.clone(), IrType::Bytes32);
            }
            I::TransientHash { output, .. }
            | I::Not { a: _, output }
            | I::TestEq { output, .. }
            | I::LessThan { output, .. }
            | I::ReconstituteField { output, .. } => {
                types.insert(output.clone(), IrType::Native);
            }
            I::JubjubScalarFromNative { output, .. } => {
                types.insert(output.clone(), IrType::JubjubScalar);
            }
            I::HashToCurve { output, .. } => {
                types.insert(output.clone(), IrType::JubjubPoint);
            }
            I::EcMul { a, output, .. } => {
                let t = type_of(&types, a);
                types.insert(output.clone(), t);
            }
            I::EcMulGenerator { scalar, output } => {
                let t = match type_of(&types, scalar) {
                    IrType::Secp256k1Scalar => IrType::Secp256k1Point,
                    IrType::Secp256r1Scalar => IrType::Secp256r1Point,
                    IrType::Curve25519Scalar => IrType::Curve25519Point,
                    _ => IrType::JubjubPoint,
                };
                types.insert(output.clone(), t);
            }
            I::IntoCoordinates { point, outputs } => {
                let t = match type_of(&types, point) {
                    IrType::Secp256k1Point => IrType::Secp256k1Base,
                    IrType::Secp256r1Point => IrType::Secp256r1Base,
                    IrType::Curve25519Point => IrType::Curve25519Base,
                    _ => IrType::Native,
                };
                types.insert(outputs.0.clone(), t.clone());
                types.insert(outputs.1.clone(), t);
            }
            I::FromCoordinates { inputs, output } => {
                let t = match type_of(&types, &inputs.0) {
                    IrType::Secp256k1Base => IrType::Secp256k1Point,
                    IrType::Secp256r1Base => IrType::Secp256r1Point,
                    IrType::Curve25519Base => IrType::Curve25519Point,
                    _ => IrType::JubjubPoint,
                };
                types.insert(output.clone(), t);
            }
            I::Encode { outputs, .. } => {
                for out in outputs {
                    types.insert(out.clone(), IrType::Native);
                }
            }
            I::DivModPowerOfTwo { outputs, .. } => {
                for out in outputs {
                    types.insert(out.clone(), IrType::Native);
                }
            }
            I::Bytes32IntoLowHigh { outputs, .. } => {
                types.insert(outputs.0.clone(), IrType::Native);
                types.insert(outputs.1.clone(), IrType::Native);
            }
            I::Assert { .. }
            | I::ConstrainBits { .. }
            | I::ConstrainEq { .. }
            | I::ConstrainToBoolean { .. }
            | I::Impact { .. }
            | I::Output { .. } => {}
        }
    }
    types
}

/// Cost class of a value type: native field / `Bytes<32>` values are cheap,
/// Jubjub is the native embedded curve, everything else is emulated.
fn is_foreign(t: &IrType) -> bool {
    matches!(
        *t,
        IrType::Secp256k1Point
            | IrType::Secp256k1Base
            | IrType::Secp256k1Scalar
            | IrType::Secp256r1Point
            | IrType::Secp256r1Base
            | IrType::Secp256r1Scalar
            | IrType::Curve25519Point
            | IrType::Curve25519Base
            | IrType::Curve25519Scalar
    )
}

fn is_point(t: &IrType) -> bool {
    matches!(
        *t,
        IrType::JubjubPoint
            | IrType::Secp256k1Point
            | IrType::Secp256r1Point
            | IrType::Curve25519Point
    )
}

// --- the estimate -----------------------------------------------------------------

/// Estimated rows for every instruction of `ir`, in instruction order.
pub fn est_rows(ir: &IrSource) -> Vec<usize> {
    let types = infer_types(ir);
    let type_of = |o: &Operand| -> IrType {
        match o {
            Operand::Variable(id) => types.get(id).cloned().unwrap_or(IrType::Native),
            Operand::Immediate(_) => IrType::Native,
        }
    };
    // The type an instruction operates on, given two operands one of which
    // may be a native immediate.
    let binary_type = |a: &Operand, b: &Operand| -> IrType {
        match type_of(a) {
            IrType::Native => type_of(b),
            t => t,
        }
    };
    ir.instructions
        .iter()
        .map(|ins| match ins {
            I::PersistentHash { alignment, .. } => sha256_rows(alignment.bin_len()),
            I::Keccak256 { alignment, .. } => keccak_rows(alignment.bin_len()),
            I::TransientHash { inputs, .. } => poseidon_rows(inputs.len()),
            I::HashToCurve { .. } => HASH_TO_CURVE,
            I::EcMul { a, .. } => {
                if is_foreign(&type_of(a)) {
                    EC_MUL_FOREIGN
                } else {
                    EC_MUL_JUBJUB
                }
            }
            I::EcMulGenerator { scalar, .. } => {
                if is_foreign(&type_of(scalar)) {
                    EC_MUL_FOREIGN
                } else {
                    EC_MUL_JUBJUB
                }
            }
            I::JubjubScalarFromNative { .. } => JUBJUB_SCALAR_FROM_NATIVE,
            I::Add { a, b, .. } => {
                let t = binary_type(a, b);
                match (is_point(&t), is_foreign(&t)) {
                    // Foreign-curve point addition; Jubjub's is ~free.
                    (true, true) => EC_ADD_FOREIGN,
                    (true, false) => SIMPLE,
                    (false, true) => FOREIGN_MUL,
                    (false, false) => SIMPLE,
                }
            }
            I::Mul { a, b, .. } => {
                if is_foreign(&binary_type(a, b)) {
                    FOREIGN_MUL
                } else {
                    SIMPLE
                }
            }
            I::Inv { a, .. } | I::Neg { a, .. } => {
                if is_foreign(&type_of(a)) {
                    FOREIGN_INV
                } else {
                    SIMPLE
                }
            }
            I::TestEq { a, b, .. } | I::ConstrainEq { a, b } => {
                if is_foreign(&binary_type(a, b)) {
                    FOREIGN_EQ
                } else {
                    SIMPLE
                }
            }
            // The coordinates are already there; the cost lands on the
            // `into_bytes32` that follows.
            I::IntoCoordinates { .. } | I::FromCoordinates { .. } => SIMPLE,
            I::IntoBytes32 { input, .. } => {
                if is_foreign(&type_of(input)) {
                    INTO_BYTES32_FOREIGN
                } else {
                    DECOMPOSE_BYTES32
                }
            }
            I::FromBytes32 { val_t, .. } => {
                if is_foreign(val_t) {
                    FROM_BYTES32_FOREIGN
                } else {
                    COMPOSE_BYTES32
                }
            }
            I::ReverseBytes { .. } => REVERSE_BYTES,
            // `Bytes<32>` → (low, high) recomposes (cheap); (low, high) →
            // `Bytes<32>` decomposes the 248-bit limb (dear).
            I::Bytes32IntoLowHigh { .. } => COMPOSE_BYTES32,
            I::Bytes32FromLowHigh { .. } => DECOMPOSE_BYTES32,
            I::ConstrainBits { bits, .. } => range_check_rows(*bits),
            I::DivModPowerOfTwo { .. } => DIV_MOD,
            I::ReconstituteField { .. } => SIMPLE,
            I::LessThan { bits, .. } => LESS_THAN_BASE + (*bits as usize).div_ceil(64),
            I::Impact { inputs, .. } => inputs.len() * SIMPLE,
            I::Encode { outputs, .. } => outputs.len() * SIMPLE,
            I::Output { vals } => vals.len() * SIMPLE,
            // `Copy` is a rename; the prover pays nothing for it.
            I::Copy { .. } => 0,
            I::Assert { .. }
            | I::ConstrainToBoolean { .. }
            | I::Not { .. }
            | I::CondSelect { .. }
            | I::PublicInput { .. }
            | I::PrivateInput { .. } => SIMPLE,
        })
        .collect()
}
