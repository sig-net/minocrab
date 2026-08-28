//! The taint lint (M23 R3): every byte-atom hash-preimage limb must be
//! provably bounded to its own byte width, or constant.
//!
//! This mechanizes notes/api-safety-survey.org §B3 — "the limb packing is
//! only injective for in-range segments … without that the packing is not
//! injective and the digest binds nothing" — the one hazard class no test on
//! honest preimages can see, because an honest prover always supplies
//! in-range values.
//!
//! # What the chip already enforces, and what it cannot
//!
//! The in-circuit decoder behind `persistent_hash`/`keccak256` range-checks
//! every limb it absorbs: `fab_decode_to_bytes_atom` decomposes each `bytes`
//! limb with `assigned_to_le_bytes(f, Some(width))`, which makes the circuit
//! unsatisfiable if the limb exceeds its width (zkir-v3 ir_vm.rs:125-175;
//! midnight-circuits decomposition.rs, "Unsatisfiable Circuit"). So the LIMB
//! is always bound by the digest. What the chip cannot see is one level up:
//! a limb PACKED from several narrower segments (`a + b·2^8k + …`) is only
//! injective in those segments if each segment is bounded to its own slot.
//! The lint therefore asks for a derivable bound on the limb wire — and the
//! bound propagation below only succeeds when every wire feeding the packing
//! arithmetic is itself constrained-or-constant, which is exactly §B3's
//! precondition, checked mechanically.
//!
//! # The Impact/popeq warrant (M23 R3 ruling, dmd 2026-08-28)
//!
//! A wire embedded in an UNCONDITIONAL `popeq`/`popeqc` Impact op is bounded
//! to its limb's byte width. The warrant is EXTERNAL and two-linked: the
//! verifier checks the pushed elements against the transaction's declared
//! transcript, and the ledger accepts the transaction only if the
//! transcript's expected value equals the normalized stored value actually
//! read (`process_read`). Guarded reads are NOT marked — a false guard
//! pushes zeros, the comparison passes, and the wire is genuinely free.
//! See `mark_popeq` in this file for the exact parse and conditions.
//!
//! # Limitations, stated plainly
//!
//! What a clean run does and does not prove:
//!
//! - BOUNDS, not shift-layout disjointness. A packing whose segments overlap
//!   bit ranges is the serializer's own layout invariant, pinned by its
//!   byte-equality tests — not this lint's.
//! - The popeq bounds are CONDITIONAL ON THE LEDGER. Unlike every other
//!   marking rule (each cited to an in-circuit constraint), the popeq rule's
//!   chain runs through the ledger's normalization invariant and the
//!   transcript equality check — outside the circuit. A clean run therefore
//!   reads: "every hash-preimage limb is bounded in-circuit, or is an
//!   unconditional ledger read the platform binds". If the ledger's
//!   invariant broke, the lint would not know.
//! - Guard recognition is SYNTACTIC: only an immediate non-zero Impact guard
//!   counts as unconditional. A variable guard that is provably always 1
//!   still leaves its read unmarked (over-fires, never under-fires).
//! - popeq ONLY. Wires embedded in pushes (`push`/`pushs` cell contents) and
//!   dynamic `idx` keys also flow to the transcript, but their in-range
//!   argument is different (transaction well-formedness, not a read of
//!   normalized state) and is NOT encoded; such wires stay unbounded unless
//!   something in-circuit bounds them.
//! - Field-absorbing hashes (`TransientHash`, `HashToCurve`) are out of
//!   scope by design — no byte atoms, no packing-injectivity question.
//! - The operand↔atom mapping follows the in-circuit decoder's own
//!   consumption rule; a stream the decoder would reject (option/compress
//!   segments, arity mismatches) is reported as unmappable, not audited
//!   around.
//!
//! # Scope
//!
//! The subjects are `Keccak256` and `PersistentHash` — the two instructions
//! that carry an `alignment` and absorb byte atoms. `TransientHash` (and
//! `HashToCurve`) absorb native FIELD elements — no byte atoms, no
//! injective-packing concern — and are deliberately out of scope.
//!
//! # Soundness direction
//!
//! Under-marking is SAFE (the lint over-fires and a human looks); OVER-marking
//! is the danger (a false negative hides a real hole). Every marking rule
//! below cites the upstream in-circuit constraint that justifies it; when
//! unsure, we do not mark. A firing on an existing circuit goes to dmd before
//! any allowlist entry is written; extending the marking rules (with a cited
//! warrant) is preferred over allowlisting.

// Ordered maps for the same reason as passes.rs (M23 R4): std's
// randomly-seeded HashMap is opaque to a model checker, and this pass is a
// named future proof target.
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use midnight_base_crypto::fab::{Alignment, AlignmentAtom, AlignmentSegment};
use minocrab_zkir::Fr;
use minocrab_zkir::v3::{Identifier, Instruction, IrType, Operand};

/// Bytes a single field element can hold losslessly — the FAB limb width
/// (transient-crypto `FR_BYTES_STORED`; the same 31 as `bytes_limbs`).
const LIMB_BYTES: usize = 31;

/// One violation: a hash-preimage limb the lint cannot prove bounded, or a
/// preimage whose operand↔atom mapping is itself malformed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Index of the hash instruction in the stream.
    pub index: usize,
    /// `"keccak256"` or `"persistent_hash"`.
    pub hash: &'static str,
    /// What is wrong, naming the wire and the atom/limb.
    pub detail: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "instruction {} ({}): {}", self.index, self.hash, self.detail)
    }
}

/// Audit one circuit's instruction stream. Empty result = every byte-atom
/// hash-preimage limb is provably bounded to its own byte width or constant.
pub fn audit(instructions: &[Instruction]) -> Vec<Finding> {
    let cap = field_max();

    // Pass A — position-independent direct constraints. ZKIR v3 is SSA (no
    // identifier is ever rebound: upstream's synthesis memory is push-only
    // and `Builder3` mints fresh identifiers), so a constraint anywhere in
    // the stream bounds the wire for the whole circuit — the same argument
    // `dedup_range_constraints` makes. The wildcard here is the SAFE
    // direction: a missed constraint only under-marks, which over-fires.
    let mut bound: BTreeMap<String, Max> = BTreeMap::new();
    for ins in instructions {
        match ins {
            Instruction::ConstrainBits { val: Operand::Variable(id), bits } => {
                note(&mut bound, id, Max::all_ones(*bits));
            }
            Instruction::ConstrainToBoolean { val: Operand::Variable(id) } => {
                note(&mut bound, id, Max::all_ones(1));
            }
            // ir_vm.rs asserts BOTH operands in-circuit:
            // `divisor < 2^(FR_BITS − bits)` and `modulus < 2^bits`
            // (assert_lower_than_fixed, the ReconstituteField arm).
            Instruction::ReconstituteField { divisor, modulus, bits, .. } => {
                if let Operand::Variable(id) = modulus {
                    note(&mut bound, id, Max::all_ones(*bits));
                }
                if let Operand::Variable(id) = divisor {
                    note(&mut bound, id, Max::all_ones(cap.bits() - *bits));
                }
            }
            // ir_vm asserts `low`'s 32nd byte is zero (so low < 2^248) and
            // byte-range-checks `high` (< 256) — the instruction's own doc.
            Instruction::Bytes32FromLowHigh { inputs: (low, high), .. } => {
                if let Operand::Variable(id) = low {
                    note(&mut bound, id, Max::all_ones(8 * LIMB_BYTES as u32));
                }
                if let Operand::Variable(id) = high {
                    note(&mut bound, id, Max::all_ones(8));
                }
            }
            // The Impact/popeq warrant (M23 R3 ruling, dmd 2026-08-28): an
            // UNCONDITIONAL popeq[c] binds each embedded wire to the ledger
            // read it witnesses — see `mark_popeq` for the parse, the guard
            // condition, and the honest scope of the warrant.
            Instruction::Impact { guard, inputs } => {
                if matches!(guard, Operand::Immediate(g) if Max::from_fr(g).bits() != 0) {
                    mark_popeq(inputs, &mut bound);
                }
            }
            _ => {}
        }
    }

    // Pass B — one forward walk: propagate producer bounds (operands always
    // precede their uses in SSA, so forward order reaches the fixpoint given
    // pass A), track which identifiers hold `Bytes32` values (for `Encode`),
    // and audit each hash as it appears. This match is EXHAUSTIVE on purpose,
    // like `operands_mut`: a new upstream instruction must break this build
    // rather than silently escape the audit — the unsound direction is a new
    // byte-absorbing hash falling through a wildcard.
    let mut is_bytes32: BTreeSet<String> = BTreeSet::new();
    let mut findings = Vec::new();
    for (index, ins) in instructions.iter().enumerate() {
        match ins {
            // ---- the two audited hashes ---------------------------------
            Instruction::PersistentHash { alignment, inputs, output } => {
                audit_hash(index, "persistent_hash", alignment, inputs, &bound, &mut findings);
                is_bytes32.insert(output.0.clone());
            }
            Instruction::Keccak256 { alignment, inputs, output } => {
                audit_hash(index, "keccak256", alignment, inputs, &bound, &mut findings);
                is_bytes32.insert(output.0.clone());
            }

            // ---- bounded producers, each with its in-circuit warrant ----
            // Encode of a Bytes32: outputs are (low 31 bytes, high byte),
            // recomposed from the value's already-range-checked assigned
            // bytes (zkir-v3 ir_instructions/encode.rs:93-96). Any other
            // input type: 2 outputs could equally be JubjubPoint coordinates
            // (field-wide), so an unknown type is left unmarked.
            Instruction::Encode { input, outputs } => {
                let input_is_bytes32 =
                    matches!(input, Operand::Variable(id) if is_bytes32.contains(&id.0));
                if input_is_bytes32 && outputs.len() == 2 {
                    note(&mut bound, &outputs[0], Max::all_ones(8 * LIMB_BYTES as u32));
                    note(&mut bound, &outputs[1], Max::all_ones(8));
                }
            }
            // Both outputs recomposed from the CANONICAL full bit
            // decomposition of `val` (assigned_to_le_bits(.., true), the
            // DivModPowerOfTwo arm): mod from bits[..bits] (< 2^bits), div
            // from bits[bits..] — and div = val >> bits, so any bound on
            // `val` shifts down with it (val is canonical, ≤ p−1).
            Instruction::DivModPowerOfTwo { val, bits, outputs } => {
                if outputs.len() == 2 {
                    let val_max = op_max(&bound, val).unwrap_or(cap);
                    note(&mut bound, &outputs[0], val_max.shr(*bits));
                    note(&mut bound, &outputs[1], Max::all_ones(*bits));
                }
            }
            // output = divisor·2^bits + modulus exactly (linear_combination),
            // with both operands asserted in range (pass A above).
            Instruction::ReconstituteField { divisor, modulus, bits, output } => {
                let d = op_max(&bound, divisor)
                    .map(|m| m.min(Max::all_ones(cap.bits() - *bits)))
                    .unwrap_or_else(|| Max::all_ones(cap.bits() - *bits));
                let m = op_max(&bound, modulus)
                    .map(|x| x.min(Max::all_ones(*bits)))
                    .unwrap_or_else(|| Max::all_ones(*bits));
                if let Some(product) = d.checked_mul(Max::pow2(*bits)) {
                    if let Some(sum) = product.checked_add(m) {
                        if sum.le(&cap) {
                            note(&mut bound, output, sum);
                        }
                    }
                }
            }
            // Bytes32 → (low 31 bytes, high byte), recomposed from the
            // value's range-checked assigned bytes; the instruction adds no
            // constraint because none is needed.
            Instruction::Bytes32IntoLowHigh { outputs: (low, high), .. } => {
                note(&mut bound, low, Max::all_ones(8 * LIMB_BYTES as u32));
                note(&mut bound, high, Max::all_ones(8));
            }
            // A rename: the output IS the operand.
            Instruction::Copy { val, output } => {
                if let Some(m) = op_max(&bound, val) {
                    note(&mut bound, output, m);
                }
                if let Operand::Variable(id) = val {
                    if is_bytes32.contains(&id.0) {
                        is_bytes32.insert(output.0.clone());
                    }
                }
            }
            // std.select over a converted AssignedBit (the CondSelect arm),
            // so the output equals one of the two branches.
            Instruction::CondSelect { bit: _, a, b, output } => {
                if let (Some(ma), Some(mb)) = (op_max(&bound, a), op_max(&bound, b)) {
                    note(&mut bound, output, ma.max(mb));
                }
            }
            // Exact interval arithmetic, valid only while the result cannot
            // wrap the field: a ≤ Ma, b ≤ Mb ⇒ a+b ≤ Ma+Mb and a·b ≤ Ma·Mb,
            // over the integers iff Ma+Mb (resp. Ma·Mb) ≤ p−1.
            Instruction::Add { a, b, output } => {
                if let (Some(ma), Some(mb)) = (op_max(&bound, a), op_max(&bound, b)) {
                    if let Some(sum) = ma.checked_add(mb) {
                        if sum.le(&cap) {
                            note(&mut bound, output, sum);
                        }
                    }
                }
            }
            Instruction::Mul { a, b, output } => {
                if let (Some(ma), Some(mb)) = (op_max(&bound, a), op_max(&bound, b)) {
                    if let Some(product) = ma.checked_mul(mb) {
                        if product.le(&cap) {
                            note(&mut bound, output, product);
                        }
                    }
                }
            }
            // Boolean outputs: each is std.convert of an AssignedBit.
            Instruction::TestEq { output, .. }
            | Instruction::Not { output, .. }
            | Instruction::LessThan { output, .. } => {
                note(&mut bound, output, Max::all_ones(1));
            }

            // ---- Bytes32-typed producers (for Encode above) -------------
            Instruction::IntoBytes32 { output, .. }
            | Instruction::ReverseBytes { output, .. }
            | Instruction::Bytes32FromLowHigh { output, .. } => {
                is_bytes32.insert(output.0.clone());
            }
            Instruction::PublicInput { val_t, output, .. }
            | Instruction::PrivateInput { val_t, output, .. } => {
                // The witnessed VALUE is free; only its shape is `val_t`
                // (the instruction's own doc), so nothing is bounded HERE.
                // A `PublicInput` embedded in an UNCONDITIONAL popeq is
                // bounded by pass A's Impact arm (`mark_popeq`) — via the
                // ledger's external warrant, per the M23 R3 ruling — and a
                // guarded one stays free, deliberately.
                if *val_t == IrType::Bytes32 {
                    is_bytes32.insert(output.0.clone());
                }
            }

            // ---- everything else neither bounds nor absorbs bytes -------
            // Field-absorbing hashes (no byte atoms — out of scope by the
            // R3 spec), curve/field ops whose outputs are field- or
            // point-wide, and the no-output instructions.
            Instruction::TransientHash { .. }
            | Instruction::HashToCurve { .. }
            | Instruction::Assert { .. }
            | Instruction::ConstrainBits { .. }
            | Instruction::ConstrainEq { .. }
            | Instruction::ConstrainToBoolean { .. }
            | Instruction::Impact { .. }
            | Instruction::EcMul { .. }
            | Instruction::EcMulGenerator { .. }
            | Instruction::IntoCoordinates { .. }
            | Instruction::FromCoordinates { .. }
            | Instruction::FromBytes32 { .. }
            | Instruction::Neg { .. }
            | Instruction::Inv { .. }
            | Instruction::JubjubScalarFromNative { .. }
            | Instruction::Output { .. } => {}
        }
    }
    findings
}

/// Map one hash's operands onto its alignment's atoms and check each
/// byte-limb, following the in-circuit decoder's own consumption rule
/// (`fab_decode_to_bytes_atom`, zkir-v3 ir_vm.rs:125-175): a `field` atom
/// consumes one operand unchecked (field-wide, nothing narrower to enforce);
/// a `bytes n` atom consumes its leftover (most significant, `n mod 31`
/// bytes) limb FIRST when `n` is not a multiple of 31, then `n / 31` full
/// 31-byte limbs. NB `bytes 0` consumes NOTHING here — unlike the Impact
/// FAB rule (`minocrab_ledger::atom_limbs`, which floors at one limb), the
/// hash decoder's `chunks + (stray != 0)` is zero for `n = 0`.
fn audit_hash(
    index: usize,
    hash: &'static str,
    alignment: &Alignment,
    inputs: &[Operand],
    bound: &BTreeMap<String, Max>,
    findings: &mut Vec<Finding>,
) {
    let mut ops = inputs.iter();
    let mut consumed = 0usize;
    for (ai, segment) in alignment.0.iter().enumerate() {
        let atom = match segment {
            AlignmentSegment::Atom(atom) => atom,
            // The in-circuit decoder REJECTS option segments ("not yet
            // implemented") — a circuit carrying one cannot synthesize, so
            // this fires only on a malformed stream, and the mapping past
            // it is undefined.
            AlignmentSegment::Option(_) => {
                findings.push(Finding {
                    index,
                    hash,
                    detail: format!(
                        "alignment segment {ai} is an option, which the \
                         in-circuit decoder rejects; cannot map operands to atoms"
                    ),
                });
                return;
            }
        };
        match atom {
            AlignmentAtom::Field => match ops.next() {
                Some(_) => consumed += 1,
                None => {
                    findings.push(too_few(index, hash, ai, consumed));
                    return;
                }
            },
            // Same rejection as Option: compress atoms cannot be decoded
            // in-circuit at all.
            AlignmentAtom::Compress => {
                findings.push(Finding {
                    index,
                    hash,
                    detail: format!(
                        "alignment segment {ai} is a compress atom, which the \
                         in-circuit decoder rejects; cannot map operands to atoms"
                    ),
                });
                return;
            }
            AlignmentAtom::Bytes { length } => {
                let stray = *length as usize % LIMB_BYTES;
                let chunks = *length as usize / LIMB_BYTES;
                let widths = (stray > 0)
                    .then_some(stray)
                    .into_iter()
                    .chain(std::iter::repeat(LIMB_BYTES).take(chunks));
                for (li, width) in widths.enumerate() {
                    let Some(op) = ops.next() else {
                        findings.push(too_few(index, hash, ai, consumed));
                        return;
                    };
                    consumed += 1;
                    check_limb(index, hash, op, ai, li, *length, width, bound, findings);
                }
            }
        }
    }
    let leftover = ops.count();
    if leftover > 0 {
        findings.push(Finding {
            index,
            hash,
            detail: format!(
                "{leftover} operand(s) beyond what the alignment consumes \
                 ({consumed}); cannot map operands to atoms"
            ),
        });
    }
}

fn too_few(index: usize, hash: &'static str, ai: usize, consumed: usize) -> Finding {
    Finding {
        index,
        hash,
        detail: format!(
            "operands exhausted at alignment segment {ai} (consumed {consumed}); \
             cannot map operands to atoms"
        ),
    }
}

/// The per-limb verdict: constant, or provably within the limb's byte width.
#[allow(clippy::too_many_arguments)]
fn check_limb(
    index: usize,
    hash: &'static str,
    op: &Operand,
    ai: usize,
    li: usize,
    atom_len: u32,
    width_bytes: usize,
    bound: &BTreeMap<String, Max>,
    findings: &mut Vec<Finding>,
) {
    let required = 8 * width_bytes as u32;
    let place =
        format!("bytes<{atom_len}> (segment {ai}) limb {li} ({width_bytes} byte(s))");
    match op {
        // A constant the prover cannot vary is no soundness hole; one that
        // exceeds its atom's width still makes the circuit unsatisfiable at
        // the decoder, so it is flagged as the bug it is.
        Operand::Immediate(v) => {
            if Max::from_fr(v).bits() > required {
                findings.push(Finding {
                    index,
                    hash,
                    detail: format!(
                        "immediate of {} bits exceeds {place} — the decoder \
                         makes this unsatisfiable",
                        Max::from_fr(v).bits()
                    ),
                });
            }
        }
        Operand::Variable(id) => match bound.get(&id.0) {
            Some(m) if m.bits() <= required => {}
            proven => findings.push(Finding {
                index,
                hash,
                detail: format!(
                    "wire {id:?} feeds {place} but is {} — required ≤ {required} bits; \
                     the packing is only injective for in-range values \
                     (api-safety-survey §B3)",
                    match proven {
                        Some(m) => format!("only proven ≤ {} bits", m.bits()),
                        None => "not provably bounded".to_string(),
                    }
                ),
            }),
        },
    }
}

/// The Impact/popeq warrant (M23 R3 ruling, dmd 2026-08-28): if `inputs`
/// parses EXACTLY as `popeq`/`popeqc` — `[0x0c|0x0d, atom count, one
/// alignment element per atom, then the limbs]` (`Op::field_repr`,
/// ops.rs:477-480; header encoding fab.rs:596-608: `bytes<n>` → n,
/// `compress` → p−1, `field` → p−2) — bound each `bytes` limb WIRE to its
/// limb's byte width.
///
/// THE WARRANT, and why it is EXTERNAL: the caller has checked the Impact's
/// guard is an immediate non-zero, so the instruction unconditionally pushes
/// these very elements into the public-input stream, where the verifier
/// checks them against the transaction's declared transcript op — and the
/// ledger accepts that transaction only if the transcript's expected value
/// equals the value actually read from state (`process_read`), whose
/// `ValueAtom`s are normalized in-range for their atoms. So the wire equals
/// a stored, normalized limb: ≤ its byte width. Nothing IN THE CIRCUIT
/// enforces this — the chain runs through the ledger's own invariant, which
/// is why guarded reads are NOT marked here (a false guard pushes
/// `select(guard, x, 0) = 0`, the comparison passes on zero, and the wire is
/// genuinely free). A VARIABLE guard that happens to always be 1 is also not
/// marked — conservatively, since the lint cannot prove it.
///
/// The FAB limbing (`AlignedValue::field_repr`, fab.rs:486-511): `bytes<n>`
/// is stray-FIRST — the leftover `n mod 31` most-significant bytes, then
/// `n / 31` full 31-byte limbs — and `bytes<0>` is ONE zero limb (the
/// `atom_limbs` floor; its stored value normalizes to zero, so the bound is
/// exactly 0). `field` and `compress` atoms occupy one field-wide limb each
/// and bound nothing. Anything that does not parse cleanly — wrong opcode,
/// non-immediate header, limb count mismatch, leftover elements — marks
/// NOTHING: under-marking is the safe direction.
fn mark_popeq(inputs: &[Operand], bound: &mut BTreeMap<String, Max>) {
    let small = |op: &Operand| -> Option<u64> {
        match op {
            Operand::Immediate(v) => {
                let m = Max::from_fr(v);
                (m.bits() <= 32).then(|| m.low_u64())
            }
            Operand::Variable(_) => None,
        }
    };
    if inputs.len() < 2 || small(&inputs[0]).is_none_or(|op| op != 0x0c && op != 0x0d) {
        return;
    }
    let Some(atom_count) = small(&inputs[1]).map(|n| n as usize) else {
        return;
    };
    if inputs.len() < 2 + atom_count {
        return;
    }
    let compress_elem = field_max(); // p − 1 (fab.rs: `compress` → −1)
    let field_elem = Max::from_fr(&(Fr::from(0u64) - Fr::from(2u64))); // p − 2
    // Per limb: Some(width bytes) for a bytes limb, None for field/compress.
    let mut widths: Vec<Option<usize>> = Vec::new();
    for header in &inputs[2..2 + atom_count] {
        let Operand::Immediate(v) = header else {
            return;
        };
        let m = Max::from_fr(v);
        if m == compress_elem || m == field_elem {
            widths.push(None);
        } else if m.bits() <= 32 {
            let n = m.low_u64() as usize;
            if n == 0 {
                widths.push(Some(0));
            } else {
                if n % LIMB_BYTES != 0 {
                    widths.push(Some(n % LIMB_BYTES));
                }
                widths.extend(std::iter::repeat_n(Some(LIMB_BYTES), n / LIMB_BYTES));
            }
        } else {
            return;
        }
    }
    let limbs = &inputs[2 + atom_count..];
    if limbs.len() != widths.len() {
        return;
    }
    for (op, width) in limbs.iter().zip(widths) {
        if let (Operand::Variable(id), Some(width)) = (op, width) {
            note(bound, id, Max::all_ones(8 * width as u32));
        }
    }
}

/// Merge a newly proven maximum for `id`, keeping the tightest.
fn note(bound: &mut BTreeMap<String, Max>, id: &Identifier, m: Max) {
    bound
        .entry(id.0.clone())
        .and_modify(|old| *old = (*old).min(m))
        .or_insert(m);
}

/// The proven maximum of an operand: an immediate's exact value, or the
/// wire's tightest noted bound.
fn op_max(bound: &BTreeMap<String, Max>, op: &Operand) -> Option<Max> {
    match op {
        Operand::Immediate(v) => Some(Max::from_fr(v)),
        Operand::Variable(id) => bound.get(&id.0).copied(),
    }
}

/// `p − 1`: the largest value a wire can hold, and the cap past which
/// interval arithmetic could wrap and is abandoned.
fn field_max() -> Max {
    Max::from_fr(&(Fr::from(0u64) - Fr::from(1u64)))
}

// ---- exact 256-bit interval maxima ------------------------------------------
//
// Bit-count bounds ("a < 2^n") are too coarse for the one pattern that
// matters: a packed limb `a + b·2^64` with `a ≤ 2^64−1, b ≤ 2^64−1` is
// EXACTLY ≤ 2^128−1, but any rule of the form `max(n,m)+1` reports 129 bits
// and falsely fires on a full-width atom. Tracking exact maxima keeps the
// arithmetic honest in both directions: no false fire on a tight packing,
// and no false pass from rounding a bound down.

/// An exact upper bound on a wire's value, as a 256-bit little-endian
/// integer. Every tracked maximum is ≤ p − 1 (the caller drops anything
/// larger), so 4 limbs never truncate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Max([u64; 4]);

impl Max {
    /// `2^bits − 1` (`bits ≤ 256`).
    fn all_ones(bits: u32) -> Max {
        let bits = bits.min(256) as usize;
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let lo = i * 64;
            *limb = if bits >= lo + 64 {
                u64::MAX
            } else if bits > lo {
                (1u64 << (bits - lo)) - 1
            } else {
                0
            };
        }
        Max(limbs)
    }

    /// `2^bits` (`bits < 256`).
    fn pow2(bits: u32) -> Max {
        let mut limbs = [0u64; 4];
        limbs[(bits / 64) as usize] = 1u64 << (bits % 64);
        Max(limbs)
    }

    /// From a field element's canonical little-endian bytes.
    fn from_fr(v: &Fr) -> Max {
        let bytes = v.as_le_bytes();
        debug_assert!(bytes.len() <= 32, "a canonical Fr fits 32 bytes");
        let mut limbs = [0u64; 4];
        for (i, byte) in bytes.iter().enumerate().take(32) {
            limbs[i / 8] |= (*byte as u64) << (8 * (i % 8));
        }
        Max(limbs)
    }

    /// Position of the highest set bit (0 for zero): `self ≤ 2^bits() − 1`.
    fn bits(&self) -> u32 {
        for i in (0..4).rev() {
            if self.0[i] != 0 {
                return 64 * i as u32 + (64 - self.0[i].leading_zeros());
            }
        }
        0
    }

    /// `None` on 256-bit overflow.
    fn checked_add(self, other: Max) -> Option<Max> {
        let mut limbs = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let (a, c1) = self.0[i].overflowing_add(other.0[i]);
            let (b, c2) = a.overflowing_add(carry);
            limbs[i] = b;
            carry = (c1 as u64) + (c2 as u64);
        }
        (carry == 0).then_some(Max(limbs))
    }

    /// `None` on 256-bit overflow.
    fn checked_mul(self, other: Max) -> Option<Max> {
        let mut wide = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let t = wide[i + j] as u128 + self.0[i] as u128 * other.0[j] as u128 + carry;
                wide[i + j] = t as u64;
                carry = t >> 64;
            }
            wide[i + 4] = carry as u64;
        }
        wide[4..].iter().all(|&l| l == 0).then(|| {
            Max([wide[0], wide[1], wide[2], wide[3]])
        })
    }

    /// Logical shift right.
    fn shr(self, bits: u32) -> Max {
        if bits >= 256 {
            return Max([0; 4]);
        }
        let (limb, rem) = ((bits / 64) as usize, bits % 64);
        let mut limbs = [0u64; 4];
        for i in 0..4 - limb {
            let mut v = self.0[i + limb] >> rem;
            if rem > 0 && i + limb + 1 < 4 {
                v |= self.0[i + limb + 1] << (64 - rem);
            }
            limbs[i] = v;
        }
        Max(limbs)
    }

    /// The low limb — the whole value when `bits() ≤ 64`, which is the only
    /// way it is used (small-integer recognition in the popeq parse).
    fn low_u64(&self) -> u64 {
        self.0[0]
    }

    fn le(&self, other: &Max) -> bool {
        for i in (0..4).rev() {
            if self.0[i] != other.0[i] {
                return self.0[i] < other.0[i];
            }
        }
        true
    }

    fn min(self, other: Max) -> Max {
        if self.le(&other) { self } else { other }
    }

    fn max(self, other: Max) -> Max {
        if self.le(&other) { other } else { self }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(name: &str) -> Identifier {
        Identifier(name.to_string())
    }

    fn var(name: &str) -> Operand {
        Operand::Variable(id(name))
    }

    fn imm(v: u64) -> Operand {
        Operand::Immediate(Fr::from(v))
    }

    fn bytes_atom(length: u32) -> AlignmentSegment {
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length })
    }

    fn keccak(alignment: Vec<AlignmentSegment>, inputs: Vec<Operand>) -> Instruction {
        Instruction::Keccak256 {
            alignment: Alignment(alignment),
            inputs,
            output: id("digest"),
        }
    }

    #[test]
    fn max_arithmetic_is_exact() {
        // The packing identity that motivates exact maxima: (2^64−1) +
        // (2^64−1)·2^64 = 2^128−1, exactly a 16-byte atom.
        let seg = Max::all_ones(64);
        let shifted = seg.checked_mul(Max::pow2(64)).unwrap();
        let limb = seg.checked_add(shifted).unwrap();
        assert_eq!(limb, Max::all_ones(128));
        assert_eq!(limb.bits(), 128);
        // A one-bit overlap is one bit too many.
        let overlap = seg.checked_add(seg.checked_mul(Max::pow2(63)).unwrap()).unwrap();
        assert!(overlap.bits() > 127);
        // Shift inverts the packing.
        assert_eq!(limb.shr(64), Max::all_ones(64));
        // Field cap: 255 bits for the BLS12-381 scalar field.
        assert_eq!(field_max().bits(), 255);
    }

    #[test]
    fn unconstrained_limb_fires_and_constrained_passes() {
        let hash = keccak(vec![bytes_atom(20)], vec![var("w")]);
        let unconstrained = vec![
            Instruction::PrivateInput {
                guard: None,
                val_t: IrType::Native,
                output: id("w"),
            },
            hash.clone(),
        ];
        let findings = audit(&unconstrained);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].detail.contains("not provably bounded"), "{}", findings[0]);

        // The constraint may come AFTER the hash — SSA makes it global.
        let constrained = vec![
            Instruction::PrivateInput {
                guard: None,
                val_t: IrType::Native,
                output: id("w"),
            },
            hash,
            Instruction::ConstrainBits { val: var("w"), bits: 160 },
        ];
        assert_eq!(audit(&constrained), vec![]);
    }

    #[test]
    fn packed_limb_needs_every_segment_bounded() {
        // limb = a + b·2^64 into a bytes<16> atom — the §B3 shape.
        let pack = |extra: Vec<Instruction>| {
            let mut stream = vec![
                Instruction::PrivateInput {
                    guard: None,
                    val_t: IrType::Native,
                    output: id("a"),
                },
                Instruction::PrivateInput {
                    guard: None,
                    val_t: IrType::Native,
                    output: id("b"),
                },
                Instruction::Mul {
                    a: var("b"),
                    b: Operand::Immediate(
                        Fr::from_le_bytes(&[0, 0, 0, 0, 0, 0, 0, 0, 1]).expect("2^64 fits"),
                    ),
                    output: id("shifted"),
                },
                Instruction::Add {
                    a: var("a"),
                    b: var("shifted"),
                    output: id("limb"),
                },
                keccak(vec![bytes_atom(16)], vec![var("limb")]),
            ];
            stream.extend(extra);
            stream
        };
        // Both segments constrained: the packed limb is exactly ≤ 2^128−1.
        let both = pack(vec![
            Instruction::ConstrainBits { val: var("a"), bits: 64 },
            Instruction::ConstrainBits { val: var("b"), bits: 64 },
        ]);
        assert_eq!(audit(&both), vec![]);
        // One segment unconstrained: the limb has no derivable bound.
        let one = pack(vec![Instruction::ConstrainBits { val: var("a"), bits: 64 }]);
        let findings = audit(&one);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].detail.contains("limb"), "{}", findings[0]);
    }

    #[test]
    fn intrinsically_bounded_sources_pass() {
        // div_mod's outputs, an immediate, and a field atom need no
        // constraint instructions at all.
        let stream = vec![
            Instruction::PrivateInput {
                guard: None,
                val_t: IrType::Native,
                output: id("w"),
            },
            Instruction::DivModPowerOfTwo {
                val: var("w"),
                bits: 8,
                outputs: vec![id("div"), id("mod")],
            },
            keccak(
                vec![
                    bytes_atom(1),
                    bytes_atom(2),
                    AlignmentSegment::Atom(AlignmentAtom::Field),
                ],
                vec![var("mod"), imm(0x1234), var("w")],
            ),
        ];
        assert_eq!(audit(&stream), vec![]);
        // But div of an UNBOUNDED value is only ≤ (p−1) >> 8 — 247 bits —
        // and must not pass a narrower atom than that.
        let wide = vec![
            Instruction::PrivateInput {
                guard: None,
                val_t: IrType::Native,
                output: id("w"),
            },
            Instruction::DivModPowerOfTwo {
                val: var("w"),
                bits: 8,
                outputs: vec![id("div"), id("mod")],
            },
            keccak(vec![bytes_atom(16)], vec![var("div")]),
        ];
        assert_eq!(audit(&wide).len(), 1);
    }

    #[test]
    fn multi_limb_atom_maps_stray_first() {
        // bytes<32> = 1-byte stray (most significant) + one 31-byte limb,
        // in that order — the decoder's consumption order. A wire bounded
        // to 8 bits passes slot 0 but could not pass slot 1's 248-bit...
        // rather: a 248-bit-bounded wire in slot 0 must FIRE (slot 0 is
        // the 1-byte limb).
        let stream = vec![
            Instruction::PrivateInput {
                guard: None,
                val_t: IrType::Native,
                output: id("hi"),
            },
            Instruction::PrivateInput {
                guard: None,
                val_t: IrType::Native,
                output: id("lo"),
            },
            Instruction::ConstrainBits { val: var("hi"), bits: 248 },
            Instruction::ConstrainBits { val: var("lo"), bits: 248 },
            keccak(vec![bytes_atom(32)], vec![var("hi"), var("lo")]),
        ];
        let findings = audit(&stream);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].detail.contains("limb 0 (1 byte"), "{}", findings[0]);
    }

    #[test]
    fn transient_hash_is_out_of_scope() {
        let stream = vec![
            Instruction::PrivateInput {
                guard: None,
                val_t: IrType::Native,
                output: id("w"),
            },
            Instruction::TransientHash { inputs: vec![var("w")], output: id("h") },
        ];
        assert_eq!(audit(&stream), vec![]);
    }

    #[test]
    fn arity_mismatch_is_reported() {
        let short = vec![keccak(vec![bytes_atom(32)], vec![imm(1)])];
        assert_eq!(audit(&short).len(), 1);
        let long = vec![keccak(vec![bytes_atom(1)], vec![imm(1), imm(2)])];
        assert_eq!(audit(&long).len(), 1);
    }

    // ---- the Impact/popeq warrant (M23 R3 ruling) ---------------------------

    /// A `public_input` gate for `name`, unguarded.
    fn pi(name: &str) -> Instruction {
        Instruction::PublicInput {
            guard: None,
            val_t: IrType::Native,
            output: id(name),
        }
    }

    /// `popeq` (0x0c) expecting one `bytes<8>` limb wire — the u64 cell
    /// read shape — under the given guard.
    fn popeq_u64(guard: Operand, wire: &str) -> Instruction {
        Instruction::Impact {
            guard,
            // [opcode, atom count, bytes<8> header, the limb]
            inputs: vec![imm(0x0c), imm(1), imm(8), var(wire)],
        }
    }

    #[test]
    fn unconditional_popeq_bounds_the_read() {
        // The class-1 shape: a ledger read's %pi wire straight into a hash.
        let stream = vec![
            pi("pi"),
            popeq_u64(imm(1), "pi"),
            keccak(vec![bytes_atom(8)], vec![var("pi")]),
        ];
        assert_eq!(audit(&stream), vec![]);
        // popeqc (0x0d) carries the same warrant.
        let cached = vec![
            pi("pi"),
            Instruction::Impact {
                guard: imm(1),
                inputs: vec![imm(0x0d), imm(1), imm(8), var("pi")],
            },
            keccak(vec![bytes_atom(8)], vec![var("pi")]),
        ];
        assert_eq!(audit(&cached), vec![]);
        // And the bound is the LIMB's, not "anything": the same read feeding
        // a narrower atom still fires.
        let narrower = vec![
            pi("pi"),
            popeq_u64(imm(1), "pi"),
            keccak(vec![bytes_atom(4)], vec![var("pi")]),
        ];
        assert_eq!(audit(&narrower).len(), 1);
    }

    #[test]
    fn guarded_popeq_stays_free() {
        // A variable guard — even one that is in fact always 1 — marks
        // nothing: when the guard is false the Impact pushes zeros and the
        // wire is genuinely free. This is the ruling's `guarded reads keep
        // firing` half.
        let variable = vec![
            pi("pi"),
            popeq_u64(var("g"), "pi"),
            keccak(vec![bytes_atom(8)], vec![var("pi")]),
        ];
        assert_eq!(audit(&variable).len(), 1);
        // An immediate-ZERO guard is a dead op, not a warrant.
        let dead = vec![
            pi("pi"),
            popeq_u64(imm(0), "pi"),
            keccak(vec![bytes_atom(8)], vec![var("pi")]),
        ];
        assert_eq!(audit(&dead).len(), 1);
    }

    #[test]
    fn popeq_limbs_follow_the_fab_rule() {
        // bytes<32> = stray byte FIRST (8 bits), then the 31-byte limb
        // (248 bits) — and a multi-atom popeq maps positions exactly.
        // Alignment: [bytes<32>, field, bytes<8>] → limbs
        // [hi (1B), lo (31B), f (field-wide), n (8B)].
        let stream = vec![
            pi("hi"),
            pi("lo"),
            pi("f"),
            pi("n"),
            Instruction::Impact {
                guard: imm(1),
                inputs: vec![
                    imm(0x0c),
                    imm(3),
                    imm(32),
                    Operand::Immediate(Fr::from(0u64) - Fr::from(2u64)), // field
                    imm(8),
                    var("hi"),
                    var("lo"),
                    var("f"),
                    var("n"),
                ],
            },
            keccak(
                vec![bytes_atom(32), bytes_atom(8)],
                vec![var("hi"), var("lo"), var("n")],
            ),
            // The field-wide limb got NO bound: absorbing it in a byte atom
            // fires.
            keccak(vec![bytes_atom(8)], vec![var("f")]),
        ];
        assert_eq!(audit(&stream).len(), 1);
    }

    #[test]
    fn malformed_popeq_marks_nothing() {
        let hash = keccak(vec![bytes_atom(8)], vec![var("pi")]);
        // Limb count disagrees with the header: one bytes<8> atom is one
        // limb, two supplied.
        let extra = vec![
            pi("pi"),
            Instruction::Impact {
                guard: imm(1),
                inputs: vec![imm(0x0c), imm(1), imm(8), var("pi"), imm(0)],
            },
            hash.clone(),
        ];
        assert_eq!(audit(&extra).len(), 1);
        // A non-popeq opcode (push, 0x10) embedding the wire is not a read
        // and carries no normalization warrant.
        let push = vec![
            pi("pi"),
            Instruction::Impact {
                guard: imm(1),
                inputs: vec![imm(0x10), imm(1), imm(8), var("pi")],
            },
            hash.clone(),
        ];
        assert_eq!(audit(&push).len(), 1);
        // A wire in the HEADER position is malformed, not a warrant.
        let header_wire = vec![
            pi("pi"),
            Instruction::Impact {
                guard: imm(1),
                inputs: vec![imm(0x0c), imm(1), var("pi"), var("pi")],
            },
            hash,
        ];
        assert_eq!(audit(&header_wire).len(), 1);
    }
}

// ============================================================================
// Kani harnesses (M23 R4) — compiled ONLY under `cargo kani -p minocrab-ir`
// ============================================================================
//
// The lint's soundness rests on the exact interval arithmetic: a Max that
// under-reports a maximum would prove a bound that does not hold — the false
// negative the whole instrument exists to prevent. These proofs pin the
// arithmetic against independent oracles (`u128`, bit arithmetic) at stated
// widths, and the order relation at full width. Bounds per proof; runtimes
// in notes/formal-verification-options.org §"As built — M23 R4".

#[cfg(kani)]
mod kani_proofs {
    use super::Max;

    fn from_u128(v: u128) -> Max {
        Max([v as u64, (v >> 64) as u64, 0, 0])
    }

    fn to_u128(m: &Max) -> Option<u128> {
        (m.0[2] == 0 && m.0[3] == 0).then(|| m.0[0] as u128 | (m.0[1] as u128) << 64)
    }

    /// `checked_add` agrees with `u128` addition wherever both are defined.
    /// BOUND: both operands ≤ 2^127 − 1, so the oracle cannot itself
    /// overflow; the 256-bit path has no carry at this width, which is the
    /// carry-chain's base case — `add_carries_across_limbs` covers the rest.
    #[kani::proof]
    fn add_matches_u128() {
        let a: u128 = kani::any();
        let b: u128 = kani::any();
        kani::assume(a < 1 << 127 && b < 1 << 127);
        let sum = from_u128(a).checked_add(from_u128(b)).expect("cannot overflow 256 bits");
        assert_eq!(to_u128(&sum), Some(a + b));
    }

    /// The carry propagates across every limb boundary: adding 1 to
    /// `2^n − 1` gives `2^n`, for every n < 256.
    #[kani::proof]
    fn add_carries_across_limbs() {
        let n: u32 = kani::any();
        kani::assume(n < 256);
        let sum = Max::all_ones(n).checked_add(Max::all_ones(1).min(Max::pow2(0)))
            // all_ones(1) is 1 and pow2(0) is 1; min keeps the proof honest
            // about both constructors agreeing on the value 1.
            .expect("2^n fits for n < 256");
        assert_eq!(sum, Max::pow2(n), "all_ones({n}) + 1 != pow2({n})");
    }

    /// 256-bit overflow is reported, never wrapped.
    #[kani::proof]
    fn add_overflow_is_none() {
        let a: u64 = kani::any();
        kani::assume(a > 0);
        assert!(Max::all_ones(256).checked_add(Max([a, 0, 0, 0])).is_none());
    }

    /// `checked_mul` agrees with `u128` multiplication. BOUND: 16-bit
    /// operands. Neither 64x64 nor 32x32 closed in 900s — the 4x4 limb
    /// loop embeds sixteen 64-bit partial-product multipliers in the SAT
    /// formula regardless of assumed operand width, and wide
    /// multiplication is the canonical SAT-hard circuit. 16-bit operands
    /// still drive the identical limb/carry code path against an exact
    /// oracle; the cross-limb carry at full width is
    /// `mul_carries_across_limbs`.
    #[kani::proof]
    fn mul_matches_u128() {
        let a: u64 = kani::any();
        let b: u64 = kani::any();
        kani::assume(a < 1 << 16 && b < 1 << 16);
        let product = Max([a, 0, 0, 0]).checked_mul(Max([b, 0, 0, 0])).expect("fits");
        assert_eq!(to_u128(&product), Some(a as u128 * b as u128));
    }

    /// The multiplier's cross-limb carry, at the boundary a 32-bit oracle
    /// cannot see: (2^64 - 1)^2 spans all four limbs and has an exact
    /// closed form.
    #[kani::proof]
    fn mul_carries_across_limbs() {
        let ones = Max([u64::MAX, 0, 0, 0]);
        let square = ones.checked_mul(ones).expect("fits 128 bits");
        // (2^64 - 1)^2 = 2^128 - 2^65 + 1
        assert_eq!(to_u128(&square), Some(u128::MAX - (1 << 65) + 2));
    }

    /// `shr` agrees with `u128` shifting for a SYMBOLIC 64-bit value at
    /// EVERY concrete shift 0..=64. A fully symbolic shift amount did not
    /// close in 900s at either 64- or 128-bit width (a symbolic barrel
    /// shifter across four limbs); sweeping the shift concretely keeps the
    /// value symbolic where the lint's soundness lives — `div = val >> bits`
    /// with `bits` a CONCRETE instruction field, so a concrete-shift sweep
    /// is in fact the exact shape the lint evaluates. Limb-boundary
    /// crossings of wider values: `shr_limb_boundaries` below.
    #[kani::proof]
    #[kani::unwind(70)] // 65 sweep steps; memcmp inside assert_eq is 32
    fn shr_matches_u128() {
        let v: u64 = kani::any();
        let mut s = 0u32;
        while s <= 64 {
            let shifted = Max([v, 0, 0, 0]).shr(s);
            let expect = if s >= 64 { 0 } else { (v >> s) as u128 };
            assert_eq!(to_u128(&shifted), Some(expect));
            s += 1;
        }
    }

    /// Every limb boundary of a full-width value, at concrete shifts: the
    /// all-ones 256-bit value shifted by each multiple of 32 has the
    /// closed form all_ones(256 - s).
    #[kani::proof]
    #[kani::unwind(40)] // the 8-step ladder, plus memcmp's per-byte loop
                        // inside assert_eq! over the 32-byte limb array
    fn shr_limb_boundaries() {
        let mut s = 0u32;
        while s < 256 {
            assert_eq!(Max::all_ones(256).shr(s), Max::all_ones(256 - s));
            s += 32;
        }
    }

    /// `bits()` is exactly the position of the highest set bit — the fact
    /// `m.bits() <= 8*w` relies on to mean `m ≤ 2^8w − 1`. BOUND: 128-bit
    /// values (limb-symmetric; the upper limbs run the same code path).
    #[kani::proof]
    fn bits_matches_leading_zeros() {
        let v: u128 = kani::any();
        assert_eq!(from_u128(v).bits(), 128 - v.leading_zeros());
    }

    /// `bits(all_ones(n)) == n` for every n ≤ 256 — the two sides of the
    /// verdict `m.bits() <= required` use the same ruler.
    #[kani::proof]
    fn all_ones_bits_roundtrip() {
        let n: u32 = kani::any();
        kani::assume(n <= 256);
        assert_eq!(Max::all_ones(n).bits(), n);
    }

    /// `le` is a total order and `min`/`max` select within it — at FULL
    /// 256-bit width (comparisons are cheap for the solver).
    #[kani::proof]
    fn le_total_order_and_min_max() {
        let a = Max([kani::any(), kani::any(), kani::any(), kani::any()]);
        let b = Max([kani::any(), kani::any(), kani::any(), kani::any()]);
        assert!(a.le(&a));
        assert!(a.le(&b) || b.le(&a));
        if a.le(&b) && b.le(&a) {
            assert_eq!(a, b);
        }
        let lo = a.min(b);
        assert!(lo.le(&a) && lo.le(&b) && (lo == a || lo == b));
        let hi = a.max(b);
        assert!(a.le(&hi) && b.le(&hi) && (hi == a || hi == b));
    }
}
