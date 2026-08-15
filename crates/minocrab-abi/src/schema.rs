//! THE PUBLISHED ABI, as text.
//!
//! An interface crate freezes this rendering of its own declarations in a
//! snapshot file. It is derived entirely from the TYPES — no artifact is
//! consulted — so what it captures is what the crate promises its
//! dependants:
//!
//! - the entry-point NAME and its 32-byte hash (the key the ledger matches
//!   a `claimContractCall` against);
//! - every argument slot's flattened primitive type and the constraint it
//!   carries, in wire order;
//! - the argument list's FAB alignment, which is the order the
//!   communications commitment hashes;
//! - the same for the result.
//!
//! ITS DIFF IS THE SEMVER DECISION. Reordering or retyping an argument
//! changes the commitment layout, so the ledger stops matching and every
//! deployed caller breaks: a changed snapshot is a MAJOR version, by
//! construction rather than by judgement. See
//! notes/interface-crates.org §"Versioning and publishing".

use minocrab::v3::{CallArgs, CallResult, LimbConstraint, Prim};

use minocrab_ledger::EntryPoint;

use crate::check::{atom_name, prim_name};

/// One circuit's block of the snapshot.
pub fn circuit_schema<A: CallArgs, R: CallResult>(entry_point: EntryPoint) -> String {
    let mut arg_prims = Vec::with_capacity(A::SLOTS);
    A::push_prims(&mut arg_prims);
    let mut out = String::new();
    out.push_str(&format!("circuit {}\n", entry_point.name()));
    out.push_str(&format!("  entry-point {}\n", hex(&entry_point.hash())));
    out.push_str(&section("arguments", &arg_prims, &A::atoms()));
    out.push_str(&section("result", &R::prims(), &R::atoms()));
    out
}

fn section(what: &str, prims: &[Prim], atoms: &[minocrab::AlignmentAtom]) -> String {
    let mut out = format!(
        "  {what} {} slot{}, alignment [{}]\n",
        prims.len(),
        if prims.len() == 1 { "" } else { "s" },
        atoms.iter().map(atom_name).collect::<Vec<_>>().join(", ")
    );
    for (slot, prim) in prims.iter().enumerate() {
        out.push_str(&format!(
            "    {slot:>3}  {:<12} {}\n",
            prim_name(*prim),
            constraint_name(prim.constraint())
        ));
    }
    out
}

/// A constraint spelled as compactc emits it.
fn constraint_name(constraint: LimbConstraint) -> String {
    match constraint {
        LimbConstraint::None => "-".to_string(),
        LimbConstraint::Zero => "constrain_eq 0".to_string(),
        LimbConstraint::Boolean => "constrain_to_boolean".to_string(),
        LimbConstraint::Bits(bits) => format!("constrain_bits {bits}"),
        LimbConstraint::Bounded { bound, bits } => {
            format!("less_than {bound} ({bits} bits) + assert")
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
