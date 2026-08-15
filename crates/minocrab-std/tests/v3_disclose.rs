//! Typed disclosure declarations, gated the way every M9 phase is gated:
//! the same circuit written with and without a declaration must lower to
//! BYTE-IDENTICAL ZKIR. A `Discloses<..>` return type is type-level only —
//! it may not add an output, move a slot or emit an instruction — which is
//! the zero-movement rule applied to phase 6.
//!
//! The generated set-equality tests are also here, implicitly: an
//! integration test crate is compiled with `cfg(test)`, so every `#[circuit]`
//! below that declares a `Discloses<..>` contributes its own generated
//! `#[test]` to this file's harness (`__declaring_discloses`, …). They pass
//! by running; that they FAIL when they should is
//! `assert_declared_disclosures`'s own unit test in the crate.

use minocrab::v3::{Circuit3, Compiled3};
use minocrab::{Private, Public};
use minocrab_std::v3::{
    circuit, entry, entry_out, label, CircuitArg, Disclose, Discloses, Uint, B32,
};
use minocrab_zkir::v3::to_zkir_string;

fn zkir(compiled: &Compiled3) -> String {
    to_zkir_string(&compiled.ir).expect("IR serializes")
}

label! {
    /// The id the request is filed under.
    RequestId = "request id";
    /// The amount, in the clear because the ledger writes it.
    Amount = "amount";
}

#[derive(CircuitArg)]
struct Request {
    request_id: B32<Private>,
    amount: Uint<128>,
}

// ---- the same circuit, declared and undeclared ------------------------------

#[circuit]
fn declaring(c: &mut Circuit3, request: Request) -> Discloses<(RequestId, Amount)> {
    let request_id = request.request_id.disclose_as::<RequestId>(c);
    let amount = request.amount.disclose_as::<Amount>(c);
    let sum = c.add(request_id.hi, amount.field());
    c.assert_bits(sum, 129);
    Discloses::of(())
}

#[circuit]
fn undeclared(c: &mut Circuit3, request: Request) {
    let request_id = B32 {
        hi: c.disclose(request.request_id.hi, "request id (hi)"),
        lo: c.disclose(request.request_id.lo, "request id (lo)"),
    };
    let amount = c.disclose(request.amount.field(), "amount");
    let sum = c.add(request_id.hi, amount);
    c.assert_bits(sum, 129);
    let _ = request_id.lo;
}

/// The zero-cost claim, stated as byte equality: a declaration and typed
/// `disclose_as` calls lower to exactly the circuit the free-string
/// `disclose` calls lower to.
#[test]
fn a_declaration_lowers_to_the_same_zkir() {
    assert_eq!(zkir(&declaring()), zkir(&undeclared()));
}

/// …and it does not move the interface: same inputs, same (absent) outputs.
#[test]
fn a_declaration_moves_no_slot() {
    let declared = declaring();
    let undeclared = undeclared();
    assert_eq!(declared.ir.inputs.len(), undeclared.ir.inputs.len());
    assert!(declared.ir.outputs.is_empty());
    assert_eq!(declared.ir.outputs, undeclared.ir.outputs);
    assert_eq!(declared.ir.instructions.len(), undeclared.ir.instructions.len());
}

/// The two spellings differ only in the disclosure RECORD, which is where
/// the win is: two limbs under one label instead of a `(hi)`/`(lo)` pair.
#[test]
fn one_label_covers_every_limb_of_a_value() {
    let declared = declaring();
    let labels: Vec<(&str, usize)> = declared
        .disclosures
        .iter()
        .map(|d| (d.label.as_str(), d.values.len()))
        .collect();
    assert_eq!(labels, vec![("request id", 2), ("amount", 1)]);

    let undeclared = undeclared();
    let labels: Vec<&str> = undeclared.disclosures.iter().map(|d| d.label.as_str()).collect();
    assert_eq!(labels, vec!["request id (hi)", "request id (lo)", "amount"]);
}

// ---- a declaration over a returned value ------------------------------------

label!(EventHash = "event hash");

#[circuit(output = "event hash")]
fn returning(c: &mut Circuit3, request: Request) -> Discloses<(RequestId,), B32<Public>> {
    let request_id = request.request_id.disclose_as::<RequestId>(c);
    let _ = request.amount;
    Discloses::of(request_id)
}

/// The attributed circuit's parameter is `request`, so the explicit
/// spelling needs the same head on its labels.
#[derive(CircuitArg)]
struct ReturningArgs {
    request: Request,
}

fn returning_explicit() -> Compiled3 {
    entry_out("event hash", |c, args: ReturningArgs| {
        let request_id = B32 {
            hi: c.disclose(args.request.request_id.hi, "request id"),
            lo: c.disclose(args.request.request_id.lo, "request id"),
        };
        let _ = args.request.amount;
        request_id
    })
}

/// `Discloses<D, R>` emits exactly what `R` emits — the two output slots and
/// their `(hi)`/`(lo)` labels are untouched by the declaration.
#[test]
fn a_declaration_over_a_returned_value_is_transparent() {
    assert_eq!(zkir(&returning()), zkir(&returning_explicit()));
    let compiled = returning();
    assert_eq!(compiled.ir.outputs.len(), 2);
    let outputs: Vec<&str> = compiled
        .disclosures
        .iter()
        .filter(|d| d.kind == minocrab::DisclosureKind::Output)
        .map(|d| d.label.as_str())
        .collect();
    assert_eq!(outputs, vec!["event hash (hi)", "event hash (lo)"]);
}

/// A circuit whose body is not an attributed function declares the same way
/// — `entry` takes any body that occupies no output slot.
#[test]
fn entry_accepts_a_declaration_directly() {
    let compiled = entry(|c, request: Request| {
        let _ = request.request_id.disclose_as::<RequestId>(c);
        let _ = request.amount;
        Discloses::<(RequestId,)>::of(())
    });
    assert_eq!(
        compiled.disclosures.iter().map(|d| d.label.as_str()).collect::<Vec<_>>(),
        vec!["request id"]
    );
}
