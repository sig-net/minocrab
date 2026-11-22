//! The README's example, verbatim. It is the README's Rust block and must be
//! kept in sync with it.

use minocrab::{Circuit, Private};
use minocrab_std::{circuit, label, CircuitArg, Disclose, Discloses, Uint, B32};

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

#[circuit]
fn declaring(c: &mut Circuit, request: Request) -> Discloses<(RequestId, Amount)> {
    let request_id = request.request_id.disclose_as::<RequestId>(c);
    let amount = request.amount.disclose_as::<Amount>(c);
    let sum = c.add(request_id.hi, amount.field());
    c.assert_bits(sum, 129);
    Discloses::of(())
}
