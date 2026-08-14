//! `#[circuit]` must generate exactly the entry point phase 2 wrote by hand
//! — so the gate is the same one the derive passes: the same circuit written
//! twice, once as an attributed function and once as an explicit argument
//! struct + `entry` call, has to lower to byte-identical ZKIR. Serialized
//! ZKIR pins the argument LABELS too (`%label.index`), so the parameter-name
//! rule and the `#[arg(name = "…")]` override on a parameter are checked by
//! the same equality.

use minocrab::v3::{Circuit3, Compiled3};
use minocrab::{Private, Public};
use minocrab_std::v3::{circuit, entry, entry_out, Bytes, CircuitArg, Uint, B32};
use minocrab_zkir::v3::to_zkir_string;

fn zkir(compiled: &Compiled3) -> String {
    to_zkir_string(&compiled.ir).expect("IR serializes")
}

/// A nested argument, shared by both spellings — `#[circuit]` changes how a
/// circuit takes its arguments, not what an argument is.
#[derive(CircuitArg)]
struct Request {
    erc20_address: Bytes<20>,
    amount: Uint<128>,
}

// ---- the same circuit, twice ------------------------------------------------

#[circuit]
fn attributed(
    c: &mut Circuit3,
    evm_nonce: Uint<64>,
    #[arg(name = "respond")] respond_bidirectional_event: B32<Private>,
    deposit_request: Request,
) {
    let sum = c.add(evm_nonce.field(), deposit_request.amount.field());
    c.assert_bits(sum, 129);
    let gated = c.mul(deposit_request.erc20_address.field(), respond_bidirectional_event.hi);
    c.assert(gated);
}

#[derive(CircuitArg)]
struct ExplicitArgs {
    evm_nonce: Uint<64>,
    #[arg(name = "respond")]
    respond_bidirectional_event: B32<Private>,
    deposit_request: Request,
}

fn explicit() -> Compiled3 {
    entry(|c, args: ExplicitArgs| {
        let sum = c.add(args.evm_nonce.field(), args.deposit_request.amount.field());
        c.assert_bits(sum, 129);
        let gated = c.mul(
            args.deposit_request.erc20_address.field(),
            args.respond_bidirectional_event.hi,
        );
        c.assert(gated);
    })
}

#[test]
fn an_attributed_circuit_lowers_like_the_explicit_entry_call() {
    assert_eq!(zkir(&explicit()), zkir(&attributed()));
}

// ---- a circuit that returns a value -----------------------------------------

#[circuit(output = "event hash")]
fn attributed_output(c: &mut Circuit3, seed: Uint<64>) -> B32<Public> {
    let hi = c.disclose(seed.field(), "seed");
    let lo = c.constant(2u64);
    B32 { hi, lo }
}

fn explicit_output() -> Compiled3 {
    entry_out("event hash", |c, args: ExplicitOutputArgs| {
        let hi = c.disclose(args.seed.field(), "seed");
        let lo = c.constant(2u64);
        B32::<Public> { hi, lo }
    })
}

#[derive(CircuitArg)]
struct ExplicitOutputArgs {
    seed: Uint<64>,
}

#[test]
fn a_returning_circuit_lowers_like_the_explicit_entry_out_call() {
    assert_eq!(zkir(&explicit_output()), zkir(&attributed_output()));
}

// ---- the argument-free circuit ----------------------------------------------

#[circuit]
fn no_arguments(c: &mut Circuit3) {
    let one = c.constant(1u64);
    c.assert(one.private());
}

#[test]
fn a_circuit_without_arguments_declares_nothing() {
    let hand = {
        let mut c = Circuit3::new();
        let one = c.constant(1u64);
        c.assert(one.private());
        c.finish(true)
    };

    assert_eq!(zkir(&hand), zkir(&no_arguments()));
}
