//! `xcall-with-payment` (signet-midnight-experiments) — cross-contract
//! calls carrying coin data (M5). The caller holds a sealed target
//! reference (field 0) and calls `notify(coin: ShieldedCoinInfo)` /
//! `confirmRequest(requestId: Bytes<32>)`; the target's `confirmRequest`
//! records the request id.
//!
//! The target's `notify`/`pay` circuits are root-call coin-custody
//! circuits (`receiveShielded` + `treasury.writeCoin`) with no
//! cross-contract machinery — they belong to the remaining M4 stdlib work
//! (coin receive), not M5, and are not rewritten here.

use minocrab::v3::{Circuit3, Compiled3, FieldT, Wire3};
use minocrab::{AlignmentAtom, Public};
use minocrab_ledger::{cell_read, contract_call, emit, set_insert, ImpactElem, LedgerValue};
use minocrab_std::v3::B32;

/// Caller ledger: the sealed target reference.
pub const TARGET: u8 = 0;

/// Target ledger fields: treasury (0), requests (1), paidRequests (2).
pub const REQUESTS: u8 = 1;

/// Constrain and disclose an already-declared `Bytes<32>` argument (all
/// `arg` declarations must precede the first instruction).
fn b32_arg(c: &mut Circuit3, arg: B32<minocrab::Private>, name: &str) -> B32<Public> {
    arg.constrain_input(c);
    B32 {
        hi: c.disclose(arg.hi, &format!("{name} (hi)")),
        lo: c.disclose(arg.lo, &format!("{name} (lo)")),
    }
}

fn declare_b32(c: &mut Circuit3, name: &str) -> B32<minocrab::Private> {
    B32 {
        hi: c.arg::<FieldT>(&format!("{name}_hi")),
        lo: c.arg::<FieldT>(&format!("{name}_lo")),
    }
}

/// The call site: fresh uncached read of the sealed target, then the call.
fn call_target(c: &mut Circuit3, one: Wire3<FieldT, Public>, args: &[Wire3<FieldT, Public>]) {
    let addr = cell_read(c, one, TARGET, vec![AlignmentAtom::Bytes { length: 32 }]);
    contract_call(c, one, [addr[0], addr[1]], args, &[]);
}

/// `export circuit callOnce(coin: ShieldedCoinInfo): []` —
/// `target.notify(disclose(coin))`. ShieldedCoinInfo = { nonce: Bytes<32>,
/// color: Bytes<32>, value: Uint<128> }, 5 FAB limbs.
pub fn call_once() -> Compiled3 {
    let mut c = Circuit3::new();
    let nonce = declare_b32(&mut c, "nonce");
    let color = declare_b32(&mut c, "color");
    let value = c.arg::<FieldT>("value");
    let nonce = b32_arg(&mut c, nonce, "nonce");
    let color = b32_arg(&mut c, color, "color");
    c.assert_bits(value, 128);
    let value = c.disclose(value, "value");
    let one = c.constant(1u64);
    call_target(&mut c, one, &[nonce.hi, nonce.lo, color.hi, color.lo, value]);
    c.finish(true)
}

/// `export circuit request(requestId: Bytes<32>): []` —
/// `target.confirmRequest(disclose(requestId))`.
pub fn request() -> Compiled3 {
    let mut c = Circuit3::new();
    let request_id = declare_b32(&mut c, "requestId");
    let request_id = b32_arg(&mut c, request_id, "requestId");
    let one = c.constant(1u64);
    call_target(&mut c, one, &[request_id.hi, request_id.lo]);
    c.finish(true)
}

/// Target `export circuit confirmRequest(requestId: Bytes<32>): []` —
/// `requests.insert(disclose(requestId))`.
pub fn confirm_request() -> Compiled3 {
    let mut c = Circuit3::new();
    let request_id = declare_b32(&mut c, "requestId");
    let request_id = b32_arg(&mut c, request_id, "requestId");
    let one = c.constant(1u64);
    let elem = LedgerValue::bytes(
        32,
        vec![ImpactElem::Wire(request_id.hi), ImpactElem::Wire(request_id.lo)],
    );
    emit(&mut c, one, &set_insert(REQUESTS, &elem));
    c.finish(true)
}
