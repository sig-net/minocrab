//! `xcall-with-payment` (signet-midnight-experiments) — cross-contract
//! calls carrying coin data (M5). The caller holds a sealed target
//! reference (field 0) and calls `notify(coin: ShieldedCoinInfo)` /
//! `confirmRequest(requestId: Bytes<32>)`; the target's `confirmRequest`
//! records the request id.
//!
//! The target's `notify`/`pay` circuits are root-call coin-custody
//! circuits: `receiveShielded` + `treasury.writeCoin` (and for `pay` a
//! `paidRequests.insert`), with no cross-contract machinery.

use crate::common::{receive_shielded, write_coin_to_self};
use crate::interfaces::PaymentTarget;
use minocrab::v3::{Circuit3, Compiled3, FieldT, Wire3};
use minocrab::Public;
use minocrab_ledger::{emit, set_insert, ImpactElem, LedgerValue};
use minocrab_std::v3::{ShieldedCoinInfo3, B32};

/// Caller ledger: the sealed target reference.
pub const TARGET: u8 = 0;

/// Target ledger fields: treasury (0), requests (1), paidRequests (2).
pub const TREASURY: u8 = 0;
pub const REQUESTS: u8 = 1;
pub const PAID_REQUESTS: u8 = 2;

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

/// The sealed target reference: each call site reads the cell fresh.
const TARGET_CONTRACT: PaymentTarget = PaymentTarget::at_field(TARGET);

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
    TARGET_CONTRACT.notify(
        &mut c,
        one,
        ShieldedCoinInfo3 {
            nonce,
            color,
            value,
        },
    );
    c.finish(true)
}

/// `export circuit request(requestId: Bytes<32>): []` —
/// `target.confirmRequest(disclose(requestId))`.
pub fn request() -> Compiled3 {
    let mut c = Circuit3::new();
    let request_id = declare_b32(&mut c, "requestId");
    let request_id = b32_arg(&mut c, request_id, "requestId");
    let one = c.constant(1u64);
    TARGET_CONTRACT.confirm_request(&mut c, one, request_id);
    c.finish(true)
}

/// Declare a `ShieldedCoinInfo` argument's five limbs (nonce, color,
/// value) — declarations only, so callers can declare all args first.
fn declare_coin(
    c: &mut Circuit3,
) -> (B32<minocrab::Private>, B32<minocrab::Private>, Wire3<FieldT, minocrab::Private>) {
    (
        declare_b32(c, "coin_nonce"),
        declare_b32(c, "coin_color"),
        c.arg::<FieldT>("coin_value"),
    )
}

/// Constrain and disclose a declared coin argument.
fn coin_arg(
    c: &mut Circuit3,
    (nonce, color, value): (B32<minocrab::Private>, B32<minocrab::Private>, Wire3<FieldT, minocrab::Private>),
) -> ShieldedCoinInfo3<Public> {
    let nonce = b32_arg(c, nonce, "coin nonce");
    let color = b32_arg(c, color, "coin color");
    c.assert_bits(value, 128);
    let value = c.disclose(value, "coin value");
    ShieldedCoinInfo3 { nonce, color, value }
}

/// Target `export circuit notify(coin: ShieldedCoinInfo): []` —
/// `receiveShielded(disclose(coin)); treasury.writeCoin(disclose(coin),
/// right(kernel.self()))`. Root-call only (pinned limitation upstream).
pub fn notify() -> Compiled3 {
    let mut c = Circuit3::new();
    let coin = declare_coin(&mut c);
    let coin = coin_arg(&mut c, coin);
    let one = c.constant(1u64);
    receive_shielded(&mut c, one, &coin);
    write_coin_to_self(&mut c, one, TREASURY, &coin);
    c.finish(true)
}

/// Target `export circuit pay(requestId: Bytes<32>, coin:
/// ShieldedCoinInfo): []` — `notify`'s custody body, then the blind
/// `paidRequests.insert(disclose(requestId))`.
pub fn pay() -> Compiled3 {
    let mut c = Circuit3::new();
    let request_id = declare_b32(&mut c, "requestId");
    let coin = declare_coin(&mut c);
    let request_id = b32_arg(&mut c, request_id, "requestId");
    let coin = coin_arg(&mut c, coin);
    let one = c.constant(1u64);
    receive_shielded(&mut c, one, &coin);
    write_coin_to_self(&mut c, one, TREASURY, &coin);
    let elem = LedgerValue::bytes(
        32,
        vec![ImpactElem::Wire(request_id.hi), ImpactElem::Wire(request_id.lo)],
    );
    emit(&mut c, one, &set_insert(PAID_REQUESTS, &elem));
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
