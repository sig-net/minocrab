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
use minocrab::v3::Circuit3;
use minocrab::{Private, Public};
use minocrab_ledger::{emit, set_insert, ImpactElem, LedgerValue};
use minocrab_std::v3::{circuit, CircuitArg, ShieldedCoinInfo3, Uint, B32};

/// Caller ledger: the sealed target reference.
pub const TARGET: u8 = 0;

/// Target ledger fields: treasury (0), requests (1), paidRequests (2).
pub const TREASURY: u8 = 0;
pub const REQUESTS: u8 = 1;
pub const PAID_REQUESTS: u8 = 2;

/// Disclose a `Bytes<32>` argument.
fn disclose_b32(c: &mut Circuit3, arg: B32<Private>, name: &str) -> B32<Public> {
    B32 {
        hi: c.disclose(arg.hi, &format!("{name} (hi)")),
        lo: c.disclose(arg.lo, &format!("{name} (lo)")),
    }
}

/// `struct ShieldedCoinInfo { nonce: Bytes<32>, color: Bytes<32>, value:
/// Uint<128> }` as an argument — the typed twin of [`ShieldedCoinInfo3`],
/// whose fields are raw wires because the body handles the coin after
/// disclosing it (as `erc20_vault`'s `ShieldedCoinArg` is).
#[derive(CircuitArg)]
struct CoinArg {
    nonce: B32<Private>,
    color: B32<Private>,
    value: Uint<128>,
}

/// The sealed target reference: each call site reads the cell fresh.
const TARGET_CONTRACT: PaymentTarget = PaymentTarget::at_field(TARGET);

/// `export circuit callOnce(coin: ShieldedCoinInfo): []` —
/// `target.notify(disclose(coin))`. ShieldedCoinInfo = { nonce: Bytes<32>,
/// color: Bytes<32>, value: Uint<128> }, 5 FAB limbs.
///
/// NAME-COLUMN CHANGE (M9 phase 5): the coin's five slots were declared
/// `nonce_hi` … `value`, an abbreviation of the Compact parameter, and the
/// mechanical rule gives them the parameter's own name — `coin_nonce_hi` …
/// `coin_value`, which is what the target's `notify`/`pay` already called
/// them. Types and order are untouched; argument names are ours, not
/// compactc's (notes/ledger-abi.org §6).
#[circuit]
pub fn call_once(c: &mut Circuit3, coin: CoinArg) {
    let nonce = disclose_b32(c, coin.nonce, "nonce");
    let color = disclose_b32(c, coin.color, "color");
    let value = c.disclose(coin.value.field(), "value");
    let one = c.constant(1u64);
    TARGET_CONTRACT.notify(
        c,
        one,
        ShieldedCoinInfo3 {
            nonce,
            color,
            value,
        },
    );
}

/// `export circuit request(requestId: Bytes<32>): []` —
/// `target.confirmRequest(disclose(requestId))`.
#[circuit]
pub fn request(c: &mut Circuit3, request_id: B32<Private>) {
    let request_id = disclose_b32(c, request_id, "requestId");
    let one = c.constant(1u64);
    TARGET_CONTRACT.confirm_request(c, one, request_id);
}

/// Disclose a coin argument.
fn disclose_coin(c: &mut Circuit3, coin: CoinArg) -> ShieldedCoinInfo3<Public> {
    let nonce = disclose_b32(c, coin.nonce, "coin nonce");
    let color = disclose_b32(c, coin.color, "coin color");
    let value = c.disclose(coin.value.field(), "coin value");
    ShieldedCoinInfo3 { nonce, color, value }
}

/// Target `export circuit notify(coin: ShieldedCoinInfo): []` —
/// `receiveShielded(disclose(coin)); treasury.writeCoin(disclose(coin),
/// right(kernel.self()))`. Root-call only (pinned limitation upstream).
#[circuit]
pub fn notify(c: &mut Circuit3, coin: CoinArg) {
    let coin = disclose_coin(c, coin);
    let one = c.constant(1u64);
    receive_shielded(c, one, &coin);
    write_coin_to_self(c, one, TREASURY, &coin);
}

/// Target `export circuit pay(requestId: Bytes<32>, coin:
/// ShieldedCoinInfo): []` — `notify`'s custody body, then the blind
/// `paidRequests.insert(disclose(requestId))`.
#[circuit]
pub fn pay(c: &mut Circuit3, request_id: B32<Private>, coin: CoinArg) {
    let request_id = disclose_b32(c, request_id, "requestId");
    let coin = disclose_coin(c, coin);
    let one = c.constant(1u64);
    receive_shielded(c, one, &coin);
    write_coin_to_self(c, one, TREASURY, &coin);
    let elem = LedgerValue::bytes(
        32,
        vec![ImpactElem::Wire(request_id.hi), ImpactElem::Wire(request_id.lo)],
    );
    emit(c, one, &set_insert(PAID_REQUESTS, &elem));
}

/// Target `export circuit confirmRequest(requestId: Bytes<32>): []` —
/// `requests.insert(disclose(requestId))`.
#[circuit]
pub fn confirm_request(c: &mut Circuit3, request_id: B32<Private>) {
    let request_id = disclose_b32(c, request_id, "requestId");
    let one = c.constant(1u64);
    let elem = LedgerValue::bytes(
        32,
        vec![ImpactElem::Wire(request_id.hi), ImpactElem::Wire(request_id.lo)],
    );
    emit(c, one, &set_insert(REQUESTS, &elem));
}
