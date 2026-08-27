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
use minocrab::{label, Private, Public};
use minocrab_ledger::{
    emit, set_insert, ImpactElem, LedgerValue, XcallCommitment, XcallEntryPointHash,
};
use minocrab_std::v3::{
    circuit, CircuitArg, Disclose, Discloses, ShieldedCoinInfo3, Uint, B32,
};

/// Caller ledger: the sealed target reference.
pub const TARGET: u8 = 0;

/// Target ledger fields: treasury (0), requests (1), paidRequests (2).
pub const TREASURY: u8 = 0;
pub const REQUESTS: u8 = 1;
pub const PAID_REQUESTS: u8 = 2;

label! {
    /// The caller side spells the coin's three fields the way its own
    /// hand-written calls did — bare `nonce`/`color`/`value` — and the target
    /// side prefixes them; the two are different circuits and the strings are
    /// what the reports have always said.
    Nonce = "nonce";
    Color = "color";
    Value = "value";
    RequestId = "requestId";
    CoinNonce = "coin nonce";
    CoinColor = "coin color";
    CoinValue = "coin value";
}

/// `struct ShieldedCoinInfo { nonce: Bytes<32>, color: Bytes<32>, value:
/// Uint<128> }` as an argument — the typed twin of [`ShieldedCoinInfo3`],
/// whose fields are raw wires because the body handles the coin after
/// disclosing it (as `erc20_vault`'s `ShieldedCoinArg` is).
#[derive(CircuitArg)]
struct CoinArg {
    nonce: minocrab_std::v3::CoinNonce<Private>,
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
pub fn call_once(
    c: &mut Circuit3,
    coin: CoinArg,
) -> Discloses<(Nonce, Color, Value, XcallEntryPointHash, XcallCommitment)> {
    let nonce = coin.nonce.disclose_as::<Nonce>(c);
    let color = coin.color.disclose_as::<Color>(c);
    let value = coin.value.disclose_as::<Value>(c).field();
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
    Discloses::of(())
}

/// `export circuit request(requestId: Bytes<32>): []` —
/// `target.confirmRequest(disclose(requestId))`.
#[circuit]
pub fn request(
    c: &mut Circuit3,
    request_id: B32<Private>,
) -> Discloses<(RequestId, XcallEntryPointHash, XcallCommitment)> {
    let request_id = request_id.disclose_as::<RequestId>(c);
    let one = c.constant(1u64);
    TARGET_CONTRACT.confirm_request(c, one, request_id);
    Discloses::of(())
}

/// Disclose a coin argument — three labels, one per field, as the
/// hand-written calls named them (the whole-coin
/// [`Disclose`] impl would fold them into one).
fn disclose_coin(c: &mut Circuit3, coin: CoinArg) -> ShieldedCoinInfo3<Public> {
    let nonce = coin.nonce.disclose_as::<CoinNonce>(c);
    let color = coin.color.disclose_as::<CoinColor>(c);
    let value = coin.value.disclose_as::<CoinValue>(c).field();
    ShieldedCoinInfo3 { nonce, color, value }
}

/// Target `export circuit notify(coin: ShieldedCoinInfo): []` —
/// `receiveShielded(disclose(coin)); treasury.writeCoin(disclose(coin),
/// right(kernel.self()))`. Root-call only (pinned limitation upstream).
#[circuit]
pub fn notify(c: &mut Circuit3, coin: CoinArg) -> Discloses<(CoinNonce, CoinColor, CoinValue)> {
    let coin = disclose_coin(c, coin);
    let one = c.constant(1u64);
    receive_shielded(c, one, &coin);
    write_coin_to_self(c, one, TREASURY, &coin);
    Discloses::of(())
}

/// Target `export circuit pay(requestId: Bytes<32>, coin:
/// ShieldedCoinInfo): []` — `notify`'s custody body, then the blind
/// `paidRequests.insert(disclose(requestId))`.
#[circuit]
pub fn pay(
    c: &mut Circuit3,
    request_id: B32<Private>,
    coin: CoinArg,
) -> Discloses<(RequestId, CoinNonce, CoinColor, CoinValue)> {
    let request_id = request_id.disclose_as::<RequestId>(c);
    let coin = disclose_coin(c, coin);
    let one = c.constant(1u64);
    receive_shielded(c, one, &coin);
    write_coin_to_self(c, one, TREASURY, &coin);
    let elem = LedgerValue::bytes(
        32,
        vec![ImpactElem::Wire(request_id.hi), ImpactElem::Wire(request_id.lo)],
    );
    emit(c, one, &set_insert(PAID_REQUESTS, &elem));
    Discloses::of(())
}

/// Target `export circuit confirmRequest(requestId: Bytes<32>): []` —
/// `requests.insert(disclose(requestId))`.
#[circuit]
pub fn confirm_request(
    c: &mut Circuit3,
    request_id: B32<Private>,
) -> Discloses<(RequestId,)> {
    let request_id = request_id.disclose_as::<RequestId>(c);
    let one = c.constant(1u64);
    let elem = LedgerValue::bytes(
        32,
        vec![ImpactElem::Wire(request_id.hi), ImpactElem::Wire(request_id.lo)],
    );
    emit(c, one, &set_insert(REQUESTS, &elem));
    Discloses::of(())
}
