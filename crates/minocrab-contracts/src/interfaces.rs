//! The callees' interfaces, as `#[interface]` traits.
//!
//! One trait per contract we call, one bodyless `fn` per callee circuit —
//! the Compact `contract Token { circuit deposit(…): Bytes<32>; }` block,
//! transliterated. Each expands to the handle struct M12 stage 2 wrote by
//! hand: an [`EntryPoint`](minocrab_ledger::EntryPoint) const per circuit
//! derived from the Compact name, `at_field(index)` / `at(address)`
//! constructors, `pin`, and one typed method per circuit over
//! `minocrab_ledger::call`.
//!
//! The diff from stage 2 is the attribute and nothing else: the same
//! circuits come out, byte for byte, which
//! `crates/minocrab-std/tests/v3_interface.rs` checks as serialized ZKIR.
//!
//! Arguments and results are `Public`, and the macro says so: passing a
//! value to another contract discloses it, so a parameter written at
//! `Private` — or left to DEFAULT to it, which `Uint<128>` does — is a
//! compile error naming `disclose()`.
//!
//! AN INTERFACE CONTAINS NO ADDRESS. `at_field` names a ledger field and
//! `at` takes one at runtime, which is why a trait here lifts into a
//! published crate unchanged — which is what happened to `SignetSigner`,
//! now the `signet-signer-interface` crate and an ordinary dependency of
//! this one.

use minocrab::Public;
use minocrab_std::v3::{interface, BytesN, ContractAddress, ShieldedCoinInfo3, Uint, B32};

/// The `xcontract-events` token — the one callee in the corpus with a
/// RETURN VALUE, and so the one that exercises `CallResult`:
///
/// ```text
/// contract Token { circuit deposit(amount: Uint<128>, caller: ContractAddress): Bytes<32>; }
/// ```
///
/// The returned `Bytes<32>`'s `[Bits(8), Bits(248)]` result constraints are
/// derived from its ABI; nothing here writes them down.
#[interface]
pub trait Token {
    fn deposit(amount: Uint<128, Public>, caller: ContractAddress<Public>) -> B32<Public>;
}

/// The `xcall` experiment's target:
///
/// ```text
/// contract Target {
///   circuit deposit(recipient: Bytes<32>, amount: Uint<128>): [];
///   circuit depositEmit(recipient: Bytes<32>, amount: Uint<128>): [];
///   circuit depositBig(data: Bytes<256>): [];
/// }
/// ```
///
/// `deposit` and `depositEmit` differ ONLY in the entry point claimed —
/// which is a prover-supplied witness — so the two methods build the same
/// circuit. That is honest limit #1 of notes/interface-crates.org, visible
/// in the API and asserted in `tests/xcall_differential.rs`.
#[interface]
pub trait XcallTarget {
    fn deposit(recipient: B32<Public>, amount: Uint<128, Public>);
    fn deposit_emit(recipient: B32<Public>, amount: Uint<128, Public>);
    fn deposit_big(data: BytesN<Public, 256>);
}

/// The `xcall-with-payment` target:
///
/// ```text
/// contract Target {
///   circuit notify(coin: ShieldedCoinInfo): [];
///   circuit confirmRequest(requestId: Bytes<32>): [];
/// }
/// ```
#[interface]
pub trait PaymentTarget {
    fn notify(coin: ShieldedCoinInfo3<Public>);
    fn confirm_request(request_id: B32<Public>);
}
