//! WETH — wrapped ether, and the first shipped consumer of interface
//! INHERITANCE (M38 rung B, notes/evm-interfaces.org §2.1 as corrected).
//!
//! WETH IS AN ERC-20 — that is the whole point of it: ether is not a token,
//! and every contract that wants to treat it as one calls `deposit()` and
//! then moves the ERC-20 balance the contract minted. So
//! `impl Extends<Erc20> for Weth`, and one `Contract<Weth>` cell takes
//! [`Deposit`] and [`Withdraw`] here AND [`erc20::Transfer`],
//! [`erc20::Approve`] and the rest of the ERC-20 surface. Rung A declared
//! the inheritance and had no lineage that used it (the vault's
//! `approve_stata` turned out to approve ON the underlying token, §4
//! adjustment 4); this is a callee where a single deployed address really
//! is reached by two interfaces' calls.
//!
//! [`Deposit`] IS THE ONE CALL IN THE LIBRARY THAT CARRIES ETHER. The ether
//! is the argument — `deposit()` takes none and wraps whatever `value` the
//! transaction carries — so it is [`Payable`], and
//! `Pending::request_payable` is the only way to file it with an amount.

use minocrab::v3::Circuit3;
use minocrab::Private;
use minocrab_std::v3::Check;

use super::erc20::{self, Erc20};
use super::{always, EvmCall, Extends, Interface, Payable, Unit, U128};

/// WRAPPED ETHER — the callee marker.
///
/// The canonical deployment is `0xC02aaA39…` on Ethereum mainnet, and every
/// chain has its own; like every marker here it records the CLAIM a
/// contract made when it built the address, not a check on the deployment
/// (see [`Erc20`]).
pub struct Weth;

impl Interface for Weth {}

/// WETH IS AN ERC-20, so every ERC-20 call may be filed against a
/// `Contract<Weth>` — which is the point of wrapping ether in the first
/// place.
impl Extends<Erc20> for Weth {}

/// The gas limit a WETH call defaults to.
///
/// [`erc20::CALL_GAS`] — the same 100,000. Both
/// calls here are cheaper than an ERC-20 `transfer` in practice (a
/// `deposit` is one balance write and a log), so the token limit is a safe
/// default and NOT a second magic number.
pub const CALL_GAS: u64 = erc20::CALL_GAS;

/// `deposit()` — selector `d0e30db0`, PAYABLE, no arguments and no return.
///
/// The ether the transaction carries becomes WETH credited to the sender.
/// There is nothing in the calldata but the selector: the AMOUNT IS THE
/// TRANSACTION'S `value` FIELD, which is why this is the library's one
/// [`Payable`] call and why a `Pending<_, _, 0>` slot files it — zero
/// argument words.
///
/// NO RETURN: `deposit` is `void`, so [`Return`](EvmCall::Return) is
/// [`Unit`] and [`succeeded`](EvmCall::succeeded) is [`always`]. Executing
/// IS succeeding; a WETH deposit that mines has wrapped the ether, and
/// there is no flag for a settle circuit to be fooled by.
pub struct Deposit;

impl EvmCall for Deposit {
    type Callee = Weth;
    const NAME: &'static str = "deposit";
    type Args = ();
    type Return = Unit;
    type Success = ();
    const GAS_LIMIT: u64 = CALL_GAS;

    fn succeeded(c: &mut Circuit3, _out: &()) -> Check<Private> {
        // The constant-true assert this makes is removed by
        // `drop_true_asserts` in `Builder3::finish`.
        always(c)
    }
}

/// THE ETHER IS THE ARGUMENT: `deposit()` is payable, and the transaction's
/// `value` field is a real amount rather than the constant zero every other
/// call in this library fixes it at.
impl Payable for Deposit {}

/// `withdraw(uint256)` — selector `2e1a7d4d`, one word, no return.
///
/// The reverse: WETH is burned and the ether is sent back to the caller.
/// NOT payable — the ether flows the other way, so a `value` on this call
/// would be ether handed to the contract and forgotten, and `Withdraw` has
/// no [`Payable`] impl to allow it.
///
/// NO RETURN, for [`Deposit`]'s reason: `withdraw` is `void`. It reverts
/// when the caller's WETH balance is short, which reaches a settle circuit
/// as the MPC's failure kind.
pub struct Withdraw;

impl EvmCall for Withdraw {
    type Callee = Weth;
    const NAME: &'static str = "withdraw";
    type Args = (U128,);
    type Return = Unit;
    type Success = ();
    const GAS_LIMIT: u64 = CALL_GAS;

    fn succeeded(c: &mut Circuit3, _out: &()) -> Check<Private> {
        always(c)
    }
}
