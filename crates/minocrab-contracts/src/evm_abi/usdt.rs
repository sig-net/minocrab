//! THE NON-CONFORMING TOKENS — USDT, BNB and the other pre-final-EIP-20
//! tokens whose `transfer` returns NOTHING (M38 rung B,
//! notes/evm-calls.org §3.1).
//!
//! [`UsdtLike`] is a SIBLING of [`Erc20`](super::erc20::Erc20), not a
//! subtype, and that is the entire design. It would be easy to make one
//! `Contract<Erc20>` do for both — the calldata is byte-identical, the
//! selectors are the same four bytes, the two differ only in what comes
//! back — and it is exactly the wrong thing:
//!
//! - Filing a `transfer` against a USDT address as an
//!   [`erc20::Transfer`](super::erc20::Transfer) declares a `bool` return.
//! - The MPC decodes the return data into the declared schema. Empty return
//!   data is not a `bool`, so the decode is a terminal extraction failure.
//! - A terminal extraction failure resolves the request as the MPC's
//!   FAILURE kind — the kind a `refund` accepts.
//! - So a transfer that MOVED THE TOKENS comes back attested as a failure,
//!   the sender is refunded on the Midnight side, and the recipient keeps
//!   the tokens. Nothing on our side can see it from the attestation.
//!
//! Declaring the calls here with `Return = Unit` is what stops the MPC ever
//! being asked to decode a flag that is not there: the call says it returns
//! nothing, so nothing is what is decoded, and the outcome is the honest
//! one — mined is succeeded, reverted is the failure kind.
//!
//! WHICH ADDRESS IS WHICH IS A DEPLOYMENT'S CLAIM, exactly as
//! [`Erc20`](super::erc20::Erc20) is: a contract that builds a
//! `Contract<UsdtLike>` from an address is stating that this token does not
//! return a flag. The types keep the two claims from being confused —
//! there is no `Extends` impl either way, so a `Contract<Erc20>` cannot
//! take a [`Transfer`] here and a `Contract<UsdtLike>` cannot take an
//! [`erc20::Transfer`](super::erc20::Transfer) — but neither type checks a
//! deployment, which is why the callee allow-list is still the contract's
//! job.
//!
//! THE SELECTORS ARE THE ERC-20 SELECTORS. `transfer(address,uint256)`
//! hashes to `a9059cbb` whatever the token does with its return, so the
//! calldata a `Contract<UsdtLike>` files is byte-for-byte what a
//! `Contract<Erc20>` would file. The difference is entirely in the
//! attested-output schema and the outcome rule, which is where the hazard
//! lives.

use minocrab::v3::Circuit3;
use minocrab::Private;
use minocrab_std::v3::Check;

use super::{always, Address, EvmCall, Interface, Unit, U128, U256};

/// A TOKEN THAT DOES NOT RETURN A FLAG — the callee marker.
///
/// NOT `Extends<Erc20>` and never will be: the whole content of the type is
/// that these two interfaces' calls must not be interchangeable. USDT is
/// the largest stablecoin by supply, so this is not a corner case.
pub struct UsdtLike;

impl Interface for UsdtLike {}

/// The gas limit a call on one of these tokens defaults to —
/// [`erc20::CALL_GAS`](super::erc20::CALL_GAS), the same 100,000. The
/// return shape does not change what a transfer costs.
pub const CALL_GAS: u64 = super::erc20::CALL_GAS;

/// `transfer(address,uint256)` — selector `a9059cbb`, NO RETURN.
///
/// The same four selector bytes and the same two words as
/// [`erc20::Transfer`](super::erc20::Transfer); what differs is
/// [`Return`](EvmCall::Return) = [`Unit`] and therefore
/// [`succeeded`](EvmCall::succeeded) = [`always`]. There is no flag, so
/// mined IS succeeded — and, crucially, the MPC is never asked to decode
/// one, so a transfer that worked cannot be attested as a failure.
pub struct Transfer;

impl EvmCall for Transfer {
    type Callee = UsdtLike;
    const NAME: &'static str = "transfer";
    type Args = (Address, U128);
    type Return = Unit;
    type Success = ();
    const GAS_LIMIT: u64 = CALL_GAS;

    fn succeeded(c: &mut Circuit3, _out: &()) -> Check<Private> {
        // The constant-true assert this makes is removed by
        // `drop_true_asserts` in `Builder3::finish`.
        always(c)
    }
}

/// `approve(address,uint256)` — selector `095ea7b3`, NO RETURN.
///
/// USDT's `approve` additionally REVERTS when the current allowance is
/// non-zero and the new one is too (its own anti-front-running rule), which
/// is why "approve zero first" is the habit. That reverts on the token, so
/// it reaches a settle circuit as the MPC's failure kind, like any other
/// revert.
pub struct Approve;

impl EvmCall for Approve {
    type Callee = UsdtLike;
    const NAME: &'static str = "approve";
    type Args = (Address, U256);
    type Return = Unit;
    type Success = ();
    const GAS_LIMIT: u64 = CALL_GAS;

    fn succeeded(c: &mut Circuit3, _out: &()) -> Check<Private> {
        always(c)
    }
}

/// `transferFrom(address,address,uint256)` — selector `23b872dd`, NO
/// RETURN. [`Transfer`]'s pull twin.
pub struct TransferFrom;

impl EvmCall for TransferFrom {
    type Callee = UsdtLike;
    const NAME: &'static str = "transferFrom";
    type Args = (Address, Address, U128);
    type Return = Unit;
    type Success = ();
    const GAS_LIMIT: u64 = CALL_GAS;

    fn succeeded(c: &mut Circuit3, _out: &()) -> Check<Private> {
        always(c)
    }
}
