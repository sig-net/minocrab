//! ERC-20 — the token interface, and the calls a signer like ours makes on
//! one (M38 rung A, notes/evm-interfaces.org §2.4).
//!
//! [`Erc20`] is the CALLEE MARKER: a `Contract<Erc20>` is an address that
//! claims to expose these functions, and a call whose
//! [`super::EvmCall::Callee`] is `Erc20` may be filed
//! against it — or against any interface that [`Extends`](super::Extends)
//! it, which is how an ERC-4626 vault takes an `approve`.
//!
//! The calls are named after the SOLIDITY FUNCTION, so `erc20::Transfer`
//! reads as the wire name it hashes to. Rung A re-homes the two M37 built:
//! `transfer` and `approve`. `transferFrom`, the OpenZeppelin allowance
//! deltas and ERC-2612 `permit` are rung B.

use minocrab::v3::Circuit3;
use minocrab::Private;
use minocrab_std::v3::{is_true, Bool as BoolWire, Check};

use super::{Address, Bool, EvmCall, Interface, U128, U256};

/// AN ERC-20 TOKEN — the callee marker.
///
/// It says what the ADDRESS CLAIMS, not what it is: nothing here checks a
/// deployment. A contract that hands an address to
/// [`Contract::from_address`](crate::evm_flow::Contract::from_address) is
/// making that claim, which is why the callee-allow-list hazard
/// (notes/evm-calls.org §3.1) is about where the address came from.
///
/// A NON-CONFORMING TOKEN IS NOT THIS INTERFACE: USDT and friends omit the
/// `bool` their `transfer` is supposed to return, and reading their
/// (absent) return as a flag is the dangerous direction. Their marker is
/// `UsdtLike`, a sibling rather than a subtype — rung B.
pub struct Erc20;

impl Interface for Erc20 {}

/// The gas limit an ERC-20 call defaults to.
///
/// The deployed vault's own `ERC20_CALL_GAS`, which is now DEFINED HERE and
/// aliased there (notes/evm-interfaces.org §2.3: a per-function gas default
/// is a fact about the function, so re-homing it moves no byte).
pub const CALL_GAS: u64 = 100_000;

/// `transfer(address,uint256) -> bool` — selector `a9059cbb`.
///
/// The amount is a [`U128`] because that is the width a Midnight-side
/// amount reaches the ABI at (`Uint<64>::widen::<128>()` is free; the other
/// direction is a range check). The Solidity spelling is `uint256` either
/// way, so the selector does not move.
///
/// THE RETURNED FLAG IS THE VERDICT —
/// [`succeeded`](super::EvmCall::succeeded) is `is_true`, not "executed is
/// success". An ERC-20 `transfer` mines happily and returns `false`, and a
/// completion that did not look would credit a transfer that moved nothing.
pub struct Transfer;

impl EvmCall for Transfer {
    type Callee = Erc20;
    const NAME: &'static str = "transfer";
    type Args = (Address, U128);
    type Return = Bool;
    type Success = ();
    const GAS_LIMIT: u64 = CALL_GAS;

    fn succeeded(_c: &mut Circuit3, ok: &BoolWire<Private>) -> Check<Private> {
        is_true(*ok)
    }
}

/// `approve(address,uint256) -> bool` — selector `095ea7b3`.
///
/// The allowance is a [`U256`] (an already-encoded word) because that is
/// what an approval IS in the wild and what the vault passes: the constant
/// unlimited-allowance word, through no encoder at all.
pub struct Approve;

impl EvmCall for Approve {
    type Callee = Erc20;
    const NAME: &'static str = "approve";
    type Args = (Address, U256);
    type Return = Bool;
    type Success = ();
    const GAS_LIMIT: u64 = CALL_GAS;

    fn succeeded(_c: &mut Circuit3, ok: &BoolWire<Private>) -> Check<Private> {
        is_true(*ok)
    }
}
