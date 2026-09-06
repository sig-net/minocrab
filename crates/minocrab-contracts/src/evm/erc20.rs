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
//! reads as the wire name it hashes to. Rung A re-homed the two M37 built
//! ([`Transfer`], [`Approve`]); rung B adds the rest of the interface a
//! signer like ours actually calls — [`TransferFrom`],
//! [`IncreaseAllowance`] / [`DecreaseAllowance`] (OpenZeppelin's, not
//! EIP-20's) and ERC-2612 [`Permit`].
//!
//! THE NON-CONFORMING TOKENS ARE NOT HERE. USDT and friends omit the `bool`
//! their `transfer` is supposed to return; their marker is
//! [`UsdtLike`](super::usdt::UsdtLike), a SIBLING interface rather than a
//! subtype, and the reason is the whole of notes/evm-calls.org §3.1.

use minocrab::v3::Circuit3;
use minocrab::Private;
use minocrab_std::v3::{is_true, Bool as BoolWire, Check};

use super::{always, Address, Bool, Bytes32, EvmCall, Interface, Unit, U128, U256, U8};

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
/// [`UsdtLike`](super::usdt::UsdtLike), a sibling rather than a subtype.
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

/// `transferFrom(address,address,uint256) -> bool` — selector `23b872dd`,
/// `(from, to, amount)`.
///
/// THE PULL, and the second half of every `approve`: a spender moves tokens
/// it was given an allowance for. It is what a contract calls after a
/// [`Permit`] (or after the holder's own `approve`) to take the tokens it
/// was authorised to take.
///
/// THE RETURNED FLAG IS THE VERDICT, exactly as [`Transfer`]'s — and the
/// stakes are the same in the other direction: a `transferFrom` that mined
/// and returned `false` pulled nothing.
pub struct TransferFrom;

impl EvmCall for TransferFrom {
    type Callee = Erc20;
    const NAME: &'static str = "transferFrom";
    type Args = (Address, Address, U128);
    type Return = Bool;
    type Success = ();
    const GAS_LIMIT: u64 = CALL_GAS;

    fn succeeded(_c: &mut Circuit3, ok: &BoolWire<Private>) -> Check<Private> {
        is_true(*ok)
    }
}

/// `increaseAllowance(address,uint256) -> bool` — selector `39509351`,
/// `(spender, addedValue)`.
///
/// NOT IN EIP-20: OpenZeppelin added the two deltas because `approve` has a
/// front-running race (a spender watching the mempool can spend the OLD
/// allowance and then the new one), and the standard workaround — approve
/// zero, then approve the new value — is two transactions. A delta is one.
///
/// OpenZeppelin REMOVED both in its v5 `ERC20`, so a v5 token does not have
/// them and a call reverts. They are here because the deployed tokens that
/// matter are older than v5; the type says what the FUNCTION is, and
/// whether a particular address exposes it is the same claim [`Erc20`]
/// itself is (see its docs).
pub struct IncreaseAllowance;

impl EvmCall for IncreaseAllowance {
    type Callee = Erc20;
    const NAME: &'static str = "increaseAllowance";
    type Args = (Address, U128);
    type Return = Bool;
    type Success = ();
    const GAS_LIMIT: u64 = CALL_GAS;

    fn succeeded(_c: &mut Circuit3, ok: &BoolWire<Private>) -> Check<Private> {
        is_true(*ok)
    }
}

/// `decreaseAllowance(address,uint256) -> bool` — selector `a457c2d7`,
/// `(spender, subtractedValue)`. [`IncreaseAllowance`]'s twin, and it
/// REVERTS rather than saturating when the subtraction would go below zero.
pub struct DecreaseAllowance;

impl EvmCall for DecreaseAllowance {
    type Callee = Erc20;
    const NAME: &'static str = "decreaseAllowance";
    type Args = (Address, U128);
    type Return = Bool;
    type Success = ();
    const GAS_LIMIT: u64 = CALL_GAS;

    fn succeeded(_c: &mut Circuit3, ok: &BoolWire<Private>) -> Check<Private> {
        is_true(*ok)
    }
}

/// ERC-2612 `permit(address,address,uint256,uint256,uint8,bytes32,bytes32)`
/// — selector `d505accf`, `(owner, spender, value, deadline, v, r, s)`:
/// SEVEN static words and no return.
///
/// THE GASLESS APPROVAL, and the MPC-signed flow's natural friend. The
/// token holder signs an EIP-712 message OFF-CHAIN and anybody — our
/// contract's derived key, here — submits it, so a contract can be granted
/// an allowance without the holder ever holding ether. That is exactly the
/// position a Midnight-side user is in.
///
/// `v` is a [`U8`] and `r`/`s` are [`Bytes32`] words the caller supplies
/// already encoded: a secp256k1 scalar does not fit a field element, and
/// there is nothing for a circuit to compute about one it is only relaying.
///
/// NO RETURN AT ALL. Solidity's `permit` returns `void`, so
/// [`Return`](EvmCall::Return) is [`Unit`] and
/// [`succeeded`](EvmCall::succeeded) is [`always`] — for a call with
/// nothing to say, executing IS succeeding, and there is no flag to be
/// fooled by. The MPC is never asked to decode one, which is the hazard
/// `Unit` exists for (notes/evm-calls.org §3.1).
///
/// WHAT THE TYPE CANNOT CHECK: that the signature is the owner's, that
/// `deadline` is in the future, or that the nonce inside the EIP-712 digest
/// is the token's current one. All three are the TOKEN's checks, and it
/// reverts — which reaches us as the MPC's failure kind.
pub struct Permit;

impl EvmCall for Permit {
    type Callee = Erc20;
    const NAME: &'static str = "permit";
    type Args = (Address, Address, U256, U256, U8, Bytes32, Bytes32);
    type Return = Unit;
    type Success = ();
    const GAS_LIMIT: u64 = CALL_GAS;

    fn succeeded(c: &mut Circuit3, _out: &()) -> Check<Private> {
        // The constant-true assert this makes is removed by
        // `drop_true_asserts` in `Builder3::finish`.
        always(c)
    }
}
