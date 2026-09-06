//! ERC-4626 — the tokenized-vault interface (M38 rungs A and C,
//! notes/evm-interfaces.org §2.4).
//!
//! AN ERC-4626 VAULT IS AN ERC-20: its shares are a token, so
//! `impl Extends<Erc20> for Erc4626` and a `Contract<Erc4626>` takes an
//! [`erc20::Approve`](super::erc20::Approve) as well as the calls here.
//! (Rung A declared that inheritance and found no lineage using it — the
//! deployed vault's `approveStata` approves ON the underlying ERC-20 with
//! the stata token as the SPENDER, notes/evm-interfaces.org §4 adjustment
//! 4. [`Weth`](super::weth::Weth) is the first shipped consumer.)
//!
//! THE FOUR ENTRY POINTS, WHICH ARE TWO PAIRS. The EIP gives every
//! direction both an exact-input and an exact-output form, and which one a
//! caller wants is a question about WHICH SIDE THE ROUNDING FALLS ON:
//!
//! | | assets fixed | shares fixed |
//! |------|--------------|--------------|
//! | in  | [`Deposit`] — spend exactly `assets`, get whatever shares | [`Mint`] — get exactly `shares`, spend whatever assets |
//! | out | [`Withdraw`] — take exactly `assets`, burn whatever shares | [`Redeem`] — burn exactly `shares`, take whatever assets |
//!
//! In each the FIXED side is the first argument and the FLOATING side is
//! the `uint256` return, which is why all four have the same outcome rule
//! (executed is succeeded — see [`Deposit`]) and why a settle circuit must
//! read the return to learn what actually moved.

use minocrab::v3::Circuit3;
use minocrab::Private;
use minocrab_std::v3::{Check, Uint};

use super::erc20::Erc20;
use super::{always, Address, EvmCall, Extends, Interface, U128, U64};

/// AN ERC-4626 TOKENIZED VAULT — the callee marker.
pub struct Erc4626;

impl Interface for Erc4626 {}

/// The shares ARE an ERC-20, so every ERC-20 call may be filed against a
/// `Contract<Erc4626>`.
impl Extends<Erc20> for Erc4626 {}

/// The gas limit an ERC-4626 call defaults to.
///
/// The deployed vault's own `LENDING_GAS`, defined here and aliased there
/// (notes/evm-interfaces.org §2.3).
pub const CALL_GAS: u64 = 500_000;

/// `deposit(uint256,address) -> uint256` — selector `6e553f65`,
/// `(assets, receiver)`.
///
/// The attested share count comes back narrowed to `uint64`
/// ([`U64::RESPOND`](super::AbiType::RESPOND)), which is what the vault's
/// `SUPPLY_RESPOND_SCHEMA` asks the MPC for.
///
/// EXECUTED IS SUCCEEDED: the number IS the outcome. A deposit that minted
/// ZERO shares executed perfectly and achieved nothing, and a caller who
/// wants that to be a failure writes its own call type with
/// `shares.gt(0u64)` — the shape [`super::EvmCall::succeeded`]
/// documents. The deployed vault's semantics are "executed", and tightening
/// them is a protocol change rather than a re-homing.
pub struct Deposit;

impl EvmCall for Deposit {
    type Callee = Erc4626;
    const NAME: &'static str = "deposit";
    type Args = (U128, Address);
    type Return = U64;
    type Success = Uint<64, Private>;
    const GAS_LIMIT: u64 = CALL_GAS;

    fn succeeded(c: &mut Circuit3, _out: &Uint<64, Private>) -> Check<Private> {
        // The constant-true assert this makes is removed by
        // `drop_true_asserts` in `Builder3::finish`.
        always(c)
    }
}

/// `mint(uint256,address) -> uint256` — selector `94bf804d`,
/// `(shares, receiver)`. The attested asset count — what the mint actually
/// COST — comes back narrowed to `uint64`.
///
/// [`Deposit`] SPELLED THE OTHER WAY ROUND: a deposit fixes the assets
/// spent and lets the shares fall out, a mint fixes the shares received and
/// lets the cost fall out. That matters to a caller with an exact share
/// target and it matters to the ALLOWANCE, because the amount the vault
/// pulls is not known until it runs — an `approve` sized to a deposit's
/// assets may be short for the mint that asks for the shares that deposit
/// would have produced.
///
/// EXECUTED IS SUCCEEDED, for [`Deposit`]'s reason.
pub struct Mint;

impl EvmCall for Mint {
    type Callee = Erc4626;
    const NAME: &'static str = "mint";
    type Args = (U128, Address);
    type Return = U64;
    type Success = Uint<64, Private>;
    const GAS_LIMIT: u64 = CALL_GAS;

    fn succeeded(c: &mut Circuit3, _out: &Uint<64, Private>) -> Check<Private> {
        always(c)
    }
}

/// `withdraw(uint256,address,address) -> uint256` — selector `b460af94`,
/// `(assets, receiver, owner)`. The attested share count — what the
/// withdrawal BURNED — comes back narrowed to `uint64`.
///
/// [`Redeem`] SPELLED THE OTHER WAY ROUND, and the pair on the way out that
/// [`Deposit`] / [`Mint`] are on the way in: a redeem fixes the shares
/// burned, a withdraw fixes the assets taken.
///
/// `owner` IS NOT THE CALLER unless the caller says so. The vault burns
/// `owner`'s shares, and doing that for an `owner` other than `msg.sender`
/// needs an ERC-20 allowance ON THE VAULT ITSELF — which is exactly why
/// `Erc4626` [`Extends`] `Erc20`, and why the approval that enables it is
/// filed against the same `Contract<Erc4626>` cell.
///
/// EXECUTED IS SUCCEEDED, for [`Deposit`]'s reason.
pub struct Withdraw;

impl EvmCall for Withdraw {
    type Callee = Erc4626;
    const NAME: &'static str = "withdraw";
    type Args = (U128, Address, Address);
    type Return = U64;
    type Success = Uint<64, Private>;
    const GAS_LIMIT: u64 = CALL_GAS;

    fn succeeded(c: &mut Circuit3, _out: &Uint<64, Private>) -> Check<Private> {
        always(c)
    }
}

/// `redeem(uint256,address,address) -> uint256` — selector `ba087652`,
/// `(shares, receiver, owner)`. The attested asset count comes back
/// narrowed to `uint64` (the vault's `REDEEM_RESPOND_SCHEMA`).
///
/// EXECUTED IS SUCCEEDED, for [`Deposit`]'s reason.
pub struct Redeem;

impl EvmCall for Redeem {
    type Callee = Erc4626;
    const NAME: &'static str = "redeem";
    type Args = (U128, Address, Address);
    type Return = U64;
    type Success = Uint<64, Private>;
    const GAS_LIMIT: u64 = CALL_GAS;

    fn succeeded(c: &mut Circuit3, _out: &Uint<64, Private>) -> Check<Private> {
        always(c)
    }
}
