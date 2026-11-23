//! ERC-4626 — the tokenized-vault interface (notes/evm-interfaces.org §2.4).
//!
//! An ERC-4626 vault is an ERC-20: its shares are a token, so
//! `impl Extends<Erc20> for Erc4626` and a `Contract<Erc4626>` takes an
//! [`erc20::Approve`](super::erc20::Approve) as well as the calls here.
//! (The deployed vault's `approveStata` approves on the underlying ERC-20
//! with the stata token as the spender, notes/evm-interfaces.org §4;
//! [`Weth`](super::weth::Weth) is a consumer of the inheritance.)
//!
//! The four entry points, which are two pairs. The EIP gives every
//! direction both an exact-input and an exact-output form, and which one a
//! caller wants is a question about which side the rounding falls on:
//!
//! | | assets fixed | shares fixed |
//! |------|--------------|--------------|
//! | in  | [`Deposit`] — spend exactly `assets`, get whatever shares | [`Mint`] — get exactly `shares`, spend whatever assets |
//! | out | [`Withdraw`] — take exactly `assets`, burn whatever shares | [`Redeem`] — burn exactly `shares`, take whatever assets |
//!
//! In each the fixed side is the first argument and the floating side is
//! the `uint256` return, which is why all four have the same outcome rule
//! (executed is succeeded — see [`Deposit`]) and why a settle circuit must
//! read the return to learn what actually moved.

use minocrab::Circuit;
use minocrab::Private;
use minocrab_std::{Check, Uint};

use super::erc20::Erc20;
use super::{always, Address, EvmCall, Extends, Interface, U128, U64};

/// AN ERC-4626 tokenized vault — the callee marker.
pub struct Erc4626;

impl Interface for Erc4626 {}

/// The shares are an ERC-20, so every ERC-20 call may be filed against a
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
/// Executed is succeeded: the number is the outcome. A deposit that minted
/// zero shares executed perfectly and achieved nothing, and a caller who
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

    fn succeeded(c: &mut Circuit, _out: &Uint<64, Private>) -> Check<Private> {
        // The constant-true assert this makes is removed by
        // `drop_true_asserts` in `Builder::finish`.
        always(c)
    }
}

/// `mint(uint256,address) -> uint256` — selector `94bf804d`,
/// `(shares, receiver)`. The attested asset count — what the mint actually
/// cost — comes back narrowed to `uint64`.
///
/// [`Deposit`] spelled the other way round: a deposit fixes the assets
/// spent and lets the shares fall out, a mint fixes the shares received and
/// lets the cost fall out. That matters to a caller with an exact share
/// target and it matters to the allowance, because the amount the vault
/// pulls is not known until it runs — an `approve` sized to a deposit's
/// assets may be short for the mint that asks for the shares that deposit
/// would have produced.
///
/// Executed is succeeded, for [`Deposit`]'s reason.
pub struct Mint;

impl EvmCall for Mint {
    type Callee = Erc4626;
    const NAME: &'static str = "mint";
    type Args = (U128, Address);
    type Return = U64;
    type Success = Uint<64, Private>;
    const GAS_LIMIT: u64 = CALL_GAS;

    fn succeeded(c: &mut Circuit, _out: &Uint<64, Private>) -> Check<Private> {
        always(c)
    }
}

/// `withdraw(uint256,address,address) -> uint256` — selector `b460af94`,
/// `(assets, receiver, owner)`. The attested share count — what the
/// withdrawal burned — comes back narrowed to `uint64`.
///
/// [`Redeem`] spelled the other way round, and the pair on the way out that
/// [`Deposit`] / [`Mint`] are on the way in: a redeem fixes the shares
/// burned, a withdraw fixes the assets taken.
///
/// `owner` is not the caller unless the caller says so. The vault burns
/// `owner`'s shares, and doing that for an `owner` other than `msg.sender`
/// needs an ERC-20 allowance on the vault itself — which is exactly why
/// `Erc4626` [`Extends`] `Erc20`, and why the approval that enables it is
/// filed against the same `Contract<Erc4626>` cell.
///
/// Executed is succeeded, for [`Deposit`]'s reason.
pub struct Withdraw;

impl EvmCall for Withdraw {
    type Callee = Erc4626;
    const NAME: &'static str = "withdraw";
    type Args = (U128, Address, Address);
    type Return = U64;
    type Success = Uint<64, Private>;
    const GAS_LIMIT: u64 = CALL_GAS;

    fn succeeded(c: &mut Circuit, _out: &Uint<64, Private>) -> Check<Private> {
        always(c)
    }
}

/// `redeem(uint256,address,address) -> uint256` — selector `ba087652`,
/// `(shares, receiver, owner)`. The attested asset count comes back
/// narrowed to `uint64` (the vault's `REDEEM_RESPOND_SCHEMA`).
///
/// Executed is succeeded, for [`Deposit`]'s reason.
pub struct Redeem;

impl EvmCall for Redeem {
    type Callee = Erc4626;
    const NAME: &'static str = "redeem";
    type Args = (U128, Address, Address);
    type Return = U64;
    type Success = Uint<64, Private>;
    const GAS_LIMIT: u64 = CALL_GAS;

    fn succeeded(c: &mut Circuit, _out: &Uint<64, Private>) -> Check<Private> {
        always(c)
    }
}
