//! ERC-4626 — the tokenized-vault interface (M38 rung A,
//! notes/evm-interfaces.org §2.4).
//!
//! AN ERC-4626 VAULT IS AN ERC-20: its shares are a token, so
//! `impl Extends<Erc20> for Erc4626` and a `Contract<Erc4626>` takes an
//! [`erc20::Approve`](super::erc20::Approve) as well as the calls here.
//! That is the deployed vault's `approveStata`, which approves an ERC-20
//! allowance ON the ERC-4626 stata token, and it is the one place rung A's
//! inheritance is load-bearing rather than decorative.
//!
//! Rung A re-homes the two M37 built — `deposit` and `redeem`. `mint` and
//! `withdraw` are rung C.

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
