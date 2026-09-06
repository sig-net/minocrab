//! AAVE V3'S `Pool` — the lending market's four money movements (M38 rung
//! C, notes/evm-interfaces.org §2.4).
//!
//! [`AaveV3Pool`] is the singleton every market exposes: one address per
//! chain per market, and every user-facing action goes through it.
//! [`Supply`] and [`Withdraw`] are the lender's side, [`Borrow`] and
//! [`Repay`] the borrower's, and the four together are what a signer like
//! ours does with a lending position.
//!
//! ALL FIVE ARE STATIC-WIDTH, which is why they are here at rung C/H and
//! not waiting on rung E's dynamic types. Aave's Pool takes addresses,
//! `uint256` amounts and two small integers; nothing in this surface is a
//! `bytes` or an array. (`flashLoan` is not — it takes arrays. It is not
//! here.)
//!
//! [`SupplyWithPermit`] IS FLAT, NOT A NESTED STRUCT: `IPool.sol` declares
//! it as eight plain parameters — rung C's own doc guessed at a
//! `(uint8,bytes32,bytes32)` struct here, the way Uniswap's calls nest
//! their arguments, and that guess was wrong (notes/evm-interfaces.org
//! §10, verified against `IPool.sol` on `main`).
//!
//! NOT AN ERC-20 AND NOT EXTENDED BY ONE: the Pool is a market, not a
//! token. The aTokens it mints ARE ERC-20s, but they are DIFFERENT
//! ADDRESSES — a `Contract<Erc20>` built from an aToken address, not a
//! `Contract<AaveV3Pool>` — so there is no `Extends` in either direction
//! and an [`erc20::Transfer`](super::erc20::Transfer) filed against a
//! `Contract<AaveV3Pool>` is a missing trait impl.
//!
//! THE `referralCode` IS ZERO. Every function that takes one takes a
//! `uint16`, the program it selects has been inactive since v2, and every
//! integrator passes 0. It is still an argument, still in the signature and
//! still a word on the wire, so [`U16`] exists for it — and the spelling is
//! load-bearing, because `uint16` and `uint256` are different selectors.

use minocrab::v3::Circuit3;
use minocrab::Private;
use minocrab_std::v3::{Check, Uint};

use super::erc4626;
use super::{always, Address, Bytes32, EvmCall, Interface, Unit, U128, U16, U256, U64, U8};

/// AAVE V3'S `Pool` — the callee marker.
///
/// It says what the ADDRESS CLAIMS, as every marker here does: nothing
/// checks a deployment, and the Pool's address differs per chain and per
/// market (Aave runs an Ethereum core market, an Ethereum Lido market, and
/// one per L2). Handing the wrong market's address to a
/// `Contract<AaveV3Pool>` is the callee-allow-list hazard
/// (notes/evm-calls.org §3.1), not a type error.
pub struct AaveV3Pool;

impl Interface for AaveV3Pool {}

/// The gas limit an Aave Pool call defaults to.
///
/// [`erc4626::CALL_GAS`] — the same 500,000, aliased rather than re-typed.
/// A lending-pool `supply` and an ERC-4626 vault `deposit` are the same
/// work, and the vault's own `LENDING_GAS` (which is that constant) names
/// it for a stata token that is a wrapper over exactly this pool. No second
/// magic number.
pub const CALL_GAS: u64 = erc4626::CALL_GAS;

/// `supply(address,uint256,address,uint16)` — selector `617ba037`,
/// `(asset, amount, onBehalfOf, referralCode)`, NO RETURN.
///
/// THE LENDER'S DEPOSIT: `amount` of `asset` is pulled from the caller and
/// `onBehalfOf` is credited with the aTokens. It needs an ERC-20 `approve`
/// on the ASSET first, with the Pool as the spender — filed against a
/// `Contract<Erc20>` built from the asset's address, not against this one.
///
/// NO RETURN AT ALL: Solidity's `supply` is `void`, so
/// [`Return`](EvmCall::Return) is [`Unit`] and
/// [`succeeded`](EvmCall::succeeded) is [`always`]. The aTokens minted are
/// `amount` one-for-one (an aToken's balance is rebasing, so the supply
/// itself has nothing to report), which is why there is no number to
/// attest and no flag to be fooled by.
pub struct Supply;

impl EvmCall for Supply {
    type Callee = AaveV3Pool;
    const NAME: &'static str = "supply";
    type Args = (Address, U128, Address, U16);
    type Return = Unit;
    type Success = ();
    const GAS_LIMIT: u64 = CALL_GAS;

    fn succeeded(c: &mut Circuit3, _out: &()) -> Check<Private> {
        // The constant-true assert this makes is removed by
        // `drop_true_asserts` in `Builder3::finish`.
        always(c)
    }
}

/// `supplyWithPermit(address,uint256,address,uint16,uint256,uint8,bytes32,bytes32)`
/// — `(asset, amount, onBehalfOf, referralCode, deadline, permitV, permitR,
/// permitS)`, NO RETURN. EIGHT static words, the maximum arity this
/// library's `AbiTuple` implements.
///
/// [`Supply`] AND AN ERC-2612 [`Permit`](super::erc20::Permit) IN ONE
/// TRANSACTION: the underlying's `approve` is folded into the signature
/// the depositor already produced off-chain, which is exactly the
/// position an MPC-signed caller is in — rung C's own open question 3
/// asked for this and left it out because §2.4's table did not list it
/// (notes/evm-interfaces.org §6 q3, §10).
///
/// THE SIGNATURE IS FLAT: `IPool.sol` declares eight plain parameters,
/// `permitV` / `permitR` / `permitS` among them — NOT the
/// `(uint8,bytes32,bytes32)` nested struct rung C's own doc guessed at,
/// which was the Uniswap shape read onto the wrong function (verified
/// against `aave-dao/aave-v3-origin`'s `src/contracts/interfaces/IPool.sol`
/// on `main`, 2026-09-06 — notes/evm-interfaces.org §10).
///
/// `amount` and `referralCode` are [`Supply`]'s own types — the same
/// lending amount and the same always-zero program selector. `deadline` is
/// a [`U256`], following [`erc20::Permit`](super::erc20::Permit)'s own
/// `deadline` field rather than the amount-shaped [`U128`]: both spell
/// `uint256`, and this is the same permit signature's field, not a new
/// one. `permitV` / `permitR` / `permitS` are `erc20::Permit`'s `v` / `r` /
/// `s`, unchanged.
///
/// NO RETURN AT ALL, for [`Supply`]'s reason: `supplyWithPermit` is `void`.
pub struct SupplyWithPermit;

impl EvmCall for SupplyWithPermit {
    type Callee = AaveV3Pool;
    const NAME: &'static str = "supplyWithPermit";
    type Args = (Address, U128, Address, U16, U256, U8, Bytes32, Bytes32);
    type Return = Unit;
    type Success = ();
    const GAS_LIMIT: u64 = CALL_GAS;

    fn succeeded(c: &mut Circuit3, _out: &()) -> Check<Private> {
        // The constant-true assert this makes is removed by
        // `drop_true_asserts` in `Builder3::finish`.
        always(c)
    }
}

/// `withdraw(address,uint256,address) -> uint256` — selector `69328dec`,
/// `(asset, amount, to)`. The attested return is the amount ACTUALLY
/// withdrawn, narrowed to `uint64`.
///
/// [`Supply`]'s reverse: aTokens are burned and the underlying goes to
/// `to`. The return is not decoration — a caller passes `type(uint256).max`
/// to mean "all of it" and learns what that was only from the return, and
/// even a bounded request can be capped by the market's available
/// liquidity.
///
/// EXECUTED IS SUCCEEDED: the number IS the outcome, exactly as
/// [`erc4626::Deposit`]'s is. A withdrawal that returned zero executed and
/// achieved nothing; a caller who wants that to be a failure writes its own
/// call type with `out.gt(0u64)`.
pub struct Withdraw;

impl EvmCall for Withdraw {
    type Callee = AaveV3Pool;
    const NAME: &'static str = "withdraw";
    type Args = (Address, U128, Address);
    type Return = U64;
    type Success = Uint<64, Private>;
    const GAS_LIMIT: u64 = CALL_GAS;

    fn succeeded(c: &mut Circuit3, _out: &Uint<64, Private>) -> Check<Private> {
        always(c)
    }
}

/// `borrow(address,uint256,uint256,uint16,address)` — selector `a415bcad`,
/// `(asset, amount, interestRateMode, referralCode, onBehalfOf)`, NO
/// RETURN.
///
/// The asset goes to the CALLER and the debt is recorded against
/// `onBehalfOf`, who must have delegated credit to the caller when the two
/// differ. Whether the position stays healthy is the Pool's check, and it
/// reverts — which reaches a settle circuit as the MPC's failure kind.
///
/// `interestRateMode` IS 2. Aave v3 defines 1 = stable and 2 = variable,
/// and stable-rate borrowing has been disabled market-wide since 2023, so
/// every live borrow passes 2. It is a `uint256` in the signature (a
/// [`U128`] here — the Solidity spelling is what the selector hashes, and
/// both spell `uint256`) rather than the `uint16` its two values would fit,
/// which is Aave's choice and not ours to narrow.
///
/// NO RETURN: `borrow` is `void`, so [`Return`](EvmCall::Return) is
/// [`Unit`] — the amount borrowed is the `amount` argument, exactly.
pub struct Borrow;

impl EvmCall for Borrow {
    type Callee = AaveV3Pool;
    const NAME: &'static str = "borrow";
    type Args = (Address, U128, U128, U16, Address);
    type Return = Unit;
    type Success = ();
    const GAS_LIMIT: u64 = CALL_GAS;

    fn succeeded(c: &mut Circuit3, _out: &()) -> Check<Private> {
        always(c)
    }
}

/// `repay(address,uint256,uint256,address) -> uint256` — selector
/// `573ade81`, `(asset, amount, interestRateMode, onBehalfOf)`. The
/// attested return is the amount ACTUALLY repaid, narrowed to `uint64`.
///
/// [`Borrow`]'s reverse, and it takes no `referralCode` — paying a debt
/// down refers nobody. Like [`Withdraw`] it is the call where the return
/// matters: `type(uint256).max` means "the whole debt", the debt accrues
/// interest every block, and the number that comes back is the only way to
/// know what was paid.
///
/// EXECUTED IS SUCCEEDED, for [`Withdraw`]'s reason.
pub struct Repay;

impl EvmCall for Repay {
    type Callee = AaveV3Pool;
    const NAME: &'static str = "repay";
    type Args = (Address, U128, U128, Address);
    type Return = U64;
    type Success = Uint<64, Private>;
    const GAS_LIMIT: u64 = CALL_GAS;

    fn succeeded(c: &mut Circuit3, _out: &Uint<64, Private>) -> Check<Private> {
        always(c)
    }
}
