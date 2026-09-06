//! Uniswap V3's `SwapRouter02` (M38 rungs A and C,
//! notes/evm-interfaces.org §2.4).
//!
//! [`UniswapV3Router`] IS `SwapRouter02` — THE SECOND GENERATION, and the
//! marker's name is the only thing about it that is generic. There are two
//! deployed routers and they are not interchangeable:
//!
//! - the ORIGINAL `SwapRouter` takes a `deadline` field inside the
//!   parameter struct, so its `exactInputSingle` is the eight-field
//!   `414bf389` and its `exactOutputSingle` the eight-field `db3e2198`;
//! - `SwapRouter02` DROPPED the deadline (a caller who wants one uses the
//!   router's `multicall` deadline overload), so its structs have seven
//!   fields and its selectors are `04e45aaf` and `5023b4df`.
//!
//! WE SHIP THE SwapRouter02 SHAPE. The vault's deployed `exactOutputSingle`
//! is `5023b4df` and the seven words it fills are the seven fields here, so
//! the eight-field forms are not merely unimplemented — filing one of our
//! calls against an original-`SwapRouter` address would send seven words to
//! a function that wants eight. That is a wire-level mistake no type here
//! catches (both routers are addresses claiming this interface), which is
//! why `evm_alloy_oracle::the_router_shape_is_the_one_we_declare` pins the
//! FIELD LIST against alloy's rendering of both generations.
//!
//! NOT AN ERC-20 AND NOT EXTENDED BY ONE: the router is a peripheral
//! contract, so [`UniswapV3Router`] stands alone and a
//! [`erc20::Transfer`](super::erc20::Transfer) filed against a
//! `Contract<UniswapV3Router>` is a missing `Extends` impl — the first rung
//! of §2.5's compile_fail ladder. (A swap still needs an ERC-20 `approve`,
//! but it is filed against the TOKEN with the router as the spender, not
//! against the router.)

use minocrab::v3::Circuit3;
use minocrab::Private;
use minocrab_std::v3::{Check, Uint};

use super::{always, AbiTuple, Address, EvmCall, Interface, U128, U160, U24, U64};

/// UNISWAP V3'S SWAP ROUTER — the callee marker.
pub struct UniswapV3Router;

impl Interface for UniswapV3Router {}

/// The gas limit a router swap defaults to — the deployed vault's own
/// `SWAP_GAS`, defined here and aliased there
/// (notes/evm-interfaces.org §2.3).
pub const SWAP_GAS: u64 = 700_000;

/// `exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))`
/// — selector `04e45aaf`, seven words: `(tokenIn, tokenOut, fee, recipient,
/// amountIn, amountOutMinimum, sqrtPriceLimitX96)`.
///
/// SPEND EXACTLY `amountIn` AND TAKE WHAT COMES BACK, with
/// `amountOutMinimum` as the slippage floor — the mirror of
/// [`ExactOutputSingle`], which fixes the output and caps the input. That
/// is the direction a caller wants when it is emptying a position rather
/// than filling an order: the amount it holds is exact and the proceeds are
/// whatever the pool gives.
///
/// SEVEN FIELDS, NO DEADLINE — this is `SwapRouter02`'s struct (the module
/// docs say why the eight-field `414bf389` is a different function). The
/// argument tuple is IDENTICAL to [`ExactOutputSingle`]'s; only the two
/// amount fields swap meaning, which is precisely why the two are distinct
/// TYPES rather than one call with a flag.
///
/// The `signature()` override is [`ExactOutputSingle`]'s, for the same
/// reason: the arguments are a Solidity struct, which the ABI renders as a
/// nested tuple.
///
/// EXECUTED IS SUCCEEDED: the attested `amountOut` IS the outcome. A swap
/// that returned less than the caller hoped still cleared
/// `amountOutMinimum`, because the ROUTER reverts when it does not — the
/// slippage check is the callee's, and it reaches us as the MPC's failure
/// kind.
pub struct ExactInputSingle;

impl EvmCall for ExactInputSingle {
    type Callee = UniswapV3Router;
    const NAME: &'static str = "exactInputSingle";
    type Args = (Address, Address, U24, Address, U128, U128, U160);
    type Return = U64;
    type Success = Uint<64, Private>;
    const GAS_LIMIT: u64 = SWAP_GAS;

    fn succeeded(c: &mut Circuit3, _out: &Uint<64, Private>) -> Check<Private> {
        // The constant-true assert this makes is removed by
        // `drop_true_asserts` in `Builder3::finish`.
        always(c)
    }

    fn signature() -> String {
        format!("{}(({}))", Self::NAME, <Self::Args as AbiTuple>::signature())
    }
}

/// `exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))`
/// — selector `5023b4df`, seven words: `(tokenIn, tokenOut, fee, recipient,
/// amountOut, amountInMaximum, sqrtPriceLimitX96)`.
///
/// The arguments are a Solidity STRUCT, which the ABI renders as a nested
/// tuple, so this is the one call that overrides
/// [`super::EvmCall::signature`] to wrap the joined
/// list in a second pair of parentheses. The word ENCODING is unaffected —
/// a static struct is its fields' words, in order, exactly as a flat
/// argument list would be.
///
/// EXECUTED IS SUCCEEDED: the attested `amountIn` IS the outcome.
pub struct ExactOutputSingle;

impl EvmCall for ExactOutputSingle {
    type Callee = UniswapV3Router;
    const NAME: &'static str = "exactOutputSingle";
    type Args = (Address, Address, U24, Address, U128, U128, U160);
    type Return = U64;
    type Success = Uint<64, Private>;
    const GAS_LIMIT: u64 = SWAP_GAS;

    fn succeeded(c: &mut Circuit3, _out: &Uint<64, Private>) -> Check<Private> {
        // The constant-true assert this makes is removed by
        // `drop_true_asserts` in `Builder3::finish`.
        always(c)
    }

    fn signature() -> String {
        format!("{}(({}))", Self::NAME, <Self::Args as AbiTuple>::signature())
    }
}
