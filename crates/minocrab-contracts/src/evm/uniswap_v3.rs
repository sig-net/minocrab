//! Uniswap V3's `SwapRouter` (M38 rung A, notes/evm-interfaces.org §2.4).
//!
//! NOT AN ERC-20 AND NOT EXTENDED BY ONE: the router is a peripheral
//! contract, so [`UniswapV3Router`] stands alone and a
//! [`erc20::Transfer`](super::erc20::Transfer) filed against a
//! `Contract<UniswapV3Router>` is a missing `Extends` impl — the first rung
//! of §2.5's compile_fail ladder.
//!
//! Rung A re-homes the one M37 built, `exactOutputSingle`;
//! `exactInputSingle` is the same nested-tuple signature and is rung C.

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
