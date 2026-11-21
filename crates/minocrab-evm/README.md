# minocrab-evm

**Typed EVM calls for [MinoCrab](https://github.com/sig-net/minocrab) circuits.** A Solidity function call is a Rust type: its name, its argument tuple, its return, the interface that exposes it, its gas limit and the rule by which its return says it worked. The four-byte selector is `keccak256` of the signature, computed in Rust when the circuit is built and embedded as an immediate; the argument words are encoded in-circuit by one encoder per Solidity leaf type. Arguments in the wrong order, a `Unit` used as an argument, and a call with no success rule are compile errors.

The library's calls live one module per interface: `erc20`, `erc4626`, `erc721`, `uniswap_v3`, `aave_v3`, `weth` and `usdt`. Nothing here knows about Signet; how a deployment files a call, and the ledger slot that tracks it, are in `minocrab-signet`.

```rust
use minocrab::Circuit;
use minocrab::Private;
use minocrab_evm::{always, erc20, Address, EvmCall, U64};
use minocrab_std::{Check, Uint};

struct Balance;
impl EvmCall for Balance {
    type Callee = erc20::Erc20;
    const NAME: &'static str = "balanceOf";
    type Args = (Address,);
    type Return = U64;
    type Success = Uint<64, Private>;
    const GAS_LIMIT: u64 = 50_000;
    fn succeeded(c: &mut Circuit, _out: &Uint<64, Private>) -> Check<Private> {
        always(c)
    }
}
assert_eq!(Balance::signature(), "balanceOf(address)");
assert_eq!(Balance::selector(), [0x70, 0xa0, 0x82, 0x31]);
```
