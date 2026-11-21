# minocrab-signet

**Sig Network's Signet protocol for [MinoCrab](https://github.com/sig-net/minocrab) circuits.** A Midnight contract asks the Sig Network MPC to sign and execute an EVM transaction in two transactions: a request circuit files a signing record and notifies the signet signer, and a settle circuit later verifies the MPC's attestation and consumes the record. The ledger slot that does this is typed by the call (`Pending<Filing, Env, WORDS>`), so the selector, the ABI words, the attested width, the schema, the gas envelope and the signing path all follow from the call type. The typed calls themselves are in `minocrab-evm`.

It implements the V1 wire vocabulary of the `@sig-net/midnight` Signet module at 0.26.0-rc.15 (`aa91570`), the version erc20-vault v0.7.0-rc.2 pins: the V1 request record with its 64-byte `executionDest`, the domain-tagged Poseidon hashes, and the attestation that commits to the block height, the MPC's verdict and the output's width and hash. A request notifies the signet signer (`signet-signer-interface`); the MPC posts its attestation to the signet responder (`signet-responder-interface`), whose event a settle circuit takes as its ticket.

```rust
use minocrab::v3::Circuit3;
use minocrab::{Private, Public};
use minocrab_evm::erc20;
use minocrab_signet::filing::Filed;
use minocrab_signet::signet_v1::schema;
use minocrab_signet::evm_flow::{Contract, Pending};
use minocrab_signet::signet_flow::Signet;
use minocrab_std::v3::{Bytes, Ledger, LedgerRepr, Uint};

#[derive(LedgerRepr)] struct Amount { amount: Uint<64, Public> }

#[derive(Ledger)]
struct Block {
    signet: Signet,
    transfers: Pending<Filed<erc20::Transfer, schema::Success>, Amount, 2>,
}
const BLOCK: Block = Block::new();

fn send(
    c: &mut Circuit3,
    callee: Contract<erc20::Erc20>,
    to: Bytes<20, Private>,
    amount: Uint<128, Private>,
    nonce: Uint<64>,
    env: Amount,
) {
    BLOCK.transfers.request(c, callee, (to, amount), nonce, |_, _| env);
}
```
