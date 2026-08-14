//! `erc20-vault` (signet-midnight-examples) — THE benchmark target: the
//! shielded cross-chain ERC-20 vault. Ported circuit by circuit; each port
//! carries a differential test against compactc's artifact.
//!
//! So far: `initialize` (Setup step 4 — one-shot, deployer-gated
//! post-deploy configuration).
//!
//! Compact original (fields in declaration order):
//! ```text
//! export ledger signBidirectionalEventMap: …;           // field 0
//! sealed ledger signetSigner: SignetSigner;             // field 1
//! export ledger mpcResponseKey: Secp256k1Point;         // field 2
//! export ledger signetRequestNonce: Counter;            // field 3
//! export ledger initialized: Counter;                   // field 4
//! export ledger vaultEvmAddress: Bytes<20>;             // field 5
//! export ledger evmChainId: Uint<64>;                   // field 6
//! export ledger caip2Id: Bytes<32>;                     // field 7
//! sealed ledger deployer: Bytes<32>;                    // field 8
//! export ledger refundCommitment: Map<RequestId, Bytes<32>>; // field 9
//! export ledger uniswapRouter: Bytes<20>;               // field 10
//! export ledger swapEventMap: …;                        // field 11
//! export ledger swapRefundCommitment: Map<…>;           // field 12
//!
//! witness callerSecretKey(): Bytes<32>;
//!
//! initialize(vaultEvm: Bytes<20>, swapRouter: Bytes<20>, chainId: Uint<64>,
//!            chainCaip2Id: Bytes<32>, responseKey: Secp256k1Point):
//!     assert(initialized == 0, "Already initialized");
//!     assert(userCommitment(callerSecretKey()) == deployer, "Not the deployer");
//!     assert(chainId > 0 as Uint<64>, "Chain ID must be positive");
//!     assert(swapRouter as Field != 0 as Field, "Router cannot be zero");
//!     initialized.increment(1);
//!     vaultEvmAddress = disclose(vaultEvm);
//!     uniswapRouter = disclose(swapRouter);
//!     evmChainId = disclose(chainId);
//!     caip2Id = disclose(chainCaip2Id);
//!     mpcResponseKey = disclose(responseKey);
//! ```
//! with `userCommitment(sk) =
//! persistentHash<Vector<2, Bytes<32>>>([pad(32, "vault:user:"), sk])`.

use minocrab::v3::{Circuit3, Compiled3, FieldT, Secp256k1PointT};
use minocrab_ledger::{cell_write, counter_increment, emit, ImpactElem, LedgerValue};
use minocrab_std::v3::B32;

use crate::common;

/// Ledger field indices, in declaration order.
pub const MPC_RESPONSE_KEY: u8 = 2;
pub const INITIALIZED: u8 = 4;
pub const VAULT_EVM_ADDRESS: u8 = 5;
pub const EVM_CHAIN_ID: u8 = 6;
pub const CAIP2_ID: u8 = 7;
pub const DEPLOYER: u8 = 8;
pub const UNISWAP_ROUTER: u8 = 10;

/// The domain-separation prefix of `userCommitment`.
pub const USER_PAD: &str = "vault:user:";

pub use crate::common::secp256k1_point_atoms;

/// `export circuit initialize(vaultEvm, swapRouter, chainId, chainCaip2Id,
/// responseKey): []`
pub fn initialize() -> Compiled3 {
    let mut c = Circuit3::new();
    // Arguments in source order, FAB-flattened: Bytes<20> = 1 limb
    // (160 bits), Uint<64> = 1 limb, Bytes<32> = [hi, lo].
    let vault_evm = c.arg::<FieldT>("vaultEvm");
    let swap_router = c.arg::<FieldT>("swapRouter");
    let chain_id = c.arg::<FieldT>("chainId");
    let caip2 = B32 {
        hi: c.arg::<FieldT>("chainCaip2Id_hi"),
        lo: c.arg::<FieldT>("chainCaip2Id_lo"),
    };
    let response_key = c.arg::<Secp256k1PointT>("responseKey");
    c.assert_bits(vault_evm, 160);
    c.assert_bits(swap_router, 160);
    c.assert_bits(chain_id, 64);
    caip2.constrain_input(&mut c);

    let one = c.constant(1u64);
    let zero = c.constant(0u64);

    // assert(initialized == 0, "Already initialized")
    c.region("initialized gate", |c| {
        common::assert_counter_zero(c, one, INITIALIZED);
    });

    // assert(userCommitment(callerSecretKey()) == deployer, "Not the deployer")
    c.region("deployer gate", |c| {
        common::assert_deployer(c, one, USER_PAD, DEPLOYER);
    });

    // assert(chainId > 0, "Chain ID must be positive")
    let positive = c.less_than(zero, chain_id, 64);
    c.assert(positive);

    // assert(swapRouter as Field != 0, "Router cannot be zero")
    let router_zero = c.test_eq(swap_router, zero);
    let router_nonzero = c.not(router_zero);
    c.assert(router_nonzero);

    // initialized.increment(1)
    emit(&mut c, one, &counter_increment(INITIALIZED, 1));

    // The five configuration writes, in source order.
    c.region("configuration writes", |c| {
        let vault_evm = c.disclose(vault_evm, "the vault's derived EVM address");
        let b20 = |w| LedgerValue::bytes(20, vec![ImpactElem::Wire(w)]);
        emit(c, one, &cell_write(VAULT_EVM_ADDRESS, &b20(vault_evm)));

        let swap_router = c.disclose(swap_router, "the Uniswap router address");
        emit(c, one, &cell_write(UNISWAP_ROUTER, &b20(swap_router)));

        let chain_id = c.disclose(chain_id, "the EVM chain id");
        let chain_val = LedgerValue::bytes(8, vec![ImpactElem::Wire(chain_id)]);
        emit(c, one, &cell_write(EVM_CHAIN_ID, &chain_val));

        let caip2_hi = c.disclose(caip2.hi, "the CAIP-2 chain id (hi)");
        let caip2_lo = c.disclose(caip2.lo, "the CAIP-2 chain id (lo)");
        let caip2_val = LedgerValue::bytes(
            32,
            vec![ImpactElem::Wire(caip2_hi), ImpactElem::Wire(caip2_lo)],
        );
        emit(c, one, &cell_write(CAIP2_ID, &caip2_val));

        let pk = c.disclose(response_key, "the MPC response key");
        let limbs = c.encode(pk);
        let pk_val = LedgerValue::new(
            common::secp256k1_point_atoms(),
            limbs.iter().map(|&w| ImpactElem::Wire(w)).collect(),
        );
        emit(c, one, &cell_write(MPC_RESPONSE_KEY, &pk_val));
    });

    c.finish(true)
}
