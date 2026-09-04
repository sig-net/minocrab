//! M35 rung F — the idiot-proofing pass, made measurable.
//!
//! The MPC's own integration caller (`signet-midnight-integration`'s
//! test-caller-contract: `initialise`, `submitIsEvenRequest`, a verify
//! circuit; the shape `midnight_stream.rs` drives against a real cluster),
//! written here FROM THE PUBLIC API AND ITS DOCS ALONE — no vault code
//! consulted — with a log of every point a mistake was possible.
//!
//! THE MISTAKE LOG (what could have gone wrong, and what catches it):
//!
//! | # | the mistake                                              | caught by                                   |
//! |---|----------------------------------------------------------|---------------------------------------------|
//! | 1 | forgetting the `signet: Signet` slot in the block         | E0609: `request` needs `&Signet`, no field   |
//! | 2 | a settle circuit taking another slot's ticket             | E0308 (`Settle<Env, Resp>` phantom pairing)  |
//! | 3 | a response type that is not a Borsh record               | E0277 (`Response: CircuitBorsh`)             |
//! | 4 | two response types with one kind byte                    | E0080, prescriptive (`assert_distinct_kinds`)|
//! | 5 | capturing a private value in the environment             | E0277 (no `LedgerRepr` at `Private`)         |
//! | 6 | a `SignRequest<2>` into a `Pending<_, _, 1>` slot          | E0308 (`WORDS` on both)                      |
//! | 7 | hand-writing the notification's path bytes / depth        | impossible: derived from the slot            |
//! | 8 | hand-writing the record's kind / version / sender / chain | impossible: from the type and the context    |
//! | 9 | forgetting the freshness check, the nonce, the insert     | impossible: inside `request`                 |
//! |10 | forgetting the record's kind/version bind, the remove     | impossible: inside `settle`                  |
//! |11 | reading the response before verifying it                 | impossible: `settle` is the only constructor |
//! |12 | declaring the wrong label set on a circuit               | the generated disclosure TEST (not compile)  |
//! |13 | forgetting `assert_initialised`                          | NOT CAUGHT — a business gate, by design      |
//! |14 | forgetting to check `output.result` after settling        | NOT CAUGHT — business logic, by design       |
//! |15 | `initialise` storing a response key the MPC won't derive  | NOT CAUGHT at build; `settle` fails to prove |
//! |16 | `initialise` leaving caip2 / chain id zero                | NOT CAUGHT at build; the MPC drops the record|
//! |17 | `key_version == 0`                                        | in-circuit assert (`construct_…_event_v2`)   |
//!
//! Hand-maintained invariants left per flow: 13, 14 (the two the design
//! keeps in the circuit) and the deployment facts 15, 16. Everything the
//! §7 table listed as hand-synchronised (kind, version, path bytes, the
//! map/env/nonce triple, the verify→kind→lookup→remove order) is gone.

use minocrab::v3::Circuit3;
use minocrab::{Private, Public};
use minocrab_contracts::common::{Caip2Id, SigningPath};
use minocrab_contracts::signet::EvmCalldata;
use minocrab_contracts::signet_flow::{
    EvmTx, Pending, Requested, Response, Settle, Settled, SignRequest, Signet,
};
use minocrab_sim::v3::cost;
use minocrab_std::v3::borsh::CircuitBorsh;
use minocrab_std::v3::{
    circuit, is_true, label, Bool, Bytes, Disclose, Discloses, Ledger, LedgerCounter, LedgerRepr,
    Secp256k1Point, Uint, B32,
};

/// `SignetEvmTarget.isEven(uint256)` attested as a Borsh bool, kind 0.
#[derive(CircuitBorsh)]
struct IsEvenResponse {
    result: Bool,
}
impl Response for IsEvenResponse {
    const KIND: u8 = 0;
}

/// What the verify circuit gets back: which argument was asked about.
#[derive(LedgerRepr)]
struct IsEvenEnv {
    argument: B32<Public>,
}

#[derive(Ledger)]
struct Caller {
    initialised: LedgerCounter,
    signet: Signet,
    is_even: Pending<IsEvenEnv, IsEvenResponse, 1>,
}

const CALLER: Caller = Caller::new();

label! {
    ResponseKey = "the MPC response key";
    ChainCaip2 = "the CAIP-2 chain id";
    ChainId = "the EVM chain id";
    Argument = "the isEven argument";
    Outcome = "the attested isEven result";
}

/// `keccak256("isEven(uint256)")[..4]`.
const IS_EVEN_SELECTOR: u64 = 0x2a2e1320;

fn assert_initialised(c: &mut Circuit3) {
    let n = CALLER.initialised.read(c);
    c.assert(n.gt(0u64).message("Not initialised"));
}

/// Pin the MPC response key (derived for this contract's address) and the
/// destination chain, once.
#[circuit]
fn initialise(
    c: &mut Circuit3,
    response_key: Secp256k1Point,
    caip2: Caip2Id<Private>,
    chain_id: Uint<64>,
) -> Discloses<(ResponseKey, ChainCaip2, ChainId)> {
    let n = CALLER.initialised.read(c);
    c.assert(n.eq(0u64).message("Already initialised"));
    CALLER.initialised.increment(c, 1);
    let key = response_key.disclose_as::<ResponseKey>(c);
    let caip2 = caip2.disclose_as::<ChainCaip2>(c);
    let chain_id = chain_id.disclose_as::<ChainId>(c);
    CALLER.signet.initialize(c, &key, &caip2, &chain_id);
    Discloses::of(())
}

/// `submitIsEvenRequest(evmNonce, keyVersion, to, argWord)`: ask the MPC to
/// sign `isEven(argWord)` to `to`, under a fixed gas envelope.
#[circuit]
fn submit_is_even_request(
    c: &mut Circuit3,
    evm_nonce: Uint<64>,
    key_version: Uint<8>,
    to: Bytes<20>,
    arg_word: B32<Private>,
) -> Discloses<(Argument, Requested)> {
    assert_initialised(c);
    let zero = c.constant(0u64).private();
    let one = c.constant(1u64).private();
    let tx = EvmTx::<1> {
        nonce: evm_nonce.field(),
        max_priority_fee_per_gas: c.constant(1_000_000_000u64).private(),
        max_fee_per_gas: c.constant(30_000_000_000u64).private(),
        gas_limit: c.constant(100_000u64).private(),
        to: to.field(),
        value: zero,
        calldata_is_some: one,
        calldata: EvmCalldata {
            selector: c.constant(IS_EVEN_SELECTOR).private(),
            no_words: one,
            words: [arg_word],
        },
    };
    let argument = arg_word.disclose_as::<Argument>(c);
    let path = SigningPath(B32::pad(c, "caller-path")).private();
    CALLER.is_even.request(
        c,
        &CALLER.signet,
        SignRequest { key_version, path, tx },
        |_, _| IsEvenEnv { argument },
    );
    Discloses::of(())
}

/// `verifyResponse`: settle, and publish the attested result.
#[circuit]
fn verify_response(
    c: &mut Circuit3,
    ticket: Settle<IsEvenEnv, IsEvenResponse>,
) -> Discloses<(Settled, Outcome)> {
    assert_initialised(c);
    let outcome = CALLER.is_even.settle(c, &CALLER.signet, ticket);
    let _asked_about = outcome.env.argument;
    let result = outcome.output.result.field().disclose_as::<Outcome>(c);
    c.assert(is_true(Bool::from_field_unchecked(result)).message("isEven attested false"));
    Discloses::of(())
}

/// Seven fields, flat: the request map at field 6, depth 1 — the MPC's
/// caller kept its map at field 4 "so the tests prove the MPC locates it via
/// the field position named in the notification"; here that position is
/// derived and this test states it.
#[test]
fn the_request_map_is_where_the_notification_says() {
    assert_eq!(CALLER.is_even.record_path().as_slice(), &[6]);
    assert_eq!(CALLER.is_even.record_path().depth(), 1);
}

#[test]
fn the_three_circuits_build() {
    let (k_init, _) = cost(&initialise().ir);
    let (k_req, rows_req) = cost(&submit_is_even_request().ir);
    let (k_ver, rows_ver) = cost(&verify_response().ir);
    eprintln!("initialise k={k_init}; submit k={k_req} rows={rows_req}; verify k={k_ver} rows={rows_ver}");
    assert!(k_init <= 13 && k_req <= 14 && k_ver <= 15);
}
