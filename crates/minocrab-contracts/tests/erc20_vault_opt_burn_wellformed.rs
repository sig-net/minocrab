//! M10 avenue 6 (burn restructure) — the WELL-FORMEDNESS GATE.
//!
//! notes/vault-optimization.org §"Q1 burn restructure" resolves avenue 6 as
//! FEASIBLE from source, with three proven precedents in the pinned suite —
//! but with one honest gap: NO pinned test has a contract claim a shielded
//! SPEND with NO contract-owned input in the transaction, which is the exact
//! shape the optimized burn produces. This test closes that gap against the
//! PINNED ledger before any circuit changes (Task A; it MUST pass, or the
//! whole avenue is dead and withdraw/swap stay k16).
//!
//! It mirrors the structure of ledger/tests/micro-dao.rs:840-960 (the cashOut
//! "claim a user-recipient output as a contract spend" precedent), reduced to
//! the burn's exact shape: ONE contract call whose transcript declares
//! `claimed_shielded_spends = { coinCommitment(coin, shieldedBurnAddress) }`
//! and NOTHING in `claimed_shielded_receives` or `claimed_nullifiers`, plus a
//! Zswap offer that provides that output to a USER recipient
//! (`Recipient::User`, i.e. `contract_address: None`) — the shielded burn
//! address `left(default)`. The claim is checked against the pinned ledger's
//! own `Transaction::well_formed`, whose `effects_check`
//! (ledger/src/verify.rs:1517-1609) is exactly the subset rule the resolution
//! cites: a claimed shielded spend must exist in the offer and may not be
//! claimed by another contract, while the receive/nullifier equalities are
//! satisfied vacuously because the burn output is user-associated, not
//! contract-associated.
//!
//! Proof independence: the transaction is built with `ProofPreimageMarker`,
//! whose `proof_verify` is a no-op (structure.rs:546-554) and whose Zswap
//! offer `well_formed` performs only structural + Pedersen checks
//! (zswap/src/verify.rs:381-386) — so no proof server is required, and
//! `effects_check` (the property under test) runs regardless. The offer
//! carries the real user-funding input (`SenderEvidence::User`,
//! `contract_address: None`) balancing the burn output, so the transaction's
//! Pedersen value-balance holds too; only fee/limit enforcement is relaxed
//! (no fee-paying Dust is modelled here). The single most important output of
//! this test is its verdict.

use midnight_base_crypto::fab::{AlignedValue, Alignment, AlignmentAtom, AlignmentSegment, Value, ValueAtom};
use midnight_base_crypto::hash::HashOutput;
use midnight_base_crypto::time::Timestamp;
use midnight_coin_structure::coin::{Info as CoinInfo, Nonce, PublicKey as CoinPublicKey, ShieldedTokenType};
use midnight_coin_structure::contract::ContractAddress;
use midnight_coin_structure::transfer::Recipient;
use midnight_ledger::construct::{ContractCallPrototype, PreTranscript};
use midnight_ledger::structure::{
    Intent, LedgerState, Signature, Transaction, INITIAL_PARAMETERS,
};
use midnight_ledger::verify::WellFormedStrictness;
use midnight_onchain_runtime::context::QueryContext;
use midnight_onchain_state::state::{ChargedState, ContractOperation, StateValue};
use midnight_onchain_vm::ops::{Key, Op};
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::{Array, HashMap as StorageHashMap};
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage};
use midnight_zswap::keys::SecretKeys;
use midnight_zswap::local::State as ZswapLocalState;
use midnight_zswap::{Input as ZswapInput, Offer as ZswapOffer, Output as ZswapOutput};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::borrow::Cow;

type Db = InMemoryDB;

/// A `Bytes<32>` FAB cell — the shape a claimed shielded spend commitment
/// travels as in the effects transcript.
fn bytes32(bytes: &[u8; 32]) -> AlignedValue {
    AlignedValue::new(
        Value(vec![ValueAtom(bytes.to_vec()).normalize()]),
        Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 })]),
    )
    .unwrap()
}

fn field_key(i: u8) -> Key {
    Key::Value(AlignedValue::new(
        Value(vec![ValueAtom(vec![i]).normalize()]),
        Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 1 })]),
    )
    .unwrap())
}

/// The op sequence a circuit emits for `kernel.claimZswapCoinSpend(cm)`: an
/// insert into effects field 2 (`claimed_shielded_spends`). This is exactly
/// the `claim(2, cm)` sequence the vault reference model
/// (tests/vault/model.rs) emits for the burn output, so the transcript this
/// produces is byte-identical to the one the optimized burn will build.
fn claim_spend_ops(cm: &[u8; 32]) -> Vec<Op<midnight_onchain_vm::result_mode::ResultModeVerify, Db>> {
    vec![
        Op::Swap { n: 0 },
        Op::Idx {
            cached: true,
            push_path: true,
            path: vec![field_key(2)].into(),
        },
        Op::Push {
            storage: false,
            value: StateValue::Cell(Sp::new(bytes32(cm))),
        },
        Op::Push {
            storage: false,
            value: StateValue::Null,
        },
        Op::Ins { cached: true, n: 2 },
        Op::Swap { n: 0 },
    ]
}

/// A `WellFormedStrictness` that exercises the effects check (the property
/// under test) while skipping proof verification (no server), signatures and
/// value balancing (provided in production by the user's funding input).
/// `WellFormedStrictness` is `#[non_exhaustive]`, so it is built from
/// `default()` and relaxed field by field.
fn effects_only_strictness() -> WellFormedStrictness {
    let mut s = WellFormedStrictness::default();
    s.enforce_balancing = false;
    s.verify_native_proofs = false;
    s.verify_contract_proofs = false;
    s.verify_signatures = false;
    s.enforce_limits = false;
    s
}

/// A contract call that claims exactly `cm` as a shielded spend, and nothing
/// else — the optimized burn's whole ledger footprint, built for `addr`.
fn spend_claim_prototype(
    rng: &mut StdRng,
    addr: ContractAddress,
    cm_bytes: &[u8; 32],
) -> ContractCallPrototype<Db> {
    let context: QueryContext<Db> = QueryContext::new(
        ChargedState::new(StateValue::Array(Array::from(Vec::<StateValue<Db>>::new()))),
        addr,
    );
    let pre = PreTranscript {
        context,
        program: claim_spend_ops(cm_bytes),
        comm_comm: None,
    };
    let partitioned = midnight_ledger::construct::partition_transcripts(
        std::slice::from_ref(&pre),
        &INITIAL_PARAMETERS,
    )
    .expect("the burn spend-claim transcript partitions");
    let (guaranteed_public_transcript, fallible_public_transcript) =
        partitioned.into_iter().next().unwrap();
    ContractCallPrototype {
        address: addr,
        entry_point: b"burn"[..].into(),
        op: ContractOperation::new(None, None),
        guaranteed_public_transcript,
        fallible_public_transcript,
        private_transcript_outputs: vec![],
        input: ().into(),
        output: ().into(),
        communication_commitment_rand: rng.r#gen(),
        key_location: KeyLocation(Cow::Borrowed("burn")),
    }
}

/// The surrendered coin, the user's funding input and the burn output the
/// vault claims — the shared fixture of both tests.
fn burn_fixture(rng: &mut StdRng) -> (CoinInfo, ZswapInput<ProofPreimage, Db>, ZswapOutput<ProofPreimage, Db>, [u8; 32]) {
    // A vault coin the user surrenders. Colour + value are what the circuit
    // constrains; the nonce is disclosed. Concrete values are immaterial to
    // well-formedness (the check is structural), so any coin serves.
    let coin = CoinInfo {
        nonce: Nonce(HashOutput(*b"burn-coin-nonce-32-bytes-padding")),
        type_: ShieldedTokenType(HashOutput(*b"vault-token-colour-32-bytes-pad!")),
        value: 55_555,
    };
    // The user who surrenders the coin. Their funding INPUT is
    // `contract_address: None` (SenderEvidence::User) — the exact shape the
    // resolution names, and the reason the nullifier equality holds vacuously
    // (a user input contributes nothing to the contract-associated multiset).
    let keys = SecretKeys::from_rng_seed(rng);
    let local = ZswapLocalState::<Db>::new()
        .insert_coin(&keys, coin)
        .expect("seeding the user's funding coin");
    let (_local, funding_input) = local
        .spend(rng, &keys, &coin.qualify(0), None)
        .expect("building the user's funding input preimage");
    assert!(
        funding_input.contract_address.is_none(),
        "the funding input must be user-owned (contract_address: None)"
    );

    // shieldedBurnAddress() = left(default<ZswapCoinPublicKey>) — the zero
    // user key. Nobody can spend an output sent here, so the value is
    // destroyed; and because it is a USER recipient the output is not
    // contract-associated, which makes the receive/nullifier equalities hold
    // vacuously. The vault claims this output's commitment as its spend.
    let burn_recipient = Recipient::User(CoinPublicKey(HashOutput([0u8; 32])));
    let burn_output: ZswapOutput<ProofPreimage, Db> =
        ZswapOutput::new(rng, &coin, None, &CoinPublicKey(HashOutput([0u8; 32])), None)
            .expect("building the burn output preimage");
    let cm = coin.commitment(&burn_recipient);
    assert_eq!(
        burn_output.coin_com, cm,
        "the built output's commitment must be the one the claim references"
    );
    (coin, funding_input, burn_output, cm.0 .0)
}

/// THE GATE (obligations 1, 2, 4). A contract that claims exactly one
/// shielded spend of a user-recipient (`shieldedBurnAddress` = `left(default)`)
/// output, with the receive and nullifier sets empty and NO contract-owned
/// input, is well-formed against the pinned ledger. The off-chain twin emits
/// the burn Output with no `createZswapInput` preceding it (obligation 4:
/// there is no contract-owned input in the offer).
#[test]
fn a_single_user_recipient_spend_claim_with_no_contract_input_is_well_formed() {
    let mut rng = StdRng::seed_from_u64(0x6275726e); // "burn"
    let (_coin, funding_input, burn_output, cm_bytes) = burn_fixture(&mut rng);

    let addr = ContractAddress(HashOutput(*b"vault-contract-address-32-bytes!"));
    let prototype = spend_claim_prototype(&mut rng, addr, &cm_bytes);

    let ttl = Timestamp::from_secs(3600);
    let intents = StorageHashMap::<u16, Intent<Signature, _, _, Db>, Db>::new().insert(
        1,
        Intent::<Signature, _, _, Db>::new(
            &mut rng, None, None, vec![prototype], vec![], vec![], None, ttl,
        ),
    );

    // The user-funded offer: one user-owned input (contract_address: None)
    // funding one burn output, same colour and value, so it value-balances.
    // Placed in the guaranteed offer (segment 0).
    let offer = ZswapOffer {
        inputs: vec![funding_input].into(),
        outputs: vec![burn_output].into(),
        transient: vec![].into(),
        deltas: vec![].into(),
    };

    let tx: Transaction<_, _, _, Db> =
        Transaction::new("local-test", intents, Some(offer), StorageHashMap::new());

    let ledger = LedgerState::<Db>::new("local-test");
    let result = tx.well_formed(&ledger, effects_only_strictness(), Timestamp::from_secs(0));

    // The verdict. If this panics, the avenue is BLOCKED and the burn
    // restructure must not land (notes/vault-optimization.org §"Burn
    // restructure — BLOCKED").
    result.expect(
        "PINNED LEDGER REJECTED the burn shape: a single claimed shielded spend of a \
         user-recipient output with empty receive/nullifier sets and no contract-owned \
         input. Avenue 6 is BLOCKED — do NOT change the circuits; record the exact \
         rejection in notes/vault-optimization.org and keep withdraw/swap at k16.",
    );
}

/// OBLIGATION 3 (adversarial): a SECOND contract claiming the same commitment
/// in the same transaction must be rejected. The pinned ledger's
/// `effects_check` treats `claimed_shielded_spends` as a per-segment set and
/// rejects a `(segment, commitment)` claimed more than once
/// (ledger/src/verify.rs:1570-1580) — so the burn output cannot be
/// double-spent by a colluding second contract. This is what makes "unclaimed
/// by another contract" (the only thing a claimed spend needs) a real gate.
#[test]
fn a_second_contract_claiming_the_same_commitment_is_rejected() {
    let mut rng = StdRng::seed_from_u64(0x6275726e32); // "burn2"
    let (_coin, funding_input, burn_output, cm_bytes) = burn_fixture(&mut rng);

    // Two DIFFERENT contracts, each claiming the SAME burn commitment.
    let addr1 = ContractAddress(HashOutput(*b"vault-contract-one-addr-32-byte!"));
    let addr2 = ContractAddress(HashOutput(*b"vault-contract-two-addr-32-byte!"));
    let proto1 = spend_claim_prototype(&mut rng, addr1, &cm_bytes);
    let proto2 = spend_claim_prototype(&mut rng, addr2, &cm_bytes);

    let ttl = Timestamp::from_secs(3600);
    let intents = StorageHashMap::<u16, Intent<Signature, _, _, Db>, Db>::new().insert(
        1,
        Intent::<Signature, _, _, Db>::new(
            &mut rng, None, None, vec![proto1, proto2], vec![], vec![], None, ttl,
        ),
    );

    let offer = ZswapOffer {
        inputs: vec![funding_input].into(),
        outputs: vec![burn_output].into(),
        transient: vec![].into(),
        deltas: vec![].into(),
    };

    let tx: Transaction<_, _, _, Db> =
        Transaction::new("local-test", intents, Some(offer), StorageHashMap::new());

    let ledger = LedgerState::<Db>::new("local-test");
    let result = tx.well_formed(&ledger, effects_only_strictness(), Timestamp::from_secs(0));
    assert!(
        result.is_err(),
        "the pinned ledger ACCEPTED two contracts claiming the same burn commitment — \
         the burn output would be double-spent. Obligation 3 is violated; the burn \
         restructure is NOT safe as built."
    );
}
