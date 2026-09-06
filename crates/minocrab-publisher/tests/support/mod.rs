//! Shared test support: the deployment side of a publish, and the decoder for
//! `sig-net/mpc`'s captured transactions.
//!
//! Compiled into every test binary that declares `mod support`, each using
//! only the part it needs — hence the blanket allowances.
#![allow(dead_code, unused_imports)]

use midnight_base_crypto::time::{Duration, Timestamp};
use midnight_coin_structure::contract::ContractAddress;
use midnight_ledger::semantics::{TransactionContext, TransactionResult};
use midnight_ledger::structure::{
    ContractDeploy, LedgerParameters, LedgerState, ProofKind, ProofMarker, Signature, Transaction,
    INITIAL_PARAMETERS,
};
use midnight_ledger::verify::WellFormedStrictness;
use midnight_onchain_runtime::context::{BlockContext, QueryContext};
use midnight_onchain_runtime::cost_model::INITIAL_COST_MODEL;
use midnight_onchain_state::state::{ContractState, StateValue};
use midnight_onchain_vm::ops::{LogEventType, Op, VersionedLogItem};
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::Array;
use midnight_transient_crypto::proofs::VerifierKey;
use minocrab_contracts::events::{MISC_SIZE, MISC_VERSION};
use minocrab_publisher::call::{empty_state, operation, SIGNER_CIRCUITS};
use minocrab_publisher::fab::bytesn_value;
use minocrab_publisher::intent::{build_intent, preimage_tx};
use minocrab_publisher::publish::ChainContext;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};

/// The network these gates deploy and publish on.
pub const NETWORK_ID: &str = "local-test";
/// The segment the publisher's intent sits in (never 0).
pub const SEGMENT: u16 = 1;
/// The communication-commitment randomness the gates use. Fixed so a rerun
/// produces the same preimage; a publisher samples it per call, which is why
/// it is an argument to the library.
pub const COMM_RAND: u64 = 0x516_e37;

pub fn ttl(tblock: Timestamp) -> Timestamp {
    tblock + Duration::from_secs(3600)
}

/// The chain's side of a publish, as these gates supply it.
///
/// `INITIAL_PARAMETERS` is spelled out HERE rather than in the library: the
/// library takes the chain's parameters as an argument (M30 A), and a test
/// with no chain has to choose something.
pub fn chain_context(tblock: Timestamp) -> ChainContext<InMemoryDB> {
    ChainContext {
        contract_state: empty_state(),
        parameters: INITIAL_PARAMETERS,
        cost_model: INITIAL_COST_MODEL,
        network_id: NETWORK_ID.to_string(),
        segment: SEGMENT,
        tblock,
    }
}

/// The singleton as this repo would deploy it: NO ledger fields (all three
/// signer circuits are stateless), one operation per circuit under whatever
/// verifier key `key` supplies.
pub fn singleton_contract_state(
    key: impl Fn(&str) -> Option<VerifierKey>,
) -> ContractState<InMemoryDB> {
    let mut operations = midnight_storage::storage::HashMap::new();
    for circuit in SIGNER_CIRCUITS {
        operations = operations.insert(circuit.as_bytes().into(), operation(key(circuit)));
    }
    ContractState::new(StateValue::Array(Array::new()), operations, Default::default())
}

/// Balancing and limits OFF: nothing here pays a DUST fee, because no DUST
/// wallet exists yet (M30 rung C — `minocrab_publisher::dust`).
pub fn unbalanced_strictness() -> WellFormedStrictness {
    let mut s = WellFormedStrictness::default();
    s.enforce_balancing = false;
    s.enforce_limits = false;
    s
}

pub fn tx_context(
    ledger: &LedgerState<InMemoryDB>,
    tblock: Timestamp,
) -> TransactionContext<InMemoryDB> {
    TransactionContext {
        ref_state: ledger.clone(),
        block_context: BlockContext { tblock, ..BlockContext::default() },
        whitelist: None,
    }
}

/// `ContractDeploy` the singleton into a fresh `LedgerState`, `well_formed`
/// it and `apply` it — the state a respond call is then published against.
///
/// The deploy itself is built with the publisher's own intent helpers, so the
/// only thing test-only about it is the fixed rng seed.
pub fn deploy_singleton(
    state: ContractState<InMemoryDB>,
    tblock: Timestamp,
) -> (LedgerState<InMemoryDB>, ContractAddress) {
    let ledger: LedgerState<InMemoryDB> = LedgerState::new(NETWORK_ID);
    let mut rng = StdRng::seed_from_u64(0x5369_676e_6574);
    let deploy = ContractDeploy::new(&mut rng, state);
    let address = deploy.address();
    let intent = build_intent(&mut rng, vec![], ttl(tblock)).add_deploy(deploy);
    let tx = preimage_tx(NETWORK_ID, SEGMENT, intent);
    let vtx = tx
        .well_formed(&ledger, unbalanced_strictness(), tblock)
        .expect("the singleton deploy is well formed");
    let (after, result) = ledger.apply(&vtx, &tx_context(&ledger, tblock));
    assert!(
        matches!(result, TransactionResult::Success(_)),
        "the singleton deploy must apply: {result:?}"
    );
    (after, address)
}

// ---- the captured transactions (M29 D's fixtures) --------------------------

/// A proven transaction as finalized blocks carry it.
pub type ProvenGolden =
    Transaction<Signature, ProofMarker, <ProofMarker as ProofKind<InMemoryDB>>::Pedersen, InMemoryDB>;

/// One decoded singleton emission: the 288-byte Misc split
/// `name(32) ‖ payload(256)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Emission {
    pub name: [u8; 32],
    pub payload: [u8; 256],
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A TRIMMED copy of M29 D's translation of mpc's `emission_from_log_item`
/// (`chain-midnight/src/emissions.rs:96-148`). `minocrab-contracts`'
/// `tests/signet_ledger_apply.rs` carries the full one, with every `ensure!`
/// asserted; here the decoder exists only to SOURCE real values — a real
/// request id and a real signature, off a real chain — for the publisher to
/// rebuild a call from.
pub fn emission_of(item: &VersionedLogItem<InMemoryDB>, who: &str) -> Emission {
    assert_eq!(item.version, MISC_VERSION, "{who}: log item version");
    assert_eq!(item.event_type, LogEventType::Misc, "{who}: log item type");
    let StateValue::Cell(cell) = &item.data else {
        panic!("{who}: Misc data is not a cell");
    };
    assert_eq!(
        cell.alignment,
        bytesn_value(MISC_SIZE as u32, &[0u8]).alignment,
        "{who}: Misc data is not one Bytes<{MISC_SIZE}> atom"
    );
    let stored = &cell.value.0[0].0;
    let mut bytes = [0u8; MISC_SIZE];
    bytes[..stored.len()].copy_from_slice(stored);
    let mut name = [0u8; 32];
    name.copy_from_slice(&bytes[..32]);
    let mut payload = [0u8; 256];
    payload.copy_from_slice(&bytes[32..]);
    Emission { name, payload }
}

/// Decode one of M29 D's fixtures and return the singleton call's emission.
///
/// The SHA-256 assertion is both the integrity check and the provenance pin:
/// each fixture's hash IS the ledger transaction hash the capture recorded
/// (`minocrab-contracts/tests/fixtures/mpc/README.md`).
pub fn golden_emission(bytes: &[u8], expected_sha256: &str, who: &str) -> Emission {
    assert_eq!(
        hex(&Sha256::digest(bytes)),
        expected_sha256,
        "{who}: imported fixture bytes differ from the recorded capture"
    );
    let tx: ProvenGolden = midnight_serialize::tagged_deserialize(&mut &bytes[..])
        .unwrap_or_else(|e| panic!("{who}: the captured transaction must decode: {e}"));
    let mut found: Option<Emission> = None;
    for (_, call) in tx.calls() {
        let Some(transcript) = call.guaranteed_transcript.as_deref() else {
            continue;
        };
        let program: Vec<Op<ResultModeVerify, InMemoryDB>> = Vec::from(&transcript.program);
        let results = QueryContext::new(empty_state(), call.address)
            .query::<ResultModeVerify>(&program, None, &INITIAL_COST_MODEL)
            .unwrap_or_else(|e| panic!("{who}: the ledger VM rejected the transcript: {e}"));
        if results.events.len() != 1 {
            continue;
        }
        assert!(found.is_none(), "{who}: more than one logging call");
        found = Some(emission_of(&results.events[0], who));
    }
    found.unwrap_or_else(|| panic!("{who}: no singleton call in the captured transaction"))
}

/// The signature and request id a captured respond event carries, at the
/// offsets the singleton's layout declares: requestId(32) ‖ x(32) ‖ y(32) ‖
/// s(32) ‖ recoveryId(1) ‖ zeros(127).
pub fn signature_of(emission: &Emission) -> ([u8; 32], minocrab_publisher::EcdsaSignature) {
    let at = |from: usize| -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&emission.payload[from..from + 32]);
        out
    };
    (
        at(0),
        minocrab_publisher::EcdsaSignature {
            big_r_x: at(32),
            big_r_y: at(64),
            s: at(96),
            recovery_id: emission.payload[128],
        },
    )
}
