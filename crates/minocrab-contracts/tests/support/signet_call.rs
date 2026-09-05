//! A Signet singleton call BUILT THE WAY THE LEDGER BUILDS IT (M29 rung C).
//!
//! Every proof preimage the singleton's tests use comes from here, and this
//! module never assembles one by hand. The path is the production path:
//!
//! ```text
//! Impact program  ──partition_transcripts──▶  Transcript (gas, effects, version)
//!                                                    │
//! arguments as an AlignedValue ──────────────────────┤
//!                                                    ▼
//!                                       ContractCallPrototype
//!                                                    │
//!               Intent::add_call ──▶ communication_commitment
//!                                    ContractCallExt::construct_proof
//!                                    (ledger/src/construct.rs:515-573)
//!                                                    ▼
//!                                            ProofPreimage
//! ```
//!
//! That is exactly what `sig-net/mpc`'s TypeScript sidecar does through the
//! ledger-v9 WASM bindings (`midnight-publisher-ts/src/intent.ts`), and what
//! a Rust publisher will do directly (M30). So the preimage the differential
//! hands to compactc's artifact and to ours is byte for byte the one
//! production produces — not a second, hand-rolled reading of the same rule.
//!
//! The one thing NOT taken from the ledger is the Impact program itself
//! ([`log_ops`]): in production it comes from compactc's generated JS
//! executor. `tests/signet_ledger_apply.rs` closes that gap against
//! `sig-net/mpc`'s captured on-chain transactions.

use std::borrow::Cow;

use midnight_base_crypto::fab::{
    AlignedValue, Alignment, AlignmentAtom, AlignmentSegment, Value, ValueAtom,
};
use midnight_base_crypto::time::{Duration, Timestamp};
use midnight_coin_structure::contract::ContractAddress;
use midnight_base_crypto::hash::HashOutput;
use midnight_ledger::construct::{
    communication_commitment, partition_transcripts, ContractCallPrototype, PreTranscript,
};
use midnight_ledger::semantics::{TransactionContext, TransactionResult};
use midnight_ledger::structure::{
    ContractAction, ContractDeploy, Intent, LedgerState, ProofPreimageMarker,
    ProofPreimageVersioned, Signature, Transaction, INITIAL_PARAMETERS,
};
use midnight_ledger::verify::WellFormedStrictness;
use midnight_onchain_runtime::context::{BlockContext, QueryContext};
use midnight_onchain_state::state::{ChargedState, ContractOperation, ContractState, StateValue};
use midnight_onchain_vm::ops::Op;
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::Array;
use midnight_transient_crypto::commitment::PedersenRandomness;
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage, VerifierKey};
use minocrab::Fr;
use minocrab_contracts::events::{MISC_SIZE, MISC_TAG, MISC_VERSION};
use rand::rngs::StdRng;
use rand::SeedableRng;

pub type VmOp = Op<ResultModeVerify, InMemoryDB>;
pub type PreimageIntent = Intent<Signature, ProofPreimageMarker, PedersenRandomness, InMemoryDB>;

/// The communication-commitment randomness every singleton call in the test
/// suite is built with. FIXED, not sampled: the benchmark harness reads the
/// preimages these tests dump (`support::dump_preimage`), so a preimage has
/// to be reproducible across runs.
pub const COMM_RAND: u64 = 0x516_e37;

/// The seed for the intent's binding randomness, for the same reason.
const INTENT_SEED: u64 = 0x5169_6e65_7400;

/// The address the tests deploy the singleton at. Arbitrary and fixed; the
/// real one differs per deployment and is not part of the proven statement
/// (it enters only through `binding_input`, which `construct_proof` leaves
/// at zero and proving overwrites).
pub const SINGLETON_ADDRESS_BYTES: [u8; 32] = [0x5a; 32];

pub fn singleton_address() -> ContractAddress {
    ContractAddress(HashOutput(SINGLETON_ADDRESS_BYTES))
}

// ---- FAB primitives --------------------------------------------------------

/// A `Bytes<n>` aligned value.
pub fn bytesn_value(n: u32, bytes: &[u8]) -> AlignedValue {
    AlignedValue::new(
        Value(vec![ValueAtom(bytes.to_vec()).normalize()]),
        Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes { length: n })]),
    )
    .expect("a Bytes<n> atom accepts n bytes")
}

pub fn cell(av: AlignedValue) -> StateValue<InMemoryDB> {
    StateValue::Cell(Sp::new(av))
}

/// A `Bytes<32>`'s two FAB slots: hi = byte 31, lo = bytes 0..31 LE.
pub fn b32_slots(bytes: &[u8; 32]) -> (Fr, Fr) {
    (
        Fr::from(u64::from(bytes[31])),
        Fr::from_le_bytes(&bytes[..31]).expect("31 bytes fit"),
    )
}

/// A `Bytes<128>`'s five FAB slots: 31-byte chunks from the front, limb 0
/// the trailing leftover.
pub fn b128_limbs(bytes: &[u8; 128]) -> Vec<Fr> {
    let mut chunks: Vec<&[u8]> = bytes.chunks(31).collect();
    chunks.reverse();
    chunks
        .into_iter()
        .map(|c| Fr::from_le_bytes(c).expect("31 bytes fit"))
        .collect()
}

/// A flat `[Field; n]` aligned value over `limbs`.
///
/// The ledger reads a call's `input` ONLY through
/// `AlignedValue::value_only_field_repr` — for the proof preimage's `inputs`
/// (via `ValueReprAlignedValue::field_vec`) and for the communication
/// commitment. The alignment itself never reaches the transaction. So an
/// argument list whose typed alignment is `[Bytes<32>, Bytes<1>, …]` and
/// this flat one produce the SAME preimage; `tests/signet_construction.rs`
/// asserts that byte for byte rather than leaving it asserted here in prose.
pub fn scalar_input(limbs: &[Fr]) -> AlignedValue {
    AlignedValue::new(
        Value(limbs.iter().map(|f| ValueAtom(f.as_le_bytes().to_vec()).normalize()).collect()),
        Alignment(limbs.iter().map(|_| AlignmentSegment::Atom(AlignmentAtom::Field)).collect()),
    )
    .expect("a Field atom accepts a field element's LE bytes")
}

// ---- the call --------------------------------------------------------------

/// The singleton's Impact program: one Misc event, `Push` + `Log`.
///
/// In production compactc's generated JS executor emits these two ops; here
/// they are written out. `tests/signet_ledger_apply.rs` checks them against
/// the ops in `sig-net/mpc`'s captured on-chain respond transactions.
pub fn log_ops(misc_bytes: &[u8]) -> Vec<VmOp> {
    vec![
        Op::Push {
            storage: false,
            value: StateValue::Array(
                vec![
                    cell(bytesn_value(4, &MISC_VERSION.to_le_bytes())),
                    cell(bytesn_value(1, &[MISC_TAG])),
                    cell(bytesn_value(MISC_SIZE as u32, misc_bytes)),
                ]
                .into(),
            ),
        },
        Op::Log,
    ]
}

/// The singleton's state as the tests deploy it: no ledger fields (the three
/// signer circuits are stateless), one operation per circuit.
pub fn empty_state() -> ChargedState<InMemoryDB> {
    ChargedState::new(StateValue::Array(Array::new()))
}

/// `ContractOperation` for a circuit under a verifier key (`None` where the
/// gate does not verify proofs).
pub fn operation(vk: Option<VerifierKey>) -> ContractOperation {
    ContractOperation::new(vk, None)
}

/// One singleton call, as a [`ContractCallPrototype`]: the ledger runs the
/// program to build the transcript ([`partition_transcripts`], which is what
/// decides the guaranteed/fallible split, the gas heuristic and the
/// transcript version), and the prototype carries the arguments beside it.
pub fn call_prototype(
    entry_point: &str,
    address: ContractAddress,
    input: AlignedValue,
    misc_bytes: &[u8],
) -> ContractCallPrototype<InMemoryDB> {
    let rand = Fr::from(COMM_RAND);
    let output: AlignedValue = ().into();
    let comm = communication_commitment(input.clone(), output.clone(), rand);
    let transcripts = partition_transcripts(
        &[PreTranscript {
            context: QueryContext::new(empty_state(), address),
            program: log_ops(misc_bytes),
            comm_comm: Some(comm),
        }],
        &INITIAL_PARAMETERS,
    )
    .expect("the singleton's Push+Log program partitions");
    ContractCallPrototype {
        address,
        entry_point: entry_point.as_bytes().into(),
        op: operation(None),
        guaranteed_public_transcript: transcripts[0].0.clone(),
        fallible_public_transcript: transcripts[0].1.clone(),
        private_transcript_outputs: vec![],
        input,
        output,
        communication_commitment_rand: rand,
        key_location: KeyLocation(Cow::Owned(entry_point.to_string())),
    }
}

/// The prototypes as one [`Intent`] — `Intent::new` folds each through
/// `add_call::<ProofPreimage>`, which computes the communication commitment
/// and calls `ContractCallExt::construct_proof`.
pub fn call_intent(protos: Vec<ContractCallPrototype<InMemoryDB>>, ttl: Timestamp) -> PreimageIntent {
    let mut rng = StdRng::seed_from_u64(INTENT_SEED);
    Intent::new(&mut rng, None, None, protos, vec![], vec![], None, ttl)
}

/// The default TTL the tests build intents with: an hour past the block time
/// they apply at, the same margin `midnight_ledger::test_utilities`'
/// `test_intents` uses.
pub fn ttl(tblock: Timestamp) -> Timestamp {
    tblock + Duration::from_secs(3600)
}

/// Every `ContractCall` in an intent, in order.
pub fn calls_of(
    intent: &PreimageIntent,
) -> Vec<midnight_ledger::structure::ContractCall<ProofPreimageMarker, InMemoryDB>> {
    intent
        .actions
        .iter_deref()
        .filter_map(|action| match action {
            ContractAction::Call(call) => Some((**call).clone()),
            _ => None,
        })
        .collect()
}

/// THE construction gate's subject: the ledger's own `ProofPreimage` for one
/// singleton call.
///
/// Built by putting the prototype through `Intent::new` and reading the
/// preimage back out of the resulting `ContractCall`, so the bytes under
/// test are the ones a real intent carries — not a reconstruction of what
/// `construct_proof` would have said.
pub fn call_preimage(entry_point: &str, input: AlignedValue, misc_bytes: &[u8]) -> ProofPreimage {
    let proto = call_prototype(entry_point, singleton_address(), input, misc_bytes);
    let intent = call_intent(vec![proto], ttl(Timestamp::from_secs(0)));
    let calls = calls_of(&intent);
    assert_eq!(calls.len(), 1, "one prototype makes one call");
    match &calls[0].proof {
        ProofPreimageVersioned::V2(pi) => (**pi).clone(),
        // `#[non_exhaustive]` upstream: a variant added by a ledger bump is a
        // preimage shape this suite has never seen, and the honest answer is
        // to stop rather than to guess at it (notes/version-bump.org).
        other => panic!("unknown ProofPreimageVersioned variant: {other:?}"),
    }
}


// ---- deploying the singleton and applying a call ---------------------------

/// One of the COMMITTED managed verifier keys (M29 rung A:
/// `crates/signet-artifacts/managed/keys/<circuit>.verifier`, written by the
/// pinned `zkir-v3`'s keygen and gated byte-for-byte by `signet-artifacts`'
/// `generated_equals_committed`).
///
/// Read by path rather than through the `signet-artifacts` crate: that crate
/// depends on `minocrab-contracts`, so depending back on it — even as a
/// dev-dependency — would make the graph harder to read than a path join
/// deserves.
pub fn managed_verifier_key(circuit: &str) -> VerifierKey {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../signet-artifacts/managed/keys")
        .join(format!("{circuit}.verifier"));
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    midnight_serialize::tagged_deserialize(&mut &bytes[..])
        .unwrap_or_else(|e| panic!("{} is a tagged VerifierKey: {e}", path.display()))
}

/// The three signer circuits' COMPACT names — what the sidecar's
/// `expectedVk` table and `RESPOND_CIRCUITS` key by, what the managed
/// directory names its files, and what the captured on-chain transactions
/// carry as entry points.
pub const SIGNER_CIRCUITS: [&str; 3] = ["signBidirectional", "respond", "respondBidirectional"];

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

/// Balancing and limits OFF: there is no DUST wallet anywhere in this
/// workspace (notes/mpc-publisher.org §2 names that as the gap M30 C
/// closes), and none of these transactions carries a zswap offer.
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

/// One intent, at segment 1, as a proof-preimage transaction on
/// `local-test`.
pub fn preimage_tx(
    intent: PreimageIntent,
) -> Transaction<Signature, ProofPreimageMarker, PedersenRandomness, InMemoryDB> {
    Transaction::from_intents(
        "local-test",
        midnight_storage::storage::HashMap::new().insert(1, intent),
    )
}

/// `ContractDeploy` the singleton into a fresh `LedgerState`, `well_formed`
/// it and `apply` it — the state a respond call is then made against.
pub fn deploy_singleton(
    state: ContractState<InMemoryDB>,
    tblock: Timestamp,
) -> (LedgerState<InMemoryDB>, ContractAddress) {
    let ledger: LedgerState<InMemoryDB> = LedgerState::new("local-test");
    let mut rng = StdRng::seed_from_u64(0x5369_676e_6574);
    let deploy = ContractDeploy::new(&mut rng, state);
    let address = deploy.address();
    let tx = preimage_tx(call_intent(vec![], ttl(tblock)).add_deploy(deploy));
    let vtx = tx
        .well_formed(&ledger, unbalanced_strictness(), tblock)
        .expect("the singleton deploy is well formed");
    let (after, result) = ledger.apply(&vtx, &tx_context(&ledger, tblock));
    assert!(
        matches!(result, TransactionResult::Success(_)),
        "the singleton deploy must apply: {result:?}"
    );
    assert!(after.index(address).is_some(), "the singleton is in the state after the deploy");
    (after, address)
}

/// The 288-byte Misc envelope of a respond-shaped event:
/// `pad(32, name)` ‖ requestId(32) ‖ x(32) ‖ y(32) ‖ s(32) ‖ recoveryId(1)
/// ‖ zeros(127).
pub fn respond_misc(
    name: &str,
    request_id: &[u8; 32],
    big_r_x: &[u8; 32],
    big_r_y: &[u8; 32],
    s: &[u8; 32],
    recovery_id: u8,
) -> Vec<u8> {
    let mut bytes = vec![0u8; MISC_SIZE];
    bytes[..name.len()].copy_from_slice(name.as_bytes());
    bytes[32..64].copy_from_slice(request_id);
    bytes[64..96].copy_from_slice(big_r_x);
    bytes[96..128].copy_from_slice(big_r_y);
    bytes[128..160].copy_from_slice(s);
    bytes[160] = recovery_id;
    bytes
}

/// A respond call's arguments with their COMPACT alignment: four
/// `Bytes<32>` then a one-byte `Uint<8>`.
pub fn respond_input(
    request_id: &[u8; 32],
    big_r_x: &[u8; 32],
    big_r_y: &[u8; 32],
    s: &[u8; 32],
    recovery_id: u8,
) -> AlignedValue {
    AlignedValue::concat([
        &bytesn_value(32, request_id),
        &bytesn_value(32, big_r_x),
        &bytesn_value(32, big_r_y),
        &bytesn_value(32, s),
        &bytesn_value(1, &[recovery_id]),
    ])
}
