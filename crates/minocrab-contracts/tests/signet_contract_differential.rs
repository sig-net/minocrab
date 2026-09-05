//! signet-contract (the Signet singleton) signBidirectional/respond/
//! respondBidirectional: call-compatibility with the corpus artifacts per
//! notes/ledger-abi.org §6 — three stateless emit-only circuits.

use std::borrow::Cow;

use midnight_base_crypto::fab::{
    Alignment, AlignmentAtom, AlignmentSegment, AlignedValue, Value, ValueAtom,
};
use midnight_onchain_state::state::StateValue;
use midnight_onchain_vm::ops::Op;
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_transient_crypto::hash::transient_commit;
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage};
use midnight_transient_crypto::repr::FieldRepr;
use minocrab::Fr;
use minocrab_contracts::events::{MISC_SIZE, MISC_TAG, MISC_VERSION};
use minocrab_contracts::signet_contract;
use minocrab_sim::v3::{assert_call_compatible, simulate};
use minocrab_zkir::v3::IrSource;

mod support;

type VmOp = Op<ResultModeVerify, InMemoryDB>;

fn corpus_zkir(name: &str) -> IrSource {
    let path = format!(
        "{}/../../corpus/zkir/signet-midnight-integration/packages/signet-contract/src/signet-contract/zkir/{name}.zkir",
        env!("CARGO_MANIFEST_DIR")
    );
    minocrab_zkir::v3::read_zkir(&path).expect("corpus golden parses")
}

fn bytesn_value(n: u32, bytes: &[u8]) -> AlignedValue {
    AlignedValue::new(
        Value(vec![ValueAtom(bytes.to_vec()).normalize()]),
        Alignment(vec![AlignmentSegment::Atom(AlignmentAtom::Bytes {
            length: n,
        })]),
    )
    .unwrap()
}

fn cell(av: AlignedValue) -> StateValue {
    StateValue::Cell(Sp::new(av))
}

/// A `Bytes<32>`'s two FAB slots: hi = byte 31, lo = bytes 0..31 LE.
fn b32_slots(bytes: &[u8; 32]) -> (Fr, Fr) {
    (
        Fr::from(u64::from(bytes[31])),
        Fr::from_le_bytes(&bytes[..31]).unwrap(),
    )
}

/// A `Bytes<128>`'s five FAB slots: 31-byte chunks from the front, limb 0
/// the trailing leftover.
fn b128_limbs(bytes: &[u8; 128]) -> Vec<Fr> {
    let mut chunks: Vec<&[u8]> = bytes.chunks(31).collect();
    chunks.reverse();
    chunks
        .into_iter()
        .map(|c| Fr::from_le_bytes(c).unwrap())
        .collect()
}

/// The reference Impact program: one Misc event, `Push` + `Log`.
fn log_ops(misc_bytes: &[u8]) -> Vec<VmOp> {
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

fn preimage(inputs: Vec<Fr>, misc_bytes: &[u8]) -> ProofPreimage {
    let mut transcript = Vec::new();
    for op in log_ops(misc_bytes) {
        op.field_repr(&mut transcript);
    }
    let rand = Fr::from(0x516_e37u64);
    let comm = transient_commit(&inputs[..], rand);
    ProofPreimage {
        inputs,
        private_transcript: vec![],
        public_transcript_inputs: transcript,
        public_transcript_outputs: vec![],
        binding_input: 0.into(),
        communications_commitment: Some((comm, rand)),
        key_location: KeyLocation(Cow::Borrowed("minocrab-contracts-test")),
    }
}

fn request_id() -> [u8; 32] {
    let mut rid = [0u8; 32];
    rid[..10].copy_from_slice(b"request-id");
    rid[31] = 0x9c;
    rid
}

/// `pad(32, name)` into the first 32 misc bytes.
fn misc_with_name(name: &str) -> Vec<u8> {
    let mut bytes = vec![0u8; MISC_SIZE];
    bytes[..name.len()].copy_from_slice(name.as_bytes());
    bytes
}

// ---- signBidirectional -----------------------------------------------------

struct SignScenario {
    request_id: [u8; 32],
    version: u8,
    payload: [u8; 128],
}

impl SignScenario {
    fn new() -> SignScenario {
        let mut payload = [0u8; 128];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        SignScenario {
            request_id: request_id(),
            version: 1,
            payload,
        }
    }

    /// name(32) ‖ version(1) ‖ requestId(32) ‖ payload(128) ‖ zeros(95).
    fn misc_bytes(&self) -> Vec<u8> {
        let mut bytes = misc_with_name(signet_contract::SIGN_BIDIRECTIONAL_EVENT);
        bytes[32] = self.version;
        bytes[33..65].copy_from_slice(&self.request_id);
        bytes[65..193].copy_from_slice(&self.payload);
        bytes
    }

    fn preimage(&self) -> ProofPreimage {
        let (rid_hi, rid_lo) = b32_slots(&self.request_id);
        let mut inputs = vec![rid_hi, rid_lo, Fr::from(u64::from(self.version))];
        inputs.extend(b128_limbs(&self.payload));
        preimage(inputs, &self.misc_bytes())
    }
}

#[test]
fn sign_bidirectional_matches_corpus() {
    let theirs = corpus_zkir("signBidirectional");
    let ours = signet_contract::SignetContract::sign_bidirectional().ir;
    let pi = SignScenario::new().preimage();
    support::dump_preimage("signBidirectional", &pi);
    assert_call_compatible(&ours, &theirs, &pi);
}

/// Criterion 3: a transcript whose logged payload disagrees with the
/// circuit's arguments must be rejected by BOTH artifacts.
#[test]
fn sign_bidirectional_rejects_tampered_event() {
    let theirs = corpus_zkir("signBidirectional");
    let ours = signet_contract::SignetContract::sign_bidirectional().ir;
    let s = SignScenario::new();

    let mut misc = s.misc_bytes();
    misc[40] ^= 0x01; // a requestId byte inside the logged bytes only
    let (rid_hi, rid_lo) = b32_slots(&s.request_id);
    let mut inputs = vec![rid_hi, rid_lo, Fr::from(u64::from(s.version))];
    inputs.extend(b128_limbs(&s.payload));
    let pi = preimage(inputs, &misc);

    assert!(simulate(&ours, &pi).is_err(), "ours must reject");
    assert!(simulate(&theirs, &pi).is_err(), "corpus must reject");
}

// ---- respond / respondBidirectional ----------------------------------------

struct RespondScenario {
    request_id: [u8; 32],
    big_r_x: [u8; 32],
    big_r_y: [u8; 32],
    s: [u8; 32],
    recovery_id: u8,
}

impl RespondScenario {
    fn new() -> RespondScenario {
        let fill = |seed: u8| {
            let mut b = [0u8; 32];
            for (i, byte) in b.iter_mut().enumerate() {
                *byte = seed.wrapping_add(i as u8).wrapping_mul(13);
            }
            b
        };
        RespondScenario {
            request_id: request_id(),
            big_r_x: fill(0x11),
            big_r_y: fill(0x47),
            s: fill(0xa3),
            recovery_id: 1,
        }
    }

    /// name(32) ‖ requestId(32) ‖ x(32) ‖ y(32) ‖ s(32) ‖ recoveryId(1) ‖ zeros(127).
    fn misc_bytes(&self, name: &str) -> Vec<u8> {
        let mut bytes = misc_with_name(name);
        bytes[32..64].copy_from_slice(&self.request_id);
        bytes[64..96].copy_from_slice(&self.big_r_x);
        bytes[96..128].copy_from_slice(&self.big_r_y);
        bytes[128..160].copy_from_slice(&self.s);
        bytes[160] = self.recovery_id;
        bytes
    }

    fn inputs(&self) -> Vec<Fr> {
        let mut inputs = Vec::new();
        for b32 in [&self.request_id, &self.big_r_x, &self.big_r_y, &self.s] {
            let (hi, lo) = b32_slots(b32);
            inputs.extend([hi, lo]);
        }
        inputs.push(Fr::from(u64::from(self.recovery_id)));
        inputs
    }

    fn preimage(&self, name: &str) -> ProofPreimage {
        preimage(self.inputs(), &self.misc_bytes(name))
    }
}

#[test]
fn respond_matches_corpus() {
    let theirs = corpus_zkir("respond");
    let ours = signet_contract::SignetContract::respond().ir;
    let s = RespondScenario::new();
    let pi = s.preimage(signet_contract::SIGNATURE_RESPONDED_EVENT);
    support::dump_preimage("respond", &pi);
    assert_call_compatible(&ours, &theirs, &pi);
}

#[test]
fn respond_bidirectional_matches_corpus() {
    let theirs = corpus_zkir("respondBidirectional");
    let ours = signet_contract::SignetContract::respond_bidirectional().ir;
    let s = RespondScenario::new();
    let pi = s.preimage(signet_contract::RESPOND_BIDIRECTIONAL_EVENT);
    support::dump_preimage("respondBidirectional", &pi);
    assert_call_compatible(&ours, &theirs, &pi);
}

/// The two respond circuits differ only by event name: each must reject
/// the other's transcript.
#[test]
fn respond_rejects_swapped_event_name() {
    let theirs = corpus_zkir("respond");
    let ours = signet_contract::SignetContract::respond().ir;
    let s = RespondScenario::new();
    let pi = s.preimage(signet_contract::RESPOND_BIDIRECTIONAL_EVENT);
    assert!(simulate(&ours, &pi).is_err(), "ours must reject");
    assert!(simulate(&theirs, &pi).is_err(), "corpus must reject");
}

/// Criterion 3: a tampered signature byte inside the logged payload only.
#[test]
fn respond_rejects_tampered_signature() {
    let theirs = corpus_zkir("respond");
    let ours = signet_contract::SignetContract::respond().ir;
    let s = RespondScenario::new();

    let mut misc = s.misc_bytes(signet_contract::SIGNATURE_RESPONDED_EVENT);
    misc[130] ^= 0x01; // an s byte inside the logged bytes only
    let pi = preimage(s.inputs(), &misc);

    assert!(simulate(&ours, &pi).is_err(), "ours must reject");
    assert!(simulate(&theirs, &pi).is_err(), "corpus must reject");
}
