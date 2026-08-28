//! test-caller-contract `initialise`: call-compatibility with the corpus
//! artifact per notes/ledger-abi.org §6 — the first differential over
//! ledger READS (Counter.read + Cell.read), plus acceptance agreement on
//! the guard failures (already initialised, wrong deployer secret).

use std::borrow::Cow;

use midnight_base_crypto::fab::{
    Alignment, AlignmentAtom, AlignmentSegment, AlignedValue, Value, ValueAtom,
};
use midnight_curves::k256;
use midnight_onchain_state::state::StateValue;
use midnight_onchain_vm::ops::{Key, Op};
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_transient_crypto::fab::{AlignmentExt, ValueReprAlignedValue};
use midnight_transient_crypto::hash::transient_commit;
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage};
use midnight_base_crypto::repr::BinaryHashRepr;
use midnight_transient_crypto::repr::FieldRepr;
use midnight_zkir_v3::ir_instructions::ec_mul::ec_mul_offcircuit;
use midnight_zkir_v3::ir_instructions::encode::encode_offcircuit;
use midnight_zkir_v3::ir_instructions::from_bytes32::from_bytes32_offcircuit;
use minocrab::Fr;
use minocrab_contracts::test_caller;
use minocrab_sim::v3::{assert_call_compatible, simulate};
use minocrab_zkir::v3::{IrSource, IrType, IrValue};
use sha2::{Digest, Sha256};

type VmOp = Op<ResultModeVerify, InMemoryDB>;

fn corpus_zkir() -> IrSource {
    let path = format!(
        "{}/../../corpus/zkir/signet-midnight-integration/packages/test-caller-contract/src/test-caller-contract/zkir/initialise.zkir",
        env!("CARGO_MANIFEST_DIR")
    );
    minocrab_zkir::v3::read_zkir(&path).expect("corpus golden parses")
}

fn atom(n: u32) -> AlignmentSegment {
    AlignmentSegment::Atom(AlignmentAtom::Bytes { length: n })
}

fn bytesn_value(n: u32, bytes: &[u8]) -> AlignedValue {
    AlignedValue::new(
        Value(vec![ValueAtom(bytes.to_vec()).normalize()]),
        Alignment(vec![atom(n)]),
    )
    .unwrap()
}

fn cell(av: AlignedValue) -> StateValue {
    StateValue::Cell(Sp::new(av))
}

/// [hi, lo] Fr slot pair of a Bytes<32>.
fn b32_slots(bytes: &[u8; 32]) -> (Fr, Fr) {
    (
        Fr::from(u64::from(bytes[31])),
        Fr::from_le_bytes(&bytes[..31]).unwrap(),
    )
}

/// `pad(32, s)`: string at the front, zero-filled.
fn pad32(s: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..s.len()].copy_from_slice(s.as_bytes());
    bytes
}

/// Off-circuit `deployerCommitment(sk)`: SHA-256 over the FAB bytes of
/// `[pad(32, DEPLOYER_PAD), sk]` — the same construction the in-circuit
/// `persistent_hash` performs (zkir-v3 ir_vm.rs:478-505).
fn deployer_commitment(sk: &[u8; 32]) -> [u8; 32] {
    let (pad_hi, pad_lo) = b32_slots(&pad32(test_caller::DEPLOYER_PAD));
    let (sk_hi, sk_lo) = b32_slots(sk);
    let alignment = Alignment(vec![atom(32), atom(32)]);
    let value = alignment
        .parse_field_repr(&[pad_hi, pad_lo, sk_hi, sk_lo])
        .expect("limbs match the alignment");
    let mut repr = Vec::new();
    ValueReprAlignedValue(value).binary_repr(&mut repr);
    Sha256::digest(&repr).into()
}

fn scalar(v: u64) -> IrValue {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&v.to_le_bytes());
    from_bytes32_offcircuit(&IrType::Secp256k1Scalar, &bytes).unwrap()
}

fn natives(v: &IrValue) -> Vec<Fr> {
    encode_offcircuit(v)
        .into_iter()
        .map(|x| match x {
            IrValue::Native(f) => f,
            other => panic!("encode produced non-native {other:?}"),
        })
        .collect()
}

/// The reference Impact program of `initialise` on a pre-state where
/// `initialised == count` and `deployer == commitment`, pinning a key
/// whose FAB value is `point_av`.
fn initialise_ops(count: u64, commitment: &[u8; 32], point_av: AlignedValue) -> Vec<VmOp> {
    let field_key = |i: u8| Key::Value(bytesn_value(1, &[i]));
    vec![
        // initialised == 0
        Op::Dup { n: 0 },
        Op::Idx {
            cached: false,
            push_path: false,
            path: vec![field_key(test_caller::INITIALISED)].into(),
        },
        Op::Popeq {
            cached: true,
            result: bytesn_value(8, &count.to_le_bytes()),
        },
        // deployerCommitment(deployerSecretKey()) == deployer
        Op::Dup { n: 0 },
        Op::Idx {
            cached: false,
            push_path: false,
            path: vec![field_key(test_caller::DEPLOYER)].into(),
        },
        Op::Popeq {
            cached: false,
            result: bytesn_value(32, commitment),
        },
        // initialised.increment(1)
        Op::Idx {
            cached: false,
            push_path: true,
            path: vec![field_key(test_caller::INITIALISED)].into(),
        },
        Op::Addi { immediate: 1 },
        Op::Ins { cached: true, n: 1 },
        // mpcResponseKey = disclose(responseKey)
        Op::Push {
            storage: false,
            value: cell(bytesn_value(1, &[test_caller::MPC_RESPONSE_KEY])),
        },
        Op::Push {
            storage: true,
            value: cell(point_av),
        },
        Op::Ins {
            cached: false,
            n: 1,
        },
    ]
}

fn transcript(ops: &[VmOp]) -> Vec<Fr> {
    let mut out = Vec::new();
    for op in ops {
        op.field_repr(&mut out);
    }
    out
}

/// The popeq results, value-only, in read order — what the ledger returns
/// through `public_transcript_outputs`.
fn outputs(count: u64, commitment: &[u8; 32]) -> Vec<Fr> {
    let mut out = Vec::new();
    for av in [
        bytesn_value(8, &count.to_le_bytes()),
        bytesn_value(32, commitment),
    ] {
        ValueReprAlignedValue(av).field_repr(&mut out);
    }
    out
}

fn preimage(inputs: Vec<Fr>, witnesses: Vec<Fr>, transcript: Vec<Fr>, outputs: Vec<Fr>) -> ProofPreimage {
    let rand = Fr::from(0xca11_e7u64);
    let comm = transient_commit(&inputs[..], rand);
    ProofPreimage {
        inputs,
        private_transcript: witnesses,
        public_transcript_inputs: transcript,
        public_transcript_outputs: outputs,
        binding_input: 0.into(),
        communications_commitment: Some((comm, rand)),
        key_location: KeyLocation(Cow::Borrowed("minocrab-contracts-test")),
    }
}

/// The concrete scenario every test shares: a deployer secret, its
/// commitment (the stored `deployer` cell), and an MPC response key.
struct Scenario {
    sk: [u8; 32],
    commitment: [u8; 32],
    point: IrValue,
}

impl Scenario {
    fn new() -> Scenario {
        let sk = {
            let mut b = [0u8; 32];
            b[..6].copy_from_slice(b"s3cr3t");
            b[31] = 0x5e;
            b
        };
        let d = scalar(0xd00d_1e5u64);
        let point = ec_mul_offcircuit(&IrValue::Secp256k1Point(k256::K256::generator()), &d).unwrap();
        Scenario {
            sk,
            commitment: deployer_commitment(&sk),
            point,
        }
    }

    fn point_av(&self) -> AlignedValue {
        let alignment = Alignment(
            test_caller::secp256k1_point_atoms()
                .into_iter()
                .map(AlignmentSegment::Atom)
                .collect(),
        );
        alignment
            .parse_field_repr(&natives(&self.point))
            .expect("point limbs match the alignment")
    }

    fn witnesses(&self) -> Vec<Fr> {
        let (hi, lo) = b32_slots(&self.sk);
        vec![hi, lo]
    }
}

#[test]
fn initialise_matches_corpus() {
    let theirs = corpus_zkir();
    let ours = test_caller::initialise().ir;
    let s = Scenario::new();

    let ops = initialise_ops(0, &s.commitment, s.point_av());
    let pi = preimage(
        natives(&s.point),
        s.witnesses(),
        transcript(&ops),
        outputs(0, &s.commitment),
    );
    assert_call_compatible(&ours, &theirs, &pi);
}

/// Criterion 3 (same acceptance): both artifacts must reject a transcript
/// where `initialised` reads back nonzero.
#[test]
fn initialise_rejects_when_already_initialised() {
    let theirs = corpus_zkir();
    let ours = test_caller::initialise().ir;
    let s = Scenario::new();

    let ops = initialise_ops(1, &s.commitment, s.point_av());
    let pi = preimage(
        natives(&s.point),
        s.witnesses(),
        transcript(&ops),
        outputs(1, &s.commitment),
    );
    assert!(simulate(&ours, &pi).is_err(), "ours must reject");
    assert!(simulate(&theirs, &pi).is_err(), "corpus must reject");
}

/// Criterion 3: both artifacts must reject a wrong deployer secret (the
/// witnessed sk hashes to something other than the stored commitment).
#[test]
fn initialise_rejects_wrong_deployer_secret() {
    let theirs = corpus_zkir();
    let ours = test_caller::initialise().ir;
    let s = Scenario::new();

    let mut wrong_sk = s.sk;
    wrong_sk[0] ^= 1;
    let (hi, lo) = b32_slots(&wrong_sk);

    let ops = initialise_ops(0, &s.commitment, s.point_av());
    let pi = preimage(
        natives(&s.point),
        vec![hi, lo],
        transcript(&ops),
        outputs(0, &s.commitment),
    );
    assert!(simulate(&ours, &pi).is_err(), "ours must reject");
    assert!(simulate(&theirs, &pi).is_err(), "corpus must reject");
}
