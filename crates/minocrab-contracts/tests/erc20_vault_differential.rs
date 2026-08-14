//! erc20-vault `initialize`: call-compatibility with the corpus artifact
//! per notes/ledger-abi.org §6 — first circuit of the benchmark target
//! running on MinoCrab, plus acceptance agreement on every guard failure.

use std::borrow::Cow;

use midnight_base_crypto::fab::{
    Alignment, AlignmentAtom, AlignmentSegment, AlignedValue, Value, ValueAtom,
};
use midnight_base_crypto::repr::BinaryHashRepr;
use midnight_curves::k256;
use midnight_onchain_state::state::StateValue;
use midnight_onchain_vm::ops::{Key, Op};
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_transient_crypto::fab::{AlignmentExt, ValueReprAlignedValue};
use midnight_transient_crypto::hash::transient_commit;
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage, Zkir};
use midnight_transient_crypto::repr::FieldRepr;
use midnight_zkir_v3::ir_instructions::ec_mul::ec_mul_offcircuit;
use midnight_zkir_v3::ir_instructions::encode::encode_offcircuit;
use midnight_zkir_v3::ir_instructions::from_bytes32::from_bytes32_offcircuit;
use minocrab::Fr;
use minocrab_contracts::erc20_vault;
use minocrab_sim::v3::simulate;
use minocrab_zkir::v3::{IrSource, IrType, IrValue};
use sha2::{Digest, Sha256};

type VmOp = Op<ResultModeVerify, InMemoryDB>;

fn corpus_zkir() -> IrSource {
    let path = format!(
        "{}/../../corpus/zkir/signet-midnight-examples/examples/erc20-vault/contract/src/erc20-vault/zkir/initialize.zkir",
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

/// Off-circuit `userCommitment(sk)`: SHA-256 over the FAB bytes of
/// `[pad(32, USER_PAD), sk]`.
fn user_commitment(sk: &[u8; 32]) -> [u8; 32] {
    let mut pad = [0u8; 32];
    pad[..erc20_vault::USER_PAD.len()].copy_from_slice(erc20_vault::USER_PAD.as_bytes());
    let (pad_hi, pad_lo) = b32_slots(&pad);
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

/// The concrete initialize() call every test shares.
struct Scenario {
    sk: [u8; 32],
    commitment: [u8; 32],
    vault_evm: [u8; 20],
    swap_router: [u8; 20],
    chain_id: u64,
    caip2: [u8; 32],
    point: IrValue,
}

impl Scenario {
    fn new() -> Scenario {
        let sk = {
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(b"deployer");
            b[31] = 0x11;
            b
        };
        let mut caip2 = [0u8; 32];
        caip2[..15].copy_from_slice(b"eip155:11155111");
        let d = scalar(0xf00d_faceu64);
        let point =
            ec_mul_offcircuit(&IrValue::Secp256k1Point(k256::K256::generator()), &d).unwrap();
        Scenario {
            sk,
            commitment: user_commitment(&sk),
            vault_evm: *b"vault-evm-addr-20byt",
            swap_router: *b"uniswap-router-20byt",
            chain_id: 11155111,
            caip2,
            point,
        }
    }

    fn point_av(&self) -> AlignedValue {
        let alignment = Alignment(
            erc20_vault::secp256k1_point_atoms()
                .into_iter()
                .map(AlignmentSegment::Atom)
                .collect(),
        );
        alignment
            .parse_field_repr(&natives(&self.point))
            .expect("point limbs match the alignment")
    }

    /// Circuit arguments in source order, FAB-flattened.
    fn inputs(&self) -> Vec<Fr> {
        let (caip2_hi, caip2_lo) = b32_slots(&self.caip2);
        let mut inputs = vec![
            Fr::from_le_bytes(&self.vault_evm).unwrap(),
            Fr::from_le_bytes(&self.swap_router).unwrap(),
            Fr::from(self.chain_id),
            caip2_hi,
            caip2_lo,
        ];
        inputs.extend(natives(&self.point));
        inputs
    }

    fn witnesses(&self) -> Vec<Fr> {
        let (hi, lo) = b32_slots(&self.sk);
        vec![hi, lo]
    }

    /// The reference Impact program on a pre-state where
    /// `initialized == count` and `deployer == commitment`.
    fn ops(&self, count: u64) -> Vec<VmOp> {
        let field_key = |i: u8| Key::Value(bytesn_value(1, &[i]));
        let write = |field: u8, value: AlignedValue| {
            vec![
                Op::Push {
                    storage: false,
                    value: cell(bytesn_value(1, &[field])),
                },
                Op::Push {
                    storage: true,
                    value: cell(value),
                },
                Op::Ins {
                    cached: false,
                    n: 1,
                },
            ]
        };
        let mut ops = vec![
            // initialized == 0
            Op::Dup { n: 0 },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![field_key(erc20_vault::INITIALIZED)].into(),
            },
            Op::Popeq {
                cached: true,
                result: bytesn_value(8, &count.to_le_bytes()),
            },
            // userCommitment(callerSecretKey()) == deployer
            Op::Dup { n: 0 },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![field_key(erc20_vault::DEPLOYER)].into(),
            },
            Op::Popeq {
                cached: false,
                result: bytesn_value(32, &self.commitment),
            },
            // initialized.increment(1)
            Op::Idx {
                cached: false,
                push_path: true,
                path: vec![field_key(erc20_vault::INITIALIZED)].into(),
            },
            Op::Addi { immediate: 1 },
            Op::Ins { cached: true, n: 1 },
        ];
        ops.extend(write(
            erc20_vault::VAULT_EVM_ADDRESS,
            bytesn_value(20, &self.vault_evm),
        ));
        ops.extend(write(
            erc20_vault::UNISWAP_ROUTER,
            bytesn_value(20, &self.swap_router),
        ));
        ops.extend(write(
            erc20_vault::EVM_CHAIN_ID,
            bytesn_value(8, &self.chain_id.to_le_bytes()),
        ));
        ops.extend(write(erc20_vault::CAIP2_ID, bytesn_value(32, &self.caip2)));
        ops.extend(write(erc20_vault::MPC_RESPONSE_KEY, self.point_av()));
        ops
    }

    /// The popeq results in read order, value-only.
    fn outputs(&self, count: u64) -> Vec<Fr> {
        let mut out = Vec::new();
        for av in [
            bytesn_value(8, &count.to_le_bytes()),
            bytesn_value(32, &self.commitment),
        ] {
            ValueReprAlignedValue(av).field_repr(&mut out);
        }
        out
    }

    fn preimage(&self, count: u64) -> ProofPreimage {
        let inputs = self.inputs();
        let mut transcript = Vec::new();
        for op in self.ops(count) {
            op.field_repr(&mut transcript);
        }
        let rand = Fr::from(0xe20u64);
        let comm = transient_commit(&inputs[..], rand);
        ProofPreimage {
            inputs,
            private_transcript: self.witnesses(),
            public_transcript_inputs: transcript,
            public_transcript_outputs: self.outputs(count),
            binding_input: 0.into(),
            communications_commitment: Some((comm, rand)),
            key_location: KeyLocation(Cow::Borrowed("minocrab-contracts-test")),
        }
    }
}

fn assert_call_compatible(ours: &IrSource, theirs: &IrSource, pi: &ProofPreimage) {
    let types = |ir: &IrSource| {
        serde_json::to_value(&ir.inputs)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|ti| ti["type"].clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(types(ours), types(theirs), "input schemas differ");
    assert_eq!(ours.outputs, theirs.outputs, "output schemas differ");

    let our_run = simulate(ours, pi).expect("our artifact accepts");
    let their_run = simulate(theirs, pi).expect("corpus artifact accepts");
    assert_eq!(our_run.pi_skips, their_run.pi_skips, "pi_skips differ");
    assert_eq!(our_run.pis, their_run.pis, "PI vectors differ");

    assert_eq!(ours.check(pi).expect("upstream accepts ours"), our_run.pi_skips);
    assert_eq!(
        theirs.check(pi).expect("upstream accepts theirs"),
        their_run.pi_skips
    );
}

#[test]
fn initialize_matches_corpus() {
    let theirs = corpus_zkir();
    let ours = erc20_vault::initialize().ir;
    let s = Scenario::new();
    assert_call_compatible(&ours, &theirs, &s.preimage(0));
}

/// Criterion 3 (same acceptance): each guard failure must be rejected by
/// BOTH artifacts.
#[test]
fn initialize_rejects_guard_failures() {
    let theirs = corpus_zkir();
    let ours = erc20_vault::initialize().ir;

    // Already initialized: the counter reads back 1.
    let s = Scenario::new();
    let pi = s.preimage(1);
    assert!(simulate(&ours, &pi).is_err(), "ours: already initialized");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: already initialized");

    // Wrong deployer secret.
    let s = Scenario::new();
    let mut pi = s.preimage(0);
    let mut wrong_sk = s.sk;
    wrong_sk[0] ^= 1;
    let (hi, lo) = b32_slots(&wrong_sk);
    pi.private_transcript = vec![hi, lo];
    assert!(simulate(&ours, &pi).is_err(), "ours: wrong secret");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: wrong secret");

    // Zero chain id.
    let mut s = Scenario::new();
    s.chain_id = 0;
    let pi = s.preimage(0);
    assert!(simulate(&ours, &pi).is_err(), "ours: zero chain id");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: zero chain id");

    // Zero router address.
    let mut s = Scenario::new();
    s.swap_router = [0u8; 20];
    let pi = s.preimage(0);
    assert!(simulate(&ours, &pi).is_err(), "ours: zero router");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: zero router");
}
