//! mint-tokens `mintWithRecipientArgument`: call-compatibility with the
//! corpus artifact per notes/ledger-abi.org §6 — validates `kernel.self()`
//! and the zswap effects ops (mintShielded + claimZswapCoinSpend) against
//! a real compactc artifact, plus rejection agreement on a tampered
//! transcript.

use std::borrow::Cow;

use midnight_base_crypto::fab::{
    Alignment, AlignmentAtom, AlignmentSegment, AlignedValue, Value, ValueAtom,
};
use midnight_base_crypto::repr::BinaryHashRepr;
use midnight_onchain_state::state::StateValue;
use midnight_onchain_vm::ops::{Key, Op};
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_transient_crypto::fab::{AlignmentExt, ValueReprAlignedValue};
use midnight_transient_crypto::hash::transient_commit;
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage, Zkir};
use midnight_transient_crypto::repr::FieldRepr;
use minocrab::Fr;
use minocrab_contracts::mint_tokens;
use minocrab_sim::v3::simulate;
use minocrab_zkir::v3::IrSource;
use sha2::{Digest, Sha256};

type VmOp = Op<ResultModeVerify, InMemoryDB>;

fn corpus_zkir(name: &str) -> IrSource {
    let path = format!(
        "{}/../../corpus/zkir/signet-midnight-experiments/experiments/mint-tokens/contract/src/mint-tokens/zkir/{name}.zkir",
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

fn pad32(s: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..s.len()].copy_from_slice(s.as_bytes());
    bytes
}

/// SHA-256 over the FAB binary of `limbs` laid out per `segments` — the
/// off-circuit persistent_hash (zkir-v3 ir_vm.rs:478-505).
fn fab_sha256(segments: Vec<AlignmentSegment>, limbs: &[Fr]) -> [u8; 32] {
    let value = Alignment(segments)
        .parse_field_repr(limbs)
        .expect("limbs match the alignment");
    let mut repr = Vec::new();
    ValueReprAlignedValue(value).binary_repr(&mut repr);
    Sha256::digest(&repr).into()
}

/// `tokenType(pad(32, DOMAIN_SEP), address)`.
fn token_type(address: &[u8; 32]) -> [u8; 32] {
    let (p_hi, p_lo) = b32_slots(&pad32("midnight:derive_token"));
    let (d_hi, d_lo) = b32_slots(&pad32(mint_tokens::DOMAIN_SEP));
    let (a_hi, a_lo) = b32_slots(address);
    fab_sha256(
        vec![atom(32), atom(32), atom(32)],
        &[p_hi, p_lo, d_hi, d_lo, a_hi, a_lo],
    )
}

/// `coinCommitment({nonce, color, value: 1}, left(recipient))`.
fn commitment(nonce: &[u8; 32], color: &[u8; 32], recipient: &[u8; 32]) -> [u8; 32] {
    let prefix = Fr::from_le_bytes(b"midnight:zswap-cc[v1]").unwrap();
    let (n_hi, n_lo) = b32_slots(nonce);
    let (c_hi, c_lo) = b32_slots(color);
    let (r_hi, r_lo) = b32_slots(recipient);
    fab_sha256(
        vec![atom(21), atom(32), atom(32), atom(16), atom(1), atom(32)],
        &[
            prefix,
            n_hi,
            n_lo,
            c_hi,
            c_lo,
            Fr::from(1u64), // value (Uint<128>)
            Fr::from(1u64), // is_left
            r_hi,
            r_lo,
        ],
    )
}

struct Scenario {
    recipient: [u8; 32],
    nonce: [u8; 32],
    address: [u8; 32],
}

impl Scenario {
    fn new() -> Scenario {
        let mut recipient = [0u8; 32];
        recipient[..9].copy_from_slice(b"zswap-pk-");
        recipient[31] = 0x44;
        let mut nonce = [0u8; 32];
        nonce[..10].copy_from_slice(b"mint-nonce");
        let mut address = [0u8; 32];
        address[..13].copy_from_slice(b"mint-contract");
        address[31] = 0x33;
        Scenario {
            recipient,
            nonce,
            address,
        }
    }

    /// The reference Impact program: kernel.self read, mintShielded upsert
    /// into effects[4], claimZswapCoinSpend insert into effects[2].
    /// `mint_to` is the coin recipient (the argument, or ownPublicKey).
    fn ops_to(&self, mint_to: &[u8; 32]) -> Vec<VmOp> {
        let color = token_type(&self.address);
        let cm = commitment(&self.nonce, &color, mint_to);
        let key = |i: u8| Key::Value(bytesn_value(1, &[i]));
        vec![
            // kernel.self()
            Op::Dup { n: 2 },
            Op::Idx {
                cached: true,
                push_path: false,
                path: vec![key(0)].into(),
            },
            Op::Popeq {
                cached: true,
                result: bytesn_value(32, &self.address),
            },
            // kernel.mintShielded(domain_sep, 1)
            Op::Swap { n: 0 },
            Op::Idx {
                cached: true,
                push_path: true,
                path: vec![key(4)].into(),
            },
            Op::Push {
                storage: false,
                value: cell(bytesn_value(32, &pad32(mint_tokens::DOMAIN_SEP))),
            },
            Op::Dup { n: 1 },
            Op::Dup { n: 1 },
            Op::Member,
            Op::Push {
                storage: false,
                value: cell(bytesn_value(8, &1u64.to_le_bytes())),
            },
            Op::Swap { n: 0 },
            Op::Neg,
            Op::Branch { skip: 4 },
            Op::Dup { n: 2 },
            Op::Dup { n: 2 },
            Op::Idx {
                cached: true,
                push_path: false,
                path: vec![Key::Stack].into(),
            },
            Op::Add,
            Op::Ins { cached: true, n: 2 },
            Op::Swap { n: 0 },
            // kernel.claimZswapCoinSpend(cm)
            Op::Swap { n: 0 },
            Op::Idx {
                cached: true,
                push_path: true,
                path: vec![key(2)].into(),
            },
            Op::Push {
                storage: false,
                value: cell(bytesn_value(32, &cm)),
            },
            Op::Push {
                storage: false,
                value: StateValue::Null,
            },
            Op::Ins { cached: true, n: 2 },
            Op::Swap { n: 0 },
        ]
    }

    fn preimage_with(&self, ops: Vec<VmOp>, witnesses: Vec<Fr>) -> ProofPreimage {
        let (r_hi, r_lo) = b32_slots(&self.recipient);
        let (n_hi, n_lo) = b32_slots(&self.nonce);
        let inputs = vec![r_hi, r_lo, n_hi, n_lo];

        let mut transcript = Vec::new();
        for op in ops {
            op.field_repr(&mut transcript);
        }
        // The single read result: kernel.self's address.
        let mut outputs = Vec::new();
        ValueReprAlignedValue(bytesn_value(32, &self.address)).field_repr(&mut outputs);

        let rand = Fr::from(0x316u64);
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

    /// mintWithRecipientArgument: mint to the recipient argument.
    fn preimage(&self) -> ProofPreimage {
        self.preimage_with(self.ops_to(&self.recipient), vec![])
    }

    /// mintWithRecipientOwnPublicKey: two ownPublicKey() witnesses (the
    /// mint recipient, then the ledger-written copy), a cell write of the
    /// second, then the mint to the first.
    fn preimage_own_pk(&self, own_pk: &[u8; 32]) -> ProofPreimage {
        let mut ops = vec![
            // veryPublicValue = ownPublicKey()
            Op::Push {
                storage: false,
                value: cell(bytesn_value(1, &[0])),
            },
            Op::Push {
                storage: true,
                value: cell(bytesn_value(32, own_pk)),
            },
            Op::Ins {
                cached: false,
                n: 1,
            },
        ];
        ops.extend(self.ops_to(own_pk));
        let (pk_hi, pk_lo) = b32_slots(own_pk);
        // Both ownPublicKey() calls witness the same key.
        self.preimage_with(ops, vec![pk_hi, pk_lo, pk_hi, pk_lo])
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
fn mint_with_recipient_argument_matches_corpus() {
    let theirs = corpus_zkir("mintWithRecipientArgument");
    let ours = mint_tokens::mint_with_recipient_argument().ir;
    let s = Scenario::new();
    assert_call_compatible(&ours, &theirs, &s.preimage());
}

#[test]
fn mint_with_recipient_own_public_key_matches_corpus() {
    let theirs = corpus_zkir("mintWithRecipientOwnPublicKey");
    let ours = mint_tokens::mint_with_recipient_own_public_key().ir;
    let s = Scenario::new();
    let mut own_pk = [0u8; 32];
    own_pk[..6].copy_from_slice(b"own-pk");
    own_pk[31] = 0x77;
    assert_call_compatible(&ours, &theirs, &s.preimage_own_pk(&own_pk));
}

/// Criterion 3: a tampered transcript (e.g. a mint of a different amount
/// than the circuit performs) must be rejected by BOTH artifacts.
#[test]
fn mint_rejects_tampered_transcript() {
    let theirs = corpus_zkir("mintWithRecipientArgument");
    let ours = mint_tokens::mint_with_recipient_argument().ir;
    let s = Scenario::new();

    let mut pi = s.preimage();
    // The amount element of the mint's `push` lives somewhere in the
    // transcript; flip every element one at a time and require agreement.
    let mut disagreements = 0;
    for i in 0..pi.public_transcript_inputs.len() {
        let saved = pi.public_transcript_inputs[i];
        pi.public_transcript_inputs[i] = saved + Fr::from(1u64);
        let ours_rejects = simulate(&ours, &pi).is_err();
        let theirs_rejects = simulate(&theirs, &pi).is_err();
        assert!(ours_rejects, "ours accepts tampered element {i}");
        if ours_rejects != theirs_rejects {
            disagreements += 1;
        }
        pi.public_transcript_inputs[i] = saved;
    }
    assert_eq!(disagreements, 0, "acceptance disagreement on tampering");
}
