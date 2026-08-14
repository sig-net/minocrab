//! erc20-vault `initialize` + `deposit`: call-compatibility with the
//! corpus artifacts per notes/ledger-abi.org §6 — the benchmark target
//! running on MinoCrab, plus acceptance agreement on guard failures and
//! tampering.

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
use midnight_zkir_v3::ir_instructions::add::add_offcircuit;
use midnight_zkir_v3::ir_instructions::ec_mul::ec_mul_offcircuit;
use midnight_zkir_v3::ir_instructions::encode::encode_offcircuit;
use midnight_zkir_v3::ir_instructions::from_bytes32::from_bytes32_offcircuit;
use midnight_zkir_v3::ir_instructions::into_bytes32::into_bytes32_offcircuit;
use midnight_zkir_v3::ir_instructions::into_coordinates::into_coordinates_offcircuit;
use midnight_zkir_v3::ir_instructions::inv::inv_offcircuit;
use midnight_zkir_v3::ir_instructions::mul::mul_offcircuit;
use minocrab::Fr;
use minocrab_contracts::erc20_vault;
use minocrab_sim::v3::simulate;
use minocrab_zkir::v3::{IrSource, IrType, IrValue};
use sha2::{Digest, Sha256};

type VmOp = Op<ResultModeVerify, InMemoryDB>;

fn corpus_zkir_named(name: &str) -> IrSource {
    let path = format!(
        "{}/../../corpus/zkir/signet-midnight-examples/examples/erc20-vault/contract/src/erc20-vault/zkir/{name}.zkir",
        env!("CARGO_MANIFEST_DIR")
    );
    minocrab_zkir::v3::read_zkir(&path).expect("corpus golden parses")
}

fn corpus_zkir() -> IrSource {
    corpus_zkir_named("initialize")
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

// --- deposit -----------------------------------------------------------------

/// A concrete deposit() call: arguments plus the ledger state the reads
/// return (initialized, vaultEvmAddress, evmChainId, signetRequestNonce,
/// kernel.self, caip2Id, signetSigner).
struct DepositScenario {
    sk: [u8; 32],
    evm_nonce: u64,
    gas_limit: u64,
    max_fee_per_gas: u64,
    max_priority_fee_per_gas: u64,
    key_version: u8,
    erc20: [u8; 20],
    amount: u64,
    // Ledger state.
    initialized: u64,
    vault_evm: [u8; 20],
    chain_id: u64,
    request_nonce: u64,
    self_addr: [u8; 32],
    caip2: [u8; 32],
    signer_addr: [u8; 32],
    ep: [u8; 32],
    cc_rand: Fr,
}

impl DepositScenario {
    fn new() -> DepositScenario {
        let sk = {
            let mut b = [0u8; 32];
            b[..9].copy_from_slice(b"depositor");
            b[31] = 0x21;
            b
        };
        let mut caip2 = [0u8; 32];
        caip2[..15].copy_from_slice(b"eip155:11155111");
        let mut self_addr = [0u8; 32];
        self_addr[..10].copy_from_slice(b"vault-addr");
        self_addr[31] = 0x31;
        let mut signer_addr = [0u8; 32];
        signer_addr[..11].copy_from_slice(b"signet-addr");
        signer_addr[31] = 0x32;
        let mut ep = [0u8; 32];
        ep[..20].copy_from_slice(b"ep:signBidirectional");
        ep[31] = 0x33;
        DepositScenario {
            sk,
            evm_nonce: 7,
            gas_limit: 65_000,
            max_fee_per_gas: 30_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            key_version: 1,
            erc20: *b"erc20-token-contract",
            amount: 123_456,
            initialized: 1,
            vault_evm: *b"vault-evm-addr-20byt",
            chain_id: 11_155_111,
            request_nonce: 4,
            self_addr,
            caip2,
            signer_addr,
            ep,
            cc_rand: Fr::from(0xdeb_051_7u64),
        }
    }

    /// `evmAddressAbiWord(vaultEvmAddress)`: 12 zero bytes + the address.
    fn word0(&self) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&self.vault_evm);
        w
    }

    /// `numericAbiWord(amount)`: 16 zero bytes + the amount big-endian.
    fn word1(&self) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[16..].copy_from_slice(&(u128::from(self.amount)).to_be_bytes());
        w
    }

    /// The record's 33 FAB limbs in slot order (the circuit's keccak input
    /// and, parsed against the 24-atom alignment, the map-insert value).
    fn event_limbs(&self) -> Vec<Fr> {
        let (self_hi, self_lo) = b32_slots(&self.self_addr);
        let path = user_commitment(&self.sk);
        let (path_hi, path_lo) = b32_slots(&path);
        let (caip2_hi, caip2_lo) = b32_slots(&self.caip2);
        let (w0_hi, w0_lo) = b32_slots(&self.word0());
        let (w1_hi, w1_lo) = b32_slots(&self.word1());
        let schema = erc20_vault::VAULT_RESPONSE_SCHEMA;
        let schema_hi = Fr::from_le_bytes(&schema[31..]).unwrap();
        let schema_lo = Fr::from_le_bytes(&schema[..31]).unwrap();
        vec![
            self_hi,
            self_lo,
            Fr::from(self.request_nonce),
            Fr::from(u64::from(self.key_version)),
            path_hi,
            path_lo,
            Fr::from(0u64), // algo: ecdsa
            Fr::from(0u64), // dest: unused
            Fr::from(0u64), // params: pad(64, "") — 3 limbs
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64), // txParamType: evmType2
            Fr::from(self.chain_id),
            Fr::from(self.evm_nonce),
            Fr::from(self.max_priority_fee_per_gas),
            Fr::from(self.max_fee_per_gas),
            Fr::from(self.gas_limit),
            Fr::from_le_bytes(&self.erc20).unwrap(), // to
            Fr::from(0u64),                          // value
            Fr::from(1u64),                          // calldata.is_some
            Fr::from_le_bytes(&erc20_vault::TRANSFER_SELECTOR).unwrap(),
            Fr::from(2u64), // noWords
            w0_hi,
            w0_lo,
            w1_hi,
            w1_lo,
            Fr::from(0u64), // accessListEntryCount
            caip2_hi,
            caip2_lo,
            schema_hi,
            schema_lo,
            schema_hi,
            schema_lo,
        ]
    }

    /// The record's 24-atom FAB alignment.
    fn event_alignment() -> Alignment {
        Alignment(
            [
                32u32, 8, 1, 32, 1, 1, 64, 1, // header
                8, 8, 16, 16, 8, 20, 16, // envelope
                1, 4, 2, 32, 32, // Maybe tag + calldata
                1,  // accessListEntryCount
                32, 34, 34, // caip2Id + schemas
            ]
            .into_iter()
            .map(atom)
            .collect(),
        )
    }

    /// The record as an AlignedValue (the map-insert's pushed cell).
    fn event_av(&self) -> AlignedValue {
        Self::event_alignment()
            .parse_field_repr(&self.event_limbs())
            .expect("event limbs match the alignment")
    }

    /// `calculateRequestId(request)`: keccak256 of the record's value-only
    /// FAB binary.
    fn request_id(&self) -> [u8; 32] {
        let mut repr = Vec::new();
        ValueReprAlignedValue(self.event_av()).binary_repr(&mut repr);
        sha3::Keccak256::digest(&repr).into()
    }

    /// The V1 notification payload: selfAddr ‖ depth=1 ‖ path [0,0,0,0] ‖
    /// zeros, as the 5 `Bytes<128>` limbs in slot order.
    fn notification_payload_limbs(&self) -> Vec<Fr> {
        let mut bytes = [0u8; 128];
        bytes[..32].copy_from_slice(&self.self_addr);
        bytes[32] = 1;
        // path [0, 0, 0, 0] — already zero.
        let mut limbs: Vec<Fr> = bytes
            .chunks(31)
            .map(|chunk| Fr::from_le_bytes(chunk).unwrap())
            .collect();
        limbs.reverse();
        limbs
    }

    /// The cross-contract-call args: requestId + notification (version,
    /// payload).
    fn call_args(&self) -> Vec<Fr> {
        let (rid_hi, rid_lo) = b32_slots(&self.request_id());
        let mut args = vec![rid_hi, rid_lo, Fr::from(1u64)];
        args.extend(self.notification_payload_limbs());
        args
    }

    fn inputs(&self) -> Vec<Fr> {
        vec![
            Fr::from(self.evm_nonce),
            Fr::from(self.gas_limit),
            Fr::from(self.max_fee_per_gas),
            Fr::from(self.max_priority_fee_per_gas),
            Fr::from(u64::from(self.key_version)),
            Fr::from_le_bytes(&self.erc20).unwrap(),
            Fr::from(self.amount),
        ]
    }

    fn witnesses(&self) -> Vec<Fr> {
        let (sk_hi, sk_lo) = b32_slots(&self.sk);
        let (ep_hi, ep_lo) = b32_slots(&self.ep);
        vec![sk_hi, sk_lo, self.cc_rand, ep_hi, ep_lo]
    }

    /// The reference Impact program, in the circuit's read/write order.
    fn ops(&self) -> Vec<VmOp> {
        let field_key = |i: u8| Key::Value(bytesn_value(1, &[i]));
        let read = |field: u8, cached: bool, result: AlignedValue| {
            vec![
                Op::Dup { n: 0 },
                Op::Idx {
                    cached: false,
                    push_path: false,
                    path: vec![field_key(field)].into(),
                },
                Op::Popeq { cached, result },
            ]
        };
        let kernel_self_ops = |result: &[u8; 32]| {
            vec![
                Op::Dup { n: 2 },
                Op::Idx {
                    cached: true,
                    push_path: false,
                    path: vec![field_key(0)].into(),
                },
                Op::Popeq {
                    cached: true,
                    result: bytesn_value(32, result),
                },
            ]
        };
        let request_id = self.request_id();

        let mut ops = Vec::new();
        // assert(initialized >= 1) — Counter.read, popeqc.
        ops.extend(read(
            erc20_vault::INITIALIZED,
            true,
            bytesn_value(8, &self.initialized.to_le_bytes()),
        ));
        // vaultEvmAddress (calldata word 0) — Cell.read, uncached.
        ops.extend(read(
            erc20_vault::VAULT_EVM_ADDRESS,
            false,
            bytesn_value(20, &self.vault_evm),
        ));
        // evmChainId — Cell.read, uncached.
        ops.extend(read(
            erc20_vault::EVM_CHAIN_ID,
            false,
            bytesn_value(8, &self.chain_id.to_le_bytes()),
        ));
        // signetRequestNonce as Uint<64> — Counter.read, popeqc.
        ops.extend(read(
            erc20_vault::SIGNET_REQUEST_NONCE,
            true,
            bytesn_value(8, &self.request_nonce.to_le_bytes()),
        ));
        // kernel.self() — the event's sender.
        ops.extend(kernel_self_ops(&self.self_addr));
        // caip2Id — Cell.read, uncached.
        ops.extend(read(
            erc20_vault::CAIP2_ID,
            false,
            bytesn_value(32, &self.caip2),
        ));
        // assert(!signBidirectionalEventMap.member(requestId))
        ops.extend([
            Op::Dup { n: 0 },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![field_key(erc20_vault::SIGN_BIDIRECTIONAL_EVENT_MAP)].into(),
            },
            Op::Push {
                storage: false,
                value: cell(bytesn_value(32, &request_id)),
            },
            Op::Member,
            Op::Popeq {
                cached: true,
                result: bytesn_value(1, &[0]),
            },
        ]);
        // signetRequestNonce.increment(1)
        ops.extend([
            Op::Idx {
                cached: false,
                push_path: true,
                path: vec![field_key(erc20_vault::SIGNET_REQUEST_NONCE)].into(),
            },
            Op::Addi { immediate: 1 },
            Op::Ins { cached: true, n: 1 },
        ]);
        // signBidirectionalEventMap.insert(requestId, disclose(request))
        ops.extend([
            Op::Idx {
                cached: false,
                push_path: true,
                path: vec![field_key(erc20_vault::SIGN_BIDIRECTIONAL_EVENT_MAP)].into(),
            },
            Op::Push {
                storage: false,
                value: cell(bytesn_value(32, &request_id)),
            },
            Op::Push {
                storage: true,
                value: cell(self.event_av()),
            },
            Op::Ins {
                cached: false,
                n: 1,
            },
            Op::Ins { cached: true, n: 1 },
        ]);
        // signetSigner — Cell.read, uncached (the callee address).
        ops.extend(read(
            erc20_vault::SIGNET_SIGNER,
            false,
            bytesn_value(32, &self.signer_addr),
        ));
        // kernel.self() again — the notification's callerAddress.
        ops.extend(kernel_self_ops(&self.self_addr));
        // kernel.claimContractCall(signer, ep, comm)
        let comm = transient_commit(&self.call_args()[..], self.cc_rand);
        let mut comm_bytes = comm.as_le_bytes();
        while comm_bytes.last() == Some(&0) {
            comm_bytes.pop();
        }
        let addr_ep_comm = AlignedValue::new(
            Value(vec![
                ValueAtom(self.signer_addr.to_vec()).normalize(),
                ValueAtom(self.ep.to_vec()).normalize(),
                ValueAtom(comm_bytes).normalize(),
            ]),
            Alignment(vec![
                atom(32),
                atom(32),
                AlignmentSegment::Atom(AlignmentAtom::Field),
            ]),
        )
        .unwrap();
        ops.extend([
            Op::Swap { n: 0 },
            Op::Idx {
                cached: true,
                push_path: true,
                path: vec![field_key(3)].into(),
            },
            Op::Dup { n: 0 },
            Op::Size,
            Op::Push {
                storage: false,
                value: cell(addr_ep_comm),
            },
            Op::Concat {
                cached: true,
                n: 160,
            },
            Op::Push {
                storage: false,
                value: StateValue::Null,
            },
            Op::Ins { cached: true, n: 2 },
            Op::Swap { n: 0 },
        ]);
        ops
    }

    /// The popeq results in read order, value-only.
    fn outputs(&self) -> Vec<Fr> {
        let mut out = Vec::new();
        for av in [
            bytesn_value(8, &self.initialized.to_le_bytes()),
            bytesn_value(20, &self.vault_evm),
            bytesn_value(8, &self.chain_id.to_le_bytes()),
            bytesn_value(8, &self.request_nonce.to_le_bytes()),
            bytesn_value(32, &self.self_addr),
            bytesn_value(32, &self.caip2),
            bytesn_value(1, &[0]),
            bytesn_value(32, &self.signer_addr),
            bytesn_value(32, &self.self_addr),
        ] {
            ValueReprAlignedValue(av).field_repr(&mut out);
        }
        out
    }

    fn preimage(&self) -> ProofPreimage {
        let inputs = self.inputs();
        let mut transcript = Vec::new();
        for op in self.ops() {
            op.field_repr(&mut transcript);
        }
        let rand = Fr::from(0xde9_0517u64);
        let comm = transient_commit(&inputs[..], rand);
        ProofPreimage {
            inputs,
            private_transcript: self.witnesses(),
            public_transcript_inputs: transcript,
            public_transcript_outputs: self.outputs(),
            binding_input: 0.into(),
            communications_commitment: Some((comm, rand)),
            key_location: KeyLocation(Cow::Borrowed("minocrab-contracts-test")),
        }
    }
}

// --- claim -------------------------------------------------------------------

/// SHA-256 over the FAB binary of `limbs` laid out per `segments` — the
/// off-circuit persistent_hash.
fn fab_sha256(segments: Vec<AlignmentSegment>, limbs: &[Fr]) -> [u8; 32] {
    let value = Alignment(segments)
        .parse_field_repr(limbs)
        .expect("limbs match the alignment");
    let mut repr = Vec::new();
    ValueReprAlignedValue(value).binary_repr(&mut repr);
    Sha256::digest(&repr).into()
}

fn pad32(s: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..s.len()].copy_from_slice(s.as_bytes());
    bytes
}

/// Sign `digest` (big-endian integer, RFC 6979) via upstream off-circuit
/// helpers; returns (r_bytes32_le, s_bytes32_le, pk).
fn sign(digest: &[u8; 32], d: &IrValue, k: &IrValue) -> ([u8; 32], [u8; 32], IrValue) {
    let generator = IrValue::Secp256k1Point(k256::K256::generator());
    let mut le = *digest;
    le.reverse();
    let z = from_bytes32_offcircuit(&IrType::Secp256k1Scalar, &le).unwrap();

    let r_point = ec_mul_offcircuit(&generator, k).unwrap();
    let (x, _y) = into_coordinates_offcircuit(&r_point).unwrap();
    let IrValue::Bytes32(x_le) = into_bytes32_offcircuit(&x).unwrap() else {
        panic!("into_bytes32 yields Bytes32");
    };
    let r = from_bytes32_offcircuit(&IrType::Secp256k1Scalar, &x_le).unwrap();

    let rd = mul_offcircuit(&r, d).unwrap();
    let z_rd = add_offcircuit(&z, &rd).unwrap();
    let k_inv = inv_offcircuit(k).unwrap();
    let s = mul_offcircuit(&k_inv, &z_rd).unwrap();

    let IrValue::Bytes32(r_le) = into_bytes32_offcircuit(&r).unwrap() else {
        panic!()
    };
    let IrValue::Bytes32(s_le) = into_bytes32_offcircuit(&s).unwrap() else {
        panic!()
    };
    let pk = ec_mul_offcircuit(&generator, d).unwrap();
    (r_le, s_le, pk)
}

/// `vaultTokenDomainSeparator(erc20)` off-circuit.
fn vault_domain_sep(erc20: &[u8; 20]) -> [u8; 32] {
    let mut erc20_b32 = [0u8; 32];
    erc20_b32[..20].copy_from_slice(erc20);
    let (e_hi, e_lo) = b32_slots(&erc20_b32);
    let (p_hi, p_lo) = b32_slots(&pad32(erc20_vault::TOKEN_PAD));
    fab_sha256(vec![atom(32), atom(32)], &[p_hi, p_lo, e_hi, e_lo])
}

/// `tokenType(vaultTokenDomainSeparator(erc20), self)` off-circuit.
fn vault_color(erc20: &[u8; 20], self_addr: &[u8; 32]) -> [u8; 32] {
    let domain_sep = vault_domain_sep(erc20);
    let (d_hi, d_lo) = b32_slots(&domain_sep);
    let (t_hi, t_lo) = b32_slots(&pad32("midnight:derive_token"));
    let (s_hi, s_lo) = b32_slots(self_addr);
    fab_sha256(
        vec![atom(32), atom(32), atom(32)],
        &[t_hi, t_lo, d_hi, d_lo, s_hi, s_lo],
    )
}

/// `coinCommitment(coin, recipient)` off-circuit — `is_left`/`data` per
/// the CoinPreimage.
fn coin_commitment_of(
    nonce: &(Fr, Fr),
    color: &[u8; 32],
    value: u64,
    is_left: bool,
    data: &[u8; 32],
) -> [u8; 32] {
    let prefix = Fr::from_le_bytes(b"midnight:zswap-cc[v1]").unwrap();
    let (c_hi, c_lo) = b32_slots(color);
    let (d_hi, d_lo) = b32_slots(data);
    fab_sha256(
        vec![atom(21), atom(32), atom(32), atom(16), atom(1), atom(32)],
        &[
            prefix, nonce.0, nonce.1, c_hi, c_lo,
            Fr::from(value),
            Fr::from(u64::from(is_left)),
            d_hi, d_lo,
        ],
    )
}

/// Who the minted coin goes to.
#[derive(Clone, Copy, PartialEq)]
enum ClaimRecipient {
    /// `some(left(pk))` — a wallet key; the auto-receive branch is off.
    Key([u8; 32]),
    /// `some(right(addr))` — a contract; auto-receive fires iff addr ==
    /// the vault itself.
    Contract([u8; 32]),
    /// `none` — mint to `left(ownPublicKey())`; branch off.
    None([u8; 32]),
}

/// A concrete claim() call settling the deposit recorded by
/// `DepositScenario` (same sk, same stored event record).
struct ClaimScenario {
    d: DepositScenario,
    mint_nonce: [u8; 32],
    recipient: ClaimRecipient,
    /// MPC response key's secret scalar seed + signature nonce seed.
    key_seed: u64,
    nonce_seed: u64,
}

impl ClaimScenario {
    fn new() -> ClaimScenario {
        let mut mint_nonce = [0u8; 32];
        mint_nonce[..11].copy_from_slice(b"mint-nonce!");
        mint_nonce[31] = 0x41;
        let mut key = [0u8; 32];
        key[..8].copy_from_slice(b"claim-pk");
        key[31] = 0x42;
        ClaimScenario {
            d: DepositScenario::new(),
            mint_nonce,
            recipient: ClaimRecipient::Key(key),
            key_seed: 0xf00d_face,
            nonce_seed: 0x0dd_b17,
        }
    }

    /// The MPC response key.
    fn mpc_key(&self) -> IrValue {
        let generator = IrValue::Secp256k1Point(k256::K256::generator());
        ec_mul_offcircuit(&generator, &scalar(self.key_seed)).unwrap()
    }

    fn mpc_key_av(&self) -> AlignedValue {
        let alignment = Alignment(
            erc20_vault::secp256k1_point_atoms()
                .into_iter()
                .map(AlignmentSegment::Atom)
                .collect(),
        );
        alignment
            .parse_field_repr(&natives(&self.mpc_key()))
            .expect("point limbs match the alignment")
    }

    /// attestationDigest = keccak256(requestId ‖ serializedOutput), with
    /// serializedOutput the packed success byte 0x01.
    fn attestation_digest(&self) -> [u8; 32] {
        let mut bytes = self.d.request_id().to_vec();
        bytes.push(1);
        sha3::Keccak256::digest(&bytes).into()
    }

    /// The attestation signature's (bigR.x, s), big-endian as stored.
    fn signature_be(&self) -> ([u8; 32], [u8; 32]) {
        let (mut r_le, mut s_le, _) = sign(
            &self.attestation_digest(),
            &scalar(self.key_seed),
            &scalar(self.nonce_seed),
        );
        r_le.reverse();
        s_le.reverse();
        (r_le, s_le)
    }

    /// The mint recipient as coinCommitment sees it: (is_left, data).
    fn recipient_data(&self) -> (bool, [u8; 32]) {
        match self.recipient {
            ClaimRecipient::Key(pk) => (true, pk),
            ClaimRecipient::Contract(addr) => (false, addr),
            ClaimRecipient::None(own_pk) => (true, own_pk),
        }
    }

    /// tokenType(vaultTokenDomainSeparator(erc20), self).
    fn color(&self) -> [u8; 32] {
        vault_color(&self.d.erc20, &self.d.self_addr)
    }

    fn domain_sep(&self) -> [u8; 32] {
        vault_domain_sep(&self.d.erc20)
    }

    /// coinCommitment({mintNonce, color, amount}, recipient).
    fn coin_commitment(&self) -> [u8; 32] {
        let prefix = Fr::from_le_bytes(b"midnight:zswap-cc[v1]").unwrap();
        let (n_hi, n_lo) = b32_slots(&self.mint_nonce);
        let (c_hi, c_lo) = b32_slots(&self.color());
        let (is_left, data) = self.recipient_data();
        let (r_hi, r_lo) = b32_slots(&data);
        fab_sha256(
            vec![atom(21), atom(32), atom(32), atom(16), atom(1), atom(32)],
            &[
                prefix,
                n_hi,
                n_lo,
                c_hi,
                c_lo,
                Fr::from(self.d.amount),
                Fr::from(u64::from(is_left)),
                r_hi,
                r_lo,
            ],
        )
    }

    /// Does the branch's guarded kernel.self read fire? (Its guard is
    /// only `!is_left`.)
    fn self_read_fires(&self) -> bool {
        matches!(self.recipient, ClaimRecipient::Contract(_))
    }

    /// Does the auto-receive claim fire? (`!is_left && right == self`.)
    fn auto_receive(&self) -> bool {
        matches!(self.recipient, ClaimRecipient::Contract(addr) if addr == self.d.self_addr)
    }

    fn inputs(&self) -> Vec<Fr> {
        let (rid_hi, rid_lo) = b32_slots(&self.d.request_id());
        let (rx, sx) = self.signature_be();
        let (rx_hi, rx_lo) = b32_slots(&rx);
        let (s_hi, s_lo) = b32_slots(&sx);
        let (n_hi, n_lo) = b32_slots(&self.mint_nonce);
        let (is_some, is_left, left, right) = match self.recipient {
            ClaimRecipient::Key(pk) => (1u64, 1u64, pk, [0u8; 32]),
            ClaimRecipient::Contract(addr) => (1, 0, [0u8; 32], addr),
            ClaimRecipient::None(_) => (0, 0, [0u8; 32], [0u8; 32]),
        };
        let (l_hi, l_lo) = b32_slots(&left);
        let (r_hi, r_lo) = b32_slots(&right);
        vec![
            rid_hi,
            rid_lo,
            rx_hi,
            rx_lo,
            Fr::from(0u64), // bigR.y (unused by verification)
            Fr::from(0u64),
            s_hi,
            s_lo,
            Fr::from(0u64), // recoveryId (unused)
            Fr::from(1u64), // serializedOutput: packed success
            n_hi,
            n_lo,
            Fr::from(is_some),
            Fr::from(is_left),
            l_hi,
            l_lo,
            r_hi,
            r_lo,
        ]
    }

    fn witnesses(&self) -> Vec<Fr> {
        let (sk_hi, sk_lo) = b32_slots(&self.d.sk);
        let mut w = vec![sk_hi, sk_lo];
        if let ClaimRecipient::None(own_pk) = self.recipient {
            let (pk_hi, pk_lo) = b32_slots(&own_pk);
            w.extend([pk_hi, pk_lo]);
        }
        w
    }

    /// The reference Impact program (`member_result` = what the map
    /// member test reads back).
    fn ops(&self, member_result: u8) -> Vec<VmOp> {
        let field_key = |i: u8| Key::Value(bytesn_value(1, &[i]));
        let request_id = self.d.request_id();
        let cm = self.coin_commitment();

        let mut ops = vec![
            // assert(initialized >= 1)
            Op::Dup { n: 0 },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![field_key(erc20_vault::INITIALIZED)].into(),
            },
            Op::Popeq {
                cached: true,
                result: bytesn_value(8, &self.d.initialized.to_le_bytes()),
            },
            // mpcResponseKey — Cell.read, uncached.
            Op::Dup { n: 0 },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![field_key(erc20_vault::MPC_RESPONSE_KEY)].into(),
            },
            Op::Popeq {
                cached: false,
                result: self.mpc_key_av(),
            },
            // member
            Op::Dup { n: 0 },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![field_key(erc20_vault::SIGN_BIDIRECTIONAL_EVENT_MAP)].into(),
            },
            Op::Push {
                storage: false,
                value: cell(bytesn_value(32, &request_id)),
            },
            Op::Member,
            Op::Popeq {
                cached: true,
                result: bytesn_value(1, &[member_result]),
            },
            // lookup
            Op::Dup { n: 0 },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![field_key(erc20_vault::SIGN_BIDIRECTIONAL_EVENT_MAP)].into(),
            },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![Key::Value(bytesn_value(32, &request_id))].into(),
            },
            Op::Popeq {
                cached: false,
                result: self.d.event_av(),
            },
            // remove
            Op::Idx {
                cached: false,
                push_path: true,
                path: vec![field_key(erc20_vault::SIGN_BIDIRECTIONAL_EVENT_MAP)].into(),
            },
            Op::Push {
                storage: false,
                value: cell(bytesn_value(32, &request_id)),
            },
            Op::Rem { cached: false },
            Op::Ins { cached: true, n: 1 },
            // mintShieldedToken: kernel.self()
            Op::Dup { n: 2 },
            Op::Idx {
                cached: true,
                push_path: false,
                path: vec![field_key(0)].into(),
            },
            Op::Popeq {
                cached: true,
                result: bytesn_value(32, &self.d.self_addr),
            },
        ];
        // kernel.mintShielded(domainSep, amount)
        let domain_sep = self.domain_sep();
        ops.extend([
            Op::Swap { n: 0 },
            Op::Idx {
                cached: true,
                push_path: true,
                path: vec![field_key(4)].into(),
            },
            Op::Push {
                storage: false,
                value: cell(bytesn_value(32, &domain_sep)),
            },
            Op::Dup { n: 1 },
            Op::Dup { n: 1 },
            Op::Member,
            Op::Push {
                storage: false,
                value: cell(bytesn_value(8, &self.d.amount.to_le_bytes())),
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
                path: vec![field_key(2)].into(),
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
        ]);
        if self.self_read_fires() {
            // The branch's guarded kernel.self read.
            ops.extend([
                Op::Dup { n: 2 },
                Op::Idx {
                    cached: true,
                    push_path: false,
                    path: vec![field_key(0)].into(),
                },
                Op::Popeq {
                    cached: true,
                    result: bytesn_value(32, &self.d.self_addr),
                },
            ]);
        }
        if self.auto_receive() {
            // The guarded receive claim.
            ops.extend([
                Op::Swap { n: 0 },
                Op::Idx {
                    cached: true,
                    push_path: true,
                    path: vec![field_key(1)].into(),
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
            ]);
        }
        ops
    }

    /// The popeq results in read order, value-only.
    fn outputs(&self, member_result: u8) -> Vec<Fr> {
        let mut avs = vec![
            bytesn_value(8, &self.d.initialized.to_le_bytes()),
            self.mpc_key_av(),
            bytesn_value(1, &[member_result]),
            self.d.event_av(),
            bytesn_value(32, &self.d.self_addr),
        ];
        if self.self_read_fires() {
            avs.push(bytesn_value(32, &self.d.self_addr));
        }
        let mut out = Vec::new();
        for av in avs {
            ValueReprAlignedValue(av).field_repr(&mut out);
        }
        out
    }

    fn preimage(&self) -> ProofPreimage {
        self.preimage_with_member(1)
    }

    fn preimage_with_member(&self, member_result: u8) -> ProofPreimage {
        let inputs = self.inputs();
        let mut transcript = Vec::new();
        for op in self.ops(member_result) {
            op.field_repr(&mut transcript);
        }
        let rand = Fr::from(0xc1a_13u64);
        let comm = transient_commit(&inputs[..], rand);
        ProofPreimage {
            inputs,
            private_transcript: self.witnesses(),
            public_transcript_inputs: transcript,
            public_transcript_outputs: self.outputs(member_result),
            binding_input: 0.into(),
            communications_commitment: Some((comm, rand)),
            key_location: KeyLocation(Cow::Borrowed("minocrab-contracts-test")),
        }
    }
}

#[test]
fn claim_matches_corpus() {
    let theirs = corpus_zkir_named("claim");
    let ours = erc20_vault::claim().ir;
    let s = ClaimScenario::new();
    assert_call_compatible(&ours, &theirs, &s.preimage());
}

/// recipient = some(right(vault)) — the auto-receive branch FIRES: the
/// guarded kernel.self read and the receive claim join the transcript.
#[test]
fn claim_matches_corpus_recipient_self() {
    let theirs = corpus_zkir_named("claim");
    let ours = erc20_vault::claim().ir;
    let mut s = ClaimScenario::new();
    s.recipient = ClaimRecipient::Contract(s.d.self_addr);
    assert!(s.auto_receive());
    assert_call_compatible(&ours, &theirs, &s.preimage());
}

/// recipient = some(right(other-contract)) — branch off, but the guarded
/// kernel.self read still fires (its guard is only !is_left).
#[test]
fn claim_matches_corpus_recipient_other_contract() {
    let theirs = corpus_zkir_named("claim");
    let ours = erc20_vault::claim().ir;
    let mut s = ClaimScenario::new();
    let mut other = [0u8; 32];
    other[..8].copy_from_slice(b"other-ct");
    s.recipient = ClaimRecipient::Contract(other);
    assert!(!s.auto_receive());
    assert_call_compatible(&ours, &theirs, &s.preimage());
}

/// recipient = none — mint to left(ownPublicKey()): the guarded witnesses
/// are consumed, the branch is off.
#[test]
fn claim_matches_corpus_recipient_none() {
    let theirs = corpus_zkir_named("claim");
    let ours = erc20_vault::claim().ir;
    let mut s = ClaimScenario::new();
    let mut own_pk = [0u8; 32];
    own_pk[..6].copy_from_slice(b"own-pk");
    own_pk[31] = 0x43;
    s.recipient = ClaimRecipient::None(own_pk);
    assert_call_compatible(&ours, &theirs, &s.preimage());
}

/// Guard failures must be rejected by BOTH artifacts.
#[test]
fn claim_rejects_guard_failures() {
    let theirs = corpus_zkir_named("claim");
    let ours = erc20_vault::claim().ir;

    // Failed EVM transfer: serializedOutput 0x00.
    let s = ClaimScenario::new();
    let mut pi = s.preimage();
    pi.inputs[9] = Fr::from(0u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: transfer failed");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: transfer failed");

    // Bad attestation signature (s + 1).
    let s = ClaimScenario::new();
    let mut pi = s.preimage();
    pi.inputs[7] = pi.inputs[7] + Fr::from(1u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: bad signature");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: bad signature");

    // Request not found (member reads back 0).
    let s = ClaimScenario::new();
    let pi = s.preimage_with_member(0);
    assert!(simulate(&ours, &pi).is_err(), "ours: request not found");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: request not found");

    // Not the depositor: wrong secret key.
    let s = ClaimScenario::new();
    let mut pi = s.preimage();
    pi.private_transcript[0] = pi.private_transcript[0] + Fr::from(1u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: not the depositor");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: not the depositor");
}

/// Tampering with any transcript element must be rejected by both
/// artifacts, with zero acceptance disagreements.
#[test]
fn claim_rejects_tampering() {
    let theirs = corpus_zkir_named("claim");
    let ours = erc20_vault::claim().ir;
    let s = ClaimScenario::new();

    let pi = s.preimage();
    let mut disagreements = 0;
    for i in 0..pi.public_transcript_inputs.len() {
        let mut t = pi.clone();
        t.public_transcript_inputs[i] = t.public_transcript_inputs[i] + Fr::from(1u64);
        let ours_rejects = simulate(&ours, &t).is_err();
        assert!(ours_rejects, "ours accepts tampered transcript element {i}");
        if ours_rejects != simulate(&theirs, &t).is_err() {
            disagreements += 1;
        }
    }
    assert_eq!(disagreements, 0, "acceptance disagreement on tampering");
}

// --- approveRouter -----------------------------------------------------------

/// A concrete approveRouter() call: the vault-account approve request.
struct ApproveScenario {
    erc20: [u8; 20],
    evm_nonce: u64,
    key_version: u8,
    initialized: u64,
    router: [u8; 20],
    chain_id: u64,
    request_nonce: u64,
    self_addr: [u8; 32],
    caip2: [u8; 32],
    signer_addr: [u8; 32],
    ep: [u8; 32],
    cc_rand: Fr,
}

impl ApproveScenario {
    fn new() -> ApproveScenario {
        let d = DepositScenario::new();
        ApproveScenario {
            erc20: d.erc20,
            evm_nonce: 9,
            key_version: 1,
            initialized: 1,
            router: *b"uniswap-router-20byt",
            chain_id: d.chain_id,
            request_nonce: 5,
            self_addr: d.self_addr,
            caip2: d.caip2,
            signer_addr: d.signer_addr,
            ep: d.ep,
            cc_rand: Fr::from(0xa9905eu64),
        }
    }

    fn word0(&self) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&self.router);
        w
    }

    fn word1(&self) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[16..].copy_from_slice(&[0xff; 16]); // 2^128 − 1, big-endian
        w
    }

    fn event_limbs(&self) -> Vec<Fr> {
        let (self_hi, self_lo) = b32_slots(&self.self_addr);
        let (path_hi, path_lo) = b32_slots(&pad32(erc20_vault::VAULT_PATH));
        let (caip2_hi, caip2_lo) = b32_slots(&self.caip2);
        let (w0_hi, w0_lo) = b32_slots(&self.word0());
        let (w1_hi, w1_lo) = b32_slots(&self.word1());
        let schema = erc20_vault::VAULT_RESPONSE_SCHEMA;
        let schema_hi = Fr::from_le_bytes(&schema[31..]).unwrap();
        let schema_lo = Fr::from_le_bytes(&schema[..31]).unwrap();
        vec![
            self_hi,
            self_lo,
            Fr::from(self.request_nonce),
            Fr::from(u64::from(self.key_version)),
            path_hi,
            path_lo,
            Fr::from(0u64), // algo
            Fr::from(0u64), // dest
            Fr::from(0u64), // params ×3
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64), // txParamType
            Fr::from(self.chain_id),
            Fr::from(self.evm_nonce),
            Fr::from(1_000_000_000u64),  // maxPriorityFeePerGas (fixed)
            Fr::from(30_000_000_000u64), // maxFeePerGas (fixed)
            Fr::from(100_000u64),        // gasLimit (fixed)
            Fr::from_le_bytes(&self.erc20).unwrap(), // to
            Fr::from(0u64),              // value
            Fr::from(1u64),              // calldata.is_some
            Fr::from_le_bytes(&erc20_vault::APPROVE_SELECTOR).unwrap(),
            Fr::from(2u64), // noWords
            w0_hi,
            w0_lo,
            w1_hi,
            w1_lo,
            Fr::from(0u64), // accessListEntryCount
            caip2_hi,
            caip2_lo,
            schema_hi,
            schema_lo,
            schema_hi,
            schema_lo,
        ]
    }

    fn event_av(&self) -> AlignedValue {
        DepositScenario::event_alignment()
            .parse_field_repr(&self.event_limbs())
            .expect("event limbs match the alignment")
    }

    fn request_id(&self) -> [u8; 32] {
        let mut repr = Vec::new();
        ValueReprAlignedValue(self.event_av()).binary_repr(&mut repr);
        sha3::Keccak256::digest(&repr).into()
    }

    fn call_args(&self) -> Vec<Fr> {
        let (rid_hi, rid_lo) = b32_slots(&self.request_id());
        let mut bytes = [0u8; 128];
        bytes[..32].copy_from_slice(&self.self_addr);
        bytes[32] = 1;
        let mut limbs: Vec<Fr> = bytes
            .chunks(31)
            .map(|chunk| Fr::from_le_bytes(chunk).unwrap())
            .collect();
        limbs.reverse();
        let mut args = vec![rid_hi, rid_lo, Fr::from(1u64)];
        args.extend(limbs);
        args
    }

    fn preimage(&self) -> ProofPreimage {
        let field_key = |i: u8| Key::Value(bytesn_value(1, &[i]));
        let read = |field: u8, cached: bool, result: AlignedValue| {
            vec![
                Op::Dup { n: 0 },
                Op::Idx {
                    cached: false,
                    push_path: false,
                    path: vec![field_key(field)].into(),
                },
                Op::Popeq { cached, result },
            ]
        };
        let kernel_self_ops = |result: &[u8; 32]| {
            vec![
                Op::Dup { n: 2 },
                Op::Idx {
                    cached: true,
                    push_path: false,
                    path: vec![field_key(0)].into(),
                },
                Op::Popeq {
                    cached: true,
                    result: bytesn_value(32, result),
                },
            ]
        };
        let request_id = self.request_id();

        let mut ops = Vec::new();
        ops.extend(read(
            erc20_vault::INITIALIZED,
            true,
            bytesn_value(8, &self.initialized.to_le_bytes()),
        ));
        ops.extend(read(
            erc20_vault::UNISWAP_ROUTER,
            false,
            bytesn_value(20, &self.router),
        ));
        ops.extend(read(
            erc20_vault::EVM_CHAIN_ID,
            false,
            bytesn_value(8, &self.chain_id.to_le_bytes()),
        ));
        ops.extend(read(
            erc20_vault::SIGNET_REQUEST_NONCE,
            true,
            bytesn_value(8, &self.request_nonce.to_le_bytes()),
        ));
        ops.extend(kernel_self_ops(&self.self_addr));
        ops.extend(read(
            erc20_vault::CAIP2_ID,
            false,
            bytesn_value(32, &self.caip2),
        ));
        ops.extend([
            Op::Dup { n: 0 },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![field_key(erc20_vault::SIGN_BIDIRECTIONAL_EVENT_MAP)].into(),
            },
            Op::Push {
                storage: false,
                value: cell(bytesn_value(32, &request_id)),
            },
            Op::Member,
            Op::Popeq {
                cached: true,
                result: bytesn_value(1, &[0]),
            },
            Op::Idx {
                cached: false,
                push_path: true,
                path: vec![field_key(erc20_vault::SIGNET_REQUEST_NONCE)].into(),
            },
            Op::Addi { immediate: 1 },
            Op::Ins { cached: true, n: 1 },
            Op::Idx {
                cached: false,
                push_path: true,
                path: vec![field_key(erc20_vault::SIGN_BIDIRECTIONAL_EVENT_MAP)].into(),
            },
            Op::Push {
                storage: false,
                value: cell(bytesn_value(32, &request_id)),
            },
            Op::Push {
                storage: true,
                value: cell(self.event_av()),
            },
            Op::Ins {
                cached: false,
                n: 1,
            },
            Op::Ins { cached: true, n: 1 },
        ]);
        ops.extend(read(
            erc20_vault::SIGNET_SIGNER,
            false,
            bytesn_value(32, &self.signer_addr),
        ));
        ops.extend(kernel_self_ops(&self.self_addr));
        let comm = transient_commit(&self.call_args()[..], self.cc_rand);
        let mut comm_bytes = comm.as_le_bytes();
        while comm_bytes.last() == Some(&0) {
            comm_bytes.pop();
        }
        let addr_ep_comm = AlignedValue::new(
            Value(vec![
                ValueAtom(self.signer_addr.to_vec()).normalize(),
                ValueAtom(self.ep.to_vec()).normalize(),
                ValueAtom(comm_bytes).normalize(),
            ]),
            Alignment(vec![
                atom(32),
                atom(32),
                AlignmentSegment::Atom(AlignmentAtom::Field),
            ]),
        )
        .unwrap();
        ops.extend([
            Op::Swap { n: 0 },
            Op::Idx {
                cached: true,
                push_path: true,
                path: vec![field_key(3)].into(),
            },
            Op::Dup { n: 0 },
            Op::Size,
            Op::Push {
                storage: false,
                value: cell(addr_ep_comm),
            },
            Op::Concat {
                cached: true,
                n: 160,
            },
            Op::Push {
                storage: false,
                value: StateValue::Null,
            },
            Op::Ins { cached: true, n: 2 },
            Op::Swap { n: 0 },
        ]);

        let inputs = vec![
            Fr::from_le_bytes(&self.erc20).unwrap(),
            Fr::from(self.evm_nonce),
            Fr::from(u64::from(self.key_version)),
        ];
        let mut transcript = Vec::new();
        for op in ops {
            op.field_repr(&mut transcript);
        }
        let mut outputs = Vec::new();
        for av in [
            bytesn_value(8, &self.initialized.to_le_bytes()),
            bytesn_value(20, &self.router),
            bytesn_value(8, &self.chain_id.to_le_bytes()),
            bytesn_value(8, &self.request_nonce.to_le_bytes()),
            bytesn_value(32, &self.self_addr),
            bytesn_value(32, &self.caip2),
            bytesn_value(1, &[0]),
            bytesn_value(32, &self.signer_addr),
            bytesn_value(32, &self.self_addr),
        ] {
            ValueReprAlignedValue(av).field_repr(&mut outputs);
        }
        let (ep_hi, ep_lo) = b32_slots(&self.ep);
        let rand = Fr::from(0xa11_0eu64);
        let comm_c = transient_commit(&inputs[..], rand);
        ProofPreimage {
            inputs,
            private_transcript: vec![self.cc_rand, ep_hi, ep_lo],
            public_transcript_inputs: transcript,
            public_transcript_outputs: outputs,
            binding_input: 0.into(),
            communications_commitment: Some((comm_c, rand)),
            key_location: KeyLocation(Cow::Borrowed("minocrab-contracts-test")),
        }
    }
}

// --- withdraw ----------------------------------------------------------------

/// `coinNullifier(coin, addr)` off-circuit — the `zswap-cn` domain,
/// dataType 0.
fn coin_nullifier_of(nonce: &(Fr, Fr), color: &[u8; 32], value: u64, addr: &[u8; 32]) -> [u8; 32] {
    let prefix = Fr::from_le_bytes(b"midnight:zswap-cn[v1]").unwrap();
    let (c_hi, c_lo) = b32_slots(color);
    let (a_hi, a_lo) = b32_slots(addr);
    fab_sha256(
        vec![atom(21), atom(32), atom(32), atom(16), atom(1), atom(32)],
        &[
            prefix, nonce.0, nonce.1, c_hi, c_lo,
            Fr::from(value),
            Fr::from(0u64),
            a_hi, a_lo,
        ],
    )
}

/// `evolveNonce` as lowered: `transientHash([tag, nonce.lo])`, upgraded as
/// `[hi: 0, lo: mod 2^248]`.
fn evolved_nonce(nonce: &[u8; 32]) -> (Fr, Fr) {
    use midnight_transient_crypto::hash::transient_hash;
    let tag = Fr::from_le_bytes(b"midnight:kernel:nonce_evolve").unwrap();
    let (_hi, lo) = b32_slots(nonce);
    let h = transient_hash(&[tag, lo]);
    let mut le = h.as_le_bytes();
    le.resize(32, 0);
    (Fr::from(0u64), Fr::from_le_bytes(&le[..31]).unwrap())
}

/// A concrete withdraw() call.
struct WithdrawScenario {
    evm_nonce: u64,
    key_version: u8,
    erc20: [u8; 20],
    amount: u64,
    dest: [u8; 20],
    coin_nonce: [u8; 32],
    sk: [u8; 32],
    initialized: u64,
    chain_id: u64,
    request_nonce: u64,
    self_addr: [u8; 32],
    caip2: [u8; 32],
    signer_addr: [u8; 32],
    ep: [u8; 32],
    cc_rand: Fr,
}

impl WithdrawScenario {
    fn new() -> WithdrawScenario {
        let d = DepositScenario::new();
        let mut coin_nonce = [0u8; 32];
        coin_nonce[..10].copy_from_slice(b"coin-nonce");
        coin_nonce[31] = 0x51;
        WithdrawScenario {
            evm_nonce: 11,
            key_version: 1,
            erc20: d.erc20,
            amount: 55_555,
            dest: *b"dest-evm-addr-20byte",
            coin_nonce,
            sk: d.sk,
            initialized: 1,
            chain_id: d.chain_id,
            request_nonce: 6,
            self_addr: d.self_addr,
            caip2: d.caip2,
            signer_addr: d.signer_addr,
            ep: d.ep,
            cc_rand: Fr::from(0x71d_47u64),
        }
    }

    fn color(&self) -> [u8; 32] {
        vault_color(&self.erc20, &self.self_addr)
    }

    fn event_limbs(&self) -> Vec<Fr> {
        let (self_hi, self_lo) = b32_slots(&self.self_addr);
        let (path_hi, path_lo) = b32_slots(&pad32(erc20_vault::VAULT_PATH));
        let (caip2_hi, caip2_lo) = b32_slots(&self.caip2);
        let mut w0 = [0u8; 32];
        w0[12..].copy_from_slice(&self.dest);
        let mut w1 = [0u8; 32];
        w1[16..].copy_from_slice(&(u128::from(self.amount)).to_be_bytes());
        let (w0_hi, w0_lo) = b32_slots(&w0);
        let (w1_hi, w1_lo) = b32_slots(&w1);
        let schema = erc20_vault::VAULT_RESPONSE_SCHEMA;
        let schema_hi = Fr::from_le_bytes(&schema[31..]).unwrap();
        let schema_lo = Fr::from_le_bytes(&schema[..31]).unwrap();
        vec![
            self_hi,
            self_lo,
            Fr::from(self.request_nonce),
            Fr::from(u64::from(self.key_version)),
            path_hi,
            path_lo,
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(self.chain_id),
            Fr::from(self.evm_nonce),
            Fr::from(1_000_000_000u64),
            Fr::from(30_000_000_000u64),
            Fr::from(100_000u64),
            Fr::from_le_bytes(&self.erc20).unwrap(),
            Fr::from(0u64),
            Fr::from(1u64),
            Fr::from_le_bytes(&erc20_vault::TRANSFER_SELECTOR).unwrap(),
            Fr::from(2u64),
            w0_hi,
            w0_lo,
            w1_hi,
            w1_lo,
            Fr::from(0u64),
            caip2_hi,
            caip2_lo,
            schema_hi,
            schema_lo,
            schema_hi,
            schema_lo,
        ]
    }

    fn event_av(&self) -> AlignedValue {
        DepositScenario::event_alignment()
            .parse_field_repr(&self.event_limbs())
            .expect("event limbs match the alignment")
    }

    fn request_id(&self) -> [u8; 32] {
        let mut repr = Vec::new();
        ValueReprAlignedValue(self.event_av()).binary_repr(&mut repr);
        sha3::Keccak256::digest(&repr).into()
    }

    /// withdrawRefundCommitment(sk, requestId).
    fn refund_commitment(&self) -> [u8; 32] {
        let (p_hi, p_lo) = b32_slots(&pad32(erc20_vault::REFUND_PAD));
        let (sk_hi, sk_lo) = b32_slots(&self.sk);
        let (r_hi, r_lo) = b32_slots(&self.request_id());
        fab_sha256(
            vec![atom(32), atom(32), atom(32)],
            &[p_hi, p_lo, sk_hi, sk_lo, r_hi, r_lo],
        )
    }

    fn call_args(&self) -> Vec<Fr> {
        let (rid_hi, rid_lo) = b32_slots(&self.request_id());
        let mut bytes = [0u8; 128];
        bytes[..32].copy_from_slice(&self.self_addr);
        bytes[32] = 1;
        let mut limbs: Vec<Fr> = bytes
            .chunks(31)
            .map(|chunk| Fr::from_le_bytes(chunk).unwrap())
            .collect();
        limbs.reverse();
        let mut args = vec![rid_hi, rid_lo, Fr::from(1u64)];
        args.extend(limbs);
        args
    }

    fn preimage(&self) -> ProofPreimage {
        let field_key = |i: u8| Key::Value(bytesn_value(1, &[i]));
        let read = |field: u8, cached: bool, result: AlignedValue| {
            vec![
                Op::Dup { n: 0 },
                Op::Idx {
                    cached: false,
                    push_path: false,
                    path: vec![field_key(field)].into(),
                },
                Op::Popeq { cached, result },
            ]
        };
        let kernel_self_ops = |result: &[u8; 32]| {
            vec![
                Op::Dup { n: 2 },
                Op::Idx {
                    cached: true,
                    push_path: false,
                    path: vec![field_key(0)].into(),
                },
                Op::Popeq {
                    cached: true,
                    result: bytesn_value(32, result),
                },
            ]
        };
        let claim = |effect: u8, note: [u8; 32]| {
            vec![
                Op::Swap { n: 0 },
                Op::Idx {
                    cached: true,
                    push_path: true,
                    path: vec![field_key(effect)].into(),
                },
                Op::Push {
                    storage: false,
                    value: cell(bytesn_value(32, &note)),
                },
                Op::Push {
                    storage: false,
                    value: StateValue::Null,
                },
                Op::Ins { cached: true, n: 2 },
                Op::Swap { n: 0 },
            ]
        };

        let request_id = self.request_id();
        let color = self.color();
        let nonce_slots = b32_slots(&self.coin_nonce);
        let cm_receive = coin_commitment_of(&nonce_slots, &color, self.amount, false, &self.self_addr);
        let nullifier = coin_nullifier_of(&nonce_slots, &color, self.amount, &self.self_addr);
        let cm_burn = coin_commitment_of(
            &evolved_nonce(&self.coin_nonce),
            &color,
            self.amount,
            true,
            &[0u8; 32],
        );

        let mut ops = Vec::new();
        ops.extend(read(
            erc20_vault::INITIALIZED,
            true,
            bytesn_value(8, &self.initialized.to_le_bytes()),
        ));
        // tokenType's kernel.self()
        ops.extend(kernel_self_ops(&self.self_addr));
        ops.extend(read(
            erc20_vault::EVM_CHAIN_ID,
            false,
            bytesn_value(8, &self.chain_id.to_le_bytes()),
        ));
        ops.extend(read(
            erc20_vault::SIGNET_REQUEST_NONCE,
            true,
            bytesn_value(8, &self.request_nonce.to_le_bytes()),
        ));
        ops.extend(kernel_self_ops(&self.self_addr));
        ops.extend(read(
            erc20_vault::CAIP2_ID,
            false,
            bytesn_value(32, &self.caip2),
        ));
        // member
        ops.extend([
            Op::Dup { n: 0 },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![field_key(erc20_vault::SIGN_BIDIRECTIONAL_EVENT_MAP)].into(),
            },
            Op::Push {
                storage: false,
                value: cell(bytesn_value(32, &request_id)),
            },
            Op::Member,
            Op::Popeq {
                cached: true,
                result: bytesn_value(1, &[0]),
            },
        ]);
        // receiveShielded
        ops.extend(kernel_self_ops(&self.self_addr));
        ops.extend(claim(1, cm_receive));
        // burn: sendImmediateShielded to the burn address
        ops.extend(kernel_self_ops(&self.self_addr));
        ops.extend(claim(0, nullifier));
        ops.extend(claim(2, cm_burn));
        // increment + event insert
        ops.extend([
            Op::Idx {
                cached: false,
                push_path: true,
                path: vec![field_key(erc20_vault::SIGNET_REQUEST_NONCE)].into(),
            },
            Op::Addi { immediate: 1 },
            Op::Ins { cached: true, n: 1 },
            Op::Idx {
                cached: false,
                push_path: true,
                path: vec![field_key(erc20_vault::SIGN_BIDIRECTIONAL_EVENT_MAP)].into(),
            },
            Op::Push {
                storage: false,
                value: cell(bytesn_value(32, &request_id)),
            },
            Op::Push {
                storage: true,
                value: cell(self.event_av()),
            },
            Op::Ins {
                cached: false,
                n: 1,
            },
            Op::Ins { cached: true, n: 1 },
            // refundCommitment.insert
            Op::Idx {
                cached: false,
                push_path: true,
                path: vec![field_key(erc20_vault::REFUND_COMMITMENT)].into(),
            },
            Op::Push {
                storage: false,
                value: cell(bytesn_value(32, &request_id)),
            },
            Op::Push {
                storage: true,
                value: cell(bytesn_value(32, &self.refund_commitment())),
            },
            Op::Ins {
                cached: false,
                n: 1,
            },
            Op::Ins { cached: true, n: 1 },
        ]);
        // notify
        ops.extend(read(
            erc20_vault::SIGNET_SIGNER,
            false,
            bytesn_value(32, &self.signer_addr),
        ));
        ops.extend(kernel_self_ops(&self.self_addr));
        let comm = transient_commit(&self.call_args()[..], self.cc_rand);
        let mut comm_bytes = comm.as_le_bytes();
        while comm_bytes.last() == Some(&0) {
            comm_bytes.pop();
        }
        let addr_ep_comm = AlignedValue::new(
            Value(vec![
                ValueAtom(self.signer_addr.to_vec()).normalize(),
                ValueAtom(self.ep.to_vec()).normalize(),
                ValueAtom(comm_bytes).normalize(),
            ]),
            Alignment(vec![
                atom(32),
                atom(32),
                AlignmentSegment::Atom(AlignmentAtom::Field),
            ]),
        )
        .unwrap();
        ops.extend([
            Op::Swap { n: 0 },
            Op::Idx {
                cached: true,
                push_path: true,
                path: vec![field_key(3)].into(),
            },
            Op::Dup { n: 0 },
            Op::Size,
            Op::Push {
                storage: false,
                value: cell(addr_ep_comm),
            },
            Op::Concat {
                cached: true,
                n: 160,
            },
            Op::Push {
                storage: false,
                value: StateValue::Null,
            },
            Op::Ins { cached: true, n: 2 },
            Op::Swap { n: 0 },
        ]);

        let (n_hi, n_lo) = nonce_slots;
        let (c_hi, c_lo) = b32_slots(&color);
        let inputs = vec![
            Fr::from(self.evm_nonce),
            Fr::from(u64::from(self.key_version)),
            Fr::from_le_bytes(&self.erc20).unwrap(),
            Fr::from(self.amount),
            Fr::from_le_bytes(&self.dest).unwrap(),
            n_hi,
            n_lo,
            c_hi,
            c_lo,
            Fr::from(self.amount), // coin.value == amount
        ];
        let mut transcript = Vec::new();
        for op in ops {
            op.field_repr(&mut transcript);
        }
        let mut outputs = Vec::new();
        for av in [
            bytesn_value(8, &self.initialized.to_le_bytes()),
            bytesn_value(32, &self.self_addr),
            bytesn_value(8, &self.chain_id.to_le_bytes()),
            bytesn_value(8, &self.request_nonce.to_le_bytes()),
            bytesn_value(32, &self.self_addr),
            bytesn_value(32, &self.caip2),
            bytesn_value(1, &[0]),
            bytesn_value(32, &self.self_addr),
            bytesn_value(32, &self.self_addr),
            bytesn_value(32, &self.signer_addr),
            bytesn_value(32, &self.self_addr),
        ] {
            ValueReprAlignedValue(av).field_repr(&mut outputs);
        }
        let (sk_hi, sk_lo) = b32_slots(&self.sk);
        let (ep_hi, ep_lo) = b32_slots(&self.ep);
        let rand = Fr::from(0x71d_4a1u64);
        let comm_c = transient_commit(&inputs[..], rand);
        ProofPreimage {
            inputs,
            private_transcript: vec![sk_hi, sk_lo, self.cc_rand, ep_hi, ep_lo],
            public_transcript_inputs: transcript,
            public_transcript_outputs: outputs,
            binding_input: 0.into(),
            communications_commitment: Some((comm_c, rand)),
            key_location: KeyLocation(Cow::Borrowed("minocrab-contracts-test")),
        }
    }
}

#[test]
fn withdraw_matches_corpus() {
    let theirs = corpus_zkir_named("withdraw");
    let ours = erc20_vault::withdraw().ir;
    let s = WithdrawScenario::new();
    assert_call_compatible(&ours, &theirs, &s.preimage());
}

#[test]
fn withdraw_rejects_guard_failures() {
    let theirs = corpus_zkir_named("withdraw");
    let ours = erc20_vault::withdraw().ir;

    // Wrong coin color: not the vault token for this ERC20.
    let s = WithdrawScenario::new();
    let mut pi = s.preimage();
    pi.inputs[7] = pi.inputs[7] + Fr::from(1u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: wrong color");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: wrong color");

    // Coin value != amount.
    let s = WithdrawScenario::new();
    let mut pi = s.preimage();
    pi.inputs[9] = pi.inputs[9] + Fr::from(1u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: value mismatch");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: value mismatch");

    // Zero amount.
    let mut s = WithdrawScenario::new();
    s.amount = 0;
    let pi = s.preimage();
    assert!(simulate(&ours, &pi).is_err(), "ours: zero amount");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: zero amount");
}

/// Tampering with any transcript element or witness must be rejected by
/// both artifacts, with zero acceptance disagreements.
#[test]
fn withdraw_rejects_tampering() {
    let theirs = corpus_zkir_named("withdraw");
    let ours = erc20_vault::withdraw().ir;
    let s = WithdrawScenario::new();

    let pi = s.preimage();
    let mut disagreements = 0;
    for i in 0..pi.public_transcript_inputs.len() {
        let mut t = pi.clone();
        t.public_transcript_inputs[i] = t.public_transcript_inputs[i] + Fr::from(1u64);
        let ours_rejects = simulate(&ours, &t).is_err();
        assert!(ours_rejects, "ours accepts tampered transcript element {i}");
        if ours_rejects != simulate(&theirs, &t).is_err() {
            disagreements += 1;
        }
    }
    for i in 0..pi.private_transcript.len() {
        let mut t = pi.clone();
        t.private_transcript[i] = t.private_transcript[i] + Fr::from(1u64);
        let ours_rejects = simulate(&ours, &t).is_err();
        assert!(ours_rejects, "ours accepts tampered witness {i}");
        if ours_rejects != simulate(&theirs, &t).is_err() {
            disagreements += 1;
        }
    }
    assert_eq!(disagreements, 0, "acceptance disagreement on tampering");
}

// --- completeWithdraw --------------------------------------------------------

/// A concrete completeWithdraw() call settling WithdrawScenario's pending
/// withdrawal.
struct CompleteWithdrawScenario {
    w: WithdrawScenario,
    /// The attested EVM outcome byte (0x01 success / 0x00 refund).
    outcome: u8,
    mint_nonce: [u8; 32],
    own_pk: [u8; 32],
    key_seed: u64,
    nonce_seed: u64,
}

impl CompleteWithdrawScenario {
    fn new(outcome: u8) -> CompleteWithdrawScenario {
        let mut mint_nonce = [0u8; 32];
        mint_nonce[..12].copy_from_slice(b"refund-nonce");
        mint_nonce[31] = 0x61;
        let mut own_pk = [0u8; 32];
        own_pk[..9].copy_from_slice(b"refund-pk");
        own_pk[31] = 0x62;
        CompleteWithdrawScenario {
            w: WithdrawScenario::new(),
            outcome,
            mint_nonce,
            own_pk,
            key_seed: 0xf00d_face,
            nonce_seed: 0x0dd_b17,
        }
    }

    fn refunding(&self) -> bool {
        self.outcome == 0
    }

    fn mpc_key_av(&self) -> AlignedValue {
        let generator = IrValue::Secp256k1Point(k256::K256::generator());
        let key = ec_mul_offcircuit(&generator, &scalar(self.key_seed)).unwrap();
        let alignment = Alignment(
            erc20_vault::secp256k1_point_atoms()
                .into_iter()
                .map(AlignmentSegment::Atom)
                .collect(),
        );
        alignment
            .parse_field_repr(&natives(&key))
            .expect("point limbs match the alignment")
    }

    fn signature_be(&self) -> ([u8; 32], [u8; 32]) {
        let mut bytes = self.w.request_id().to_vec();
        bytes.push(self.outcome);
        let digest: [u8; 32] = sha3::Keccak256::digest(&bytes).into();
        let (mut r_le, mut s_le, _) = sign(&digest, &scalar(self.key_seed), &scalar(self.nonce_seed));
        r_le.reverse();
        s_le.reverse();
        (r_le, s_le)
    }

    fn inputs(&self) -> Vec<Fr> {
        let (rid_hi, rid_lo) = b32_slots(&self.w.request_id());
        let (rx, sx) = self.signature_be();
        let (rx_hi, rx_lo) = b32_slots(&rx);
        let (s_hi, s_lo) = b32_slots(&sx);
        let (n_hi, n_lo) = b32_slots(&self.mint_nonce);
        vec![
            rid_hi,
            rid_lo,
            rx_hi,
            rx_lo,
            Fr::from(0u64),
            Fr::from(0u64),
            s_hi,
            s_lo,
            Fr::from(0u64),
            Fr::from(u64::from(self.outcome)),
            n_hi,
            n_lo,
        ]
    }

    fn witnesses(&self) -> Vec<Fr> {
        if !self.refunding() {
            return vec![];
        }
        let (sk_hi, sk_lo) = b32_slots(&self.w.sk);
        let (pk_hi, pk_lo) = b32_slots(&self.own_pk);
        vec![sk_hi, sk_lo, pk_hi, pk_lo]
    }

    fn preimage(&self) -> ProofPreimage {
        let field_key = |i: u8| Key::Value(bytesn_value(1, &[i]));
        let request_id = self.w.request_id();

        let mut ops = vec![
            // assert(initialized >= 1)
            Op::Dup { n: 0 },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![field_key(erc20_vault::INITIALIZED)].into(),
            },
            Op::Popeq {
                cached: true,
                result: bytesn_value(8, &self.w.initialized.to_le_bytes()),
            },
            // mpcResponseKey
            Op::Dup { n: 0 },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![field_key(erc20_vault::MPC_RESPONSE_KEY)].into(),
            },
            Op::Popeq {
                cached: false,
                result: self.mpc_key_av(),
            },
            // refundCommitment.member(requestId)
            Op::Dup { n: 0 },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![field_key(erc20_vault::REFUND_COMMITMENT)].into(),
            },
            Op::Push {
                storage: false,
                value: cell(bytesn_value(32, &request_id)),
            },
            Op::Member,
            Op::Popeq {
                cached: true,
                result: bytesn_value(1, &[1]),
            },
            // signBidirectionalEventMap.lookup + remove
            Op::Dup { n: 0 },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![field_key(erc20_vault::SIGN_BIDIRECTIONAL_EVENT_MAP)].into(),
            },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![Key::Value(bytesn_value(32, &request_id))].into(),
            },
            Op::Popeq {
                cached: false,
                result: self.w.event_av(),
            },
            Op::Idx {
                cached: false,
                push_path: true,
                path: vec![field_key(erc20_vault::SIGN_BIDIRECTIONAL_EVENT_MAP)].into(),
            },
            Op::Push {
                storage: false,
                value: cell(bytesn_value(32, &request_id)),
            },
            Op::Rem { cached: false },
            Op::Ins { cached: true, n: 1 },
        ];
        if self.refunding() {
            // refundCommitment.lookup (guarded branch)
            ops.extend([
                Op::Dup { n: 0 },
                Op::Idx {
                    cached: false,
                    push_path: false,
                    path: vec![field_key(erc20_vault::REFUND_COMMITMENT)].into(),
                },
                Op::Idx {
                    cached: false,
                    push_path: false,
                    path: vec![Key::Value(bytesn_value(32, &request_id))].into(),
                },
                Op::Popeq {
                    cached: false,
                    result: bytesn_value(32, &self.w.refund_commitment()),
                },
                // mint's kernel.self
                Op::Dup { n: 2 },
                Op::Idx {
                    cached: true,
                    push_path: false,
                    path: vec![field_key(0)].into(),
                },
                Op::Popeq {
                    cached: true,
                    result: bytesn_value(32, &self.w.self_addr),
                },
            ]);
            // kernel.mintShielded + claimZswapCoinSpend
            let domain_sep = vault_domain_sep(&self.w.erc20);
            let color = vault_color(&self.w.erc20, &self.w.self_addr);
            let cm = coin_commitment_of(
                &b32_slots(&self.mint_nonce),
                &color,
                self.w.amount,
                true,
                &self.own_pk,
            );
            ops.extend([
                Op::Swap { n: 0 },
                Op::Idx {
                    cached: true,
                    push_path: true,
                    path: vec![field_key(4)].into(),
                },
                Op::Push {
                    storage: false,
                    value: cell(bytesn_value(32, &domain_sep)),
                },
                Op::Dup { n: 1 },
                Op::Dup { n: 1 },
                Op::Member,
                Op::Push {
                    storage: false,
                    value: cell(bytesn_value(8, &self.w.amount.to_le_bytes())),
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
                Op::Swap { n: 0 },
                Op::Idx {
                    cached: true,
                    push_path: true,
                    path: vec![field_key(2)].into(),
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
            ]);
        }
        // refundCommitment.remove(requestId) — unguarded tail.
        ops.extend([
            Op::Idx {
                cached: false,
                push_path: true,
                path: vec![field_key(erc20_vault::REFUND_COMMITMENT)].into(),
            },
            Op::Push {
                storage: false,
                value: cell(bytesn_value(32, &request_id)),
            },
            Op::Rem { cached: false },
            Op::Ins { cached: true, n: 1 },
        ]);

        let inputs = self.inputs();
        let mut transcript = Vec::new();
        for op in ops {
            op.field_repr(&mut transcript);
        }
        let mut avs = vec![
            bytesn_value(8, &self.w.initialized.to_le_bytes()),
            self.mpc_key_av(),
            bytesn_value(1, &[1]),
            self.w.event_av(),
        ];
        if self.refunding() {
            avs.push(bytesn_value(32, &self.w.refund_commitment()));
            avs.push(bytesn_value(32, &self.w.self_addr));
        }
        let mut outputs = Vec::new();
        for av in avs {
            ValueReprAlignedValue(av).field_repr(&mut outputs);
        }
        let rand = Fr::from(0xc0417u64);
        let comm_c = transient_commit(&inputs[..], rand);
        ProofPreimage {
            inputs,
            private_transcript: self.witnesses(),
            public_transcript_inputs: transcript,
            public_transcript_outputs: outputs,
            binding_input: 0.into(),
            communications_commitment: Some((comm_c, rand)),
            key_location: KeyLocation(Cow::Borrowed("minocrab-contracts-test")),
        }
    }
}

/// Attested success: no refund, cleanup only.
#[test]
fn complete_withdraw_success_matches_corpus() {
    let theirs = corpus_zkir_named("completeWithdraw");
    let ours = erc20_vault::complete_withdraw().ir;
    let s = CompleteWithdrawScenario::new(1);
    assert_call_compatible(&ours, &theirs, &s.preimage());
}

/// Attested false return: the guarded refund branch fires.
#[test]
fn complete_withdraw_refund_matches_corpus() {
    let theirs = corpus_zkir_named("completeWithdraw");
    let ours = erc20_vault::complete_withdraw().ir;
    let s = CompleteWithdrawScenario::new(0);
    assert_call_compatible(&ours, &theirs, &s.preimage());
}

#[test]
fn complete_withdraw_rejects_guard_failures() {
    let theirs = corpus_zkir_named("completeWithdraw");
    let ours = erc20_vault::complete_withdraw().ir;

    // Bad attestation signature.
    let s = CompleteWithdrawScenario::new(1);
    let mut pi = s.preimage();
    pi.inputs[7] = pi.inputs[7] + Fr::from(1u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: bad signature");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: bad signature");

    // Not the withdrawer: wrong secret on the refund path.
    let s = CompleteWithdrawScenario::new(0);
    let mut pi = s.preimage();
    pi.private_transcript[0] = pi.private_transcript[0] + Fr::from(1u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: not the withdrawer");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: not the withdrawer");
}

/// Tamper sweep over the refund-path transcript.
#[test]
fn complete_withdraw_rejects_tampering() {
    let theirs = corpus_zkir_named("completeWithdraw");
    let ours = erc20_vault::complete_withdraw().ir;
    let s = CompleteWithdrawScenario::new(0);

    let pi = s.preimage();
    let mut disagreements = 0;
    for i in 0..pi.public_transcript_inputs.len() {
        let mut t = pi.clone();
        t.public_transcript_inputs[i] = t.public_transcript_inputs[i] + Fr::from(1u64);
        let ours_rejects = simulate(&ours, &t).is_err();
        assert!(ours_rejects, "ours accepts tampered transcript element {i}");
        if ours_rejects != simulate(&theirs, &t).is_err() {
            disagreements += 1;
        }
    }
    assert_eq!(disagreements, 0, "acceptance disagreement on tampering");
}

// --- swap --------------------------------------------------------------------

fn abi_addr_word(addr: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(addr);
    w
}

fn abi_num_word(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

fn schema_slots(schema: &[u8]) -> (Fr, Fr) {
    (
        Fr::from_le_bytes(&schema[31..]).unwrap(),
        Fr::from_le_bytes(&schema[..31]).unwrap(),
    )
}

/// A concrete swap() call.
struct SwapScenario {
    evm_nonce: u64,
    key_version: u8,
    token_in: [u8; 20],
    token_out: [u8; 20],
    fee: u32,
    amount_out: u64,
    amount_in_max: u64,
    coin_nonce: [u8; 32],
    sk: [u8; 32],
    initialized: u64,
    vault_evm: [u8; 20],
    chain_id: u64,
    router: [u8; 20],
    request_nonce: u64,
    self_addr: [u8; 32],
    caip2: [u8; 32],
    signer_addr: [u8; 32],
    ep: [u8; 32],
    cc_rand: Fr,
}

impl SwapScenario {
    fn new() -> SwapScenario {
        let d = DepositScenario::new();
        let mut coin_nonce = [0u8; 32];
        coin_nonce[..10].copy_from_slice(b"swap-nonce");
        coin_nonce[31] = 0x71;
        SwapScenario {
            evm_nonce: 13,
            key_version: 1,
            token_in: d.erc20,
            token_out: *b"erc20-token-outward!",
            fee: 3000,
            amount_out: 77_777,
            amount_in_max: 99_999,
            coin_nonce,
            sk: d.sk,
            initialized: 1,
            vault_evm: d.vault_evm,
            chain_id: d.chain_id,
            router: *b"uniswap-router-20byt",
            request_nonce: 7,
            self_addr: d.self_addr,
            caip2: d.caip2,
            signer_addr: d.signer_addr,
            ep: d.ep,
            cc_rand: Fr::from(0x54a9u64),
        }
    }

    fn event_alignment7() -> Alignment {
        Alignment(
            [
                32u32, 8, 1, 32, 1, 1, 64, 1, // header
                8, 8, 16, 16, 8, 20, 16, // envelope
                1, 4, 2, 32, 32, 32, 32, 32, 32, 32, // Maybe tag + 7-word calldata
                1,  // accessListEntryCount
                32, 38, 37, // caip2Id + schemas
            ]
            .into_iter()
            .map(atom)
            .collect(),
        )
    }

    fn event_limbs(&self) -> Vec<Fr> {
        let (self_hi, self_lo) = b32_slots(&self.self_addr);
        let (path_hi, path_lo) = b32_slots(&pad32(erc20_vault::VAULT_PATH));
        let (caip2_hi, caip2_lo) = b32_slots(&self.caip2);
        let words = [
            abi_addr_word(&self.token_in),
            abi_addr_word(&self.token_out),
            abi_num_word(u128::from(self.fee)),
            abi_addr_word(&self.vault_evm),
            abi_num_word(u128::from(self.amount_out)),
            abi_num_word(u128::from(self.amount_in_max)),
            [0u8; 32],
        ];
        let (out_hi, out_lo) = schema_slots(erc20_vault::SWAP_OUTPUT_SCHEMA);
        let (re_hi, re_lo) = schema_slots(erc20_vault::SWAP_RESPOND_SCHEMA);
        let mut limbs = vec![
            self_hi,
            self_lo,
            Fr::from(self.request_nonce),
            Fr::from(u64::from(self.key_version)),
            path_hi,
            path_lo,
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(self.chain_id),
            Fr::from(self.evm_nonce),
            Fr::from(1_000_000_000u64),
            Fr::from(30_000_000_000u64),
            Fr::from(700_000u64),
            Fr::from_le_bytes(&self.router).unwrap(),
            Fr::from(0u64),
            Fr::from(1u64),
            Fr::from_le_bytes(&erc20_vault::EXACT_OUTPUT_SINGLE_SELECTOR).unwrap(),
            Fr::from(7u64),
        ];
        for w in &words {
            let (hi, lo) = b32_slots(w);
            limbs.push(hi);
            limbs.push(lo);
        }
        limbs.extend([
            Fr::from(0u64), // accessListEntryCount
            caip2_hi,
            caip2_lo,
            out_hi,
            out_lo,
            re_hi,
            re_lo,
        ]);
        limbs
    }

    fn event_av(&self) -> AlignedValue {
        Self::event_alignment7()
            .parse_field_repr(&self.event_limbs())
            .expect("event limbs match the alignment")
    }

    fn request_id(&self) -> [u8; 32] {
        let mut repr = Vec::new();
        ValueReprAlignedValue(self.event_av()).binary_repr(&mut repr);
        sha3::Keccak256::digest(&repr).into()
    }

    fn refund_commitment(&self) -> [u8; 32] {
        let (p_hi, p_lo) = b32_slots(&pad32(erc20_vault::REFUND_PAD));
        let (sk_hi, sk_lo) = b32_slots(&self.sk);
        let (r_hi, r_lo) = b32_slots(&self.request_id());
        fab_sha256(
            vec![atom(32), atom(32), atom(32)],
            &[p_hi, p_lo, sk_hi, sk_lo, r_hi, r_lo],
        )
    }

    fn call_args(&self) -> Vec<Fr> {
        let (rid_hi, rid_lo) = b32_slots(&self.request_id());
        let mut bytes = [0u8; 128];
        bytes[..32].copy_from_slice(&self.self_addr);
        bytes[32] = 1;
        bytes[33] = 11; // requestsPath [11, 0, 0, 0]
        let mut limbs: Vec<Fr> = bytes
            .chunks(31)
            .map(|chunk| Fr::from_le_bytes(chunk).unwrap())
            .collect();
        limbs.reverse();
        let mut args = vec![rid_hi, rid_lo, Fr::from(1u64)];
        args.extend(limbs);
        args
    }

    fn preimage(&self) -> ProofPreimage {
        let field_key = |i: u8| Key::Value(bytesn_value(1, &[i]));
        let read = |field: u8, cached: bool, result: AlignedValue| {
            vec![
                Op::Dup { n: 0 },
                Op::Idx {
                    cached: false,
                    push_path: false,
                    path: vec![field_key(field)].into(),
                },
                Op::Popeq { cached, result },
            ]
        };
        let kernel_self_ops = |result: &[u8; 32]| {
            vec![
                Op::Dup { n: 2 },
                Op::Idx {
                    cached: true,
                    push_path: false,
                    path: vec![field_key(0)].into(),
                },
                Op::Popeq {
                    cached: true,
                    result: bytesn_value(32, result),
                },
            ]
        };
        let claim = |effect: u8, note: [u8; 32]| {
            vec![
                Op::Swap { n: 0 },
                Op::Idx {
                    cached: true,
                    push_path: true,
                    path: vec![field_key(effect)].into(),
                },
                Op::Push {
                    storage: false,
                    value: cell(bytesn_value(32, &note)),
                },
                Op::Push {
                    storage: false,
                    value: StateValue::Null,
                },
                Op::Ins { cached: true, n: 2 },
                Op::Swap { n: 0 },
            ]
        };

        let request_id = self.request_id();
        let color = vault_color(&self.token_in, &self.self_addr);
        let nonce_slots = b32_slots(&self.coin_nonce);
        let cm_receive =
            coin_commitment_of(&nonce_slots, &color, self.amount_in_max, false, &self.self_addr);
        let nullifier =
            coin_nullifier_of(&nonce_slots, &color, self.amount_in_max, &self.self_addr);
        let cm_burn = coin_commitment_of(
            &evolved_nonce(&self.coin_nonce),
            &color,
            self.amount_in_max,
            true,
            &[0u8; 32],
        );

        let mut ops = Vec::new();
        ops.extend(read(
            erc20_vault::INITIALIZED,
            true,
            bytesn_value(8, &self.initialized.to_le_bytes()),
        ));
        ops.extend(kernel_self_ops(&self.self_addr));
        ops.extend(read(
            erc20_vault::VAULT_EVM_ADDRESS,
            false,
            bytesn_value(20, &self.vault_evm),
        ));
        ops.extend(read(
            erc20_vault::EVM_CHAIN_ID,
            false,
            bytesn_value(8, &self.chain_id.to_le_bytes()),
        ));
        ops.extend(read(
            erc20_vault::UNISWAP_ROUTER,
            false,
            bytesn_value(20, &self.router),
        ));
        ops.extend(read(
            erc20_vault::SIGNET_REQUEST_NONCE,
            true,
            bytesn_value(8, &self.request_nonce.to_le_bytes()),
        ));
        ops.extend(kernel_self_ops(&self.self_addr));
        ops.extend(read(
            erc20_vault::CAIP2_ID,
            false,
            bytesn_value(32, &self.caip2),
        ));
        ops.extend([
            Op::Dup { n: 0 },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![field_key(erc20_vault::SWAP_EVENT_MAP)].into(),
            },
            Op::Push {
                storage: false,
                value: cell(bytesn_value(32, &request_id)),
            },
            Op::Member,
            Op::Popeq {
                cached: true,
                result: bytesn_value(1, &[0]),
            },
        ]);
        ops.extend(kernel_self_ops(&self.self_addr));
        ops.extend(claim(1, cm_receive));
        ops.extend(kernel_self_ops(&self.self_addr));
        ops.extend(claim(0, nullifier));
        ops.extend(claim(2, cm_burn));
        ops.extend([
            Op::Idx {
                cached: false,
                push_path: true,
                path: vec![field_key(erc20_vault::SIGNET_REQUEST_NONCE)].into(),
            },
            Op::Addi { immediate: 1 },
            Op::Ins { cached: true, n: 1 },
            Op::Idx {
                cached: false,
                push_path: true,
                path: vec![field_key(erc20_vault::SWAP_EVENT_MAP)].into(),
            },
            Op::Push {
                storage: false,
                value: cell(bytesn_value(32, &request_id)),
            },
            Op::Push {
                storage: true,
                value: cell(self.event_av()),
            },
            Op::Ins {
                cached: false,
                n: 1,
            },
            Op::Ins { cached: true, n: 1 },
            Op::Idx {
                cached: false,
                push_path: true,
                path: vec![field_key(erc20_vault::SWAP_REFUND_COMMITMENT)].into(),
            },
            Op::Push {
                storage: false,
                value: cell(bytesn_value(32, &request_id)),
            },
            Op::Push {
                storage: true,
                value: cell(bytesn_value(32, &self.refund_commitment())),
            },
            Op::Ins {
                cached: false,
                n: 1,
            },
            Op::Ins { cached: true, n: 1 },
        ]);
        ops.extend(read(
            erc20_vault::SIGNET_SIGNER,
            false,
            bytesn_value(32, &self.signer_addr),
        ));
        ops.extend(kernel_self_ops(&self.self_addr));
        let comm = transient_commit(&self.call_args()[..], self.cc_rand);
        let mut comm_bytes = comm.as_le_bytes();
        while comm_bytes.last() == Some(&0) {
            comm_bytes.pop();
        }
        let addr_ep_comm = AlignedValue::new(
            Value(vec![
                ValueAtom(self.signer_addr.to_vec()).normalize(),
                ValueAtom(self.ep.to_vec()).normalize(),
                ValueAtom(comm_bytes).normalize(),
            ]),
            Alignment(vec![
                atom(32),
                atom(32),
                AlignmentSegment::Atom(AlignmentAtom::Field),
            ]),
        )
        .unwrap();
        ops.extend([
            Op::Swap { n: 0 },
            Op::Idx {
                cached: true,
                push_path: true,
                path: vec![field_key(3)].into(),
            },
            Op::Dup { n: 0 },
            Op::Size,
            Op::Push {
                storage: false,
                value: cell(addr_ep_comm),
            },
            Op::Concat {
                cached: true,
                n: 160,
            },
            Op::Push {
                storage: false,
                value: StateValue::Null,
            },
            Op::Ins { cached: true, n: 2 },
            Op::Swap { n: 0 },
        ]);

        let nonce_slots = b32_slots(&self.coin_nonce);
        let (c_hi, c_lo) = b32_slots(&color);
        let inputs = vec![
            Fr::from(self.evm_nonce),
            Fr::from(u64::from(self.key_version)),
            Fr::from_le_bytes(&self.token_in).unwrap(),
            Fr::from_le_bytes(&self.token_out).unwrap(),
            Fr::from(u64::from(self.fee)),
            Fr::from(self.amount_out),
            Fr::from(self.amount_in_max),
            nonce_slots.0,
            nonce_slots.1,
            c_hi,
            c_lo,
            Fr::from(self.amount_in_max),
        ];
        let mut transcript = Vec::new();
        for op in ops {
            op.field_repr(&mut transcript);
        }
        let mut outputs = Vec::new();
        for av in [
            bytesn_value(8, &self.initialized.to_le_bytes()),
            bytesn_value(32, &self.self_addr),
            bytesn_value(20, &self.vault_evm),
            bytesn_value(8, &self.chain_id.to_le_bytes()),
            bytesn_value(20, &self.router),
            bytesn_value(8, &self.request_nonce.to_le_bytes()),
            bytesn_value(32, &self.self_addr),
            bytesn_value(32, &self.caip2),
            bytesn_value(1, &[0]),
            bytesn_value(32, &self.self_addr),
            bytesn_value(32, &self.self_addr),
            bytesn_value(32, &self.signer_addr),
            bytesn_value(32, &self.self_addr),
        ] {
            ValueReprAlignedValue(av).field_repr(&mut outputs);
        }
        let (sk_hi, sk_lo) = b32_slots(&self.sk);
        let (ep_hi, ep_lo) = b32_slots(&self.ep);
        let rand = Fr::from(0x54a9_1u64);
        let comm_c = transient_commit(&inputs[..], rand);
        ProofPreimage {
            inputs,
            private_transcript: vec![sk_hi, sk_lo, self.cc_rand, ep_hi, ep_lo],
            public_transcript_inputs: transcript,
            public_transcript_outputs: outputs,
            binding_input: 0.into(),
            communications_commitment: Some((comm_c, rand)),
            key_location: KeyLocation(Cow::Borrowed("minocrab-contracts-test")),
        }
    }
}

#[test]
fn swap_matches_corpus() {
    let theirs = corpus_zkir_named("swap");
    let ours = erc20_vault::swap().ir;
    let s = SwapScenario::new();
    assert_call_compatible(&ours, &theirs, &s.preimage());
}

#[test]
fn swap_rejects_guard_failures() {
    let theirs = corpus_zkir_named("swap");
    let ours = erc20_vault::swap().ir;

    // Wrong coin color: not the tokenIn vault token.
    let s = SwapScenario::new();
    let mut pi = s.preimage();
    pi.inputs[9] = pi.inputs[9] + Fr::from(1u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: wrong color");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: wrong color");

    // Coin value != amountInMaximum.
    let s = SwapScenario::new();
    let mut pi = s.preimage();
    pi.inputs[11] = pi.inputs[11] + Fr::from(1u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: value mismatch");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: value mismatch");

    // Zero amountOut.
    let mut s = SwapScenario::new();
    s.amount_out = 0;
    let pi = s.preimage();
    assert!(simulate(&ours, &pi).is_err(), "ours: zero amountOut");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: zero amountOut");
}

// --- completeSwap ------------------------------------------------------------

/// A concrete completeSwap() call settling SwapScenario's pending swap.
struct CompleteSwapScenario {
    s: SwapScenario,
    /// The attested amountIn actually spent (≤ amountInMaximum).
    amount_in: u64,
    mint_nonce: [u8; 32],
    own_pk: [u8; 32],
    key_seed: u64,
    nonce_seed: u64,
}

impl CompleteSwapScenario {
    fn new() -> CompleteSwapScenario {
        let mut mint_nonce = [0u8; 32];
        mint_nonce[..10].copy_from_slice(b"swap-mint!");
        mint_nonce[31] = 0x81;
        let mut own_pk = [0u8; 32];
        own_pk[..7].copy_from_slice(b"swap-pk");
        own_pk[31] = 0x82;
        CompleteSwapScenario {
            s: SwapScenario::new(),
            amount_in: 88_888,
            mint_nonce,
            own_pk,
            key_seed: 0xf00d_face,
            nonce_seed: 0x0dd_b17,
        }
    }

    fn mpc_key_av(&self) -> AlignedValue {
        let generator = IrValue::Secp256k1Point(k256::K256::generator());
        let key = ec_mul_offcircuit(&generator, &scalar(self.key_seed)).unwrap();
        let alignment = Alignment(
            erc20_vault::secp256k1_point_atoms()
                .into_iter()
                .map(AlignmentSegment::Atom)
                .collect(),
        );
        alignment
            .parse_field_repr(&natives(&key))
            .expect("point limbs match the alignment")
    }

    fn signature_be(&self) -> ([u8; 32], [u8; 32]) {
        let mut bytes = self.s.request_id().to_vec();
        bytes.extend(self.amount_in.to_le_bytes());
        let digest: [u8; 32] = sha3::Keccak256::digest(&bytes).into();
        let (mut r_le, mut s_le, _) = sign(&digest, &scalar(self.key_seed), &scalar(self.nonce_seed));
        r_le.reverse();
        s_le.reverse();
        (r_le, s_le)
    }

    /// changeNonce = persistentHash([mintNonce, pad(32, "change")]).
    fn change_nonce(&self) -> [u8; 32] {
        let (n_hi, n_lo) = b32_slots(&self.mint_nonce);
        let (p_hi, p_lo) = b32_slots(&pad32("change"));
        fab_sha256(vec![atom(32), atom(32)], &[n_hi, n_lo, p_hi, p_lo])
    }

    fn preimage(&self) -> ProofPreimage {
        let field_key = |i: u8| Key::Value(bytesn_value(1, &[i]));
        let request_id = self.s.request_id();
        let kernel_self_ops = |result: &[u8; 32]| {
            vec![
                Op::Dup { n: 2 },
                Op::Idx {
                    cached: true,
                    push_path: false,
                    path: vec![field_key(0)].into(),
                },
                Op::Popeq {
                    cached: true,
                    result: bytesn_value(32, result),
                },
            ]
        };
        let mint = |domain_sep: [u8; 32], amount: u64, cm: [u8; 32]| {
            vec![
                Op::Swap { n: 0 },
                Op::Idx {
                    cached: true,
                    push_path: true,
                    path: vec![field_key(4)].into(),
                },
                Op::Push {
                    storage: false,
                    value: cell(bytesn_value(32, &domain_sep)),
                },
                Op::Dup { n: 1 },
                Op::Dup { n: 1 },
                Op::Member,
                Op::Push {
                    storage: false,
                    value: cell(bytesn_value(8, &amount.to_le_bytes())),
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
                Op::Swap { n: 0 },
                Op::Idx {
                    cached: true,
                    push_path: true,
                    path: vec![field_key(2)].into(),
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
        };

        let color_out = vault_color(&self.s.token_out, &self.s.self_addr);
        let color_in = vault_color(&self.s.token_in, &self.s.self_addr);
        let change = self.s.amount_in_max - self.amount_in;
        let cm_out = coin_commitment_of(
            &b32_slots(&self.mint_nonce),
            &color_out,
            self.s.amount_out,
            true,
            &self.own_pk,
        );
        let cm_change = coin_commitment_of(
            &b32_slots(&self.change_nonce()),
            &color_in,
            change,
            true,
            &self.own_pk,
        );

        let mut ops = vec![
            Op::Dup { n: 0 },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![field_key(erc20_vault::INITIALIZED)].into(),
            },
            Op::Popeq {
                cached: true,
                result: bytesn_value(8, &self.s.initialized.to_le_bytes()),
            },
            Op::Dup { n: 0 },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![field_key(erc20_vault::MPC_RESPONSE_KEY)].into(),
            },
            Op::Popeq {
                cached: false,
                result: self.mpc_key_av(),
            },
            Op::Dup { n: 0 },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![field_key(erc20_vault::SWAP_REFUND_COMMITMENT)].into(),
            },
            Op::Push {
                storage: false,
                value: cell(bytesn_value(32, &request_id)),
            },
            Op::Member,
            Op::Popeq {
                cached: true,
                result: bytesn_value(1, &[1]),
            },
            Op::Dup { n: 0 },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![field_key(erc20_vault::SWAP_EVENT_MAP)].into(),
            },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![Key::Value(bytesn_value(32, &request_id))].into(),
            },
            Op::Popeq {
                cached: false,
                result: self.s.event_av(),
            },
            Op::Idx {
                cached: false,
                push_path: true,
                path: vec![field_key(erc20_vault::SWAP_EVENT_MAP)].into(),
            },
            Op::Push {
                storage: false,
                value: cell(bytesn_value(32, &request_id)),
            },
            Op::Rem { cached: false },
            Op::Ins { cached: true, n: 1 },
            Op::Dup { n: 0 },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![field_key(erc20_vault::SWAP_REFUND_COMMITMENT)].into(),
            },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![Key::Value(bytesn_value(32, &request_id))].into(),
            },
            Op::Popeq {
                cached: false,
                result: bytesn_value(32, &self.s.refund_commitment()),
            },
            Op::Idx {
                cached: false,
                push_path: true,
                path: vec![field_key(erc20_vault::SWAP_REFUND_COMMITMENT)].into(),
            },
            Op::Push {
                storage: false,
                value: cell(bytesn_value(32, &request_id)),
            },
            Op::Rem { cached: false },
            Op::Ins { cached: true, n: 1 },
        ];
        ops.extend(kernel_self_ops(&self.s.self_addr));
        ops.extend(mint(
            vault_domain_sep(&self.s.token_out),
            self.s.amount_out,
            cm_out,
        ));
        ops.extend(kernel_self_ops(&self.s.self_addr));
        ops.extend(mint(vault_domain_sep(&self.s.token_in), change, cm_change));

        let (rid_hi, rid_lo) = b32_slots(&request_id);
        let (rx, sx) = self.signature_be();
        let (rx_hi, rx_lo) = b32_slots(&rx);
        let (s_hi, s_lo) = b32_slots(&sx);
        let (n_hi, n_lo) = b32_slots(&self.mint_nonce);
        let inputs = vec![
            rid_hi,
            rid_lo,
            rx_hi,
            rx_lo,
            Fr::from(0u64),
            Fr::from(0u64),
            s_hi,
            s_lo,
            Fr::from(0u64),
            Fr::from(self.amount_in),
            n_hi,
            n_lo,
        ];
        let mut transcript = Vec::new();
        for op in ops {
            op.field_repr(&mut transcript);
        }
        let mut outputs = Vec::new();
        for av in [
            bytesn_value(8, &self.s.initialized.to_le_bytes()),
            self.mpc_key_av(),
            bytesn_value(1, &[1]),
            self.s.event_av(),
            bytesn_value(32, &self.s.refund_commitment()),
            bytesn_value(32, &self.s.self_addr),
            bytesn_value(32, &self.s.self_addr),
        ] {
            ValueReprAlignedValue(av).field_repr(&mut outputs);
        }
        let (sk_hi, sk_lo) = b32_slots(&self.s.sk);
        let (pk_hi, pk_lo) = b32_slots(&self.own_pk);
        let rand = Fr::from(0xc054a9u64);
        let comm_c = transient_commit(&inputs[..], rand);
        ProofPreimage {
            inputs,
            private_transcript: vec![sk_hi, sk_lo, pk_hi, pk_lo],
            public_transcript_inputs: transcript,
            public_transcript_outputs: outputs,
            binding_input: 0.into(),
            communications_commitment: Some((comm_c, rand)),
            key_location: KeyLocation(Cow::Borrowed("minocrab-contracts-test")),
        }
    }
}

#[test]
fn complete_swap_matches_corpus() {
    let theirs = corpus_zkir_named("completeSwap");
    let ours = erc20_vault::complete_swap().ir;
    let s = CompleteSwapScenario::new();
    assert_call_compatible(&ours, &theirs, &s.preimage());
}

/// Exact spend: change is 0 (a harmless 0-value coin).
#[test]
fn complete_swap_exact_spend_matches_corpus() {
    let theirs = corpus_zkir_named("completeSwap");
    let ours = erc20_vault::complete_swap().ir;
    let mut s = CompleteSwapScenario::new();
    s.amount_in = s.s.amount_in_max;
    assert_call_compatible(&ours, &theirs, &s.preimage());
}

#[test]
fn complete_swap_rejects_guard_failures() {
    let theirs = corpus_zkir_named("completeSwap");
    let ours = erc20_vault::complete_swap().ir;

    // Bad attestation signature.
    let s = CompleteSwapScenario::new();
    let mut pi = s.preimage();
    pi.inputs[7] = pi.inputs[7] + Fr::from(1u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: bad signature");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: bad signature");

    // Not the swapper.
    let s = CompleteSwapScenario::new();
    let mut pi = s.preimage();
    pi.private_transcript[0] = pi.private_transcript[0] + Fr::from(1u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: not the swapper");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: not the swapper");
}

/// Tamper sweep.
#[test]
fn complete_swap_rejects_tampering() {
    let theirs = corpus_zkir_named("completeSwap");
    let ours = erc20_vault::complete_swap().ir;
    let s = CompleteSwapScenario::new();

    let pi = s.preimage();
    let mut disagreements = 0;
    for i in 0..pi.public_transcript_inputs.len() {
        let mut t = pi.clone();
        t.public_transcript_inputs[i] = t.public_transcript_inputs[i] + Fr::from(1u64);
        let ours_rejects = simulate(&ours, &t).is_err();
        assert!(ours_rejects, "ours accepts tampered transcript element {i}");
        if ours_rejects != simulate(&theirs, &t).is_err() {
            disagreements += 1;
        }
    }
    assert_eq!(disagreements, 0, "acceptance disagreement on tampering");
}

// --- refund ------------------------------------------------------------------

/// Which pending request the refund settles.
enum RefundRoute {
    Withdrawal(WithdrawScenario),
    Swap(SwapScenario),
}

/// A concrete refund() call (the MPC attested the fixed failure output).
struct RefundScenario {
    route: RefundRoute,
    mint_nonce: [u8; 32],
    own_pk: [u8; 32],
    key_seed: u64,
    nonce_seed: u64,
}

impl RefundScenario {
    fn new(route: RefundRoute) -> RefundScenario {
        let mut mint_nonce = [0u8; 32];
        mint_nonce[..11].copy_from_slice(b"never-nonce");
        mint_nonce[31] = 0x91;
        let mut own_pk = [0u8; 32];
        own_pk[..8].copy_from_slice(b"never-pk");
        own_pk[31] = 0x92;
        RefundScenario {
            route,
            mint_nonce,
            own_pk,
            key_seed: 0xf00d_face,
            nonce_seed: 0x0dd_b17,
        }
    }

    fn request_id(&self) -> [u8; 32] {
        match &self.route {
            RefundRoute::Withdrawal(w) => w.request_id(),
            RefundRoute::Swap(s) => s.request_id(),
        }
    }

    fn sk(&self) -> [u8; 32] {
        match &self.route {
            RefundRoute::Withdrawal(w) => w.sk,
            RefundRoute::Swap(s) => s.sk,
        }
    }

    fn mpc_key_av(&self) -> AlignedValue {
        let generator = IrValue::Secp256k1Point(k256::K256::generator());
        let key = ec_mul_offcircuit(&generator, &scalar(self.key_seed)).unwrap();
        let alignment = Alignment(
            erc20_vault::secp256k1_point_atoms()
                .into_iter()
                .map(AlignmentSegment::Atom)
                .collect(),
        );
        alignment
            .parse_field_repr(&natives(&key))
            .expect("point limbs match the alignment")
    }

    fn signature_be(&self) -> ([u8; 32], [u8; 32]) {
        let mut bytes = self.request_id().to_vec();
        bytes.extend(erc20_vault::MPC_FAILURE_OUTPUT);
        let digest: [u8; 32] = sha3::Keccak256::digest(&bytes).into();
        let (mut r_le, mut s_le, _) = sign(&digest, &scalar(self.key_seed), &scalar(self.nonce_seed));
        r_le.reverse();
        s_le.reverse();
        (r_le, s_le)
    }

    fn preimage(&self) -> ProofPreimage {
        let field_key = |i: u8| Key::Value(bytesn_value(1, &[i]));
        let request_id = self.request_id();
        let kernel_self_ops = |result: &[u8; 32]| {
            vec![
                Op::Dup { n: 2 },
                Op::Idx {
                    cached: true,
                    push_path: false,
                    path: vec![field_key(0)].into(),
                },
                Op::Popeq {
                    cached: true,
                    result: bytesn_value(32, result),
                },
            ]
        };
        let mint = |domain_sep: [u8; 32], amount: u64, cm: [u8; 32]| {
            vec![
                Op::Swap { n: 0 },
                Op::Idx {
                    cached: true,
                    push_path: true,
                    path: vec![field_key(4)].into(),
                },
                Op::Push {
                    storage: false,
                    value: cell(bytesn_value(32, &domain_sep)),
                },
                Op::Dup { n: 1 },
                Op::Dup { n: 1 },
                Op::Member,
                Op::Push {
                    storage: false,
                    value: cell(bytesn_value(8, &amount.to_le_bytes())),
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
                Op::Swap { n: 0 },
                Op::Idx {
                    cached: true,
                    push_path: true,
                    path: vec![field_key(2)].into(),
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
        };
        let remove = |field: u8| {
            vec![
                Op::Idx {
                    cached: false,
                    push_path: true,
                    path: vec![field_key(field)].into(),
                },
                Op::Push {
                    storage: false,
                    value: cell(bytesn_value(32, &request_id)),
                },
                Op::Rem { cached: false },
                Op::Ins { cached: true, n: 1 },
            ]
        };
        let lookup = |field: u8, result: AlignedValue| {
            vec![
                Op::Dup { n: 0 },
                Op::Idx {
                    cached: false,
                    push_path: false,
                    path: vec![field_key(field)].into(),
                },
                Op::Idx {
                    cached: false,
                    push_path: false,
                    path: vec![Key::Value(bytesn_value(32, &request_id))].into(),
                },
                Op::Popeq {
                    cached: false,
                    result,
                },
            ]
        };
        let member = |field: u8, result: u8| {
            vec![
                Op::Dup { n: 0 },
                Op::Idx {
                    cached: false,
                    push_path: false,
                    path: vec![field_key(field)].into(),
                },
                Op::Push {
                    storage: false,
                    value: cell(bytesn_value(32, &request_id)),
                },
                Op::Member,
                Op::Popeq {
                    cached: true,
                    result: bytesn_value(1, &[result]),
                },
            ]
        };

        let initialized: u64 = 1;
        let mut ops = vec![
            Op::Dup { n: 0 },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![field_key(erc20_vault::INITIALIZED)].into(),
            },
            Op::Popeq {
                cached: true,
                result: bytesn_value(8, &initialized.to_le_bytes()),
            },
            Op::Dup { n: 0 },
            Op::Idx {
                cached: false,
                push_path: false,
                path: vec![field_key(erc20_vault::MPC_RESPONSE_KEY)].into(),
            },
            Op::Popeq {
                cached: false,
                result: self.mpc_key_av(),
            },
        ];
        let mut avs = vec![
            bytesn_value(8, &initialized.to_le_bytes()),
            self.mpc_key_av(),
        ];
        match &self.route {
            RefundRoute::Withdrawal(w) => {
                ops.extend(member(erc20_vault::REFUND_COMMITMENT, 1));
                avs.push(bytesn_value(1, &[1]));
                ops.extend(lookup(erc20_vault::SIGN_BIDIRECTIONAL_EVENT_MAP, w.event_av()));
                avs.push(w.event_av());
                ops.extend(remove(erc20_vault::SIGN_BIDIRECTIONAL_EVENT_MAP));
                ops.extend(lookup(
                    erc20_vault::REFUND_COMMITMENT,
                    bytesn_value(32, &w.refund_commitment()),
                ));
                avs.push(bytesn_value(32, &w.refund_commitment()));
                ops.extend(kernel_self_ops(&w.self_addr));
                avs.push(bytesn_value(32, &w.self_addr));
                let color = vault_color(&w.erc20, &w.self_addr);
                let cm = coin_commitment_of(
                    &b32_slots(&self.mint_nonce),
                    &color,
                    w.amount,
                    true,
                    &self.own_pk,
                );
                ops.extend(mint(vault_domain_sep(&w.erc20), w.amount, cm));
                ops.extend(remove(erc20_vault::REFUND_COMMITMENT));
            }
            RefundRoute::Swap(s) => {
                ops.extend(member(erc20_vault::REFUND_COMMITMENT, 0));
                avs.push(bytesn_value(1, &[0]));
                ops.extend(member(erc20_vault::SWAP_REFUND_COMMITMENT, 1));
                avs.push(bytesn_value(1, &[1]));
                ops.extend(lookup(erc20_vault::SWAP_EVENT_MAP, s.event_av()));
                avs.push(s.event_av());
                ops.extend(remove(erc20_vault::SWAP_EVENT_MAP));
                ops.extend(lookup(
                    erc20_vault::SWAP_REFUND_COMMITMENT,
                    bytesn_value(32, &s.refund_commitment()),
                ));
                avs.push(bytesn_value(32, &s.refund_commitment()));
                ops.extend(remove(erc20_vault::SWAP_REFUND_COMMITMENT));
                ops.extend(kernel_self_ops(&s.self_addr));
                avs.push(bytesn_value(32, &s.self_addr));
                let color = vault_color(&s.token_in, &s.self_addr);
                let cm = coin_commitment_of(
                    &b32_slots(&self.mint_nonce),
                    &color,
                    s.amount_in_max,
                    true,
                    &self.own_pk,
                );
                ops.extend(mint(vault_domain_sep(&s.token_in), s.amount_in_max, cm));
            }
        }

        let (rid_hi, rid_lo) = b32_slots(&request_id);
        let (rx, sx) = self.signature_be();
        let (rx_hi, rx_lo) = b32_slots(&rx);
        let (s_hi, s_lo) = b32_slots(&sx);
        let (n_hi, n_lo) = b32_slots(&self.mint_nonce);
        let inputs = vec![
            rid_hi,
            rid_lo,
            rx_hi,
            rx_lo,
            Fr::from(0u64),
            Fr::from(0u64),
            s_hi,
            s_lo,
            Fr::from(0u64),
            Fr::from_le_bytes(&erc20_vault::MPC_FAILURE_OUTPUT).unwrap(),
            n_hi,
            n_lo,
        ];
        let mut transcript = Vec::new();
        for op in ops {
            op.field_repr(&mut transcript);
        }
        let mut outputs = Vec::new();
        for av in avs {
            ValueReprAlignedValue(av).field_repr(&mut outputs);
        }
        let (sk_hi, sk_lo) = b32_slots(&self.sk());
        let (pk_hi, pk_lo) = b32_slots(&self.own_pk);
        let rand = Fr::from(0xde5_e77_1eu64);
        let comm_c = transient_commit(&inputs[..], rand);
        ProofPreimage {
            inputs,
            private_transcript: vec![sk_hi, sk_lo, pk_hi, pk_lo],
            public_transcript_inputs: transcript,
            public_transcript_outputs: outputs,
            binding_input: 0.into(),
            communications_commitment: Some((comm_c, rand)),
            key_location: KeyLocation(Cow::Borrowed("minocrab-contracts-test")),
        }
    }
}

#[test]
fn refund_withdrawal_matches_corpus() {
    let theirs = corpus_zkir_named("refund");
    let ours = erc20_vault::refund().ir;
    let s = RefundScenario::new(RefundRoute::Withdrawal(WithdrawScenario::new()));
    assert_call_compatible(&ours, &theirs, &s.preimage());
}

#[test]
fn refund_swap_matches_corpus() {
    let theirs = corpus_zkir_named("refund");
    let ours = erc20_vault::refund().ir;
    let s = RefundScenario::new(RefundRoute::Swap(SwapScenario::new()));
    assert_call_compatible(&ours, &theirs, &s.preimage());
}

#[test]
fn refund_rejects_guard_failures() {
    let theirs = corpus_zkir_named("refund");
    let ours = erc20_vault::refund().ir;

    // Not the MPC failure output (an attested 5-byte non-failure value).
    let s = RefundScenario::new(RefundRoute::Withdrawal(WithdrawScenario::new()));
    let mut pi = s.preimage();
    pi.inputs[9] = Fr::from(0x0102030405u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: not the failure output");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: not the failure output");

    // Not the withdrawer.
    let s = RefundScenario::new(RefundRoute::Withdrawal(WithdrawScenario::new()));
    let mut pi = s.preimage();
    pi.private_transcript[0] = pi.private_transcript[0] + Fr::from(1u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: not the withdrawer");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: not the withdrawer");

    // Not the swapper.
    let s = RefundScenario::new(RefundRoute::Swap(SwapScenario::new()));
    let mut pi = s.preimage();
    pi.private_transcript[0] = pi.private_transcript[0] + Fr::from(1u64);
    assert!(simulate(&ours, &pi).is_err(), "ours: not the swapper");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: not the swapper");
}

/// Tamper sweep over both routes' transcripts.
#[test]
fn refund_rejects_tampering() {
    let theirs = corpus_zkir_named("refund");
    let ours = erc20_vault::refund().ir;

    for route in [
        RefundScenario::new(RefundRoute::Withdrawal(WithdrawScenario::new())),
        RefundScenario::new(RefundRoute::Swap(SwapScenario::new())),
    ] {
        let pi = route.preimage();
        let mut disagreements = 0;
        for i in 0..pi.public_transcript_inputs.len() {
            let mut t = pi.clone();
            t.public_transcript_inputs[i] = t.public_transcript_inputs[i] + Fr::from(1u64);
            let ours_rejects = simulate(&ours, &t).is_err();
            assert!(ours_rejects, "ours accepts tampered transcript element {i}");
            if ours_rejects != simulate(&theirs, &t).is_err() {
                disagreements += 1;
            }
        }
        assert_eq!(disagreements, 0, "acceptance disagreement on tampering");
    }
}

#[test]
fn approve_router_matches_corpus() {
    let theirs = corpus_zkir_named("approveRouter");
    let ours = erc20_vault::approve_router().ir;
    let s = ApproveScenario::new();
    assert_call_compatible(&ours, &theirs, &s.preimage());
}

#[test]
fn approve_router_rejects_guard_failures() {
    let theirs = corpus_zkir_named("approveRouter");
    let ours = erc20_vault::approve_router().ir;

    // Not initialized.
    let mut s = ApproveScenario::new();
    s.initialized = 0;
    let pi = s.preimage();
    assert!(simulate(&ours, &pi).is_err(), "ours: not initialized");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: not initialized");

    // Zero ERC20.
    let mut s = ApproveScenario::new();
    s.erc20 = [0u8; 20];
    let pi = s.preimage();
    assert!(simulate(&ours, &pi).is_err(), "ours: zero erc20");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: zero erc20");
}

#[test]
fn deposit_matches_corpus() {
    let theirs = corpus_zkir_named("deposit");
    let ours = erc20_vault::deposit().ir;
    let s = DepositScenario::new();
    assert_call_compatible(&ours, &theirs, &s.preimage());
}

/// Guard failures must be rejected by BOTH artifacts.
#[test]
fn deposit_rejects_guard_failures() {
    let theirs = corpus_zkir_named("deposit");
    let ours = erc20_vault::deposit().ir;

    // Not initialized.
    let mut s = DepositScenario::new();
    s.initialized = 0;
    let pi = s.preimage();
    assert!(simulate(&ours, &pi).is_err(), "ours: not initialized");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: not initialized");

    // Zero ERC20 address.
    let mut s = DepositScenario::new();
    s.erc20 = [0u8; 20];
    let pi = s.preimage();
    assert!(simulate(&ours, &pi).is_err(), "ours: zero erc20");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: zero erc20");

    // Zero amount.
    let mut s = DepositScenario::new();
    s.amount = 0;
    let pi = s.preimage();
    assert!(simulate(&ours, &pi).is_err(), "ours: zero amount");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: zero amount");

    // Zero gas limit.
    let mut s = DepositScenario::new();
    s.gas_limit = 0;
    let pi = s.preimage();
    assert!(simulate(&ours, &pi).is_err(), "ours: zero gas limit");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: zero gas limit");

    // keyVersion 0.
    let mut s = DepositScenario::new();
    s.key_version = 0;
    let pi = s.preimage();
    assert!(simulate(&ours, &pi).is_err(), "ours: keyVersion 0");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: keyVersion 0");

    // Request already exists (member reads back true).
    let s = DepositScenario::new();
    let mut pi = s.preimage();
    // The member popeq result is output element index 6 in read order:
    // init(1) + vaultEvm(1) + chainId(1) + nonce(1) + self(2) + caip2(2) = 8.
    assert_eq!(pi.public_transcript_outputs[8], Fr::from(0u64));
    pi.public_transcript_outputs[8] = Fr::from(1u64);
    // The transcript's member popeq must agree with the flipped output.
    let mut s2 = DepositScenario::new();
    s2.initialized = s.initialized;
    let mut transcript = Vec::new();
    let mut ops = s2.ops();
    for op in &mut ops {
        if let Op::Popeq { result, .. } = op {
            if *result == bytesn_value(1, &[0]) {
                *result = bytesn_value(1, &[1]);
            }
        }
        op.field_repr(&mut transcript);
    }
    pi.public_transcript_inputs = transcript;
    assert!(simulate(&ours, &pi).is_err(), "ours: request exists");
    assert!(simulate(&theirs, &pi).is_err(), "corpus: request exists");
}

/// Tampering with any transcript element or witness must be rejected by
/// both artifacts, with zero acceptance disagreements.
#[test]
fn deposit_rejects_tampering() {
    let theirs = corpus_zkir_named("deposit");
    let ours = erc20_vault::deposit().ir;
    let s = DepositScenario::new();

    let pi = s.preimage();
    let mut disagreements = 0;
    for i in 0..pi.public_transcript_inputs.len() {
        let mut t = pi.clone();
        t.public_transcript_inputs[i] = t.public_transcript_inputs[i] + Fr::from(1u64);
        let ours_rejects = simulate(&ours, &t).is_err();
        assert!(ours_rejects, "ours accepts tampered transcript element {i}");
        if ours_rejects != simulate(&theirs, &t).is_err() {
            disagreements += 1;
        }
    }
    for i in 0..pi.private_transcript.len() {
        let mut t = pi.clone();
        t.private_transcript[i] = t.private_transcript[i] + Fr::from(1u64);
        let ours_rejects = simulate(&ours, &t).is_err();
        assert!(ours_rejects, "ours accepts tampered witness {i}");
        if ours_rejects != simulate(&theirs, &t).is_err() {
            disagreements += 1;
        }
    }
    assert_eq!(disagreements, 0, "acceptance disagreement on tampering");
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
