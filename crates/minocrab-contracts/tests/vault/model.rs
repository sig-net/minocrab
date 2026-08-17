//! The erc20-vault REFERENCE MODEL: per-circuit scenarios that carry a
//! concrete pre-state plus the arguments and witnesses of one call, and
//! emit the Impact op stream, the popeq results and the `ProofPreimage`
//! that stream implies.
//!
//! One model, three consumers: the differential suite (PI-equality against
//! compactc's artifacts), the property harness (spec agreement at scale),
//! and the adversarial sweeps. Moved verbatim out of
//! `erc20_vault_differential.rs` in M10 step 1 — the builders were already
//! the reference model, they were just private to one test binary.
//!
//! Since M10 step 4 every scenario also carries the [`Art`] it models:
//! `Art::Compat` reproduces the direct ports, `Art::Opt` the optimized fork
//! and `Art::Borsh` the M11 fork OF that fork (which inherits every M10
//! rung, so it shares the optimized op stream — the artifact-dependent
//! branches here ask `art == Art::Compat`, never `== Art::Opt`).
//! `with_art` rebuilds a generated scenario for another artifact, so ONE
//! generated case gates all three. Everything artifact-dependent — the
//! discretionary hash constructions, and from rung (i) the op stream
//! itself — is selected from `self.art`; a scenario that ignored it would
//! show up immediately as a PI mismatch against its own circuit.

use std::borrow::Cow;

use midnight_base_crypto::fab::{
    Alignment, AlignmentAtom, AlignmentSegment, AlignedValue, Value, ValueAtom,
};
use midnight_base_crypto::repr::BinaryHashRepr;
use midnight_curves::k256;
use midnight_onchain_state::state::StateValue;
use midnight_onchain_vm::ops::{Key, Op};
use midnight_transient_crypto::fab::{AlignmentExt, ValueReprAlignedValue};
use midnight_transient_crypto::hash::transient_commit;
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage};
use midnight_transient_crypto::repr::FieldRepr;
use midnight_zkir_v3::ir_instructions::ec_mul::ec_mul_offcircuit;
use minocrab::Fr;
use minocrab_contracts::{erc20_vault, erc20_vault_borsh};
use minocrab_zkir::v3::IrValue;
use sha2::Digest;

use super::prims::*;

/// A response-kind constant as the wire carries it.
///
/// The circuit declares kinds as `u32` (the const-generic parameter of
/// `Tag<K>` and the constants beside it); a Borsh fieldless-enum discriminant
/// is ONE byte, which is what the model puts in the digest preimage and in
/// the argument slot.
pub fn kind(k: u32) -> u8 {
    u8::try_from(k).expect("a Borsh tag is one byte")
}

/// The record's LEADING limbs: M11 stage 7's format-version byte, or nothing.
///
/// The deployed record starts at `sender`; the stage-7 record puts
/// `formatVersion = 0x80` in front of it, so a decoder reads the version
/// before anything else (`signet::RECORD_FORMAT_VERSION`).
pub fn record_head(art: Art) -> Vec<Fr> {
    if art.is_borsh_format() {
        vec![Fr::from(u64::from(
            minocrab_contracts::signet::RECORD_FORMAT_VERSION,
        ))]
    } else {
        vec![]
    }
}

/// The record's TRAILING limbs: M11 stage 7's 1-byte response kind, or the
/// two in-band ABI-JSON schema strings the deployed record carries (two limbs
/// each — a `Bytes<34>`/`Bytes<38>`/`Bytes<37>` is `[hi = byte 31.., lo =
/// bytes 0..31]`).
pub fn record_tail(
    art: Art,
    out_schema: &[u8],
    respond_schema: &[u8],
    response_kind: u32,
) -> Vec<Fr> {
    if art.is_borsh_format() {
        return vec![Fr::from(u64::from(kind(response_kind)))];
    }
    let (out_hi, out_lo) = schema_slots(out_schema);
    let (re_hi, re_lo) = schema_slots(respond_schema);
    vec![out_hi, out_lo, re_hi, re_lo]
}

/// The record's FAB alignment for `words` calldata words: the deployed atom
/// list, or M11 stage 7's — a `bytes<1>` version in front, and ONE `bytes<1>`
/// kind where the two schema atoms were.
pub fn record_alignment(art: Art, words: usize, out_len: u32, respond_len: u32) -> Alignment {
    let mut a: Vec<u32> = Vec::new();
    if art.is_borsh_format() {
        a.push(1); // formatVersion
    }
    a.extend([
        32u32, 8, 1, 32, 1, 1, 64, 1, // header
        8, 8, 16, 16, 8, 20, 16, // envelope
        1, 4, 2, // Maybe tag + calldata head
    ]);
    a.extend(std::iter::repeat_n(32u32, words)); // words
    a.push(1); // accessListEntryCount
    a.push(32); // caip2Id
    if art.is_borsh_format() {
        a.push(1); // responseKind
    } else {
        a.push(out_len);
        a.push(respond_len);
    }
    Alignment(a.into_iter().map(atom).collect())
}

/// The concrete initialize() call every test shares.
#[derive(Clone, Debug)]
pub struct Scenario {
    pub art: Art,
    /// The secret the CALLER witnesses.
    pub sk: [u8; 32],
    /// The secret whose commitment is STORED in the `deployer` field. Equal
    /// to `sk` when the deployer gate should pass. Stored as the secret
    /// rather than as the digest so the scenario survives `with_art`: the
    /// commitment construction is discretionary, the deployer's identity is
    /// not.
    pub deployer_sk: [u8; 32],
    pub vault_evm: [u8; 20],
    pub swap_router: [u8; 20],
    pub chain_id: u64,
    pub caip2: [u8; 32],
    pub point: IrValue,
}

impl Scenario {
    /// The same call against the other artifact.
    pub fn with_art(mut self, art: Art) -> Scenario {
        self.art = art;
        self
    }

    /// The commitment the `deployer` field holds.
    pub fn commitment(&self) -> [u8; 32] {
        user_commitment(self.art, &self.deployer_sk)
    }

    pub fn new() -> Scenario {
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
            art: Art::Compat,
            sk,
            deployer_sk: sk,
            vault_evm: *b"vault-evm-addr-20byt",
            swap_router: *b"uniswap-router-20byt",
            chain_id: 11155111,
            caip2,
            point,
        }
    }

    pub fn point_av(&self) -> AlignedValue {
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
    pub fn inputs(&self) -> Vec<Fr> {
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

    pub fn witnesses(&self) -> Vec<Fr> {
        let (hi, lo) = b32_slots(&self.sk);
        vec![hi, lo]
    }

    /// The reference Impact program on a pre-state where
    /// `initialized == count` and `deployer == commitment`.
    pub fn ops(&self, count: u64) -> Vec<VmOp> {
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
                result: bytesn_value(32, &self.commitment()),
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
    pub fn outputs(&self, count: u64) -> Vec<Fr> {
        let mut out = Vec::new();
        for av in [
            bytesn_value(8, &count.to_le_bytes()),
            bytesn_value(32, &self.commitment()),
        ] {
            ValueReprAlignedValue(av).field_repr(&mut out);
        }
        out
    }

    pub fn preimage(&self, count: u64) -> ProofPreimage {
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

// --- deposit -----------------------------------------------------------------

/// A concrete deposit() call: arguments plus the ledger state the reads
/// return (initialized, vaultEvmAddress, evmChainId, signetRequestNonce,
/// kernel.self, caip2Id, signetSigner).
#[derive(Clone, Debug)]
pub struct DepositScenario {
    pub art: Art,
    pub sk: [u8; 32],
    pub evm_nonce: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: u64,
    pub max_priority_fee_per_gas: u64,
    pub key_version: u8,
    pub erc20: [u8; 20],
    /// `Uint<128>` in Compact: widened here so generation can reach the
    /// `> u64::MAX` band the `"Amount exceeds Uint<64> max"` guard rejects.
    pub amount: u128,
    // Ledger state.
    pub initialized: u64,
    /// Does `signBidirectionalEventMap` already hold this request id?
    /// Drives both the `member` popeq and the pre-state map.
    pub request_exists: bool,
    pub vault_evm: [u8; 20],
    pub chain_id: u64,
    pub request_nonce: u64,
    pub self_addr: [u8; 32],
    pub caip2: [u8; 32],
    pub signer_addr: [u8; 32],
    pub ep: [u8; 32],
    pub cc_rand: Fr,
}

impl DepositScenario {
    /// The same call against the other artifact.
    pub fn with_art(mut self, art: Art) -> DepositScenario {
        self.art = art;
        self
    }

    pub fn new() -> DepositScenario {
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
        // DERIVED from the Signet singleton's circuit name (M12 stage 1);
        // the ep limbs are witnesses, so this is a preimage-only change.
        let ep = minocrab_ledger::ep_hash("signBidirectional");
        DepositScenario {
            art: Art::Compat,
            sk,
            evm_nonce: 7,
            gas_limit: 65_000,
            max_fee_per_gas: 30_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            key_version: 1,
            erc20: *b"erc20-token-contract",
            amount: 123_456,
            initialized: 1,
            request_exists: false,
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
    pub fn word0(&self) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&self.vault_evm);
        w
    }

    /// `numericAbiWord(amount)`: 16 zero bytes + the amount big-endian.
    pub fn word1(&self) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[16..].copy_from_slice(&self.amount.to_be_bytes());
        w
    }

    /// The deposited amount as the `Uint<64>` a claim mints. Only
    /// meaningful once the deposit guards passed (`amount <= u64::MAX`).
    pub fn amount_u64(&self) -> u64 {
        u64::try_from(self.amount).unwrap_or(u64::MAX)
    }

    /// The record's 33 FAB limbs in slot order (the circuit's keccak input
    /// and, parsed against the 24-atom alignment, the map-insert value).
    pub fn event_limbs(&self) -> Vec<Fr> {
        let (self_hi, self_lo) = b32_slots(&self.self_addr);
        let path = user_commitment(self.art, &self.sk);
        let (path_hi, path_lo) = b32_slots(&path);
        let (caip2_hi, caip2_lo) = b32_slots(&self.caip2);
        let (w0_hi, w0_lo) = b32_slots(&self.word0());
        let (w1_hi, w1_lo) = b32_slots(&self.word1());
        let mut limbs = record_head(self.art);
        limbs.extend([
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
        ]);
        limbs.extend(record_tail(
            self.art,
            erc20_vault::VAULT_RESPONSE_SCHEMA,
            erc20_vault::VAULT_RESPONSE_SCHEMA,
            erc20_vault_borsh::RESPONSE_KIND_CLAIM,
        ));
        limbs
    }

    /// The record's FAB alignment: 24 atoms deployed, 24 at stage 7 (a
    /// version atom in, two schema atoms out, a kind atom in).
    pub fn event_alignment(art: Art) -> Alignment {
        record_alignment(
            art,
            erc20_vault::VAULT_WORDS,
            erc20_vault::VAULT_SCHEMA_LEN as u32,
            erc20_vault::VAULT_SCHEMA_LEN as u32,
        )
    }

    /// The record as an AlignedValue (the map-insert's pushed cell).
    pub fn event_av(&self) -> AlignedValue {
        Self::event_alignment(self.art)
            .parse_field_repr(&self.event_limbs())
            .expect("event limbs match the alignment")
    }

    /// `calculateRequestId(request)`: keccak256 of the record's value-only
    /// FAB binary.
    pub fn request_id(&self) -> [u8; 32] {
        let mut repr = Vec::new();
        ValueReprAlignedValue(self.event_av()).binary_repr(&mut repr);
        sha3::Keccak256::digest(&repr).into()
    }

    /// The V1 notification payload: selfAddr ‖ depth=1 ‖ path [0,0,0,0] ‖
    /// zeros, as the 5 `Bytes<128>` limbs in slot order.
    pub fn notification_payload_limbs(&self) -> Vec<Fr> {
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
    pub fn call_args(&self) -> Vec<Fr> {
        let (rid_hi, rid_lo) = b32_slots(&self.request_id());
        let mut args = vec![rid_hi, rid_lo, Fr::from(1u64)];
        args.extend(self.notification_payload_limbs());
        args
    }

    pub fn inputs(&self) -> Vec<Fr> {
        vec![
            Fr::from(self.evm_nonce),
            Fr::from(self.gas_limit),
            Fr::from(self.max_fee_per_gas),
            Fr::from(self.max_priority_fee_per_gas),
            Fr::from(u64::from(self.key_version)),
            Fr::from_le_bytes(&self.erc20).unwrap(),
            Fr::from_le_bytes(&self.amount.to_le_bytes()).unwrap(),
        ]
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (sk_hi, sk_lo) = b32_slots(&self.sk);
        let (ep_hi, ep_lo) = b32_slots(&self.ep);
        vec![sk_hi, sk_lo, self.cc_rand, ep_hi, ep_lo]
    }

    /// The reference Impact program, in the circuit's read/write order.
    pub fn ops(&self) -> Vec<VmOp> {
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
                result: bytesn_value(1, &[u8::from(self.request_exists)]),
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
        // kernel.self() again — the notification's callerAddress. The
        // optimized artifact threads this circuit's first read instead
        // (rung i, avenue 7).
        if self.art == Art::Compat {
            ops.extend(kernel_self_ops(&self.self_addr));
        }
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
    pub fn outputs(&self) -> Vec<Fr> {
        let mut avs = vec![
            bytesn_value(8, &self.initialized.to_le_bytes()),
            bytesn_value(20, &self.vault_evm),
            bytesn_value(8, &self.chain_id.to_le_bytes()),
            bytesn_value(8, &self.request_nonce.to_le_bytes()),
            bytesn_value(32, &self.self_addr),
            bytesn_value(32, &self.caip2),
            bytesn_value(1, &[u8::from(self.request_exists)]),
            bytesn_value(32, &self.signer_addr),
        ];
        if self.art == Art::Compat {
            avs.push(bytesn_value(32, &self.self_addr));
        }
        let mut out = Vec::new();
        for av in avs {
            ValueReprAlignedValue(av).field_repr(&mut out);
        }
        out
    }

    pub fn preimage(&self) -> ProofPreimage {
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

/// Who the minted coin goes to.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ClaimRecipient {
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
#[derive(Clone, Debug)]
pub struct ClaimScenario {
    pub d: DepositScenario,
    /// Does `signBidirectionalEventMap` still hold the request? (The
    /// double-claim gate.)
    pub found: bool,
    pub mint_nonce: [u8; 32],
    pub recipient: ClaimRecipient,
    /// The attested EVM result byte. `deserialize<VaultResponse, 1>` reads
    /// it as `byte == 1`, so only `0x01` is a success. Under `Art::Borsh` it
    /// is the `success` field of a Borsh `VaultResponse`, where anything
    /// outside {0, 1} is REJECTED rather than read as `false`.
    pub serialized_output: u8,
    /// The response KIND byte at offset 0 of the attested output — M11 stage
    /// 5, `Art::Borsh` only. The default is this circuit's own kind; a
    /// different one is an attestation issued for another settle circuit, and
    /// must not settle here.
    pub response_kind: u8,
    /// The secret the CALLER witnesses. `None` = the depositor's own (the
    /// gate passes); `Some(other)` drives the "Not the depositor" guard.
    pub claimant_sk: Option<[u8; 32]>,
    /// MPC response key's secret scalar seed + signature nonce seed.
    pub key_seed: u64,
    pub nonce_seed: u64,
}

impl ClaimScenario {
    /// The artifact this settle models — the deposit it settles owns it,
    /// so the record and the commitment can never disagree.
    pub fn art(&self) -> Art {
        self.d.art
    }

    /// The same call against the other artifact.
    pub fn with_art(mut self, art: Art) -> ClaimScenario {
        self.d.art = art;
        self
    }

    pub fn new() -> ClaimScenario {
        let mut mint_nonce = [0u8; 32];
        mint_nonce[..11].copy_from_slice(b"mint-nonce!");
        mint_nonce[31] = 0x41;
        let mut key = [0u8; 32];
        key[..8].copy_from_slice(b"claim-pk");
        key[31] = 0x42;
        ClaimScenario {
            d: DepositScenario::new(),
            found: true,
            mint_nonce,
            recipient: ClaimRecipient::Key(key),
            serialized_output: 1,
            response_kind: kind(erc20_vault_borsh::RESPONSE_KIND_CLAIM),
            claimant_sk: None,
            key_seed: 0xf00d_face,
            nonce_seed: 0x0dd_b17,
        }
    }

    /// The MPC response key.
    pub fn mpc_key(&self) -> IrValue {
        let generator = IrValue::Secp256k1Point(k256::K256::generator());
        ec_mul_offcircuit(&generator, &scalar(self.key_seed)).unwrap()
    }

    pub fn mpc_key_av(&self) -> AlignedValue {
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

    /// The attested output's BYTES — what the digest preimage carries after
    /// the request id.
    ///
    /// Compat/Opt: the deployed `Bytes<1>`, one packed success byte. Borsh
    /// (M11 stage 5): `borsh(VaultResponse { kind, success })` — the kind byte
    /// then the bool byte, which is that struct's canonical Borsh encoding.
    pub fn attested_output_bytes(&self) -> Vec<u8> {
        match self.art() {
            Art::Compat | Art::Opt => vec![self.serialized_output],
            Art::Borsh | Art::Modern => vec![self.response_kind, self.serialized_output],
        }
    }

    /// The attested output's ARGUMENT SLOTS, in declaration order — one per
    /// declared field.
    pub fn attested_output_slots(&self) -> Vec<Fr> {
        self.attested_output_bytes()
            .into_iter()
            .map(|b| Fr::from(u64::from(b)))
            .collect()
    }

    /// attestationDigest = keccak256(requestId ‖ attested output bytes).
    pub fn attestation_digest(&self) -> [u8; 32] {
        let mut bytes = self.d.request_id().to_vec();
        bytes.extend(self.attested_output_bytes());
        sha3::Keccak256::digest(&bytes).into()
    }

    /// The attestation signature's (bigR.x, s), big-endian as stored.
    pub fn signature_be(&self) -> ([u8; 32], [u8; 32]) {
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
    pub fn recipient_data(&self) -> (bool, [u8; 32]) {
        match self.recipient {
            ClaimRecipient::Key(pk) => (true, pk),
            ClaimRecipient::Contract(addr) => (false, addr),
            ClaimRecipient::None(own_pk) => (true, own_pk),
        }
    }

    /// tokenType(vaultTokenDomainSeparator(erc20), self).
    pub fn color(&self) -> [u8; 32] {
        vault_color(self.art(), &self.d.erc20, &self.d.self_addr)
    }

    pub fn domain_sep(&self) -> [u8; 32] {
        vault_domain_sep(self.art(), &self.d.erc20)
    }

    /// coinCommitment({mintNonce, color, amount}, recipient).
    pub fn coin_commitment(&self) -> [u8; 32] {
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
                Fr::from(self.d.amount_u64()),
                Fr::from(u64::from(is_left)),
                r_hi,
                r_lo,
            ],
        )
    }

    /// Does the branch's guarded kernel.self read fire? (Its guard is
    /// only `!is_left`.)
    pub fn self_read_fires(&self) -> bool {
        matches!(self.recipient, ClaimRecipient::Contract(_))
    }

    /// Does the auto-receive claim fire? (`!is_left && right == self`.)
    pub fn auto_receive(&self) -> bool {
        matches!(self.recipient, ClaimRecipient::Contract(addr) if addr == self.d.self_addr)
    }

    pub fn inputs(&self) -> Vec<Fr> {
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
        let mut inputs = vec![
            rid_hi,
            rid_lo,
            rx_hi,
            rx_lo,
            Fr::from(0u64), // bigR.y (unused by verification)
            Fr::from(0u64),
            s_hi,
            s_lo,
            Fr::from(0u64), // recoveryId (unused)
        ];
        inputs.extend(self.attested_output_slots()); // serializedOutput
        inputs.extend([
            n_hi,
            n_lo,
            Fr::from(is_some),
            Fr::from(is_left),
            l_hi,
            l_lo,
            r_hi,
            r_lo,
        ]);
        inputs
    }

    /// The secret key the caller presents.
    pub fn claimant_sk(&self) -> [u8; 32] {
        self.claimant_sk.unwrap_or(self.d.sk)
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (sk_hi, sk_lo) = b32_slots(&self.claimant_sk());
        let mut w = vec![sk_hi, sk_lo];
        if let ClaimRecipient::None(own_pk) = self.recipient {
            let (pk_hi, pk_lo) = b32_slots(&own_pk);
            w.extend([pk_hi, pk_lo]);
        }
        w
    }

    /// The reference Impact program (`member_result` = what the map
    /// member test reads back).
    pub fn ops(&self, member_result: u8) -> Vec<VmOp> {
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
                value: cell(bytesn_value(8, &self.d.amount_u64().to_le_bytes())),
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
    pub fn outputs(&self, member_result: u8) -> Vec<Fr> {
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

    pub fn preimage(&self) -> ProofPreimage {
        self.preimage_with_member(1)
    }

    pub fn preimage_with_member(&self, member_result: u8) -> ProofPreimage {
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

// --- approveRouter -----------------------------------------------------------

/// A concrete approveRouter() call: the vault-account approve request.
#[derive(Clone, Debug)]
pub struct ApproveScenario {
    pub art: Art,
    pub erc20: [u8; 20],
    pub evm_nonce: u64,
    pub key_version: u8,
    pub initialized: u64,
    /// Does `signBidirectionalEventMap` already hold this request id?
    pub request_exists: bool,
    pub router: [u8; 20],
    pub chain_id: u64,
    pub request_nonce: u64,
    pub self_addr: [u8; 32],
    pub caip2: [u8; 32],
    pub signer_addr: [u8; 32],
    pub ep: [u8; 32],
    pub cc_rand: Fr,
}

impl ApproveScenario {
    /// The same call against the other artifact.
    pub fn with_art(mut self, art: Art) -> ApproveScenario {
        self.art = art;
        self
    }

    pub fn new() -> ApproveScenario {
        let d = DepositScenario::new();
        ApproveScenario {
            art: Art::Compat,
            erc20: d.erc20,
            evm_nonce: 9,
            key_version: 1,
            initialized: 1,
            request_exists: false,
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

    pub fn word0(&self) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&self.router);
        w
    }

    pub fn word1(&self) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[16..].copy_from_slice(&[0xff; 16]); // 2^128 − 1, big-endian
        w
    }

    pub fn event_limbs(&self) -> Vec<Fr> {
        let (self_hi, self_lo) = b32_slots(&self.self_addr);
        let (path_hi, path_lo) = b32_slots(&pad32(erc20_vault::VAULT_PATH));
        let (caip2_hi, caip2_lo) = b32_slots(&self.caip2);
        let (w0_hi, w0_lo) = b32_slots(&self.word0());
        let (w1_hi, w1_lo) = b32_slots(&self.word1());
        let mut limbs = record_head(self.art);
        limbs.extend([
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
        ]);
        // APPROVE — the one REQUEST-ONLY kind: no settle circuit accepts it
        // (`erc20_vault_borsh::RESPONSE_KIND_APPROVE`).
        limbs.extend(record_tail(
            self.art,
            erc20_vault::VAULT_RESPONSE_SCHEMA,
            erc20_vault::VAULT_RESPONSE_SCHEMA,
            erc20_vault_borsh::RESPONSE_KIND_APPROVE,
        ));
        limbs
    }

    pub fn event_av(&self) -> AlignedValue {
        DepositScenario::event_alignment(self.art)
            .parse_field_repr(&self.event_limbs())
            .expect("event limbs match the alignment")
    }

    pub fn request_id(&self) -> [u8; 32] {
        let mut repr = Vec::new();
        ValueReprAlignedValue(self.event_av()).binary_repr(&mut repr);
        sha3::Keccak256::digest(&repr).into()
    }

    pub fn call_args(&self) -> Vec<Fr> {
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

    /// The reference Impact program, in the circuit's read/write order.
    pub fn ops(&self) -> Vec<VmOp> {
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
                result: bytesn_value(1, &[u8::from(self.request_exists)]),
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
        // The notification's callerAddress — threaded from this circuit's
        // first read in the optimized artifact (rung i, avenue 7).
        if self.art == Art::Compat {
            ops.extend(kernel_self_ops(&self.self_addr));
        }
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

    /// The `ProofPreimage` this call implies: arguments, witnesses, the op
    /// stream's `field_repr`, and the popeq results in read order.
    pub fn preimage(&self) -> ProofPreimage {
        let ops = self.ops();

        let inputs = vec![
            Fr::from_le_bytes(&self.erc20).unwrap(),
            Fr::from(self.evm_nonce),
            Fr::from(u64::from(self.key_version)),
        ];
        let mut transcript = Vec::new();
        for op in ops {
            op.field_repr(&mut transcript);
        }
        let mut avs = vec![
            bytesn_value(8, &self.initialized.to_le_bytes()),
            bytesn_value(20, &self.router),
            bytesn_value(8, &self.chain_id.to_le_bytes()),
            bytesn_value(8, &self.request_nonce.to_le_bytes()),
            bytesn_value(32, &self.self_addr),
            bytesn_value(32, &self.caip2),
            bytesn_value(1, &[u8::from(self.request_exists)]),
            bytesn_value(32, &self.signer_addr),
        ];
        if self.art == Art::Compat {
            avs.push(bytesn_value(32, &self.self_addr));
        }
        let mut outputs = Vec::new();
        for av in avs {
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

/// A concrete withdraw() call.
#[derive(Clone, Debug)]
pub struct WithdrawScenario {
    pub art: Art,
    pub evm_nonce: u64,
    pub key_version: u8,
    pub erc20: [u8; 20],
    /// `Uint<128>` in Compact — see [`DepositScenario::amount`].
    pub amount: u128,
    pub dest: [u8; 20],
    pub coin_nonce: [u8; 32],
    pub sk: [u8; 32],
    pub initialized: u64,
    pub chain_id: u64,
    pub request_nonce: u64,
    pub self_addr: [u8; 32],
    pub caip2: [u8; 32],
    pub signer_addr: [u8; 32],
    pub ep: [u8; 32],
    pub cc_rand: Fr,
    /// Does `signBidirectionalEventMap` already hold this request id?
    pub request_exists: bool,
}

impl WithdrawScenario {
    /// The same call against the other artifact.
    pub fn with_art(mut self, art: Art) -> WithdrawScenario {
        self.art = art;
        self
    }

    pub fn new() -> WithdrawScenario {
        let d = DepositScenario::new();
        let mut coin_nonce = [0u8; 32];
        coin_nonce[..10].copy_from_slice(b"coin-nonce");
        coin_nonce[31] = 0x51;
        WithdrawScenario {
            art: Art::Compat,
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
            request_exists: false,
        }
    }

    /// The surrendered amount as the `Uint<64>` a refund re-mints. Only
    /// meaningful once the withdraw guards passed.
    pub fn amount_u64(&self) -> u64 {
        u64::try_from(self.amount).unwrap_or(u64::MAX)
    }

    pub fn color(&self) -> [u8; 32] {
        vault_color(self.art, &self.erc20, &self.self_addr)
    }

    pub fn event_limbs(&self) -> Vec<Fr> {
        let (self_hi, self_lo) = b32_slots(&self.self_addr);
        let (path_hi, path_lo) = b32_slots(&pad32(erc20_vault::VAULT_PATH));
        let (caip2_hi, caip2_lo) = b32_slots(&self.caip2);
        let mut w0 = [0u8; 32];
        w0[12..].copy_from_slice(&self.dest);
        let mut w1 = [0u8; 32];
        w1[16..].copy_from_slice(&self.amount.to_be_bytes());
        let (w0_hi, w0_lo) = b32_slots(&w0);
        let (w1_hi, w1_lo) = b32_slots(&w1);
        let mut limbs = record_head(self.art);
        limbs.extend([
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
        ]);
        limbs.extend(record_tail(
            self.art,
            erc20_vault::VAULT_RESPONSE_SCHEMA,
            erc20_vault::VAULT_RESPONSE_SCHEMA,
            erc20_vault_borsh::RESPONSE_KIND_WITHDRAW,
        ));
        limbs
    }

    pub fn event_av(&self) -> AlignedValue {
        DepositScenario::event_alignment(self.art)
            .parse_field_repr(&self.event_limbs())
            .expect("event limbs match the alignment")
    }

    pub fn request_id(&self) -> [u8; 32] {
        let mut repr = Vec::new();
        ValueReprAlignedValue(self.event_av()).binary_repr(&mut repr);
        sha3::Keccak256::digest(&repr).into()
    }

    /// withdrawRefundCommitment(sk, requestId).
    pub fn refund_commitment(&self) -> [u8; 32] {
        refund_commitment(self.art, &self.sk, &self.request_id())
    }

    pub fn call_args(&self) -> Vec<Fr> {
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

    /// The reference Impact program, in the circuit's read/write order.
    pub fn ops(&self) -> Vec<VmOp> {
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
        let cm_receive =
            coin_commitment_of(&nonce_slots, &color, self.amount_u64(), false, &self.self_addr);
        let nullifier = coin_nullifier_of(&nonce_slots, &color, self.amount_u64(), &self.self_addr);
        let cm_burn = coin_commitment_of(
            &evolved_nonce(&self.coin_nonce),
            &color,
            self.amount_u64(),
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
        // The event's sender — threaded from the colour derivation's read
        // in the optimized artifact (rung i, avenue 7).
        if self.art == Art::Compat {
            ops.extend(kernel_self_ops(&self.self_addr));
        }
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
                result: bytesn_value(1, &[u8::from(self.request_exists)]),
            },
        ]);
        // The burn. The compat port receives the surrendered coin into
        // custody (receiveShielded) then spends it to the burn address
        // (sendImmediateShielded: nullifier + evolved-nonce output). The
        // optimized artifact (rung vi, avenue 6) claims a SINGLE shielded
        // spend of the burn-output commitment: the user funds the burn Output
        // directly, so there is no receive claim and no nullifier — only the
        // evolved-nonce output commitment survives, byte-identical.
        if self.art == Art::Compat {
            // receiveShielded (its recipient is the same address again)
            ops.extend(kernel_self_ops(&self.self_addr));
            ops.extend(claim(1, cm_receive));
            // burn: sendImmediateShielded — nullifier then output
            ops.extend(kernel_self_ops(&self.self_addr));
            ops.extend(claim(0, nullifier));
        }
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
        // The notification's callerAddress — threaded from this circuit's
        // first read in the optimized artifact (rung i, avenue 7).
        if self.art == Art::Compat {
            ops.extend(kernel_self_ops(&self.self_addr));
        }
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

    /// The `ProofPreimage` this call implies: arguments, witnesses, the op
    /// stream's `field_repr`, and the popeq results in read order.
    pub fn preimage(&self) -> ProofPreimage {
        let ops = self.ops();

        let nonce_slots = b32_slots(&self.coin_nonce);
        let color = self.color();
        let (n_hi, n_lo) = nonce_slots;
        let (c_hi, c_lo) = b32_slots(&color);
        let inputs = vec![
            Fr::from(self.evm_nonce),
            Fr::from(u64::from(self.key_version)),
            Fr::from_le_bytes(&self.erc20).unwrap(),
            Fr::from_le_bytes(&self.amount.to_le_bytes()).unwrap(),
            Fr::from_le_bytes(&self.dest).unwrap(),
            n_hi,
            n_lo,
            c_hi,
            c_lo,
            Fr::from_le_bytes(&self.amount.to_le_bytes()).unwrap(), // coin.value == amount
        ];
        let mut transcript = Vec::new();
        for op in ops {
            op.field_repr(&mut transcript);
        }
        let mut avs = vec![
            bytesn_value(8, &self.initialized.to_le_bytes()),
            bytesn_value(32, &self.self_addr),
            bytesn_value(8, &self.chain_id.to_le_bytes()),
            bytesn_value(8, &self.request_nonce.to_le_bytes()),
        ];
        if self.art == Art::Compat {
            avs.push(bytesn_value(32, &self.self_addr));
        }
        avs.push(bytesn_value(32, &self.caip2));
        avs.push(bytesn_value(1, &[u8::from(self.request_exists)]));
        if self.art == Art::Compat {
            // receiveShielded's and the burn's re-reads.
            avs.push(bytesn_value(32, &self.self_addr));
            avs.push(bytesn_value(32, &self.self_addr));
        }
        avs.push(bytesn_value(32, &self.signer_addr));
        if self.art == Art::Compat {
            avs.push(bytesn_value(32, &self.self_addr));
        }
        let mut outputs = Vec::new();
        for av in avs {
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

// --- completeWithdraw --------------------------------------------------------

/// A concrete completeWithdraw() call settling WithdrawScenario's pending
/// withdrawal.
#[derive(Clone, Debug)]
pub struct CompleteWithdrawScenario {
    pub w: WithdrawScenario,
    /// Does `refundCommitment` hold the id? (The pending-withdrawal
    /// marker, and the double-settle gate.)
    pub pending: bool,
    /// The attested EVM outcome byte (0x01 success / 0x00 refund). Under
    /// `Art::Borsh` it is a Borsh `bool`, so a byte outside {0, 1} is
    /// REJECTED where the port and the optimized fork refund-route on it.
    pub outcome: u8,
    /// The response KIND byte — M11 stage 5, `Art::Borsh` only. Defaults to
    /// `RESPONSE_KIND_WITHDRAW`.
    pub response_kind: u8,
    pub mint_nonce: [u8; 32],
    pub own_pk: [u8; 32],
    pub key_seed: u64,
    pub nonce_seed: u64,
    /// The secret the CALLER witnesses on the refund branch; `None` = the
    /// withdrawer's own.
    pub claimant_sk: Option<[u8; 32]>,
}

impl CompleteWithdrawScenario {
    /// The artifact this settle models (owned by the withdrawal it settles).
    pub fn art(&self) -> Art {
        self.w.art
    }

    /// The same call against the other artifact.
    pub fn with_art(mut self, art: Art) -> CompleteWithdrawScenario {
        self.w.art = art;
        self
    }

    pub fn new(outcome: u8) -> CompleteWithdrawScenario {
        let mut mint_nonce = [0u8; 32];
        mint_nonce[..12].copy_from_slice(b"refund-nonce");
        mint_nonce[31] = 0x61;
        let mut own_pk = [0u8; 32];
        own_pk[..9].copy_from_slice(b"refund-pk");
        own_pk[31] = 0x62;
        CompleteWithdrawScenario {
            w: WithdrawScenario::new(),
            pending: true,
            outcome,
            response_kind: kind(erc20_vault_borsh::RESPONSE_KIND_WITHDRAW),
            mint_nonce,
            own_pk,
            key_seed: 0xf00d_face,
            nonce_seed: 0x0dd_b17,
            claimant_sk: None,
        }
    }

    /// The secret key the caller presents.
    pub fn claimant_sk(&self) -> [u8; 32] {
        self.claimant_sk.unwrap_or(self.w.sk)
    }

    /// Does the guarded refund branch fire?
    ///
    /// The Compact source is `deserialize<VaultResponse, 1>(o).success`,
    /// which for a packed `Boolean` is `o == 1` — NOT a canonicity-checked
    /// decode. So every attested byte other than `0x01` refunds, including
    /// non-canonical ones. (Contrast `abiWordToBool`, Signet.compact:461-463,
    /// which DOES assert canonicity.) The differential suite only ever
    /// exercised {0x00, 0x01}, where `== 0` and `!= 1` coincide, which is why
    /// this read wrong for so long; the property harness caught it on its
    /// first run. See notes/vault-optimization.org §"As built — step 1".
    pub fn refunding(&self) -> bool {
        self.outcome != 1
    }

    pub fn mpc_key_av(&self) -> AlignedValue {
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

    /// The attested output's BYTES — see
    /// [`ClaimScenario::attested_output_bytes`]; `completeWithdraw` carries
    /// the same `VaultResponse` shape under kind 1.
    pub fn attested_output_bytes(&self) -> Vec<u8> {
        match self.art() {
            Art::Compat | Art::Opt => vec![self.outcome],
            Art::Borsh | Art::Modern => vec![self.response_kind, self.outcome],
        }
    }

    /// The attested output's ARGUMENT SLOTS, in declaration order.
    pub fn attested_output_slots(&self) -> Vec<Fr> {
        self.attested_output_bytes()
            .into_iter()
            .map(|b| Fr::from(u64::from(b)))
            .collect()
    }

    pub fn signature_be(&self) -> ([u8; 32], [u8; 32]) {
        let mut bytes = self.w.request_id().to_vec();
        bytes.extend(self.attested_output_bytes());
        let digest: [u8; 32] = sha3::Keccak256::digest(&bytes).into();
        let (mut r_le, mut s_le, _) = sign(&digest, &scalar(self.key_seed), &scalar(self.nonce_seed));
        r_le.reverse();
        s_le.reverse();
        (r_le, s_le)
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let (rid_hi, rid_lo) = b32_slots(&self.w.request_id());
        let (rx, sx) = self.signature_be();
        let (rx_hi, rx_lo) = b32_slots(&rx);
        let (s_hi, s_lo) = b32_slots(&sx);
        let (n_hi, n_lo) = b32_slots(&self.mint_nonce);
        let mut inputs = vec![
            rid_hi,
            rid_lo,
            rx_hi,
            rx_lo,
            Fr::from(0u64),
            Fr::from(0u64),
            s_hi,
            s_lo,
            Fr::from(0u64),
        ];
        inputs.extend(self.attested_output_slots());
        inputs.extend([n_hi, n_lo]);
        inputs
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        if !self.refunding() {
            return vec![];
        }
        let (sk_hi, sk_lo) = b32_slots(&self.claimant_sk());
        let (pk_hi, pk_lo) = b32_slots(&self.own_pk);
        vec![sk_hi, sk_lo, pk_hi, pk_lo]
    }

    /// The reference Impact program, in the circuit's read/write order.
    pub fn ops(&self) -> Vec<VmOp> {
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
                result: bytesn_value(1, &[u8::from(self.pending)]),
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
            let domain_sep = vault_domain_sep(self.art(), &self.w.erc20);
            let color = vault_color(self.art(), &self.w.erc20, &self.w.self_addr);
            let cm = coin_commitment_of(
                &b32_slots(&self.mint_nonce),
                &color,
                self.w.amount_u64(),
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
                    value: cell(bytesn_value(8, &self.w.amount_u64().to_le_bytes())),
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
        ops
    }

    /// The `ProofPreimage` this call implies: arguments, witnesses, the op
    /// stream's `field_repr`, and the popeq results in read order.
    pub fn preimage(&self) -> ProofPreimage {
        let ops = self.ops();

        let inputs = self.inputs();
        let mut transcript = Vec::new();
        for op in ops {
            op.field_repr(&mut transcript);
        }
        let mut avs = vec![
            bytesn_value(8, &self.w.initialized.to_le_bytes()),
            self.mpc_key_av(),
            bytesn_value(1, &[u8::from(self.pending)]),
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

// --- swap --------------------------------------------------------------------

/// A concrete swap() call.
#[derive(Clone, Debug)]
pub struct SwapScenario {
    pub art: Art,
    pub evm_nonce: u64,
    pub key_version: u8,
    pub token_in: [u8; 20],
    pub token_out: [u8; 20],
    pub fee: u32,
    /// `Uint<128>` in Compact — see [`DepositScenario::amount`].
    pub amount_out: u128,
    /// `Uint<128>` in Compact — see [`DepositScenario::amount`].
    pub amount_in_max: u128,
    pub coin_nonce: [u8; 32],
    pub sk: [u8; 32],
    pub initialized: u64,
    pub vault_evm: [u8; 20],
    pub chain_id: u64,
    pub router: [u8; 20],
    pub request_nonce: u64,
    pub self_addr: [u8; 32],
    pub caip2: [u8; 32],
    pub signer_addr: [u8; 32],
    pub ep: [u8; 32],
    pub cc_rand: Fr,
    /// Does `swapEventMap` already hold this request id?
    pub request_exists: bool,
}

impl SwapScenario {
    /// The same call against the other artifact.
    pub fn with_art(mut self, art: Art) -> SwapScenario {
        self.art = art;
        self
    }

    pub fn new() -> SwapScenario {
        let d = DepositScenario::new();
        let mut coin_nonce = [0u8; 32];
        coin_nonce[..10].copy_from_slice(b"swap-nonce");
        coin_nonce[31] = 0x71;
        SwapScenario {
            art: Art::Compat,
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
            request_exists: false,
        }
    }

    /// `amountOut` as the `Uint<64>` completeSwap mints. Only meaningful
    /// once the swap guards passed.
    pub fn amount_out_u64(&self) -> u64 {
        u64::try_from(self.amount_out).unwrap_or(u64::MAX)
    }

    /// `amountInMaximum` as the `Uint<64>` a refund re-mints.
    pub fn amount_in_max_u64(&self) -> u64 {
        u64::try_from(self.amount_in_max).unwrap_or(u64::MAX)
    }

    /// The 7-word record's FAB alignment: 29 atoms deployed, 29 at stage 7.
    pub fn event_alignment7(art: Art) -> Alignment {
        record_alignment(
            art,
            erc20_vault::SWAP_WORDS,
            erc20_vault::SWAP_OUTPUT_LEN as u32,
            erc20_vault::SWAP_RESPOND_LEN as u32,
        )
    }

    pub fn event_limbs(&self) -> Vec<Fr> {
        let (self_hi, self_lo) = b32_slots(&self.self_addr);
        let (path_hi, path_lo) = b32_slots(&pad32(erc20_vault::VAULT_PATH));
        let (caip2_hi, caip2_lo) = b32_slots(&self.caip2);
        let words = [
            abi_addr_word(&self.token_in),
            abi_addr_word(&self.token_out),
            abi_num_word(u128::from(self.fee)),
            abi_addr_word(&self.vault_evm),
            abi_num_word(self.amount_out),
            abi_num_word(self.amount_in_max),
            [0u8; 32],
        ];
        let mut limbs = record_head(self.art);
        limbs.extend([
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
        ]);
        for w in &words {
            let (hi, lo) = b32_slots(w);
            limbs.push(hi);
            limbs.push(lo);
        }
        limbs.extend([
            Fr::from(0u64), // accessListEntryCount
            caip2_hi,
            caip2_lo,
        ]);
        limbs.extend(record_tail(
            self.art,
            erc20_vault::SWAP_OUTPUT_SCHEMA,
            erc20_vault::SWAP_RESPOND_SCHEMA,
            erc20_vault_borsh::RESPONSE_KIND_SWAP,
        ));
        limbs
    }

    pub fn event_av(&self) -> AlignedValue {
        Self::event_alignment7(self.art)
            .parse_field_repr(&self.event_limbs())
            .expect("event limbs match the alignment")
    }

    pub fn request_id(&self) -> [u8; 32] {
        let mut repr = Vec::new();
        ValueReprAlignedValue(self.event_av()).binary_repr(&mut repr);
        sha3::Keccak256::digest(&repr).into()
    }

    pub fn refund_commitment(&self) -> [u8; 32] {
        refund_commitment(self.art, &self.sk, &self.request_id())
    }

    pub fn call_args(&self) -> Vec<Fr> {
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

    /// The reference Impact program, in the circuit's read/write order.
    pub fn ops(&self) -> Vec<VmOp> {
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
        let color = vault_color(self.art, &self.token_in, &self.self_addr);
        let nonce_slots = b32_slots(&self.coin_nonce);
        let cm_receive = coin_commitment_of(
            &nonce_slots,
            &color,
            self.amount_in_max_u64(),
            false,
            &self.self_addr,
        );
        let nullifier =
            coin_nullifier_of(&nonce_slots, &color, self.amount_in_max_u64(), &self.self_addr);
        let cm_burn = coin_commitment_of(
            &evolved_nonce(&self.coin_nonce),
            &color,
            self.amount_in_max_u64(),
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
        // The event's sender — threaded from the colour derivation's read
        // in the optimized artifact (rung i, avenue 7).
        if self.art == Art::Compat {
            ops.extend(kernel_self_ops(&self.self_addr));
        }
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
                result: bytesn_value(1, &[u8::from(self.request_exists)]),
            },
        ]);
        // The burn — as in withdraw. Compat: receiveShielded (custody) then
        // sendImmediateShielded (nullifier + evolved-nonce output). Opt (rung
        // vi, avenue 6): a SINGLE claimed shielded spend of the burn-output
        // commitment, no receive claim and no nullifier.
        if self.art == Art::Compat {
            ops.extend(kernel_self_ops(&self.self_addr));
            ops.extend(claim(1, cm_receive));
            ops.extend(kernel_self_ops(&self.self_addr));
            ops.extend(claim(0, nullifier));
        }
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
        // The notification's callerAddress — threaded from this circuit's
        // first read in the optimized artifact (rung i, avenue 7).
        if self.art == Art::Compat {
            ops.extend(kernel_self_ops(&self.self_addr));
        }
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

    /// The `ProofPreimage` this call implies: arguments, witnesses, the op
    /// stream's `field_repr`, and the popeq results in read order.
    pub fn preimage(&self) -> ProofPreimage {
        let ops = self.ops();

        let color = vault_color(self.art, &self.token_in, &self.self_addr);
        let nonce_slots = b32_slots(&self.coin_nonce);
        let (c_hi, c_lo) = b32_slots(&color);
        let inputs = vec![
            Fr::from(self.evm_nonce),
            Fr::from(u64::from(self.key_version)),
            Fr::from_le_bytes(&self.token_in).unwrap(),
            Fr::from_le_bytes(&self.token_out).unwrap(),
            Fr::from(u64::from(self.fee)),
            Fr::from_le_bytes(&self.amount_out.to_le_bytes()).unwrap(),
            Fr::from_le_bytes(&self.amount_in_max.to_le_bytes()).unwrap(),
            nonce_slots.0,
            nonce_slots.1,
            c_hi,
            c_lo,
            Fr::from_le_bytes(&self.amount_in_max.to_le_bytes()).unwrap(),
        ];
        let mut transcript = Vec::new();
        for op in ops {
            op.field_repr(&mut transcript);
        }
        let mut avs = vec![
            bytesn_value(8, &self.initialized.to_le_bytes()),
            bytesn_value(32, &self.self_addr),
            bytesn_value(20, &self.vault_evm),
            bytesn_value(8, &self.chain_id.to_le_bytes()),
            bytesn_value(20, &self.router),
            bytesn_value(8, &self.request_nonce.to_le_bytes()),
        ];
        if self.art == Art::Compat {
            avs.push(bytesn_value(32, &self.self_addr));
        }
        avs.push(bytesn_value(32, &self.caip2));
        avs.push(bytesn_value(1, &[u8::from(self.request_exists)]));
        if self.art == Art::Compat {
            avs.push(bytesn_value(32, &self.self_addr));
            avs.push(bytesn_value(32, &self.self_addr));
        }
        avs.push(bytesn_value(32, &self.signer_addr));
        if self.art == Art::Compat {
            avs.push(bytesn_value(32, &self.self_addr));
        }
        let mut outputs = Vec::new();
        for av in avs {
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

// --- completeSwap ------------------------------------------------------------

/// A concrete completeSwap() call settling SwapScenario's pending swap.
#[derive(Clone, Debug)]
pub struct CompleteSwapScenario {
    pub s: SwapScenario,
    /// Does `swapRefundCommitment` hold the id? (The pending-swap marker.)
    pub pending: bool,
    /// The attested amountIn actually spent (≤ amountInMaximum).
    pub amount_in: u64,
    /// The response KIND byte — M11 stage 5, `Art::Borsh` only. Defaults to
    /// `RESPONSE_KIND_SWAP`.
    pub response_kind: u8,
    pub mint_nonce: [u8; 32],
    pub own_pk: [u8; 32],
    pub key_seed: u64,
    pub nonce_seed: u64,
    /// The secret the CALLER witnesses; `None` = the swapper's own.
    pub claimant_sk: Option<[u8; 32]>,
}

impl CompleteSwapScenario {
    /// The artifact this settle models (owned by the swap it settles).
    pub fn art(&self) -> Art {
        self.s.art
    }

    /// The same call against the other artifact.
    pub fn with_art(mut self, art: Art) -> CompleteSwapScenario {
        self.s.art = art;
        self
    }

    pub fn new() -> CompleteSwapScenario {
        let mut mint_nonce = [0u8; 32];
        mint_nonce[..10].copy_from_slice(b"swap-mint!");
        mint_nonce[31] = 0x81;
        let mut own_pk = [0u8; 32];
        own_pk[..7].copy_from_slice(b"swap-pk");
        own_pk[31] = 0x82;
        CompleteSwapScenario {
            s: SwapScenario::new(),
            pending: true,
            amount_in: 88_888,
            response_kind: kind(erc20_vault_borsh::RESPONSE_KIND_SWAP),
            mint_nonce,
            own_pk,
            key_seed: 0xf00d_face,
            nonce_seed: 0x0dd_b17,
            claimant_sk: None,
        }
    }

    /// The secret key the caller presents.
    pub fn claimant_sk(&self) -> [u8; 32] {
        self.claimant_sk.unwrap_or(self.s.sk)
    }

    pub fn mpc_key_av(&self) -> AlignedValue {
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

    /// The attested output's BYTES: the deployed 8-byte little-endian
    /// `amountIn` (which stage 0 proved is already a canonical Borsh `u64`),
    /// with the kind byte in front under `Art::Borsh` —
    /// `borsh(SwapResponse { kind, amount_in })`.
    pub fn attested_output_bytes(&self) -> Vec<u8> {
        let mut bytes = match self.art() {
            Art::Compat | Art::Opt => vec![],
            Art::Borsh | Art::Modern => vec![self.response_kind],
        };
        bytes.extend(self.amount_in.to_le_bytes());
        bytes
    }

    /// The attested output's ARGUMENT SLOTS: `amountIn` is ONE slot (a
    /// `Uint<64>`), not eight bytes, so this is not the byte list.
    pub fn attested_output_slots(&self) -> Vec<Fr> {
        let mut slots = match self.art() {
            Art::Compat | Art::Opt => vec![],
            Art::Borsh | Art::Modern => vec![Fr::from(u64::from(self.response_kind))],
        };
        slots.push(Fr::from(self.amount_in));
        slots
    }

    pub fn signature_be(&self) -> ([u8; 32], [u8; 32]) {
        let mut bytes = self.s.request_id().to_vec();
        bytes.extend(self.attested_output_bytes());
        let digest: [u8; 32] = sha3::Keccak256::digest(&bytes).into();
        let (mut r_le, mut s_le, _) = sign(&digest, &scalar(self.key_seed), &scalar(self.nonce_seed));
        r_le.reverse();
        s_le.reverse();
        (r_le, s_le)
    }

    /// The change coin's nonce, as this artifact derives it.
    pub fn change_nonce(&self) -> [u8; 32] {
        change_nonce(self.art(), &self.mint_nonce)
    }

    /// The reference Impact program, in the circuit's read/write order.
    pub fn ops(&self) -> Vec<VmOp> {
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

        let color_out = vault_color(self.art(), &self.s.token_out, &self.s.self_addr);
        let color_in = vault_color(self.art(), &self.s.token_in, &self.s.self_addr);
        let change = self.s.amount_in_max_u64().wrapping_sub(self.amount_in);
        let cm_out = coin_commitment_of(
            &b32_slots(&self.mint_nonce),
            &color_out,
            self.s.amount_out_u64(),
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
                result: bytesn_value(1, &[u8::from(self.pending)]),
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
            vault_domain_sep(self.art(), &self.s.token_out),
            self.s.amount_out_u64(),
            cm_out,
        ));
        // The change mint's own kernel.self read — one read serves both
        // mints in the optimized artifact (rung i, avenue 7).
        if self.art() == Art::Compat {
            ops.extend(kernel_self_ops(&self.s.self_addr));
        }
        ops.extend(mint(vault_domain_sep(self.art(), &self.s.token_in), change, cm_change));
        ops
    }

    /// The `ProofPreimage` this call implies: arguments, witnesses, the op
    /// stream's `field_repr`, and the popeq results in read order.
    pub fn preimage(&self) -> ProofPreimage {
        let ops = self.ops();

        let request_id = self.s.request_id();
        let (rid_hi, rid_lo) = b32_slots(&request_id);
        let (rx, sx) = self.signature_be();
        let (rx_hi, rx_lo) = b32_slots(&rx);
        let (s_hi, s_lo) = b32_slots(&sx);
        let (n_hi, n_lo) = b32_slots(&self.mint_nonce);
        let mut inputs = vec![
            rid_hi,
            rid_lo,
            rx_hi,
            rx_lo,
            Fr::from(0u64),
            Fr::from(0u64),
            s_hi,
            s_lo,
            Fr::from(0u64),
        ];
        inputs.extend(self.attested_output_slots());
        inputs.extend([n_hi, n_lo]);
        let mut transcript = Vec::new();
        for op in ops {
            op.field_repr(&mut transcript);
        }
        let mut avs = vec![
            bytesn_value(8, &self.s.initialized.to_le_bytes()),
            self.mpc_key_av(),
            bytesn_value(1, &[u8::from(self.pending)]),
            self.s.event_av(),
            bytesn_value(32, &self.s.refund_commitment()),
            bytesn_value(32, &self.s.self_addr),
        ];
        if self.art() == Art::Compat {
            avs.push(bytesn_value(32, &self.s.self_addr));
        }
        let mut outputs = Vec::new();
        for av in avs {
            ValueReprAlignedValue(av).field_repr(&mut outputs);
        }
        let (sk_hi, sk_lo) = b32_slots(&self.claimant_sk());
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

// --- refund ------------------------------------------------------------------

/// Which pending request the refund settles.
#[derive(Clone, Debug)]
pub enum RefundRoute {
    Withdrawal(WithdrawScenario),
    Swap(SwapScenario),
}

/// A concrete refund() call (the MPC attested the fixed failure output).
#[derive(Clone, Debug)]
pub struct RefundScenario {
    pub route: RefundRoute,
    pub mint_nonce: [u8; 32],
    pub own_pk: [u8; 32],
    pub key_seed: u64,
    pub nonce_seed: u64,
    /// The attested 5-byte output. Only the protocol's fixed failure
    /// sentinel refunds. `Art::Compat`/`Art::Opt` only — the Borsh artifact
    /// replaced the sentinel with the response kind.
    pub serialized_output: [u8; 5],
    /// The response KIND byte — M11 stage 5, `Art::Borsh` only, where it is
    /// the WHOLE attested output. Defaults to `RESPONSE_KIND_FAILURE`; the
    /// generator moves the two in lockstep, so one generated case says "a
    /// failure response" or "not a failure response" to all three artifacts.
    pub response_kind: u8,
    /// `initialized` at call time.
    pub initialized: u64,
    /// The secret the CALLER witnesses; `None` = the withdrawer's/swapper's
    /// own.
    pub claimant_sk: Option<[u8; 32]>,
    /// Cross-route trap: also place the id in the OTHER route's pending
    /// marker. refund routes on `refundCommitment.member` ALONE, so this
    /// must not change the outcome.
    pub also_other_marker: bool,
}

impl RefundScenario {
    /// The artifact this settle models (owned by the request it refunds).
    pub fn art(&self) -> Art {
        match &self.route {
            RefundRoute::Withdrawal(w) => w.art,
            RefundRoute::Swap(s) => s.art,
        }
    }

    /// The same call against the other artifact.
    pub fn with_art(mut self, art: Art) -> RefundScenario {
        match &mut self.route {
            RefundRoute::Withdrawal(w) => w.art = art,
            RefundRoute::Swap(s) => s.art = art,
        }
        self
    }

    pub fn new(route: RefundRoute) -> RefundScenario {
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
            serialized_output: erc20_vault::MPC_FAILURE_OUTPUT,
            response_kind: kind(erc20_vault_borsh::RESPONSE_KIND_FAILURE),
            initialized: 1,
            claimant_sk: None,
            also_other_marker: false,
        }
    }

    /// The secret key the caller presents.
    pub fn claimant_sk(&self) -> [u8; 32] {
        self.claimant_sk.unwrap_or(self.sk())
    }

    /// The vault's own address in this scenario's route.
    pub fn self_addr(&self) -> [u8; 32] {
        match &self.route {
            RefundRoute::Withdrawal(w) => w.self_addr,
            RefundRoute::Swap(s) => s.self_addr,
        }
    }

    pub fn request_id(&self) -> [u8; 32] {
        match &self.route {
            RefundRoute::Withdrawal(w) => w.request_id(),
            RefundRoute::Swap(s) => s.request_id(),
        }
    }

    pub fn sk(&self) -> [u8; 32] {
        match &self.route {
            RefundRoute::Withdrawal(w) => w.sk,
            RefundRoute::Swap(s) => s.sk,
        }
    }

    pub fn mpc_key_av(&self) -> AlignedValue {
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

    /// The attested output's BYTES: the deployed 5-byte `0xdeadbeef01`
    /// sentinel, or — under `Art::Borsh` — the single kind byte that replaced
    /// it, `borsh(FailureResponse { kind })`.
    pub fn attested_output_bytes(&self) -> Vec<u8> {
        match self.art() {
            Art::Compat | Art::Opt => self.serialized_output.to_vec(),
            Art::Borsh | Art::Modern => vec![self.response_kind],
        }
    }

    /// The attested output's ARGUMENT SLOTS: one either way — five packed
    /// little-endian bytes, or the kind byte.
    pub fn attested_output_slots(&self) -> Vec<Fr> {
        match self.art() {
            Art::Compat | Art::Opt => {
                vec![Fr::from_le_bytes(&self.serialized_output).unwrap()]
            }
            Art::Borsh | Art::Modern => vec![Fr::from(u64::from(self.response_kind))],
        }
    }

    pub fn signature_be(&self) -> ([u8; 32], [u8; 32]) {
        let mut bytes = self.request_id().to_vec();
        bytes.extend(self.attested_output_bytes());
        let digest: [u8; 32] = sha3::Keccak256::digest(&bytes).into();
        let (mut r_le, mut s_le, _) = sign(&digest, &scalar(self.key_seed), &scalar(self.nonce_seed));
        r_le.reverse();
        s_le.reverse();
        (r_le, s_le)
    }

    /// The reference Impact program, plus the popeq results in read order
    /// (refund's two routes interleave the two, so they are built once).
    pub fn ops_and_reads(&self) -> (Vec<VmOp>, Vec<AlignedValue>) {
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

        let initialized: u64 = self.initialized;
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
        // The optimized artifact reads kernel.self ONCE, unguarded, right
        // after the routing member test, and both branches' mints use it
        // (rung i, avenue 7). The port instead reads it inside whichever
        // branch runs, so its read lands later — and in a different place
        // per route. Either way the transcript carries exactly one answer.
        // (`!= Compat` rather than `== Opt`: the M11 Borsh artifact is a fork
        // OF the optimized one and inherits every M10 rung, so the op stream
        // it expects is the optimized one — as it is everywhere else in this
        // file, which asks `art == Art::Compat`.)
        let shared_self = self.art() != Art::Compat;
        match &self.route {
            RefundRoute::Withdrawal(w) => {
                ops.extend(member(erc20_vault::REFUND_COMMITMENT, 1));
                avs.push(bytesn_value(1, &[1]));
                if shared_self {
                    ops.extend(kernel_self_ops(&w.self_addr));
                    avs.push(bytesn_value(32, &w.self_addr));
                }
                ops.extend(lookup(erc20_vault::SIGN_BIDIRECTIONAL_EVENT_MAP, w.event_av()));
                avs.push(w.event_av());
                ops.extend(remove(erc20_vault::SIGN_BIDIRECTIONAL_EVENT_MAP));
                ops.extend(lookup(
                    erc20_vault::REFUND_COMMITMENT,
                    bytesn_value(32, &w.refund_commitment()),
                ));
                avs.push(bytesn_value(32, &w.refund_commitment()));
                if !shared_self {
                    ops.extend(kernel_self_ops(&w.self_addr));
                    avs.push(bytesn_value(32, &w.self_addr));
                }
                let color = vault_color(self.art(), &w.erc20, &w.self_addr);
                let cm = coin_commitment_of(
                    &b32_slots(&self.mint_nonce),
                    &color,
                    w.amount_u64(),
                    true,
                    &self.own_pk,
                );
                let mint_ops =
                    mint(vault_domain_sep(self.art(), &w.erc20), w.amount_u64(), cm);
                let remove_ops = remove(erc20_vault::REFUND_COMMITMENT);
                if self.art() != Art::Compat {
                    // Rung 5(iv), avenue 4: the merged re-mint runs after BOTH
                    // routes' guarded commitment-map removes, so on the
                    // withdrawal route the refundCommitment remove precedes the
                    // single mint. The port keeps compactc's order (mint, then
                    // remove).
                    ops.extend(remove_ops);
                    ops.extend(mint_ops);
                } else {
                    ops.extend(mint_ops);
                    ops.extend(remove_ops);
                }
            }
            RefundRoute::Swap(s) => {
                ops.extend(member(erc20_vault::REFUND_COMMITMENT, 0));
                avs.push(bytesn_value(1, &[0]));
                if shared_self {
                    ops.extend(kernel_self_ops(&s.self_addr));
                    avs.push(bytesn_value(32, &s.self_addr));
                }
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
                if !shared_self {
                    ops.extend(kernel_self_ops(&s.self_addr));
                    avs.push(bytesn_value(32, &s.self_addr));
                }
                let color = vault_color(self.art(), &s.token_in, &s.self_addr);
                let cm = coin_commitment_of(
                    &b32_slots(&self.mint_nonce),
                    &color,
                    s.amount_in_max_u64(),
                    true,
                    &self.own_pk,
                );
                ops.extend(mint(
                    vault_domain_sep(self.art(), &s.token_in),
                    s.amount_in_max_u64(),
                    cm,
                ));
            }
        }
        (ops, avs)
    }

    /// The reference Impact program, in the circuit's read/write order.
    pub fn ops(&self) -> Vec<VmOp> {
        self.ops_and_reads().0
    }

    /// The `ProofPreimage` this call implies.
    pub fn preimage(&self) -> ProofPreimage {
        let (ops, avs) = self.ops_and_reads();
        let request_id = self.request_id();
        let (rid_hi, rid_lo) = b32_slots(&request_id);
        let (rx, sx) = self.signature_be();
        let (rx_hi, rx_lo) = b32_slots(&rx);
        let (s_hi, s_lo) = b32_slots(&sx);
        let (n_hi, n_lo) = b32_slots(&self.mint_nonce);
        let mut inputs = vec![
            rid_hi,
            rid_lo,
            rx_hi,
            rx_lo,
            Fr::from(0u64),
            Fr::from(0u64),
            s_hi,
            s_lo,
            Fr::from(0u64),
        ];
        inputs.extend(self.attested_output_slots());
        inputs.extend([n_hi, n_lo]);
        let mut transcript = Vec::new();
        for op in ops {
            op.field_repr(&mut transcript);
        }
        let mut outputs = Vec::new();
        for av in avs {
            ValueReprAlignedValue(av).field_repr(&mut outputs);
        }
        let (sk_hi, sk_lo) = b32_slots(&self.claimant_sk());
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

// --- pre-states ---------------------------------------------------------------
//
// Each scenario knows what its circuit's reads must return; a `PreState` is
// simply that knowledge laid out as the 13-field ledger tree. It is not
// redundant with the `Popeq` results in `ops()`: the executor runs in VERIFY
// mode, so `ResultModeVerify::process_read` compares every popeq result
// against what the real state holds and errors `ReadMismatch` if the two
// ever drift apart. Building both is what makes that check bite.

use super::exec::PreState;

impl Scenario {
    /// `initialized == count`, `deployer == commitment`.
    pub fn pre_state(&self, count: u64) -> PreState {
        PreState {
            initialized: count,
            deployer: self.commitment(),
            ..Default::default()
        }
    }
}

impl DepositScenario {
    pub fn pre_state(&self) -> PreState {
        PreState {
            sign_event_map: if self.request_exists {
                vec![(self.request_id(), self.event_av())]
            } else {
                vec![]
            },
            signet_signer: self.signer_addr,
            request_nonce: self.request_nonce,
            initialized: self.initialized,
            vault_evm: self.vault_evm,
            chain_id: self.chain_id,
            caip2: self.caip2,
            ..Default::default()
        }
    }
}

impl ClaimScenario {
    pub fn pre_state(&self) -> PreState {
        PreState {
            sign_event_map: if self.found {
                vec![(self.d.request_id(), self.d.event_av())]
            } else {
                vec![]
            },
            mpc_response_key: Some(self.mpc_key_av()),
            initialized: self.d.initialized,
            ..Default::default()
        }
    }
}

impl ApproveScenario {
    pub fn pre_state(&self) -> PreState {
        PreState {
            sign_event_map: if self.request_exists {
                vec![(self.request_id(), self.event_av())]
            } else {
                vec![]
            },
            signet_signer: self.signer_addr,
            request_nonce: self.request_nonce,
            initialized: self.initialized,
            chain_id: self.chain_id,
            caip2: self.caip2,
            uniswap_router: self.router,
            ..Default::default()
        }
    }
}

impl WithdrawScenario {
    pub fn pre_state(&self) -> PreState {
        PreState {
            sign_event_map: if self.request_exists {
                vec![(self.request_id(), self.event_av())]
            } else {
                vec![]
            },
            signet_signer: self.signer_addr,
            request_nonce: self.request_nonce,
            initialized: self.initialized,
            chain_id: self.chain_id,
            caip2: self.caip2,
            ..Default::default()
        }
    }
}

impl CompleteWithdrawScenario {
    pub fn pre_state(&self) -> PreState {
        PreState {
            sign_event_map: vec![(self.w.request_id(), self.w.event_av())],
            mpc_response_key: Some(self.mpc_key_av()),
            initialized: self.w.initialized,
            refund_commitment: if self.pending {
                vec![(self.w.request_id(), self.w.refund_commitment())]
            } else {
                vec![]
            },
            ..Default::default()
        }
    }
}

impl SwapScenario {
    pub fn pre_state(&self) -> PreState {
        PreState {
            signet_signer: self.signer_addr,
            request_nonce: self.request_nonce,
            initialized: self.initialized,
            vault_evm: self.vault_evm,
            chain_id: self.chain_id,
            caip2: self.caip2,
            uniswap_router: self.router,
            swap_event_map: if self.request_exists {
                vec![(self.request_id(), self.event_av())]
            } else {
                vec![]
            },
            ..Default::default()
        }
    }
}

impl CompleteSwapScenario {
    pub fn pre_state(&self) -> PreState {
        PreState {
            mpc_response_key: Some(self.mpc_key_av()),
            initialized: self.s.initialized,
            swap_event_map: vec![(self.s.request_id(), self.s.event_av())],
            swap_refund_commitment: if self.pending {
                vec![(self.s.request_id(), self.s.refund_commitment())]
            } else {
                vec![]
            },
            ..Default::default()
        }
    }
}

impl RefundScenario {
    pub fn pre_state(&self) -> PreState {
        let mut pre = PreState {
            mpc_response_key: Some(self.mpc_key_av()),
            initialized: self.initialized,
            ..Default::default()
        };
        match &self.route {
            RefundRoute::Withdrawal(w) => {
                pre.sign_event_map = vec![(w.request_id(), w.event_av())];
                pre.refund_commitment = vec![(w.request_id(), w.refund_commitment())];
                if self.also_other_marker {
                    // Cross-route trap: the same id ALSO carries a
                    // pending-swap marker. refund routes on
                    // refundCommitment.member alone, so this is inert.
                    pre.swap_refund_commitment =
                        vec![(w.request_id(), w.refund_commitment())];
                }
            }
            RefundRoute::Swap(s) => {
                pre.swap_event_map = vec![(s.request_id(), s.event_av())];
                pre.swap_refund_commitment = vec![(s.request_id(), s.refund_commitment())];
            }
        }
        pre
    }
}
