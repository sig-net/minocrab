//! The erc20-vault REFERENCE MODEL: per-circuit scenarios that carry a
//! concrete pre-state plus the arguments and witnesses of one call, and
//! emit the Impact op stream and the `ProofPreimage` that stream implies.
//!
//! One model, three consumers: the differential suite (PI-equality against
//! compactc's artifacts), the property harness (spec agreement at scale),
//! and the adversarial sweeps.
//!
//! Shape (M28): an [`Env`] is the ledger state every circuit may read plus
//! the call context; a [`Req`] is a Signet request as the record holds it,
//! with its Poseidon id; each scenario is `Env` + arguments + the flags
//! that pick a branch (`request_exists`, `pending`, the attested output).
//! The op stream is built from `ops::*` in the circuit's read order — the
//! order compactc's artifact reads in, which the differential pins — and
//! the popeq results are DERIVED from that stream (`ops::outputs_of`), so a
//! scenario cannot list an output its ops never read.

use std::borrow::Cow;

use midnight_base_crypto::fab::AlignedValue;
use midnight_curves::k256;
use midnight_transient_crypto::hash::transient_commit;
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage};
use midnight_zkir_v3::ir_instructions::ec_mul::ec_mul_offcircuit;
use minocrab::Fr;
use minocrab_contracts::erc20_vault as v;
use minocrab_zkir::v3::IrValue;

use super::exec::PreState;
use super::ops;
use super::prims::*;

// ---- the ledger fields, by declaration index ----------------------------------------

pub const SIGN_BIDIRECTIONAL_EVENT_MAP: u8 = 0;
pub const SIGNET_SIGNER: u8 = 1;
pub const MPC_RESPONSE_KEY: u8 = 2;
pub const SIGNET_REQUEST_NONCE: u8 = 3;
pub const INITIALISED: u8 = 4;
pub const VAULT_EVM_ADDRESS: u8 = 5;
pub const EVM_CHAIN_ID: u8 = 6;
pub const CAIP2_ID: u8 = 7;
pub const DEPLOYER: u8 = 8;
pub const DEPOSIT_EVENT_MAP: u8 = 9;
pub const DEPOSIT_SETTLE_VIEWS: u8 = 10;
pub const WITHDRAW_SETTLE_VIEWS: u8 = 11;
pub const UNISWAP_ROUTER: u8 = 12;
pub const SWAP_EVENT_MAP: u8 = 13;
pub const SWAP_SETTLE_VIEWS: u8 = 14;
pub const STATA_UNDERLYING: u8 = 15;
pub const STATA_TOKEN: u8 = 16;
pub const SUPPLY_EVENT_MAP: u8 = 17;
pub const SUPPLY_SETTLE_VIEWS: u8 = 18;
pub const REDEEM_EVENT_MAP: u8 = 19;
pub const REDEEM_SETTLE_VIEWS: u8 = 20;

/// The circuit's own `kernel.self()`.
pub const SELF_ADDR: [u8; 32] = {
    let mut a = [0u8; 32];
    let s = b"vault-addr";
    let mut i = 0;
    while i < s.len() {
        a[i] = s[i];
        i += 1;
    }
    a[31] = 0x31;
    a
};

/// A `[u8; 32]` from a short tag and a distinguishing top byte.
pub fn tagged32(tag: &[u8], top: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..tag.len()].copy_from_slice(tag);
    out[31] = top;
    out
}

// ---- the environment -------------------------------------------------------------------

/// The ledger cells every circuit may read, plus the call context: the
/// contract's own address, the singleton's, the MPC key's secret seed and
/// the signer's entry-point hash.
#[derive(Clone, Debug)]
pub struct Env {
    pub initialised: u64,
    pub request_nonce: u64,
    pub vault_evm: [u8; 20],
    pub chain_id: u64,
    pub caip2: [u8; 32],
    pub router: [u8; 20],
    pub stata_underlying: [u8; 20],
    pub stata_token: [u8; 20],
    /// The secret whose commitment the `deployer` cell holds.
    pub deployer_sk: [u8; 32],
    pub self_addr: [u8; 32],
    pub signer_addr: [u8; 32],
    /// The MPC response key's secret scalar seed.
    pub key_seed: u64,
    /// The singleton's `signBidirectional` entry-point hash.
    pub ep: [u8; 32],
}

impl Default for Env {
    fn default() -> Env {
        Env::new()
    }
}

impl Env {
    pub fn new() -> Env {
        let mut caip2 = [0u8; 32];
        caip2[..15].copy_from_slice(b"eip155:11155111");
        Env {
            initialised: 1,
            request_nonce: 4,
            vault_evm: *b"vault-evm-addr-20byt",
            chain_id: 11_155_111,
            caip2,
            router: *b"uniswap-router-20byt",
            stata_underlying: *b"stata-underlying-usd",
            stata_token: *b"stata-token-wrapper!",
            deployer_sk: tagged32(b"deployer", 0x11),
            self_addr: SELF_ADDR,
            signer_addr: tagged32(b"signet-addr", 0x32),
            key_seed: 0xf00d_face,
            // DERIVED from the singleton's circuit name (M12 stage 1).
            ep: minocrab_ledger::ep_hash("signBidirectional"),
        }
    }

    /// The MPC response key.
    pub fn mpc_key(&self) -> IrValue {
        let generator = IrValue::Secp256k1Point(k256::K256::generator());
        ec_mul_offcircuit(&generator, &scalar(self.key_seed)).unwrap()
    }

    /// The key as the `mpcResponseKey` cell holds it (5 FAB limbs).
    pub fn mpc_key_av(&self) -> AlignedValue {
        point_av(&self.mpc_key())
    }

    /// The `deployer` cell.
    pub fn deployer(&self) -> [u8; 32] {
        user_commitment(&self.deployer_sk)
    }

    /// The ledger with every cell set and every map empty.
    pub fn pre_state(&self) -> PreState {
        PreState {
            signet_signer: self.signer_addr,
            mpc_response_key: Some(self.mpc_key_av()),
            request_nonce: self.request_nonce,
            initialised: self.initialised,
            vault_evm: self.vault_evm,
            chain_id: self.chain_id,
            caip2: self.caip2,
            deployer: self.deployer(),
            uniswap_router: self.router,
            stata_underlying: self.stata_underlying,
            stata_token: self.stata_token,
            ..Default::default()
        }
    }

    // -- the reads every circuit shares --

    pub fn read_initialised(&self) -> Vec<VmOp> {
        ops::read(INITIALISED, true, bytesn_value(8, &self.initialised.to_le_bytes()))
    }
    pub fn read_mpc_key(&self) -> Vec<VmOp> {
        ops::read(MPC_RESPONSE_KEY, false, self.mpc_key_av())
    }
    pub fn read_chain_id(&self) -> Vec<VmOp> {
        ops::read(EVM_CHAIN_ID, false, bytesn_value(8, &self.chain_id.to_le_bytes()))
    }
    pub fn read_b20(&self, field: u8, value: &[u8; 20]) -> Vec<VmOp> {
        ops::read(field, false, bytesn_value(20, value))
    }
    pub fn kernel_self(&self) -> Vec<VmOp> {
        ops::kernel_self(&self.self_addr)
    }

    /// The three reads `constructSignBidirectionalEvent` makes:
    /// `signetRequestNonce`, `kernel.self()`, `caip2Id`.
    pub fn assemble_request_reads(&self) -> Vec<VmOp> {
        let mut o = ops::read(SIGNET_REQUEST_NONCE, true, bytesn_value(8, &self.request_nonce.to_le_bytes()));
        o.extend(self.kernel_self());
        o.extend(ops::read(CAIP2_ID, false, bytesn_value(32, &self.caip2)));
        o
    }

    /// The V1 notification payload: selfAddr ‖ depth ‖ path[4] ‖ zeros, as
    /// the `Bytes<128>` limbs in slot order.
    pub fn notification_payload_limbs(&self, map_field: u8) -> Vec<Fr> {
        let (seg, off) = ops::segment_of(map_field);
        let mut bytes = [0u8; 128];
        bytes[..32].copy_from_slice(&self.self_addr);
        bytes[32] = 2; // depth: every path is two elements
        bytes[33] = seg;
        bytes[34] = off;
        let mut limbs: Vec<Fr> = bytes
            .chunks(31)
            .map(|chunk| Fr::from_le_bytes(chunk).unwrap())
            .collect();
        limbs.reverse();
        limbs
    }

    /// The cross-contract-call args: requestId + notification (version,
    /// payload).
    pub fn call_args(&self, map_field: u8, request_id: &[u8; 32]) -> Vec<Fr> {
        let (rid_hi, rid_lo) = b32_slots(request_id);
        let mut args = vec![rid_hi, rid_lo, Fr::from(1u64)];
        args.extend(self.notification_payload_limbs(map_field));
        args
    }

    /// `signetSigner.signBidirectional(requestId, notification)`: the
    /// signer read, `kernel.self()`, the claimed call.
    pub fn notify_ops(&self, map_field: u8, request_id: &[u8; 32], cc_rand: Fr) -> Vec<VmOp> {
        let mut o = ops::read(SIGNET_SIGNER, false, bytesn_value(32, &self.signer_addr));
        o.extend(self.kernel_self());
        let comm = transient_commit(&self.call_args(map_field, request_id)[..], cc_rand);
        o.extend(ops::claim_contract_call(&self.signer_addr, &self.ep, comm));
        o
    }

    /// The cross-contract call's witnesses: `cc-rand`, then the entry-point
    /// hash's two limbs.
    pub fn call_witnesses(&self, cc_rand: Fr) -> Vec<Fr> {
        let (ep_hi, ep_lo) = b32_slots(&self.ep);
        vec![cc_rand, ep_hi, ep_lo]
    }

    /// `receiveShielded(coin); sendImmediateShielded(coin, burn, value)` —
    /// the custody claim, the nullifier, the evolved-nonce output.
    pub fn burn_ops(&self, coin_nonce: &[u8; 32], color: &[u8; 32], value: u128) -> Vec<VmOp> {
        let nonce_slots = b32_slots(coin_nonce);
        let cm_receive = coin_commitment_of(&nonce_slots, color, value, false, &self.self_addr);
        let nullifier = coin_nullifier_of(&nonce_slots, color, value, &self.self_addr);
        let cm_burn = coin_commitment_of(&evolved_nonce(coin_nonce), color, value, true, &[0u8; 32]);
        let mut o = self.kernel_self();
        o.extend(ops::claim(1, &cm_receive));
        o.extend(self.kernel_self());
        o.extend(ops::claim(0, &nullifier));
        o.extend(ops::claim(2, &cm_burn));
        o
    }

    /// `mintShieldedToken(vaultTokenDomainSeparator(erc20), amount, nonce,
    /// left(pk))`: `kernel.self()`, the mint, the spend claim.
    pub fn mint_to_key_ops(&self, erc20: &[u8; 20], amount: u64, nonce: &[u8; 32], pk: &[u8; 32]) -> Vec<VmOp> {
        let color = vault_color(erc20, &self.self_addr);
        let cm = coin_commitment_of(&b32_slots(nonce), &color, u128::from(amount), true, pk);
        let mut o = self.kernel_self();
        o.extend(ops::mint_and_spend(&vault_domain_sep(erc20), amount, &cm));
        o
    }
}

/// A `Secp256k1Point` as its cell value.
pub fn point_av(point: &IrValue) -> AlignedValue {
    aligned_atoms(&v::secp256k1_point_atoms(), &natives(point))
}

fn aligned_atoms(atoms: &[minocrab::AlignmentAtom], limbs: &[Fr]) -> AlignedValue {
    use midnight_base_crypto::fab::{Alignment, AlignmentSegment};
    use midnight_transient_crypto::fab::AlignmentExt;
    Alignment(atoms.iter().cloned().map(AlignmentSegment::Atom).collect())
        .parse_field_repr(limbs)
        .expect("limbs match the alignment")
}

/// The `ProofPreimage` a call implies: arguments, witnesses, the op stream's
/// `field_repr`, and the popeq results the stream reads.
pub fn preimage_of(inputs: Vec<Fr>, witnesses: Vec<Fr>, ops: &[VmOp], rand: Fr) -> ProofPreimage {
    let comm = transient_commit(&inputs[..], rand);
    ProofPreimage {
        public_transcript_inputs: ops::transcript_of(ops),
        public_transcript_outputs: ops::outputs_of(ops),
        inputs,
        private_transcript: witnesses,
        binding_input: 0.into(),
        communications_commitment: Some((comm, rand)),
        key_location: KeyLocation(Cow::Borrowed("minocrab-contracts-test")),
    }
}

// ---- a Signet request --------------------------------------------------------------------

/// The EVM transaction a request asks the MPC to sign.
#[derive(Clone, Debug)]
pub struct Tx {
    pub nonce: u64,
    pub priority_fee: u128,
    pub max_fee: u128,
    pub gas: u64,
    pub to: [u8; 20],
    pub selector: [u8; 4],
    pub words: Vec<[u8; 32]>,
}

impl Tx {
    /// A vault-signed call under the contract-FIXED gas envelope.
    pub fn fixed(nonce: u64, gas: u64, to: [u8; 20], selector: [u8; 4], words: Vec<[u8; 32]>) -> Tx {
        Tx {
            nonce,
            priority_fee: u128::from(v::FIXED_PRIORITY_FEE),
            max_fee: u128::from(v::FIXED_MAX_FEE),
            gas,
            to,
            selector,
            words,
        }
    }
}

/// A `SignBidirectionalEvent` as the record holds it.
#[derive(Clone, Debug)]
pub struct Req {
    pub key_version: u8,
    pub path: [u8; 32],
    pub tx: Tx,
    pub out_schema: &'static [u8],
    pub respond_schema: &'static [u8],
}

impl Req {
    /// The record's FAB limbs in slot order — the request id's Poseidon
    /// input and, parsed against [`Req::widths`], the map-insert value.
    pub fn limbs(&self, env: &Env) -> Vec<Fr> {
        let (self_hi, self_lo) = b32_slots(&env.self_addr);
        let (path_hi, path_lo) = b32_slots(&self.path);
        let (caip2_hi, caip2_lo) = b32_slots(&env.caip2);
        let mut limbs = vec![
            self_hi,
            self_lo,
            Fr::from(env.request_nonce),
            Fr::from(u64::from(self.key_version)),
            path_hi,
            path_lo,
            Fr::from(0u64), // algo: ecdsa
            Fr::from(0u64), // dest: unused
            Fr::from(0u64), // params: pad(64, "") — 3 limbs
            Fr::from(0u64),
            Fr::from(0u64),
            Fr::from(0u64), // txParamType: evmType2
            Fr::from(env.chain_id),
            Fr::from(self.tx.nonce),
            u128_limb(self.tx.priority_fee),
            u128_limb(self.tx.max_fee),
            Fr::from(self.tx.gas),
            b20(&self.tx.to),
            Fr::from(0u64), // value
            Fr::from(1u64), // calldata.is_some
            Fr::from_le_bytes(&self.tx.selector).unwrap(),
            Fr::from(self.tx.words.len() as u64), // noWords
        ];
        for w in &self.tx.words {
            let (hi, lo) = b32_slots(w);
            limbs.extend([hi, lo]);
        }
        limbs.push(Fr::from(0u64)); // accessListEntryCount
        limbs.extend([caip2_hi, caip2_lo]);
        let (o_hi, o_lo) = schema_slots(self.out_schema);
        let (r_hi, r_lo) = schema_slots(self.respond_schema);
        limbs.extend([o_hi, o_lo, r_hi, r_lo]);
        limbs
    }

    /// The record's FAB atom widths.
    pub fn widths(&self) -> Vec<u32> {
        let mut a = vec![32, 8, 1, 32, 1, 1, 64, 1, 8, 8, 16, 16, 8, 20, 16, 1, 4, 2];
        a.extend(std::iter::repeat_n(32u32, self.tx.words.len()));
        a.push(1);
        a.push(32);
        a.push(self.out_schema.len() as u32);
        a.push(self.respond_schema.len() as u32);
        a
    }

    /// The record as an AlignedValue (the map-insert's pushed cell).
    pub fn av(&self, env: &Env) -> AlignedValue {
        aligned(&self.widths(), &self.limbs(env))
    }

    /// `calculateRequestId(request)`.
    pub fn request_id(&self, env: &Env) -> [u8; 32] {
        request_id_of(&self.limbs(env))
    }
}

/// The record-then-notify tail every request circuit ends with: the
/// freshness check, the burn (when a coin is surrendered), the nonce
/// increment, the record insert, the settle-view insert, the notification.
#[allow(clippy::too_many_arguments)]
fn request_tail(
    env: &Env,
    map_field: u8,
    req: &Req,
    request_exists: bool,
    burn: Option<Vec<VmOp>>,
    view: Option<(u8, AlignedValue)>,
    cc_rand: Fr,
) -> Vec<VmOp> {
    let rid = req.request_id(env);
    let mut o = ops::member(map_field, &rid, request_exists);
    if let Some(burn) = burn {
        o.extend(burn);
    }
    o.extend(ops::counter_inc(SIGNET_REQUEST_NONCE));
    o.extend(ops::insert(map_field, &rid, req.av(env)));
    if let Some((field, av)) = view {
        o.extend(ops::insert(field, &rid, av));
    }
    o.extend(env.notify_ops(map_field, &rid, cc_rand));
    o
}

fn max_allowance_word() -> [u8; 32] {
    abi_num_word(u128::MAX)
}

fn unbounded_to_u64(v: u128) -> u64 {
    u64::try_from(v).unwrap_or(u64::MAX)
}

// ==== initialise ===========================================================================

/// The concrete `initialise()` call: the deployer's secret, the seven
/// configuration values, and the pre-state's `initialised` counter (in
/// `env`).
#[derive(Clone, Debug)]
pub struct InitialiseScenario {
    pub env: Env,
    /// The secret the CALLER witnesses; `env.deployer_sk` is whose
    /// commitment is stored.
    pub sk: [u8; 32],
    pub vault_evm: [u8; 20],
    pub swap_router: [u8; 20],
    pub stata_underlying: [u8; 20],
    pub stata_token: [u8; 20],
    pub chain_id: u64,
    pub caip2: [u8; 32],
    pub point: IrValue,
}

impl InitialiseScenario {
    pub fn new() -> InitialiseScenario {
        let env = Env {
            initialised: 0,
            ..Env::new()
        };
        InitialiseScenario {
            sk: env.deployer_sk,
            vault_evm: env.vault_evm,
            swap_router: env.router,
            stata_underlying: env.stata_underlying,
            stata_token: env.stata_token,
            chain_id: env.chain_id,
            caip2: env.caip2,
            point: env.mpc_key(),
            env,
        }
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let (caip2_hi, caip2_lo) = b32_slots(&self.caip2);
        let mut inputs = vec![
            b20(&self.vault_evm),
            b20(&self.swap_router),
            b20(&self.stata_underlying),
            b20(&self.stata_token),
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

    pub fn ops(&self) -> Vec<VmOp> {
        let mut o = self.env.read_initialised();
        o.extend(ops::read(DEPLOYER, false, bytesn_value(32, &self.env.deployer())));
        o.extend(ops::counter_inc(INITIALISED));
        o.extend(ops::cell_write(VAULT_EVM_ADDRESS, bytesn_value(20, &self.vault_evm)));
        o.extend(ops::cell_write(UNISWAP_ROUTER, bytesn_value(20, &self.swap_router)));
        o.extend(ops::cell_write(STATA_UNDERLYING, bytesn_value(20, &self.stata_underlying)));
        o.extend(ops::cell_write(STATA_TOKEN, bytesn_value(20, &self.stata_token)));
        o.extend(ops::cell_write(EVM_CHAIN_ID, bytesn_value(8, &self.chain_id.to_le_bytes())));
        o.extend(ops::cell_write(CAIP2_ID, bytesn_value(32, &self.caip2)));
        o.extend(ops::cell_write(MPC_RESPONSE_KEY, point_av(&self.point)));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0xe20u64))
    }

    /// `initialised == count`, `deployer == commitment`; the configuration
    /// cells unset (they are what this call writes).
    pub fn pre_state(&self) -> PreState {
        PreState {
            initialised: self.env.initialised,
            deployer: self.env.deployer(),
            ..Default::default()
        }
    }
}

// ==== the allowances =======================================================================

/// `approveStata(evmNonce, keyVersion)`.
#[derive(Clone, Debug)]
pub struct ApproveStataScenario {
    pub env: Env,
    pub evm_nonce: u64,
    pub key_version: u8,
    pub request_exists: bool,
    pub cc_rand: Fr,
}

impl ApproveStataScenario {
    pub fn new() -> ApproveStataScenario {
        ApproveStataScenario {
            env: Env::new(),
            evm_nonce: 3,
            key_version: 1,
            request_exists: false,
            cc_rand: Fr::from(0x57a7au64),
        }
    }

    pub fn req(&self) -> Req {
        Req {
            key_version: self.key_version,
            path: pad32(v::VAULT_PATH),
            tx: Tx::fixed(
                self.evm_nonce,
                v::ERC20_CALL_GAS,
                self.env.stata_underlying,
                v::APPROVE_SELECTOR,
                vec![abi_addr_word(&self.env.stata_token), max_allowance_word()],
            ),
            out_schema: v::VAULT_RESPONSE_SCHEMA,
            respond_schema: v::VAULT_RESPONSE_SCHEMA,
        }
    }

    pub fn request_id(&self) -> [u8; 32] {
        self.req().request_id(&self.env)
    }

    pub fn inputs(&self) -> Vec<Fr> {
        vec![Fr::from(self.evm_nonce), Fr::from(u64::from(self.key_version))]
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        self.env.call_witnesses(self.cc_rand)
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let mut o = self.env.read_initialised();
        o.extend(self.env.read_b20(STATA_TOKEN, &self.env.stata_token));
        o.extend(self.env.read_chain_id());
        o.extend(self.env.read_b20(STATA_UNDERLYING, &self.env.stata_underlying));
        o.extend(self.env.assemble_request_reads());
        o.extend(request_tail(&self.env, SIGN_BIDIRECTIONAL_EVENT_MAP, &self.req(), self.request_exists, None, None, self.cc_rand));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0xa5_7a7au64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.env.pre_state();
        if self.request_exists {
            pre.sign_event_map = vec![(self.request_id(), self.req().av(&self.env))];
        }
        pre
    }
}

/// `approveRouter(erc20Address, evmNonce, keyVersion)`.
#[derive(Clone, Debug)]
pub struct ApproveRouterScenario {
    pub env: Env,
    pub erc20: [u8; 20],
    pub evm_nonce: u64,
    pub key_version: u8,
    pub request_exists: bool,
    pub cc_rand: Fr,
}

impl ApproveRouterScenario {
    pub fn new() -> ApproveRouterScenario {
        ApproveRouterScenario {
            env: Env::new(),
            erc20: *b"erc20-token-contract",
            evm_nonce: 9,
            key_version: 1,
            request_exists: false,
            cc_rand: Fr::from(0xa11_0eu64),
        }
    }

    pub fn req(&self) -> Req {
        Req {
            key_version: self.key_version,
            path: pad32(v::VAULT_PATH),
            tx: Tx::fixed(
                self.evm_nonce,
                v::ERC20_CALL_GAS,
                self.erc20,
                v::APPROVE_SELECTOR,
                vec![abi_addr_word(&self.env.router), max_allowance_word()],
            ),
            out_schema: v::VAULT_RESPONSE_SCHEMA,
            respond_schema: v::VAULT_RESPONSE_SCHEMA,
        }
    }

    pub fn request_id(&self) -> [u8; 32] {
        self.req().request_id(&self.env)
    }

    pub fn inputs(&self) -> Vec<Fr> {
        vec![b20(&self.erc20), Fr::from(self.evm_nonce), Fr::from(u64::from(self.key_version))]
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        self.env.call_witnesses(self.cc_rand)
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let mut o = self.env.read_initialised();
        o.extend(self.env.read_b20(UNISWAP_ROUTER, &self.env.router));
        o.extend(self.env.read_chain_id());
        o.extend(self.env.assemble_request_reads());
        o.extend(request_tail(&self.env, SIGN_BIDIRECTIONAL_EVENT_MAP, &self.req(), self.request_exists, None, None, self.cc_rand));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0xa9_9a0u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.env.pre_state();
        if self.request_exists {
            pre.sign_event_map = vec![(self.request_id(), self.req().av(&self.env))];
        }
        pre
    }
}

// ==== deposit ==============================================================================

/// `startDeposit(evmNonce, gasLimit, maxFeePerGas, maxPriorityFeePerGas,
/// keyVersion, depositRequest)`.
#[derive(Clone, Debug)]
pub struct StartDepositScenario {
    pub env: Env,
    pub sk: [u8; 32],
    pub evm_nonce: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub key_version: u8,
    pub erc20: [u8; 20],
    /// `Uint<128>` in Compact: widened so generation can reach the band
    /// the `"Amount exceeds Uint<64> max"` guard rejects.
    pub amount: u128,
    pub request_exists: bool,
    pub cc_rand: Fr,
}

impl StartDepositScenario {
    pub fn new() -> StartDepositScenario {
        StartDepositScenario {
            env: Env::new(),
            sk: tagged32(b"depositor", 0x21),
            evm_nonce: 7,
            gas_limit: 65_000,
            max_fee_per_gas: 30_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            key_version: 1,
            erc20: *b"erc20-token-contract",
            amount: 123_456,
            request_exists: false,
            cc_rand: Fr::from(0xdeb_051_7u64),
        }
    }

    /// The depositor's identity commitment — the request's signing path.
    pub fn commitment(&self) -> [u8; 32] {
        user_commitment(&self.sk)
    }

    pub fn amount_u64(&self) -> u64 {
        unbounded_to_u64(self.amount)
    }

    pub fn req(&self) -> Req {
        Req {
            key_version: self.key_version,
            path: self.commitment(),
            tx: Tx {
                nonce: self.evm_nonce,
                priority_fee: self.max_priority_fee_per_gas,
                max_fee: self.max_fee_per_gas,
                gas: self.gas_limit,
                to: self.erc20,
                selector: v::TRANSFER_SELECTOR,
                words: vec![abi_addr_word(&self.env.vault_evm), abi_num_word(self.amount)],
            },
            out_schema: v::VAULT_RESPONSE_SCHEMA,
            respond_schema: v::VAULT_RESPONSE_SCHEMA,
        }
    }

    pub fn request_id(&self) -> [u8; 32] {
        self.req().request_id(&self.env)
    }

    /// The `DepositSettleView` the request pins.
    pub fn view_av(&self) -> AlignedValue {
        let (c_hi, c_lo) = b32_slots(&self.commitment());
        aligned(&[32, 20, 8], &[c_hi, c_lo, b20(&self.erc20), Fr::from(self.amount_u64())])
    }

    pub fn inputs(&self) -> Vec<Fr> {
        vec![
            Fr::from(self.evm_nonce),
            Fr::from(self.gas_limit),
            u128_limb(self.max_fee_per_gas),
            u128_limb(self.max_priority_fee_per_gas),
            Fr::from(u64::from(self.key_version)),
            b20(&self.erc20),
            u128_limb(self.amount),
        ]
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (sk_hi, sk_lo) = b32_slots(&self.sk);
        let mut w = vec![sk_hi, sk_lo];
        w.extend(self.env.call_witnesses(self.cc_rand));
        w
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let mut o = self.env.read_initialised();
        o.extend(self.env.read_b20(VAULT_EVM_ADDRESS, &self.env.vault_evm));
        o.extend(self.env.read_chain_id());
        o.extend(self.env.assemble_request_reads());
        o.extend(request_tail(
            &self.env,
            DEPOSIT_EVENT_MAP,
            &self.req(),
            self.request_exists,
            None,
            Some((DEPOSIT_SETTLE_VIEWS, self.view_av())),
            self.cc_rand,
        ));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0xde9_0517u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.env.pre_state();
        if self.request_exists {
            pre.deposit_event_map = vec![(self.request_id(), self.req().av(&self.env))];
        }
        pre
    }
}

/// Who a claim's minted coin goes to.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ClaimRecipient {
    /// `some(left(pk))` — a wallet key; the auto-receive branch is off.
    Key([u8; 32]),
    /// `some(right(addr))` — a contract; auto-receive fires iff addr ==
    /// self.
    Contract([u8; 32]),
    /// `none` — `left(ownPublicKey())`, witnessed.
    None([u8; 32]),
}

/// The part every settle circuit shares: whether the map still holds the
/// request, the mint nonce, the caller's own key, whose secret is
/// presented, and the signature nonce seed.
#[derive(Clone, Debug)]
pub struct Settle {
    /// The map member answer the circuit reads (the double-settle gate).
    pub pending: bool,
    pub mint_nonce: [u8; 32],
    /// `ownPublicKey()` as witnessed (the mint recipient of every
    /// caller-only settle).
    pub own_pk: [u8; 32],
    /// The secret the CALLER witnesses. `None` = the requester's own (the
    /// gate passes); `Some(other)` drives the "Not the …" guard.
    pub claimant_sk: Option<[u8; 32]>,
    pub nonce_seed: u64,
}

impl Settle {
    pub fn new() -> Settle {
        Settle {
            pending: true,
            mint_nonce: tagged32(b"mint-nonce!", 0x41),
            own_pk: tagged32(b"own-pk", 0x43),
            claimant_sk: None,
            nonce_seed: 0x0dd_b17,
        }
    }

    /// The secret key the caller presents.
    pub fn sk(&self, requester: &[u8; 32]) -> [u8; 32] {
        self.claimant_sk.unwrap_or(*requester)
    }

    /// The attestation's `(bigR.x, s)`, little-endian — the circuit-input
    /// form.
    pub fn signature(&self, env: &Env, request_id: &[u8; 32], output_limbs: &[Fr]) -> ([u8; 32], [u8; 32]) {
        let digest = attestation_digest(request_id, output_limbs);
        let (r_le, s_le, _) = sign(&digest, &scalar(env.key_seed), &scalar(self.nonce_seed));
        (r_le, s_le)
    }

    /// The settle circuits' leading argument slots: `requestId`,
    /// `respondBidirectionalEvent` (bigR.x, bigR.y, s, recoveryId),
    /// `serializedOutput`.
    pub fn head_inputs(&self, env: &Env, request_id: &[u8; 32], output_limbs: &[Fr]) -> Vec<Fr> {
        let (rid_hi, rid_lo) = b32_slots(request_id);
        let (rx, sx) = self.signature(env, request_id, output_limbs);
        let (rx_hi, rx_lo) = b32_slots(&rx);
        let (s_hi, s_lo) = b32_slots(&sx);
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
        inputs.extend_from_slice(output_limbs);
        inputs
    }

    pub fn nonce_slots(&self) -> [Fr; 2] {
        let (hi, lo) = b32_slots(&self.mint_nonce);
        [hi, lo]
    }

    /// `[sk, ownPublicKey()]` — the witnesses of a caller-only settle.
    pub fn witnesses_with_own_pk(&self, requester: &[u8; 32]) -> Vec<Fr> {
        let (sk_hi, sk_lo) = b32_slots(&self.sk(requester));
        let (pk_hi, pk_lo) = b32_slots(&self.own_pk);
        vec![sk_hi, sk_lo, pk_hi, pk_lo]
    }
}

/// The MPC's failure output, as the `Bytes<5>` argument's one limb.
pub fn failure_output_limb(output: &[u8; 5]) -> Fr {
    Fr::from_le_bytes(output).expect("5 bytes fit")
}

/// `completeDeposit(requestId, respond, serializedOutput: Bytes<1>,
/// mintNonce, recipient)`.
#[derive(Clone, Debug)]
pub struct CompleteDepositScenario {
    pub d: StartDepositScenario,
    pub settle: Settle,
    pub recipient: ClaimRecipient,
    /// The attested EVM result byte: `deserialize<VaultResponse, 1>` reads
    /// it as `byte == 1`, so only `0x01` is a success.
    pub serialized_output: u8,
}

impl CompleteDepositScenario {
    pub fn new() -> CompleteDepositScenario {
        CompleteDepositScenario {
            d: StartDepositScenario::new(),
            settle: Settle::new(),
            recipient: ClaimRecipient::Key(tagged32(b"claim-pk", 0x42)),
            serialized_output: 1,
        }
    }

    pub fn env(&self) -> &Env {
        &self.d.env
    }

    pub fn output_limbs(&self) -> Vec<Fr> {
        vec![Fr::from(u64::from(self.serialized_output))]
    }

    /// The mint recipient as coinCommitment sees it: (is_left, data).
    pub fn recipient_data(&self) -> (bool, [u8; 32]) {
        match self.recipient {
            ClaimRecipient::Key(pk) => (true, pk),
            ClaimRecipient::Contract(addr) => (false, addr),
            ClaimRecipient::None(own_pk) => (true, own_pk),
        }
    }

    pub fn coin_commitment(&self) -> [u8; 32] {
        let color = vault_color(&self.d.erc20, &self.env().self_addr);
        let (is_left, data) = self.recipient_data();
        coin_commitment_of(&b32_slots(&self.settle.mint_nonce), &color, u128::from(self.d.amount_u64()), is_left, &data)
    }

    /// Does the branch's guarded kernel.self read fire? (Its guard is
    /// only `!is_left`.)
    pub fn self_read_fires(&self) -> bool {
        matches!(self.recipient, ClaimRecipient::Contract(_))
    }

    /// Does the auto-receive claim fire? (`!is_left && right == self`.)
    pub fn auto_receive(&self) -> bool {
        matches!(self.recipient, ClaimRecipient::Contract(addr) if addr == self.env().self_addr)
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let mut inputs = self.settle.head_inputs(self.env(), &self.d.request_id(), &self.output_limbs());
        inputs.extend(self.settle.nonce_slots());
        let (is_some, is_left, left, right) = match self.recipient {
            ClaimRecipient::Key(pk) => (1u64, 1u64, pk, [0u8; 32]),
            ClaimRecipient::Contract(addr) => (1, 0, [0u8; 32], addr),
            ClaimRecipient::None(_) => (0, 0, [0u8; 32], [0u8; 32]),
        };
        let (l_hi, l_lo) = b32_slots(&left);
        let (r_hi, r_lo) = b32_slots(&right);
        inputs.extend([Fr::from(is_some), Fr::from(is_left), l_hi, l_lo, r_hi, r_lo]);
        inputs
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (sk_hi, sk_lo) = b32_slots(&self.settle.sk(&self.d.sk));
        let mut w = vec![sk_hi, sk_lo];
        if let ClaimRecipient::None(own_pk) = self.recipient {
            let (pk_hi, pk_lo) = b32_slots(&own_pk);
            w.extend([pk_hi, pk_lo]);
        }
        w
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let env = self.env();
        let rid = self.d.request_id();
        let cm = self.coin_commitment();
        let mut o = env.read_initialised();
        o.extend(env.read_mpc_key());
        o.extend(ops::member(DEPOSIT_EVENT_MAP, &rid, self.settle.pending));
        o.extend(ops::remove(DEPOSIT_EVENT_MAP, &rid));
        o.extend(ops::lookup(DEPOSIT_SETTLE_VIEWS, &rid, self.d.view_av()));
        o.extend(ops::remove(DEPOSIT_SETTLE_VIEWS, &rid));
        // mintShieldedToken: kernel.self(), the mint, the spend claim.
        o.extend(env.kernel_self());
        o.extend(ops::mint_and_spend(&vault_domain_sep(&self.d.erc20), self.d.amount_u64(), &cm));
        if self.self_read_fires() {
            o.extend(env.kernel_self());
        }
        if self.auto_receive() {
            o.extend(ops::claim(1, &cm));
        }
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0xc1a_1au64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.env().pre_state();
        let rid = self.d.request_id();
        if self.settle.pending {
            pre.deposit_event_map = vec![(rid, self.d.req().av(self.env()))];
        }
        pre.deposit_settle_views = vec![(rid, self.d.view_av())];
        pre
    }
}

// ==== withdraw =============================================================================

/// `startWithdraw(evmNonce, keyVersion, withdrawRequest, coin)`.
#[derive(Clone, Debug)]
pub struct StartWithdrawScenario {
    pub env: Env,
    pub sk: [u8; 32],
    pub evm_nonce: u64,
    pub key_version: u8,
    pub erc20: [u8; 20],
    pub amount: u128,
    pub dest: [u8; 20],
    pub coin_nonce: [u8; 32],
    /// The surrendered coin's colour — the vault token's by default; a
    /// scenario may present another.
    pub coin_color: Option<[u8; 32]>,
    /// The surrendered coin's value — `amount` by default.
    pub coin_value: Option<u128>,
    pub request_exists: bool,
    pub cc_rand: Fr,
}

impl StartWithdrawScenario {
    pub fn new() -> StartWithdrawScenario {
        StartWithdrawScenario {
            env: Env::new(),
            sk: tagged32(b"withdrawer", 0x22),
            evm_nonce: 11,
            key_version: 1,
            erc20: *b"erc20-token-contract",
            amount: 98_765,
            dest: *b"dest-evm-address-20b",
            coin_nonce: tagged32(b"coin-nonce", 0x44),
            coin_color: None,
            coin_value: None,
            request_exists: false,
            cc_rand: Fr::from(0x0d0_0ffu64),
        }
    }

    pub fn amount_u64(&self) -> u64 {
        unbounded_to_u64(self.amount)
    }

    /// The vault token's colour for this ERC20.
    pub fn vault_color(&self) -> [u8; 32] {
        vault_color(&self.erc20, &self.env.self_addr)
    }

    pub fn coin_color(&self) -> [u8; 32] {
        self.coin_color.unwrap_or_else(|| self.vault_color())
    }

    pub fn coin_value(&self) -> u128 {
        self.coin_value.unwrap_or(self.amount)
    }

    pub fn req(&self) -> Req {
        Req {
            key_version: self.key_version,
            path: pad32(v::VAULT_PATH),
            tx: Tx::fixed(
                self.evm_nonce,
                v::ERC20_CALL_GAS,
                self.erc20,
                v::TRANSFER_SELECTOR,
                vec![abi_addr_word(&self.dest), abi_num_word(self.amount)],
            ),
            out_schema: v::VAULT_RESPONSE_SCHEMA,
            respond_schema: v::VAULT_RESPONSE_SCHEMA,
        }
    }

    pub fn request_id(&self) -> [u8; 32] {
        self.req().request_id(&self.env)
    }

    pub fn refund_commitment(&self) -> [u8; 32] {
        refund_commitment(&self.sk, &self.request_id())
    }

    /// The `WithdrawSettleView` the request pins.
    pub fn view_av(&self) -> AlignedValue {
        let (c_hi, c_lo) = b32_slots(&self.refund_commitment());
        aligned(&[32, 20, 8], &[c_hi, c_lo, b20(&self.erc20), Fr::from(self.amount_u64())])
    }

    pub fn coin_inputs(&self) -> Vec<Fr> {
        let (n_hi, n_lo) = b32_slots(&self.coin_nonce);
        let (c_hi, c_lo) = b32_slots(&self.coin_color());
        vec![n_hi, n_lo, c_hi, c_lo, u128_limb(self.coin_value())]
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let mut inputs = vec![
            Fr::from(self.evm_nonce),
            Fr::from(u64::from(self.key_version)),
            b20(&self.erc20),
            u128_limb(self.amount),
            b20(&self.dest),
        ];
        inputs.extend(self.coin_inputs());
        inputs
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (sk_hi, sk_lo) = b32_slots(&self.sk);
        let mut w = vec![sk_hi, sk_lo];
        w.extend(self.env.call_witnesses(self.cc_rand));
        w
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let mut o = self.env.read_initialised();
        // tokenType's kernel.self()
        o.extend(self.env.kernel_self());
        o.extend(self.env.read_chain_id());
        o.extend(self.env.assemble_request_reads());
        o.extend(request_tail(
            &self.env,
            SIGN_BIDIRECTIONAL_EVENT_MAP,
            &self.req(),
            self.request_exists,
            Some(self.env.burn_ops(&self.coin_nonce, &self.coin_color(), self.coin_value())),
            Some((WITHDRAW_SETTLE_VIEWS, self.view_av())),
            self.cc_rand,
        ));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0x41d_0517u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.env.pre_state();
        if self.request_exists {
            pre.sign_event_map = vec![(self.request_id(), self.req().av(&self.env))];
        }
        pre
    }
}

/// `completeWithdraw(requestId, respond, serializedOutput: Bytes<1>,
/// mintNonce)`.
#[derive(Clone, Debug)]
pub struct CompleteWithdrawScenario {
    pub w: StartWithdrawScenario,
    pub settle: Settle,
    /// The attested EVM result byte; anything but `0x01` is a failed
    /// transfer and routes to the withdrawer-only re-mint.
    pub outcome: u8,
}

impl CompleteWithdrawScenario {
    pub fn new(outcome: u8) -> CompleteWithdrawScenario {
        CompleteWithdrawScenario {
            w: StartWithdrawScenario::new(),
            settle: Settle::new(),
            outcome,
        }
    }

    pub fn env(&self) -> &Env {
        &self.w.env
    }

    pub fn refunding(&self) -> bool {
        self.outcome != 1
    }

    pub fn output_limbs(&self) -> Vec<Fr> {
        vec![Fr::from(u64::from(self.outcome))]
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let mut inputs = self.settle.head_inputs(self.env(), &self.w.request_id(), &self.output_limbs());
        inputs.extend(self.settle.nonce_slots());
        inputs
    }

    /// The secret is witnessed UNCONDITIONALLY (the commitment is hoisted
    /// out of the `if`); `ownPublicKey()` only on the refund branch.
    pub fn witnesses(&self) -> Vec<Fr> {
        let (sk_hi, sk_lo) = b32_slots(&self.settle.sk(&self.w.sk));
        let mut w = vec![sk_hi, sk_lo];
        if self.refunding() {
            let (pk_hi, pk_lo) = b32_slots(&self.settle.own_pk);
            w.extend([pk_hi, pk_lo]);
        }
        w
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let env = self.env();
        let rid = self.w.request_id();
        let mut o = env.read_initialised();
        o.extend(env.read_mpc_key());
        o.extend(ops::member(WITHDRAW_SETTLE_VIEWS, &rid, self.settle.pending));
        o.extend(ops::lookup(WITHDRAW_SETTLE_VIEWS, &rid, self.w.view_av()));
        o.extend(ops::remove(SIGN_BIDIRECTIONAL_EVENT_MAP, &rid));
        if self.refunding() {
            o.extend(env.mint_to_key_ops(&self.w.erc20, self.w.amount_u64(), &self.settle.mint_nonce, &self.settle.own_pk));
        }
        o.extend(ops::remove(WITHDRAW_SETTLE_VIEWS, &rid));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0xc0_0517u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.env().pre_state();
        let rid = self.w.request_id();
        pre.sign_event_map = vec![(rid, self.w.req().av(self.env()))];
        if self.settle.pending {
            pre.withdraw_settle_views = vec![(rid, self.w.view_av())];
        }
        pre
    }
}

/// `refundWithdraw(requestId, respond, serializedOutput: Bytes<5>,
/// mintNonce)`.
#[derive(Clone, Debug)]
pub struct RefundWithdrawScenario {
    pub w: StartWithdrawScenario,
    pub settle: Settle,
    /// The attested output; only `MPC_FAILURE_OUTPUT` refunds.
    pub serialized_output: [u8; 5],
}

impl RefundWithdrawScenario {
    pub fn new() -> RefundWithdrawScenario {
        RefundWithdrawScenario {
            w: StartWithdrawScenario::new(),
            settle: Settle::new(),
            serialized_output: v::MPC_FAILURE_OUTPUT,
        }
    }

    pub fn env(&self) -> &Env {
        &self.w.env
    }

    pub fn output_limbs(&self) -> Vec<Fr> {
        vec![failure_output_limb(&self.serialized_output)]
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let mut inputs = self.settle.head_inputs(self.env(), &self.w.request_id(), &self.output_limbs());
        inputs.extend(self.settle.nonce_slots());
        inputs
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        self.settle.witnesses_with_own_pk(&self.w.sk)
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let env = self.env();
        let rid = self.w.request_id();
        let mut o = env.read_initialised();
        o.extend(env.read_mpc_key());
        o.extend(ops::member(WITHDRAW_SETTLE_VIEWS, &rid, self.settle.pending));
        o.extend(ops::lookup(WITHDRAW_SETTLE_VIEWS, &rid, self.w.view_av()));
        o.extend(ops::remove(SIGN_BIDIRECTIONAL_EVENT_MAP, &rid));
        o.extend(ops::remove(WITHDRAW_SETTLE_VIEWS, &rid));
        o.extend(env.mint_to_key_ops(&self.w.erc20, self.w.amount_u64(), &self.settle.mint_nonce, &self.settle.own_pk));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0x4ef_0517u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.env().pre_state();
        let rid = self.w.request_id();
        pre.sign_event_map = vec![(rid, self.w.req().av(self.env()))];
        if self.settle.pending {
            pre.withdraw_settle_views = vec![(rid, self.w.view_av())];
        }
        pre
    }
}

// ==== swap =================================================================================

/// `startSwap(evmNonce, keyVersion, swapRequest, coin)`.
#[derive(Clone, Debug)]
pub struct StartSwapScenario {
    pub env: Env,
    pub sk: [u8; 32],
    pub evm_nonce: u64,
    pub key_version: u8,
    pub token_in: [u8; 20],
    pub token_out: [u8; 20],
    pub fee: u32,
    pub amount_out: u128,
    pub amount_in_max: u128,
    pub coin_nonce: [u8; 32],
    pub coin_color: Option<[u8; 32]>,
    pub coin_value: Option<u128>,
    pub request_exists: bool,
    pub cc_rand: Fr,
}

impl StartSwapScenario {
    pub fn new() -> StartSwapScenario {
        StartSwapScenario {
            env: Env::new(),
            sk: tagged32(b"swapper", 0x23),
            evm_nonce: 13,
            key_version: 1,
            token_in: *b"token-in-contract-20",
            token_out: *b"token-out-contract20",
            fee: 3000,
            amount_out: 50_000,
            amount_in_max: 60_000,
            coin_nonce: tagged32(b"swap-coin-nonce", 0x45),
            coin_color: None,
            coin_value: None,
            request_exists: false,
            cc_rand: Fr::from(0x5aa_9u64),
        }
    }

    pub fn amount_out_u64(&self) -> u64 {
        unbounded_to_u64(self.amount_out)
    }

    pub fn amount_in_max_u64(&self) -> u64 {
        unbounded_to_u64(self.amount_in_max)
    }

    pub fn vault_color(&self) -> [u8; 32] {
        vault_color(&self.token_in, &self.env.self_addr)
    }

    pub fn coin_color(&self) -> [u8; 32] {
        self.coin_color.unwrap_or_else(|| self.vault_color())
    }

    pub fn coin_value(&self) -> u128 {
        self.coin_value.unwrap_or(self.amount_in_max)
    }

    pub fn req(&self) -> Req {
        Req {
            key_version: self.key_version,
            path: pad32(v::VAULT_PATH),
            tx: Tx::fixed(
                self.evm_nonce,
                v::SWAP_GAS,
                self.env.router,
                v::EXACT_OUTPUT_SINGLE_SELECTOR,
                vec![
                    abi_addr_word(&self.token_in),
                    abi_addr_word(&self.token_out),
                    abi_num_word(u128::from(self.fee)),
                    abi_addr_word(&self.env.vault_evm),
                    abi_num_word(self.amount_out),
                    abi_num_word(self.amount_in_max),
                    [0u8; 32],
                ],
            ),
            out_schema: v::SWAP_OUTPUT_SCHEMA,
            respond_schema: v::SWAP_RESPOND_SCHEMA,
        }
    }

    pub fn request_id(&self) -> [u8; 32] {
        self.req().request_id(&self.env)
    }

    pub fn refund_commitment(&self) -> [u8; 32] {
        refund_commitment(&self.sk, &self.request_id())
    }

    /// The `SwapSettleView` the request pins.
    pub fn view_av(&self) -> AlignedValue {
        let (c_hi, c_lo) = b32_slots(&self.refund_commitment());
        aligned(
            &[32, 20, 20, 8, 8],
            &[
                c_hi,
                c_lo,
                b20(&self.token_in),
                b20(&self.token_out),
                Fr::from(self.amount_out_u64()),
                Fr::from(self.amount_in_max_u64()),
            ],
        )
    }

    pub fn coin_inputs(&self) -> Vec<Fr> {
        let (n_hi, n_lo) = b32_slots(&self.coin_nonce);
        let (c_hi, c_lo) = b32_slots(&self.coin_color());
        vec![n_hi, n_lo, c_hi, c_lo, u128_limb(self.coin_value())]
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let mut inputs = vec![
            Fr::from(self.evm_nonce),
            Fr::from(u64::from(self.key_version)),
            b20(&self.token_in),
            b20(&self.token_out),
            Fr::from(u64::from(self.fee)),
            u128_limb(self.amount_out),
            u128_limb(self.amount_in_max),
        ];
        inputs.extend(self.coin_inputs());
        inputs
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (sk_hi, sk_lo) = b32_slots(&self.sk);
        let mut w = vec![sk_hi, sk_lo];
        w.extend(self.env.call_witnesses(self.cc_rand));
        w
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let mut o = self.env.read_initialised();
        o.extend(self.env.kernel_self());
        o.extend(self.env.read_b20(VAULT_EVM_ADDRESS, &self.env.vault_evm));
        o.extend(self.env.read_chain_id());
        o.extend(self.env.read_b20(UNISWAP_ROUTER, &self.env.router));
        o.extend(self.env.assemble_request_reads());
        o.extend(request_tail(
            &self.env,
            SWAP_EVENT_MAP,
            &self.req(),
            self.request_exists,
            Some(self.env.burn_ops(&self.coin_nonce, &self.coin_color(), self.coin_value())),
            Some((SWAP_SETTLE_VIEWS, self.view_av())),
            self.cc_rand,
        ));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0x5a_0517u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.env.pre_state();
        if self.request_exists {
            pre.swap_event_map = vec![(self.request_id(), self.req().av(&self.env))];
        }
        pre
    }
}

/// `completeSwap(requestId, respond, serializedOutput: Bytes<8>,
/// mintNonce, changeNonce)`.
#[derive(Clone, Debug)]
pub struct CompleteSwapScenario {
    pub s: StartSwapScenario,
    pub settle: Settle,
    /// The attested `amountIn` the swap spent (packed to 8 bytes).
    pub amount_in: u64,
    pub change_nonce: [u8; 32],
}

impl CompleteSwapScenario {
    pub fn new() -> CompleteSwapScenario {
        CompleteSwapScenario {
            s: StartSwapScenario::new(),
            settle: Settle::new(),
            amount_in: 55_000,
            change_nonce: tagged32(b"change-nonce", 0x46),
        }
    }

    pub fn env(&self) -> &Env {
        &self.s.env
    }

    pub fn output_limbs(&self) -> Vec<Fr> {
        vec![Fr::from(self.amount_in)]
    }

    /// `amountInMaximum − amountIn`, when it does not underflow.
    pub fn change(&self) -> Option<u64> {
        self.s.amount_in_max_u64().checked_sub(self.amount_in)
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let mut inputs = self.settle.head_inputs(self.env(), &self.s.request_id(), &self.output_limbs());
        inputs.extend(self.settle.nonce_slots());
        let (c_hi, c_lo) = b32_slots(&self.change_nonce);
        inputs.extend([c_hi, c_lo]);
        inputs
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        self.settle.witnesses_with_own_pk(&self.s.sk)
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let env = self.env();
        let rid = self.s.request_id();
        let mut o = env.read_initialised();
        o.extend(env.read_mpc_key());
        o.extend(ops::member(SWAP_SETTLE_VIEWS, &rid, self.settle.pending));
        o.extend(ops::lookup(SWAP_SETTLE_VIEWS, &rid, self.s.view_av()));
        o.extend(ops::remove(SWAP_EVENT_MAP, &rid));
        o.extend(ops::remove(SWAP_SETTLE_VIEWS, &rid));
        o.extend(env.mint_to_key_ops(&self.s.token_out, self.s.amount_out_u64(), &self.settle.mint_nonce, &self.settle.own_pk));
        // The change coin (the wrapping difference when it underflows —
        // the circuit rejects before this is read).
        let change = self.s.amount_in_max_u64().wrapping_sub(self.amount_in);
        o.extend(env.mint_to_key_ops(&self.s.token_in, change, &self.change_nonce, &self.settle.own_pk));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0xc5a_0517u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.env().pre_state();
        let rid = self.s.request_id();
        pre.swap_event_map = vec![(rid, self.s.req().av(self.env()))];
        if self.settle.pending {
            pre.swap_settle_views = vec![(rid, self.s.view_av())];
        }
        pre
    }
}

/// `refundSwap(requestId, respond, serializedOutput: Bytes<5>, mintNonce)`.
#[derive(Clone, Debug)]
pub struct RefundSwapScenario {
    pub s: StartSwapScenario,
    pub settle: Settle,
    pub serialized_output: [u8; 5],
}

impl RefundSwapScenario {
    pub fn new() -> RefundSwapScenario {
        RefundSwapScenario {
            s: StartSwapScenario::new(),
            settle: Settle::new(),
            serialized_output: v::MPC_FAILURE_OUTPUT,
        }
    }

    pub fn env(&self) -> &Env {
        &self.s.env
    }

    pub fn output_limbs(&self) -> Vec<Fr> {
        vec![failure_output_limb(&self.serialized_output)]
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let mut inputs = self.settle.head_inputs(self.env(), &self.s.request_id(), &self.output_limbs());
        inputs.extend(self.settle.nonce_slots());
        inputs
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        self.settle.witnesses_with_own_pk(&self.s.sk)
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let env = self.env();
        let rid = self.s.request_id();
        let mut o = env.read_initialised();
        o.extend(env.read_mpc_key());
        o.extend(ops::member(SWAP_SETTLE_VIEWS, &rid, self.settle.pending));
        o.extend(ops::lookup(SWAP_SETTLE_VIEWS, &rid, self.s.view_av()));
        o.extend(ops::remove(SWAP_EVENT_MAP, &rid));
        o.extend(ops::remove(SWAP_SETTLE_VIEWS, &rid));
        o.extend(env.mint_to_key_ops(&self.s.token_in, self.s.amount_in_max_u64(), &self.settle.mint_nonce, &self.settle.own_pk));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0x4e5a_0517u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.env().pre_state();
        let rid = self.s.request_id();
        pre.swap_event_map = vec![(rid, self.s.req().av(self.env()))];
        if self.settle.pending {
            pre.swap_settle_views = vec![(rid, self.s.view_av())];
        }
        pre
    }
}

// ==== supply (Aave, via the stataUSDC wrapper) =============================================

/// `startSupply(evmNonce, keyVersion, amount, coin)`.
#[derive(Clone, Debug)]
pub struct StartSupplyScenario {
    pub env: Env,
    pub sk: [u8; 32],
    pub evm_nonce: u64,
    pub key_version: u8,
    pub amount: u128,
    pub coin_nonce: [u8; 32],
    pub coin_color: Option<[u8; 32]>,
    pub coin_value: Option<u128>,
    pub request_exists: bool,
    pub cc_rand: Fr,
}

impl StartSupplyScenario {
    pub fn new() -> StartSupplyScenario {
        StartSupplyScenario {
            env: Env::new(),
            sk: tagged32(b"supplier", 0x24),
            evm_nonce: 17,
            key_version: 1,
            amount: 250_000,
            coin_nonce: tagged32(b"supply-coin-nonce", 0x47),
            coin_color: None,
            coin_value: None,
            request_exists: false,
            cc_rand: Fr::from(0x5099_17u64),
        }
    }

    pub fn amount_u64(&self) -> u64 {
        unbounded_to_u64(self.amount)
    }

    /// The vault token's colour for the underlying.
    pub fn vault_color(&self) -> [u8; 32] {
        vault_color(&self.env.stata_underlying, &self.env.self_addr)
    }

    pub fn coin_color(&self) -> [u8; 32] {
        self.coin_color.unwrap_or_else(|| self.vault_color())
    }

    pub fn coin_value(&self) -> u128 {
        self.coin_value.unwrap_or(self.amount)
    }

    pub fn req(&self) -> Req {
        Req {
            key_version: self.key_version,
            path: pad32(v::VAULT_PATH),
            tx: Tx::fixed(
                self.evm_nonce,
                v::LENDING_GAS,
                self.env.stata_token,
                v::DEPOSIT_SELECTOR,
                vec![abi_num_word(self.amount), abi_addr_word(&self.env.vault_evm)],
            ),
            out_schema: v::SUPPLY_OUTPUT_SCHEMA,
            respond_schema: v::SUPPLY_RESPOND_SCHEMA,
        }
    }

    pub fn request_id(&self) -> [u8; 32] {
        self.req().request_id(&self.env)
    }

    pub fn refund_commitment(&self) -> [u8; 32] {
        refund_commitment(&self.sk, &self.request_id())
    }

    /// The `SupplySettleView` the request pins.
    pub fn view_av(&self) -> AlignedValue {
        let (c_hi, c_lo) = b32_slots(&self.refund_commitment());
        aligned(&[32, 8], &[c_hi, c_lo, Fr::from(self.amount_u64())])
    }

    pub fn coin_inputs(&self) -> Vec<Fr> {
        let (n_hi, n_lo) = b32_slots(&self.coin_nonce);
        let (c_hi, c_lo) = b32_slots(&self.coin_color());
        vec![n_hi, n_lo, c_hi, c_lo, u128_limb(self.coin_value())]
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let mut inputs = vec![
            Fr::from(self.evm_nonce),
            Fr::from(u64::from(self.key_version)),
            u128_limb(self.amount),
        ];
        inputs.extend(self.coin_inputs());
        inputs
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (sk_hi, sk_lo) = b32_slots(&self.sk);
        let mut w = vec![sk_hi, sk_lo];
        w.extend(self.env.call_witnesses(self.cc_rand));
        w
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let mut o = self.env.read_initialised();
        o.extend(self.env.read_b20(STATA_UNDERLYING, &self.env.stata_underlying));
        o.extend(self.env.kernel_self());
        o.extend(self.env.read_b20(VAULT_EVM_ADDRESS, &self.env.vault_evm));
        o.extend(self.env.read_chain_id());
        o.extend(self.env.read_b20(STATA_TOKEN, &self.env.stata_token));
        o.extend(self.env.assemble_request_reads());
        o.extend(request_tail(
            &self.env,
            SUPPLY_EVENT_MAP,
            &self.req(),
            self.request_exists,
            Some(self.env.burn_ops(&self.coin_nonce, &self.coin_color(), self.coin_value())),
            Some((SUPPLY_SETTLE_VIEWS, self.view_av())),
            self.cc_rand,
        ));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0x50_0517u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.env.pre_state();
        if self.request_exists {
            pre.supply_event_map = vec![(self.request_id(), self.req().av(&self.env))];
        }
        pre
    }
}

/// `completeSupply(requestId, respond, serializedOutput: Bytes<8>,
/// mintNonce)`.
#[derive(Clone, Debug)]
pub struct CompleteSupplyScenario {
    pub s: StartSupplyScenario,
    pub settle: Settle,
    /// The attested shares minted by the wrapper.
    pub shares: u64,
}

impl CompleteSupplyScenario {
    pub fn new() -> CompleteSupplyScenario {
        CompleteSupplyScenario {
            s: StartSupplyScenario::new(),
            settle: Settle::new(),
            shares: 249_000,
        }
    }

    pub fn env(&self) -> &Env {
        &self.s.env
    }

    pub fn output_limbs(&self) -> Vec<Fr> {
        vec![Fr::from(self.shares)]
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let mut inputs = self.settle.head_inputs(self.env(), &self.s.request_id(), &self.output_limbs());
        inputs.extend(self.settle.nonce_slots());
        inputs
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        self.settle.witnesses_with_own_pk(&self.s.sk)
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let env = self.env();
        let rid = self.s.request_id();
        let mut o = env.read_initialised();
        o.extend(env.read_mpc_key());
        o.extend(ops::member(SUPPLY_EVENT_MAP, &rid, self.settle.pending));
        o.extend(ops::remove(SUPPLY_EVENT_MAP, &rid));
        o.extend(ops::lookup(SUPPLY_SETTLE_VIEWS, &rid, self.s.view_av()));
        o.extend(ops::remove(SUPPLY_SETTLE_VIEWS, &rid));
        o.extend(env.read_b20(STATA_TOKEN, &env.stata_token));
        o.extend(env.mint_to_key_ops(&env.stata_token, self.shares, &self.settle.mint_nonce, &self.settle.own_pk));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0xc50_0517u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.env().pre_state();
        let rid = self.s.request_id();
        if self.settle.pending {
            pre.supply_event_map = vec![(rid, self.s.req().av(self.env()))];
        }
        pre.supply_settle_views = vec![(rid, self.s.view_av())];
        pre
    }
}

/// `refundSupply(requestId, respond, serializedOutput: Bytes<5>, mintNonce)`.
#[derive(Clone, Debug)]
pub struct RefundSupplyScenario {
    pub s: StartSupplyScenario,
    pub settle: Settle,
    pub serialized_output: [u8; 5],
}

impl RefundSupplyScenario {
    pub fn new() -> RefundSupplyScenario {
        RefundSupplyScenario {
            s: StartSupplyScenario::new(),
            settle: Settle::new(),
            serialized_output: v::MPC_FAILURE_OUTPUT,
        }
    }

    pub fn env(&self) -> &Env {
        &self.s.env
    }

    pub fn output_limbs(&self) -> Vec<Fr> {
        vec![failure_output_limb(&self.serialized_output)]
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let mut inputs = self.settle.head_inputs(self.env(), &self.s.request_id(), &self.output_limbs());
        inputs.extend(self.settle.nonce_slots());
        inputs
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        self.settle.witnesses_with_own_pk(&self.s.sk)
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let env = self.env();
        let rid = self.s.request_id();
        let mut o = env.read_initialised();
        o.extend(env.read_mpc_key());
        o.extend(ops::member(SUPPLY_SETTLE_VIEWS, &rid, self.settle.pending));
        o.extend(ops::lookup(SUPPLY_SETTLE_VIEWS, &rid, self.s.view_av()));
        o.extend(ops::remove(SUPPLY_EVENT_MAP, &rid));
        o.extend(ops::remove(SUPPLY_SETTLE_VIEWS, &rid));
        o.extend(env.read_b20(STATA_UNDERLYING, &env.stata_underlying));
        o.extend(env.mint_to_key_ops(&env.stata_underlying, self.s.amount_u64(), &self.settle.mint_nonce, &self.settle.own_pk));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0x4e50_0517u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.env().pre_state();
        let rid = self.s.request_id();
        pre.supply_event_map = vec![(rid, self.s.req().av(self.env()))];
        if self.settle.pending {
            pre.supply_settle_views = vec![(rid, self.s.view_av())];
        }
        pre
    }
}

// ==== redeem (Aave, via the stataUSDC wrapper) =============================================

/// `startRedeem(evmNonce, keyVersion, shares, coin)`.
#[derive(Clone, Debug)]
pub struct StartRedeemScenario {
    pub env: Env,
    pub sk: [u8; 32],
    pub evm_nonce: u64,
    pub key_version: u8,
    pub shares: u128,
    pub coin_nonce: [u8; 32],
    pub coin_color: Option<[u8; 32]>,
    pub coin_value: Option<u128>,
    pub request_exists: bool,
    pub cc_rand: Fr,
}

impl StartRedeemScenario {
    pub fn new() -> StartRedeemScenario {
        StartRedeemScenario {
            env: Env::new(),
            sk: tagged32(b"redeemer", 0x25),
            evm_nonce: 19,
            key_version: 1,
            shares: 240_000,
            coin_nonce: tagged32(b"redeem-coin-nonce", 0x48),
            coin_color: None,
            coin_value: None,
            request_exists: false,
            cc_rand: Fr::from(0x4ed_0517u64),
        }
    }

    pub fn shares_u64(&self) -> u64 {
        unbounded_to_u64(self.shares)
    }

    /// The vault token's colour for the wrapper.
    pub fn vault_color(&self) -> [u8; 32] {
        vault_color(&self.env.stata_token, &self.env.self_addr)
    }

    pub fn coin_color(&self) -> [u8; 32] {
        self.coin_color.unwrap_or_else(|| self.vault_color())
    }

    pub fn coin_value(&self) -> u128 {
        self.coin_value.unwrap_or(self.shares)
    }

    pub fn req(&self) -> Req {
        Req {
            key_version: self.key_version,
            path: pad32(v::VAULT_PATH),
            tx: Tx::fixed(
                self.evm_nonce,
                v::LENDING_GAS,
                self.env.stata_token,
                v::REDEEM_SELECTOR,
                vec![
                    abi_num_word(self.shares),
                    abi_addr_word(&self.env.vault_evm),
                    abi_addr_word(&self.env.vault_evm),
                ],
            ),
            out_schema: v::REDEEM_OUTPUT_SCHEMA,
            respond_schema: v::REDEEM_RESPOND_SCHEMA,
        }
    }

    pub fn request_id(&self) -> [u8; 32] {
        self.req().request_id(&self.env)
    }

    pub fn refund_commitment(&self) -> [u8; 32] {
        refund_commitment(&self.sk, &self.request_id())
    }

    /// The `RedeemSettleView` the request pins.
    pub fn view_av(&self) -> AlignedValue {
        let (c_hi, c_lo) = b32_slots(&self.refund_commitment());
        aligned(&[32, 8], &[c_hi, c_lo, Fr::from(self.shares_u64())])
    }

    pub fn coin_inputs(&self) -> Vec<Fr> {
        let (n_hi, n_lo) = b32_slots(&self.coin_nonce);
        let (c_hi, c_lo) = b32_slots(&self.coin_color());
        vec![n_hi, n_lo, c_hi, c_lo, u128_limb(self.coin_value())]
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let mut inputs = vec![
            Fr::from(self.evm_nonce),
            Fr::from(u64::from(self.key_version)),
            u128_limb(self.shares),
        ];
        inputs.extend(self.coin_inputs());
        inputs
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        let (sk_hi, sk_lo) = b32_slots(&self.sk);
        let mut w = vec![sk_hi, sk_lo];
        w.extend(self.env.call_witnesses(self.cc_rand));
        w
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let mut o = self.env.read_initialised();
        o.extend(self.env.read_b20(STATA_TOKEN, &self.env.stata_token));
        o.extend(self.env.kernel_self());
        // redeem(shares, vault, vault): the cell is read once per word.
        o.extend(self.env.read_b20(VAULT_EVM_ADDRESS, &self.env.vault_evm));
        o.extend(self.env.read_b20(VAULT_EVM_ADDRESS, &self.env.vault_evm));
        o.extend(self.env.read_chain_id());
        o.extend(self.env.read_b20(STATA_TOKEN, &self.env.stata_token));
        o.extend(self.env.assemble_request_reads());
        o.extend(request_tail(
            &self.env,
            REDEEM_EVENT_MAP,
            &self.req(),
            self.request_exists,
            Some(self.env.burn_ops(&self.coin_nonce, &self.coin_color(), self.coin_value())),
            Some((REDEEM_SETTLE_VIEWS, self.view_av())),
            self.cc_rand,
        ));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0x4ede_0517u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.env.pre_state();
        if self.request_exists {
            pre.redeem_event_map = vec![(self.request_id(), self.req().av(&self.env))];
        }
        pre
    }
}

/// `completeRedeem(requestId, respond, serializedOutput: Bytes<8>,
/// mintNonce)`.
#[derive(Clone, Debug)]
pub struct CompleteRedeemScenario {
    pub s: StartRedeemScenario,
    pub settle: Settle,
    /// The attested assets the wrapper paid out.
    pub assets: u64,
}

impl CompleteRedeemScenario {
    pub fn new() -> CompleteRedeemScenario {
        CompleteRedeemScenario {
            s: StartRedeemScenario::new(),
            settle: Settle::new(),
            assets: 241_500,
        }
    }

    pub fn env(&self) -> &Env {
        &self.s.env
    }

    pub fn output_limbs(&self) -> Vec<Fr> {
        vec![Fr::from(self.assets)]
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let mut inputs = self.settle.head_inputs(self.env(), &self.s.request_id(), &self.output_limbs());
        inputs.extend(self.settle.nonce_slots());
        inputs
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        self.settle.witnesses_with_own_pk(&self.s.sk)
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let env = self.env();
        let rid = self.s.request_id();
        let mut o = env.read_initialised();
        o.extend(env.read_mpc_key());
        o.extend(ops::member(REDEEM_EVENT_MAP, &rid, self.settle.pending));
        o.extend(ops::remove(REDEEM_EVENT_MAP, &rid));
        o.extend(ops::lookup(REDEEM_SETTLE_VIEWS, &rid, self.s.view_av()));
        o.extend(ops::remove(REDEEM_SETTLE_VIEWS, &rid));
        o.extend(env.read_b20(STATA_UNDERLYING, &env.stata_underlying));
        o.extend(env.mint_to_key_ops(&env.stata_underlying, self.assets, &self.settle.mint_nonce, &self.settle.own_pk));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0xc4ed_0517u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.env().pre_state();
        let rid = self.s.request_id();
        if self.settle.pending {
            pre.redeem_event_map = vec![(rid, self.s.req().av(self.env()))];
        }
        pre.redeem_settle_views = vec![(rid, self.s.view_av())];
        pre
    }
}

/// `refundRedeem(requestId, respond, serializedOutput: Bytes<5>, mintNonce)`.
#[derive(Clone, Debug)]
pub struct RefundRedeemScenario {
    pub s: StartRedeemScenario,
    pub settle: Settle,
    pub serialized_output: [u8; 5],
}

impl RefundRedeemScenario {
    pub fn new() -> RefundRedeemScenario {
        RefundRedeemScenario {
            s: StartRedeemScenario::new(),
            settle: Settle::new(),
            serialized_output: v::MPC_FAILURE_OUTPUT,
        }
    }

    pub fn env(&self) -> &Env {
        &self.s.env
    }

    pub fn output_limbs(&self) -> Vec<Fr> {
        vec![failure_output_limb(&self.serialized_output)]
    }

    pub fn inputs(&self) -> Vec<Fr> {
        let mut inputs = self.settle.head_inputs(self.env(), &self.s.request_id(), &self.output_limbs());
        inputs.extend(self.settle.nonce_slots());
        inputs
    }

    pub fn witnesses(&self) -> Vec<Fr> {
        self.settle.witnesses_with_own_pk(&self.s.sk)
    }

    pub fn ops(&self) -> Vec<VmOp> {
        let env = self.env();
        let rid = self.s.request_id();
        let mut o = env.read_initialised();
        o.extend(env.read_mpc_key());
        o.extend(ops::member(REDEEM_SETTLE_VIEWS, &rid, self.settle.pending));
        o.extend(ops::lookup(REDEEM_SETTLE_VIEWS, &rid, self.s.view_av()));
        o.extend(ops::remove(REDEEM_EVENT_MAP, &rid));
        o.extend(ops::remove(REDEEM_SETTLE_VIEWS, &rid));
        o.extend(env.read_b20(STATA_TOKEN, &env.stata_token));
        o.extend(env.mint_to_key_ops(&env.stata_token, self.s.shares_u64(), &self.settle.mint_nonce, &self.settle.own_pk));
        o
    }

    pub fn preimage(&self) -> ProofPreimage {
        preimage_of(self.inputs(), self.witnesses(), &self.ops(), Fr::from(0x4e4ed_0517u64))
    }

    pub fn pre_state(&self) -> PreState {
        let mut pre = self.env().pre_state();
        let rid = self.s.request_id();
        pre.redeem_event_map = vec![(rid, self.s.req().av(self.env()))];
        if self.settle.pending {
            pre.redeem_settle_views = vec![(rid, self.s.view_av())];
        }
        pre
    }
}
