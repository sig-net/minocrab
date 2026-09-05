//! Off-circuit primitives of the erc20-vault reference model: the FAB
//! encodings, hash constructions and signature helpers that reproduce, in
//! ordinary Rust, exactly what the circuits compute in-circuit.
//!
//! ONE concretization since M28: every vault commitment is Poseidon —
//! `upgradeFromTransient(transientHash(…))` — as the deployed contract's
//! source has it (`userCommitment`, `refundCommitment`,
//! `vaultTokenDomainSeparator`, `calculateRequestId`,
//! `calculateSignetAttestationDigest`). The retired forks' alternative
//! constructions are history (notes/vault-refresh.org §0). What stays
//! protocol-pinned and SHA-256 is the ledger's own: `tokenType`, the coin
//! commitment and nullifier.

use midnight_base_crypto::fab::{
    Alignment, AlignmentAtom, AlignmentSegment, AlignedValue, Value, ValueAtom,
};
use midnight_base_crypto::repr::BinaryHashRepr;
use midnight_curves::k256;
use midnight_onchain_state::state::StateValue;
use midnight_onchain_vm::ops::Op;
use midnight_onchain_vm::result_mode::ResultModeVerify;
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_transient_crypto::fab::{AlignmentExt, ValueReprAlignedValue};
use midnight_transient_crypto::hash::transient_hash;
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
use minocrab_zkir::v3::{IrSource, IrType, IrValue};
use sha2::{Digest, Sha256};

pub type VmOp = Op<ResultModeVerify, InMemoryDB>;

pub fn corpus_zkir_named(name: &str) -> IrSource {
    let path = format!(
        "{}/../../corpus/zkir/signet-midnight-examples/examples/erc20-vault/contract/src/erc20-vault/zkir/{name}.zkir",
        env!("CARGO_MANIFEST_DIR")
    );
    minocrab_zkir::v3::read_zkir(&path).expect("corpus golden parses")
}

pub fn atom(n: u32) -> AlignmentSegment {
    AlignmentSegment::Atom(AlignmentAtom::Bytes { length: n })
}

pub fn bytesn_value(n: u32, bytes: &[u8]) -> AlignedValue {
    AlignedValue::new(
        Value(vec![ValueAtom(bytes.to_vec()).normalize()]),
        Alignment(vec![atom(n)]),
    )
    .unwrap()
}

/// A multi-atom value from its limbs and atom widths.
pub fn aligned(widths: &[u32], limbs: &[Fr]) -> AlignedValue {
    Alignment(widths.iter().map(|&w| atom(w)).collect())
        .parse_field_repr(limbs)
        .expect("limbs match the alignment")
}

pub fn cell(av: AlignedValue) -> StateValue {
    StateValue::Cell(Sp::new(av))
}

/// [hi, lo] Fr slot pair of a Bytes<32>.
pub fn b32_slots(bytes: &[u8; 32]) -> (Fr, Fr) {
    (
        Fr::from(u64::from(bytes[31])),
        Fr::from_le_bytes(&bytes[..31]).unwrap(),
    )
}

/// A `Bytes<20>` as its single limb.
pub fn b20(bytes: &[u8; 20]) -> Fr {
    Fr::from_le_bytes(bytes).unwrap()
}

/// A `Uint<128>` as its single limb.
pub fn u128_limb(v: u128) -> Fr {
    Fr::from_le_bytes(&v.to_le_bytes()).unwrap()
}

/// `upgradeFromTransient(transientHash(limbs))` — Poseidon over the limbs,
/// then the field element's 31 low bytes as a `Bytes<32>` whose byte 31 is
/// zero (`[hi: 0, lo: f mod 2^248]` in slot terms).
pub fn transient_upgrade(limbs: &[Fr]) -> [u8; 32] {
    let f = transient_hash(limbs);
    let mut le = f.as_le_bytes();
    le.resize(32, 0);
    let mut out = [0u8; 32];
    out[..31].copy_from_slice(&le[..31]);
    out
}

/// `userCommitment(sk)` — the MPC's key-derivation PATH of a deposit.
pub fn user_commitment(sk: &[u8; 32]) -> [u8; 32] {
    let (p_hi, p_lo) = b32_slots(&pad32(erc20_vault::USER_PAD));
    let (sk_hi, sk_lo) = b32_slots(sk);
    transient_upgrade(&[p_hi, p_lo, sk_hi, sk_lo])
}

/// `refundCommitment(sk, requestId)`.
pub fn refund_commitment(sk: &[u8; 32], request_id: &[u8; 32]) -> [u8; 32] {
    let (p_hi, p_lo) = b32_slots(&pad32(erc20_vault::REFUND_PAD));
    let (sk_hi, sk_lo) = b32_slots(sk);
    let (r_hi, r_lo) = b32_slots(request_id);
    transient_upgrade(&[p_hi, p_lo, sk_hi, sk_lo, r_hi, r_lo])
}

/// `vaultTokenDomainSeparator(erc20)` — the address `as Field as
/// Bytes<32>` is `[hi: 0, lo: addr]`.
pub fn vault_domain_sep(erc20: &[u8; 20]) -> [u8; 32] {
    let (p_hi, p_lo) = b32_slots(&pad32(erc20_vault::TOKEN_PAD));
    transient_upgrade(&[p_hi, p_lo, Fr::from(0u64), b20(erc20)])
}

/// `tokenType(vaultTokenDomainSeparator(erc20), self)` — PINNED: the
/// ledger derives the colour (coin-structure/src/contract.rs:58-68).
pub fn vault_color(erc20: &[u8; 20], self_addr: &[u8; 32]) -> [u8; 32] {
    let (d_hi, d_lo) = b32_slots(&vault_domain_sep(erc20));
    let (t_hi, t_lo) = b32_slots(&pad32("midnight:derive_token"));
    let (s_hi, s_lo) = b32_slots(self_addr);
    fab_sha256(
        vec![atom(32), atom(32), atom(32)],
        &[t_hi, t_lo, d_hi, d_lo, s_hi, s_lo],
    )
}

/// `calculateRequestId(request)` — Poseidon over the record's FAB limbs in
/// slot order (what the MPC's `compact-hashing` recomputes from the stored
/// cell), upgraded.
pub fn request_id_of(limbs: &[Fr]) -> [u8; 32] {
    transient_upgrade(limbs)
}

/// `calculateSignetAttestationDigest(requestId, serializedOutput)` —
/// Poseidon over the id's slot pair then the output's limbs, upgraded.
pub fn attestation_digest(request_id: &[u8; 32], output_limbs: &[Fr]) -> [u8; 32] {
    let (r_hi, r_lo) = b32_slots(request_id);
    let mut limbs = vec![r_hi, r_lo];
    limbs.extend_from_slice(output_limbs);
    transient_upgrade(&limbs)
}

pub fn scalar(v: u64) -> IrValue {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&v.to_le_bytes());
    from_bytes32_offcircuit(&IrType::Secp256k1Scalar, &bytes).unwrap()
}

pub fn natives(v: &IrValue) -> Vec<Fr> {
    encode_offcircuit(v)
        .into_iter()
        .map(|x| match x {
            IrValue::Native(f) => f,
            other => panic!("encode produced non-native {other:?}"),
        })
        .collect()
}

/// SHA-256 over the FAB binary of `limbs` laid out per `segments` — the
/// off-circuit persistent_hash.
pub fn fab_sha256(segments: Vec<AlignmentSegment>, limbs: &[Fr]) -> [u8; 32] {
    let value = Alignment(segments)
        .parse_field_repr(limbs)
        .expect("limbs match the alignment");
    let mut repr = Vec::new();
    ValueReprAlignedValue(value).binary_repr(&mut repr);
    Sha256::digest(&repr).into()
}

pub fn pad32(s: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..s.len()].copy_from_slice(s.as_bytes());
    bytes
}

/// Sign `digest` (big-endian integer, RFC 6979) via upstream off-circuit
/// helpers; returns (r_bytes32_le, s_bytes32_le, pk). The LE forms are the
/// circuit-input form `verifyRespondBidirectionalEvent` takes since the
/// protocol move (no in-circuit reversal).
pub fn sign(digest: &[u8; 32], d: &IrValue, k: &IrValue) -> ([u8; 32], [u8; 32], IrValue) {
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

/// `coinCommitment(coin, recipient)` off-circuit — `is_left`/`data` per
/// the CoinPreimage.
pub fn coin_commitment_of(
    nonce: &(Fr, Fr),
    color: &[u8; 32],
    value: u128,
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
            u128_limb(value),
            Fr::from(u64::from(is_left)),
            d_hi, d_lo,
        ],
    )
}

/// `coinNullifier(coin, addr)` off-circuit — the `zswap-cn` domain,
/// dataType 0.
pub fn coin_nullifier_of(nonce: &(Fr, Fr), color: &[u8; 32], value: u128, addr: &[u8; 32]) -> [u8; 32] {
    let prefix = Fr::from_le_bytes(b"midnight:zswap-cn[v1]").unwrap();
    let (c_hi, c_lo) = b32_slots(color);
    let (a_hi, a_lo) = b32_slots(addr);
    fab_sha256(
        vec![atom(21), atom(32), atom(32), atom(16), atom(1), atom(32)],
        &[
            prefix, nonce.0, nonce.1, c_hi, c_lo,
            u128_limb(value),
            Fr::from(0u64),
            a_hi, a_lo,
        ],
    )
}

/// `evolveNonce` as lowered: `transientHash([tag, nonce.lo])`, upgraded as
/// `[hi: 0, lo: mod 2^248]`.
pub fn evolved_nonce(nonce: &[u8; 32]) -> (Fr, Fr) {
    let tag = Fr::from_le_bytes(b"midnight:kernel:nonce_evolve").unwrap();
    let (_hi, lo) = b32_slots(nonce);
    b32_slots(&transient_upgrade(&[tag, lo]))
}

pub fn abi_addr_word(addr: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(addr);
    w
}

pub fn abi_num_word(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

/// A schema literal's [hi, lo] slot pair — `Bytes<n>` for 32 ≤ n ≤ 62
/// splits at byte 31: the tail (bytes 31..n) is the FIRST limb.
pub fn schema_slots(schema: &[u8]) -> (Fr, Fr) {
    (
        Fr::from_le_bytes(&schema[31..]).unwrap(),
        Fr::from_le_bytes(&schema[..31]).unwrap(),
    )
}

/// The point at infinity as a `Secp256k1Point` value — `G * 0`.
///
/// Used by the adversarial sweeps: it is a *valid* public key (for secret
/// key 0) that authenticates every signature made under that key, so any
/// place a public key is accepted without a non-identity check is a hole.
pub fn identity_point() -> IrValue {
    ec_mul_offcircuit(
        &IrValue::Secp256k1Point(k256::K256::generator()),
        &scalar(0),
    )
    .unwrap()
}
