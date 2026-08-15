//! Off-circuit primitives of the erc20-vault reference model: the FAB
//! encodings, hash constructions and signature helpers that reproduce, in
//! ordinary Rust, exactly what the circuits compute in-circuit.
//!
//! These are the CONCRETIZATION of the spec's symbolic terms
//! (`super::spec::Term`): `user_commitment` realises `Term::UserCommit`,
//! `vault_domain_sep` realises `Term::DomainSep`, and so on.
//!
//! The four DISCRETIONARY constructions — `user_commitment`,
//! `refund_commitment`, `vault_domain_sep`, `change_nonce` — take an
//! [`Art`], because they are exactly what an optimized artifact is free to
//! change (notes/vault-optimization.org §"(c) SPEC-DISCRETIONARY"). Their
//! `Art::Opt` arms ARE the deviation log, in executable form: the spec, the
//! reference model and the injectivity sweep all route through them, so a
//! deviation that is not written here fails the harness rather than
//! silently passing it. Everything else in this module is protocol-pinned
//! and must concretise identically in every artifact.
//!
//! Moved verbatim out of `erc20_vault_differential.rs` (M10 step 1) so the
//! differential suite and the property harness share one model.

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
use midnight_zkir_v3::ir_instructions::add::add_offcircuit;
use midnight_zkir_v3::ir_instructions::ec_mul::ec_mul_offcircuit;
use midnight_zkir_v3::ir_instructions::encode::encode_offcircuit;
use midnight_zkir_v3::ir_instructions::from_bytes32::from_bytes32_offcircuit;
use midnight_zkir_v3::ir_instructions::into_bytes32::into_bytes32_offcircuit;
use midnight_zkir_v3::ir_instructions::into_coordinates::into_coordinates_offcircuit;
use midnight_zkir_v3::ir_instructions::inv::inv_offcircuit;
use midnight_zkir_v3::ir_instructions::mul::mul_offcircuit;
use minocrab::Fr;
use minocrab_contracts::{erc20_vault, erc20_vault_opt};
use minocrab_zkir::v3::{IrSource, IrType, IrValue};
use sha2::{Digest, Sha256};

pub use super::artifact::Art;

pub type VmOp = Op<ResultModeVerify, InMemoryDB>;

pub fn corpus_zkir_named(name: &str) -> IrSource {
    let path = format!(
        "{}/../../corpus/zkir/signet-midnight-examples/examples/erc20-vault/contract/src/erc20-vault/zkir/{name}.zkir",
        env!("CARGO_MANIFEST_DIR")
    );
    minocrab_zkir::v3::read_zkir(&path).expect("corpus golden parses")
}

pub fn corpus_zkir() -> IrSource {
    corpus_zkir_named("initialize")
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

/// DISCRETIONARY. Off-circuit `userCommitment(sk)`.
///
/// The commitment is the MPC's key-derivation PATH, so it stays SHA-256 in
/// both artifacts (a Poseidon variant would strand funds at the old derived
/// EVM account — notes/vault-optimization.org §"Q4"). Only the PREIMAGE
/// LENGTH is discretionary:
/// - Compat: SHA-256 over `[pad(32, "vault:user:"), sk]` — 64 bytes, 2 blocks.
/// - Opt (rung 5(i-userCommit), avenue 1): SHA-256 over
///   `[Bytes<11> "vault:user:", sk]` — 43 bytes, ONE block. Same domain tag,
///   the zero padding dropped: −1,880 rows at each of initialize, deposit,
///   claim. Layout tabulated in `common::commitment_short`.
pub fn user_commitment(art: Art, sk: &[u8; 32]) -> [u8; 32] {
    match art {
        Art::Compat => {
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
        // The 11-byte tag "vault:user:" fits one field limb; the Bytes<11>
        // atom emits exactly 11 bytes, so the preimage is 11 + 32 = 43 bytes
        // = one SHA-256 block.
        Art::Opt => {
            let tag = Fr::from_le_bytes(erc20_vault::USER_PAD.as_bytes()).unwrap();
            let (sk_hi, sk_lo) = b32_slots(sk);
            fab_sha256(vec![atom(11), atom(32)], &[tag, sk_hi, sk_lo])
        }
    }
}

/// DISCRETIONARY. Off-circuit `withdrawRefundCommitment(sk, requestId)`.
///
/// - Compat: SHA-256 (`persistentHash`) over `[pad(32, REFUND_PAD), sk,
///   requestId]` — 96 bytes, 2 blocks.
/// - Opt (rung 5(v), avenue 3): POSEIDON (`transientHash`) over the same six
///   field limbs. The digest is a `Field`; its canonical little-endian
///   bytes are the stored `Bytes<32>` value, and `b32_slots` splits it into
///   the `[hi, lo]` slot pair the circuit's `div_mod(f, 248)` produces.
///   Poseidon is safe here because the commitment is internal and
///   short-lived — see `erc20_vault_opt::withdraw_refund_commitment` for the
///   durability argument. The `Map<_, Field>` value-typing of §"Q5" is
///   deferred, so the value stays `Bytes<32>`.
pub fn refund_commitment(art: Art, sk: &[u8; 32], request_id: &[u8; 32]) -> [u8; 32] {
    let (p_hi, p_lo) = b32_slots(&pad32(erc20_vault::REFUND_PAD));
    let (sk_hi, sk_lo) = b32_slots(sk);
    let (r_hi, r_lo) = b32_slots(request_id);
    match art {
        Art::Compat => fab_sha256(
            vec![atom(32), atom(32), atom(32)],
            &[p_hi, p_lo, sk_hi, sk_lo, r_hi, r_lo],
        ),
        Art::Opt => {
            use midnight_transient_crypto::hash::transient_hash;
            let f = transient_hash(&[p_hi, p_lo, sk_hi, sk_lo, r_hi, r_lo]);
            let mut le = f.as_le_bytes();
            le.resize(32, 0);
            le.try_into().expect("32-byte field repr")
        }
    }
}

/// DISCRETIONARY. completeSwap's change-coin nonce.
pub fn change_nonce(art: Art, mint_nonce: &[u8; 32]) -> [u8; 32] {
    match art {
        // `persistentHash([mintNonce, pad(32, "change")])`.
        Art::Compat => {
            let (n_hi, n_lo) = b32_slots(mint_nonce);
            let (p_hi, p_lo) = b32_slots(&pad32("change"));
            fab_sha256(vec![atom(32), atom(32)], &[n_hi, n_lo, p_hi, p_lo])
        }
        // Rung (ii), avenue 5: the mint nonce with its top byte
        // complemented. Injective, fixed-point-free and total — the
        // uniqueness argument is in `erc20_vault_opt::change_nonce`.
        Art::Opt => {
            let mut out = *mint_nonce;
            out[31] = 255 - out[31];
            out
        }
    }
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
/// helpers; returns (r_bytes32_le, s_bytes32_le, pk).
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

/// DISCRETIONARY. `vaultTokenDomainSeparator(erc20)` off-circuit.
pub fn vault_domain_sep(art: Art, erc20: &[u8; 20]) -> [u8; 32] {
    match art {
        // SHA-256 over `[pad(32, "erc20:vault:"), erc20]`.
        Art::Compat => {
            let mut erc20_b32 = [0u8; 32];
            erc20_b32[..20].copy_from_slice(erc20);
            let (e_hi, e_lo) = b32_slots(&erc20_b32);
            let (p_hi, p_lo) = b32_slots(&pad32(erc20_vault::TOKEN_PAD));
            fab_sha256(vec![atom(32), atom(32)], &[p_hi, p_lo, e_hi, e_lo])
        }
        // Rung (iii), avenue 2: the injective encoding
        // `0x01 ‖ zeros ‖ erc20`, i.e. the slot pair [hi = 0x01, lo =
        // erc20]. Layout and safety argument in
        // `erc20_vault_opt::vault_token_domain_separator`.
        Art::Opt => {
            let mut out = [0u8; 32];
            out[..20].copy_from_slice(erc20);
            out[31] = erc20_vault_opt::VAULT_TOKEN_TAG;
            out
        }
    }
}

/// `tokenType(vaultTokenDomainSeparator(erc20), self)` off-circuit. The
/// `tokenType` construction itself is PINNED (the ledger derives the colour,
/// coin-structure/src/contract.rs:58-68); only its separator argument is
/// discretionary, hence the `art`.
pub fn vault_color(art: Art, erc20: &[u8; 20], self_addr: &[u8; 32]) -> [u8; 32] {
    let domain_sep = vault_domain_sep(art, erc20);
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
pub fn coin_commitment_of(
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

/// `coinNullifier(coin, addr)` off-circuit — the `zswap-cn` domain,
/// dataType 0.
pub fn coin_nullifier_of(nonce: &(Fr, Fr), color: &[u8; 32], value: u64, addr: &[u8; 32]) -> [u8; 32] {
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
pub fn evolved_nonce(nonce: &[u8; 32]) -> (Fr, Fr) {
    use midnight_transient_crypto::hash::transient_hash;
    let tag = Fr::from_le_bytes(b"midnight:kernel:nonce_evolve").unwrap();
    let (_hi, lo) = b32_slots(nonce);
    let h = transient_hash(&[tag, lo]);
    let mut le = h.as_le_bytes();
    le.resize(32, 0);
    (Fr::from(0u64), Fr::from_le_bytes(&le[..31]).unwrap())
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
