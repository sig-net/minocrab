//! ZKIR v3-only stdlib: the `zkir-v3-library.compact` ports.
//!
//! Built against the typed v3 frontend (`minocrab::v3`). Lowering follows
//! compactc exactly (notes/builtin-lowering.org §13, verified against the
//! library's compiled output): Compact-level `Bytes<32>` values live as
//! `[hi, lo]` native slot pairs ([`B32`]); typed `Bytes<32>` values appear
//! only at instruction boundaries; byte surgery is div_mod / reconstitute
//! chains over the low limb.

use minocrab::v3::{
    Bytes32T, Circuit3, FieldT, IrTy, Secp256k1PointT, Secp256k1ScalarT, Wire3,
};
use minocrab::{Alignment, AlignmentAtom, AlignmentSegment, Fr, Meet, Private, Public, Visibility};

/// Visibility usable by v3 stdlib gadgets (closed under [`Meet`], reachable
/// from [`Public`]) — the v3 twin of [`crate::bundle::Vis`].
pub trait Vis3: Visibility + Meet<Self, Out = Self> + Sized + Copy {
    fn from_public<T: IrTy>(w: Wire3<T, Public>) -> Wire3<T, Self>;
}

impl Vis3 for Public {
    fn from_public<T: IrTy>(w: Wire3<T, Public>) -> Wire3<T, Public> {
        w
    }
}

impl Vis3 for Private {
    fn from_public<T: IrTy>(w: Wire3<T, Public>) -> Wire3<T, Private> {
        w.private()
    }
}

/// A Compact-level `Bytes<32>`: the `[hi, lo]` native slot pair (hi = byte
/// 31, lo = bytes 0..30 little-endian).
#[derive(Clone, Copy)]
pub struct B32<V: Vis3> {
    pub hi: Wire3<FieldT, V>,
    pub lo: Wire3<FieldT, V>,
}

impl B32<Public> {
    /// `pad(32, s)` as a constant pair: the string's bytes occupy bytes
    /// 0.., the rest is zero (the stdlib pad builtin's layout, confirmed
    /// against compactc's inline literals, e.g. test-caller-contract
    /// initialise's `"signet-caller:deployer:"`).
    pub fn pad(c: &mut Circuit3, s: &str) -> B32<Public> {
        assert!(s.len() <= 32, "pad(32, ..) literal longer than 32 bytes");
        let mut bytes = [0u8; 32];
        bytes[..s.len()].copy_from_slice(s.as_bytes());
        B32 {
            hi: c.constant(Fr::from(u64::from(bytes[31]))),
            lo: c.constant(Fr::from_le_bytes(&bytes[..31]).expect("31 bytes fit")),
        }
    }
}

impl<V: Vis3> B32<V> {
    /// `bit ? a : b`, limbwise.
    pub fn cond_select(
        c: &mut Circuit3,
        bit: Wire3<FieldT, V>,
        a: &B32<V>,
        b: &B32<V>,
    ) -> B32<V> {
        B32 {
            hi: c.cond_select(bit, a.hi, b.hi),
            lo: c.cond_select(bit, a.lo, b.lo),
        }
    }
}

impl<V: Vis3> B32<V> {
    /// Constrain a `Bytes<32>` entering the circuit (8/248 bits).
    pub fn constrain_input(self, c: &mut Circuit3) {
        c.assert_bits(self.hi, 8);
        c.assert_bits(self.lo, 248);
    }

    /// To the typed `Bytes<32>` value (instruction-boundary form).
    pub fn to_typed(self, c: &mut Circuit3) -> Wire3<Bytes32T, V> {
        c.bytes32_from_low_high(self.lo, self.hi)
    }

    /// From the typed `Bytes<32>` value.
    pub fn from_typed(c: &mut Circuit3, typed: Wire3<Bytes32T, V>) -> Self {
        let (lo, hi) = c.bytes32_into_low_high(typed);
        B32 { hi, lo }
    }
}

/// Explode a limb into `nbytes` byte wires, least-significant first: a
/// chain of `div_mod_power_of_two(_, 8)` where each remainder is a byte and
/// the final quotient is the last byte (compactc's `bytes->vector` shape).
fn explode_limb<V: Vis3>(
    c: &mut Circuit3,
    limb: Wire3<FieldT, V>,
    nbytes: usize,
) -> Vec<Wire3<FieldT, V>> {
    let mut bytes = Vec::with_capacity(nbytes);
    let mut acc = limb;
    for _ in 0..nbytes - 1 {
        let (quotient, byte) = c.div_mod_power_of_two(acc, 8);
        bytes.push(byte);
        acc = quotient;
    }
    bytes.push(acc);
    bytes
}

/// Rebuild a limb from byte wires (least-significant first): a right-fold
/// of `reconstitute_field(rest, byte, 8)` (compactc's `vector->bytes`).
fn rebuild_limb<V: Vis3>(c: &mut Circuit3, bytes: &[Wire3<FieldT, V>]) -> Wire3<FieldT, V> {
    let mut acc = *bytes.last().expect("at least one byte");
    for &byte in bytes[..bytes.len() - 1].iter().rev() {
        acc = c.reconstitute_field(acc, byte, 8);
    }
    acc
}

/// `Bytes<32> as Vector<32, Uint<8>>`: bytes 0..30 from the low limb, byte
/// 31 is the high limb directly.
pub fn b32_to_bytes<V: Vis3>(c: &mut Circuit3, b: &B32<V>) -> Vec<Wire3<FieldT, V>> {
    let mut bytes = explode_limb(c, b.lo, 31);
    bytes.push(b.hi);
    bytes
}

/// `Vector<32, Uint<8>> as Bytes<32>` (`v[0]` least significant).
pub fn bytes_to_b32<V: Vis3>(c: &mut Circuit3, bytes: &[Wire3<FieldT, V>]) -> B32<V> {
    assert_eq!(bytes.len(), 32);
    B32 {
        lo: rebuild_limb(c, &bytes[..31]),
        hi: bytes[31],
    }
}

/// `struct Secp256k1EcdsaSignature { r: Secp256k1Scalar, s: Secp256k1Scalar }`
#[derive(Clone, Copy)]
pub struct Secp256k1EcdsaSignature<V: Vis3> {
    pub r: Wire3<Secp256k1ScalarT, V>,
    pub s: Wire3<Secp256k1ScalarT, V>,
}

/// `circuit hashToSecp256k1Scalar(digest: Bytes<32>): Secp256k1Scalar` —
/// the digest is a big-endian integer (RFC 6979), so reverse the bytes and
/// reduce mod the scalar-field order.
pub fn hash_to_secp256k1_scalar<V: Vis3>(
    c: &mut Circuit3,
    digest: &B32<V>,
) -> Wire3<Secp256k1ScalarT, V> {
    let le_bytes = b32_to_bytes(c, digest);
    let be_bytes: Vec<_> = le_bytes.into_iter().rev().collect();
    let reversed = bytes_to_b32(c, &be_bytes);
    let typed = reversed.to_typed(c);
    c.from_bytes32(typed)
}

/// `circuit secp256k1EcdsaVerify(msgHash, sig, pk): Boolean`
///
/// Standard ECDSA: `w = s⁻¹`, `u1 = z·w`, `u2 = r·w`,
/// `P = u1·G + u2·pk`, valid iff `P.x == r` as 32-byte big-endian
/// integers. Accepts both low-s and high-s signatures (as the library
/// does); `msgHash` is taken as given and must be bound to the real
/// message by the caller.
pub fn secp256k1_ecdsa_verify<V: Vis3>(
    c: &mut Circuit3,
    msg_hash: &B32<V>,
    sig: &Secp256k1EcdsaSignature<V>,
    pk: Wire3<Secp256k1PointT, V>,
) -> Wire3<FieldT, V> {
    let z = hash_to_secp256k1_scalar(c, msg_hash);
    let w = c.inv(sig.s);
    let u1 = c.mul(z, w);
    let u2 = c.mul(sig.r, w);
    let g_u1 = c.ec_mul_generator(u1);
    let pk_u2 = c.ec_mul(pk, u2);
    let point = c.add(g_u1, pk_u2);

    // (secp256k1PointX(point) as Bytes<32>) as Secp256k1Scalar == r —
    // compactc emits the into/from round-trip as-is.
    let (x, _y) = c.into_coordinates(point);
    let x_bytes = c.into_bytes32(x);
    let x_pair = B32::from_typed(c, x_bytes);
    let x_typed = x_pair.to_typed(c);
    let x_scalar: Wire3<Secp256k1ScalarT, V> = c.from_bytes32(x_typed);
    c.test_eq(x_scalar, sig.r)
}

/// A secp256k1 base-field element as 32 big-endian byte wires
/// (`secp256k1BaseBigEndian`: canonical LE bytes, reversed).
fn base_big_endian<V: Vis3>(
    c: &mut Circuit3,
    base: Wire3<minocrab::v3::Secp256k1BaseT, V>,
) -> Vec<Wire3<FieldT, V>> {
    let typed = c.into_bytes32(base);
    let pair = B32::from_typed(c, typed);
    let le = b32_to_bytes(c, &pair);
    le.into_iter().rev().collect()
}

/// `circuit secp256k1EthereumAddress(pk): Bytes<20>` — keccak256 of the
/// point's big-endian coordinates, bytes 12..31. `Bytes<20>` is a single
/// native slot. The point at infinity is rejected
/// (`pk != default<Secp256k1Point>`).
pub fn secp256k1_ethereum_address<V: Vis3>(
    c: &mut Circuit3,
    pk: Wire3<Secp256k1PointT, V>,
) -> Wire3<FieldT, V> {
    // default<Secp256k1Point> = generator · 0, built as compactc does
    // (into_bytes32(0) → from_bytes32 scalar → ec_mul_generator).
    let zero = c.constant(0u64);
    let zero_bytes = c.into_bytes32(zero);
    let zero_scalar: Wire3<Secp256k1ScalarT, Public> = c.from_bytes32(zero_bytes);
    let identity = c.ec_mul_generator(zero_scalar);
    let is_identity = c.test_eq(pk, V::from_public(identity));
    let not_identity = c.not(is_identity);
    c.assert(not_identity);

    // keccak256 over the 64 big-endian coordinate bytes (alignment =
    // 64 × bytes 1, per the verified library dump).
    let (x, y) = c.into_coordinates(pk);
    let mut bytes = base_big_endian(c, x);
    bytes.extend(base_big_endian(c, y));
    let alignment = minocrab::Alignment(
        (0..64)
            .map(|_| AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 1 }))
            .collect(),
    );
    let erased: Vec<_> = bytes.iter().map(|w| w.erase()).collect();
    let hash = c.keccak256(alignment, &erased);

    // slice<20>(hash, 12): bytes 12..31 of the digest, rebuilt as the
    // single Bytes<20> limb.
    let pair = B32::from_typed(c, hash);
    let hash_bytes = b32_to_bytes(c, &pair);
    rebuild_limb(c, &hash_bytes[12..32])
}

// --- coins (the zswap stdlib circuits, v3) -----------------------------------

/// `circuit ownPublicKey(): ZswapCoinPublicKey` — witness-backed: the
/// local secret key never enters the circuit, the runtime supplies the
/// derived key as a witness, input-constrained like any `Bytes<32>`
/// (confirmed against the mint-tokens corpus artifact).
pub fn own_public_key(c: &mut Circuit3) -> B32<Private> {
    let pk = B32 {
        hi: c.witness::<FieldT>(),
        lo: c.witness::<FieldT>(),
    };
    pk.constrain_input(c);
    pk
}

/// A `bytes<n>` (n ≤ 31) literal as a single constant limb.
fn short_literal<V: Vis3>(c: &mut Circuit3, bytes: &[u8]) -> Wire3<FieldT, V> {
    assert!(bytes.len() <= 31);
    V::from_public(c.constant(Fr::from_le_bytes(bytes).expect("≤31 bytes fit")))
}

fn b32_atom() -> AlignmentSegment {
    AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 })
}

/// `circuit tokenType(domain_sep: Bytes<32>, contract: ContractAddress):
/// Bytes<32>` — `persistentHash([pad(32, "midnight:derive_token"),
/// domain_sep, contract])` (input order confirmed against the mint-tokens
/// corpus artifact).
pub fn token_type<V: Vis3>(
    c: &mut Circuit3,
    domain_sep: &B32<V>,
    contract: &B32<V>,
) -> B32<V> {
    let prefix = B32::pad(c, "midnight:derive_token");
    let (p_hi, p_lo) = (V::from_public(prefix.hi), V::from_public(prefix.lo));
    let alignment = Alignment(vec![b32_atom(), b32_atom(), b32_atom()]);
    let digest = c.persistent_hash(
        alignment,
        &[
            p_hi.erase(),
            p_lo.erase(),
            domain_sep.hi.erase(),
            domain_sep.lo.erase(),
            contract.hi.erase(),
            contract.lo.erase(),
        ],
    );
    B32::from_typed(c, digest)
}

/// `struct ShieldedCoinInfo { nonce: Bytes<32>, color: Bytes<32>,
/// value: Uint<128> }`.
#[derive(Clone, Copy)]
pub struct ShieldedCoinInfo3<V: Vis3> {
    pub nonce: B32<V>,
    pub color: B32<V>,
    pub value: Wire3<FieldT, V>,
}

/// `Either<ZswapCoinPublicKey, ContractAddress>` — a coin recipient. Both
/// arms are `Bytes<32>` on the wire; `is_left` = 1 selects the public key.
#[derive(Clone, Copy)]
pub struct CoinRecipient<V: Vis3> {
    pub is_left: Wire3<FieldT, V>,
    pub left: B32<V>,
    pub right: B32<V>,
}

/// `circuit coinCommitment(coin, recipient): Bytes<32>` —
/// `persistentHash` over the coin preimage `["midnight:zswap-cc[v1]"
/// (Bytes<21>), nonce, color, value (Uint<128>), is_left (Boolean),
/// recipient bytes]`, mirroring the v2 port (`crate::coin`) and the
/// mint-tokens corpus artifact.
pub fn coin_commitment<V: Vis3>(
    c: &mut Circuit3,
    coin: &ShieldedCoinInfo3<V>,
    recipient: &CoinRecipient<V>,
) -> B32<V> {
    let prefix = short_literal::<V>(c, b"midnight:zswap-cc[v1]");
    let data = B32::cond_select(c, recipient.is_left, &recipient.left, &recipient.right);
    let alignment = Alignment(vec![
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 21 }),
        b32_atom(),
        b32_atom(),
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 16 }),
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 1 }),
        b32_atom(),
    ]);
    let digest = c.persistent_hash(
        alignment,
        &[
            prefix.erase(),
            coin.nonce.hi.erase(),
            coin.nonce.lo.erase(),
            coin.color.hi.erase(),
            coin.color.lo.erase(),
            coin.value.erase(),
            recipient.is_left.erase(),
            data.hi.erase(),
            data.lo.erase(),
        ],
    );
    B32::from_typed(c, digest)
}
