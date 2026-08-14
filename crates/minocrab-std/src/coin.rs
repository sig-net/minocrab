//! Midnight kernel types and the kernel-independent coin circuits.
//!
//! Ports of the "Midnight kernel types" / "helper circuits" sections of
//! `standard-library.compact`. Only the pure parts live here: circuits that
//! call `kernel.*` (mint/send/receive/claim) additionally need the ledger
//! ABI (notes/ledger-abi.org) and land with the eDSL's ledger-op support.

use minocrab::{AlignmentAtom, Circuit, Wire};

use crate::bundle::{cond_select, Bundle, Vis};
use crate::data::Either;
use crate::hash::{persistent_commit, persistent_hash, upgrade_from_transient};
use crate::types::{str_as_field, Bool, Bytes32, BytesN, U128, U64};

/// `struct ContractAddress { bytes: Bytes<32>; }`
#[derive(Clone)]
pub struct ContractAddress<V: Vis> {
    pub bytes: Bytes32<V>,
}

/// `struct ZswapCoinPublicKey { bytes: Bytes<32>; }`
#[derive(Clone)]
pub struct ZswapCoinPublicKey<V: Vis> {
    pub bytes: Bytes32<V>,
}

/// `struct UserAddress { bytes: Bytes<32>; }`
#[derive(Clone)]
pub struct UserAddress<V: Vis> {
    pub bytes: Bytes32<V>,
}

macro_rules! bytes32_newtype_bundle {
    ($ty:ident) => {
        impl<V: Vis> Bundle<V> for $ty<V> {
            const WIDTH: usize = Bytes32::<V>::WIDTH;

            fn push_wires(&self, out: &mut Vec<Wire<V>>) {
                self.bytes.push_wires(out);
            }

            fn from_wires(wires: &mut dyn Iterator<Item = Wire<V>>) -> Self {
                $ty {
                    bytes: Bytes32::from_wires(wires),
                }
            }

            fn push_atoms(out: &mut Vec<AlignmentAtom>) {
                Bytes32::<V>::push_atoms(out);
            }
        }
    };
}

bytes32_newtype_bundle!(ContractAddress);
bytes32_newtype_bundle!(ZswapCoinPublicKey);
bytes32_newtype_bundle!(UserAddress);

/// `struct ShieldedCoinInfo { nonce: Bytes<32>; color: Bytes<32>; value: Uint<128>; }`
#[derive(Clone)]
pub struct ShieldedCoinInfo<V: Vis> {
    pub nonce: Bytes32<V>,
    pub color: Bytes32<V>,
    pub value: U128<V>,
}

impl<V: Vis> Bundle<V> for ShieldedCoinInfo<V> {
    const WIDTH: usize = Bytes32::<V>::WIDTH * 2 + U128::<V>::WIDTH;

    fn push_wires(&self, out: &mut Vec<Wire<V>>) {
        self.nonce.push_wires(out);
        self.color.push_wires(out);
        self.value.push_wires(out);
    }

    fn from_wires(wires: &mut dyn Iterator<Item = Wire<V>>) -> Self {
        ShieldedCoinInfo {
            nonce: Bytes32::from_wires(wires),
            color: Bytes32::from_wires(wires),
            value: U128::from_wires(wires),
        }
    }

    fn push_atoms(out: &mut Vec<AlignmentAtom>) {
        Bytes32::<V>::push_atoms(out);
        Bytes32::<V>::push_atoms(out);
        U128::<V>::push_atoms(out);
    }
}

/// `struct QualifiedShieldedCoinInfo { …; mt_index: Uint<64>; }`
#[derive(Clone)]
pub struct QualifiedShieldedCoinInfo<V: Vis> {
    pub nonce: Bytes32<V>,
    pub color: Bytes32<V>,
    pub value: U128<V>,
    pub mt_index: U64<V>,
}

impl<V: Vis> Bundle<V> for QualifiedShieldedCoinInfo<V> {
    const WIDTH: usize = ShieldedCoinInfo::<V>::WIDTH + U64::<V>::WIDTH;

    fn push_wires(&self, out: &mut Vec<Wire<V>>) {
        self.nonce.push_wires(out);
        self.color.push_wires(out);
        self.value.push_wires(out);
        self.mt_index.push_wires(out);
    }

    fn from_wires(wires: &mut dyn Iterator<Item = Wire<V>>) -> Self {
        QualifiedShieldedCoinInfo {
            nonce: Bytes32::from_wires(wires),
            color: Bytes32::from_wires(wires),
            value: U128::from_wires(wires),
            mt_index: U64::from_wires(wires),
        }
    }

    fn push_atoms(out: &mut Vec<AlignmentAtom>) {
        Bytes32::<V>::push_atoms(out);
        Bytes32::<V>::push_atoms(out);
        U128::<V>::push_atoms(out);
        U64::<V>::push_atoms(out);
    }
}

impl<V: Vis> QualifiedShieldedCoinInfo<V> {
    /// `downcastQualifiedCoin`: drop the Merkle-tree index (zero cost).
    pub fn downcast(&self) -> ShieldedCoinInfo<V> {
        ShieldedCoinInfo {
            nonce: self.nonce.clone(),
            color: self.color.clone(),
            value: self.value,
        }
    }
}

impl<V: Vis> ShieldedCoinInfo<V> {
    /// `upcastQualifiedCoin`: `mt_index: 0`.
    pub fn upcast(&self, c: &mut Circuit) -> QualifiedShieldedCoinInfo<V> {
        let zero = V::from_public(c.constant(0u64));
        QualifiedShieldedCoinInfo {
            nonce: self.nonce.clone(),
            color: self.color.clone(),
            value: self.value,
            mt_index: crate::types::UintN(zero),
        }
    }
}

/// `circuit nativeToken(): Bytes<32>` — `pad(32, "")`, i.e. all zeros.
pub fn native_token<V: Vis>(c: &mut Circuit) -> Bytes32<V> {
    Bytes32::pad(c, "")
}

/// `circuit tokenType(domain_sep, contractAddress): Bytes<32>` —
/// `persistentCommit<Vector<2, Bytes<32>>>([domain_sep, address.bytes],
/// pad(32, "midnight:derive_token"))`.
pub fn token_type<V: Vis>(
    c: &mut Circuit,
    domain_sep: &Bytes32<V>,
    contract_address: &ContractAddress<V>,
) -> Bytes32<V> {
    let rand = Bytes32::pad(c, "midnight:derive_token");
    let value = [domain_sep.clone(), contract_address.bytes.clone()];
    persistent_commit(c, &value, &rand)
}

/// `circuit evolveNonce(index: Uint<128>, nonce: Bytes<32>): Bytes<32>` —
/// `upgradeFromTransient(transientHash<Vector<3, Field>>([domain, index,
/// degrade(nonce)]))`.
pub fn evolve_nonce<V: Vis>(c: &mut Circuit, index: U128<V>, nonce: &Bytes32<V>) -> Bytes32<V> {
    let domain = str_as_field(c, "midnight:kernel:nonce_evolve");
    let degraded = crate::hash::degrade_to_transient(nonce);
    let hash = c.transient_hash(&[domain, index.as_field(), degraded]);
    upgrade_from_transient(c, hash)
}

/// `struct CoinPreimage` — private in the Compact stdlib; the preimage of
/// both the coin commitment and the coin nullifier.
struct CoinPreimage<V: Vis> {
    /// `"midnight:zswap-cc[v1]"` / `"midnight:zswap-cn[v1]"` (`Bytes<21>`).
    domain_sep: BytesN<V, 21>,
    info: ShieldedCoinInfo<V>,
    data_type: Bool<V>,
    data: Bytes32<V>,
}

impl<V: Vis> Bundle<V> for CoinPreimage<V> {
    const WIDTH: usize = BytesN::<V, 21>::WIDTH
        + ShieldedCoinInfo::<V>::WIDTH
        + Bool::<V>::WIDTH
        + Bytes32::<V>::WIDTH;

    fn push_wires(&self, out: &mut Vec<Wire<V>>) {
        self.domain_sep.push_wires(out);
        self.info.push_wires(out);
        self.data_type.push_wires(out);
        self.data.push_wires(out);
    }

    fn from_wires(wires: &mut dyn Iterator<Item = Wire<V>>) -> Self {
        CoinPreimage {
            domain_sep: BytesN::from_wires(wires),
            info: ShieldedCoinInfo::from_wires(wires),
            data_type: Bool::from_wires(wires),
            data: Bytes32::from_wires(wires),
        }
    }

    fn push_atoms(out: &mut Vec<AlignmentAtom>) {
        BytesN::<V, 21>::push_atoms(out);
        ShieldedCoinInfo::<V>::push_atoms(out);
        Bool::<V>::push_atoms(out);
        Bytes32::<V>::push_atoms(out);
    }
}

/// `circuit coinCommitment(coin, recipient): Bytes<32>`
pub fn coin_commitment<V: Vis>(
    c: &mut Circuit,
    coin: &ShieldedCoinInfo<V>,
    recipient: &Either<V, ZswapCoinPublicKey<V>, ContractAddress<V>>,
) -> Bytes32<V> {
    let domain_sep = BytesN::literal(c, b"midnight:zswap-cc[v1]");
    // `recipient.is_left ? recipient.left.bytes : recipient.right.bytes`
    let data = cond_select(
        c,
        recipient.is_left.0,
        &recipient.left.bytes,
        &recipient.right.bytes,
    );
    let preimage = CoinPreimage {
        domain_sep,
        info: coin.clone(),
        data_type: recipient.is_left,
        data,
    };
    persistent_hash(c, &preimage)
}

/// `circuit coinNullifier(coin, addr): Bytes<32>`
pub fn coin_nullifier<V: Vis>(
    c: &mut Circuit,
    coin: &ShieldedCoinInfo<V>,
    addr: &ContractAddress<V>,
) -> Bytes32<V> {
    let domain_sep = BytesN::literal(c, b"midnight:zswap-cn[v1]");
    // dataType: false — the hypothetical is_left of
    // Either<ZswapCoinSecretKey, ContractAddress>.
    let data_type = Bool(crate::bundle::boolean(c, false));
    let preimage = CoinPreimage {
        domain_sep,
        info: coin.clone(),
        data_type,
        data: addr.bytes.clone(),
    };
    persistent_hash(c, &preimage)
}
