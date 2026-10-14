//! **EXPLORATION, not a corpus rewrite.** Per-recipient disclosure: handing
//! one named person a value only they can read, from inside a contract.
//!
//! The question this module exists to answer is "can a MinoCrab contract do
//! what DAML's privacy model does — make sure a party sees the data within
//! their purview, and nobody else?" The design discussion, the comparison
//! with DAML and the list of things that do NOT carry over live in
//! `notes/disclosure-model.org`; this module is the executable half.
//!
//! # The mechanism
//!
//! Hashed ElGamal (ECIES without a MAC) over Jubjub, computed IN-CIRCUIT, with
//! the ciphertext written to the public ledger. Recipient key `pk = g^ek`,
//! ephemeral scalar `e` fresh per call:
//!
//! ```text
//! E    = g^e                  the ephemeral public key
//! S    = pk^e = g^{ek·e}      the ECDH shared secret point
//! mask = KDF(S, domain)       a domain-separated field element
//! ct   = value + mask         a field one-time pad
//! ```
//!
//! The recipient recomputes `S = E^ek` from their own secret and recovers
//! `value = ct - mask`. That recovery needs NO proof and no on-chain
//! transaction — it is field arithmetic over a ledger read, which is why
//! [`tests/disclosure.rs`] implements it natively in Rust rather than as a
//! circuit.
//!
//! # Provenance
//!
//! This is a translation of OpenZeppelin's `crypto/EcdhMask.compact`
//! (`corpus/src/oz-compact-contracts/contracts/src/crypto/EcdhMask.compact`,
//! v0.3.0-alpha.2), per the reuse-before-writing rule — including its
//! weak-input guards and its KDF shape, so a MinoCrab contract and a Compact
//! contract using that module derive the same mask from the same key.
//!
//! WITH ONE DELIBERATE DIVERGENCE. OZ maps bytes to a Jubjub scalar as
//! `degradeToTransient(persistentHash(..))` — truncate the digest to 248 bits,
//! which is below the Jubjub scalar order ℓ (≈ 2^251.8), so the result is
//! always in range. Sound, but it is a workaround for a missing Compact
//! builtin: ZKIR HAS `jubjub_scalar_from_native`, which reduces mod ℓ, and
//! [`ephemeral_scalar`] ends on it. The truncation is kept in front of the
//! reduction so the scalar derived from a given seed is bit-for-bit the one
//! OZ's module derives (the reduction is the identity on a 248-bit input);
//! what the extra instruction buys is that range-correctness no longer rests
//! on `degrade`'s width happening to be below ℓ.
//!
//! OUR CORPUS COPY IS STALE, and that is why there is no differential here.
//! `corpus/compile-report.tsv` has `EcdhMask.compact line 148 char 22: no
//! compatible function named ecMulGenerator is in scope … supplied (Field),
//! declared (JubjubScalar)` — the vendored rev (5f3ecd4, v0.3.0-alpha.2)
//! passes a `Field` where compactc 0.34.0 wants a `JubjubScalar`, so none of
//! the OZ `crypto/` modules compile and there is no artifact to compare
//! against. Upstream `main` (v0.4.0-alpha.6) has since changed the signature
//! to `e: JubjubScalar`, which is what this module takes and what MinoCrab's
//! `GeneratorScalarTy` bound would have forced anyway: the same mistake is a
//! Rust type error here and was a compile failure there.
//!
//! # Two corrections upstream is making, and where this module stands on them
//!
//! Both are OPEN PRs on `OpenZeppelin/compact-contracts`, read 2026-10-11,
//! neither merged — so the vendored module and `main` both still have them.
//!
//! **#1110, "derive ElGamal's mask through Ecdh" (3/3).** `EcdhMask.encrypt`
//! and `ElGamal.encryptPoint` each carried their own Diffie-Hellman step AND
//! their own copy of the two weak-input guards, so the guards could drift
//! apart. The fix routes both through one `Ecdh.deriveShared`. This module
//! takes the lesson one step further than Compact can: [`derive_shared`] is
//! the only DH, and it returns a [`SharedSecret`] whose field is PRIVATE to
//! this module, so there is no way to obtain a shared secret without passing
//! the guards. The factoring is not a convention here, it is the type system —
//! which matters because the homomorphic ElGamal path is exactly the next
//! thing anyone exploring this will add (`notes/disclosure-model.org` §8).
//!
//! **#913, "hash to field and a uniform EcdhMask pad" (2/3).** The sharper
//! one, and it is a real leak rather than a tidiness point: `ct = m + kdf(S)`
//! with `kdf(S) < 2^248` NEVER WRAPS, so a plaintext anywhere near field size
//! publishes its top bits in the clear. OZ's own `encrypt` is safe (its
//! `value` is a `Uint<128>`, hidden with ~2^-120 slack), but `decrypt` returns
//! a `Field` and the module is described as masking "a single field element",
//! which invites a field-sized plaintext into a pad that cannot hide one.
//! Their fix is `fieldKdf`, RFC 9380 `hash_to_field` with an MGF1 expander
//! (Compact has no XOR for `expand_message_xmd`), uniform over the whole field
//! within 2^-257.
//!
//! WHERE THIS MODULE STANDS: safe, by the type and not by the comment.
//! [`encrypt`] takes `Uint<128>`, which is range-constrained in-circuit, so
//! the 248-bit pad has 120 bits of slack and no top bits leak. There is
//! deliberately NO `encrypt_field` — adding one needs `fieldKdf` first, and
//! `tests/disclosure.rs::the_248_bit_pad_cannot_hide_a_wide_value` pins why by
//! recovering the top bits of a 248-bit "plaintext" from its ciphertext. That
//! test is the reason the argument type is what it is.
//!
//! # What is on the ledger, and what that leaks
//!
//! ```text
//! export ledger keys:  Map<Bytes<32>, (Field, Field)>;  // field 0: account -> encode(pk)
//! export ledger memos: List<(Field, Field, Field)>;     // field 1: encode(E) ‖ ct
//! ```
//!
//! `memos` is ONE global append-only list, not a per-recipient
//! `Map<account, List<..>>`, and that is the privacy-relevant choice: a
//! per-recipient map publishes who received a disclosure and how many, which
//! is exactly the metadata DAML's stakeholder projection does not publish. A
//! single list costs the recipient a trial-decryption scan (O(n) in the
//! list, the Zcash model) and publishes only that a disclosure happened.
//! See `notes/disclosure-model.org` §4.
//!
//! # Why the keys are stored as `encode` LIMBS, not as `JubjubPoint`
//!
//! A `JubjubPoint` is `Cell`-only in a MinoCrab ledger: its limbs come out of
//! an `encode` instruction, ZKIR has no in-circuit inverse, so
//! [`LedgerRepr::from_limbs`] cannot rebuild one and a
//! `LedgerMap<_, JubjubPoint>` does not exist (see that impl's docs in
//! `minocrab-std`). [`PointLimbs`] is the way round: store the two field
//! limbs, which read back fine, and have the SENDER supply the point as a
//! typed argument that the circuit binds to the stored limbs. Off-circuit the
//! limbs decode back into a point (`decode_offcircuit`), which is all the
//! recipient's wallet needs.

use minocrab::v3::{Circuit3, FieldT, JubjubScalarT, Val, Wire3};
use minocrab::{label, Alignment, AlignmentAtom, AlignmentSegment, Fr, Private, Public};
use minocrab_std::v3::hash;
use minocrab_std::v3::{
    contract, is_true, not, CircuitAbi, Disclose, Discloses, JubjubPoint, Ledger, LedgerList,
    LedgerMap, LedgerRepr, Prim, ProofWires, Uint, Vis3, B32,
};

/// The domain-separation tag this contract's KDF is keyed with — the
/// `domain` argument OZ's `EcdhMask` leaves to its consumer. A recipient's
/// wallet MUST use the same bytes, and a different contract reusing the same
/// recipient key MUST use different ones.
pub const DOMAIN: &str = "minocrab_disclosure_ecdh_v1";

label! {
    /// The account a disclosure is addressed to. Public by necessity for
    /// `register` (it is the map key); see the module docs for why
    /// `disclose_to` does NOT make it public.
    pub RegisteredAccount = "registered account";
    /// The registered public key — one label for both `encode` limbs.
    pub RegisteredKey = "registered key";
    /// The ephemeral public key `E = g^e`, both limbs.
    pub EphemeralKey = "ephemeral key";
    /// The masked value `ct = value + KDF(pk^e)`. This is the ONLY thing the
    /// disclosure makes public about the value, and it is a one-time pad.
    pub MaskedValue = "masked value";
}

// ---- the stored shapes ------------------------------------------------------------

/// `encode(JubjubPoint)` — the two field limbs (x, y) a point crosses into
/// the ledger as. The `Public` instantiation is a ledger shape; the `Private`
/// one only ever appears between the `encode` and the `disclose`.
#[derive(Clone, Copy)]
pub struct PointLimbs<V: Vis3 = Private> {
    /// The affine x coordinate.
    pub x: Wire3<FieldT, V>,
    /// The affine y coordinate.
    pub y: Wire3<FieldT, V>,
}

impl<V: Vis3> PointLimbs<V> {
    /// `encode(point)` — the instruction, and the only constructor that ties
    /// these limbs to a point.
    pub fn of(c: &mut Circuit3, point: JubjubPoint<V>) -> Self {
        let limbs = c.encode(point.point());
        assert_eq!(limbs.len(), 2, "a Jubjub point encodes to two field limbs");
        PointLimbs {
            x: limbs[0],
            y: limbs[1],
        }
    }

    /// The limbs in slot order, for a hash preimage.
    pub fn slots(self) -> [Wire3<FieldT, V>; 2] {
        [self.x, self.y]
    }
}

impl Disclose for PointLimbs<Private> {
    type Public = PointLimbs<Public>;

    fn disclose_as<L: minocrab_std::v3::DisclosureLabel>(
        self,
        c: &mut Circuit3,
    ) -> PointLimbs<Public> {
        PointLimbs {
            x: self.x.disclose_as::<L>(c),
            y: self.y.disclose_as::<L>(c),
        }
    }
}

impl ProofWires for PointLimbs<Public> {
    fn push_wires(&self, out: &mut Vec<Val>) {
        out.push(self.x.val());
        out.push(self.y.val());
    }
}

impl LedgerRepr for PointLimbs<Public> {
    fn atoms() -> Vec<AlignmentAtom> {
        vec![AlignmentAtom::Field, AlignmentAtom::Field]
    }

    fn push_limbs(&self, _c: &mut Circuit3, limbs: &mut Vec<Wire3<FieldT, Public>>) {
        limbs.push(self.x);
        limbs.push(self.y);
    }

    fn from_limbs(limbs: Vec<Wire3<FieldT, Public>>) -> Self {
        assert_eq!(limbs.len(), 2, "a point is two field limbs");
        PointLimbs {
            x: limbs[0],
            y: limbs[1],
        }
    }
}

impl<V: Vis3> CircuitAbi for PointLimbs<V> {
    const SLOTS: usize = 2;

    fn push_atoms(atoms: &mut Vec<AlignmentAtom>) {
        atoms.push(AlignmentAtom::Field);
        atoms.push(AlignmentAtom::Field);
    }

    fn push_prims(prims: &mut Vec<Prim>) {
        prims.push(Prim::Field);
        prims.push(Prim::Field);
    }
}

/// The ciphertext as the ledger stores it: `{ ephemeralPk, ct }`, with the
/// point flattened to its `encode` limbs (see the module docs).
#[derive(Clone, Copy)]
pub struct Memo<V: Vis3 = Private> {
    /// `encode(E)`, `E = g^e`.
    pub ephemeral: PointLimbs<V>,
    /// `value + KDF(pk^e, DOMAIN)`.
    pub ct: Wire3<FieldT, V>,
}

impl ProofWires for Memo<Public> {
    fn push_wires(&self, out: &mut Vec<Val>) {
        self.ephemeral.push_wires(out);
        out.push(self.ct.val());
    }
}

impl LedgerRepr for Memo<Public> {
    fn atoms() -> Vec<AlignmentAtom> {
        vec![
            AlignmentAtom::Field,
            AlignmentAtom::Field,
            AlignmentAtom::Field,
        ]
    }

    fn push_limbs(&self, c: &mut Circuit3, limbs: &mut Vec<Wire3<FieldT, Public>>) {
        self.ephemeral.push_limbs(c, limbs);
        limbs.push(self.ct);
    }

    fn from_limbs(mut limbs: Vec<Wire3<FieldT, Public>>) -> Self {
        assert_eq!(limbs.len(), 3, "a memo is three field limbs");
        let ct = limbs.pop().expect("three limbs");
        Memo {
            ephemeral: PointLimbs::from_limbs(limbs),
            ct,
        }
    }
}

// ---- the primitive ----------------------------------------------------------------

/// The FAB alignment of a `Bytes<32>` pair — `Vector<2, Bytes<32>>`, the KDF's
/// second hash preimage.
fn two_b32_alignment() -> Alignment {
    Alignment(vec![
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
        AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
    ])
}

/// The FAB alignment of a `JubjubPoint` — two `field` atoms, the KDF's first
/// hash preimage.
fn point_alignment() -> Alignment {
    Alignment(vec![
        AlignmentSegment::Atom(AlignmentAtom::Field),
        AlignmentSegment::Atom(AlignmentAtom::Field),
    ])
}

/// `EcdhMask_kdf(sShared, domain)` — the field mask from the shared secret
/// point, domain-separated.
///
/// `persistentHash` (SHA-256) deliberately, not `transientHash`: the recipient
/// reproduces this mask off-chain, possibly across a platform upgrade, so it
/// has to be upgrade-stable. `degradeToTransient` truncates the 32-byte digest
/// to its low 31 bytes, which is where the hiding margin comes from — the mask
/// is uniform over `[0, 2^248)` while the value is `< 2^128`.
pub fn kdf(c: &mut Circuit3, shared: SharedSecret) -> Wire3<FieldT, Private> {
    c.region("ecdh kdf", |c| {
        let [x, y] = shared.0.slots();
        let point_hash = hash::persistent_hash_compact(c, point_alignment(), &[x.erase(), y.erase()]);
        let domain = B32::pad(c, DOMAIN);
        let mixed = hash::persistent_hash_compact(
            c,
            two_b32_alignment(),
            &[
                point_hash.hi.erase(),
                point_hash.lo.erase(),
                Private::from_public(domain.hi).erase(),
                Private::from_public(domain.lo).erase(),
            ],
        );
        hash::degrade_to_transient(c, &mixed)
    })
}

/// A Jubjub scalar from a 32-byte seed and a tag — OZ's `expandRandomness`,
/// finished with `jubjub_scalar_from_native` (see the module docs' divergence
/// note).
///
/// # The freshness obligation this does NOT discharge
///
/// `e` is a ONE-TIME PAD key. It must be unique per `(recipient, call)` AND
/// unpredictable to observers: `recipientPk` is public, so anyone who learns
/// `e` recomputes `S = pk^e` and opens the ciphertext. A unique but guessable
/// seed (a counter, a public nonce) therefore breaks confidentiality
/// completely. Nothing in-circuit can check either property — the circuit sees
/// a field element and cannot tell a secret one from a public one. The seed
/// MUST be a high-entropy witness the sender's wallet never publishes, and
/// `notes/disclosure-model.org` §5 records this as the sharpest edge in the
/// whole design.
pub fn ephemeral_scalar(
    c: &mut Circuit3,
    seed: &B32<Private>,
    tag: &B32<Public>,
) -> Wire3<JubjubScalarT, Private> {
    c.region("expand randomness", |c| {
        let expanded = hash::persistent_hash_compact(
            c,
            two_b32_alignment(),
            &[
                seed.hi.erase(),
                seed.lo.erase(),
                Private::from_public(tag.hi).erase(),
                Private::from_public(tag.lo).erase(),
            ],
        );
        let native = hash::degrade_to_transient(c, &expanded);
        c.jubjub_scalar_from_native(native)
    })
}

/// An ECDH shared secret point `S`, and the proof that the two weak-input
/// guards ran on the way to it.
///
/// The inner limbs are PRIVATE TO THIS MODULE, so [`derive_shared`] is the only
/// way to obtain one and [`kdf`] is the only thing that consumes one. That is
/// the structural version of what OZ's PR #1110 achieves by convention: there,
/// a second encryption path can still write its own `ecMul` and skip the
/// guards (which is exactly how `ElGamal.encryptPoint` came to duplicate
/// them); here it cannot, because it would have nothing to hand `kdf`.
pub struct SharedSecret(PointLimbs<Private>);

/// `Ecdh_deriveShared(pk, e)` — the ONE Diffie-Hellman step, with the ONE copy
/// of the weak-input guards. Returns `(E = g^e, S = pk^e)`.
///
/// # The guards, and why they are here rather than at each call site
///
/// `recipientPk = identity` gives `S = identity` for any `e`, and
/// `e ≡ 0 (mod ℓ)` gives `S = identity` for any key. Both yield
/// `mask = KDF(identity, domain)`, a value ANY observer can recompute, so a
/// ciphertext masked with it opens trivially. The identity IS a valid
/// prime-order-subgroup point, so the runtime's subgroup constraint does not
/// catch either case — nothing below this function would.
///
/// The ephemeral POINT is guarded, not the scalar: `g^e == identity` captures
/// both `e == 0` and any `e` reducing to 0 mod ℓ, so the guard holds however
/// the runtime treats an out-of-range scalar. Guarding `e != 0` instead would
/// lean on `ec_mul` faulting for `e >= ℓ`.
///
/// # What it does NOT guard, because no circuit can
///
/// That `e` is FRESH and SECRET — see [`ephemeral_scalar`]. A guard can rule
/// out the two values that break the scheme for everyone; it cannot tell a
/// high-entropy witness from a counter.
pub fn derive_shared(
    c: &mut Circuit3,
    recipient_pk: JubjubPoint<Private>,
    e: Wire3<JubjubScalarT, Private>,
) -> (PointLimbs<Private>, SharedSecret) {
    c.region("ecdh derive shared", |c| {
        // The identity's encode limbs as CONSTANTS, which is the one place
        // this diverges from OZ's shape for cost rather than correctness.
        // Compact has no point literal, so `EcdhMask` writes
        // `ecMulGenerator(0 as JubjubScalar)` and pays a full scalar
        // multiplication to learn a value known at compile time. Jubjub is a
        // twisted Edwards curve, so its identity is affine `(0, 1)` and
        // `encode` yields exactly those two limbs — pinned by
        // `tests/disclosure.rs::the_identity_point_encodes_to_zero_one`, which
        // is what makes this a measurement rather than a belief. Measured
        // saving: 657 rows, 13453 -> 12796, k unchanged at 14 — less than a
        // general scalar multiplication costs, because the operand was the
        // constant zero and the cost model already knew it.
        let identity = PointLimbs::<Private> {
            x: Private::from_public(c.constant(0u64)),
            y: Private::from_public(c.constant(1u64)),
        };

        let pk_limbs = PointLimbs::of(c, recipient_pk);
        let pk_is_identity = point_is(c, pk_limbs, identity);
        c.assert(not(pk_is_identity).message("Ecdh: identity pk"));

        let ephemeral = c.ec_mul_generator(e);
        let ephemeral = PointLimbs::of(c, JubjubPoint::from_point(ephemeral));
        let eph_is_identity = point_is(c, ephemeral, identity);
        c.assert(not(eph_is_identity).message("Ecdh: zero ephemeral"));

        let shared = c.ec_mul(recipient_pk.point(), e);
        let shared = PointLimbs::of(c, JubjubPoint::from_point(shared));
        (ephemeral, SharedSecret(shared))
    })
}

/// `EcdhMask_encrypt(recipientPk, value, e, DOMAIN)`.
///
/// # Why `value` is a `Uint<128>` and not a `Field`
///
/// Because [`kdf`]'s pad is 248 bits and `ct = value + mask` is field
/// addition that NEVER WRAPS for a 248-bit mask, so a plaintext anywhere near
/// field size publishes its top bits (upstream PR #913; the module docs carry
/// the argument and `tests/disclosure.rs` demonstrates the recovery). At
/// `Uint<128>` the pad has 120 bits of slack and hides the value with ~2^-120
/// statistical distance. The type is the enforcement: there is no way to hand
/// this function a wider plaintext, and no `encrypt_field` to reach for
/// instead.
///
/// # No authentication
///
/// The pad is malleable and nothing here authenticates it. Safe in the same
/// narrow sense it is safe in OZ's module — the ciphertext is computed
/// in-circuit from a value the same circuit commits to, and is immutable once
/// written — and `notes/disclosure-model.org` §6 says what breaks if either
/// half of that stops being true.
pub fn encrypt(
    c: &mut Circuit3,
    recipient_pk: JubjubPoint<Private>,
    value: Uint<128>,
    e: Wire3<JubjubScalarT, Private>,
) -> Memo<Private> {
    let (ephemeral, shared) = derive_shared(c, recipient_pk, e);
    c.region("ecdh mask", |c| {
        let mask = kdf(c, shared);
        let ct = c.add(value.field(), mask);
        Memo { ephemeral, ct }
    })
}

/// Two points are equal iff both `encode` limbs are — the only equality a
/// `JubjubPoint` has in ZKIR, since `test_eq` is a field-and-`Bytes<32>`
/// instruction and a point is neither.
fn point_is<V: Vis3>(c: &mut Circuit3, a: PointLimbs<V>, b: PointLimbs<V>) -> minocrab_std::v3::Check<V> {
    let x = c.test_eq(a.x, b.x);
    let y = c.test_eq(a.y, b.y);
    is_true(minocrab_std::v3::Bool::from_field_unchecked(x))
        .and(is_true(minocrab_std::v3::Bool::from_field_unchecked(y)))
}

// ---- the contract -----------------------------------------------------------------

/// The exploration contract's ledger block.
#[derive(Ledger)]
pub struct Disclosure {
    /// `account -> encode(pk)`. A public directory: who may be disclosed to,
    /// and under which key. DAML has no analogue — a party's identity is a
    /// participant-node fact, not a ledger row — and §3 of the note says what
    /// that costs.
    pub keys: LedgerMap<B32<Public>, PointLimbs<Public>>,
    /// Every disclosure ever made, in one list, addressed to nobody in
    /// particular as far as the ledger can tell. The recipient finds theirs by
    /// trial decryption.
    pub memos: LedgerList<Memo<Public>>,
}

/// The contract's ledger block.
pub const DISCLOSURE: Disclosure = Disclosure::new();

#[contract]
impl Disclosure {
    /// `register(account, pk)` — publish the account's Jubjub public key,
    /// proving the registrant holds its secret.
    ///
    /// Both arguments go public: the account is the map key and the key is the
    /// stored value, and a directory everyone can encrypt to is the point.
    ///
    /// # Proof of possession, and the half of the hole it closes
    ///
    /// `ek` is witnessed and `ec_mul_generator(ek)` is bound to the supplied
    /// `pk` limb for limb, so a key nobody controls cannot be registered.
    /// Without it "their key" means nothing: an attacker could point an
    /// account at a key whose secret is lost, and every disclosure to that
    /// account would then be undecryptable by anyone — a denial of service
    /// that no later transaction can undo, since the registry entry is the
    /// only thing a sender binds against.
    ///
    /// WHAT IT DOES NOT CLOSE, and the distinction is the whole reason this
    /// is only half a fix: it proves knowledge of the key's secret, NOT the
    /// right to speak for `account`. `account` is still a caller-supplied
    /// `Bytes<32>`, so a squatter may register SOMEONE ELSE'S account id
    /// under a key they genuinely hold — the proof passes, because they do
    /// know that `ek`, and disclosures to that account then go to them.
    /// Closing it needs the account BOUND TO THE CALLER (`own_public_key`,
    /// or a commitment to the caller's secret the way the vault's
    /// `common::commitment_transient` does), which is a separate rung and
    /// deliberately not done here. `notes/disclosure-model.org` §6 keeps the
    /// two apart, because conflating them is how "we check the key" comes to
    /// sound like "accounts are safe".
    ///
    /// The witnessed scalar goes through `jubjub_scalar_from_native`, which
    /// reduces mod ℓ, so a wallet's `ek` (already `< ℓ`) passes through
    /// unchanged, and a prover witnessing `ek + ℓ` proves the same statement
    /// about the same key. That is the module's existing idiom — see
    /// [`ephemeral_scalar`].
    #[circuit]
    pub fn register(
        c: &mut Circuit3,
        account: B32<Private>,
        pk: JubjubPoint<Private>,
    ) -> Discloses<(RegisteredAccount, RegisteredKey)> {
        let supplied = PointLimbs::of(c, pk);
        let ek_native = c.witness::<FieldT>();
        let ek = c.jubjub_scalar_from_native(ek_native);
        let derived = c.ec_mul_generator(ek);
        let derived = PointLimbs::of(c, JubjubPoint::from_point(derived));
        c.assert_eq(supplied.x, derived.x);
        c.assert_eq(supplied.y, derived.y);

        let account = account.disclose_as::<RegisteredAccount>(c);
        let limbs = supplied.disclose_as::<RegisteredKey>(c);
        DISCLOSURE.keys.insert(c, &account, &limbs);
        Discloses::of(())
    }

    /// `discloseTo(account, pk, value, seed)` — put `value` on the ledger in a
    /// form only the holder of `account`'s secret key can read.
    ///
    /// # What the circuit proves, and what it merely does
    ///
    /// PROVES: the ciphertext is a well-formed hashed-ElGamal encryption, under
    /// a fresh-looking ephemeral key, of a `Uint<128>` the circuit range-
    /// constrained, to the public key the ledger has registered for `account`.
    /// A sender cannot address a memo to a key of their choosing and claim it
    /// went to `account`: `pk` is bound to `keys[account]` limb for limb.
    ///
    /// MERELY DOES: delivery. Nothing here, and nothing a ZK contract can do,
    /// makes the recipient's wallet actually read the memo, and nothing stops
    /// the sender from encrypting the same value to a second key as well. Those
    /// two gaps are the whole difference from DAML and they are §2 of the note.
    ///
    /// # The account is NOT disclosed
    ///
    /// `account` enters the lookup as a public key (a map lookup's key is an
    /// Impact operand — there is no private map read), so this circuit DOES
    /// publish which account is being disclosed to, and the typed declaration
    /// says so. That is a real leak against DAML's model, and
    /// `notes/disclosure-model.org` §4 gives the two ways out — a per-call
    /// one-time address, or dropping the registry read and having the sender
    /// witness the key — neither of which is free.
    #[circuit]
    pub fn disclose_to(
        c: &mut Circuit3,
        account: B32<Private>,
        pk: JubjubPoint<Private>,
        value: Uint<128>,
        seed: B32<Private>,
    ) -> Discloses<(RegisteredAccount, EphemeralKey, MaskedValue)> {
        // The pk the sender supplied, bound to the one the ledger registered.
        let supplied = PointLimbs::of(c, pk);
        let account = account.disclose_as::<RegisteredAccount>(c);
        let registered = DISCLOSURE.keys.lookup(c, &account);
        c.assert_eq(supplied.x, registered.x);
        c.assert_eq(supplied.y, registered.y);

        // A tag distinguishing this expansion from any sibling in the same
        // call — there is one encryption here, so one tag.
        let tag = B32::pad(c, "memo");
        let e = ephemeral_scalar(c, &seed, &tag);
        let memo = encrypt(c, pk, value, e);

        let memo = Memo {
            ephemeral: memo.ephemeral.disclose_as::<EphemeralKey>(c),
            ct: memo.ct.disclose_as::<MaskedValue>(c),
        };
        DISCLOSURE.memos.push_front(c, &memo);
        Discloses::of(())
    }
}

/// `pad(32, s)` — Compact's right-zero-padding, as a const-friendly helper.
pub const fn pad32(s: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < s.len() {
        out[i] = s[i];
        i += 1;
    }
    out
}

/// The `Fr` the domain tag hashes as, for a wallet reproducing [`kdf`]
/// natively — the low 31 bytes little-endian, which is what
/// `B32::constant` puts in the low limb.
pub fn domain_fr() -> (Fr, Fr) {
    let bytes = pad32(DOMAIN.as_bytes());
    let lo = Fr::from_le_bytes(&bytes[..31]).expect("31 bytes fit a field element");
    let hi = Fr::from(u64::from(bytes[31]));
    (hi, lo)
}
