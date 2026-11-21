//! Compact's `kernel` ADT, and the token stdlib circuits built on it (M17,
//! notes/kernel-tokens.org).
//!
//! TWO LAYERS wearing one name, and the split is the milestone's main
//! structural finding:
//!
//! | layer | what it is | here |
//! |---|---|---|
//! | KERNEL PRIMITIVES | `declare-ledger-adt Kernel` functions with vm-code | [`mint_unshielded`](crate::kernel::mint_unshielded) … [`block_time_greater_than`](crate::kernel::block_time_greater_than) |
//! | STDLIB CIRCUITS | ordinary `export circuit`s written IN COMPACT, composed from those | [`send_unshielded`](crate::kernel::send_unshielded) … [`unshielded_balance_lte`](crate::kernel::unshielded_balance_lte) |
//!
//! The second layer is `standard-library.compact:113-350` transcribed. Each
//! function below carries the Compact it is a port of, and the bodies are
//! deliberately as close to it as Rust allows — these are the circuits whose
//! *composition* is the specification, and a reader should be able to check
//! them against the Compact source line by line.
//!
//! `kernel.checkpoint()` IS ABSENT. compactc before 0.36 could not compile it
//! for ZKIR v3 (notes/kernel-tokens.org finding (a)); compactc 0.36.0 lowers
//! it to one `impact` of `0xff` (corpus `kernel_checkpoint.zkir`), which is
//! not ported yet.
//!
//! THE BALANCE CAVEAT, which is Compact's own and worth repeating: the
//! balance these functions read is the contract's balance at the START of
//! execution. Unshielded sends, receives and mints inside the same circuit do
//! NOT feed back into it. `unshieldedBalance` also imposes exact-match
//! semantics at apply time, so the comparison forms are usually what a
//! contract wants.

use minocrab::{AnyWire, Circuit, FieldT, SelfAddressReads, Wire};
use minocrab::{AlignmentAtom, Fr, Private, Public};
use minocrab_ledger::{
    emit, kernel_balance, kernel_block_time, kernel_claim_unshielded_coin_spend,
    kernel_claim_zswap_coin_receive, kernel_claim_zswap_coin_spend, kernel_claim_zswap_nullifier,
    kernel_inc_unshielded_inputs, kernel_inc_unshielded_outputs, kernel_mint_shielded,
    kernel_mint_unshielded, kernel_self, kernel_caller, BalanceCmp, ImpactElem, LedgerValue,
};

use super::assumed::Assumed;
use super::hash;
use super::ledger::LedgerRepr;
use super::predicate::is_true;
use super::{Select, 
    coin_commitment_to, coin_commitment_to_contract, coin_nullifier_contract, Bool, CoinColor,
    CoinNonce, CoinRecipient, ContractAddress, Either, Maybe, QualifiedShieldedCoinInfo,
    ShieldedCoinInfo, ShieldedSendResult, TokenDomainSeparator, Uint, UserAddress, B32,
};

/// Compact's `TokenType` — `Either<Bytes<32>, Bytes<32>>`.
pub type TokenType<V = Public> = Either<B32<V>, B32<V>, V>;

/// Compact's `UnshieldedRecipient` — `Either<ContractAddress, UserAddress>`.
pub type UnshieldedRecipient<V = Public> = Either<ContractAddress<V>, UserAddress<V>, V>;

/// `left<Bytes<32>, Bytes<32>>(color)` — an unshielded token type, which is
/// the ONLY `TokenType` Compact's own stdlib ever builds.
///
/// A distinct type rather than a [`TokenType`], and the reason is the
/// instruction stream. Four of the five FAB limbs of `left(color)` are
/// CONSTANT — the `is_left` tag and the unused right arm's two — and compactc
/// inlines all four into the Impact `push`. Routing them through
/// [`LedgerRepr`] would name each with a `copy`, which is
/// the named-immediate gap M15 recorded for ledger VALUE positions and left
/// as dmd's call.
///
/// This closes it where it can be closed WITHOUT that API change: an
/// `UnshieldedToken` knows its own constants, so it builds its `LedgerValue`
/// with [`ImpactElem::Imm`] directly and never asks the trait for a wire that
/// does not exist. A `TokenType` whose tag is computed still goes the ordinary
/// way — the general `Either` impl is untouched.
#[derive(Clone, Copy)]
pub struct UnshieldedToken<V: super::Vis = Public>(pub B32<V>);

/// `left<Bytes<32>, Bytes<32>>(color)`.
pub fn unshielded(_c: &mut Circuit, color: CoinColor<Public>) -> UnshieldedToken<Public> {
    UnshieldedToken(color.bytes())
}

impl UnshieldedToken<Public> {
    /// The five FAB limbs, three of them inline constants: `[1, hi, lo, 0, 0]`
    /// under `[bytes<1>, bytes<32>, bytes<32>]`.
    pub fn ledger_value(&self) -> LedgerValue {
        LedgerValue::new(
            vec![
                AlignmentAtom::Bytes { length: 1 },
                AlignmentAtom::Bytes { length: 32 },
                AlignmentAtom::Bytes { length: 32 },
            ],
            vec![
                ImpactElem::Imm(Fr::from(1u64)),
                ImpactElem::Wire(self.0.hi),
                ImpactElem::Wire(self.0.lo),
                ImpactElem::Imm(Fr::from(0u64)),
                ImpactElem::Imm(Fr::from(0u64)),
            ],
        )
    }
}

// ---- the kernel primitives --------------------------------------------------

/// The cached `kernel.self()` answer — populated ONLY by
/// [`cache_self_address`], parked in the circuit's gadget scratch state
/// under this private type so nothing outside this module can touch it.
struct CachedSelfAddress(SelfAddress);

/// `kernel.self()` as a PROOF OF SELF — a value only the three
/// `self_address*` readers produce, because `ContractAddress<Public>` is
/// Compact's value type and is built from any `B32` (recipients, `Either`
/// arms, call targets), so it cannot carry that meaning. A helper that
/// means "mint to / burn from / notify AS this contract" takes a
/// `SelfAddress`; anything that merely wants an address takes
/// `.address()`. Zero rows: the same two limbs. (External review §4.5 and
/// notes/api-safety-survey.org §3 item 5.)
#[derive(Clone, Copy)]
pub struct SelfAddress(ContractAddress<Public>);

impl SelfAddress {
    /// The address, as the value type every other API takes.
    pub fn address(self) -> ContractAddress<Public> {
        self.0
    }

    /// [`ContractAddress::bytes`].
    pub fn bytes(self) -> B32<Public> {
        self.0.bytes()
    }

    /// [`ContractAddress::private`] — forget it is public and self.
    pub fn private(self) -> ContractAddress<Private> {
        self.0.private()
    }
}

impl From<SelfAddress> for ContractAddress<Public> {
    fn from(me: SelfAddress) -> Self {
        me.0
    }
}

/// A guarded self-address read is still a self-address where the guard
/// held (and the zero address where it did not) — `Guarded::or` needs this.
impl Select<Public> for SelfAddress {
    fn select(c: &mut Circuit, bit: Wire<FieldT, Public>, a: Self, b: Self) -> Self {
        SelfAddress(Select::select(c, bit, a.0, b.0))
    }
}

/// `kernel.self()` — the contract's own address. Reads fresh, unless this
/// circuit earlier kept an unguarded read ([`cache_self_address`], or a read
/// under [`SelfAddressReads::OncePerCircuit`]), in which case the kept wires
/// come back and no read is emitted.
///
/// The kept address is returned INSIDE a `when` scope too, with no read.
/// That is sound because the address is constant for the transaction and
/// every effect in the scope is guarded anyway; but note what it means for a
/// value taken out of the scope: `c.when(g, self_address).or_default()` is
/// then the address even where `g` is false, not the zero a guarded read
/// yields. A caller that needs the zero selects it (`.or(..)`, or a
/// `cond_select` on `g`), as `common::mint_shielded_token`'s receive guard
/// already does by multiplying with its guard.
///
/// How it reads is the circuit's lowering setting
/// ([`Lowering::self_address`](minocrab::Lowering::self_address)):
/// [`SelfAddressReads::OncePerCircuit`], the default, keeps the first read
/// made outside every `when` scope (a read inside one is guarded, and is
/// never kept); [`SelfAddressReads::EveryCall`], compactc's and so the
/// compat profile's, emits a read per call, so the ports' per-call-site
/// reads are reproduced by construction.
pub fn self_address(c: &mut Circuit) -> SelfAddress {
    if let Some(cached) = c.ext_get::<CachedSelfAddress>() {
        return cached.0;
    }
    match c.consult_lowering().self_address {
        SelfAddressReads::OncePerCircuit if !c.in_guarded_scope() => read_and_keep(c),
        _ => {
            let wires = kernel_self(c);
            SelfAddress(ContractAddress::from_limbs(never_stale(c, wires)))
        }
    }
}

/// The kernel's self read is a `popeq` on a value no transaction can change,
/// so it is acknowledged at the read and never wears `Assumed` (M42 B).
fn never_stale(c: &mut Circuit, wires: [Wire<FieldT, Public>; 2]) -> [Wire<FieldT, Public>; 2] {
    c.acknowledge_stale(&[wires[0].val(), wires[1].val()]);
    wires
}

/// Read `kernel.self()` and make it the answer every later [`self_address`]
/// call in this circuit gets.
fn read_and_keep(c: &mut Circuit) -> SelfAddress {
    let wires = kernel_self(c);
    let me = SelfAddress(ContractAddress::from_limbs(never_stale(c, wires)));
    c.ext_insert(CachedSelfAddress(me));
    me
}

/// Read `kernel.self()` ONCE and make it the ambient answer for every
/// later [`self_address`] call in this circuit (M18).
///
/// Under the default lowering ([`SelfAddressReads::OncePerCircuit`]) that is
/// what [`self_address`] does anyway, so this IS `self_address` plus the
/// refusal below: it states the intent at the call site, and it emits the
/// circuit's single read if none was kept yet.
///
/// The soundness paragraph is M10 rung i's, unchanged: the address is
/// constant for the transaction and read count is FRAMING, not protocol —
/// every read that IS emitted still reconciles through the ledger's
/// `process_read`. This is the typed CSE notes/ir-passes.org §3 assigns to
/// a gadget rather than a pass: the caller states the intent once, at the
/// top of the circuit, instead of threading the address through every
/// helper (`…_with` twins) — and a circuit whose helpers make their OWN
/// reads today must keep plain [`self_address`], because the cache would
/// swallow those reads and move the stream (the dump gate enforces this
/// per circuit).
///
/// INSIDE A SCOPE ([`Circuit::when`] / [`Circuit::when_private`]) this
/// keeps nothing: a read made there is guarded (it yields zero where the
/// guard is false), so keeping it would hand that zero to every later read
/// outside the scope. It returns what [`self_address`] returns there: the
/// kept address if an earlier unguarded read made one, else a guarded read
/// that is not kept.
///
/// REFUSED in a circuit that CHOSE [`SelfAddressReads::EveryCall`]
/// (`minocrab_compat::profile`, compactc's profile): compactc never caches,
/// so a parity port that called this would swallow reads its Compact twin
/// makes. A value-dependent check, so a build-time panic, recorded for
/// review.
#[track_caller]
pub fn cache_self_address(c: &mut Circuit) -> SelfAddress {
    let lowering = c.consult_lowering();
    assert!(
        lowering.self_address == SelfAddressReads::OncePerCircuit,
        "cache_self_address in a circuit whose lowering reads kernel.self() at every call \
         (compactc's, set by minocrab_compat::profile): compactc never caches, so the cache \
         would swallow reads the Compact twin makes and move the stream. Remove the \
         cache_self_address call (a parity port reads at every call site), or, if this \
         circuit has no Compact twin, drop the profile and choose \
         SelfAddressReads::OncePerCircuit instead."
    );
    // Kept, guarded or fresh exactly as `self_address` decides: inside a
    // `when` nothing is kept.
    self_address(c)
}

/// What [`caller`] returns: the ledger's `PublicAddress` under a `Maybe` —
/// `None` at the top of a transaction, `Some(Left(contract))` when another
/// contract called this one, `Some(Right(user))` when a user's funds did.
pub type Caller = Maybe<Either<ContractAddress<Public>, UserAddress<Public>, Public>, Public>;

/// `kernel.caller()` — WHO is calling this circuit, as the ledger knows it.
///
/// The read is `context[6]`, authenticated by the ledger at admission: a
/// prover cannot choose it, which is exactly why a "only contract X may
/// spend this grant" rule compares this value rather than an argument.
/// Like [`self_address`] it is fixed for the transaction, so the read is
/// acknowledged here and never wears [`Assumed`].
///
/// Six public inputs; the lowering is compactc 0.35.0's, byte for byte
/// (`minocrab_ledger::kernel_caller`). First wanted by the passport account
/// custody port (PR #184), which hand-assembled the opcodes for lack of this.
pub fn caller(c: &mut Circuit) -> Caller {
    let w = kernel_caller(c);
    c.acknowledge_stale(&w.iter().map(|x| x.val()).collect::<Vec<_>>());
    Maybe {
        is_some: Bool::from_field_unchecked(w[0]),
        value: Either {
            is_left: Bool::from_field_unchecked(w[1]),
            left: ContractAddress::from_limbs([w[2], w[3]]),
            right: UserAddress::from_limbs([w[4], w[5]]),
        },
    }
}

/// `kernel.mintShielded(domain_sep, amount)` — effects\[4\].
pub fn mint_shielded(c: &mut Circuit, domain_sep: &TokenDomainSeparator<Public>, amount: Uint<64, Public>) {
    let (ds, amt) = (domain_sep.bytes().ledger_value(c), amount.ledger_value(c));
    emit(c, &kernel_mint_shielded(&ds, &amt));
}

/// `kernel.mintUnshielded(domain_sep, amount)` — effects\[5\], and the same
/// accumulator shape [`mint_shielded`] is.
pub fn mint_unshielded(c: &mut Circuit, domain_sep: &TokenDomainSeparator<Public>, amount: Uint<64, Public>) {
    let (ds, amt) = (domain_sep.bytes().ledger_value(c), amount.ledger_value(c));
    emit(c, &kernel_mint_unshielded(&ds, &amt));
}

/// `kernel.incUnshieldedInputs(token_type, amount)` — effects\[6\]. Called when
/// the contract RECEIVES an unshielded token.
pub fn inc_unshielded_inputs(
    c: &mut Circuit,
    token: &UnshieldedToken<Public>,
    amount: Uint<128, Public>,
) {
    let (t, amt) = (token.ledger_value(), amount.ledger_value(c));
    emit(c, &kernel_inc_unshielded_inputs(&t, &amt));
}

/// `kernel.incUnshieldedOutputs(token_type, amount)` — effects\[7\]. Called when
/// the contract SENDS one.
pub fn inc_unshielded_outputs(
    c: &mut Circuit,
    token: &UnshieldedToken<Public>,
    amount: Uint<128, Public>,
) {
    let (t, amt) = (token.ledger_value(), amount.ledger_value(c));
    emit(c, &kernel_inc_unshielded_outputs(&t, &amt));
}

/// `kernel.claimUnshieldedCoinSpend(token_type, recipient, amount)` —
/// effects\[8\]. Authorizes a transfer; the key is the token type and the
/// recipient TOGETHER, so the two travel as one six-atom value.
pub fn claim_unshielded_coin_spend(
    c: &mut Circuit,
    token: &UnshieldedToken<Public>,
    recipient: &UnshieldedRecipient<Public>,
    amount: Uint<128, Public>,
) {
    let key = concat_values(token.ledger_value(), recipient.ledger_value(c));
    let amt = amount.ledger_value(c);
    emit(c, &kernel_claim_unshielded_coin_spend(&key, &amt));
}

/// The two halves of `claimUnshieldedCoinSpend`'s key, side by side in one
/// `LedgerValue` — which is what the single `push` in its stream carries.
fn concat_values(a: LedgerValue, b: LedgerValue) -> LedgerValue {
    let mut atoms = a.atoms().to_vec();
    let mut elems = a.elems().to_vec();
    atoms.extend_from_slice(b.atoms());
    elems.extend_from_slice(b.elems());
    LedgerValue::new(atoms, elems)
}

/// `kernel.balance(token_type)` — the contract's balance of an unshielded
/// token, or ZERO if it has never held one. See the module docs for what
/// "balance" means here.
pub fn balance(c: &mut Circuit, token: &UnshieldedToken<Public>) -> Assumed<Uint<128, Public>> {
    let t = token.ledger_value();
    Assumed::of_read(Uint::from_field_unchecked(kernel_balance(c, &t, BalanceCmp::Value, None)))
}

/// `kernel.balanceLessThan(token_type, amount)`.
pub fn balance_less_than(
    c: &mut Circuit,
    token: &UnshieldedToken<Public>,
    amount: Uint<128, Public>,
) -> Assumed<Bool<Public>> {
    let (t, amt) = (token.ledger_value(), amount.ledger_value(c));
    Assumed::of_read(Bool::from_field_unchecked(kernel_balance(c, &t, BalanceCmp::LessThan, Some(&amt))))
}

/// `kernel.balanceGreaterThan(token_type, amount)`.
pub fn balance_greater_than(
    c: &mut Circuit,
    token: &UnshieldedToken<Public>,
    amount: Uint<128, Public>,
) -> Assumed<Bool<Public>> {
    let (t, amt) = (token.ledger_value(), amount.ledger_value(c));
    Assumed::of_read(Bool::from_field_unchecked(kernel_balance(c, &t, BalanceCmp::GreaterThan, Some(&amt))))
}

/// `kernel.blockTimeLessThan(t)` — whether the block time is before `t`.
pub fn block_time_less_than(c: &mut Circuit, time: Uint<64, Public>) -> Assumed<Bool<Public>> {
    let t = time.ledger_value(c);
    Assumed::of_read(Bool::from_field_unchecked(kernel_block_time(c, &t, false)))
}

/// `kernel.blockTimeGreaterThan(t)`.
pub fn block_time_greater_than(c: &mut Circuit, time: Uint<64, Public>) -> Assumed<Bool<Public>> {
    let t = time.ledger_value(c);
    Assumed::of_read(Bool::from_field_unchecked(kernel_block_time(c, &t, true)))
}

// ---- the stdlib circuits ----------------------------------------------------
//
// standard-library.compact:275-350, transcribed. Each is a composition of the
// primitives above and nothing else.

/// `circuit blockTimeLt(time): Boolean { return kernel.blockTimeLessThan(time); }`
pub fn block_time_lt(c: &mut Circuit, time: Uint<64, Public>) -> Assumed<Bool<Public>> {
    block_time_less_than(c, time)
}

/// `circuit blockTimeGte(time): Boolean { return !blockTimeLt(time); }`
pub fn block_time_gte(c: &mut Circuit, time: Uint<64, Public>) -> Assumed<Bool<Public>> {
    let lt = block_time_lt(c, time);
    Assumed::of_read(not(c, lt.into_inner()))
}

/// `circuit blockTimeGt(time): Boolean { return kernel.blockTimeGreaterThan(time); }`
pub fn block_time_gt(c: &mut Circuit, time: Uint<64, Public>) -> Assumed<Bool<Public>> {
    block_time_greater_than(c, time)
}

/// `circuit blockTimeLte(time): Boolean { return !blockTimeGt(time); }`
pub fn block_time_lte(c: &mut Circuit, time: Uint<64, Public>) -> Assumed<Bool<Public>> {
    let gt = block_time_gt(c, time);
    Assumed::of_read(not(c, gt.into_inner()))
}

/// Compact's `!b` on a Boolean: the `not` instruction (3 rows). compactc
/// writes `cond_select(b, 0, 1)` (5 rows; `minocrab_compat::kernel`). The
/// two are the same constraint on `b` and the same value: `not` converts its
/// operand to a bit (midnight-zkir 3.2.0 `ir_vm.rs:1186-1193`) exactly as
/// `cond_select` converts its selector (`:1064-1071`), and both yield `1 - b`.
fn not(c: &mut Circuit, b: Bool<Public>) -> Bool<Public> {
    Bool::from_field_unchecked(c.not(b.field()))
}

/// `circuit unshieldedBalance(color): Uint<128>`
pub fn unshielded_balance(c: &mut Circuit, color: CoinColor<Public>) -> Assumed<Uint<128, Public>> {
    let token = unshielded(c, color);
    balance(c, &token)
}

/// `circuit unshieldedBalanceLt(color, amount): Boolean`
pub fn unshielded_balance_lt(
    c: &mut Circuit,
    color: CoinColor<Public>,
    amount: Uint<128, Public>,
) -> Assumed<Bool<Public>> {
    let token = unshielded(c, color);
    balance_less_than(c, &token, amount)
}

/// `circuit unshieldedBalanceGte(color, amount): Boolean { return !…Lt(…); }`
pub fn unshielded_balance_gte(
    c: &mut Circuit,
    color: CoinColor<Public>,
    amount: Uint<128, Public>,
) -> Assumed<Bool<Public>> {
    let lt = unshielded_balance_lt(c, color, amount);
    Assumed::of_read(not(c, lt.into_inner()))
}

/// `circuit unshieldedBalanceGt(color, amount): Boolean`
pub fn unshielded_balance_gt(
    c: &mut Circuit,
    color: CoinColor<Public>,
    amount: Uint<128, Public>,
) -> Assumed<Bool<Public>> {
    let token = unshielded(c, color);
    balance_greater_than(c, &token, amount)
}

/// `circuit unshieldedBalanceLte(color, amount): Boolean { return !…Gt(…); }`
pub fn unshielded_balance_lte(
    c: &mut Circuit,
    color: CoinColor<Public>,
    amount: Uint<128, Public>,
) -> Assumed<Bool<Public>> {
    let gt = unshielded_balance_gt(c, color, amount);
    Assumed::of_read(not(c, gt.into_inner()))
}

/// ```text
/// circuit receiveUnshielded(color, amount): [] {
///   kernel.incUnshieldedInputs(left<Bytes<32>, Bytes<32>>(color), amount);
/// }
/// ```
pub fn receive_unshielded(c: &mut Circuit, color: CoinColor<Public>, amount: Uint<128, Public>) {
    let token = unshielded(c, color);
    inc_unshielded_inputs(c, &token, amount);
}

/// `recipient.is_left && recipient.left.bytes == kernel.self().bytes` — the
/// AUTO-RECEIVE guard both [`send_unshielded`] and [`mint_unshielded_token`]
/// end with, and the reason each of them is more than a pair of effects.
///
/// The address is [`self_address`] under `is_left` (a user recipient never
/// needs it): the kept address if the circuit has one (no read), else a
/// read guarded by `is_left` that yields zero where `is_left` is off. The
/// value only matters where `is_left` is 1, and there both are the address.
///
/// LEAN against compactc's (`minocrab_compat::kernel::is_self`, which reads
/// under an explicit guard and uses two `cond_select`s): the limb `&&` is a
/// `mul`, sound because both operands are `test_eq` outputs, bits by
/// construction, so the selector bit check it drops constrained nothing. The
/// outer `cond_select(is_left, …)` STAYS: it is the one instruction that
/// constrains `is_left` to be a bit whether or not a read is emitted.
fn is_self(c: &mut Circuit, recipient: &UnshieldedRecipient<Public>) -> Wire<FieldT, Public> {
    let is_left = recipient.is_left.field();
    let me = c.when(is_left, self_address).or_default().bytes();
    let left = recipient.left.bytes();
    let eq_hi = c.test_eq(left.hi, me.hi);
    let eq_lo = c.test_eq(left.lo, me.lo);
    let both = c.mul(eq_hi, eq_lo);
    c.cond_select(is_left, both, 0u64)
}

/// Emit `ops` under `guard`, in ONE `when` scope: the guard is conjoined
/// with the ambient scope once on entry. compactc's
/// (`minocrab_compat::kernel::emit_guarded`) conjoins it per op, the same
/// `cond_select(ambient, guard, 0)` repeated, so each Impact op carries the
/// same guard value either way; the repeats are only rows.
fn emit_guarded(c: &mut Circuit, guard: Wire<FieldT, Public>, ops: &[minocrab_ledger::ImpactOp]) {
    c.when(guard, |c| emit(c, ops));
}

/// ```text
/// circuit sendUnshielded(color, amount, recipient): [] {
///   kernel.incUnshieldedOutputs(left<Bytes<32>, Bytes<32>>(color), amount);
///   kernel.claimUnshieldedCoinSpend(left<Bytes<32>, Bytes<32>>(color), recipient, amount);
///   // Auto-receive when sending to self
///   if (recipient.is_left && recipient.left.bytes == kernel.self().bytes) {
///     kernel.incUnshieldedInputs(left<Bytes<32>, Bytes<32>>(color), amount);
///   }
/// }
/// ```
pub fn send_unshielded(
    c: &mut Circuit,
    color: CoinColor<Public>,
    amount: Uint<128, Public>,
    recipient: &UnshieldedRecipient<Public>,
) {
    let token = unshielded(c, color);
    inc_unshielded_outputs(c, &token, amount);
    claim_unshielded_coin_spend(c, &token, recipient, amount);
    let mine = is_self(c, recipient);
    let t = token.ledger_value();
    let amt = amount.ledger_value(c);
    emit_guarded(c, mine, &minocrab_ledger::kernel_inc_unshielded_inputs(&t, &amt));
}

/// ```text
/// circuit mintUnshieldedToken(domainSep, amount, recipient): Bytes<32> {
///   kernel.mintUnshielded(domainSep, amount);
///   const color = tokenType(domainSep, kernel.self());
///   kernel.claimUnshieldedCoinSpend(left<Bytes<32>, Bytes<32>>(color), recipient, amount);
///   // Auto-receive when minting to self
///   if (recipient.is_left && recipient.left.bytes == kernel.self().bytes) {
///     kernel.incUnshieldedInputs(left<Bytes<32>, Bytes<32>>(color), amount);
///   }
///   return color;
/// }
/// ```
///
/// Note the amount is a `Uint<64>` at the mint and a `Uint<128>` at the
/// claim — Compact widens it, and so does this.
pub fn mint_unshielded_token(
    c: &mut Circuit,
    domain_sep: &TokenDomainSeparator<Public>,
    amount: Uint<64, Public>,
    recipient: &UnshieldedRecipient<Public>,
) -> CoinColor<Public> {
    mint_unshielded(c, domain_sep, amount);
    let me = self_address(c);
    let color = super::token_type(c, domain_sep, &me.bytes());
    let token = unshielded(c, color);
    let wide = Uint::<128, Public>::from_field_unchecked(amount.field());
    claim_unshielded_coin_spend(c, &token, recipient, wide);
    let mine = is_self(c, recipient);
    let t = token.ledger_value();
    let amt = wide.ledger_value(c);
    emit_guarded(c, mine, &minocrab_ledger::kernel_inc_unshielded_inputs(&t, &amt));
    color
}

// ---- the SHIELDED half ------------------------------------------------------
//
// The zswap primitives and the three stdlib circuits built from them. What
// makes this half longer than the unshielded one is not the kernel — the three
// claims below are the same accumulator shape as the rest — but the COIN
// ALGEBRA between them: a nonce is evolved, a commitment is hashed, a value is
// split into what is sent and what comes back as change.
//
// Two shapes recur, and both are compactc's rather than ours:
//
//   - A coin paid to THIS contract is `right(kernel.self())`, a literal, so
//     its commitment has no recipient select at all
//     (`coin_commitment_to_contract`).
//   - `upgradeFromTransient(transientHash([<tag>, degradeToTransient(nonce)]))`
//     is how every derived nonce is made; the tag is inline and the two
//     `Copy`s are the casts (`hash::degrade_to_transient`).

/// `kernel.claimZswapNullifier(nul)` — effects\[0\]. Says this contract spent
/// the coin that nullifier names.
pub fn claim_zswap_nullifier(c: &mut Circuit, nullifier: &B32<Public>) {
    let nul = nullifier.ledger_value(c);
    emit(c, &kernel_claim_zswap_nullifier(&nul));
}

/// `kernel.claimZswapCoinSpend(cm)` — effects\[2\]. Says this contract
/// AUTHORIZED the output that commitment names.
pub fn claim_zswap_coin_spend(c: &mut Circuit, commitment: &B32<Public>) {
    let cm = commitment.ledger_value(c);
    emit(c, &kernel_claim_zswap_coin_spend(&cm));
}

/// `kernel.claimZswapCoinReceive(cm)` — effects\[1\]. Says this contract now
/// OWNS the coin that commitment names. Separate from the spend claim because
/// a contract paying itself makes both.
pub fn claim_zswap_coin_receive(c: &mut Circuit, commitment: &B32<Public>) {
    let cm = commitment.ledger_value(c);
    emit(c, &kernel_claim_zswap_coin_receive(&cm));
}

/// The domain a coin's successor nonce is derived under, and the `/2` variant
/// `sendShielded` gives its CHANGE coin — two coins come out of one input, so
/// they cannot share a nonce.
const NONCE_EVOLVE: &[u8] = b"midnight:kernel:nonce_evolve";
const NONCE_EVOLVE_CHANGE: &[u8] = b"midnight:kernel:nonce_evolve/2";

/// `upgradeFromTransient(transientHash<Vector<2, Field>>([<domain> as Field,
/// degradeToTransient(nonce)]))` — the nonce of a coin derived from another.
///
/// Not the stdlib's `evolveNonce`, which hashes an INDEX as well; this is the
/// two-element form `sendShielded` and `mergeCoin` write inline.
fn derived_nonce(c: &mut Circuit, domain: &[u8], nonce: &CoinNonce<Public>) -> CoinNonce<Public> {
    let degraded = hash::degrade_to_transient(c, &nonce.bytes());
    let h = c.transient_hash(&[
        AnyWire::immediate(super::short_literal_imm(domain)),
        degraded.erase(),
    ]);
    CoinNonce(hash::upgrade_from_transient(c, h))
}

/// `a == b` on `Bytes<32>`: a `test_eq` per limb and their product. compactc
/// writes the `&&` as `cond_select(hi, lo, 0)` (`minocrab_compat::kernel`);
/// the product is the same value because `hi` is a `test_eq` output, a bit
/// by construction, so the selector bit check the select adds constrains
/// nothing (`mul` 3 rows, `cond_select` 5).
fn bytes_eq(c: &mut Circuit, a: &B32<Public>, b: &B32<Public>) -> Wire<FieldT, Public> {
    let hi = c.test_eq(a.hi, b.hi);
    let lo = c.test_eq(a.lo, b.lo);
    c.mul(hi, lo)
}

/// Compact's `a - b` on a `Uint<128>`: the difference, and the assertion that
/// there is one — a subtraction that would go below zero is a failed proof,
/// not a wrap.
fn checked_sub(
    c: &mut Circuit,
    a: Wire<FieldT, Public>,
    b: Wire<FieldT, Public>,
) -> Wire<FieldT, Public> {
    let underflow = c.less_than(a, b, 128);
    let ok = not(c, Bool::from_field_unchecked(underflow));
    c.assert(is_true(ok).message("subtraction would underflow"));
    let neg = c.neg(b);
    c.add(a, neg)
}

/// Compact's `x as Uint<128>` on a value just computed: the range
/// constraint, and the checked wire. compactc also names the result with a
/// `copy` (`minocrab_compat::kernel::as_uint128`), an alias of zero rows.
fn as_uint128(c: &mut Circuit, w: Wire<FieldT, Public>) -> Wire<FieldT, Public> {
    // Inside a `when` the checked value is the selected one; that is the
    // value everything downstream (the commitment, the ledger op) consumes —
    // compactc's branch semantics, and what keeps the hash preimage provably
    // bounded for the taint lint.
    Uint::<128, Public>::from_field_checked(c, w).field()
}

/// ```text
/// circuit mergeCoin(a: QualifiedShieldedCoinInfo, b: QualifiedShieldedCoinInfo): ShieldedCoinInfo {
///   const selfAddr = kernel.self();
///   createZswapInput(a);
///   kernel.claimZswapNullifier(coinNullifier(downcastQualifiedCoin(a), selfAddr));
///   createZswapInput(b);
///   kernel.claimZswapNullifier(coinNullifier(downcastQualifiedCoin(b), selfAddr));
///   assert(a.color == b.color, "Can only merge coins of the same color");
///   const newCoin = ShieldedCoinInfo{
///     nonce: upgradeFromTransient(transientHash<Vector<2, Field>>([
///              "midnight:kernel:nonce_evolve" as Field, degradeToTransient(a.nonce)])),
///     color: a.color,
///     value: (a.value + b.value) as Uint<128>
///   };
///   createZswapOutput(newCoin, right<ZswapCoinPublicKey, ContractAddress>(selfAddr));
///   const cm = coinCommitment(newCoin, right<ZswapCoinPublicKey, ContractAddress>(selfAddr));
///   kernel.claimZswapCoinSpend(cm);
///   kernel.claimZswapCoinReceive(cm);
///   return newCoin;
/// }
/// ```
///
/// `createZswapInput`/`createZswapOutput` are Void witness natives — they tell
/// the off-circuit builder to put the coin in the transaction's offer and emit
/// NOTHING here, which is why two coins going in cost only their two
/// nullifiers.
pub fn merge_coin(
    c: &mut Circuit,
    a: &QualifiedShieldedCoinInfo<Public>,
    b: &QualifiedShieldedCoinInfo<Public>,
) -> ShieldedCoinInfo<Public> {
    merge(c, &a.downcast(), &b.downcast())
}

/// ```text
/// circuit mergeCoinImmediate(a: QualifiedShieldedCoinInfo, b: ShieldedCoinInfo): ShieldedCoinInfo {
///   return mergeCoin(a, upcastQualifiedCoin(b));
/// }
/// ```
///
/// `upcastQualifiedCoin` sets `mt_index: 0`, and NOTHING reads it — the index
/// is the ledger's business, and the merge only ever downcasts back. So this
/// is [`merge_coin`]'s body against `b` directly rather than a round trip
/// through a qualified coin with a fabricated index, and compactc's artifacts
/// agree: `sMergeCoinImmediate` is `sMergeCoin` minus `b`'s `mt_index`
/// constraint, instruction for instruction.
pub fn merge_coin_immediate(
    c: &mut Circuit,
    a: &QualifiedShieldedCoinInfo<Public>,
    b: &ShieldedCoinInfo<Public>,
) -> ShieldedCoinInfo<Public> {
    merge(c, &a.downcast(), b)
}

/// Everything both merges do, once the coins are downcast.
fn merge(
    c: &mut Circuit,
    a: &ShieldedCoinInfo<Public>,
    b: &ShieldedCoinInfo<Public>,
) -> ShieldedCoinInfo<Public> {
    let me = self_address(c).bytes();
    let nul_a = coin_nullifier_contract(c, a, &me);
    claim_zswap_nullifier(c, &nul_a);
    let nul_b = coin_nullifier_contract(c, b, &me);
    claim_zswap_nullifier(c, &nul_b);

    let same_colour = bytes_eq(c, &a.color.bytes(), &b.color.bytes());
    c.assert(
        is_true(Bool::from_field_unchecked(same_colour)).message("Can only merge coins of the same color"),
    );

    // Field order is evaluation order, and compactc's too: the derived nonce
    // before the sum.
    let nonce = derived_nonce(c, NONCE_EVOLVE, &a.nonce);
    let sum = c.add(a.value, b.value);
    let new_coin = ShieldedCoinInfo {
        nonce,
        color: a.color,
        value: as_uint128(c, sum),
    };
    let cm = coin_commitment_to_contract(c, &new_coin, &me);
    claim_zswap_coin_spend(c, &cm);
    claim_zswap_coin_receive(c, &cm);
    new_coin
}

/// ```text
/// circuit sendShielded(input: QualifiedShieldedCoinInfo,
///                      recipient: Either<ZswapCoinPublicKey, ContractAddress>,
///                      value: Uint<128>): ShieldedSendResult {
///   const selfAddr = kernel.self();
///   createZswapInput(input);
///   kernel.claimZswapNullifier(coinNullifier(downcastQualifiedCoin(input), selfAddr));
///   const change = input.value - value;
///   const output = ShieldedCoinInfo{ nonce: <derived>, color: input.color, value: value };
///   createZswapOutput(output, recipient);
///   kernel.claimZswapCoinSpend(coinCommitment(output, recipient));
///   // Auto-receive when sending to self
///   if (!recipient.is_left && recipient.right.bytes == selfAddr.bytes) {
///     kernel.claimZswapCoinReceive(coinCommitment(output, recipient));
///   }
///   if (change == 0) { return ShieldedSendResult{ change: none, sent: output }; }
///   else { <change coin, spent and received by this contract>; }
/// }
/// ```
///
/// THE `if (change == 0)` IS AN EXPRESSION, and it is written out here rather
/// than through [`Circuit::when_value`](minocrab::Circuit::when_value)
/// for one reason worth stating: compactc FOLDS the `Maybe`'s tag into the
/// guard it already has. `none` and `some` differ in a tag that is `0` on one
/// side and `1` on the other, so selecting it yields `cond_select(change == 0,
/// 0, 1)` — which is the `else` arm's guard, already computed. A chain would
/// emit that select a second time. So the tag IS the guard here, named once,
/// and only the five payload slots are selected.
///
/// `output`'s commitment is hashed ONCE and claimed twice (spend, and the
/// auto-receive). compactc hashes it twice, one per `coinCommitment` call in
/// the source (`minocrab_compat::kernel::send_shielded`, about 5,640 rows):
/// the same `persistent_hash` on the same wires, so the same digest.
pub fn send_shielded(
    c: &mut Circuit,
    input: &QualifiedShieldedCoinInfo<Public>,
    recipient: &CoinRecipient<Public>,
    value: Uint<128, Public>,
) -> ShieldedSendResult<Public> {
    let me = self_address(c).bytes();
    let spent = input.downcast();
    let nul = coin_nullifier_contract(c, &spent, &me);
    claim_zswap_nullifier(c, &nul);

    let change = checked_sub(c, input.value, value.field());

    let output = ShieldedCoinInfo {
        nonce: derived_nonce(c, NONCE_EVOLVE, &input.nonce),
        color: input.color,
        value: value.field(),
    };
    let to = B32::cond_select(c, recipient.is_left, &recipient.left.bytes(), &recipient.right.bytes());
    let cm = coin_commitment_to(c, &output, recipient.is_left.erase(), &to);
    claim_zswap_coin_spend(c, &cm);

    // Auto-receive when sending to self: `!recipient.is_left && …`, which is
    // one `cond_select` with the arms the other way round from `is_self`'s.
    // The address needs no guarded read — `selfAddr` is already to hand.
    // The select stays (rather than `(1 - is_left) * same`): it is a bit
    // check on `is_left` that does not depend on what else reads it.
    let same = bytes_eq(c, &recipient.right.bytes(), &me);
    let mine = c.cond_select(recipient.is_left, 0u64, same);
    let cm_val = cm.ledger_value(c);
    emit_guarded(c, mine, &minocrab_ledger::kernel_claim_zswap_coin_receive(&cm_val));

    let spent_it_all = c.test_eq(change, 0u64);
    let has_change = not(c, Bool::from_field_unchecked(spent_it_all)).field();
    let change_coin = ShieldedCoinInfo {
        nonce: derived_nonce(c, NONCE_EVOLVE_CHANGE, &input.nonce),
        color: input.color,
        value: change,
    };
    let change_cm = coin_commitment_to_contract(c, &change_coin, &me);
    c.when(has_change, |c| {
        claim_zswap_coin_spend(c, &change_cm);
        claim_zswap_coin_receive(c, &change_cm);
    });

    // `none<ShieldedCoinInfo>()` is the default coin, so the payload is the
    // change coin selected against zero — the tag is `has_change` above.
    let none_unless = |c: &mut Circuit, w| c.cond_select(spent_it_all, 0u64, w);
    let change_value = ShieldedCoinInfo {
        nonce: CoinNonce(B32 {
            hi: none_unless(c, change_coin.nonce.bytes().hi),
            lo: none_unless(c, change_coin.nonce.bytes().lo),
        }),
        color: CoinColor(B32 {
            hi: none_unless(c, change_coin.color.bytes().hi),
            lo: none_unless(c, change_coin.color.bytes().lo),
        }),
        value: none_unless(c, change_coin.value),
    };
    ShieldedSendResult {
        change: Maybe {
            is_some: Bool::from_field_unchecked(has_change),
            value: change_value,
        },
        sent: output,
    }
}
