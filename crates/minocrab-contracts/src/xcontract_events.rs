//! `xcontract-events` (signet-midnight-experiments) — provable event
//! attribution across a cross-contract call (M5): vault A calls token B's
//! `deposit`, B emits a DepositEvent and returns its hash, and BOTH sides
//! record the hash in authenticated state. The communication commitment
//! guarantees the hash A stores is exactly what B returned.
//!
//! Compact originals (vault / token):
//! ```text
//! contract Token { circuit deposit(amount: Uint<128>, caller: ContractAddress): Bytes<32>; }
//! export sealed ledger token: Token;      // vault field 0
//! export ledger vaultCallCount: Counter;  // vault field 1
//! export ledger vaultDeposits: Set<Bytes<32>>; // vault field 2
//!
//! depositViaVault(amount): Bytes<32> {
//!   vaultCallCount.increment(1);
//!   const me = kernel.self();
//!   const eventHash = token.deposit(disclose(amount), me);
//!   vaultDeposits.insert(eventHash);
//!   return eventHash;
//! }
//!
//! export ledger depositCount: Counter;    // token field 0
//! export ledger lastAmount: Uint<128>;    // token field 1
//! export ledger emittedDeposits: Set<Bytes<32>>; // token field 2
//! struct DepositEvent { amount: Uint<128>; sequence: Uint<64>; caller: ContractAddress }
//!
//! deposit(amount, caller): Bytes<32> {
//!   sequence = depositCount as Uint<64>; depositCount.increment(1);
//!   lastAmount = amount;
//!   payload = serialize<DepositEvent, 256>({amount, sequence, caller});
//!   eventHash = persistentHash<Bytes<256>>(payload);
//!   emittedDeposits.insert(eventHash);
//!   emit (Misc { name: pad(32, "deposit"), payload });
//!   return eventHash;
//! }
//! ```

use minocrab::v3::Circuit3;
use minocrab::{label, Private, Public};
use minocrab_ledger::{
    cell_write, counter_increment, counter_read, emit, emit_event, set_insert,
    ImpactElem, LedgerValue, XcallCommitment, XcallEntryPointHash, XcallResult,
};
use minocrab_std::v3::kernel;
use minocrab_std::v3::{
    circuit, BytesN, ContractAddress, Disclose, Discloses, Serializer, Uint, B32,
};

use crate::events::{MISC_SIZE, MISC_TAG, MISC_VERSION};
use crate::interfaces::Token;

/// Vault ledger fields, in declaration order.
pub const TOKEN: u8 = 0;
pub const VAULT_CALL_COUNT: u8 = 1;
pub const VAULT_DEPOSITS: u8 = 2;

/// Token ledger fields.
pub const DEPOSIT_COUNT: u8 = 0;
pub const LAST_AMOUNT: u8 = 1;
pub const EMITTED_DEPOSITS: u8 = 2;

/// The token's event: `Misc { name: pad(32, "deposit"), payload }` — the
/// `Misc` shape itself (tag, version, 288 = name(32) ‖ payload(256)) is
/// declared once, in [`crate::events`].
pub const EVENT_NAME: &str = "deposit";
pub const PAYLOAD_SIZE: usize = 256;

label! {
    /// Shared with the Borsh twin, which is the same callee circuit built
    /// through a different serializer.
    pub(crate) Amount = "amount";
    pub(crate) Caller = "caller";
}

fn b32_ledger_value(b: &B32<Public>) -> LedgerValue {
    LedgerValue::bytes(32, vec![ImpactElem::Wire(b.hi), ImpactElem::Wire(b.lo)])
}

/// `export circuit depositViaVault(amount: Uint<128>): Bytes<32>`.
///
/// The corpus's only circuits with a RETURN VALUE, so the only users of
/// `#[circuit(output = ..)]`: the label names the disclosed value, and
/// `CircuitOut for B32<Public>` suffixes the two limbs `(hi)`/`(lo)` — the
/// hand-written labels, unchanged.
#[circuit(output = "event hash")]
pub fn deposit_via_vault(
    c: &mut Circuit3,
    amount: Uint<128>,
) -> Discloses<(Amount, XcallEntryPointHash, XcallCommitment, XcallResult), B32<Public>> {
    let a = amount.disclose_as::<Amount>(c).field();
    let one = c.constant(1u64);

    emit(c, one, &counter_increment(VAULT_CALL_COUNT, 1));
    let me = kernel::self_address(c);
    // eventHash = token.deposit(a, me) — the Bytes<32> return type gives
    // the result limbs' [Bits(8), Bits(248)] constraints, and the sealed
    // `token` cell is read inside the call, as compactc reads it.
    let event_hash: B32<Public> =
        Token::at_field(TOKEN).deposit(c, one, Uint::from_field_unchecked(a), me);
    emit(
        c,
        one,
        &set_insert(VAULT_DEPOSITS, &b32_ledger_value(&event_hash)),
    );
    Discloses::of(event_hash)
}

/// `export circuit deposit(amount: Uint<128>, caller: ContractAddress):
/// Bytes<32>` — the token-side callee (an ordinary circuit; the caller
/// machinery is all vault-side).
#[circuit(output = "event hash")]
pub fn token_deposit(
    c: &mut Circuit3,
    amount: Uint<128>,
    caller: ContractAddress<Private>,
) -> Discloses<(Amount, Caller), B32<Public>> {
    let caller = caller.bytes();
    let a = amount.disclose_as::<Amount>(c).field();
    let cal = caller.disclose_as::<Caller>(c);
    let one = c.constant(1u64);

    // const sequence = depositCount as Uint<64> — read before the increment.
    let sequence = counter_read(c, one, DEPOSIT_COUNT);
    emit(c, one, &counter_increment(DEPOSIT_COUNT, 1));
    let amount_val = LedgerValue::bytes(16, vec![ImpactElem::Wire(a)]);
    emit(c, one, &cell_write(LAST_AMOUNT, &amount_val));

    // payload = serialize<DepositEvent, 256>({amount, sequence, caller}).
    let mut s = Serializer::<Public>::new();
    s.push_uint(a, 16);
    s.push_uint(sequence, 8);
    s.push_b32(&cal);
    let payload = s.finish::<PAYLOAD_SIZE>(c);

    // eventHash = persistentHash<Bytes<256>>(payload).
    let alignment = BytesN::<Public, PAYLOAD_SIZE>::alignment();
    let limbs: Vec<_> = payload.limbs().iter().map(|w| w.erase()).collect();
    let digest = c.persistent_hash(alignment, &limbs);
    let event_hash = B32::from_typed(c, digest);

    emit(
        c,
        one,
        &set_insert(EMITTED_DEPOSITS, &b32_ledger_value(&event_hash)),
    );

    // emit (Misc { name: pad(32, "deposit"), payload }).
    let mut name = [0u8; 32];
    name[..EVENT_NAME.len()].copy_from_slice(EVENT_NAME.as_bytes());
    let mut misc = Serializer::<Public>::new();
    misc.push_literal(c, &name);
    misc.push_bytes_n(&payload);
    let misc = misc.finish::<MISC_SIZE>(c);
    let misc_val = LedgerValue::bytes(
        MISC_SIZE as u32,
        misc.limbs().iter().map(|&w| ImpactElem::Wire(w)).collect(),
    );
    emit(c, one, &emit_event(MISC_VERSION, MISC_TAG, &misc_val));

    Discloses::of(event_hash)
}
