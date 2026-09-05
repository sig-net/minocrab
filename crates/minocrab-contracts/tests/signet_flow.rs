//! `signet_flow::Pending` on a toy contract: the smallest request/settle
//! pair, built through the public API alone.
//!
//! What this file pins: the block layout the derive computes over the
//! multi-field slots, the notification path derived from it, the label sets
//! `request` and `settle` publish (the `#[circuit]` disclosure gate does
//! that one), and that each circuit builds at a finite cost. The
//! round-trip through a simulated MPC is M35 rung D's.

use minocrab::v3::Circuit3;
use minocrab::{Private, Public};
use minocrab_contracts::common::{witness_sk, SecretKey, SigningPath};
use minocrab_contracts::signet::EvmCalldata;
use minocrab_contracts::signet_flow::{
    Commit, EvmTx, FailureResponse, Pending, Requested, Response, Settle, Settled, SignRequest,
    Signet,
};
use minocrab_sim::v3::cost;
use minocrab_std::v3::borsh::CircuitBorsh;
use minocrab_std::v3::{
    circuit, is_true, label, Bool, Disclose, Discloses, Ledger, LedgerCounter, LedgerRepr, Uint,
    B32,
};

// ---- the contract's own types -------------------------------------------------

/// What `claim` needs back: public by construction.
#[derive(LedgerRepr)]
struct DepositEnv {
    amount: Uint<64, Public>,
}

/// A withdrawal's environment: the amount, and a COMMITMENT to the
/// withdrawer's key — the one thing that survives privately.
#[derive(LedgerRepr)]
struct WithdrawEnv {
    amount: Uint<64, Public>,
    withdrawer: Commit<SecretKey<Private>>,
}

const WITHDRAWER_DOMAIN: &str = "toy:withdrawer:";

/// `{ success: bool }`, kind 0.
#[derive(CircuitBorsh)]
struct ClaimResponse {
    success: Bool,
}
impl Response for ClaimResponse {
    const KIND: u8 = 0;
}

/// `{ success: bool }`, kind 1 — the same shape, a different kind.
#[derive(CircuitBorsh)]
struct WithdrawResponse {
    success: Bool,
}
impl Response for WithdrawResponse {
    const KIND: u8 = 1;
}

/// The MPC's "never executed" output, kind 3, shared by every flow.
#[derive(CircuitBorsh)]
struct Failure {
    _unused: Uint<8>,
}
impl Response for Failure {
    const KIND: u8 = 3;
}
impl FailureResponse for Failure {}

/// The ledger block: seven fields from three declarations.
#[derive(Ledger)]
struct Toy {
    initialized: LedgerCounter,
    signet: Signet,
    deposits: Pending<DepositEnv, ClaimResponse>,
    withdrawals: Pending<WithdrawEnv, WithdrawResponse>,
}

const TOY: Toy = Toy::new();

label! {
    Amount = "amount";
    WithdrawerCommitment = "withdrawer commitment";
}

fn evm_tx(c: &mut Circuit3, amount: minocrab::v3::Wire3<minocrab::v3::FieldT, Private>) -> EvmTx<2> {
    let zero = c.constant(0u64).private();
    let one = c.constant(1u64).private();
    let two = c.constant(2u64).private();
    let to = c.constant(0x42u64).private();
    let word = B32 { hi: zero, lo: amount };
    EvmTx {
        nonce: zero,
        max_priority_fee_per_gas: one,
        max_fee_per_gas: two,
        gas_limit: c.constant(100_000u64).private(),
        to,
        value: zero,
        calldata_is_some: one,
        calldata: EvmCalldata {
            selector: c.constant(0xa9059cbbu64).private(),
            no_words: two,
            words: [word, word],
        },
    }
}

// ---- the circuits ------------------------------------------------------------------

#[circuit]
fn deposit(c: &mut Circuit3, key_version: Uint<8>, amount: Uint<64>) -> Discloses<(Amount, Requested)> {
    let amount_pub = amount.field().disclose_as::<Amount>(c);
    let tx = evm_tx(c, amount.field());
    let path = SigningPath(B32 {
        hi: c.constant(7u64).private(),
        lo: c.constant(9u64).private(),
    });
    TOY.deposits.request(c, &TOY.signet, SignRequest { key_version, path, tx }, |_, _| {
        DepositEnv { amount: Uint::from_field_unchecked(amount_pub) }
    });
    Discloses::of(())
}

#[circuit]
fn withdraw(
    c: &mut Circuit3,
    key_version: Uint<8>,
    amount: Uint<64>,
) -> Discloses<(Amount, WithdrawerCommitment, Requested)> {
    let amount_pub = amount.field().disclose_as::<Amount>(c);
    let tx = evm_tx(c, amount.field());
    let path = SigningPath::vault_path(c).private();
    let sk = witness_sk(c);
    TOY.withdrawals.request(c, &TOY.signet, SignRequest { key_version, path, tx }, |c, id| {
        WithdrawEnv {
            amount: Uint::from_field_unchecked(amount_pub),
            withdrawer: Commit::to::<WithdrawerCommitment>(c, WITHDRAWER_DOMAIN, &sk, id),
        }
    });
    Discloses::of(())
}

#[circuit]
fn claim(c: &mut Circuit3, ticket: Settle<DepositEnv, ClaimResponse>) -> Discloses<Settled> {
    let outcome = TOY.deposits.settle(c, &TOY.signet, ticket);
    c.assert(is_true(outcome.output.success).message("The MPC attested a failure"));
    let _amount = outcome.env.amount;
    Discloses::of(())
}

#[circuit]
fn refund_withdrawal(c: &mut Circuit3, ticket: Settle<WithdrawEnv, Failure>) -> Discloses<Settled> {
    let outcome = TOY.withdrawals.settle_failed(c, &TOY.signet, ticket);
    // The withdrawer gate: a FRESH witness against the stored commitment.
    let sk = witness_sk(c);
    outcome
        .env
        .withdrawer
        .open(c, WITHDRAWER_DOMAIN, &sk, outcome.request_id, "Not the withdrawer");
    let _amount = outcome.env.amount;
    Discloses::of(())
}

// ---- the tests ----------------------------------------------------------------------

/// `initialized` is field 0, `signet` fields 1..6, `deposits` 6 and 7,
/// `withdrawals` 8 and 9 — a block of ten, so still one-element paths.
#[test]
fn the_block_is_laid_out_by_slot_width() {
    assert_eq!(TOY.initialized.index(), 0);
    assert_eq!(TOY.signet.signer.index(), 1);
    assert_eq!(TOY.signet.evm_chain_id.index(), 5);
    assert_eq!(TOY.deposits.record_path().as_slice(), &[6]);
    assert_eq!(TOY.withdrawals.record_path().as_slice(), &[8]);
    assert_eq!(TOY.withdrawals.record_path().depth(), 1);
}

/// Each circuit builds, and at a cost a settle's secp256k1 verification
/// dominates (the vault's settle circuits sit at k = 13-14).
#[test]
fn the_circuits_build_at_a_finite_cost() {
    let (k_req, rows_req) = cost(&deposit().ir);
    let (k_wd, _) = cost(&withdraw().ir);
    let (k_claim, rows_claim) = cost(&claim().ir);
    let (k_ref, _) = cost(&refund_withdrawal().ir);
    assert!(rows_req > 0 && rows_claim > rows_req, "{rows_req} {rows_claim}");
    assert!(k_req <= 14 && k_wd <= 14 && k_claim <= 15 && k_ref <= 15, "{k_req} {k_wd} {k_claim} {k_ref}");
}

// ---- the record the circuit files vs the reader the MPC runs ----------------------

/// THE DRIFT GATE: the atoms `SignBidirectionalEventV2` declares (what a
/// `Pending` slot stores, limb for limb) are decoded by the MPC reader's
/// stage-7 twin (`signet_sim::reader`, translated from the MPC's own code)
/// into the same fields, and the id the reader recomputes — Poseidon over
/// the cell's field representation — is over exactly the limbs the circuit
/// hashes: the cell's field repr equals the record's limb values in slot
/// order.
#[test]
fn the_filed_record_is_what_the_mpc_reader_decodes() {
    use midnight_base_crypto::fab::{AlignedValue, Alignment, AlignmentSegment, Value, ValueAtom};
    use midnight_onchain_state::state::StateValue;
    use midnight_storage::arena::Sp;
    use minocrab_contracts::signet::SignBidirectionalEventV2;
    use signet_sim::records::{CompactMaybe, EvmCalldata, EvmType2TxParams, SignBidirectionalRecordV2, RECORD_FORMAT_VERSION};
    use signet_sim::reader::decode_record_v2;
    use signet_sim::request_id::binary_repr_v2;

    let record = SignBidirectionalRecordV2 {
        format_version: RECORD_FORMAT_VERSION,
        sender: [0xe4; 32],
        request_nonce: 9,
        key_version: 1,
        path: [0x77; 32],
        algo: 0,
        dest: 0,
        params: [0u8; 64],
        tx_param_type: 0,
        tx_params: EvmType2TxParams {
            chain_id: 1,
            nonce: 2,
            max_priority_fee_per_gas: 3,
            max_fee_per_gas: 4,
            gas_limit: 5,
            to: [0x42; 20],
            value: 0,
            calldata: CompactMaybe {
                is_some: true,
                value: EvmCalldata { selector: [0xa9, 0x05, 0x9c, 0xbb], no_words: 2, words: vec![[6u8; 32], [7u8; 32]] },
            },
            access_list_entry_count: 0,
            access_list: vec![],
        },
        caip2_id: [0x33; 32],
        response_kind: 0,
    };

    // The cell as the ledger holds it: the CIRCUIT's declared atoms, filled
    // from the reader's own byte layout, trailing zeros trimmed.
    let atoms = SignBidirectionalEventV2::<Public, 2>::atoms();
    let bytes = binary_repr_v2(&record);
    let mut at = 0usize;
    let mut alignment = Vec::new();
    let mut value = Vec::new();
    for atom in &atoms {
        let midnight_base_crypto::fab::AlignmentAtom::Bytes { length } = atom else {
            panic!("signet records declare Bytes atoms only")
        };
        let width = *length as usize;
        let mut v = bytes[at..at + width].to_vec();
        while v.last() == Some(&0) {
            v.pop();
        }
        alignment.push(AlignmentSegment::Atom(*atom));
        value.push(ValueAtom(v));
        at += width;
    }
    assert_eq!(at, bytes.len(), "the declared atoms cover exactly the reader's preimage");
    let cell = StateValue::Cell(Sp::new(AlignedValue { alignment: Alignment(alignment), value: Value(value) }));

    let decoded = decode_record_v2(&cell).expect("the MPC reader decodes what the circuit files");
    assert_eq!(decoded, record);

    // The MPC hashes the cell's FIELD representation; the circuit hashes the
    // record's limbs in slot order. They must be the same field elements —
    // here reconstructed from the bytes exactly as `SignBidirectionalEventV2`
    // carries them (a `bytes<n>` atom: the leftover most-significant limb
    // first, then 31-byte limbs — which for every atom of this record is
    // one limb, or `[hi, lo]` for a `Bytes<32>`).
    use midnight_transient_crypto::fab::AlignedValueExt as _;
    let StateValue::Cell(aligned) = &cell else { unreachable!() };
    let mut fields = Vec::new();
    aligned.value_only_field_repr(&mut fields);
    let mut ours = Vec::new();
    let mut at = 0usize;
    for atom in &atoms {
        let midnight_base_crypto::fab::AlignmentAtom::Bytes { length } = atom else { unreachable!() };
        let width = *length as usize;
        let chunk = &bytes[at..at + width];
        // FAB limbs of a `bytes<n>`: the leftover (n mod 31) MOST-significant
        // bytes first, then 31-byte limbs from the top down — `[hi, lo]` for
        // a `Bytes<32>`, three limbs for the 64-byte `params`.
        let r = width % 31;
        let mut end = width;
        if r != 0 {
            ours.push(minocrab::Fr::from_le_bytes(&chunk[end - r..end]).unwrap());
            end -= r;
        }
        while end > 0 {
            ours.push(minocrab::Fr::from_le_bytes(&chunk[end - 31..end]).unwrap());
            end -= 31;
        }
        at += width;
    }
    assert_eq!(fields, ours, "the MPC's field preimage is the circuit's limb list");
    assert_eq!(
        signet_sim::hashing::compute_request_id(aligned),
        midnight_transient_crypto::hash::upgrade_from_transient(midnight_transient_crypto::hash::transient_hash(&ours)).0
    );
}
