//! manager (aa-midnight-evm-experiment): call-compatibility with the corpus
//! artifacts per notes/ledger-abi.org §6 — the account-abstraction custody
//! contract running on MinoCrab, plus acceptance agreement on guard
//! failures.
//!
//! Same criterion as the vault suite: same typed I/O schema + equal
//! `pis`/`pi_skips` on a shared `ProofPreimage`, with the preimage built by
//! a reference model of the vm-code's op stream (the compiled
//! `contract/index.js`, read function by function) — instruction streams
//! free to differ, which they deliberately do (the port uses the keccak
//! chip's in-chip packing where compactc splices bytes).

use std::borrow::Cow;

use midnight_base_crypto::fab::{
    AlignedValue, Alignment, AlignmentSegment, Value, ValueAtom,
};
use midnight_base_crypto::repr::BinaryHashRepr;
use midnight_onchain_state::state::StateValue;
use midnight_onchain_vm::ops::{Key, Op};
use midnight_transient_crypto::fab::{AlignmentExt, ValueReprAlignedValue};
use midnight_transient_crypto::hash::transient_commit;
use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage};
use midnight_transient_crypto::repr::FieldRepr;
use minocrab::Fr;
use minocrab_contracts::manager;
use minocrab_sim::v3::{assert_call_compatible, simulate};
use minocrab_zkir::v3::IrSource;
use sha2::{Digest, Sha256};

mod support;
mod vault;

use vault::prims::{atom, b32_slots, bytesn_value, cell, VmOp};

fn corpus_zkir(name: &str) -> IrSource {
    let path = format!(
        "{}/../../corpus/zkir/aa-midnight-evm-experiment/contracts/manager/zkir/{name}.zkir",
        env!("CARGO_MANIFEST_DIR")
    );
    minocrab_zkir::v3::read_zkir(&path).expect("corpus golden parses")
}

/// Both artifacts must REJECT the preimage.
fn assert_both_reject(ours: &IrSource, theirs: &IrSource, pi: &ProofPreimage, what: &str) {
    assert!(simulate(ours, pi).is_err(), "ours accepts: {what}");
    assert!(simulate(theirs, pi).is_err(), "corpus accepts: {what}");
}

// --- off-circuit primitives --------------------------------------------------

fn pad32(s: &str) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[..s.len()].copy_from_slice(s.as_bytes());
    b
}

/// SHA-256 over the FAB binary of `limbs` laid out per `segments`.
fn fab_sha256(segments: Vec<AlignmentSegment>, limbs: &[Fr]) -> [u8; 32] {
    let value = Alignment(segments)
        .parse_field_repr(limbs)
        .expect("limbs match the alignment");
    let mut repr = Vec::new();
    ValueReprAlignedValue(value).binary_repr(&mut repr);
    Sha256::digest(&repr).into()
}

/// `shieldedKey` / `unshieldedKey` off-circuit.
fn family_key(acct: &[u8; 32], colour: &[u8; 32], tag: &str) -> [u8; 32] {
    let (a_hi, a_lo) = b32_slots(acct);
    let (c_hi, c_lo) = b32_slots(colour);
    let (t_hi, t_lo) = b32_slots(&pad32(tag));
    fab_sha256(
        vec![atom(32), atom(32), atom(32)],
        &[a_hi, a_lo, c_hi, c_lo, t_hi, t_lo],
    )
}

fn shielded_key(acct: &[u8; 32], colour: &[u8; 32]) -> [u8; 32] {
    family_key(acct, colour, manager::SHIELDED_FAMILY_TAG)
}

fn unshielded_key(acct: &[u8; 32], colour: &[u8; 32]) -> [u8; 32] {
    family_key(acct, colour, manager::UNSHIELDED_FAMILY_TAG)
}

/// `ownerCommitment(sk)` — `persistentCommit<Bytes<21>>(tag, sk)`: SHA-256
/// over `[sk (32 bytes), tag (21 bytes)]`.
fn owner_commitment(sk: &[u8; 32]) -> [u8; 32] {
    let (sk_hi, sk_lo) = b32_slots(sk);
    let tag = Fr::from_le_bytes(manager::OWNER_TAG).unwrap();
    fab_sha256(vec![atom(32), atom(21)], &[sk_hi, sk_lo, tag])
}

// --- op-stream builders ------------------------------------------------------

fn field_key(i: u8) -> Key {
    Key::Value(bytesn_value(1, &[i]))
}

/// `Cell.read` on a top-level field: `dup 0; idx [field]; popeq`.
fn cell_read(field: u8, cached: bool, result: AlignedValue) -> Vec<VmOp> {
    vec![
        Op::Dup { n: 0 },
        Op::Idx {
            cached: false,
            push_path: false,
            path: vec![field_key(field)].into(),
        },
        Op::Popeq { cached, result },
    ]
}

/// `kernel.self()`: `dup 2; idx cached [0]; popeqc`.
fn kernel_self(result: &[u8; 32]) -> Vec<VmOp> {
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
}

/// `map.member(key)` / `set.member(elem)`: `dup 0; idx [field]; push key;
/// member; popeqc`.
fn member(field: u8, key: AlignedValue, holds: bool) -> Vec<VmOp> {
    vec![
        Op::Dup { n: 0 },
        Op::Idx {
            cached: false,
            push_path: false,
            path: vec![field_key(field)].into(),
        },
        Op::Push {
            storage: false,
            value: cell(key),
        },
        Op::Member,
        Op::Popeq {
            cached: true,
            result: bytesn_value(1, &[u8::from(holds)]),
        },
    ]
}

/// `map.lookup(key)`: `dup 0; idx [field]; idx {key}; popeq`.
fn lookup(field: u8, key: AlignedValue, result: AlignedValue) -> Vec<VmOp> {
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
            path: vec![Key::Value(key)].into(),
        },
        Op::Popeq {
            cached: false,
            result,
        },
    ]
}

/// `map.insert(key, value)`: `idx pushPath [field]; push key; push value;
/// ins; insc`.
fn insert(field: u8, key: AlignedValue, value: AlignedValue) -> Vec<VmOp> {
    vec![
        Op::Idx {
            cached: false,
            push_path: true,
            path: vec![field_key(field)].into(),
        },
        Op::Push {
            storage: false,
            value: cell(key),
        },
        Op::Push {
            storage: true,
            value: cell(value),
        },
        Op::Ins {
            cached: false,
            n: 1,
        },
        Op::Ins { cached: true, n: 1 },
    ]
}

/// `set.insert(elem)`: the value slot is Null.
fn set_insert(field: u8, elem: AlignedValue) -> Vec<VmOp> {
    vec![
        Op::Idx {
            cached: false,
            push_path: true,
            path: vec![field_key(field)].into(),
        },
        Op::Push {
            storage: false,
            value: cell(elem),
        },
        Op::Push {
            storage: true,
            value: StateValue::Null,
        },
        Op::Ins {
            cached: false,
            n: 1,
        },
        Op::Ins { cached: true, n: 1 },
    ]
}

/// `map.remove(key)`: `idx pushPath [field]; push key; rem; insc`.
fn remove(field: u8, key: AlignedValue) -> Vec<VmOp> {
    vec![
        Op::Idx {
            cached: false,
            push_path: true,
            path: vec![field_key(field)].into(),
        },
        Op::Push {
            storage: false,
            value: cell(key),
        },
        Op::Rem { cached: false },
        Op::Ins { cached: true, n: 1 },
    ]
}

/// A kernel effects claim (`claimZswapNullifier` slot 0, `…CoinReceive`
/// slot 1, `…CoinSpend` slot 2): `swap; idx cached pushPath [slot];
/// push value; push null; insc 2; swap`.
fn kernel_claim(slot: u8, value: &[u8; 32]) -> Vec<VmOp> {
    vec![
        Op::Swap { n: 0 },
        Op::Idx {
            cached: true,
            push_path: true,
            path: vec![field_key(slot)].into(),
        },
        Op::Push {
            storage: false,
            value: cell(bytesn_value(32, value)),
        },
        Op::Push {
            storage: false,
            value: StateValue::Null,
        },
        Op::Ins { cached: true, n: 2 },
        Op::Swap { n: 0 },
    ]
}

/// `receiveShielded(coin)` — a kernel.self read, then the receive claim of
/// `coinCommitment(coin, right(self))`.
fn receive_shielded(self_addr: &[u8; 32], cm: &[u8; 32]) -> Vec<VmOp> {
    let mut ops = kernel_self(self_addr);
    ops.extend(kernel_claim(1, cm));
    ops
}

/// The coin value a `Map<_, QualifiedShieldedCoinInfo>` lookup pops:
/// `[nonce b32, color b32, value b16, mt_index b8]`.
fn qualified_coin_av(nonce: &[u8; 32], color: &[u8; 32], value: u128, mt_index: u64) -> AlignedValue {
    AlignedValue::new(
        Value(vec![
            ValueAtom(nonce.to_vec()).normalize(),
            ValueAtom(color.to_vec()).normalize(),
            ValueAtom(value.to_le_bytes().to_vec()).normalize(),
            ValueAtom(mt_index.to_le_bytes().to_vec()).normalize(),
        ]),
        Alignment(vec![atom(32), atom(32), atom(16), atom(8)]),
    )
    .unwrap()
}

/// An UNQUALIFIED coin as the runtime pushes it into `insertCoin`:
/// `[nonce b32, color b32, value b16]`.
fn coin_av(nonce: &[u8; 32], color: &[u8; 32], value: u128) -> AlignedValue {
    AlignedValue::new(
        Value(vec![
            ValueAtom(nonce.to_vec()).normalize(),
            ValueAtom(color.to_vec()).normalize(),
            ValueAtom(value.to_le_bytes().to_vec()).normalize(),
        ]),
        Alignment(vec![atom(32), atom(32), atom(16)]),
    )
    .unwrap()
}

/// `pools.insertCoin(col, coin, right(self))` — the qualify dance: the map
/// path, the key, the runtime coin commitment resolved on chain, the coin
/// spliced behind its resolved index.
fn insert_coin(field: u8, col: &[u8; 32], coin: AlignedValue, cm: &[u8; 32]) -> Vec<VmOp> {
    vec![
        Op::Idx {
            cached: false,
            push_path: true,
            path: vec![field_key(field)].into(),
        },
        Op::Push {
            storage: false,
            value: cell(bytesn_value(32, col)),
        },
        Op::Dup { n: 5 },
        Op::Push {
            storage: false,
            value: cell(bytesn_value(32, cm)),
        },
        Op::Idx {
            cached: true,
            push_path: false,
            path: vec![field_key(1), Key::Stack].into(),
        },
        Op::Push {
            storage: false,
            value: cell(coin),
        },
        Op::Swap { n: 0 },
        Op::Concat {
            cached: true,
            n: 91,
        },
        Op::Ins {
            cached: false,
            n: 1,
        },
        Op::Ins { cached: true, n: 1 },
    ]
}

/// `Either<Bytes<32>, Bytes<32>>` as the unshielded-token value the kernel
/// effect ops carry: `left(color)`.
fn left_color_av(color: &[u8; 32]) -> AlignedValue {
    AlignedValue::new(
        Value(vec![
            ValueAtom(vec![1]).normalize(),
            ValueAtom(color.to_vec()).normalize(),
            ValueAtom(vec![]).normalize(),
        ]),
        Alignment(vec![atom(1), atom(32), atom(32)]),
    )
    .unwrap()
}

/// The kernel effects accumulator `incUnshieldedInputs` (slot 6) /
/// `incUnshieldedOutputs` (slot 7): merge `amount` into the map at
/// `left(color)`.
fn inc_unshielded(slot: u8, color: &[u8; 32], amount: u128) -> Vec<VmOp> {
    vec![
        Op::Swap { n: 0 },
        Op::Idx {
            cached: true,
            push_path: true,
            path: vec![field_key(slot)].into(),
        },
        Op::Push {
            storage: false,
            value: cell(left_color_av(color)),
        },
        Op::Dup { n: 1 },
        Op::Dup { n: 1 },
        Op::Member,
        Op::Push {
            storage: false,
            value: cell(bytesn_value(16, &amount.to_le_bytes())),
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
    ]
}

/// Assemble a preimage from args, witnesses, ops and popeq outputs, for a
/// circuit returning nothing.
fn preimage(inputs: Vec<Fr>, witnesses: Vec<Fr>, ops: &[VmOp], outputs: Vec<AlignedValue>) -> ProofPreimage {
    preimage_returning(inputs, witnesses, ops, outputs, vec![])
}

/// [`preimage`] for a circuit RETURNING values: the communications
/// commitment covers the inputs followed by the encoded outputs
/// (ir_vm.rs:662-681).
fn preimage_returning(
    inputs: Vec<Fr>,
    witnesses: Vec<Fr>,
    ops: &[VmOp],
    outputs: Vec<AlignedValue>,
    returns: Vec<Fr>,
) -> ProofPreimage {
    let mut transcript = Vec::new();
    for op in ops {
        op.field_repr(&mut transcript);
    }
    let mut out = Vec::new();
    for av in outputs {
        ValueReprAlignedValue(av).field_repr(&mut out);
    }
    let rand = Fr::from(0xaa17u64);
    let mut committed = inputs.clone();
    committed.extend(returns.iter());
    let comm = transient_commit(&committed[..], rand);
    ProofPreimage {
        inputs,
        private_transcript: witnesses,
        public_transcript_inputs: transcript,
        public_transcript_outputs: out,
        binding_input: 0.into(),
        communications_commitment: Some((comm, rand)),
        key_location: KeyLocation(Cow::Borrowed("minocrab-contracts-test")),
    }
}

fn b32_inputs(v: &[u8; 32]) -> Vec<Fr> {
    let (hi, lo) = b32_slots(v);
    vec![hi, lo]
}

// --- fixture values ----------------------------------------------------------

fn acct1() -> [u8; 32] {
    let mut a = [0u8; 32];
    a[..7].copy_from_slice(b"account");
    a[31] = 0x21;
    a
}

fn acct2() -> [u8; 32] {
    let mut a = [0u8; 32];
    a[..8].copy_from_slice(b"account2");
    a[31] = 0x22;
    a
}

fn colour1() -> [u8; 32] {
    let mut c = [0u8; 32];
    c[..6].copy_from_slice(b"colour");
    c[31] = 0x31;
    c
}

fn self_addr() -> [u8; 32] {
    let mut s = [0u8; 32];
    s[..12].copy_from_slice(b"manager-self");
    s[31] = 0x41;
    s
}

// --- readers -----------------------------------------------------------------

#[test]
fn is_registered_matches_corpus() {
    let theirs = corpus_zkir("isRegistered");
    let ours = manager::is_registered().ir;
    for holds in [false, true] {
        let ops = member(manager::ACCOUNTS, bytesn_value(32, &acct1()), holds);
        let pi = preimage_returning(
            b32_inputs(&acct1()),
            vec![],
            &ops,
            vec![bytesn_value(1, &[u8::from(holds)])],
            vec![Fr::from(u64::from(holds))],
        );
        assert_call_compatible(&ours, &theirs, &pi);
    }
}

#[test]
fn pool_has_colour_matches_corpus() {
    let theirs = corpus_zkir("poolHasColour");
    let ours = manager::pool_has_colour().ir;
    for holds in [false, true] {
        let ops = member(manager::POOLS, bytesn_value(32, &colour1()), holds);
        let pi = preimage_returning(
            b32_inputs(&colour1()),
            vec![],
            &ops,
            vec![bytesn_value(1, &[u8::from(holds)])],
            vec![Fr::from(u64::from(holds))],
        );
        assert_call_compatible(&ours, &theirs, &pi);
    }
}

#[test]
fn pool_value_matches_corpus() {
    let theirs = corpus_zkir("poolValue");
    let ours = manager::pool_value().ir;

    // Colour absent: the guarded lookup is skipped, the value reads 0.
    let ops = member(manager::POOLS, bytesn_value(32, &colour1()), false);
    let pi = preimage_returning(
        b32_inputs(&colour1()),
        vec![],
        &ops,
        vec![bytesn_value(1, &[0])],
        vec![Fr::from(0u64)],
    );
    assert_call_compatible(&ours, &theirs, &pi);

    // Colour pooled: member then the lookup of the whole qualified coin.
    let nonce = pad32("pool-coin-nonce");
    let coin = qualified_coin_av(&nonce, &colour1(), 5_000, 7);
    let mut ops = member(manager::POOLS, bytesn_value(32, &colour1()), true);
    ops.extend(lookup(
        manager::POOLS,
        bytesn_value(32, &colour1()),
        coin.clone(),
    ));
    let pi = preimage_returning(
        b32_inputs(&colour1()),
        vec![],
        &ops,
        vec![bytesn_value(1, &[1]), coin],
        vec![Fr::from(5_000u64)],
    );
    assert_call_compatible(&ours, &theirs, &pi);
}

#[test]
fn shielded_account_balance_matches_corpus() {
    let theirs = corpus_zkir("shieldedAccountBalance");
    let ours = manager::shielded_account_balance().ir;
    let key = shielded_key(&acct1(), &colour1());

    // Cell absent — reads 0.
    let ops = member(manager::SHIELDED_BALANCES, bytesn_value(32, &key), false);
    let mut inputs = b32_inputs(&acct1());
    inputs.extend(b32_inputs(&colour1()));
    let pi = preimage_returning(
        inputs.clone(),
        vec![],
        &ops,
        vec![bytesn_value(1, &[0])],
        vec![Fr::from(0u64)],
    );
    assert_call_compatible(&ours, &theirs, &pi);

    // Cell present.
    let balance = 123_456u128;
    let mut ops = member(manager::SHIELDED_BALANCES, bytesn_value(32, &key), true);
    ops.extend(lookup(
        manager::SHIELDED_BALANCES,
        bytesn_value(32, &key),
        bytesn_value(16, &balance.to_le_bytes()),
    ));
    let pi = preimage_returning(
        inputs,
        vec![],
        &ops,
        vec![
            bytesn_value(1, &[1]),
            bytesn_value(16, &balance.to_le_bytes()),
        ],
        vec![Fr::from_le_bytes(&balance.to_le_bytes()).unwrap()],
    );
    assert_call_compatible(&ours, &theirs, &pi);
}

#[test]
fn unshielded_account_balance_matches_corpus() {
    let theirs = corpus_zkir("unshieldedAccountBalance");
    let ours = manager::unshielded_account_balance().ir;
    let key = unshielded_key(&acct1(), &colour1());
    let balance = 99u128;
    let mut ops = member(manager::UNSHIELDED_BALANCES, bytesn_value(32, &key), true);
    ops.extend(lookup(
        manager::UNSHIELDED_BALANCES,
        bytesn_value(32, &key),
        bytesn_value(16, &balance.to_le_bytes()),
    ));
    let mut inputs = b32_inputs(&acct1());
    inputs.extend(b32_inputs(&colour1()));
    let pi = preimage_returning(
        inputs,
        vec![],
        &ops,
        vec![
            bytesn_value(1, &[1]),
            bytesn_value(16, &balance.to_le_bytes()),
        ],
        vec![Fr::from_le_bytes(&balance.to_le_bytes()).unwrap()],
    );
    assert_call_compatible(&ours, &theirs, &pi);
}

#[test]
fn account_record_matches_corpus() {
    let theirs = corpus_zkir("accountRecord");
    let ours = manager::account_record().ir;
    let acct = bytesn_value(32, &acct1());

    // Unregistered: one member read, the zero record.
    let ops = member(manager::ACCOUNTS, acct.clone(), false);
    let pi = preimage_returning(
        b32_inputs(&acct1()),
        vec![],
        &ops,
        vec![bytesn_value(1, &[0])],
        vec![Fr::from(0u64); 4],
    );
    assert_call_compatible(&ours, &theirs, &pi);

    // Native: member, mode lookup (0), the two absent-EVM-state members.
    let mut ops = member(manager::ACCOUNTS, acct.clone(), true);
    ops.extend(lookup(
        manager::ACCOUNT_MODES,
        acct.clone(),
        bytesn_value(1, &[0]),
    ));
    ops.extend(member(manager::EVM_OWNERS, acct.clone(), false));
    ops.extend(member(manager::EVM_NONCES, acct.clone(), false));
    let pi = preimage_returning(
        b32_inputs(&acct1()),
        vec![],
        &ops,
        vec![
            bytesn_value(1, &[1]),
            bytesn_value(1, &[0]),
            bytesn_value(1, &[0]),
            bytesn_value(1, &[0]),
        ],
        vec![Fr::from(1u64), Fr::from(0u64), Fr::from(0u64), Fr::from(0u64)],
    );
    assert_call_compatible(&ours, &theirs, &pi);

    // EVM: member, mode lookup (1), both members, both lookups.
    let owner = *b"evm-owner-20-bytes!!";
    let next_nonce = 42u64;
    let mut ops = member(manager::ACCOUNTS, acct.clone(), true);
    ops.extend(lookup(
        manager::ACCOUNT_MODES,
        acct.clone(),
        bytesn_value(1, &[1]),
    ));
    ops.extend(member(manager::EVM_OWNERS, acct.clone(), true));
    ops.extend(member(manager::EVM_NONCES, acct.clone(), true));
    ops.extend(lookup(
        manager::EVM_OWNERS,
        acct.clone(),
        bytesn_value(20, &owner),
    ));
    ops.extend(lookup(
        manager::EVM_NONCES,
        acct.clone(),
        bytesn_value(8, &next_nonce.to_le_bytes()),
    ));
    let pi = preimage_returning(
        b32_inputs(&acct1()),
        vec![],
        &ops,
        vec![
            bytesn_value(1, &[1]),
            bytesn_value(1, &[1]),
            bytesn_value(1, &[1]),
            bytesn_value(1, &[1]),
            bytesn_value(20, &owner),
            bytesn_value(8, &next_nonce.to_le_bytes()),
        ],
        vec![
            Fr::from(1u64),
            Fr::from(1u64),
            Fr::from_le_bytes(&owner).unwrap(),
            Fr::from(next_nonce),
        ],
    );
    assert_call_compatible(&ours, &theirs, &pi);
}

// --- deposits ----------------------------------------------------------------

#[test]
fn deposit_unshielded_matches_corpus() {
    let theirs = corpus_zkir("depositUnshielded");
    let ours = manager::deposit_unshielded().ir;

    let amount = 777u128;
    let prior = 1_000u128;
    let key = unshielded_key(&acct1(), &colour1());

    for existing in [false, true] {
        let mut ops = member(manager::ACCOUNTS, bytesn_value(32, &acct1()), true);
        ops.extend(inc_unshielded(6, &colour1(), amount));
        ops.extend(member(
            manager::UNSHIELDED_BALANCES,
            bytesn_value(32, &key),
            existing,
        ));
        let base = if existing { prior } else { 0 };
        if existing {
            ops.extend(lookup(
                manager::UNSHIELDED_BALANCES,
                bytesn_value(32, &key),
                bytesn_value(16, &prior.to_le_bytes()),
            ));
        }
        ops.extend(insert(
            manager::UNSHIELDED_BALANCES,
            bytesn_value(32, &key),
            bytesn_value(16, &(base + amount).to_le_bytes()),
        ));

        let mut outputs = vec![bytesn_value(1, &[1]), bytesn_value(1, &[u8::from(existing)])];
        if existing {
            outputs.push(bytesn_value(16, &prior.to_le_bytes()));
        }

        let mut inputs = b32_inputs(&colour1());
        inputs.push(Fr::from_le_bytes(&amount.to_le_bytes()).unwrap());
        inputs.extend(b32_inputs(&acct1()));
        let pi = preimage(inputs, vec![], &ops, outputs);
        assert_call_compatible(&ours, &theirs, &pi);
    }
}

#[test]
fn deposit_unshielded_rejects_guard_failures() {
    let theirs = corpus_zkir("depositUnshielded");
    let ours = manager::deposit_unshielded().ir;
    let key = unshielded_key(&acct1(), &colour1());
    let amount = 777u128;

    // Zero amount.
    let mut ops = member(manager::ACCOUNTS, bytesn_value(32, &acct1()), true);
    ops.extend(inc_unshielded(6, &colour1(), 0));
    ops.extend(member(
        manager::UNSHIELDED_BALANCES,
        bytesn_value(32, &key),
        false,
    ));
    ops.extend(insert(
        manager::UNSHIELDED_BALANCES,
        bytesn_value(32, &key),
        bytesn_value(16, &0u128.to_le_bytes()),
    ));
    let mut inputs = b32_inputs(&colour1());
    inputs.push(Fr::from(0u64));
    inputs.extend(b32_inputs(&acct1()));
    let pi = preimage(
        inputs,
        vec![],
        &ops,
        vec![bytesn_value(1, &[1]), bytesn_value(1, &[0])],
    );
    assert_both_reject(&ours, &theirs, &pi, "zero amount");

    // Unregistered credit account.
    let mut ops = member(manager::ACCOUNTS, bytesn_value(32, &acct1()), false);
    ops.extend(inc_unshielded(6, &colour1(), amount));
    ops.extend(member(
        manager::UNSHIELDED_BALANCES,
        bytesn_value(32, &key),
        false,
    ));
    ops.extend(insert(
        manager::UNSHIELDED_BALANCES,
        bytesn_value(32, &key),
        bytesn_value(16, &amount.to_le_bytes()),
    ));
    let mut inputs = b32_inputs(&colour1());
    inputs.push(Fr::from_le_bytes(&amount.to_le_bytes()).unwrap());
    inputs.extend(b32_inputs(&acct1()));
    let pi = preimage(
        inputs,
        vec![],
        &ops,
        vec![bytesn_value(1, &[0]), bytesn_value(1, &[0])],
    );
    assert_both_reject(&ours, &theirs, &pi, "unregistered account");
}

#[test]
fn deposit_shielded_matches_corpus() {
    use vault::prims::coin_commitment_of;

    let theirs = corpus_zkir("depositShielded");
    let ours = manager::deposit_shielded().ir;

    let coin_nonce = pad32("deposit-coin-nonce");
    let value = 4_000u128;
    let me = self_addr();
    let key = shielded_key(&acct1(), &colour1());
    let nonce_slots = b32_slots(&coin_nonce);
    // The value the receive claim commits to.
    // NOTE: coin_commitment_of takes a u64 value; deposit values here stay
    // under 2^64 so the shared helper applies.
    let cm = coin_commitment_of(&nonce_slots, &colour1(), value as u64, false, &me);

    // FIRST CREDIT of this colour: pools.member false, insertCoin of the
    // deposited coin itself.
    let mut ops = member(manager::ACCOUNTS, bytesn_value(32, &acct1()), true);
    ops.extend(receive_shielded(&me, &cm));
    ops.extend(member(manager::POOLS, bytesn_value(32, &colour1()), false));
    ops.extend(kernel_self(&me));
    ops.extend(insert_coin(
        manager::POOLS,
        &colour1(),
        coin_av(&coin_nonce, &colour1(), value),
        &cm,
    ));
    ops.extend(member(
        manager::SHIELDED_BALANCES,
        bytesn_value(32, &key),
        false,
    ));
    ops.extend(insert(
        manager::SHIELDED_BALANCES,
        bytesn_value(32, &key),
        bytesn_value(16, &value.to_le_bytes()),
    ));

    let mut inputs = b32_inputs(&coin_nonce);
    inputs.extend(b32_inputs(&colour1()));
    inputs.push(Fr::from_le_bytes(&value.to_le_bytes()).unwrap());
    inputs.extend(b32_inputs(&acct1()));
    let pi = preimage(
        inputs,
        vec![],
        &ops,
        vec![
            bytesn_value(1, &[1]),
            bytesn_value(32, &me),
            bytesn_value(1, &[0]),
            bytesn_value(32, &me),
            bytesn_value(1, &[0]),
        ],
    );
    support::dump_preimage("manager_depositShielded", &pi);
    assert_call_compatible(&ours, &theirs, &pi);
}

#[test]
fn deposit_shielded_merge_matches_corpus() {
    use vault::prims::{coin_commitment_of, coin_nullifier_of, evolved_nonce};

    let theirs = corpus_zkir("depositShielded");
    let ours = manager::deposit_shielded().ir;

    let coin_nonce = pad32("deposit-coin-nonce-2");
    let pooled_nonce = pad32("pooled-coin-nonce");
    let value = 2_500u128;
    let pooled_value = 6_000u128;
    let mt_index = 3u64;
    let me = self_addr();
    let key = shielded_key(&acct1(), &colour1());

    let deposit_cm =
        coin_commitment_of(&b32_slots(&coin_nonce), &colour1(), value as u64, false, &me);

    // mergeCoinImmediate(pooled, coin): self read, both nullifiers, the
    // merged coin's spend+receive claims.
    let nul_pooled = coin_nullifier_of(
        &b32_slots(&pooled_nonce),
        &colour1(),
        pooled_value as u64,
        &me,
    );
    let nul_coin = coin_nullifier_of(&b32_slots(&coin_nonce), &colour1(), value as u64, &me);
    let merged_nonce = evolved_nonce(&pooled_nonce);
    let merged_value = pooled_value + value;
    let merged_cm = coin_commitment_of(&merged_nonce, &colour1(), merged_value as u64, false, &me);

    let mut ops = member(manager::ACCOUNTS, bytesn_value(32, &acct1()), true);
    ops.extend(receive_shielded(&me, &deposit_cm));
    ops.extend(member(manager::POOLS, bytesn_value(32, &colour1()), true));
    // pools.lookup(c.color) — the mergeCoinImmediate argument.
    ops.extend(lookup(
        manager::POOLS,
        bytesn_value(32, &colour1()),
        qualified_coin_av(&pooled_nonce, &colour1(), pooled_value, mt_index),
    ));
    // merge internals.
    ops.extend(kernel_self(&me));
    ops.extend(kernel_claim(0, &nul_pooled));
    ops.extend(kernel_claim(0, &nul_coin));
    ops.extend(kernel_claim(2, &merged_cm));
    ops.extend(kernel_claim(1, &merged_cm));
    // the insertCoin recipient's own kernel.self read, then the insert.
    ops.extend(kernel_self(&me));
    let merged_nonce_bytes = {
        let mut b = [0u8; 32];
        let le = merged_nonce.1;
        // reconstruct the 32-byte nonce: hi byte then 31-byte low limb.
        let lo = le;
        let mut lo_bytes = lo.as_le_bytes();
        lo_bytes.resize(31, 0);
        b[..31].copy_from_slice(&lo_bytes);
        let mut hi_bytes = merged_nonce.0.as_le_bytes();
        hi_bytes.resize(1, 0);
        b[31] = hi_bytes[0];
        b
    };
    ops.extend(insert_coin(
        manager::POOLS,
        &colour1(),
        coin_av(&merged_nonce_bytes, &colour1(), merged_value),
        &merged_cm,
    ));
    ops.extend(member(
        manager::SHIELDED_BALANCES,
        bytesn_value(32, &key),
        false,
    ));
    ops.extend(insert(
        manager::SHIELDED_BALANCES,
        bytesn_value(32, &key),
        bytesn_value(16, &value.to_le_bytes()),
    ));

    let mut inputs = b32_inputs(&coin_nonce);
    inputs.extend(b32_inputs(&colour1()));
    inputs.push(Fr::from_le_bytes(&value.to_le_bytes()).unwrap());
    inputs.extend(b32_inputs(&acct1()));
    let pi = preimage(
        inputs,
        vec![],
        &ops,
        vec![
            bytesn_value(1, &[1]),
            bytesn_value(32, &me),
            bytesn_value(1, &[1]),
            qualified_coin_av(&pooled_nonce, &colour1(), pooled_value, mt_index),
            bytesn_value(32, &me),
            bytesn_value(32, &me),
            bytesn_value(1, &[0]),
        ],
    );
    assert_call_compatible(&ours, &theirs, &pi);
}

// ===========================================================================
// execute
// ===========================================================================

use midnight_zkir_v3::ir_instructions::ec_mul::ec_mul_offcircuit;
use midnight_zkir_v3::ir_instructions::into_bytes32::into_bytes32_offcircuit;
use midnight_zkir_v3::ir_instructions::into_coordinates::into_coordinates_offcircuit;
use midnight_curves::k256;
use minocrab_zkir::v3::IrValue;
use vault::prims::{coin_commitment_of, coin_nullifier_of, evolved_nonce, natives, scalar, sign};

fn keccak(data: &[u8]) -> [u8; 32] {
    use sha3::Digest as _;
    sha3::Keccak256::digest(data).into()
}

fn addr_word(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

fn num_word(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

/// `secp256k1EthereumAddress(pk)` off-circuit.
fn eth_address(pk: &IrValue) -> [u8; 20] {
    let (x, y) = into_coordinates_offcircuit(pk).unwrap();
    let IrValue::Bytes32(x_le) = into_bytes32_offcircuit(&x).unwrap() else {
        panic!("into_bytes32 yields Bytes32")
    };
    let IrValue::Bytes32(y_le) = into_bytes32_offcircuit(&y).unwrap() else {
        panic!("into_bytes32 yields Bytes32")
    };
    let mut buf = [0u8; 64];
    let mut x_be = x_le;
    x_be.reverse();
    let mut y_be = y_le;
    y_be.reverse();
    buf[..32].copy_from_slice(&x_be);
    buf[32..].copy_from_slice(&y_be);
    let digest = keccak(&buf);
    digest[12..].try_into().unwrap()
}

/// `evmAccountIdFor(manager, owner, salt)` off-circuit.
fn evm_account_id(mgr: &[u8; 32], owner: &[u8; 20], salt: &[u8; 32]) -> [u8; 32] {
    let mut pre = Vec::with_capacity(128);
    pre.extend_from_slice(&manager::ACCOUNT_TAG);
    pre.extend_from_slice(mgr);
    pre.extend_from_slice(&addr_word(owner));
    pre.extend_from_slice(salt);
    keccak(&pre)
}

/// `evmDomainSeparatorFor(manager, domain)` off-circuit.
fn evm_domain_separator(mgr: &[u8; 32], domain: &[u8; 32]) -> [u8; 32] {
    let alias: [u8; 20] = keccak(mgr)[12..].try_into().unwrap();
    let mut pre = Vec::with_capacity(160);
    pre.extend_from_slice(&manager::DOMAIN_TYPE);
    pre.extend_from_slice(&manager::DOMAIN_NAME);
    pre.extend_from_slice(&manager::DOMAIN_VERSION);
    pre.extend_from_slice(&addr_word(&alias));
    pre.extend_from_slice(domain);
    keccak(&pre)
}

fn eip712_digest(domain_sep: &[u8; 32], struct_hash: &[u8; 32]) -> [u8; 32] {
    let mut pre = Vec::with_capacity(66);
    pre.extend_from_slice(&[0x19, 0x01]);
    pre.extend_from_slice(domain_sep);
    pre.extend_from_slice(struct_hash);
    keccak(&pre)
}

/// The 32-byte nonce a `(hi, lo)` slot pair denotes.
fn nonce_bytes(slots: &(Fr, Fr)) -> [u8; 32] {
    let mut b = [0u8; 32];
    let mut lo = slots.1.as_le_bytes();
    lo.resize(31, 0);
    b[..31].copy_from_slice(&lo);
    let mut hi = slots.0.as_le_bytes();
    hi.resize(1, 0);
    b[31] = hi[0];
    b
}

/// `evolveNonce(index, nonce)` — the EXPORTED stdlib circuit:
/// `transientHash<Vector<3, Field>>([tag, index, degrade(nonce)])`.
fn evolve_nonce_indexed(index: u64, nonce: &[u8; 32]) -> (Fr, Fr) {
    use midnight_transient_crypto::hash::transient_hash;
    let tag = Fr::from_le_bytes(b"midnight:kernel:nonce_evolve").unwrap();
    let (_hi, lo) = b32_slots(nonce);
    let h = transient_hash(&[tag, Fr::from(index), lo]);
    let mut le = h.as_le_bytes();
    le.resize(32, 0);
    (Fr::from(0u64), Fr::from_le_bytes(&le[..31]).unwrap())
}

/// `sendShielded`'s CHANGE nonce — the "/2" domain.
fn evolved_nonce_change(nonce: &[u8; 32]) -> (Fr, Fr) {
    use midnight_transient_crypto::hash::transient_hash;
    let tag = Fr::from_le_bytes(b"midnight:kernel:nonce_evolve/2").unwrap();
    let (_hi, lo) = b32_slots(nonce);
    let h = transient_hash(&[tag, lo]);
    let mut le = h.as_le_bytes();
    le.resize(32, 0);
    (Fr::from(0u64), Fr::from_le_bytes(&le[..31]).unwrap())
}

/// `blockTimeLt(time)` (and `blockTimeGte`, which is its negation): `dup 2;
/// idx cached [2]; push time; lt; popeqc`.
fn blocktime_lt(time: u64, result: bool) -> Vec<VmOp> {
    vec![
        Op::Dup { n: 2 },
        Op::Idx {
            cached: true,
            push_path: false,
            path: vec![field_key(2)].into(),
        },
        Op::Push {
            storage: false,
            value: cell(bytesn_value(8, &time.to_le_bytes())),
        },
        Op::Lt,
        Op::Popeq {
            cached: true,
            result: bytesn_value(1, &[u8::from(result)]),
        },
    ]
}

/// `unshieldedBalanceLt(color, amount)`'s query — the kernel balance map at
/// field 5, with the on-chain member/branch fallback for an absent colour.
fn unshielded_balance_lt(color: &[u8; 32], amount: u128, result: bool) -> Vec<VmOp> {
    vec![
        Op::Dup { n: 2 },
        Op::Idx {
            cached: true,
            push_path: false,
            path: vec![field_key(5)].into(),
        },
        Op::Dup { n: 0 },
        Op::Push {
            storage: false,
            value: cell(left_color_av(color)),
        },
        Op::Member,
        Op::Branch { skip: 3 },
        Op::Pop,
        Op::Push {
            storage: false,
            value: cell(bytesn_value(16, &0u128.to_le_bytes())),
        },
        Op::Jmp { skip: 1 },
        Op::Idx {
            cached: true,
            push_path: false,
            path: vec![Key::Value(left_color_av(color))].into(),
        },
        Op::Push {
            storage: false,
            value: cell(bytesn_value(16, &amount.to_le_bytes())),
        },
        Op::Lt,
        Op::Popeq {
            cached: true,
            result: bytesn_value(1, &[u8::from(result)]),
        },
    ]
}

/// `claimUnshieldedCoinSpend` (slot 8): the accumulator whose key is
/// `left(color) ‖ recipient`.
fn claim_unshielded_spend(
    color: &[u8; 32],
    recipient_is_left: bool,
    recipient: &[u8; 32],
    amount: u128,
) -> Vec<VmOp> {
    let (left, right) = if recipient_is_left {
        (recipient.to_vec(), vec![])
    } else {
        (vec![], recipient.to_vec())
    };
    let key = AlignedValue::new(
        Value(vec![
            ValueAtom(vec![1]).normalize(),
            ValueAtom(color.to_vec()).normalize(),
            ValueAtom(vec![]).normalize(),
            ValueAtom(vec![u8::from(recipient_is_left)]).normalize(),
            ValueAtom(left).normalize(),
            ValueAtom(right).normalize(),
        ]),
        Alignment(vec![atom(1), atom(32), atom(32), atom(1), atom(32), atom(32)]),
    )
    .unwrap();
    vec![
        Op::Swap { n: 0 },
        Op::Idx {
            cached: true,
            push_path: true,
            path: vec![field_key(8)].into(),
        },
        Op::Push {
            storage: false,
            value: cell(key),
        },
        Op::Dup { n: 1 },
        Op::Dup { n: 1 },
        Op::Member,
        Op::Push {
            storage: false,
            value: cell(bytesn_value(16, &amount.to_le_bytes())),
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
    ]
}

/// The `ExecutePayload` argument, with the FAB flattening and the EIP-712
/// struct-hash preimage derived from one place.
#[derive(Clone)]
struct MPayload {
    selector: u8,
    auth_mode: u8,
    account: [u8; 32],
    owner: [u8; 20],
    account_salt: [u8; 32],
    nonce: u64,
    valid_until: u64,
    primary_color: [u8; 32],
    primary_amount: u128,
    recipient_kind: u8,
    recipient: [u8; 32],
    to_account: [u8; 32],
    want_nonce: [u8; 32],
    want_color: [u8; 32],
    want_amount: u128,
    credit_account: [u8; 32],
}

impl Default for MPayload {
    fn default() -> MPayload {
        MPayload {
            selector: 0,
            auth_mode: 0,
            account: [0; 32],
            owner: [0; 20],
            account_salt: [0; 32],
            nonce: 0,
            valid_until: 0,
            primary_color: [0; 32],
            primary_amount: 0,
            recipient_kind: 0,
            recipient: [0; 32],
            to_account: [0; 32],
            want_nonce: [0; 32],
            want_color: [0; 32],
            want_amount: 0,
            credit_account: [0; 32],
        }
    }
}

impl MPayload {
    /// The 24 argument limbs, in field order.
    fn inputs(&self) -> Vec<Fr> {
        let mut v = vec![
            Fr::from(u64::from(self.selector)),
            Fr::from(u64::from(self.auth_mode)),
        ];
        v.extend(b32_inputs(&self.account));
        v.push(Fr::from_le_bytes(&self.owner).unwrap());
        v.extend(b32_inputs(&self.account_salt));
        v.push(Fr::from(self.nonce));
        v.push(Fr::from(self.valid_until));
        v.extend(b32_inputs(&self.primary_color));
        v.push(Fr::from_le_bytes(&self.primary_amount.to_le_bytes()).unwrap());
        v.push(Fr::from(u64::from(self.recipient_kind)));
        v.extend(b32_inputs(&self.recipient));
        v.extend(b32_inputs(&self.to_account));
        v.extend(b32_inputs(&self.want_nonce));
        v.extend(b32_inputs(&self.want_color));
        v.push(Fr::from_le_bytes(&self.want_amount.to_le_bytes()).unwrap());
        v.extend(b32_inputs(&self.credit_account));
        v
    }

    /// `evmStructHashFor(manager, p)` off-circuit.
    fn struct_hash(&self, mgr: &[u8; 32]) -> [u8; 32] {
        let mut pre = Vec::new();
        match self.selector {
            1 => {
                pre.extend_from_slice(&manager::REGISTER_TYPE);
                pre.extend_from_slice(mgr);
                pre.extend_from_slice(&self.account);
                pre.extend_from_slice(&addr_word(&self.owner));
                pre.extend_from_slice(&self.account_salt);
                pre.extend_from_slice(&num_word(u128::from(self.valid_until)));
            }
            2 | 3 => {
                pre.extend_from_slice(if self.selector == 2 {
                    &manager::WITHDRAW_SHIELDED_TYPE
                } else {
                    &manager::WITHDRAW_UNSHIELDED_TYPE
                });
                pre.extend_from_slice(mgr);
                pre.extend_from_slice(&self.account);
                pre.extend_from_slice(&addr_word(&self.owner));
                pre.extend_from_slice(&num_word(u128::from(self.nonce)));
                pre.extend_from_slice(&num_word(u128::from(self.valid_until)));
                pre.extend_from_slice(&self.primary_color);
                pre.extend_from_slice(&num_word(self.primary_amount));
                pre.extend_from_slice(&num_word(u128::from(self.recipient_kind)));
                pre.extend_from_slice(&self.recipient);
            }
            4 | 5 => {
                pre.extend_from_slice(if self.selector == 4 {
                    &manager::TRANSFER_SHIELDED_TYPE
                } else {
                    &manager::TRANSFER_UNSHIELDED_TYPE
                });
                pre.extend_from_slice(mgr);
                pre.extend_from_slice(&self.account);
                pre.extend_from_slice(&addr_word(&self.owner));
                pre.extend_from_slice(&num_word(u128::from(self.nonce)));
                pre.extend_from_slice(&num_word(u128::from(self.valid_until)));
                pre.extend_from_slice(&self.to_account);
                pre.extend_from_slice(&self.primary_color);
                pre.extend_from_slice(&num_word(self.primary_amount));
            }
            6 => {
                pre.extend_from_slice(&manager::OPEN_SWAP_TYPE);
                pre.extend_from_slice(mgr);
                pre.extend_from_slice(&self.account);
                pre.extend_from_slice(&addr_word(&self.owner));
                pre.extend_from_slice(&num_word(u128::from(self.nonce)));
                pre.extend_from_slice(&num_word(u128::from(self.valid_until)));
                pre.extend_from_slice(&self.primary_color);
                pre.extend_from_slice(&num_word(self.primary_amount));
                pre.extend_from_slice(&num_word(u128::from(self.recipient_kind)));
                pre.extend_from_slice(&self.recipient);
                pre.extend_from_slice(&self.want_nonce);
                pre.extend_from_slice(&self.want_color);
                pre.extend_from_slice(&num_word(self.want_amount));
                pre.extend_from_slice(&self.credit_account);
            }
            _ => panic!("selector {} signs nothing", self.selector),
        }
        keccak(&pre)
    }

    fn digest(&self, mgr: &[u8; 32], domain: &[u8; 32]) -> [u8; 32] {
        eip712_digest(&evm_domain_separator(mgr, domain), &self.struct_hash(mgr))
    }
}

/// A throwaway-but-valid signature/key for NATIVE calls: the ECDSA chain
/// runs straight-line whatever the mode, so `s` must be invertible and `pk`
/// must not be the identity.
fn dummy_sig_inputs() -> Vec<Fr> {
    let g = IrValue::Secp256k1Point(k256::K256::generator());
    let pk = ec_mul_offcircuit(&g, &scalar(9)).unwrap();
    let mut v = natives(&scalar(7));
    v.extend(natives(&scalar(7)));
    v.extend(natives(&pk));
    v
}

/// Real EVM signature inputs over `digest` for secret `d`, plus the signer's
/// derived address.
fn evm_sig_inputs(digest: &[u8; 32], d: u64) -> (Vec<Fr>, [u8; 20]) {
    let d = scalar(d);
    let k = scalar(0x517e_c0de_u64);
    let (r_le, s_le, pk) = sign(digest, &d, &k);
    use midnight_zkir_v3::ir_instructions::from_bytes32::from_bytes32_offcircuit;
    use minocrab_zkir::v3::IrType;
    let r = from_bytes32_offcircuit(&IrType::Secp256k1Scalar, &r_le).unwrap();
    let s = from_bytes32_offcircuit(&IrType::Secp256k1Scalar, &s_le).unwrap();
    let mut v = natives(&r);
    v.extend(natives(&s));
    v.extend(natives(&pk));
    (v, eth_address(&pk))
}

fn deployment_domain() -> [u8; 32] {
    pad32("aa-deployment-domain")
}

fn caller_sk() -> [u8; 32] {
    let mut s = pad32("native-caller-secret");
    s[31] = 0x51;
    s
}

/// The native gateway's read block (`authenticatedActionAccount`, mode 0).
fn native_gateway_reads(na: &[u8; 32]) -> (Vec<VmOp>, Vec<AlignedValue>) {
    let acct = bytesn_value(32, na);
    let mut ops = member(manager::ACCOUNTS, acct.clone(), true);
    ops.extend(member(manager::ACCOUNT_MODES, acct.clone(), true));
    ops.extend(lookup(manager::ACCOUNT_MODES, acct.clone(), bytesn_value(1, &[0])));
    ops.extend(lookup(manager::ACCOUNT_MODES, acct.clone(), bytesn_value(1, &[0])));
    ops.extend(member(manager::EVM_OWNERS, acct.clone(), false));
    ops.extend(member(manager::EVM_NONCES, acct, false));
    let outs = vec![
        bytesn_value(1, &[1]),
        bytesn_value(1, &[1]),
        bytesn_value(1, &[0]),
        bytesn_value(1, &[0]),
        bytesn_value(1, &[0]),
        bytesn_value(1, &[0]),
    ];
    (ops, outs)
}

#[test]
fn execute_native_registration_matches_corpus() {
    let theirs = corpus_zkir("execute");
    let ours = manager::execute().ir;

    let sk = caller_sk();
    let na = owner_commitment(&sk);
    let me = self_addr();

    let p = MPayload::default(); // selector 0, all fields canonical zero.

    let mut ops = kernel_self(&me);
    // registerAccount(nativeAccount, 0)
    ops.extend(member(manager::ACCOUNTS, bytesn_value(32, &na), false));
    ops.extend(member(manager::ACCOUNT_MODES, bytesn_value(32, &na), false));
    ops.extend(set_insert(manager::ACCOUNTS, bytesn_value(32, &na)));
    ops.extend(insert(
        manager::ACCOUNT_MODES,
        bytesn_value(32, &na),
        bytesn_value(1, &[0]),
    ));

    let mut inputs = p.inputs();
    inputs.extend(dummy_sig_inputs());
    let (hi, lo) = b32_slots(&sk);
    let pi = preimage(
        inputs,
        vec![hi, lo],
        &ops,
        vec![
            bytesn_value(32, &me),
            bytesn_value(1, &[0]),
            bytesn_value(1, &[0]),
        ],
    );
    support::dump_preimage("manager_execute_reg_native", &pi);
    assert_call_compatible(&ours, &theirs, &pi);
}

#[test]
fn execute_evm_registration_matches_corpus() {
    let theirs = corpus_zkir("execute");
    let ours = manager::execute().ir;

    let sk = caller_sk();
    let me = self_addr();
    let domain = deployment_domain();
    let salt = pad32("evm-account-salt-1");

    // The signer's address comes from the key, and the account id from the
    // address — so derive owner first, then assemble the payload and sign.
    let d = 0xdead_beefu64;
    let g = IrValue::Secp256k1Point(k256::K256::generator());
    let owner = eth_address(&ec_mul_offcircuit(&g, &scalar(d)).unwrap());
    let account = evm_account_id(&me, &owner, &salt);

    let p = MPayload {
        selector: 1,
        auth_mode: 1,
        account,
        owner,
        account_salt: salt,
        valid_until: 5_000,
        ..MPayload::default()
    };
    let digest = p.digest(&me, &domain);
    let (sig_inputs, signer) = evm_sig_inputs(&digest, d);
    assert_eq!(signer, owner);

    let mut ops = kernel_self(&me);
    ops.extend(cell_read(
        manager::DEPLOYMENT_DOMAIN,
        false,
        bytesn_value(32, &domain),
    ));
    // assertLiveDeadline: blockTimeGte(validUntil - 3600) → lt is FALSE;
    // blockTimeLt(validUntil) → TRUE.
    ops.extend(blocktime_lt(p.valid_until - 3600, false));
    ops.extend(blocktime_lt(p.valid_until, true));
    // registerAccount(account, 1)
    ops.extend(member(manager::ACCOUNTS, bytesn_value(32, &account), false));
    ops.extend(member(manager::ACCOUNT_MODES, bytesn_value(32, &account), false));
    ops.extend(set_insert(manager::ACCOUNTS, bytesn_value(32, &account)));
    ops.extend(insert(
        manager::ACCOUNT_MODES,
        bytesn_value(32, &account),
        bytesn_value(1, &[1]),
    ));
    // evmOwners.insert(account, owner)
    ops.extend(insert(
        manager::EVM_OWNERS,
        bytesn_value(32, &account),
        bytesn_value(20, &owner),
    ));
    // evmNonces.insert(account, 0) — a registration stores the record's
    // first usable nonce.
    ops.extend(insert(
        manager::EVM_NONCES,
        bytesn_value(32, &account),
        bytesn_value(8, &0u64.to_le_bytes()),
    ));

    let mut inputs = p.inputs();
    inputs.extend(sig_inputs);
    let (hi, lo) = b32_slots(&sk);
    let pi = preimage(
        inputs,
        vec![hi, lo],
        &ops,
        vec![
            bytesn_value(32, &me),
            bytesn_value(32, &domain),
            bytesn_value(1, &[0]),
            bytesn_value(1, &[1]),
            bytesn_value(1, &[0]),
            bytesn_value(1, &[0]),
        ],
    );
    support::dump_preimage("manager_execute_reg_evm", &pi);
    assert_call_compatible(&ours, &theirs, &pi);
}

#[test]
fn execute_native_transfer_shielded_matches_corpus() {
    let theirs = corpus_zkir("execute");
    let ours = manager::execute().ir;

    let sk = caller_sk();
    let na = owner_commitment(&sk);
    let me = self_addr();
    let domain = deployment_domain();
    let val = 250u128;
    let balance = 1_000u128;

    let p = MPayload {
        selector: 4,
        auth_mode: 0,
        account: na,
        primary_color: colour1(),
        primary_amount: val,
        to_account: acct2(),
        ..MPayload::default()
    };

    let debit_key = shielded_key(&na, &colour1());
    let credit_key = shielded_key(&acct2(), &colour1());

    let mut ops = kernel_self(&me);
    ops.extend(cell_read(
        manager::DEPLOYMENT_DOMAIN,
        false,
        bytesn_value(32, &domain),
    ));
    let (gw_ops, gw_outs) = native_gateway_reads(&na);
    ops.extend(gw_ops);
    // custody: destination check, debit read, debit write, credit read+write.
    ops.extend(member(manager::ACCOUNTS, bytesn_value(32, &acct2()), true));
    ops.extend(member(
        manager::SHIELDED_BALANCES,
        bytesn_value(32, &debit_key),
        true,
    ));
    ops.extend(lookup(
        manager::SHIELDED_BALANCES,
        bytesn_value(32, &debit_key),
        bytesn_value(16, &balance.to_le_bytes()),
    ));
    ops.extend(insert(
        manager::SHIELDED_BALANCES,
        bytesn_value(32, &debit_key),
        bytesn_value(16, &(balance - val).to_le_bytes()),
    ));
    ops.extend(member(
        manager::SHIELDED_BALANCES,
        bytesn_value(32, &credit_key),
        false,
    ));
    ops.extend(insert(
        manager::SHIELDED_BALANCES,
        bytesn_value(32, &credit_key),
        bytesn_value(16, &val.to_le_bytes()),
    ));

    let mut inputs = p.inputs();
    inputs.extend(dummy_sig_inputs());
    let (hi, lo) = b32_slots(&sk);
    let mut outs = vec![bytesn_value(32, &me), bytesn_value(32, &domain)];
    outs.extend(gw_outs);
    outs.extend([
        bytesn_value(1, &[1]),
        bytesn_value(1, &[1]),
        bytesn_value(16, &balance.to_le_bytes()),
        bytesn_value(1, &[0]),
    ]);
    let pi = preimage(inputs, vec![hi, lo], &ops, outs);
    support::dump_preimage("manager_execute_transfer_shielded", &pi);
    assert_call_compatible(&ours, &theirs, &pi);
}

#[test]
fn execute_evm_transfer_unshielded_matches_corpus() {
    let theirs = corpus_zkir("execute");
    let ours = manager::execute().ir;

    let sk = caller_sk();
    let me = self_addr();
    let domain = deployment_domain();
    let val = 42u128;
    let balance = 500u128;
    let stored_nonce = 7u64;

    let d = 0xfeed_f00du64;
    let g = IrValue::Secp256k1Point(k256::K256::generator());
    let owner = eth_address(&ec_mul_offcircuit(&g, &scalar(d)).unwrap());
    let account = acct1();

    let p = MPayload {
        selector: 5,
        auth_mode: 1,
        account,
        owner,
        nonce: stored_nonce,
        valid_until: 9_000,
        primary_color: colour1(),
        primary_amount: val,
        to_account: acct2(),
        ..MPayload::default()
    };
    let digest = p.digest(&me, &domain);
    let (sig_inputs, signer) = evm_sig_inputs(&digest, d);
    assert_eq!(signer, owner);

    let debit_key = unshielded_key(&account, &colour1());
    let credit_key = unshielded_key(&acct2(), &colour1());
    let acct = bytesn_value(32, &account);

    let mut ops = kernel_self(&me);
    ops.extend(cell_read(
        manager::DEPLOYMENT_DOMAIN,
        false,
        bytesn_value(32, &domain),
    ));
    // The EVM gateway's read block.
    ops.extend(member(manager::ACCOUNTS, acct.clone(), true));
    ops.extend(member(manager::ACCOUNT_MODES, acct.clone(), true));
    ops.extend(lookup(manager::ACCOUNT_MODES, acct.clone(), bytesn_value(1, &[1])));
    ops.extend(member(manager::EVM_OWNERS, acct.clone(), true));
    ops.extend(member(manager::EVM_NONCES, acct.clone(), true));
    ops.extend(lookup(manager::EVM_OWNERS, acct.clone(), bytesn_value(20, &owner)));
    ops.extend(lookup(
        manager::EVM_NONCES,
        acct.clone(),
        bytesn_value(8, &stored_nonce.to_le_bytes()),
    ));
    // assertLiveDeadline.
    ops.extend(blocktime_lt(p.valid_until - 3600, false));
    ops.extend(blocktime_lt(p.valid_until, true));
    // custody: destination check, unshielded debit, unshielded credit.
    ops.extend(member(manager::ACCOUNTS, bytesn_value(32, &acct2()), true));
    ops.extend(member(
        manager::UNSHIELDED_BALANCES,
        bytesn_value(32, &debit_key),
        true,
    ));
    ops.extend(lookup(
        manager::UNSHIELDED_BALANCES,
        bytesn_value(32, &debit_key),
        bytesn_value(16, &balance.to_le_bytes()),
    ));
    ops.extend(insert(
        manager::UNSHIELDED_BALANCES,
        bytesn_value(32, &debit_key),
        bytesn_value(16, &(balance - val).to_le_bytes()),
    ));
    ops.extend(member(
        manager::UNSHIELDED_BALANCES,
        bytesn_value(32, &credit_key),
        false,
    ));
    ops.extend(insert(
        manager::UNSHIELDED_BALANCES,
        bytesn_value(32, &credit_key),
        bytesn_value(16, &val.to_le_bytes()),
    ));
    // The checked nonce write.
    ops.extend(insert(
        manager::EVM_NONCES,
        acct,
        bytesn_value(8, &(stored_nonce + 1).to_le_bytes()),
    ));

    let mut inputs = p.inputs();
    inputs.extend(sig_inputs);
    let (hi, lo) = b32_slots(&sk);
    let pi = preimage(
        inputs,
        vec![hi, lo],
        &ops,
        vec![
            bytesn_value(32, &me),
            bytesn_value(32, &domain),
            bytesn_value(1, &[1]),
            bytesn_value(1, &[1]),
            bytesn_value(1, &[1]),
            bytesn_value(1, &[1]),
            bytesn_value(1, &[1]),
            bytesn_value(20, &owner),
            bytesn_value(8, &stored_nonce.to_le_bytes()),
            bytesn_value(1, &[0]),
            bytesn_value(1, &[1]),
            bytesn_value(1, &[1]),
            bytesn_value(1, &[1]),
            bytesn_value(16, &balance.to_le_bytes()),
            bytesn_value(1, &[0]),
        ],
    );
    support::dump_preimage("manager_execute_transfer_evm", &pi);
    assert_call_compatible(&ours, &theirs, &pi);
}

#[test]
fn execute_native_withdraw_shielded_matches_corpus() {
    let theirs = corpus_zkir("execute");
    let ours = manager::execute().ir;

    let sk = caller_sk();
    let na = owner_commitment(&sk);
    let me = self_addr();
    let domain = deployment_domain();
    let val = 300u128;
    let balance = 800u128;
    let pooled_value = 1_000u128;
    let pooled_nonce = pad32("pooled-give-nonce");
    let mt_index = 5u64;
    let user_pk = pad32("withdrawer-wallet-pk");

    let p = MPayload {
        selector: 2,
        auth_mode: 0,
        account: na,
        primary_color: colour1(),
        primary_amount: val,
        recipient_kind: 0,
        recipient: user_pk,
        ..MPayload::default()
    };

    let debit_key = shielded_key(&na, &colour1());

    // sendShielded internals, off-circuit.
    let nul = coin_nullifier_of(
        &b32_slots(&pooled_nonce),
        &colour1(),
        pooled_value as u64,
        &me,
    );
    let out_nonce = evolved_nonce(&pooled_nonce);
    let out_cm = coin_commitment_of(&out_nonce, &colour1(), val as u64, true, &user_pk);
    let change_value = pooled_value - val;
    let change_nonce = evolved_nonce_change(&pooled_nonce);
    let change_cm =
        coin_commitment_of(&change_nonce, &colour1(), change_value as u64, false, &me);

    let mut ops = kernel_self(&me);
    ops.extend(cell_read(
        manager::DEPLOYMENT_DOMAIN,
        false,
        bytesn_value(32, &domain),
    ));
    let (gw_ops, gw_outs) = native_gateway_reads(&na);
    ops.extend(gw_ops);
    // custody: debit read, pool member+lookup, sendShielded, repool,
    // debit write.
    ops.extend(member(
        manager::SHIELDED_BALANCES,
        bytesn_value(32, &debit_key),
        true,
    ));
    ops.extend(lookup(
        manager::SHIELDED_BALANCES,
        bytesn_value(32, &debit_key),
        bytesn_value(16, &balance.to_le_bytes()),
    ));
    ops.extend(member(manager::POOLS, bytesn_value(32, &colour1()), true));
    ops.extend(lookup(
        manager::POOLS,
        bytesn_value(32, &colour1()),
        qualified_coin_av(&pooled_nonce, &colour1(), pooled_value, mt_index),
    ));
    // sendShielded: self read, input nullifier, output spend claim (the
    // auto-receive is off — the recipient is a user key), change claims.
    ops.extend(kernel_self(&me));
    ops.extend(kernel_claim(0, &nul));
    ops.extend(kernel_claim(2, &out_cm));
    ops.extend(kernel_claim(2, &change_cm));
    ops.extend(kernel_claim(1, &change_cm));
    // repoolOrRemove(col, some(change)): its own self read, then insertCoin.
    ops.extend(kernel_self(&me));
    ops.extend(insert_coin(
        manager::POOLS,
        &colour1(),
        coin_av(&nonce_bytes(&change_nonce), &colour1(), change_value),
        &change_cm,
    ));
    // the debit write.
    ops.extend(insert(
        manager::SHIELDED_BALANCES,
        bytesn_value(32, &debit_key),
        bytesn_value(16, &(balance - val).to_le_bytes()),
    ));

    let mut inputs = p.inputs();
    inputs.extend(dummy_sig_inputs());
    let (hi, lo) = b32_slots(&sk);
    let mut outs = vec![bytesn_value(32, &me), bytesn_value(32, &domain)];
    outs.extend(gw_outs);
    outs.extend([
        bytesn_value(1, &[1]),
        bytesn_value(16, &balance.to_le_bytes()),
        bytesn_value(1, &[1]),
        qualified_coin_av(&pooled_nonce, &colour1(), pooled_value, mt_index),
        bytesn_value(32, &me),
        bytesn_value(32, &me),
    ]);
    let pi = preimage(inputs, vec![hi, lo], &ops, outs);
    support::dump_preimage("manager_execute_withdraw_shielded", &pi);
    assert_call_compatible(&ours, &theirs, &pi);
}

#[test]
fn execute_native_withdraw_unshielded_matches_corpus() {
    let theirs = corpus_zkir("execute");
    let ours = manager::execute().ir;

    let sk = caller_sk();
    let na = owner_commitment(&sk);
    let me = self_addr();
    let domain = deployment_domain();
    let val = 60u128;
    let balance = 90u128;
    let user_addr = pad32("withdrawer-user-addr");

    let p = MPayload {
        selector: 3,
        auth_mode: 0,
        account: na,
        primary_color: colour1(),
        primary_amount: val,
        recipient_kind: 0,
        recipient: user_addr,
        ..MPayload::default()
    };

    let debit_key = unshielded_key(&na, &colour1());

    let mut ops = kernel_self(&me);
    ops.extend(cell_read(
        manager::DEPLOYMENT_DOMAIN,
        false,
        bytesn_value(32, &domain),
    ));
    let (gw_ops, gw_outs) = native_gateway_reads(&na);
    ops.extend(gw_ops);
    // custody: unshielded debit read, the contract-balance guard, the send,
    // the debit write.
    ops.extend(member(
        manager::UNSHIELDED_BALANCES,
        bytesn_value(32, &debit_key),
        true,
    ));
    ops.extend(lookup(
        manager::UNSHIELDED_BALANCES,
        bytesn_value(32, &debit_key),
        bytesn_value(16, &balance.to_le_bytes()),
    ));
    // unshieldedBalanceGte = !unshieldedBalanceLt — false for a funded pool.
    ops.extend(unshielded_balance_lt(&colour1(), val, false));
    // sendUnshielded: incOutputs, claimSpend(right(user)), no auto-receive.
    ops.extend(inc_unshielded(7, &colour1(), val));
    ops.extend(claim_unshielded_spend(&colour1(), false, &user_addr, val));
    // the debit write.
    ops.extend(insert(
        manager::UNSHIELDED_BALANCES,
        bytesn_value(32, &debit_key),
        bytesn_value(16, &(balance - val).to_le_bytes()),
    ));

    let mut inputs = p.inputs();
    inputs.extend(dummy_sig_inputs());
    let (hi, lo) = b32_slots(&sk);
    let mut outs = vec![bytesn_value(32, &me), bytesn_value(32, &domain)];
    outs.extend(gw_outs);
    outs.extend([
        bytesn_value(1, &[1]),
        bytesn_value(16, &balance.to_le_bytes()),
        bytesn_value(1, &[0]),
    ]);
    let pi = preimage(inputs, vec![hi, lo], &ops, outs);
    support::dump_preimage("manager_execute_withdraw_unshielded", &pi);
    assert_call_compatible(&ours, &theirs, &pi);
}

#[test]
fn execute_native_open_swap_matches_corpus() {
    let theirs = corpus_zkir("execute");
    let ours = manager::execute().ir;

    let sk = caller_sk();
    let na = owner_commitment(&sk);
    let me = self_addr();
    let domain = deployment_domain();
    let give = 400u128;
    let balance = 900u128;
    let pooled_value = 1_500u128;
    let pooled_nonce = pad32("pooled-swap-nonce");
    let mt_index = 9u64;
    let want_colour = {
        let mut c = pad32("want-colour");
        c[31] = 0x77;
        c
    };
    let want_nonce = pad32("maker-want-nonce");
    let want = 123u128;

    let p = MPayload {
        selector: 6,
        auth_mode: 0,
        account: na,
        primary_color: colour1(),
        primary_amount: give,
        recipient_kind: 0,
        want_nonce,
        want_color: want_colour,
        want_amount: want,
        credit_account: acct2(),
        ..MPayload::default()
    };

    let debit_key = shielded_key(&na, &colour1());
    let credit_key = shielded_key(&acct2(), &want_colour);

    // The open offer: nullify the pooled coin, change back to the contract.
    let nul = coin_nullifier_of(
        &b32_slots(&pooled_nonce),
        &colour1(),
        pooled_value as u64,
        &me,
    );
    let change_value = pooled_value - give;
    let change_nonce = evolve_nonce_indexed(2, &pooled_nonce);
    let change_cm =
        coin_commitment_of(&change_nonce, &colour1(), change_value as u64, false, &me);
    // The want leg: receive the wanted coin into custody.
    let want_cm = coin_commitment_of(&b32_slots(&want_nonce), &want_colour, want as u64, false, &me);

    let mut ops = kernel_self(&me);
    ops.extend(cell_read(
        manager::DEPLOYMENT_DOMAIN,
        false,
        bytesn_value(32, &domain),
    ));
    let (gw_ops, gw_outs) = native_gateway_reads(&na);
    ops.extend(gw_ops);
    // custody: debit read; pool guard; swap credit check; the open arm.
    ops.extend(member(
        manager::SHIELDED_BALANCES,
        bytesn_value(32, &debit_key),
        true,
    ));
    ops.extend(lookup(
        manager::SHIELDED_BALANCES,
        bytesn_value(32, &debit_key),
        bytesn_value(16, &balance.to_le_bytes()),
    ));
    ops.extend(member(manager::POOLS, bytesn_value(32, &colour1()), true));
    ops.extend(lookup(
        manager::POOLS,
        bytesn_value(32, &colour1()),
        qualified_coin_av(&pooled_nonce, &colour1(), pooled_value, mt_index),
    ));
    ops.extend(member(manager::ACCOUNTS, bytesn_value(32, &acct2()), true));
    // the open arm: self read, nullifier, change spend+receive, repool.
    ops.extend(kernel_self(&me));
    ops.extend(kernel_claim(0, &nul));
    ops.extend(kernel_claim(2, &change_cm));
    ops.extend(kernel_claim(1, &change_cm));
    ops.extend(kernel_self(&me));
    ops.extend(insert_coin(
        manager::POOLS,
        &colour1(),
        coin_av(&nonce_bytes(&change_nonce), &colour1(), change_value),
        &change_cm,
    ));
    // the debit write.
    ops.extend(insert(
        manager::SHIELDED_BALANCES,
        bytesn_value(32, &debit_key),
        bytesn_value(16, &(balance - give).to_le_bytes()),
    ));
    // the want leg: receiveShielded, fresh pool insert.
    ops.extend(receive_shielded(&me, &want_cm));
    ops.extend(member(manager::POOLS, bytesn_value(32, &want_colour), false));
    ops.extend(kernel_self(&me));
    ops.extend(insert_coin(
        manager::POOLS,
        &want_colour,
        coin_av(&want_nonce, &want_colour, want),
        &want_cm,
    ));
    // the credit write.
    ops.extend(member(
        manager::SHIELDED_BALANCES,
        bytesn_value(32, &credit_key),
        false,
    ));
    ops.extend(insert(
        manager::SHIELDED_BALANCES,
        bytesn_value(32, &credit_key),
        bytesn_value(16, &want.to_le_bytes()),
    ));

    let mut inputs = p.inputs();
    inputs.extend(dummy_sig_inputs());
    let (hi, lo) = b32_slots(&sk);
    let mut outs = vec![bytesn_value(32, &me), bytesn_value(32, &domain)];
    outs.extend(gw_outs);
    outs.extend([
        bytesn_value(1, &[1]),
        bytesn_value(16, &balance.to_le_bytes()),
        bytesn_value(1, &[1]),
        qualified_coin_av(&pooled_nonce, &colour1(), pooled_value, mt_index),
        bytesn_value(1, &[1]),
        bytesn_value(32, &me),
        bytesn_value(32, &me),
        bytesn_value(32, &me),
        bytesn_value(1, &[0]),
        bytesn_value(32, &me),
        bytesn_value(1, &[0]),
    ]);
    let pi = preimage(inputs, vec![hi, lo], &ops, outs);
    support::dump_preimage("manager_execute_open_swap", &pi);
    assert_call_compatible(&ours, &theirs, &pi);
}

#[test]
fn execute_rejects_guard_failures() {
    let theirs = corpus_zkir("execute");
    let ours = manager::execute().ir;

    let sk = caller_sk();
    let na = owner_commitment(&sk);
    let me = self_addr();

    // A non-canonical envelope: native registration carrying a live amount.
    let p = MPayload {
        primary_amount: 5,
        ..MPayload::default()
    };
    let mut ops = kernel_self(&me);
    ops.extend(member(manager::ACCOUNTS, bytesn_value(32, &na), false));
    ops.extend(member(manager::ACCOUNT_MODES, bytesn_value(32, &na), false));
    ops.extend(set_insert(manager::ACCOUNTS, bytesn_value(32, &na)));
    ops.extend(insert(
        manager::ACCOUNT_MODES,
        bytesn_value(32, &na),
        bytesn_value(1, &[0]),
    ));
    let mut inputs = p.inputs();
    inputs.extend(dummy_sig_inputs());
    let (hi, lo) = b32_slots(&sk);
    let pi = preimage(
        inputs,
        vec![hi, lo],
        &ops,
        vec![
            bytesn_value(32, &me),
            bytesn_value(1, &[0]),
            bytesn_value(1, &[0]),
        ],
    );
    assert_both_reject(&ours, &theirs, &pi, "non-canonical native registration");

    // An already-registered account colliding at registration.
    let p = MPayload::default();
    let mut ops = kernel_self(&me);
    ops.extend(member(manager::ACCOUNTS, bytesn_value(32, &na), true));
    ops.extend(member(manager::ACCOUNT_MODES, bytesn_value(32, &na), true));
    ops.extend(set_insert(manager::ACCOUNTS, bytesn_value(32, &na)));
    ops.extend(insert(
        manager::ACCOUNT_MODES,
        bytesn_value(32, &na),
        bytesn_value(1, &[0]),
    ));
    let mut inputs = p.inputs();
    inputs.extend(dummy_sig_inputs());
    let pi = preimage(
        inputs,
        vec![hi, lo],
        &ops,
        vec![
            bytesn_value(32, &me),
            bytesn_value(1, &[1]),
            bytesn_value(1, &[1]),
        ],
    );
    assert_both_reject(&ours, &theirs, &pi, "account already registered");
}

/// Named swap (recipientKind 1): the give leg pays a NAMED user key through
/// `sendShielded` rather than releasing an open imbalance, and spends the
/// pool EXACTLY (no change → the colour leaves the pool).
#[test]
fn execute_native_named_swap_exact_spend_matches_corpus() {
    let theirs = corpus_zkir("execute");
    let ours = manager::execute().ir;

    let sk = caller_sk();
    let na = owner_commitment(&sk);
    let me = self_addr();
    let domain = deployment_domain();
    let give = 1_500u128;
    let balance = 2_000u128;
    let pooled_value = 1_500u128; // exact spend
    let pooled_nonce = pad32("pooled-named-nonce");
    let mt_index = 2u64;
    let taker_pk = pad32("named-taker-key");
    let want_colour = {
        let mut c = pad32("want-colour-2");
        c[31] = 0x78;
        c
    };
    let want_nonce = pad32("maker-want-nonce-2");
    let want = 44u128;

    let p = MPayload {
        selector: 6,
        auth_mode: 0,
        account: na,
        primary_color: colour1(),
        primary_amount: give,
        recipient_kind: 1,
        recipient: taker_pk,
        want_nonce,
        want_color: want_colour,
        want_amount: want,
        credit_account: acct2(),
        ..MPayload::default()
    };

    let debit_key = shielded_key(&na, &colour1());
    let credit_key = shielded_key(&acct2(), &want_colour);

    // sendShielded to left(taker): nullifier, output spend, NO auto-receive,
    // change == 0 so no change claims and the pool entry is REMOVED.
    let nul = coin_nullifier_of(
        &b32_slots(&pooled_nonce),
        &colour1(),
        pooled_value as u64,
        &me,
    );
    let out_nonce = evolved_nonce(&pooled_nonce);
    let out_cm = coin_commitment_of(&out_nonce, &colour1(), give as u64, true, &taker_pk);
    let want_cm = coin_commitment_of(&b32_slots(&want_nonce), &want_colour, want as u64, false, &me);

    let mut ops = kernel_self(&me);
    ops.extend(cell_read(
        manager::DEPLOYMENT_DOMAIN,
        false,
        bytesn_value(32, &domain),
    ));
    let (gw_ops, gw_outs) = native_gateway_reads(&na);
    ops.extend(gw_ops);
    ops.extend(member(
        manager::SHIELDED_BALANCES,
        bytesn_value(32, &debit_key),
        true,
    ));
    ops.extend(lookup(
        manager::SHIELDED_BALANCES,
        bytesn_value(32, &debit_key),
        bytesn_value(16, &balance.to_le_bytes()),
    ));
    ops.extend(member(manager::POOLS, bytesn_value(32, &colour1()), true));
    ops.extend(lookup(
        manager::POOLS,
        bytesn_value(32, &colour1()),
        qualified_coin_av(&pooled_nonce, &colour1(), pooled_value, mt_index),
    ));
    ops.extend(member(manager::ACCOUNTS, bytesn_value(32, &acct2()), true));
    // sendShielded: self, nullifier, output spend; change == 0 → the
    // repool REMOVES the colour.
    ops.extend(kernel_self(&me));
    ops.extend(kernel_claim(0, &nul));
    ops.extend(kernel_claim(2, &out_cm));
    ops.extend(remove(manager::POOLS, bytesn_value(32, &colour1())));
    // the debit write.
    ops.extend(insert(
        manager::SHIELDED_BALANCES,
        bytesn_value(32, &debit_key),
        bytesn_value(16, &(balance - give).to_le_bytes()),
    ));
    // the want leg.
    ops.extend(receive_shielded(&me, &want_cm));
    ops.extend(member(manager::POOLS, bytesn_value(32, &want_colour), false));
    ops.extend(kernel_self(&me));
    ops.extend(insert_coin(
        manager::POOLS,
        &want_colour,
        coin_av(&want_nonce, &want_colour, want),
        &want_cm,
    ));
    // the credit write.
    ops.extend(member(
        manager::SHIELDED_BALANCES,
        bytesn_value(32, &credit_key),
        false,
    ));
    ops.extend(insert(
        manager::SHIELDED_BALANCES,
        bytesn_value(32, &credit_key),
        bytesn_value(16, &want.to_le_bytes()),
    ));

    let mut inputs = p.inputs();
    inputs.extend(dummy_sig_inputs());
    let (hi, lo) = b32_slots(&sk);
    let mut outs = vec![bytesn_value(32, &me), bytesn_value(32, &domain)];
    outs.extend(gw_outs);
    outs.extend([
        bytesn_value(1, &[1]),
        bytesn_value(16, &balance.to_le_bytes()),
        bytesn_value(1, &[1]),
        qualified_coin_av(&pooled_nonce, &colour1(), pooled_value, mt_index),
        bytesn_value(1, &[1]),
        bytesn_value(32, &me),
        bytesn_value(32, &me),
        bytesn_value(1, &[0]),
        bytesn_value(32, &me),
        bytesn_value(1, &[0]),
    ]);
    let pi = preimage(inputs, vec![hi, lo], &ops, outs);
    assert_call_compatible(&ours, &theirs, &pi);
}
