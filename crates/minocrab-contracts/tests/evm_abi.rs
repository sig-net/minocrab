//! M37 rung A — the typed EVM call layer, against the things that already
//! pin the vault.
//!
//! Four claims, each answering "how do we know?" with an EXISTING oracle
//! rather than a second reading of the same idea:
//!
//! 1. SELECTORS. `EvmCall::selector()` keccaks a signature built from the
//!    argument tuple's types. The five call types the vault uses must hash
//!    to the five selector constants in `erc20_vault` — and those are not
//!    our own arithmetic: `erc20_vault_differential` pins the vault's
//!    calldata, selector bytes and all, against compactc's own artifact.
//!    Plus one selector NOT in the vault (`balanceOf(address)` = 70a08231,
//!    a value anyone can look up) so the test is not circular.
//! 2. WORDS. Each `AbiType::word`, simulated on a concrete value, equals
//!    the host-side oracle in `tests/vault/prims.rs` (`abi_addr_word` /
//!    `abi_num_word`) — the same equality the vault differential rests on.
//! 3. ZERO MOVEMENT. The encoders MOVED out of `signet` into `evm`; a
//!    circuit built through `signet::evm_address_abi_word` and one built
//!    through `Address::word` serialize to byte-identical ZKIR. (The
//!    209-circuit dump says the same thing at scale; this says it in one
//!    assertion a reader can hold.)
//! 4. `build_tx`. `build_tx::<Erc20Transfer, 2>` emits the same stream as
//!    `erc20_vault_pending::erc20_call` — whose twenty lines are copied in
//!    here as `reference::erc20_call`, since rung A does not rewire the
//!    vault and the comparison has to be against what the vault does today.

use std::borrow::Cow;

use midnight_transient_crypto::proofs::{KeyLocation, ProofPreimage};
use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Fr, Private};
use minocrab_contracts::erc20_vault::{
    APPROVE_SELECTOR, DEPOSIT_SELECTOR, ERC20_CALL_GAS, EXACT_OUTPUT_SINGLE_SELECTOR,
    FIXED_MAX_FEE, FIXED_PRIORITY_FEE, REDEEM_SELECTOR, TRANSFER_SELECTOR,
};
use minocrab_contracts::evm::{
    always, build_tx, AbiType, Address, Bool, Bytes32, Erc20Approve, Erc20Transfer,
    Erc4626Deposit,
    Erc4626Redeem, EvmCall, ExactOutputSingle, U128, U24, U256, U64,
};
use minocrab_contracts::signet::{self, EvmCalldata};
use minocrab_contracts::signet_flow::EvmTx;
use minocrab_sim::v3::simulate;
use minocrab_std::v3::{Bool as BoolWire, Bytes, Check, Uint, B32};
use minocrab_zkir::v3::IrValue;

mod vault;

use vault::prims::{abi_addr_word, abi_num_word, b20, b32_slots, u128_limb};

// ---- harness -----------------------------------------------------------------

/// A circuit's serialized ZKIR — the house twin pattern
/// (`minocrab-std/tests/v3_guard_scope.rs`).
fn zkir(build: impl FnOnce(&mut Circuit3)) -> String {
    let mut c = Circuit3::new();
    build(&mut c);
    minocrab_zkir::v3::to_zkir_string(&c.finish(true).ir).expect("serializes")
}

fn preimage(inputs: &[Fr]) -> ProofPreimage {
    ProofPreimage {
        inputs: inputs.to_vec(),
        private_transcript: Vec::new(),
        public_transcript_inputs: Vec::new(),
        public_transcript_outputs: Vec::new(),
        binding_input: 0.into(),
        communications_commitment: None,
        key_location: KeyLocation(Cow::Borrowed("minocrab-evm-abi")),
    }
}

/// Build a word from `inputs.len()` raw field arguments, run it, and hand
/// back the word's `[hi, lo]` slot pair as the simulator computed it.
fn run_word(
    inputs: &[Fr],
    build: impl FnOnce(&mut Circuit3, &[Wire3<FieldT, Private>]) -> B32<Private>,
) -> (Fr, Fr) {
    let mut c = Circuit3::new();
    let args: Vec<Wire3<FieldT, Private>> = (0..inputs.len())
        .map(|i| c.arg::<FieldT>(&format!("a{i}")))
        .collect();
    let word = build(&mut c, &args);
    let hi = c.disclose(word.hi, "hi");
    let lo = c.disclose(word.lo, "lo");
    c.output(hi, "hi");
    c.output(lo, "lo");
    let compiled = c.finish(false);
    let run = simulate(&compiled.ir, &preimage(inputs)).expect("the encoder accepts");
    match (&run.outputs[0], &run.outputs[1]) {
        (IrValue::Native(hi), IrValue::Native(lo)) => (*hi, *lo),
        other => panic!("expected two native outputs, got {other:?}"),
    }
}

// ---- 1. selectors ------------------------------------------------------------

/// The five calls the vault makes, hashed from their argument TYPES, are the
/// five selector constants the differential suite pins against compactc's
/// calldata.
#[test]
fn selectors_are_the_vaults() {
    assert_eq!(
        Erc20Transfer::selector(),
        TRANSFER_SELECTOR,
        "transfer(address,uint256)"
    );
    assert_eq!(
        Erc20Approve::selector(),
        APPROVE_SELECTOR,
        "approve(address,uint256)"
    );
    assert_eq!(
        ExactOutputSingle::selector(),
        EXACT_OUTPUT_SINGLE_SELECTOR,
        "exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))"
    );
    assert_eq!(
        Erc4626Deposit::selector(),
        DEPOSIT_SELECTOR,
        "deposit(uint256,address)"
    );
    assert_eq!(
        Erc4626Redeem::selector(),
        REDEEM_SELECTOR,
        "redeem(uint256,address,address)"
    );
}

/// NOT CIRCULAR: a selector the vault does not contain, against the value
/// every ERC-20 explorer prints for it.
///
/// `balanceOf(address)` is `70a08231`. Nothing in this repository stores
/// that number, so if `selector()` were somehow reading the vault's
/// constants rather than hashing, this is where it would show.
#[test]
fn the_hash_is_not_circular() {
    struct BalanceOf;
    impl EvmCall for BalanceOf {
        const NAME: &'static str = "balanceOf";
        type Args = (Address,);
        type Return = U256;
        type Success = B32<Private>;
        const KIND: u8 = 0;
        const GAS_LIMIT: u64 = 30_000;

        fn succeeded(c: &mut Circuit3, _out: &B32<Private>) -> Check<Private> {
            always(c)
        }
    }
    assert_eq!(BalanceOf::signature(), "balanceOf(address)");
    assert_eq!(BalanceOf::selector(), [0x70, 0xa0, 0x82, 0x31]);
}

/// The struct-tuple wrapping is load-bearing: WITHOUT the extra parentheses
/// `exactOutputSingle` hashes to something else entirely.
#[test]
fn the_struct_wrapping_changes_the_selector() {
    struct Flat;
    impl EvmCall for Flat {
        const NAME: &'static str = "exactOutputSingle";
        type Args = <ExactOutputSingle as EvmCall>::Args;
        type Return = U64;
        type Success = Uint<64, Private>;
        const KIND: u8 = 0;
        const GAS_LIMIT: u64 = 0;
        // no `signature()` override — the flat join

        fn succeeded(c: &mut Circuit3, _out: &Uint<64, Private>) -> Check<Private> {
            always(c)
        }
    }
    assert_ne!(Flat::selector(), EXACT_OUTPUT_SINGLE_SELECTOR);
}

// ---- 2. words against the host oracles ---------------------------------------

/// `Address::word` on a concrete address is `abi_addr_word` — the host-side
/// encoding the vault's reference model uses for every calldata word it
/// checks against compactc.
#[test]
fn address_words_match_the_oracle() {
    let addr: [u8; 20] = [
        0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x99,
    ];
    let got = run_word(&[b20(&addr)], |c, a| {
        Address::word(c, &Bytes::<20, Private>::from_field_unchecked(a[0]))
    });
    assert_eq!(got, b32_slots(&abi_addr_word(&addr)));
}

/// The three numeric leaves ride the same encoder, and each agrees with
/// `abi_num_word` at its own width.
#[test]
fn numeric_words_match_the_oracle() {
    // U64 — a Midnight-side amount.
    let v: u64 = 1_234_567_890_123;
    let got = run_word(&[Fr::from(v)], |c, a| {
        U64::word(c, &Uint::<64, Private>::from_field_unchecked(a[0]))
    });
    assert_eq!(got, b32_slots(&abi_num_word(u128::from(v))));

    // U128 — the vault's own amount width, at the top of its range.
    let v: u128 = u128::MAX - 7;
    let got = run_word(&[u128_limb(v)], |c, a| {
        U128::word(c, &Uint::<128, Private>::from_field_unchecked(a[0]))
    });
    assert_eq!(got, b32_slots(&abi_num_word(v)));

    // U24 — Uniswap's fee tier.
    let fee: u32 = 3_000;
    let got = run_word(&[Fr::from(u64::from(fee))], |c, a| {
        U24::word(c, &Uint::<24, Private>::from_field_unchecked(a[0]))
    });
    assert_eq!(got, b32_slots(&abi_num_word(u128::from(fee))));
}

/// `bool` is right-aligned in the word, like any integer.
#[test]
fn bool_words_match_the_oracle() {
    for (v, n) in [(0u64, 0u128), (1, 1)] {
        let got = run_word(&[Fr::from(v)], |c, a| {
            Bool::word(c, &BoolWire::<Private>::from_field_unchecked(a[0]))
        });
        assert_eq!(got, b32_slots(&abi_num_word(n)), "bool {v}");
    }
}

/// The pre-encoded leaves are the identity: the word out is the word in,
/// and no instruction is emitted to make it so.
#[test]
fn pre_encoded_words_are_the_identity() {
    let mut word = [0u8; 32];
    word[16..].copy_from_slice(&[0xff; 16]); // the unlimited allowance
    let (hi, lo) = b32_slots(&word);

    for name in ["U256", "Bytes32"] {
        let got = run_word(&[hi, lo], |c, a| {
            let w = B32 { hi: a[0], lo: a[1] };
            if name == "U256" {
                U256::word(c, &w)
            } else {
                Bytes32::word(c, &w)
            }
        });
        assert_eq!(got, (hi, lo), "{name}");
    }

    // …and it costs nothing: the circuit is the one that never called it.
    let bare = zkir(|c| {
        let hi = c.arg::<FieldT>("hi");
        let lo = c.arg::<FieldT>("lo");
        let hi = c.disclose(hi, "hi");
        let lo = c.disclose(lo, "lo");
        c.output(hi, "hi");
        c.output(lo, "lo");
    });
    let encoded = zkir(|c| {
        let hi = c.arg::<FieldT>("hi");
        let lo = c.arg::<FieldT>("lo");
        let w = U256::word(c, &B32 { hi, lo });
        let hi = c.disclose(w.hi, "hi");
        let lo = c.disclose(w.lo, "lo");
        c.output(hi, "hi");
        c.output(lo, "lo");
    });
    assert_eq!(bare, encoded, "U256::word emits nothing");
}

// ---- 3. zero movement of the moved encoders ----------------------------------

/// The address encoder MOVED from `signet` to `evm`. Both spellings build
/// byte-identical ZKIR — the move is a place to write the body down, not a
/// different lowering.
#[test]
fn the_moved_address_encoder_did_not_move_an_instruction() {
    let old = zkir(|c| {
        let a = c.arg::<FieldT>("addr");
        let w = signet::evm_address_abi_word(c, a);
        let hi = c.disclose(w.hi, "hi");
        let lo = c.disclose(w.lo, "lo");
        c.output(hi, "hi");
        c.output(lo, "lo");
    });
    let new = zkir(|c| {
        let a = c.arg::<FieldT>("addr");
        let w = Address::word(c, &Bytes::<20, Private>::from_field_unchecked(a));
        let hi = c.disclose(w.hi, "hi");
        let lo = c.disclose(w.lo, "lo");
        c.output(hi, "hi");
        c.output(lo, "lo");
    });
    assert_eq!(old, new);
}

/// The same for the numeric encoder — and for BOTH typed spellings of it,
/// since `U64` and `U128` differ only in the range they claim.
#[test]
fn the_moved_numeric_encoder_did_not_move_an_instruction() {
    let old = zkir(|c| {
        let v = c.arg::<FieldT>("value");
        let w = signet::numeric_abi_word(c, v);
        let hi = c.disclose(w.hi, "hi");
        let lo = c.disclose(w.lo, "lo");
        c.output(hi, "hi");
        c.output(lo, "lo");
    });
    let via_u128 = zkir(|c| {
        let v = c.arg::<FieldT>("value");
        let w = U128::word(c, &Uint::<128, Private>::from_field_unchecked(v));
        let hi = c.disclose(w.hi, "hi");
        let lo = c.disclose(w.lo, "lo");
        c.output(hi, "hi");
        c.output(lo, "lo");
    });
    let via_u64 = zkir(|c| {
        let v = c.arg::<FieldT>("value");
        let w = U64::word(c, &Uint::<64, Private>::from_field_unchecked(v));
        let hi = c.disclose(w.hi, "hi");
        let lo = c.disclose(w.lo, "lo");
        c.output(hi, "hi");
        c.output(lo, "lo");
    });
    assert_eq!(old, via_u128);
    assert_eq!(old, via_u64);
}

// ---- 4. build_tx against the vault's own erc20_call --------------------------

/// The vault's transaction assembly as it stands today, copied verbatim
/// from `erc20_vault_pending.rs` (rung A does not rewire the vault, so the
/// comparison has to be against a copy).
mod reference {
    use super::*;

    /// `FixedGas::<LIMIT>::wires` — the contract-FIXED gas envelope.
    fn fixed_gas(c: &mut Circuit3, limit: u64) -> [Wire3<FieldT, Private>; 3] {
        let priority_fee = c.constant(FIXED_PRIORITY_FEE);
        let max_fee = c.constant(FIXED_MAX_FEE);
        let gas = c.constant(limit);
        [priority_fee.private(), max_fee.private(), gas.private()]
    }

    /// `erc20_call` — a two-word ERC-20 call as an `EvmTx`.
    fn erc20_call(
        c: &mut Circuit3,
        selector: &[u8; 4],
        to: Wire3<FieldT, Private>,
        words: [B32<Private>; 2],
        nonce: Wire3<FieldT, Private>,
        gas: [Wire3<FieldT, Private>; 3],
    ) -> EvmTx<2> {
        let zero = c.constant(0u64).private();
        let one = c.constant(1u64).private();
        let two = c.constant(2u64).private();
        let selector = c
            .constant(minocrab::Fr::from_le_bytes(selector).unwrap())
            .private();
        EvmTx {
            nonce,
            max_priority_fee_per_gas: gas[0],
            max_fee_per_gas: gas[1],
            gas_limit: gas[2],
            to,
            value: zero,
            calldata_is_some: one,
            calldata: EvmCalldata {
                selector,
                no_words: two,
                words,
            },
        }
    }

    /// The vault's `withdraw` body, from the words to the transaction.
    pub fn transfer_tx(
        c: &mut Circuit3,
        to: Wire3<FieldT, Private>,
        dest: Wire3<FieldT, Private>,
        amount: Wire3<FieldT, Private>,
        nonce: Wire3<FieldT, Private>,
    ) -> EvmTx<2> {
        let word0 = signet::evm_address_abi_word(c, dest);
        let word1 = signet::numeric_abi_word(c, amount);
        let gas = fixed_gas(c, ERC20_CALL_GAS);
        erc20_call(c, &TRANSFER_SELECTOR, to, [word0, word1], nonce, gas)
    }
}

/// Publish every wire of an `EvmTx<2>`, so the ZKIR comparison is over the
/// transaction the two constructions BUILD, not merely over what they
/// happened to emit on the way.
fn publish_tx(c: &mut Circuit3, tx: EvmTx<2>) {
    let fields = [
        ("nonce", tx.nonce),
        ("maxPriorityFeePerGas", tx.max_priority_fee_per_gas),
        ("maxFeePerGas", tx.max_fee_per_gas),
        ("gasLimit", tx.gas_limit),
        ("to", tx.to),
        ("value", tx.value),
        ("calldataIsSome", tx.calldata_is_some),
        ("selector", tx.calldata.selector),
        ("noWords", tx.calldata.no_words),
        ("word0.hi", tx.calldata.words[0].hi),
        ("word0.lo", tx.calldata.words[0].lo),
        ("word1.hi", tx.calldata.words[1].hi),
        ("word1.lo", tx.calldata.words[1].lo),
    ];
    for (label, w) in fields {
        let w = c.disclose(w, label);
        c.output(w, label);
    }
}

/// `build_tx::<Erc20Transfer, 2>` IS `erc20_call` with the selector, the
/// word count and the gas limit read off the type instead of typed out.
#[test]
fn build_tx_is_the_vaults_erc20_call() {
    let ours = zkir(|c| {
        let to = c.arg::<FieldT>("to");
        let dest = c.arg::<FieldT>("dest");
        let amount = c.arg::<FieldT>("amount");
        let nonce = c.arg::<FieldT>("nonce");
        let tx = build_tx::<Erc20Transfer, 2>(
            c,
            Bytes::<20, Private>::from_field_unchecked(to),
            (
                Bytes::<20, Private>::from_field_unchecked(dest),
                Uint::<128, Private>::from_field_unchecked(amount),
            ),
            nonce,
        );
        publish_tx(c, tx);
    });
    let theirs = zkir(|c| {
        let to = c.arg::<FieldT>("to");
        let dest = c.arg::<FieldT>("dest");
        let amount = c.arg::<FieldT>("amount");
        let nonce = c.arg::<FieldT>("nonce");
        let tx = reference::transfer_tx(c, to, dest, amount, nonce);
        publish_tx(c, tx);
    });
    assert_eq!(ours, theirs);
}

/// And the values it carries are the ones the reference model expects: the
/// selector immediate is `a9059cbb` packed little-endian, the fee envelope
/// is 1 gwei / 30 gwei, the limit is the ERC-20 limit and the word count is
/// two.
#[test]
fn build_tx_carries_the_declared_envelope() {
    let mut c = Circuit3::new();
    let to = c.arg::<FieldT>("to");
    let dest = c.arg::<FieldT>("dest");
    let amount = c.arg::<FieldT>("amount");
    let nonce = c.arg::<FieldT>("nonce");
    let tx = build_tx::<Erc20Transfer, 2>(
        &mut c,
        Bytes::<20, Private>::from_field_unchecked(to),
        (
            Bytes::<20, Private>::from_field_unchecked(dest),
            Uint::<128, Private>::from_field_unchecked(amount),
        ),
        nonce,
    );
    publish_tx(&mut c, tx);
    let compiled = c.finish(false);

    let addr: [u8; 20] = [0x11; 20];
    let callee: [u8; 20] = [0x22; 20];
    let amount: u128 = 42;
    let run = simulate(
        &compiled.ir,
        &preimage(&[
            b20(&callee),
            b20(&addr),
            u128_limb(amount),
            Fr::from(7u64),
        ]),
    )
    .expect("build_tx accepts");

    let native = |i: usize| match &run.outputs[i] {
        IrValue::Native(f) => *f,
        other => panic!("output {i} is not native: {other:?}"),
    };
    assert_eq!(native(0), Fr::from(7u64), "nonce");
    assert_eq!(native(1), Fr::from(FIXED_PRIORITY_FEE), "1 gwei priority");
    assert_eq!(native(2), Fr::from(FIXED_MAX_FEE), "30 gwei cap");
    assert_eq!(native(3), Fr::from(ERC20_CALL_GAS), "the ERC-20 gas limit");
    assert_eq!(native(4), b20(&callee), "to = the callee");
    assert_eq!(native(5), Fr::from(0u64), "value = 0");
    assert_eq!(native(6), Fr::from(1u64), "calldata is some");
    assert_eq!(
        native(7),
        Fr::from_le_bytes(&TRANSFER_SELECTOR).unwrap(),
        "the transfer selector"
    );
    assert_eq!(native(8), Fr::from(2u64), "two words");

    let (hi0, lo0) = b32_slots(&abi_addr_word(&addr));
    let (hi1, lo1) = b32_slots(&abi_num_word(amount));
    assert_eq!((native(9), native(10)), (hi0, lo0), "word 0 = the recipient");
    assert_eq!((native(11), native(12)), (hi1, lo1), "word 1 = the amount");
}

// ---- the outcome predicate ----------------------------------------------------

/// The instructions of a serialized circuit, by op name — enough to say what
/// was emitted without pinning the identifier NUMBERS, which shift when an
/// instruction is folded away (a folded `Copy` still consumed its name).
fn ops_of(zkir: &str) -> Vec<String> {
    let value: serde_json::Value = serde_json::from_str(zkir).expect("its own output parses");
    value["instructions"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|i| i["op"].as_str().expect("an op name").to_string())
        .collect()
}

/// `always(c)` COSTS NOTHING, and it costs nothing by FOLDING rather than by
/// a branch in the API (dmd, 2026-09-05; notes/ir-passes.org §11).
///
/// The two circuits below differ by exactly one `c.assert(always(c))`, and
/// they emit the same instructions: `always` lowers to an `assert` on a copy
/// of the immediate 1, `fold_immediate_copies` rewrites the operand to the
/// immediate and `drop_true_asserts` deletes the instruction — both inside
/// `Builder3::finish`, so nothing downstream ever sees it. (The identifier
/// NUMBERS still shift by one: the folded `Copy` consumed its name on the
/// way past. Nothing reads those, and the row cost is what the `k` gate
/// measures.)
#[test]
fn always_is_folded_out_of_the_artifact() {
    let with = zkir(|c| {
        let x = c.arg::<FieldT>("x");
        let ok = always(c);
        c.assert(ok.message("unreachable: `always` never fails"));
        let _ = c.mul(x, x);
    });
    let without = zkir(|c| {
        let x = c.arg::<FieldT>("x");
        let _ = c.mul(x, x);
    });
    assert!(!with.contains("\"assert\""), "`always` left an assert behind:\n{with}");
    assert_eq!(ops_of(&with), ops_of(&without), "`always` left an instruction behind");
}

/// …and `is_true` on a WIRE does not fold: the flag is a real constraint.
/// The negative control for the test above — without it, "the same
/// instructions" would also be consistent with `c.assert` emitting nothing
/// at all.
#[test]
fn is_true_on_a_wire_is_not_folded() {
    let with = zkir(|c| {
        let w = c.arg::<FieldT>("ok");
        let flag = BoolWire::<Private>::from_field_checked(c, w);
        c.assert(minocrab_std::v3::is_true(flag));
    });
    let without = zkir(|c| {
        let w = c.arg::<FieldT>("ok");
        let _ = BoolWire::<Private>::from_field_checked(c, w);
    });
    assert!(with.contains("\"assert\""), "an assert on a wire was folded away");
    assert_ne!(ops_of(&with), ops_of(&without));
}

/// THE FIVE CALL TYPES' VERDICTS, as declared: the two ERC-20 calls read the
/// returned flag, the three numeric ones treat execution as success. A table
/// rather than a sentence, because the wrong entry here IS the
/// spurious-completion hole (notes/evm-calls.org §3) — an `Erc20Transfer`
/// whose `succeeded` emitted nothing would let an attested `false` complete.
#[test]
fn a_flag_return_is_checked_and_a_number_is_not() {
    let flag = zkir(|c| {
        let w = c.arg::<FieldT>("ok");
        let ok = BoolWire::<Private>::from_field_checked(c, w);
        let check = <Erc20Transfer as EvmCall>::succeeded(c, &ok);
        c.assert(check);
    });
    assert!(flag.contains("\"assert\""), "Erc20Transfer::succeeded emitted no assert");

    let approve = zkir(|c| {
        let w = c.arg::<FieldT>("ok");
        let ok = BoolWire::<Private>::from_field_checked(c, w);
        let check = <Erc20Approve as EvmCall>::succeeded(c, &ok);
        c.assert(check);
    });
    assert_eq!(approve, flag, "the two ERC-20 calls disagree on their verdict");

    for name in ["deposit", "redeem", "swap"] {
        let executed = zkir(|c| {
            let n = Uint::<64, Private>::from_field_unchecked(c.arg::<FieldT>("n"));
            let check = match name {
                "deposit" => <Erc4626Deposit as EvmCall>::succeeded(c, &n),
                "redeem" => <Erc4626Redeem as EvmCall>::succeeded(c, &n),
                _ => <ExactOutputSingle as EvmCall>::succeeded(c, &n),
            };
            c.assert(check);
        });
        assert!(
            !executed.contains("\"assert\""),
            "{name}: `always` left an assert behind:\n{executed}"
        );
        assert!(ops_of(&executed).is_empty(), "{name}: `always` emitted an instruction");
    }
}

/// THE MAPPING, and why `()` is the right projection for a flag: a return
/// the verdict already consumed carries nothing a settle circuit could act
/// on, so there is nothing to misread. The numeric calls keep their value,
/// and neither projection emits an instruction.
#[test]
fn a_checked_flag_maps_to_nothing_and_a_number_maps_to_itself() {
    let mut c = Circuit3::new();
    let ok = BoolWire::<Private>::from_field_unchecked(c.arg::<FieldT>("ok"));
    let projected: <Erc20Transfer as EvmCall>::Success = <Erc20Transfer as EvmCall>::map(&mut c, ok);
    assert_eq!(projected, ());

    let n = Uint::<64, Private>::from_field_unchecked(c.arg::<FieldT>("n"));
    let kept: <Erc4626Deposit as EvmCall>::Success = <Erc4626Deposit as EvmCall>::map(&mut c, n);
    assert_eq!(
        format!("{:?}", kept.field().val()),
        format!("{:?}", n.field().val()),
        "the identity projection moved the wire"
    );

    let before = zkir(|c| {
        let _ = c.arg::<FieldT>("n");
    });
    let after = zkir(|c| {
        let n = Uint::<64, Private>::from_field_unchecked(c.arg::<FieldT>("n"));
        let _ = <Erc4626Deposit as EvmCall>::map(c, n);
    });
    assert_eq!(before, after, "the identity projection emitted an instruction");
}
