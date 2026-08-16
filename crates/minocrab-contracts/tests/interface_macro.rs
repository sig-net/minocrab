//! `#[interface]` must be exactly the handles M12 stage 2 wrote by hand.
//!
//! The gate is not a token comparison but SERIALIZED ZKIR: the same circuit
//! is built twice — once through the attribute-generated handle, once
//! through a hand-written twin of the shape stage 2 committed — and the two
//! lowerings are compared byte for byte. That pins the argument limb order,
//! the result constraints and the address read, which is everything the
//! expansion decides.
//!
//! The macro's own unit tests (crates/minocrab-macros/src/interface.rs)
//! cover the error inventory and the thinness rule; this file covers what
//! the expansion MEANS.

use minocrab::v3::{Circuit3, Compiled3, FieldT, Wire3};
use minocrab::{Public, Visibility};
use minocrab_contracts::interfaces::{PaymentTarget, Token};
use signet_signer_interface::notification::construct_notification_v1;
use signet_signer_interface::{SignBidirectionalEventNotification, SignetSigner};
use xcall_target_interface::XcallTarget;
use minocrab_contracts::{xcall, xcontract_events};
use minocrab_ledger::{call, ep_hash, Callee, EntryPoint};
use minocrab_std::v3::{BytesN, ContractAddress, ShieldedCoinInfo3, Uint, B32};
use minocrab_zkir::v3::to_zkir_string;

fn zkir(compiled: &Compiled3) -> String {
    to_zkir_string(&compiled.ir).expect("IR serializes")
}

// ---- the hand-written twins (M12 stage 2's committed shape) -----------------

#[derive(Clone, Copy)]
struct HandToken {
    callee: Callee,
}

impl HandToken {
    const DEPOSIT: EntryPoint = EntryPoint::new("deposit");

    const fn at_field(index: u8) -> HandToken {
        HandToken {
            callee: Callee::Field(index),
        }
    }

    fn deposit<V: Visibility + Copy>(
        self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, V>,
        amount: Uint<128, Public>,
        caller: ContractAddress<Public>,
    ) -> B32<Public> {
        call(c, guard, self.callee, Self::DEPOSIT, (amount, caller))
    }
}

#[derive(Clone, Copy)]
struct HandSigner {
    callee: Callee,
}

impl HandSigner {
    const SIGN_BIDIRECTIONAL: EntryPoint = EntryPoint::new("signBidirectional");

    const fn at_field(index: u8) -> HandSigner {
        HandSigner {
            callee: Callee::Field(index),
        }
    }

    fn pin<V: Visibility + Copy>(self, c: &mut Circuit3, guard: Wire3<FieldT, V>) -> HandSigner {
        HandSigner {
            callee: self.callee.pin(c, guard),
        }
    }

    fn sign_bidirectional<V: Visibility + Copy>(
        self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, V>,
        request_id: B32<Public>,
        notification: SignBidirectionalEventNotification<Public>,
    ) {
        call(
            c,
            guard,
            self.callee,
            Self::SIGN_BIDIRECTIONAL,
            (request_id, notification),
        )
    }
}

#[derive(Clone, Copy)]
struct HandXcallTarget {
    callee: Callee,
}

impl HandXcallTarget {
    const DEPOSIT_BIG: EntryPoint = EntryPoint::new("depositBig");

    const fn at_field(index: u8) -> HandXcallTarget {
        HandXcallTarget {
            callee: Callee::Field(index),
        }
    }

    fn deposit_big<V: Visibility + Copy>(
        self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, V>,
        data: BytesN<Public, 256>,
    ) {
        call(c, guard, self.callee, Self::DEPOSIT_BIG, (data,))
    }
}

#[derive(Clone, Copy)]
struct HandPaymentTarget {
    callee: Callee,
}

impl HandPaymentTarget {
    const NOTIFY: EntryPoint = EntryPoint::new("notify");

    const fn at_field(index: u8) -> HandPaymentTarget {
        HandPaymentTarget {
            callee: Callee::Field(index),
        }
    }

    fn notify<V: Visibility + Copy>(
        self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, V>,
        coin: ShieldedCoinInfo3<Public>,
    ) {
        call(c, guard, self.callee, Self::NOTIFY, (coin,))
    }
}

// ---- the same circuits, both ways -------------------------------------------

/// A RESULT-carrying call: `token.deposit(amount, me) -> Bytes<32>`, whose
/// two result limbs must pick up `[Bits(8), Bits(248)]` from the type.
fn returning_call(build: impl FnOnce(&mut Circuit3, Wire3<FieldT, Public>) -> B32<Public>) -> Compiled3 {
    let mut c = Circuit3::new();
    let amount = c.arg::<FieldT>("amount");
    c.assert_bits(amount, 128);
    c.disclose(amount, "amount");
    let one = c.constant(1u64);
    let hash = build(&mut c, one);
    c.output(hash.hi, "event hash (hi)");
    c.output(hash.lo, "event hash (lo)");
    c.finish(true)
}

#[test]
fn a_returning_call_lowers_like_the_hand_written_handle() {
    let attributed = returning_call(|c, one| {
        let me = ContractAddress::from_limbs(minocrab_ledger::kernel_self(c, one));
        let amount = Uint::from_field_unchecked(pull_amount(c));
        Token::at_field(0).deposit(c, one, amount, me)
    });
    let hand = returning_call(|c, one| {
        let me = ContractAddress::from_limbs(minocrab_ledger::kernel_self(c, one));
        let amount = Uint::from_field_unchecked(pull_amount(c));
        HandToken::at_field(0).deposit(c, one, amount, me)
    });
    assert_eq!(zkir(&hand), zkir(&attributed));
}

/// The amount wire, recovered without re-declaring an argument: a constant
/// stands in, since what is under test is the CALL, not the argument.
fn pull_amount(c: &mut Circuit3) -> Wire3<FieldT, Public> {
    c.constant(7u64)
}

/// A unit-returning call with a STRUCT argument, and the `pin` shape: the
/// erc20-vault's `notify_signet`, in miniature.
fn notify_call(build: impl FnOnce(&mut Circuit3, Wire3<FieldT, Public>)) -> Compiled3 {
    let mut c = Circuit3::new();
    let id = B32 {
        hi: c.arg::<FieldT>("requestId_hi"),
        lo: c.arg::<FieldT>("requestId_lo"),
    };
    id.constrain_input(&mut c);
    let one = c.constant(1u64);
    build(&mut c, one);
    c.finish(true)
}

fn notification(c: &mut Circuit3, one: Wire3<FieldT, Public>) -> (B32<Public>, SignBidirectionalEventNotification<Public>) {
    let me = ContractAddress::from_limbs(minocrab_ledger::kernel_self(c, one));
    let id = B32::pad(c, "request-id");
    (
        id,
        construct_notification_v1::<Public>(c, &me.bytes(), 1, [1, 2, 3, 4]),
    )
}

#[test]
fn a_pinned_struct_argument_call_lowers_like_the_hand_written_handle() {
    let attributed = notify_call(|c, one| {
        let signer = SignetSigner::at_field(1).pin(c, one);
        let (id, note) = notification(c, one);
        signer.sign_bidirectional(c, one, id, note);
    });
    let hand = notify_call(|c, one| {
        let signer = HandSigner::at_field(1).pin(c, one);
        let (id, note) = notification(c, one);
        signer.sign_bidirectional(c, one, id, note);
    });
    assert_eq!(zkir(&hand), zkir(&attributed));
}

/// A nine-limb argument (`Bytes<256>`) and a five-limb struct
/// (`ShieldedCoinInfo`): the limb ORDER is what the flattening decides.
#[test]
fn multi_limb_arguments_lower_like_the_hand_written_handles() {
    let big = |hand: bool| {
        let mut c = Circuit3::new();
        let data = BytesN::<_, 256>::arg(&mut c, "data");
        data.constrain_input(&mut c);
        let data: BytesN<Public, 256> = data.map_limbs(|_, w| c.disclose(w, "data"));
        let one = c.constant(1u64);
        if hand {
            HandXcallTarget::at_field(0).deposit_big(&mut c, one, data);
        } else {
            XcallTarget::at_field(0).deposit_big(&mut c, one, data);
        }
        c.finish(true)
    };
    assert_eq!(zkir(&big(true)), zkir(&big(false)));

    let coin = |hand: bool| {
        let mut c = Circuit3::new();
        let one = c.constant(1u64);
        let value = c.constant(9u64);
        let coin = ShieldedCoinInfo3 {
            nonce: B32::pad(&mut c, "nonce"),
            color: B32::pad(&mut c, "color"),
            value,
        };
        if hand {
            HandPaymentTarget::at_field(0).notify(&mut c, one, coin);
        } else {
            PaymentTarget::at_field(0).notify(&mut c, one, coin);
        }
        c.finish(true)
    };
    assert_eq!(zkir(&coin(true)), zkir(&coin(false)));
}

// ---- what the expansion promises --------------------------------------------

/// The entry-point consts are the DERIVED hashes of the Compact names — the
/// `snake_case` → `lowerCamelCase` rule applied to the method names.
#[test]
fn entry_point_consts_are_the_derived_names() {
    assert_eq!(SignetSigner::SIGN_BIDIRECTIONAL.name(), "signBidirectional");
    assert_eq!(Token::DEPOSIT.name(), "deposit");
    assert_eq!(XcallTarget::DEPOSIT.name(), "deposit");
    assert_eq!(XcallTarget::DEPOSIT_EMIT.name(), "depositEmit");
    assert_eq!(XcallTarget::DEPOSIT_BIG.name(), "depositBig");
    assert_eq!(PaymentTarget::NOTIFY.name(), "notify");
    assert_eq!(PaymentTarget::CONFIRM_REQUEST.name(), "confirmRequest");

    assert_eq!(Token::DEPOSIT.hash(), ep_hash("deposit"));
    assert_eq!(
        SignetSigner::SIGN_BIDIRECTIONAL.hash(),
        ep_hash("signBidirectional")
    );
}

/// The ported circuits themselves still go through the handles, and the
/// two `xcall` methods still build ONE circuit (honest limit #1).
#[test]
fn the_ported_circuits_still_call_through_the_interfaces() {
    assert_eq!(
        zkir(&xcall::call_once()),
        zkir(&xcall::call_emit()),
        "depositEmit differs from deposit only in a witness"
    );
    // depositViaVault's result limbs carry the Bytes<32> constraints,
    // which is visible as two ConstrainBits right after the witnesses.
    let ir = zkir(&xcontract_events::deposit_via_vault());
    assert!(ir.contains("constrain_bits"), "{ir}");
}

/// `at(address)` and `at_field(index)` are different callees, and the
/// difference is a ledger read.
#[test]
fn at_and_at_field_differ_by_the_cell_read() {
    let build = |pinned: bool| {
        let mut c = Circuit3::new();
        let one = c.constant(1u64);
        let target = if pinned {
            let addr = ContractAddress::from_limbs([c.constant(1u64), c.constant(2u64)]);
            XcallTarget::at(addr)
        } else {
            XcallTarget::at_field(0)
        };
        let recipient = B32::pad(&mut c, "recipient");
        let amount = Uint::constant(&mut c, 5);
        target.deposit(&mut c, one, recipient, amount);
        c.finish(true)
    };
    assert_ne!(zkir(&build(true)), zkir(&build(false)));
}
