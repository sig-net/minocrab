//! The callees' interfaces, hand-written.
//!
//! One handle struct per contract we call, with one typed method per callee
//! circuit. This is what M12 stage 3's `#[interface]` attribute will
//! GENERATE from a bodyless trait, and stage 4 will move into published
//! interface crates — written out by hand first, so the expansion has a
//! target that is known to work and known to be zero-movement.
//!
//! What every handle looks like, and why:
//!
//! - an [`EntryPoint`] const per circuit, DERIVED from the Compact name
//!   (never a hand-typed 32-byte key: `EntryPoint::hash` calls upstream's
//!   `EntryPointBuf::ep_hash`);
//! - `at_field(index)` — the callee's address lives in a sealed ledger
//!   cell, re-read fresh at every call site, as compactc does;
//! - `at(address)` — the callee's address is data the caller holds;
//! - `pin(c, guard)` — resolve an `at_field` handle's address NOW, for the
//!   one shape where compactc's receiver-first evaluation order is visible
//!   (see [`Callee::pin`]);
//! - typed methods over [`minocrab_ledger::call`], whose parameters are the
//!   callee's Compact parameters at `Public`. Passing a value
//!   cross-contract discloses it, so a private value has to `disclose()`
//!   first and forgetting is a compile error.
//!
//! AN INTERFACE CRATE NEVER CONTAINS AN ADDRESS. These handles carry a
//! [`Callee`], which is a ledger field index or a runtime address — the
//! deployment's business, not the interface's.

use minocrab::v3::{Circuit3, FieldT, Wire3};
use minocrab::{Public, Visibility};
use minocrab_ledger::{call, Callee, EntryPoint};
use minocrab_std::v3::{BytesN, ContractAddress, ShieldedCoinInfo3, Uint, B32};

use crate::signet::Notification;

/// The Signet singleton (`packages/signet-midnight/src/Signet.compact`), as
/// the erc20-vault declares it: `contract SignetSigner { circuit
/// signBidirectional(requestId: Bytes<32>, notification:
/// SignBidirectionalEventNotification): []; }`.
#[derive(Clone, Copy)]
pub struct SignetSigner {
    callee: Callee,
}

impl SignetSigner {
    pub const SIGN_BIDIRECTIONAL: EntryPoint = EntryPoint::new("signBidirectional");

    /// The signer's address lives in ledger field `index` (the vault's
    /// `export sealed ledger signetSigner`).
    pub const fn at_field(index: u8) -> SignetSigner {
        SignetSigner {
            callee: Callee::Field(index),
        }
    }

    /// The signer's address as data.
    pub fn at(address: ContractAddress<Public>) -> SignetSigner {
        SignetSigner {
            callee: Callee::Pinned(address.limbs()),
        }
    }

    /// Resolve an [`Self::at_field`] handle's address now.
    pub fn pin<V: Visibility + Copy>(
        self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, V>,
    ) -> SignetSigner {
        SignetSigner {
            callee: self.callee.pin(c, guard),
        }
    }

    /// `signetSigner.signBidirectional(requestId, notification)`.
    pub fn sign_bidirectional<V: Visibility + Copy>(
        self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, V>,
        request_id: B32<Public>,
        notification: Notification<Public>,
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

/// The `xcontract-events` token: `contract Token { circuit deposit(amount:
/// Uint<128>, caller: ContractAddress): Bytes<32>; }` — the one callee in
/// the corpus with a RETURN VALUE, and so the one that exercises
/// `CallResult`.
#[derive(Clone, Copy)]
pub struct Token {
    callee: Callee,
}

impl Token {
    pub const DEPOSIT: EntryPoint = EntryPoint::new("deposit");

    pub const fn at_field(index: u8) -> Token {
        Token {
            callee: Callee::Field(index),
        }
    }

    pub fn at(address: ContractAddress<Public>) -> Token {
        Token {
            callee: Callee::Pinned(address.limbs()),
        }
    }

    pub fn pin<V: Visibility + Copy>(self, c: &mut Circuit3, guard: Wire3<FieldT, V>) -> Token {
        Token {
            callee: self.callee.pin(c, guard),
        }
    }

    /// `token.deposit(amount, caller) -> Bytes<32>` — the returned event
    /// hash. Its `[Bits(8), Bits(248)]` result constraints are DERIVED from
    /// `B32`'s ABI, not written here.
    pub fn deposit<V: Visibility + Copy>(
        self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, V>,
        amount: Uint<128, Public>,
        caller: ContractAddress<Public>,
    ) -> B32<Public> {
        call(c, guard, self.callee, Self::DEPOSIT, (amount, caller))
    }
}

/// The `xcall` experiment's target: `contract Target { circuit
/// deposit/depositEmit(recipient: Bytes<32>, amount: Uint<128>): [];
/// circuit depositBig(data: Bytes<256>): []; }`.
///
/// `deposit` and `depositEmit` differ ONLY in the entry point claimed —
/// which is a prover-supplied witness — so the two methods build the same
/// circuit. That is the honest limit #1 of the design, visible in the API.
#[derive(Clone, Copy)]
pub struct XcallTarget {
    callee: Callee,
}

impl XcallTarget {
    pub const DEPOSIT: EntryPoint = EntryPoint::new("deposit");
    pub const DEPOSIT_EMIT: EntryPoint = EntryPoint::new("depositEmit");
    pub const DEPOSIT_BIG: EntryPoint = EntryPoint::new("depositBig");

    pub const fn at_field(index: u8) -> XcallTarget {
        XcallTarget {
            callee: Callee::Field(index),
        }
    }

    pub fn at(address: ContractAddress<Public>) -> XcallTarget {
        XcallTarget {
            callee: Callee::Pinned(address.limbs()),
        }
    }

    pub fn pin<V: Visibility + Copy>(
        self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, V>,
    ) -> XcallTarget {
        XcallTarget {
            callee: self.callee.pin(c, guard),
        }
    }

    pub fn deposit<V: Visibility + Copy>(
        self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, V>,
        recipient: B32<Public>,
        amount: Uint<128, Public>,
    ) {
        call(c, guard, self.callee, Self::DEPOSIT, (recipient, amount))
    }

    pub fn deposit_emit<V: Visibility + Copy>(
        self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, V>,
        recipient: B32<Public>,
        amount: Uint<128, Public>,
    ) {
        call(
            c,
            guard,
            self.callee,
            Self::DEPOSIT_EMIT,
            (recipient, amount),
        )
    }

    pub fn deposit_big<V: Visibility + Copy>(
        self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, V>,
        data: BytesN<Public, 256>,
    ) {
        call(c, guard, self.callee, Self::DEPOSIT_BIG, (data,))
    }
}

/// The `xcall-with-payment` target: `contract Target { circuit notify(coin:
/// ShieldedCoinInfo): []; circuit confirmRequest(requestId: Bytes<32>): [];
/// }`.
#[derive(Clone, Copy)]
pub struct PaymentTarget {
    callee: Callee,
}

impl PaymentTarget {
    pub const NOTIFY: EntryPoint = EntryPoint::new("notify");
    pub const CONFIRM_REQUEST: EntryPoint = EntryPoint::new("confirmRequest");

    pub const fn at_field(index: u8) -> PaymentTarget {
        PaymentTarget {
            callee: Callee::Field(index),
        }
    }

    pub fn at(address: ContractAddress<Public>) -> PaymentTarget {
        PaymentTarget {
            callee: Callee::Pinned(address.limbs()),
        }
    }

    pub fn pin<V: Visibility + Copy>(
        self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, V>,
    ) -> PaymentTarget {
        PaymentTarget {
            callee: self.callee.pin(c, guard),
        }
    }

    pub fn notify<V: Visibility + Copy>(
        self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, V>,
        coin: ShieldedCoinInfo3<Public>,
    ) {
        call(c, guard, self.callee, Self::NOTIFY, (coin,))
    }

    pub fn confirm_request<V: Visibility + Copy>(
        self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, V>,
        request_id: B32<Public>,
    ) {
        call(
            c,
            guard,
            self.callee,
            Self::CONFIRM_REQUEST,
            (request_id,),
        )
    }
}
