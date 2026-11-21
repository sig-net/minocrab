//! Contract events: Compact's `emit <event>`, typed.
//!
//! An event on Midnight is a value the circuit appends to the transaction's
//! public log. compactc lowers `emit` (compiler/analysis-passes/lower-emit.ss:20-27)
//! to two Impact instructions: a `push` of the MIP-0002 wrapper, the
//! three-element `Array[Cell(version: u32 as bytes<4>), Cell(tag: bytes<1>),
//! Cell(payload)]`, and then the VM `log` op. The payload is the serialized
//! event value, one `bytes<n>` atom of the declared event size.
//!
//! An event is PUBLIC output: everything in it goes into the transcript, so
//! the payload is a [`BytesN`] of [`Public`] wires, as a [`Serializer`]
//! (`finish::<N>`) or [`borsh::to_bytes`] over public values returns it. A
//! private payload is a different type and does not compile; disclose the
//! values first.
//!
//! [`Serializer`]: super::Serializer
//! [`borsh::to_bytes`]: super::borsh::to_bytes

use minocrab::v3::Circuit3;
use minocrab::Public;
use minocrab_ledger::{ImpactElem, LedgerValue};

use super::BytesN;

/// `emit <event>`: push the MIP-0002 wrapper of `version`, `tag` and
/// `payload`, then the VM `log` op — the ops of
/// [`minocrab_ledger::emit_event`], emitted with [`minocrab_ledger::emit`].
///
/// Every wire of `payload` is recorded as a disclosure of the circuit (an
/// `impact public input` statement, as for every Impact operand), and the
/// emission takes the ambient guard: inside `c.when(…)` both instructions
/// carry that scope's condition, and inside `c.when_private(…)` the call is
/// refused at build time.
///
/// ```
/// use minocrab::v3::{Circuit3, FieldT};
/// use minocrab::Public;
/// use minocrab_std::v3::{event, Serializer};
///
/// let mut c = Circuit3::new();
/// let x = c.arg::<FieldT>("x");
/// let x = c.disclose(x, "x");
/// let mut s = Serializer::<Public>::new();
/// s.push_literal(&mut c, b"name");
/// let payload = s.finish::<64>(&mut c);
/// event::emit(&mut c, 1, 0, &payload);
/// # let _ = x;
/// ```
///
/// A private payload is refused by type (the payload is `BytesN<Public, N>`,
/// and a `BytesN<Private, N>` does not unify with it):
///
/// ```compile_fail,E0308
/// use minocrab::v3::Circuit3;
/// use minocrab::Private;
/// use minocrab_std::v3::{event, Serializer};
///
/// let mut c = Circuit3::new();
/// let mut s = Serializer::<Private>::new();
/// s.push_literal(&mut c, b"name");
/// let payload = s.finish::<64>(&mut c);
/// event::emit(&mut c, 1, 0, &payload);
/// ```
#[track_caller]
pub fn emit<const N: usize>(c: &mut Circuit3, version: u32, tag: u8, payload: &BytesN<Public, N>) {
    let payload = LedgerValue::bytes(
        N as u32,
        payload.limbs().iter().map(|&w| ImpactElem::Wire(w)).collect(),
    );
    minocrab_ledger::emit(c, &minocrab_ledger::emit_event(version, tag, &payload));
}
