//! The cross-contract call: `contract_call`, `Callee`, the `Xcall*` labels,
//! `ep_hash`.

use midnight_base_crypto::fab::AlignmentAtom;
use midnight_onchain_state::state::EntryPointBuf;
use minocrab::v3::{CallArgs, CallResult, Circuit3, Disclose, FieldT, Prim, Wire3};
use minocrab::v3::{ImpactElem, LimbConstraint};
use minocrab::{Fr, Public, Visibility};

use crate::impact::*;
use crate::kernel::*;
use crate::reads::*;

// What a cross-contract call itself discloses. A CALLER declares these in
// its own `Discloses<..>` — a call is a disclosure the caller makes, so the
// labels are part of this crate's public vocabulary rather than strings
// buried in `contract_call`.
minocrab::label! {
    pub XcallEntryPointHash = "xcall entry-point hash";
    pub XcallCommitment = "xcall communications commitment";
    pub XcallResult = "xcall result";
}


// --- cross-contract calls ---------------------------------------------------

/// One cross-contract call `target.circ(args…) → results`, exactly as
/// compactc desugars it (circuit-passes/desugar-contract-calls.ss:116-137;
/// notes/ledger-abi.org §Implementation): witness the callee's return
/// limbs, the communication randomness and the entry-point-hash limbs;
/// recompute `comm = transientHash([rand] ++ args ++ results)` in-circuit;
/// claim `(addr, entry_point, comm)` via [`kernel_claim_contract_call`].
///
/// `addr` is the callee's address (`Bytes<32>` `[hi, lo]`, from a
/// [`cell_read`] of the target field — one fresh uncached read per call
/// site — or [`kernel_self`]). `args` are the call arguments' FAB limbs in
/// order, already disclosed. `results` has one entry per FAB limb of the
/// callee's declared return type: the constraint compactc places right
/// after that limb's witness (`Bytes<32>` →
/// `[Bits(8), Bits(248)]`, `Uint<128>` → `[Bits(128)]`, a `Field` limb →
/// `None`).
///
/// The result constraints and a circuit's own ARGUMENT constraints are the
/// same table — compactc runs `emit-constraints-for` over both — so a
/// caller derives this list from the callee's return type via
/// `CircuitAbi::prims`, and [`LimbConstraint`] is that table's output type
/// rather than anything local to this function.
///
/// Returns the callee's result wires. They are disclosed: the claim binds
/// them publicly (under cc-rand hiding) via `comm`, and Compact treats
/// them as public downstream.
pub fn contract_call<V: Visibility + Copy + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    addr: [Wire3<FieldT, Public>; 2],
    args: &[Wire3<FieldT, Public>],
    results: &[LimbConstraint],
) -> Vec<Wire3<FieldT, Public>> {
    contract_call_with(c, guard, addr, args, results, None)
}

/// Marker: this circuit BINDS every cross-contract call's entry point
/// in-circuit — see [`bind_entry_points`].
pub struct BindEntryPoints;

/// Opt this circuit into HARDENED cross-contract calls: every typed
/// [`call`] after this line constrains the two witnessed entry-point-hash
/// limbs to the constants its [`EntryPoint`] hashes to — two
/// `constrain_eq`, no public input. Without it a call's entry point is a
/// prover-supplied witness (compactc's own shape, which the corpus ports
/// mirror) and any two same-shaped entry points of the callee are
/// interchangeable in the proof; the ledger's `(address, entry point,
/// commitment)` match is what binds them there (external review §4.5,
/// notes/interface-crates.org §Honest limits #1). A contract that wants
/// the proof to say which circuit it called says so here.
pub fn bind_entry_points(c: &mut Circuit3) {
    c.ext_insert(BindEntryPoints);
}

/// [`contract_call`] with the entry point BOUND: `bind` carries the hash's
/// two limbs the witnessed ones must equal.
fn contract_call_with<V: Visibility + Copy + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    addr: [Wire3<FieldT, Public>; 2],
    args: &[Wire3<FieldT, Public>],
    results: &[LimbConstraint],
    bind: Option<[Fr; 2]>,
) -> Vec<Wire3<FieldT, Public>> {
    // Every witness of the call is read UNDER THE CALL'S GUARD, as the op
    // that claims it is emitted under it: a call inside a branch consumes
    // the prover's cc-rand, entry-point limbs and results only where the
    // branch runs, or the private transcript shifts for everything after
    // it (the external review's §4.3; the same class the choke point closed
    // for the scope-based reads). Straight-line callers pass a constant
    // true, which lowers to compactc's own `guard: null`.
    let results: Vec<_> = results
        .iter()
        .map(|&constraint| {
            let w = c.witness_guarded::<FieldT, V>(guard);
            constraint.emit(c, w);
            w
        })
        .collect();
    let cc_rand = c.witness_guarded::<FieldT, V>(guard);
    let ep_hi = c.witness_guarded::<FieldT, V>(guard);
    c.assert_bits(ep_hi, 8);
    let ep_lo = c.witness_guarded::<FieldT, V>(guard);
    c.assert_bits(ep_lo, 248);
    if let Some([hi, lo]) = bind {
        // The hardened mode: the prover's entry point IS the declared one.
        c.assert_eq(ep_hi, hi);
        c.assert_eq(ep_lo, lo);
    }

    let mut preimage = vec![cc_rand];
    preimage.extend(args.iter().map(|w| w.private()));
    preimage.extend(results.iter().copied());
    let comm = c.transient_hash(&preimage);

    let [ep_hi, ep_lo] = c.disclose_all_as::<XcallEntryPointHash, _, 2>([ep_hi, ep_lo]);
    let comm = comm.disclose_as::<XcallCommitment>(c);

    let addr_ep_comm = LedgerValue::new(
        vec![
            AlignmentAtom::Bytes { length: 32 },
            AlignmentAtom::Bytes { length: 32 },
            AlignmentAtom::Field,
        ],
        vec![
            ImpactElem::Wire(addr[0]),
            ImpactElem::Wire(addr[1]),
            ImpactElem::Wire(ep_hi),
            ImpactElem::Wire(ep_lo),
            ImpactElem::Wire(comm),
        ],
    );
    emit(c, guard, &kernel_claim_contract_call(&addr_ep_comm));

    results.disclose_as::<XcallResult>(c)
}

/// WHERE a cross-contract call's target address comes from.
///
/// The two variants are the two things a Compact receiver expression can
/// be, and they lower differently:
///
/// - [`Callee::Field`] is a sealed ledger cell holding the address
///   (`export sealed ledger target: Target`). EVERY call site does its own
///   FRESH UNCACHED read: `xcall`'s `callTwice` calls the same target twice
///   in one circuit and compactc reads the cell twice, so caching the first
///   read would be a row-count difference, not an optimization.
/// - [`Callee::Pinned`] is an address the caller already holds as data
///   (`kernel.self()`, an argument, a constant, or a `Field` callee resolved
///   early with [`Callee::pin`]).
///
/// An interface crate NEVER contains an address: a deployment pins one via
/// a sealed cell or passes it as data. That is why this type has no
/// constant-address variant.
#[derive(Clone, Copy)]
pub enum Callee {
    /// The ledger field whose cell holds the callee's address.
    Field(u8),
    /// The same, by ledger field PATH (`elems[..len]`) — a block of sixteen
    /// fields or more is segmented and its fields have no single index.
    FieldPath([u8; 3], u8),
    /// The callee's address as FAB limbs `[hi, lo]`.
    Pinned([Wire3<FieldT, Public>; 2]),
}

impl Callee {
    /// Resolve the address NOW, returning a [`Callee::Pinned`].
    ///
    /// WHY THIS EXISTS: compactc evaluates a call's RECEIVER before its
    /// argument expressions; Rust evaluates the arguments before the call.
    /// Where an argument expression emits instructions — erc20-vault's
    /// `constructSignBidirectionalEventNotificationV1(kernel.self(), …)` —
    /// the two orders differ, and the public transcript is ordered, so the
    /// difference is real. A port with such an argument pins its callee at
    /// the point compactc reads it and the streams agree. Where the
    /// arguments emit nothing (every other call site in the corpus),
    /// `Field` resolved inside [`call`] gives the same stream and is the
    /// simpler spelling.
    pub fn pin<V: Visibility + Copy + minocrab::OnChainGuard>(self, c: &mut Circuit3, guard: Wire3<FieldT, V>) -> Callee {
        Callee::Pinned(self.address(c, guard))
    }

    /// The address limbs — for [`Callee::Field`], the fresh uncached read.
    fn address<V: Visibility + Copy + minocrab::OnChainGuard>(
        self,
        c: &mut Circuit3,
        guard: Wire3<FieldT, V>,
    ) -> [Wire3<FieldT, Public>; 2] {
        match self {
            Callee::Field(index) => {
                let limbs = cell_read(c, guard, index, vec![AlignmentAtom::Bytes { length: 32 }]);
                [limbs[0], limbs[1]]
            }
            Callee::FieldPath(elems, len) => {
                let path: Vec<LedgerKey> = elems[..usize::from(len)]
                    .iter()
                    .map(|&i| LedgerKey::Field(i))
                    .collect();
                let limbs = cell_read_at(c, guard, &path, vec![AlignmentAtom::Bytes { length: 32 }]);
                [limbs[0], limbs[1]]
            }
            Callee::Pinned(limbs) => limbs,
        }
    }
}

/// ONE TYPED CROSS-CONTRACT CALL: `callee.entry_point(args…) -> R`.
///
/// The whole of M12 above the desugar. [`contract_call`] takes flat limb
/// vectors and a hand-written result-constraint list; this takes the
/// callee's declared argument and result TYPES and derives both — the limb
/// order from [`CallArgs::push_call_slots`], the result constraints from
/// [`CircuitAbi::prims`](minocrab::v3::CircuitAbi::prims) run through
/// compactc's own table. A caller can no
/// longer flatten a struct in the wrong order or forget a result's range
/// check, because it never writes either down.
///
/// `entry_point` is the callee circuit's name. THE CIRCUIT DOES NOT BIND IT
/// unless it opted in with [`bind_entry_points`]
/// (notes/interface-crates.org §Honest limits #1): the entry-point hash is
/// a prover-supplied witness, which is exactly why `xcall`'s `callOnce` and
/// `callEmit` compile to the same circuit. What binds it is the LEDGER's
/// `(address, entry_point, comm)` match against the callee's own
/// transaction. Naming it here types the developer's call and tells the
/// transaction builder which circuit to run; it is not a proof obligation.
pub fn call<A: CallArgs, R: CallResult, V: Visibility + Copy + minocrab::OnChainGuard>(
    c: &mut Circuit3,
    guard: Wire3<FieldT, V>,
    callee: Callee,
    entry_point: EntryPoint,
    args: A,
) -> R {
    // Bound only where the circuit asked for it (`bind_entry_points`);
    // otherwise the entry point names the callee for the transaction
    // builder and the type checker, and the proof leaves it to the ledger.
    let bind = c
        .ext_get::<BindEntryPoints>()
        .is_some()
        .then(|| entry_point.limbs());
    let addr = callee.address(c, guard);
    let arg_slots = args.call_slots();
    let constraints: Vec<LimbConstraint> = R::prims()
        .into_iter()
        .map(Prim::constraint)
        .collect();
    let results = contract_call_with(c, guard, addr, &arg_slots, &constraints, bind);
    debug_assert_eq!(results.len(), R::SLOTS, "contract_call returned {} slots", results.len());
    R::from_call_slots(&results)
}

/// A callee circuit's ENTRY POINT: its Compact name, and the `Bytes<32>`
/// hash the ledger matches a `claimContractCall` against.
///
/// The hash is not ours to define. `EntryPointBuf::ep_hash`
/// (midnight-onchain-state `state.rs`) is the definition —
/// `persistent_commit(name, "midnight:entry-point" ‖ 12 zero bytes)` — and
/// [`EntryPoint::hash`] CALLS it. Nothing here re-derives a SHA: a
/// reimplementation that agreed today would be a silent chain-split the
/// day upstream changed the domain separator.
///
/// This is what "derive keys, don't type them" means for M12: an interface
/// declares circuit NAMES, and the 32-byte keys the claim carries fall out
/// of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryPoint(&'static str);

impl EntryPoint {
    /// The entry point of the circuit called `name` (the Compact circuit
    /// name, e.g. `"signBidirectional"`).
    pub const fn new(name: &'static str) -> EntryPoint {
        EntryPoint(name)
    }

    /// The Compact circuit name.
    pub const fn name(self) -> &'static str {
        self.0
    }

    /// The 32-byte entry-point hash.
    pub fn hash(self) -> [u8; 32] {
        ep_hash(self.0)
    }

    /// The hash's two FAB limbs, `[hi, lo]` — the witness values a
    /// [`contract_call`] site's prover supplies.
    pub fn limbs(self) -> [Fr; 2] {
        ep_limbs(self.0)
    }
}

/// [`EntryPoint::hash`] for a name known only at run time (an artifact
/// walker, a generator): upstream's own `EntryPointBuf::ep_hash`.
pub fn ep_hash(name: &str) -> [u8; 32] {
    EntryPointBuf::from(name.as_bytes()).ep_hash().0
}

/// [`EntryPoint::limbs`] for a name known only at run time.
///
/// The split is the standard `Bytes<32>` one (notes/builtin-lowering.org
/// §1): `hi` is byte 31 alone, `lo` bytes 0..30 little-endian.
pub fn ep_limbs(name: &str) -> [Fr; 2] {
    let hash = ep_hash(name);
    [
        Fr::from(u64::from(hash[31])),
        Fr::from_le_bytes(&hash[..31]).expect("31 bytes fit the native field"),
    ]
}
