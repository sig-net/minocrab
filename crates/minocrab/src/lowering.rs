//! The per-circuit lowering state: the few choices about how a circuit is
//! lowered that no gadget can carry, because shared helpers (the vaults'
//! mint, burn and receive) reach them through core rather than through a
//! gadget a port could swap.
//!
//! The defaults are the lean choices, for a contract written in MinoCrab:
//! `kernel.self()` is read once per circuit, implied range
//! constraints are dropped and the simplification pass runs. A circuit ported from Compact, and every circuit
//! of the deployed signer, states compactc's settings explicitly, as its
//! first line, through `minocrab_compat::profile`, so none of them moves;
//! nothing else needs to touch this.

use super::Circuit;

/// How `minocrab_std::kernel::self_address` reads `kernel.self()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelfAddressReads {
    /// Every call emits a read. compactc's (it never caches), so
    /// `minocrab_compat::profile` chooses it.
    EveryCall,
    /// The first read made outside every `when` scope is kept, and later
    /// calls emit nothing. A read inside a scope is guarded (it yields the
    /// default where the guard is false), so it is never the one kept. The
    /// default.
    OncePerCircuit,
}

/// The settings. One place to add a setting: a field here, its default in
/// the `Default` impl, and compactc's value in `minocrab_compat::profile`,
/// whose struct literal is exhaustive on purpose, so it stops compiling
/// until it says what compactc does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lowering {
    /// See [`SelfAddressReads`].
    pub self_address: SelfAddressReads,
    /// Whether [`Circuit::finish`] drops a range constraint an earlier one
    /// already proved at least as tight. See
    /// [`Circuit::dedup_range_constraints`].
    pub dedup_range_constraints: bool,
    /// Whether [`Circuit::finish`] runs the simplification pass
    /// (`minocrab_ir::passes::simplify`, notes/ir-passes.org §14):
    /// pure instructions nothing reads are deleted, and an exact repeat of
    /// an earlier computation reads the earlier one's result. On by default;
    /// merging and select-folding change the stream compactc emits, so a
    /// circuit with a Compact twin turns it off through `minocrab_compat::profile`.
    pub simplify: bool,
}

impl Default for Lowering {
    fn default() -> Self {
        Lowering { self_address: SelfAddressReads::OncePerCircuit, dedup_range_constraints: true, simplify: true }
    }
}

/// What the circuit holds: the settings, and the two facts the checks need.
#[derive(Default)]
pub(super) struct LoweringState {
    pub(super) settings: Lowering,
    /// [`Circuit::set_lowering`] has run: the settings are the circuit's
    /// stated choice, not the defaults.
    chosen: bool,
    /// A gadget has emitted instructions that depend on the settings
    /// ([`Circuit::consult_lowering`]), so changing them now would leave
    /// the circuit lowered half one way and half the other.
    consulted: bool,
}

impl Circuit {
    /// This circuit's lowering settings.
    pub fn lowering(&self) -> Lowering {
        self.lowering.settings
    }

    /// Whether [`Circuit::set_lowering`] has run: the settings are a stated
    /// choice rather than the defaults.
    pub fn lowering_chosen(&self) -> bool {
        self.lowering.chosen
    }

    /// Choose this circuit's lowering. Call it first in the circuit body,
    /// before any gadget runs (`minocrab_compat::profile` is the one caller
    /// in the tree).
    ///
    /// Refused at build time once a gadget has lowered under the previous
    /// settings ([`Circuit::consult_lowering`]): the circuit would be half
    /// one lowering and half the other. A value-dependent check, so a panic
    /// rather than a compile error.
    #[track_caller]
    pub fn set_lowering(&mut self, settings: Lowering) {
        assert!(
            !self.lowering.consulted,
            "set_lowering (minocrab_compat::profile) called after a gadget already lowered \
             under this circuit's settings (a kernel.self() read). Make it the FIRST line of \
             the circuit body, before any gadget runs."
        );
        self.lowering.settings = settings;
        self.lowering.chosen = true;
    }

    /// The settings, for a gadget whose emitted instructions depend on them:
    /// recorded as relied upon, so a later [`Circuit::set_lowering`] is
    /// refused rather than silently lowering the rest differently.
    pub fn consult_lowering(&mut self) -> Lowering {
        self.lowering.consulted = true;
        self.lowering.settings
    }
}
