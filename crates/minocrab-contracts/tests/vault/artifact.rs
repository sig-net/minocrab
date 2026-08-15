//! The four artifacts the harness gates, and where each forked circuit
//! stands relative to the artifact it was forked from.
//!
//! M10 forks the vault (§Sequencing step 4): `erc20_vault` stays the
//! COMPATIBILITY reference — frozen rows, PI-equal to compactc — and
//! `erc20_vault_opt` is where optimizations land. M11 stage 4 forks again:
//! `erc20_vault_borsh` starts byte-identical to the optimized fork and is
//! where the Borsh WIRE-FORMAT changes land, so the optimized artifact's
//! measured M10 ladder is not reopened. Everything below the artifact
//! boundary (specs, scenarios, sweeps) is written once and run three times,
//! selected by [`Art`]; the concretization of the spec's discretionary terms
//! is likewise selected by [`Art`] (see [`super::prims`]), so the set of
//! non-`Compat` arms IS the deviation log.
//!
//! [`Fork`] is the other half, and there are now three ledgers because there
//! are three forks:
//!
//! - [`fork_status`] — opt vs the direct port. An opt circuit that is still
//!   byte-identical inherits the port's compactc PI-equality differential;
//!   one that has diverged does not. Asserted both ways in
//!   `tests/erc20_vault_opt_fork.rs`.
//! - [`borsh_fork_status`] — borsh vs opt. Same discipline one link further
//!   along the chain `compactc ≡ port ≡ opt ≡ borsh`, asserted both ways in
//!   `tests/erc20_vault_borsh_fork.rs`.
//! - [`modern_fork_status`] — the twin vs borsh, and the one ledger whose
//!   entries are NOT about byte-identity ([`Twin`]): a rewritten circuit
//!   inherits the borsh fork's coverage because it proves the same statement
//!   (same typed I/O schema, same `pis`/`pi_skips` on the same preimage), and
//!   `tests/erc20_vault_modern_fork.rs` asserts exactly that, in both
//!   directions.
//!
//! Recording that per circuit — and asserting BOTH directions — is what makes
//! the moment a circuit leaves its predecessor's coverage an explicit,
//! reviewed edit rather than a silent one.

use minocrab::v3::Compiled3;
use minocrab_contracts::{erc20_vault, erc20_vault_borsh, erc20_vault_modern, erc20_vault_opt};
use minocrab_zkir::v3::IrSource;

/// Which artifact a case runs against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Art {
    /// `erc20_vault` — the direct ports, PI-equal to compactc.
    Compat,
    /// `erc20_vault_opt` — the M10 optimized fork.
    Opt,
    /// `erc20_vault_borsh` — the M11 Borsh fork of the optimized vault.
    Borsh,
    /// `erc20_vault_modern` — the M9 phase 8 SHOWCASE TWIN: the borsh fork's
    /// contract, written through the whole M9 API. Same semantics, same wire
    /// format, different instruction stream.
    Modern,
}

/// Every artifact, for the suites that run every case once per artifact.
pub const ARTS: [Art; 4] = [Art::Compat, Art::Opt, Art::Borsh, Art::Modern];

impl Art {
    pub fn name(self) -> &'static str {
        match self {
            Art::Compat => "erc20_vault",
            Art::Opt => "erc20_vault_opt",
            Art::Borsh => "erc20_vault_borsh",
            Art::Modern => "erc20_vault_modern",
        }
    }

    /// Does this artifact carry M11's Borsh wire format?
    ///
    /// The twin IMPORTS the borsh fork's response types rather than restating
    /// them, so every place the harness asks "is this the Borsh format?" has
    /// to ask THIS and not `== Art::Borsh` — the one hazard of adding a
    /// fourth artifact that the compiler cannot point at (an `==` still
    /// compiles; a non-exhaustive `match` does not).
    pub fn is_borsh_format(self) -> bool {
        matches!(self, Art::Borsh | Art::Modern)
    }
}

/// One vault circuit, named independently of the artifact that builds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Circuit {
    Initialize,
    Deposit,
    Claim,
    ApproveRouter,
    Withdraw,
    CompleteWithdraw,
    Refund,
    Swap,
    CompleteSwap,
}

impl Circuit {
    pub const ALL: [Circuit; 9] = [
        Circuit::Initialize,
        Circuit::Deposit,
        Circuit::Claim,
        Circuit::ApproveRouter,
        Circuit::Withdraw,
        Circuit::CompleteWithdraw,
        Circuit::Refund,
        Circuit::Swap,
        Circuit::CompleteSwap,
    ];

    /// The compactc `.zkir` stem — also the dumped preimage stem the
    /// benchmark harness reads.
    pub fn zkir_name(self) -> &'static str {
        match self {
            Circuit::Initialize => "initialize",
            Circuit::Deposit => "deposit",
            Circuit::Claim => "claim",
            Circuit::ApproveRouter => "approveRouter",
            Circuit::Withdraw => "withdraw",
            Circuit::CompleteWithdraw => "completeWithdraw",
            Circuit::Refund => "refund",
            Circuit::Swap => "swap",
            Circuit::CompleteSwap => "completeSwap",
        }
    }

    pub fn build(self, art: Art) -> Compiled3 {
        match (art, self) {
            (Art::Compat, Circuit::Initialize) => erc20_vault::initialize(),
            (Art::Compat, Circuit::Deposit) => erc20_vault::deposit(),
            (Art::Compat, Circuit::Claim) => erc20_vault::claim(),
            (Art::Compat, Circuit::ApproveRouter) => erc20_vault::approve_router(),
            (Art::Compat, Circuit::Withdraw) => erc20_vault::withdraw(),
            (Art::Compat, Circuit::CompleteWithdraw) => erc20_vault::complete_withdraw(),
            (Art::Compat, Circuit::Refund) => erc20_vault::refund(),
            (Art::Compat, Circuit::Swap) => erc20_vault::swap(),
            (Art::Compat, Circuit::CompleteSwap) => erc20_vault::complete_swap(),
            (Art::Opt, Circuit::Initialize) => erc20_vault_opt::initialize(),
            (Art::Opt, Circuit::Deposit) => erc20_vault_opt::deposit(),
            (Art::Opt, Circuit::Claim) => erc20_vault_opt::claim(),
            (Art::Opt, Circuit::ApproveRouter) => erc20_vault_opt::approve_router(),
            (Art::Opt, Circuit::Withdraw) => erc20_vault_opt::withdraw(),
            (Art::Opt, Circuit::CompleteWithdraw) => erc20_vault_opt::complete_withdraw(),
            (Art::Opt, Circuit::Refund) => erc20_vault_opt::refund(),
            (Art::Opt, Circuit::Swap) => erc20_vault_opt::swap(),
            (Art::Opt, Circuit::CompleteSwap) => erc20_vault_opt::complete_swap(),
            (Art::Borsh, Circuit::Initialize) => erc20_vault_borsh::initialize(),
            (Art::Borsh, Circuit::Deposit) => erc20_vault_borsh::deposit(),
            (Art::Borsh, Circuit::Claim) => erc20_vault_borsh::claim(),
            (Art::Borsh, Circuit::ApproveRouter) => erc20_vault_borsh::approve_router(),
            (Art::Borsh, Circuit::Withdraw) => erc20_vault_borsh::withdraw(),
            (Art::Borsh, Circuit::CompleteWithdraw) => erc20_vault_borsh::complete_withdraw(),
            (Art::Borsh, Circuit::Refund) => erc20_vault_borsh::refund(),
            (Art::Borsh, Circuit::Swap) => erc20_vault_borsh::swap(),
            (Art::Borsh, Circuit::CompleteSwap) => erc20_vault_borsh::complete_swap(),
            (Art::Modern, Circuit::Initialize) => erc20_vault_modern::initialize(),
            (Art::Modern, Circuit::Deposit) => erc20_vault_modern::deposit(),
            (Art::Modern, Circuit::Claim) => erc20_vault_modern::claim(),
            (Art::Modern, Circuit::ApproveRouter) => erc20_vault_modern::approve_router(),
            (Art::Modern, Circuit::Withdraw) => erc20_vault_modern::withdraw(),
            (Art::Modern, Circuit::CompleteWithdraw) => erc20_vault_modern::complete_withdraw(),
            (Art::Modern, Circuit::Refund) => erc20_vault_modern::refund(),
            (Art::Modern, Circuit::Swap) => erc20_vault_modern::swap(),
            (Art::Modern, Circuit::CompleteSwap) => erc20_vault_modern::complete_swap(),
        }
    }

    pub fn ir(self, art: Art) -> IrSource {
        self.build(art).ir
    }
}

/// Where a forked circuit stands relative to the artifact it was forked
/// from — the port for [`fork_status`], the optimized vault for
/// [`borsh_fork_status`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fork {
    /// Byte-identical to the predecessor, so whatever covers the
    /// predecessor covers this circuit transitively, and the fork test runs
    /// it to say so out loud.
    Identical,
    /// Deliberately different since `rung`. The predecessor's differential
    /// no longer applies — the gates are the spec harness (acceptance
    /// agreement, ledger effects), PI-equality RE-ANCHORED to this
    /// artifact's reference model, and the adversarial sweeps.
    Diverged {
        rung: &'static str,
        why: &'static str,
    },
}

/// THE OPT DIVERGENCE LEDGER. Moving an entry from `Identical` to `Diverged` is
/// the moment a circuit leaves compactc's coverage; it is a deliberate edit,
/// reviewed with the rung that causes it, and the fork test asserts the
/// ledger against the built artifacts in both directions.
pub fn fork_status(circuit: Circuit) -> Fork {
    /// Rung (i): one `kernel.self()` read per circuit instead of one per
    /// stdlib call site.
    const DEDUP: &str = "kernel.self() read once per circuit and threaded";
    /// Rung (iii): the token domain separator is encoded, not hashed.
    const SEPARATOR: &str = "vaultTokenDomainSeparator is an injective encoding, not a SHA-256";
    /// Rung 5(i-userCommit): the identity commitment is a one-block SHA.
    const USERCOMMIT: &str = "userCommitment is a one-block SHA (short preimage), not two";
    let diverged = |rung, why| Fork::Diverged { rung, why };
    match circuit {
        // Rung 5(i-userCommit) alone: only the short identity commitment
        // touches initialize.
        Circuit::Initialize => {
            diverged("M10 rung 5(i-userCommit), avenue 1", USERCOMMIT)
        }
        Circuit::ApproveRouter => diverged("M10 rung (i), avenue 7", DEDUP),
        Circuit::Deposit => diverged(
            "M10 rungs (i)+5(i-userCommit), avenues 7+1",
            "kernel.self() threaded; userCommitment one-block",
        ),
        Circuit::Claim => diverged(
            "M10 rungs (iii)+5(i-userCommit), avenues 2+1",
            "separator encoded; userCommitment one-block",
        ),
        Circuit::CompleteWithdraw => diverged(
            "M10 rungs (iii)+5(v), avenues 2+3",
            "separator encoded; refund commitment Poseidon",
        ),
        Circuit::Refund => diverged(
            "M10 rungs (i)+(iii)+5(iv)+5(v), avenues 7+2+4+3",
            "kernel.self() threaded; separator encoded; branch re-mint merged (one commitment hash + one mint, cond_selected inputs); refund commitment Poseidon",
        ),
        Circuit::Withdraw | Circuit::Swap => diverged(
            "M10 rungs (i)+(iii)+(vi)+5(v), avenues 7+2+6+3",
            "kernel.self() threaded; separator encoded; burn = single claimed spend, no receive/nullifier; refund commitment Poseidon",
        ),
        Circuit::CompleteSwap => diverged(
            "M10 rungs (i)+(ii)+(iii)+5(v), avenues 7+5+2+3",
            "kernel.self() threaded; changeNonce derived; separator encoded; refund commitment Poseidon",
        ),
    }
}

/// THE TWIN'S LEDGER — `erc20_vault_modern` against `erc20_vault_borsh`, and
/// the third link that has to be declared rather than discovered.
///
/// It records something the two earlier ledgers never had to: a circuit that
/// is NOT byte-identical to its predecessor and still inherits everything the
/// predecessor has. That is the phase-8 claim, and [`Twin::PiEqual`] is where
/// it is written down per circuit — asserted in BOTH directions in
/// `tests/erc20_vault_modern_fork.rs`, which is stricter than the earlier
/// fork tests: a `PiEqual` entry must really differ in bytes AND really agree
/// on `pis`/`pi_skips` for the SAME `ProofPreimage`.
pub fn modern_fork_status(circuit: Circuit) -> Twin {
    /// Every circuit is rewritten the same way, so the reason is one string.
    const MODERN: &str = "the M9 API's spelling: guard-free ledger methods (the Impact guard is \
                          the immediate 1, not a named wire), typed cells and a typed \
                          Secp256k1Point cell, predicates for the boolean and in-branch checks, \
                          literal operands where a constant was named only to be compared";
    let _ = circuit;
    Twin::PiEqual { why: MODERN }
}

/// Where a rewritten circuit stands relative to the artifact it was rewritten
/// from, for a fork whose point is NOT byte-identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Twin {
    /// Byte-identical: the rewrite did not reach this circuit.
    Identical,
    /// The stream differs, and the STATEMENT does not: same typed I/O schema,
    /// and the same `pis`/`pi_skips` on the same preimage. That is the M3/M4
    /// equivalence criterion (notes/ledger-abi.org §6), which is exactly what
    /// leaves the instruction stream free — so the predecessor's coverage
    /// (the spec harness, the sweeps, and transitively whatever covers IT)
    /// applies unchanged.
    PiEqual { why: &'static str },
    /// The PIs differ too, so nothing transfers: only the spec harness run
    /// against this artifact's own reference model covers the circuit.
    /// Unused today, and the fork test asserts that it is unused rather than
    /// assumed — a rewrite that moved a PI would have to say so here.
    SpecAnchored { why: &'static str },
}

/// THE BORSH DIVERGENCE LEDGER — `erc20_vault_borsh` against
/// `erc20_vault_opt`, the second fork and the second link that has to be
/// declared rather than discovered.
///
/// At M11 stage 4 every entry was `Identical`: the borsh artifact was a
/// byte-identical fork, so it inherited the whole chain (`compactc ≡ port ≡
/// opt`) transitively. M11's later stages move entries here — never in
/// [`fork_status`], which is M10's ledger and is closed.
pub fn borsh_fork_status(circuit: Circuit) -> Fork {
    /// Stage 5: the attested output is a kind-tagged Borsh subset type.
    const ATTESTED: &str = "attested output is {kind, …} in Borsh, not an opaque byte string: \
                            the digest preimage carries the response kind, and completeWithdraw's \
                            success is a Borsh bool (0x02 is unprovable, not a refund)";
    let diverged = |rung, why| Fork::Diverged { rung, why };
    match circuit {
        // The five non-settle circuits are untouched by the response format.
        Circuit::Initialize
        | Circuit::Deposit
        | Circuit::ApproveRouter
        | Circuit::Withdraw
        | Circuit::Swap => Fork::Identical,
        Circuit::Claim | Circuit::CompleteWithdraw | Circuit::CompleteSwap | Circuit::Refund => {
            diverged("M11 stage 5, attested outputs", ATTESTED)
        }
    }
}
