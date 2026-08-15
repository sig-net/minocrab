//! The two artifacts the harness gates, and where each opt circuit stands
//! relative to its direct port.
//!
//! M10 forks the vault (§Sequencing step 4): `erc20_vault` stays the
//! COMPATIBILITY reference — frozen rows, PI-equal to compactc — and
//! `erc20_vault_opt` is where optimizations land. Everything below the
//! artifact boundary (specs, scenarios, sweeps) is written once and run
//! twice, selected by [`Art`]; the concretization of the spec's
//! discretionary terms is likewise selected by [`Art`] (see
//! [`super::prims`]), so the set of `Art::Opt` arms IS the deviation log.
//!
//! [`Fork`] is the other half: an opt circuit that is still byte-identical
//! to its port inherits the port's compactc PI-equality differential, and
//! one that has diverged does not. Recording that per circuit — and
//! asserting BOTH directions in `tests/erc20_vault_opt_fork.rs` — is what
//! makes the moment a circuit leaves compactc's coverage an explicit,
//! reviewed edit rather than a silent one.

use minocrab::v3::Compiled3;
use minocrab_contracts::{erc20_vault, erc20_vault_opt};
use minocrab_zkir::v3::IrSource;

/// Which artifact a case runs against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Art {
    /// `erc20_vault` — the direct ports, PI-equal to compactc.
    Compat,
    /// `erc20_vault_opt` — the M10 optimized fork.
    Opt,
}

/// Both artifacts, for the suites that run every case twice.
pub const ARTS: [Art; 2] = [Art::Compat, Art::Opt];

impl Art {
    pub fn name(self) -> &'static str {
        match self {
            Art::Compat => "erc20_vault",
            Art::Opt => "erc20_vault_opt",
        }
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
        }
    }

    pub fn ir(self, art: Art) -> IrSource {
        self.build(art).ir
    }
}

/// Where an opt circuit stands relative to its direct port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fork {
    /// Byte-identical to the port. compactc's PI-equality differential
    /// therefore covers this opt circuit transitively, and
    /// `tests/erc20_vault_opt_fork.rs` runs it to say so out loud.
    Identical,
    /// Deliberately different since `rung`. compactc's differential no
    /// longer applies — the gates are the spec harness (acceptance
    /// agreement, ledger effects), PI-equality RE-ANCHORED to the opt
    /// reference model, and the adversarial sweeps.
    Diverged {
        rung: &'static str,
        why: &'static str,
    },
}

/// THE DIVERGENCE LEDGER. Moving an entry from `Identical` to `Diverged` is
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
        Circuit::CompleteWithdraw => diverged("M10 rung (iii), avenue 2", SEPARATOR),
        Circuit::Refund => {
            diverged("M10 rungs (i)+(iii), avenues 7+2", "kernel.self() threaded; separator encoded")
        }
        Circuit::Withdraw | Circuit::Swap => diverged(
            "M10 rungs (i)+(iii)+(vi), avenues 7+2+6",
            "kernel.self() threaded; separator encoded; burn = single claimed spend, no receive/nullifier",
        ),
        Circuit::CompleteSwap => diverged(
            "M10 rungs (i)+(ii)+(iii), avenues 7+5+2",
            "kernel.self() threaded; changeNonce derived; separator encoded",
        ),
    }
}
