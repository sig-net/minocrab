//! The artifact the harness gates, and the circuits it builds.
//!
//! Until M28 there were four artifacts here — the compat port and three
//! forks (`opt`, `borsh`, `modern`) — with a divergence ledger per fork.
//! The forks were RETIRED in M28 (notes/vault-refresh.org §0): upstream's
//! protocol move adopted their avenues (Poseidon commitments, per-flow
//! refunds), their compactc anchor left the corpus with the rename, and the
//! `Pending` lineage (`erc20_vault_pending`) is the API's expression of the
//! new protocol. What survives of them is a FORMAT, not a circuit: the
//! Borsh record and attestation shapes the serialization-conformance tests
//! and the `Pending` lineage carry, which is why [`Art`] keeps its variants
//! as concretization selectors for [`super::prims`] while [`ARTS`] — the
//! artifacts a case is RUN against — is the compat port alone.

use minocrab::v3::Compiled3;
use minocrab_contracts::erc20_vault;
use minocrab_zkir::v3::IrSource;

/// Which concretization a scenario models. Only [`Art::Compat`] has
/// circuits behind it; the others select the retired forks' hash
/// constructions and record formats in [`super::prims`] and
/// [`super::model`], which the format tests still exercise.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Art {
    /// `erc20_vault` — the direct ports, PI-equal to compactc.
    Compat,
    /// The M10 optimized constructions (no circuit since M28).
    Opt,
    /// The M11 Borsh wire format over the optimized constructions (no
    /// circuit since M28; the `Pending` lineage carries the format).
    Borsh,
    /// The M9 phase-8 twin of the borsh fork (no circuit since M28).
    Modern,
}

/// Every artifact a case is RUN against.
pub const ARTS: [Art; 1] = [Art::Compat];

impl Art {
    pub fn name(self) -> &'static str {
        match self {
            Art::Compat => "erc20_vault",
            Art::Opt => "erc20_vault_opt (retired)",
            Art::Borsh => "erc20_vault_borsh (retired)",
            Art::Modern => "erc20_vault_modern (retired)",
        }
    }

    /// Does this concretization carry M11's Borsh wire format?
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
            (Art::Opt | Art::Borsh | Art::Modern, _) => panic!(
                "{}: the fork circuits were retired in M28 (notes/vault-refresh.org §0); \
                 only their concretization survives, in tests/vault/prims.rs",
                art.name()
            ),
        }
    }

    pub fn ir(self, art: Art) -> IrSource {
        self.build(art).ir
    }
}
