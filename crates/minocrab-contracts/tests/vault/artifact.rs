//! The vault's seventeen circuits, named independently of the module that
//! builds them, with each one's compactc `.zkir` stem.
//!
//! One artifact since M28: the compat port, PI-equal to compactc's. The
//! three forks that used to sit beside it are retired
//! (notes/vault-refresh.org §0).

use minocrab::v3::Compiled3;
use minocrab_contracts::erc20_vault;
use minocrab_zkir::v3::IrSource;

/// One vault circuit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Circuit {
    Initialise,
    ApproveStata,
    ApproveRouter,
    StartDeposit,
    CompleteDeposit,
    StartWithdraw,
    CompleteWithdraw,
    RefundWithdraw,
    StartSwap,
    CompleteSwap,
    RefundSwap,
    StartSupply,
    CompleteSupply,
    RefundSupply,
    StartRedeem,
    CompleteRedeem,
    RefundRedeem,
}

impl Circuit {
    pub const ALL: [Circuit; 17] = [
        Circuit::Initialise,
        Circuit::ApproveStata,
        Circuit::ApproveRouter,
        Circuit::StartDeposit,
        Circuit::CompleteDeposit,
        Circuit::StartWithdraw,
        Circuit::CompleteWithdraw,
        Circuit::RefundWithdraw,
        Circuit::StartSwap,
        Circuit::CompleteSwap,
        Circuit::RefundSwap,
        Circuit::StartSupply,
        Circuit::CompleteSupply,
        Circuit::RefundSupply,
        Circuit::StartRedeem,
        Circuit::CompleteRedeem,
        Circuit::RefundRedeem,
    ];

    /// The compactc `.zkir` stem — also the dumped preimage stem the
    /// benchmark harness reads.
    pub fn zkir_name(self) -> &'static str {
        match self {
            Circuit::Initialise => "initialise",
            Circuit::ApproveStata => "approveStata",
            Circuit::ApproveRouter => "approveRouter",
            Circuit::StartDeposit => "startDeposit",
            Circuit::CompleteDeposit => "completeDeposit",
            Circuit::StartWithdraw => "startWithdraw",
            Circuit::CompleteWithdraw => "completeWithdraw",
            Circuit::RefundWithdraw => "refundWithdraw",
            Circuit::StartSwap => "startSwap",
            Circuit::CompleteSwap => "completeSwap",
            Circuit::RefundSwap => "refundSwap",
            Circuit::StartSupply => "startSupply",
            Circuit::CompleteSupply => "completeSupply",
            Circuit::RefundSupply => "refundSupply",
            Circuit::StartRedeem => "startRedeem",
            Circuit::CompleteRedeem => "completeRedeem",
            Circuit::RefundRedeem => "refundRedeem",
        }
    }

    pub fn build(self) -> Compiled3 {
        match self {
            Circuit::Initialise => erc20_vault::Vault::initialise(),
            Circuit::ApproveStata => erc20_vault::Vault::approve_stata(),
            Circuit::ApproveRouter => erc20_vault::Vault::approve_router(),
            Circuit::StartDeposit => erc20_vault::Vault::start_deposit(),
            Circuit::CompleteDeposit => erc20_vault::Vault::complete_deposit(),
            Circuit::StartWithdraw => erc20_vault::Vault::start_withdraw(),
            Circuit::CompleteWithdraw => erc20_vault::Vault::complete_withdraw(),
            Circuit::RefundWithdraw => erc20_vault::Vault::refund_withdraw(),
            Circuit::StartSwap => erc20_vault::Vault::start_swap(),
            Circuit::CompleteSwap => erc20_vault::Vault::complete_swap(),
            Circuit::RefundSwap => erc20_vault::Vault::refund_swap(),
            Circuit::StartSupply => erc20_vault::Vault::start_supply(),
            Circuit::CompleteSupply => erc20_vault::Vault::complete_supply(),
            Circuit::RefundSupply => erc20_vault::Vault::refund_supply(),
            Circuit::StartRedeem => erc20_vault::Vault::start_redeem(),
            Circuit::CompleteRedeem => erc20_vault::Vault::complete_redeem(),
            Circuit::RefundRedeem => erc20_vault::Vault::refund_redeem(),
        }
    }

    pub fn ir(self) -> IrSource {
        self.build().ir
    }

    /// compactc's own artifact, parsed once per circuit.
    pub fn corpus(self) -> &'static IrSource {
        use std::collections::HashMap;
        use std::sync::OnceLock;
        static TWINS: OnceLock<HashMap<Circuit, IrSource>> = OnceLock::new();
        &TWINS.get_or_init(|| {
            Circuit::ALL
                .iter()
                .map(|c| (*c, super::prims::corpus_zkir_named(c.zkir_name())))
                .collect()
        })[&self]
    }
}
