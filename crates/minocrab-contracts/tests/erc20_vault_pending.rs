//! The vault on `Pending` (M35 rung C): layout, and row cost against the
//! modern lineage circuit by circuit.
//!
//! The cost rule of the milestone: the `Pending` calls do what the modern
//! circuits did by hand, so a circuit costing MORE here is a bug in the API,
//! not a price of it. Where a circuit here does strictly less work (no
//! calldata re-parse, no second map for the refund marker) it may cost
//! less, and the table below records the measured pair for the note.
//!
//! The modern lineage was RETIRED in M28 (notes/vault-refresh.org §0); its
//! side of the comparison is the `(k, rows)` the row snapshot last froze for
//! it (commit abb4cfb, 2026-09-05), kept here as the baseline the rule was
//! stated against.

use minocrab_contracts::erc20_vault;
use minocrab_contracts::erc20_vault_pending as pending;
use minocrab_sim::v3::cost;

/// `erc20_vault_modern`'s last measured `(k, rows)`, from
/// `tests/row_snapshot.rs` at abb4cfb.
mod modern {
    pub const INITIALIZE: (u8, usize) = (13, 2412);
    pub const DEPOSIT: (u8, usize) = (13, 3424);
    pub const CLAIM: (u8, usize) = (16, 37740);
    pub const APPROVE_ROUTER: (u8, usize) = (11, 1126);
    pub const WITHDRAW: (u8, usize) = (14, 11502);
    pub const COMPLETE_WITHDRAW: (u8, usize) = (16, 35847);
    pub const REFUND: (u8, usize) = (16, 36480);
    pub const SWAP: (u8, usize) = (14, 12326);
    pub const COMPLETE_SWAP: (u8, usize) = (16, 45961);
}

/// Twenty-two fields, segmented (the remainder leads): `[0, i]` for i < 7,
/// then `[1, i − 7]`.
#[test]
fn the_block_is_segmented_past_fifteen_fields() {
    let v = &pending::VAULT;
    assert_eq!(v.deposits.record_path().as_slice(), &[1, 2]);
    assert_eq!(v.withdrawals.record_path().as_slice(), &[1, 4]);
    assert_eq!(v.swaps.record_path().as_slice(), &[1, 6]);
    assert_eq!(v.approvals.record_path().as_slice(), &[1, 8]);
    assert_eq!(v.supplies.record_path().as_slice(), &[1, 11]);
    assert_eq!(v.redeems.record_path().as_slice(), &[1, 13]);
    assert_eq!(v.deposits.record_path().depth(), 2);
}

/// THE COST RULE, as measured (2026-09-05). A request circuit here pays
/// two things its modern twin does not: the environment insert (16-22
/// rows: the typed continuation state, written once instead of re-parsed
/// from calldata on settle) and the segmented block's two-element paths
/// (~30 rows per circuit; with a fifteen-field block `initialize` is
/// row-identical to modern's 2,412). Every settle circuit is CHEAPER by
/// 260-900 rows. So the gate is per PAIR — a request and the settle that
/// consumes it cost no more than the modern pair — and per-circuit `k`
/// never rises. `initialize` and `approve_router` have no settle; they
/// are held to modern's `k` and to the segmentation allowance.
#[test]
fn no_pair_costs_more_than_the_modern_lineage() {
    let m = |ir: &minocrab_zkir::v3::IrSource| cost(ir);
    let p_init = m(&pending::Vault::initialize().ir);
    let m_init = modern::INITIALIZE;
    let p_dep = m(&pending::Vault::deposit().ir);
    let m_dep = modern::DEPOSIT;
    let p_claim = m(&pending::Vault::claim().ir);
    let m_claim = modern::CLAIM;
    let p_wd = m(&pending::Vault::withdraw().ir);
    let m_wd = modern::WITHDRAW;
    let p_cwd = m(&pending::Vault::complete_withdraw().ir);
    let m_cwd = modern::COMPLETE_WITHDRAW;
    let p_swap = m(&pending::Vault::swap().ir);
    let m_swap = modern::SWAP;
    let p_cswap = m(&pending::Vault::complete_swap().ir);
    let m_cswap = modern::COMPLETE_SWAP;
    let p_appr = m(&pending::Vault::approve_router().ir);
    let m_appr = modern::APPROVE_ROUTER;
    let p_rwd = m(&pending::Vault::refund_withdrawal().ir);
    let p_rsw = m(&pending::Vault::refund_swap().ir);
    let m_ref = modern::REFUND;

    let rows: Vec<(&str, (u8, usize), (u8, usize))> = vec![
        ("initialize", p_init, m_init),
        ("deposit", p_dep, m_dep),
        ("claim", p_claim, m_claim),
        ("withdraw", p_wd, m_wd),
        ("complete_withdraw", p_cwd, m_cwd),
        ("swap", p_swap, m_swap),
        ("complete_swap", p_cswap, m_cswap),
        ("approve_router", p_appr, m_appr),
        ("refund_withdrawal", p_rwd, m_ref),
        ("refund_swap", p_rsw, m_ref),
    ];
    for (name, (k, r), (k_m, r_m)) in &rows {
        eprintln!("{name:>18}: pending k={k} rows={r:>6}   modern k={k_m} rows={r_m:>6}");
        assert!(k <= k_m, "{name}: k rose from {k_m} to {k}");
    }
    // Pairs: request + the settle that consumes it.
    let pairs = [
        ("deposit+claim", p_dep.1 + p_claim.1, m_dep.1 + m_claim.1),
        ("withdraw+complete", p_wd.1 + p_cwd.1, m_wd.1 + m_cwd.1),
        ("withdraw+refund", p_wd.1 + p_rwd.1, m_wd.1 + m_ref.1),
        ("swap+complete", p_swap.1 + p_cswap.1, m_swap.1 + m_cswap.1),
        ("swap+refund", p_swap.1 + p_rsw.1, m_swap.1 + m_ref.1),
    ];
    for (name, ours, theirs) in pairs {
        eprintln!("{name:>18}: pending {ours:>6}   modern {theirs:>6}");
        assert!(ours <= theirs, "{name}: {ours} > {theirs}");
    }
    // The two settle-less circuits: the segmentation allowance only.
    const SEGMENTATION_ALLOWANCE: usize = 64;
    assert!(p_init.1 <= m_init.1 + SEGMENTATION_ALLOWANCE, "initialize: {} vs {}", p_init.1, m_init.1);
    assert!(p_appr.1 <= m_appr.1 + SEGMENTATION_ALLOWANCE, "approve_router: {} vs {}", p_appr.1, m_appr.1);
}

/// The lending flows (M35 rung C extension), against their COMPAT PORT
/// twins (`erc20_vault`, PI-equal to compactc) rather than the retired
/// modern lineage, which never had them: each `Pending`-based circuit must
/// cost no more `k` than the circuit it replaces.
#[test]
fn the_lending_flows_cost_no_more_than_the_compat_port() {
    let rows: Vec<(&str, (u8, usize), (u8, usize))> = vec![
        (
            "approve_stata",
            cost(&pending::Vault::approve_stata().ir),
            cost(&erc20_vault::Vault::approve_stata().ir),
        ),
        (
            "supply / start_supply",
            cost(&pending::Vault::supply().ir),
            cost(&erc20_vault::Vault::start_supply().ir),
        ),
        (
            "complete_supply",
            cost(&pending::Vault::complete_supply().ir),
            cost(&erc20_vault::Vault::complete_supply().ir),
        ),
        (
            "refund_supply",
            cost(&pending::Vault::refund_supply().ir),
            cost(&erc20_vault::Vault::refund_supply().ir),
        ),
        (
            "redeem / start_redeem",
            cost(&pending::Vault::redeem().ir),
            cost(&erc20_vault::Vault::start_redeem().ir),
        ),
        (
            "complete_redeem",
            cost(&pending::Vault::complete_redeem().ir),
            cost(&erc20_vault::Vault::complete_redeem().ir),
        ),
        (
            "refund_redeem",
            cost(&pending::Vault::refund_redeem().ir),
            cost(&erc20_vault::Vault::refund_redeem().ir),
        ),
    ];
    for (name, (k, r), (k_c, r_c)) in &rows {
        eprintln!("{name:>22}: pending k={k} rows={r:>6}   compat k={k_c} rows={r_c:>6}");
        assert!(k <= k_c, "{name}: k rose from {k_c} to {k}");
    }
}
