//! The vault on `Pending` (M35 rung C): layout, and row cost against the
//! modern lineage circuit by circuit.
//!
//! The cost rule of the milestone: the `Pending` calls do what the modern
//! circuits do by hand, so a circuit costing MORE here is a bug in the API,
//! not a price of it. Where a circuit here does strictly less work (no
//! calldata re-parse, no second map for the refund marker) it may cost
//! less, and the table below records the measured pair for the note.

use minocrab_contracts::{erc20_vault_modern as modern, erc20_vault_pending as pending};
use minocrab_sim::v3::cost;

/// Sixteen fields, segmented: `[0]`, then `[1, i − 1]`.
#[test]
fn the_block_is_segmented_past_fifteen_fields() {
    let v = &pending::VAULT;
    assert_eq!(v.deposits.record_path().as_slice(), &[1, 8]);
    assert_eq!(v.withdrawals.record_path().as_slice(), &[1, 10]);
    assert_eq!(v.swaps.record_path().as_slice(), &[1, 12]);
    assert_eq!(v.approvals.record_path().as_slice(), &[1, 14]);
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
    let p_init = m(&pending::initialize().ir);
    let m_init = m(&modern::initialize().ir);
    let p_dep = m(&pending::deposit().ir);
    let m_dep = m(&modern::deposit().ir);
    let p_claim = m(&pending::claim().ir);
    let m_claim = m(&modern::claim().ir);
    let p_wd = m(&pending::withdraw().ir);
    let m_wd = m(&modern::withdraw().ir);
    let p_cwd = m(&pending::complete_withdraw().ir);
    let m_cwd = m(&modern::complete_withdraw().ir);
    let p_swap = m(&pending::swap().ir);
    let m_swap = m(&modern::swap().ir);
    let p_cswap = m(&pending::complete_swap().ir);
    let m_cswap = m(&modern::complete_swap().ir);
    let p_appr = m(&pending::approve_router().ir);
    let m_appr = m(&modern::approve_router().ir);
    let p_rwd = m(&pending::refund_withdrawal().ir);
    let p_rsw = m(&pending::refund_swap().ir);
    let m_ref = m(&modern::refund().ir);

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
