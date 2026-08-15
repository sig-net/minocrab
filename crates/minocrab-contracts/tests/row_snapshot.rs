//! A frozen `(k, rows)` snapshot of every circuit in this crate.
//!
//! The const-generic refactor of M7 is a TYPE-level change: the sequence,
//! order and arguments of the `Circuit3` builder calls must not move, so
//! every circuit's cost must stay bit-identical. This test is the guard —
//! it prices each circuit with the same cost model the benchmark harness
//! uses (`minocrab_sim::v3::cost`, i.e. Midnight's own model) and compares
//! against the table below, generated at the commit that introduced it.
//!
//! The twelve benchmark circuits agree with the published numbers in
//! `BENCHMARK.md`.
//!
//! To regenerate after an INTENTIONAL cost change (a toolchain bump that
//! moves lowering is one — notes/version-bump.org):
//! `cargo test --release -p minocrab-contracts --test row_snapshot -- \
//!      --ignored regenerate_row_snapshot`, or `./bump.sh accept` to run
//! every regenerator at once. It rewrites the table below in place, so the
//! new baseline arrives as a reviewable diff.

mod support;

use support::{circuits, rewrite_generated_region, test_source};

/// `(circuit, k, rows)` — frozen at "M7: freeze per-circuit (k, rows) in a
/// row-snapshot guard test".
const SNAPSHOT: &[(&str, u8, usize)] = &[
    // GENERATED BEGIN — rewritten by `regenerate_row_snapshot`
    ("erc20_vault::initialize", 13, 4272),
    ("erc20_vault::deposit", 15, 17502),
    ("erc20_vault::claim", 16, 47660),
    ("erc20_vault::approve_router", 14, 13344),
    ("erc20_vault::withdraw", 16, 42373),
    ("erc20_vault::complete_withdraw", 16, 47466),
    ("erc20_vault::refund", 16, 65231),
    ("erc20_vault::swap", 16, 51485),
    ("erc20_vault::complete_swap", 16, 65071),
    ("erc20_vault_opt::initialize", 13, 2412),
    ("erc20_vault_opt::deposit", 14, 15632),
    ("erc20_vault_opt::claim", 16, 42051),
    ("erc20_vault_opt::approve_router", 14, 13332),
    ("erc20_vault_opt::withdraw", 15, 23707),
    ("erc20_vault_opt::complete_withdraw", 16, 40157),
    ("erc20_vault_opt::refund", 16, 40806),
    ("erc20_vault_opt::swap", 16, 32819),
    ("erc20_vault_opt::complete_swap", 16, 50254),
    ("erc20_vault_borsh::initialize", 13, 2412),
    ("erc20_vault_borsh::deposit", 14, 15632),
    ("erc20_vault_borsh::claim", 16, 42057),
    ("erc20_vault_borsh::approve_router", 14, 13332),
    ("erc20_vault_borsh::withdraw", 15, 23707),
    ("erc20_vault_borsh::complete_withdraw", 16, 40163),
    ("erc20_vault_borsh::refund", 16, 40797),
    ("erc20_vault_borsh::swap", 16, 32819),
    ("erc20_vault_borsh::complete_swap", 16, 50263),
    ("erc20_vault_modern::initialize", 13, 2412),
    ("erc20_vault_modern::deposit", 14, 15632),
    ("erc20_vault_modern::claim", 16, 42057),
    ("erc20_vault_modern::approve_router", 14, 13332),
    ("erc20_vault_modern::withdraw", 15, 23707),
    ("erc20_vault_modern::complete_withdraw", 16, 40163),
    ("erc20_vault_modern::refund", 16, 40797),
    ("erc20_vault_modern::swap", 16, 32819),
    ("erc20_vault_modern::complete_swap", 16, 50263),
    ("signet_contract::sign_bidirectional", 11, 1205),
    ("signet_contract::respond", 10, 1004),
    ("signet_contract::respond_bidirectional", 10, 1004),
    ("attest::map_only", 8, 135),
    ("attest::verify_only", 15, 25276),
    ("attest::sha_verify", 16, 48988),
    ("attest::keccak_verify", 16, 51766),
    ("events::base", 8, 180),
    ("events::emit_n(1)", 9, 368),
    ("events::emit_n(2)", 10, 544),
    ("events::emit_n(4)", 10, 898),
    ("events_borsh::base", 8, 180),
    ("events_borsh::emit_n(1)", 9, 368),
    ("events_borsh::emit_n(2)", 10, 544),
    ("events_borsh::emit_n(4)", 10, 898),
    ("hashing::control(32)", 7, 118),
    ("hashing::control(64)", 8, 184),
    ("hashing::control(128)", 9, 336),
    ("hashing::control(256)", 10, 640),
    ("hashing::control(1024)", 12, 2486),
    ("hashing::persistent(32)", 13, 2013),
    ("hashing::persistent(64)", 13, 3943),
    ("hashing::persistent(128)", 13, 5975),
    ("hashing::persistent(256)", 14, 10040),
    ("hashing::persistent(1024)", 16, 34453),
    ("hashing::keccak(64)", 14, 4419),
    ("hashing::keccak(128)", 14, 4587),
    ("hashing::keccak(256)", 14, 9098),
    ("hashing::transient(32)", 8, 149),
    ("hashing::transient(256)", 10, 758),
    ("hashing::transient(1024)", 12, 2869),
    ("hashing::persistent_vec8", 14, 10147),
    ("xcall::local_base", 8, 180),
    ("xcall::call_once", 9, 297),
    ("xcall::call_twice", 9, 442),
    ("xcall::call_big", 10, 851),
    ("xcall::target_deposit", 8, 180),
    ("xcall::target_deposit_emit", 9, 368),
    ("xcall::target_deposit_big", 10, 640),
    ("xcall_with_payment::call_once", 9, 400),
    ("xcall_with_payment::request", 9, 255),
    ("xcall_with_payment::notify", 14, 11585),
    ("xcall_with_payment::pay", 14, 11687),
    ("xcall_with_payment::confirm_request", 8, 125),
    ("xcontract_events::deposit_via_vault", 9, 345),
    ("xcontract_events::token_deposit", 14, 10940),
    ("xcontract_events_borsh::token_deposit", 14, 10940),
    ("mint_tokens::mint_with_recipient_argument", 14, 9663),
    ("mint_tokens::mint_with_recipient_own_public_key", 14, 9807),
    ("serde_builtin::check_roundtrip", 15, 18408),
    ("test_caller::initialise", 13, 3984),
    ("bounded::b10", 6, 41),
    ("bounded::b300", 6, 41),
    ("bounded::b1000", 6, 41),
    ("bounded::b70000", 7, 41),
    ("bounded::b1", 6, 32),
    ("bounded::b2", 6, 33),
    ("bounded::b256", 6, 34),
    ("bounded::b255", 9, 41),
    ("bounded::b_enum", 6, 41),
    ("bounded::b_struct", 7, 120),
    ("bounded::b_compare", 7, 81),
    // GENERATED END
];

#[test]
fn every_circuit_matches_its_frozen_cost() {
    let circuits = circuits();
    assert_eq!(
        circuits.len(),
        SNAPSHOT.len(),
        "snapshot table covers {} circuits but {} are built — add the new \
         circuit to SNAPSHOT (regenerate with the `regenerate_row_snapshot` test)",
        SNAPSHOT.len(),
        circuits.len()
    );

    let mut failures = Vec::new();
    for ((name, build), &(snap_name, k, rows)) in circuits.iter().zip(SNAPSHOT) {
        assert_eq!(*name, snap_name, "snapshot table out of order");
        let (got_k, got_rows) = minocrab_sim::v3::cost(&build().ir);
        if (got_k, got_rows) != (k, rows) {
            failures.push(format!(
                "  {name}: expected k={k} rows={rows}, got k={got_k} rows={got_rows} \
                 ({:+})",
                got_rows as i64 - rows as i64
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "circuit cost changed — this refactor must be type-level only:\n{}",
        failures.join("\n")
    );
}

/// Regeneration helper: rewrites the SNAPSHOT table in this file.
#[test]
#[ignore = "regeneration helper, not a check"]
fn regenerate_row_snapshot() {
    let mut body = String::new();
    for (name, build) in circuits() {
        let (k, rows) = minocrab_sim::v3::cost(&build().ir);
        body.push_str(&format!("    (\"{name}\", {k}, {rows}),\n"));
    }
    rewrite_generated_region(&test_source("row_snapshot.rs"), &body);
}
