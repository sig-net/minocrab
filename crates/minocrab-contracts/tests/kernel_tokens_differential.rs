//! `kernel.compact` — the M17 differential: the kernel primitives and the
//! token-stdlib circuits built on them, against compactc's own artifacts
//! (notes/kernel-tokens.org).
//!
//! WHY THE FIXTURE IS OURS, measured for the fourth milestone running: across
//! the three `--feature-zkir-v3` corpus sources the kernel/token surface used
//! is `kernel.self` (25), `receiveShielded` (10), `mintShieldedToken` (7) and
//! `sendImmediateShielded` (6) — all SHIELDED, and not one v3 use of an
//! unshielded primitive, of `balance*`, of `blockTime*` or of `mergeCoin`.
//!
//! `kernel.checkpoint()` IS NOT HERE, and cannot be: compactc's ZKIR-v3
//! backend has no `ckpt` case, so a contract calling it does not compile for
//! our target at all (the v2 backend assembles it to 255). The fixture's
//! header quotes the failure.

use minocrab::v3::Compiled3;
use minocrab_contracts::kernel_tokens as kt;
use minocrab_zkir::v3::{to_zkir_string, IrSource};

/// compactc's artifact for one fixture circuit.
fn theirs(name: &str) -> IrSource {
    let path = format!(
        "{}/tests/fixtures/kernel/out/zkir/{name}.zkir",
        env!("CARGO_MANIFEST_DIR")
    );
    minocrab_zkir::v3::read_zkir(&path).expect("the pinned compactc's artifact parses")
}

/// Serialized ZKIR with every `%name.index` identifier canonicalized — the
/// same renaming every differential here uses.
fn canonical(ir: &IrSource) -> String {
    let text = to_zkir_string(ir).expect("serializes");
    let mut renames: Vec<(String, String)> = Vec::new();
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(at) = rest.find('%') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let end = rest[1..]
            .find(|ch: char| !(ch.is_alphanumeric() || ch == '_' || ch == '.'))
            .map(|i| i + 1)
            .unwrap_or(rest.len());
        let name = &rest[..end];
        let next = renames.len();
        let canon = match renames.iter().find(|(from, _)| from == name) {
            Some((_, to)) => to.clone(),
            None => {
                let to = format!("%{next}");
                renames.push((name.to_string(), to.clone()));
                to
            }
        };
        out.push_str(&canon);
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// The circuits ported so far: compactc's artifact name and our builder.
fn cases() -> Vec<(&'static str, fn() -> Compiled3)> {
    vec![
        // the nine kernel primitives that have vm-code and can be compiled
        ("kMintUnshielded", kt::k_mint_unshielded as fn() -> Compiled3),
        ("kClaimUnshieldedCoinSpend", kt::k_claim_unshielded_coin_spend),
        ("kIncUnshieldedOutputs", kt::k_inc_unshielded_outputs),
        ("kIncUnshieldedInputs", kt::k_inc_unshielded_inputs),
        ("kBalance", kt::k_balance),
        ("kBalanceLessThan", kt::k_balance_less_than),
        ("kBalanceGreaterThan", kt::k_balance_greater_than),
        ("kBlockTimeLessThan", kt::k_block_time_less_than),
        ("kBlockTimeGreaterThan", kt::k_block_time_greater_than),
        // the stdlib circuits composed from them
        ("sBlockTimeLt", kt::s_block_time_lt),
        ("sBlockTimeGte", kt::s_block_time_gte),
        ("sBlockTimeGt", kt::s_block_time_gt),
        ("sBlockTimeLte", kt::s_block_time_lte),
        ("sUnshieldedBalance", kt::s_unshielded_balance),
        ("sUnshieldedBalanceLt", kt::s_unshielded_balance_lt),
        ("sUnshieldedBalanceGte", kt::s_unshielded_balance_gte),
        ("sUnshieldedBalanceGt", kt::s_unshielded_balance_gt),
        ("sUnshieldedBalanceLte", kt::s_unshielded_balance_lte),
        ("sReceiveUnshielded", kt::s_receive_unshielded),
        // the two with a conditional auto-receive
        ("sSendUnshielded", kt::s_send_unshielded),
        ("sMintUnshieldedToken", kt::s_mint_unshielded_token),
    ]
}

/// THE HEADLINE: for every kernel primitive and every stdlib circuit ported,
/// our lowering IS compactc's — op for op, immediate for immediate.
///
/// What that pins: the effects-array slot each primitive writes (4-8), the
/// accumulator's `member`/`branch`/`idxc [stack]`/`add` upsert, the
/// zero-default in the balance lookup, the OPERAND-ORDER trick that turns a
/// `lt` into a `gt` in both `balanceGreaterThan` and `blockTimeGreaterThan`,
/// and the `cond_select(b, 0, 1)` compactc lowers `!b` to.
#[test]
fn identical_instruction_streams() {
    for (name, build) in cases() {
        assert_eq!(
            canonical(&build().ir),
            canonical(&theirs(name)),
            "{name}: our lowering differs from compactc's"
        );
    }
}

/// What the fixture compiles that is NOT yet ported, named so the gap is a
/// list rather than an absence. Each is a SHIELDED composition or a
/// conditional one; see notes/kernel-tokens.org §"As built".
const NOT_YET_PORTED: [&str; 3] = ["sMergeCoin", "sMergeCoinImmediate", "sSendShielded"];

/// Every fixture circuit is either ported or explicitly listed as not — so
/// the coverage gap cannot widen silently, which is the failure mode a
/// case-list-only test has.
#[test]
fn every_fixture_circuit_is_accounted_for() {
    let dir = format!(
        "{}/tests/fixtures/kernel/out/zkir",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut compiled: Vec<String> = std::fs::read_dir(&dir)
        .expect("the fixture is compiled")
        .map(|e| {
            e.expect("a readable entry")
                .file_name()
                .to_string_lossy()
                .trim_end_matches(".zkir")
                .to_string()
        })
        .collect();
    compiled.sort();

    let mut accounted: Vec<String> = cases()
        .iter()
        .map(|(n, _)| n.to_string())
        .chain(NOT_YET_PORTED.iter().map(|n| n.to_string()))
        .collect();
    accounted.sort();

    assert_eq!(compiled, accounted);
}
