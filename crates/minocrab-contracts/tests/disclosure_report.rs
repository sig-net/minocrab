//! The disclosure report, valued: what a real run of a real circuit made
//! public, resolved to the values it took (M9 phase 6).
//!
//! The generated set-equality tests beside each circuit check the LABELS,
//! statically and cheaply. This is the other half — the v3 twin of v2's
//! `simulate_compiled` report — and it needs a `ProofPreimage`, so it lives
//! here, on the vault harness that already builds one.
//!
//! What it pins is the whole reporting path at once: that a v3 `Disclosure3`
//! carries an `Identifier` the simulator's memory can be keyed by (before
//! phase 6 it carried `index: 0`, and every value in a v3 report would have
//! read `<not computed>`); that a `Bytes<32>` disclosed under one label
//! reports BOTH limbs under that one label; and that the values are the
//! preimage's own.

use midnight_transient_crypto::proofs::ProofPreimage;
use minocrab::v3::Compiled3;
use minocrab_contracts::erc20_vault;
use minocrab_sim::v3::simulate_compiled;

mod support;
mod vault;

use vault::model::*;

/// The golden: `startDeposit`'s disclosure report, line by line
/// (`label | kind | values`).
///
/// Regenerate with `--ignored --nocapture print_start_deposit_disclosure_report`.
const START_DEPOSIT_REPORT: &str = "\
depositor identity commitment | disclosed | -, 1a6f81ba97ed069ae2e8228f8262a7c6639207a0284600ccc6c6cefb75faa3
impact public input | statement | 01
request id | disclosed | -, 7d3772434413379766fae88e0f67c8339dfc6c27b021afc5bdb9e6bf129527
request record | disclosed | 31, 7661756c742d61646472, 04, 01, -, 1a6f81ba97ed069ae2e8228f8262a7c6639207a0284600ccc6c6cefb75faa3, -, -, -, -, -, -, a736aa, 07, 00ca9a3b, 00ac23fc06, e8fd, 65726332302d746f6b656e2d636f6e7472616374, -, 01, a9059cbb, 02, 74, 0000000000000000000000007661756c742d65766d2d616464722d32306279, 40, 000000000000000000000000000000000000000000000000000000000001e2, -, -, 6569703135353a3131313535313131, 227d5d, 5b7b226e616d65223a2273756363657373222c2274797065223a22626f6f6c, 227d5d, 5b7b226e616d65223a2273756363657373222c2274797065223a22626f6f6c
the deposited ERC20 | disclosed | 65726332302d746f6b656e2d636f6e7472616374
the deposited amount | disclosed | 40e201
xcall communications commitment | disclosed | e14745ddce19580a721a4fb11ffd11174a2c8644ca13a3ebbf07bdbe3887ba4d
xcall entry-point hash | disclosed | f3, 8f2c97ee5f46d2d83348ccfdb2b2b1fec86db22198200fd0601b8647ec443e";

fn report_lines(compiled: &Compiled3, pi: &ProofPreimage) -> Vec<String> {
    let (_run, report) = simulate_compiled(compiled, pi).expect("the circuit accepts");
    report
        .disclosures
        .iter()
        .map(|d| format!("{} | {} | {}", d.label, d.kind, d.values.join(", ")))
        .collect()
}

/// Every disclosure `startDeposit` makes, with this run's values.
#[test]
fn the_start_deposit_disclosure_report_is_valued() {
    let compiled = erc20_vault::Vault::start_deposit();
    let pi = StartDepositScenario::new().preimage();
    let lines = report_lines(&compiled, &pi);

    // Nothing resolves to `<not computed>`: every record points at a value
    // the run actually produced — the Identifier fix, in one assertion.
    assert!(
        !lines.iter().any(|l| l.contains("<not computed>")),
        "a disclosure did not resolve:\n{}",
        lines.join("\n")
    );

    // One record per LOGICAL value, however many wires it has: the identity
    // commitment and the request id report two limbs each on one line, the
    // request record its thirty-odd, the settle view's token and amount one
    // each, and the cross-contract call's two disclosures are the ledger
    // layer's own (declared by the CALLER — see `start_deposit`'s signature).
    let disclosed: Vec<&String> = lines.iter().filter(|l| l.contains("| disclosed |")).collect();
    assert_eq!(disclosed.len(), 7, "{}", lines.join("\n"));

    let golden: Vec<String> = START_DEPOSIT_REPORT.lines().map(str::to_string).collect();
    let summary = summarize(&lines);
    assert_eq!(summary, golden, "\nBUILT:\n{}\n", summary.join("\n"));
}

/// The report is long (one `statement` line per Impact input); the golden
/// keeps every `disclosed` line and one representative `statement` line.
fn summarize(lines: &[String]) -> Vec<String> {
    let mut kept: Vec<String> = Vec::new();
    let mut seen_statement = false;
    for line in lines {
        if line.contains("| statement |") {
            if seen_statement {
                continue;
            }
            seen_statement = true;
        }
        kept.push(line.clone());
    }
    kept.sort();
    kept
}

#[test]
#[ignore]
fn print_start_deposit_disclosure_report() {
    let compiled = erc20_vault::Vault::start_deposit();
    let pi = StartDepositScenario::new().preimage();
    for line in summarize(&report_lines(&compiled, &pi)) {
        println!("{line}");
    }
}
