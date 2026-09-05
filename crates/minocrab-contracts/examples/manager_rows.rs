//! Print `(k, rows)` for the manager port's nine circuits — the MinoCrab
//! side of the row comparison against compactc's artifacts
//! (`cargo run -p minocrab-sim --example zkircost -- corpus/zkir/aa-…/zkir/*.zkir`).

use minocrab_contracts::manager;

fn main() {
    let circuits: Vec<(&str, minocrab::v3::Compiled3)> = vec![
        ("isRegistered", manager::Manager::is_registered()),
        ("accountRecord", manager::Manager::account_record()),
        ("shieldedAccountBalance", manager::Manager::shielded_account_balance()),
        ("unshieldedAccountBalance", manager::Manager::unshielded_account_balance()),
        ("poolValue", manager::Manager::pool_value()),
        ("poolHasColour", manager::Manager::pool_has_colour()),
        ("depositUnshielded", manager::Manager::deposit_unshielded()),
        ("depositShielded", manager::Manager::deposit_shielded()),
        ("execute", manager::Manager::execute()),
    ];
    for (name, compiled) in circuits {
        let (k, rows) = minocrab_sim::v3::cost(&compiled.ir);
        println!("{name:28} k={k:2} rows={rows}");
    }
}
