//! Print `(k, rows)` for the manager port's nine circuits — the MinoCrab
//! side of the row comparison against compactc's artifacts
//! (`cargo run -p minocrab-sim --example zkircost -- corpus/zkir/aa-…/zkir/*.zkir`).

use minocrab_contracts::manager;

fn main() {
    let circuits: Vec<(&str, minocrab::v3::Compiled3)> = vec![
        ("isRegistered", manager::is_registered()),
        ("accountRecord", manager::account_record()),
        ("shieldedAccountBalance", manager::shielded_account_balance()),
        ("unshieldedAccountBalance", manager::unshielded_account_balance()),
        ("poolValue", manager::pool_value()),
        ("poolHasColour", manager::pool_has_colour()),
        ("depositUnshielded", manager::deposit_unshielded()),
        ("depositShielded", manager::deposit_shielded()),
        ("execute", manager::execute()),
    ];
    for (name, compiled) in circuits {
        let (k, rows) = minocrab_sim::v3::cost(&compiled.ir);
        println!("{name:28} k={k:2} rows={rows}");
    }
}
