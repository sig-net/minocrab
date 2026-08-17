//! THE TWO MAP SLOTS HAVE TWO HANDLES, AND ONLY ONE OF THEM IS RIGHT HERE.
//!
//! `SIGN_EVENT_MAP_V2` and `SWAP_EVENT_MAP_V2` are `LedgerMap::at(VAULT.<the
//! same field>.index())` — the SAME ledger slot as the deployed
//! `VAULT.sign_bidirectional_event_map` / `VAULT.swap_event_map`, re-typed to
//! the stage-7 record. That is what makes the state layout unchanged, and it
//! is also what makes the deployed handle still compile inside the stage-7
//! artifacts: `VAULT.swap_event_map.lookup(c, &id)` in `erc20_vault_borsh` is
//! well-typed and reads the slot with `SwapRecord`'s offsets, off a value that
//! is a `SwapRecordV2`. The record moved at both ends (a version byte in
//! front, a kind byte where 75 bytes of schema were), so every field it names
//! comes back shifted, and nothing in the type system says so — the two
//! handles differ only in the type parameter their aliases pin.
//!
//! So the rule is spelled at the SOURCE level, where it can be stated: inside
//! the two stage-7 files the deployed handles appear exactly twice, in the
//! `LedgerMap::at` lines that DEFINE the V2 statics, and nowhere else.
//!
//! Source-level because there is no type-level way to say it. A `Diverged`
//! entry in the fork ledger, the spec harness and the adversarial sweeps all
//! run the artifact and would catch a wrong VALUE; they would not catch a
//! circuit that reads the right slot with the wrong offsets and asserts on
//! whatever comes back, because the reference model would be written against
//! the same mistake.

/// A source file of `minocrab-contracts`.
fn contract_source(name: &str) -> (std::path::PathBuf, String) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{} is not readable: {e}", path.display()));
    (path, text)
}

/// The deployed handles, as they are spelled.
const DEPLOYED_HANDLES: [&str; 2] = ["VAULT.sign_bidirectional_event_map", "VAULT.swap_event_map"];

/// Every line of `text` naming a deployed handle: `(1-based line number, the
/// line)`.
fn handle_lines(text: &str) -> Vec<(usize, &str)> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| DEPLOYED_HANDLES.iter().any(|handle| line.contains(handle)))
        .map(|(i, line)| (i + 1, line.trim()))
        .collect()
}

/// `erc20_vault_borsh.rs` names a deployed map handle exactly twice — in the
/// two `LedgerMap::at` lines that define the V2 statics — and
/// `erc20_vault_modern.rs` never names one at all.
#[test]
fn the_stage7_artifacts_use_only_the_v2_map_statics() {
    let complaint = |path: &std::path::Path, at: usize, line: &str| {
        format!(
            "{}:{at}: `{line}`\n\
             That is the DEPLOYED handle for a slot this file fills with a stage-7 record. \
             `SIGN_EVENT_MAP_V2` and `SWAP_EVENT_MAP_V2` are the only legal spelling here: \
             they are the same ledger field, re-typed to `VaultRecordV2` / `SwapRecordV2`. \
             The deployed handle compiles and reads the same slot with the DEPLOYED record's \
             offsets — a version byte and 68-to-75 bytes of vanished schema out of step — so \
             every field it returns is the wrong limb, with no type error to say so",
            path.display()
        )
    };

    let (path, text) = contract_source("erc20_vault_borsh.rs");
    let found = handle_lines(&text);
    for (at, line) in &found {
        assert!(
            line.contains("LedgerMap::at("),
            "{}",
            complaint(&path, *at, line)
        );
    }
    assert_eq!(
        found.len(),
        2,
        "{}: expected exactly the two `LedgerMap::at` definitions of the V2 statics to name a \
         deployed map handle, found {} lines: {:?}. Fewer means the statics stopped being \
         `LedgerMap::at(VAULT.<field>.index())` — which is what keeps the state layout \
         unchanged — and this check went vacuous",
        path.display(),
        found.len(),
        found
    );

    let (path, text) = contract_source("erc20_vault_modern.rs");
    if let Some((at, line)) = handle_lines(&text).first() {
        panic!("{}", complaint(&path, *at, line));
    }
}
