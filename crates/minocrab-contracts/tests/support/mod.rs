//! Shared test support. Not a test target (lives in a subdirectory).
//!
//! Compiled into every test binary that declares `mod support`, each of
//! which uses only the part it needs — hence the blanket `dead_code`
//! allowance.
#![allow(dead_code)]

use midnight_transient_crypto::proofs::ProofPreimage;

use minocrab::v3::Compiled3;
use minocrab_contracts::{
    attest, erc20_vault, erc20_vault_borsh, erc20_vault_opt, events, hashing, mint_tokens,
    serde_builtin, signet_contract, test_caller, xcall, xcall_with_payment, xcontract_events,
};

/// A circuit under snapshot: its name and how to build it.
pub type Circuit = (&'static str, fn() -> Compiled3);

/// Every circuit the workspace builds, in snapshot order. Shared by the
/// snapshot guards (`row_snapshot`, `interface_snapshot`) so both cover
/// exactly the same set; their frozen tables stay independent.
pub fn circuits() -> Vec<Circuit> {
    macro_rules! c {
        ($name:literal, $f:expr) => {
            ($name, { $f } as fn() -> Compiled3)
        };
    }
    vec![
        c!("erc20_vault::initialize", || erc20_vault::initialize()),
        c!("erc20_vault::deposit", || erc20_vault::deposit()),
        c!("erc20_vault::claim", || erc20_vault::claim()),
        c!("erc20_vault::approve_router", || erc20_vault::approve_router()),
        c!("erc20_vault::withdraw", || erc20_vault::withdraw()),
        c!("erc20_vault::complete_withdraw", || erc20_vault::complete_withdraw()),
        c!("erc20_vault::refund", || erc20_vault::refund()),
        c!("erc20_vault::swap", || erc20_vault::swap()),
        c!("erc20_vault::complete_swap", || erc20_vault::complete_swap()),
        // erc20-vault, OPTIMIZED (M10 step 4): the same nine circuits from the
        // forked artifact. At the forking commit every row and every interface
        // line below is identical to the port's; later M10 rungs move the rows
        // of this block ONLY — a moved port row means an optimization leaked
        // into the compatibility reference.
        c!("erc20_vault_opt::initialize", || erc20_vault_opt::initialize()),
        c!("erc20_vault_opt::deposit", || erc20_vault_opt::deposit()),
        c!("erc20_vault_opt::claim", || erc20_vault_opt::claim()),
        c!("erc20_vault_opt::approve_router", || erc20_vault_opt::approve_router()),
        c!("erc20_vault_opt::withdraw", || erc20_vault_opt::withdraw()),
        c!("erc20_vault_opt::complete_withdraw", || erc20_vault_opt::complete_withdraw()),
        c!("erc20_vault_opt::refund", || erc20_vault_opt::refund()),
        c!("erc20_vault_opt::swap", || erc20_vault_opt::swap()),
        c!("erc20_vault_opt::complete_swap", || erc20_vault_opt::complete_swap()),
        // erc20-vault, BORSH (M11 stage 4): the same nine circuits again, forked
        // from the OPTIMIZED artifact. At the forking commit every row and every
        // interface line below is identical to the opt block's; M11's format
        // changes move the rows of this block ONLY.
        c!("erc20_vault_borsh::initialize", || erc20_vault_borsh::initialize()),
        c!("erc20_vault_borsh::deposit", || erc20_vault_borsh::deposit()),
        c!("erc20_vault_borsh::claim", || erc20_vault_borsh::claim()),
        c!("erc20_vault_borsh::approve_router", || erc20_vault_borsh::approve_router()),
        c!("erc20_vault_borsh::withdraw", || erc20_vault_borsh::withdraw()),
        c!("erc20_vault_borsh::complete_withdraw", || erc20_vault_borsh::complete_withdraw()),
        c!("erc20_vault_borsh::refund", || erc20_vault_borsh::refund()),
        c!("erc20_vault_borsh::swap", || erc20_vault_borsh::swap()),
        c!("erc20_vault_borsh::complete_swap", || erc20_vault_borsh::complete_swap()),
        c!("signet_contract::sign_bidirectional", || signet_contract::sign_bidirectional()),
        c!("signet_contract::respond", || signet_contract::respond()),
        c!("signet_contract::respond_bidirectional", || {
            signet_contract::respond_bidirectional()
        }),
        c!("attest::map_only", || attest::map_only()),
        c!("attest::verify_only", || attest::verify_only()),
        c!("attest::sha_verify", || attest::sha_verify()),
        c!("attest::keccak_verify", || attest::keccak_verify()),
        c!("events::base", || events::base()),
        c!("events::emit_n(1)", || events::emit_n(1)),
        c!("events::emit_n(2)", || events::emit_n(2)),
        c!("events::emit_n(4)", || events::emit_n(4)),
        c!("hashing::control(32)", || hashing::control(32)),
        c!("hashing::control(64)", || hashing::control(64)),
        c!("hashing::control(128)", || hashing::control(128)),
        c!("hashing::control(256)", || hashing::control(256)),
        c!("hashing::control(1024)", || hashing::control(1024)),
        c!("hashing::persistent(32)", || hashing::persistent(32)),
        c!("hashing::persistent(64)", || hashing::persistent(64)),
        c!("hashing::persistent(128)", || hashing::persistent(128)),
        c!("hashing::persistent(256)", || hashing::persistent(256)),
        c!("hashing::persistent(1024)", || hashing::persistent(1024)),
        c!("hashing::keccak(64)", || hashing::keccak(64)),
        c!("hashing::keccak(128)", || hashing::keccak(128)),
        c!("hashing::keccak(256)", || hashing::keccak(256)),
        c!("hashing::transient(32)", || hashing::transient(32)),
        c!("hashing::transient(256)", || hashing::transient(256)),
        c!("hashing::transient(1024)", || hashing::transient(1024)),
        c!("hashing::persistent_vec8", || hashing::persistent_vec8()),
        c!("xcall::local_base", || xcall::local_base()),
        c!("xcall::call_once", || xcall::call_once()),
        c!("xcall::call_twice", || xcall::call_twice()),
        c!("xcall::call_big", || xcall::call_big()),
        c!("xcall::target_deposit", || xcall::target_deposit()),
        c!("xcall::target_deposit_emit", || xcall::target_deposit_emit()),
        c!("xcall::target_deposit_big", || xcall::target_deposit_big()),
        c!("xcall_with_payment::call_once", || xcall_with_payment::call_once()),
        c!("xcall_with_payment::request", || xcall_with_payment::request()),
        c!("xcall_with_payment::notify", || xcall_with_payment::notify()),
        c!("xcall_with_payment::pay", || xcall_with_payment::pay()),
        c!("xcall_with_payment::confirm_request", || xcall_with_payment::confirm_request()),
        c!("xcontract_events::deposit_via_vault", || xcontract_events::deposit_via_vault()),
        c!("xcontract_events::token_deposit", || xcontract_events::token_deposit()),
        c!("mint_tokens::mint_with_recipient_argument", || {
            mint_tokens::mint_with_recipient_argument()
        }),
        c!("mint_tokens::mint_with_recipient_own_public_key", || {
            mint_tokens::mint_with_recipient_own_public_key()
        }),
        c!("serde_builtin::check_roundtrip", || serde_builtin::check_roundtrip()),
        c!("test_caller::initialise", || test_caller::initialise()),
    ]
}

/// Dump a differential test's honest, corpus-verified preimage for the
/// benchmark harness (crates/minocrab-bench): no-op unless
/// `MINOCRAB_DUMP_PREIMAGES=<dir>` is set. Both toolchains' artifacts are
/// PI-equal on these preimages, so the benchmark proves the SAME statement
/// under both.
pub fn dump_preimage(circuit: &str, pi: &ProofPreimage) {
    dump_preimage_in(None, circuit, pi)
}

/// [`dump_preimage`] into a per-side subdirectory. The optimized artifact
/// cannot share the port's preimage — it proves its own statement for the
/// same logical operation — so the benchmark reads its preimages from
/// `preimages/opt/` (crates/minocrab-bench: `Preimages::PerSide`).
pub fn dump_preimage_in(side: Option<&str>, circuit: &str, pi: &ProofPreimage) {
    let Some(dir) = std::env::var_os("MINOCRAB_DUMP_PREIMAGES") else {
        return;
    };
    let mut dir = std::path::PathBuf::from(dir);
    if let Some(side) = side {
        dir.push(side);
    }
    std::fs::create_dir_all(&dir).expect("create preimage dump dir");
    let mut buf = Vec::new();
    midnight_serialize::tagged_serialize(pi, &mut buf).expect("preimage serializes");
    std::fs::write(dir.join(format!("{circuit}.preimage")), buf).expect("preimage writes");
}
