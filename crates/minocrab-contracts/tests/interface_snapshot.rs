//! A frozen snapshot of every circuit's ORDERED interface: arguments,
//! outputs and witness reads.
//!
//! The differential comparator (`assert_call_compatible`) checks only the
//! *type* column of the input schema — and nearly every argument is a
//! `Scalar<BLS12-381>`, so a same-typed permutation of the argument list is
//! invisible to it except through PI equality on the one honest preimage it
//! runs. Argument ORDER is the real contract: it feeds the communications
//! commitment and the preimage layout, so a reorder, rename or insertion
//! silently breaks every caller. This test is the instrument that makes such
//! movement mechanically visible before the M9 port starts rewriting the
//! argument lists.
//!
//! Per circuit it freezes, in order:
//!   - `in  <label>: <type>` — one line per `IrSource::inputs` entry (the
//!     `c.arg` calls, in declaration order). The label is the declared name
//!     with the `%`/`.index` disambiguator stripped.
//!   - `out <label>: <type>` — one line per `IrSource::outputs` entry,
//!     labelled from the matching `DisclosureKind::Output` record (the IR
//!     itself carries no output names).
//!   - `wit <type>` — one line per `PrivateInput` instruction, i.e. per
//!     private-transcript read, in execution order; `(guarded)` marks a
//!     conditional read. Witnesses are not entry-point arguments, and
//!     `Compiled3` only counts them, so the list is recovered from the
//!     instruction stream (the count is cross-checked against
//!     `Compiled3::witnesses`).
//!
//! To regenerate after an INTENTIONAL interface change (a toolchain bump
//! that moves a schema is one — notes/version-bump.org):
//! `cargo test --release -p minocrab-contracts --test interface_snapshot -- \
//!      --ignored regenerate_interface_snapshot`, or `./bump.sh accept` to
//! run every regenerator at once. It rewrites the table below in place, so
//! the new baseline arrives as a reviewable diff.

mod support;

use minocrab::v3::Compiled3;
use minocrab::DisclosureKind;
use minocrab_zkir::v3::{Instruction, IrType};
use support::{circuits, rewrite_generated_region, test_source};

/// `(circuit, interface)` — frozen at "M9 phase 0: freeze every circuit's
/// ordered interface in a snapshot guard test".
const SNAPSHOT: &[(&str, &str)] = &[
    // GENERATED BEGIN — rewritten by `regenerate_interface_snapshot`
    (
        "erc20_vault::initialize",
        "\
in  vaultEvm: Scalar<BLS12-381>
in  swapRouter: Scalar<BLS12-381>
in  chainId: Scalar<BLS12-381>
in  chainCaip2Id_hi: Scalar<BLS12-381>
in  chainCaip2Id_lo: Scalar<BLS12-381>
in  responseKey: Point<Secp256k1>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::deposit",
        "\
in  evmNonce: Scalar<BLS12-381>
in  gasLimit: Scalar<BLS12-381>
in  maxFeePerGas: Scalar<BLS12-381>
in  maxPriorityFeePerGas: Scalar<BLS12-381>
in  keyVersion: Scalar<BLS12-381>
in  depositRequest_erc20Address: Scalar<BLS12-381>
in  depositRequest_amount: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::claim",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  respond_bigR_x_hi: Scalar<BLS12-381>
in  respond_bigR_x_lo: Scalar<BLS12-381>
in  respond_bigR_y_hi: Scalar<BLS12-381>
in  respond_bigR_y_lo: Scalar<BLS12-381>
in  respond_s_hi: Scalar<BLS12-381>
in  respond_s_lo: Scalar<BLS12-381>
in  respond_recoveryId: Scalar<BLS12-381>
in  serializedOutput: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
in  recipient_is_some: Scalar<BLS12-381>
in  recipient_is_left: Scalar<BLS12-381>
in  recipient_left_hi: Scalar<BLS12-381>
in  recipient_left_lo: Scalar<BLS12-381>
in  recipient_right_hi: Scalar<BLS12-381>
in  recipient_right_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381> (guarded)
wit Scalar<BLS12-381> (guarded)
",
    ),
    (
        "erc20_vault::approve_router",
        "\
in  erc20Address: Scalar<BLS12-381>
in  evmNonce: Scalar<BLS12-381>
in  keyVersion: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::withdraw",
        "\
in  evmNonce: Scalar<BLS12-381>
in  keyVersion: Scalar<BLS12-381>
in  withdrawRequest_erc20Address: Scalar<BLS12-381>
in  withdrawRequest_amount: Scalar<BLS12-381>
in  withdrawRequest_destEvmAddress: Scalar<BLS12-381>
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::complete_withdraw",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  respond_bigR_x_hi: Scalar<BLS12-381>
in  respond_bigR_x_lo: Scalar<BLS12-381>
in  respond_bigR_y_hi: Scalar<BLS12-381>
in  respond_bigR_y_lo: Scalar<BLS12-381>
in  respond_s_hi: Scalar<BLS12-381>
in  respond_s_lo: Scalar<BLS12-381>
in  respond_recoveryId: Scalar<BLS12-381>
in  serializedOutput: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381> (guarded)
wit Scalar<BLS12-381> (guarded)
wit Scalar<BLS12-381> (guarded)
wit Scalar<BLS12-381> (guarded)
",
    ),
    (
        "erc20_vault::refund",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  respond_bigR_x_hi: Scalar<BLS12-381>
in  respond_bigR_x_lo: Scalar<BLS12-381>
in  respond_bigR_y_hi: Scalar<BLS12-381>
in  respond_bigR_y_lo: Scalar<BLS12-381>
in  respond_s_hi: Scalar<BLS12-381>
in  respond_s_lo: Scalar<BLS12-381>
in  respond_recoveryId: Scalar<BLS12-381>
in  serializedOutput: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381> (guarded)
wit Scalar<BLS12-381> (guarded)
wit Scalar<BLS12-381> (guarded)
wit Scalar<BLS12-381> (guarded)
wit Scalar<BLS12-381> (guarded)
wit Scalar<BLS12-381> (guarded)
wit Scalar<BLS12-381> (guarded)
wit Scalar<BLS12-381> (guarded)
",
    ),
    (
        "erc20_vault::swap",
        "\
in  evmNonce: Scalar<BLS12-381>
in  keyVersion: Scalar<BLS12-381>
in  swapRequest_tokenIn: Scalar<BLS12-381>
in  swapRequest_tokenOut: Scalar<BLS12-381>
in  swapRequest_fee: Scalar<BLS12-381>
in  swapRequest_amountOut: Scalar<BLS12-381>
in  swapRequest_amountInMaximum: Scalar<BLS12-381>
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault::complete_swap",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  respond_bigR_x_hi: Scalar<BLS12-381>
in  respond_bigR_x_lo: Scalar<BLS12-381>
in  respond_bigR_y_hi: Scalar<BLS12-381>
in  respond_bigR_y_lo: Scalar<BLS12-381>
in  respond_s_hi: Scalar<BLS12-381>
in  respond_s_lo: Scalar<BLS12-381>
in  respond_recoveryId: Scalar<BLS12-381>
in  serializedOutput: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_opt::initialize",
        "\
in  vaultEvm: Scalar<BLS12-381>
in  swapRouter: Scalar<BLS12-381>
in  chainId: Scalar<BLS12-381>
in  chainCaip2Id_hi: Scalar<BLS12-381>
in  chainCaip2Id_lo: Scalar<BLS12-381>
in  responseKey: Point<Secp256k1>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_opt::deposit",
        "\
in  evmNonce: Scalar<BLS12-381>
in  gasLimit: Scalar<BLS12-381>
in  maxFeePerGas: Scalar<BLS12-381>
in  maxPriorityFeePerGas: Scalar<BLS12-381>
in  keyVersion: Scalar<BLS12-381>
in  depositRequest_erc20Address: Scalar<BLS12-381>
in  depositRequest_amount: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_opt::claim",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  respond_bigR_x_hi: Scalar<BLS12-381>
in  respond_bigR_x_lo: Scalar<BLS12-381>
in  respond_bigR_y_hi: Scalar<BLS12-381>
in  respond_bigR_y_lo: Scalar<BLS12-381>
in  respond_s_hi: Scalar<BLS12-381>
in  respond_s_lo: Scalar<BLS12-381>
in  respond_recoveryId: Scalar<BLS12-381>
in  serializedOutput: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
in  recipient_is_some: Scalar<BLS12-381>
in  recipient_is_left: Scalar<BLS12-381>
in  recipient_left_hi: Scalar<BLS12-381>
in  recipient_left_lo: Scalar<BLS12-381>
in  recipient_right_hi: Scalar<BLS12-381>
in  recipient_right_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381> (guarded)
wit Scalar<BLS12-381> (guarded)
",
    ),
    (
        "erc20_vault_opt::approve_router",
        "\
in  erc20Address: Scalar<BLS12-381>
in  evmNonce: Scalar<BLS12-381>
in  keyVersion: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_opt::withdraw",
        "\
in  evmNonce: Scalar<BLS12-381>
in  keyVersion: Scalar<BLS12-381>
in  withdrawRequest_erc20Address: Scalar<BLS12-381>
in  withdrawRequest_amount: Scalar<BLS12-381>
in  withdrawRequest_destEvmAddress: Scalar<BLS12-381>
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_opt::complete_withdraw",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  respond_bigR_x_hi: Scalar<BLS12-381>
in  respond_bigR_x_lo: Scalar<BLS12-381>
in  respond_bigR_y_hi: Scalar<BLS12-381>
in  respond_bigR_y_lo: Scalar<BLS12-381>
in  respond_s_hi: Scalar<BLS12-381>
in  respond_s_lo: Scalar<BLS12-381>
in  respond_recoveryId: Scalar<BLS12-381>
in  serializedOutput: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381> (guarded)
wit Scalar<BLS12-381> (guarded)
wit Scalar<BLS12-381> (guarded)
wit Scalar<BLS12-381> (guarded)
",
    ),
    (
        "erc20_vault_opt::refund",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  respond_bigR_x_hi: Scalar<BLS12-381>
in  respond_bigR_x_lo: Scalar<BLS12-381>
in  respond_bigR_y_hi: Scalar<BLS12-381>
in  respond_bigR_y_lo: Scalar<BLS12-381>
in  respond_s_hi: Scalar<BLS12-381>
in  respond_s_lo: Scalar<BLS12-381>
in  respond_recoveryId: Scalar<BLS12-381>
in  serializedOutput: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_opt::swap",
        "\
in  evmNonce: Scalar<BLS12-381>
in  keyVersion: Scalar<BLS12-381>
in  swapRequest_tokenIn: Scalar<BLS12-381>
in  swapRequest_tokenOut: Scalar<BLS12-381>
in  swapRequest_fee: Scalar<BLS12-381>
in  swapRequest_amountOut: Scalar<BLS12-381>
in  swapRequest_amountInMaximum: Scalar<BLS12-381>
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_opt::complete_swap",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  respond_bigR_x_hi: Scalar<BLS12-381>
in  respond_bigR_x_lo: Scalar<BLS12-381>
in  respond_bigR_y_hi: Scalar<BLS12-381>
in  respond_bigR_y_lo: Scalar<BLS12-381>
in  respond_s_hi: Scalar<BLS12-381>
in  respond_s_lo: Scalar<BLS12-381>
in  respond_recoveryId: Scalar<BLS12-381>
in  serializedOutput: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_borsh::initialize",
        "\
in  vaultEvm: Scalar<BLS12-381>
in  swapRouter: Scalar<BLS12-381>
in  chainId: Scalar<BLS12-381>
in  chainCaip2Id_hi: Scalar<BLS12-381>
in  chainCaip2Id_lo: Scalar<BLS12-381>
in  responseKey: Point<Secp256k1>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_borsh::deposit",
        "\
in  evmNonce: Scalar<BLS12-381>
in  gasLimit: Scalar<BLS12-381>
in  maxFeePerGas: Scalar<BLS12-381>
in  maxPriorityFeePerGas: Scalar<BLS12-381>
in  keyVersion: Scalar<BLS12-381>
in  depositRequest_erc20Address: Scalar<BLS12-381>
in  depositRequest_amount: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_borsh::claim",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  respond_bigR_x_hi: Scalar<BLS12-381>
in  respond_bigR_x_lo: Scalar<BLS12-381>
in  respond_bigR_y_hi: Scalar<BLS12-381>
in  respond_bigR_y_lo: Scalar<BLS12-381>
in  respond_s_hi: Scalar<BLS12-381>
in  respond_s_lo: Scalar<BLS12-381>
in  respond_recoveryId: Scalar<BLS12-381>
in  serializedOutput_kind: Scalar<BLS12-381>
in  serializedOutput_success: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
in  recipient_is_some: Scalar<BLS12-381>
in  recipient_is_left: Scalar<BLS12-381>
in  recipient_left_hi: Scalar<BLS12-381>
in  recipient_left_lo: Scalar<BLS12-381>
in  recipient_right_hi: Scalar<BLS12-381>
in  recipient_right_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381> (guarded)
wit Scalar<BLS12-381> (guarded)
",
    ),
    (
        "erc20_vault_borsh::approve_router",
        "\
in  erc20Address: Scalar<BLS12-381>
in  evmNonce: Scalar<BLS12-381>
in  keyVersion: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_borsh::withdraw",
        "\
in  evmNonce: Scalar<BLS12-381>
in  keyVersion: Scalar<BLS12-381>
in  withdrawRequest_erc20Address: Scalar<BLS12-381>
in  withdrawRequest_amount: Scalar<BLS12-381>
in  withdrawRequest_destEvmAddress: Scalar<BLS12-381>
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_borsh::complete_withdraw",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  respond_bigR_x_hi: Scalar<BLS12-381>
in  respond_bigR_x_lo: Scalar<BLS12-381>
in  respond_bigR_y_hi: Scalar<BLS12-381>
in  respond_bigR_y_lo: Scalar<BLS12-381>
in  respond_s_hi: Scalar<BLS12-381>
in  respond_s_lo: Scalar<BLS12-381>
in  respond_recoveryId: Scalar<BLS12-381>
in  serializedOutput_kind: Scalar<BLS12-381>
in  serializedOutput_success: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381> (guarded)
wit Scalar<BLS12-381> (guarded)
wit Scalar<BLS12-381> (guarded)
wit Scalar<BLS12-381> (guarded)
",
    ),
    (
        "erc20_vault_borsh::refund",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  respond_bigR_x_hi: Scalar<BLS12-381>
in  respond_bigR_x_lo: Scalar<BLS12-381>
in  respond_bigR_y_hi: Scalar<BLS12-381>
in  respond_bigR_y_lo: Scalar<BLS12-381>
in  respond_s_hi: Scalar<BLS12-381>
in  respond_s_lo: Scalar<BLS12-381>
in  respond_recoveryId: Scalar<BLS12-381>
in  serializedOutput_kind: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_borsh::swap",
        "\
in  evmNonce: Scalar<BLS12-381>
in  keyVersion: Scalar<BLS12-381>
in  swapRequest_tokenIn: Scalar<BLS12-381>
in  swapRequest_tokenOut: Scalar<BLS12-381>
in  swapRequest_fee: Scalar<BLS12-381>
in  swapRequest_amountOut: Scalar<BLS12-381>
in  swapRequest_amountInMaximum: Scalar<BLS12-381>
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_borsh::complete_swap",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  respond_bigR_x_hi: Scalar<BLS12-381>
in  respond_bigR_x_lo: Scalar<BLS12-381>
in  respond_bigR_y_hi: Scalar<BLS12-381>
in  respond_bigR_y_lo: Scalar<BLS12-381>
in  respond_s_hi: Scalar<BLS12-381>
in  respond_s_lo: Scalar<BLS12-381>
in  respond_recoveryId: Scalar<BLS12-381>
in  serializedOutput_kind: Scalar<BLS12-381>
in  serializedOutput_amountIn: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_modern::initialize",
        "\
in  vaultEvm: Scalar<BLS12-381>
in  swapRouter: Scalar<BLS12-381>
in  chainId: Scalar<BLS12-381>
in  chainCaip2Id_hi: Scalar<BLS12-381>
in  chainCaip2Id_lo: Scalar<BLS12-381>
in  responseKey: Point<Secp256k1>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_modern::deposit",
        "\
in  evmNonce: Scalar<BLS12-381>
in  gasLimit: Scalar<BLS12-381>
in  maxFeePerGas: Scalar<BLS12-381>
in  maxPriorityFeePerGas: Scalar<BLS12-381>
in  keyVersion: Scalar<BLS12-381>
in  depositRequest_erc20Address: Scalar<BLS12-381>
in  depositRequest_amount: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_modern::claim",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  respond_bigR_x_hi: Scalar<BLS12-381>
in  respond_bigR_x_lo: Scalar<BLS12-381>
in  respond_bigR_y_hi: Scalar<BLS12-381>
in  respond_bigR_y_lo: Scalar<BLS12-381>
in  respond_s_hi: Scalar<BLS12-381>
in  respond_s_lo: Scalar<BLS12-381>
in  respond_recoveryId: Scalar<BLS12-381>
in  serializedOutput_kind: Scalar<BLS12-381>
in  serializedOutput_success: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
in  recipient_is_some: Scalar<BLS12-381>
in  recipient_is_left: Scalar<BLS12-381>
in  recipient_left_hi: Scalar<BLS12-381>
in  recipient_left_lo: Scalar<BLS12-381>
in  recipient_right_hi: Scalar<BLS12-381>
in  recipient_right_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381> (guarded)
wit Scalar<BLS12-381> (guarded)
",
    ),
    (
        "erc20_vault_modern::approve_router",
        "\
in  erc20Address: Scalar<BLS12-381>
in  evmNonce: Scalar<BLS12-381>
in  keyVersion: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_modern::withdraw",
        "\
in  evmNonce: Scalar<BLS12-381>
in  keyVersion: Scalar<BLS12-381>
in  withdrawRequest_erc20Address: Scalar<BLS12-381>
in  withdrawRequest_amount: Scalar<BLS12-381>
in  withdrawRequest_destEvmAddress: Scalar<BLS12-381>
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_modern::complete_withdraw",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  respond_bigR_x_hi: Scalar<BLS12-381>
in  respond_bigR_x_lo: Scalar<BLS12-381>
in  respond_bigR_y_hi: Scalar<BLS12-381>
in  respond_bigR_y_lo: Scalar<BLS12-381>
in  respond_s_hi: Scalar<BLS12-381>
in  respond_s_lo: Scalar<BLS12-381>
in  respond_recoveryId: Scalar<BLS12-381>
in  serializedOutput_kind: Scalar<BLS12-381>
in  serializedOutput_success: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381> (guarded)
wit Scalar<BLS12-381> (guarded)
wit Scalar<BLS12-381> (guarded)
wit Scalar<BLS12-381> (guarded)
",
    ),
    (
        "erc20_vault_modern::refund",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  respond_bigR_x_hi: Scalar<BLS12-381>
in  respond_bigR_x_lo: Scalar<BLS12-381>
in  respond_bigR_y_hi: Scalar<BLS12-381>
in  respond_bigR_y_lo: Scalar<BLS12-381>
in  respond_s_hi: Scalar<BLS12-381>
in  respond_s_lo: Scalar<BLS12-381>
in  respond_recoveryId: Scalar<BLS12-381>
in  serializedOutput_kind: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_modern::swap",
        "\
in  evmNonce: Scalar<BLS12-381>
in  keyVersion: Scalar<BLS12-381>
in  swapRequest_tokenIn: Scalar<BLS12-381>
in  swapRequest_tokenOut: Scalar<BLS12-381>
in  swapRequest_fee: Scalar<BLS12-381>
in  swapRequest_amountOut: Scalar<BLS12-381>
in  swapRequest_amountInMaximum: Scalar<BLS12-381>
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "erc20_vault_modern::complete_swap",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  respond_bigR_x_hi: Scalar<BLS12-381>
in  respond_bigR_x_lo: Scalar<BLS12-381>
in  respond_bigR_y_hi: Scalar<BLS12-381>
in  respond_bigR_y_lo: Scalar<BLS12-381>
in  respond_s_hi: Scalar<BLS12-381>
in  respond_s_lo: Scalar<BLS12-381>
in  respond_recoveryId: Scalar<BLS12-381>
in  serializedOutput_kind: Scalar<BLS12-381>
in  serializedOutput_amountIn: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "signet_contract::sign_bidirectional",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  notification_version: Scalar<BLS12-381>
in  notification_payload_0: Scalar<BLS12-381>
in  notification_payload_1: Scalar<BLS12-381>
in  notification_payload_2: Scalar<BLS12-381>
in  notification_payload_3: Scalar<BLS12-381>
in  notification_payload_4: Scalar<BLS12-381>
",
    ),
    (
        "signet_contract::respond",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  bigR_x_hi: Scalar<BLS12-381>
in  bigR_x_lo: Scalar<BLS12-381>
in  bigR_y_hi: Scalar<BLS12-381>
in  bigR_y_lo: Scalar<BLS12-381>
in  s_hi: Scalar<BLS12-381>
in  s_lo: Scalar<BLS12-381>
in  recoveryId: Scalar<BLS12-381>
",
    ),
    (
        "signet_contract::respond_bidirectional",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  bigR_x_hi: Scalar<BLS12-381>
in  bigR_x_lo: Scalar<BLS12-381>
in  bigR_y_hi: Scalar<BLS12-381>
in  bigR_y_lo: Scalar<BLS12-381>
in  s_hi: Scalar<BLS12-381>
in  s_lo: Scalar<BLS12-381>
in  recoveryId: Scalar<BLS12-381>
",
    ),
    (
        "attest::map_only",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
",
    ),
    (
        "attest::verify_only",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  digest_hi: Scalar<BLS12-381>
in  digest_lo: Scalar<BLS12-381>
in  r_hi: Scalar<BLS12-381>
in  r_lo: Scalar<BLS12-381>
in  s_hi: Scalar<BLS12-381>
in  s_lo: Scalar<BLS12-381>
in  pk: Point<Secp256k1>
",
    ),
    (
        "attest::sha_verify",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  output_0: Scalar<BLS12-381>
in  output_1: Scalar<BLS12-381>
in  output_2: Scalar<BLS12-381>
in  output_3: Scalar<BLS12-381>
in  output_4: Scalar<BLS12-381>
in  r_hi: Scalar<BLS12-381>
in  r_lo: Scalar<BLS12-381>
in  s_hi: Scalar<BLS12-381>
in  s_lo: Scalar<BLS12-381>
in  pk: Point<Secp256k1>
",
    ),
    (
        "attest::keccak_verify",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  output_0: Scalar<BLS12-381>
in  output_1: Scalar<BLS12-381>
in  output_2: Scalar<BLS12-381>
in  output_3: Scalar<BLS12-381>
in  output_4: Scalar<BLS12-381>
in  r_hi: Scalar<BLS12-381>
in  r_lo: Scalar<BLS12-381>
in  s_hi: Scalar<BLS12-381>
in  s_lo: Scalar<BLS12-381>
in  pk: Point<Secp256k1>
",
    ),
    (
        "events::base",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "events::emit_n(1)",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "events::emit_n(2)",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "events::emit_n(4)",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "events_borsh::base",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "events_borsh::emit_n(1)",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "events_borsh::emit_n(2)",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "events_borsh::emit_n(4)",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "hashing::control(32)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
",
    ),
    (
        "hashing::control(64)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
",
    ),
    (
        "hashing::control(128)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
in  data_3: Scalar<BLS12-381>
in  data_4: Scalar<BLS12-381>
",
    ),
    (
        "hashing::control(256)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
in  data_3: Scalar<BLS12-381>
in  data_4: Scalar<BLS12-381>
in  data_5: Scalar<BLS12-381>
in  data_6: Scalar<BLS12-381>
in  data_7: Scalar<BLS12-381>
in  data_8: Scalar<BLS12-381>
",
    ),
    (
        "hashing::control(1024)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
in  data_3: Scalar<BLS12-381>
in  data_4: Scalar<BLS12-381>
in  data_5: Scalar<BLS12-381>
in  data_6: Scalar<BLS12-381>
in  data_7: Scalar<BLS12-381>
in  data_8: Scalar<BLS12-381>
in  data_9: Scalar<BLS12-381>
in  data_10: Scalar<BLS12-381>
in  data_11: Scalar<BLS12-381>
in  data_12: Scalar<BLS12-381>
in  data_13: Scalar<BLS12-381>
in  data_14: Scalar<BLS12-381>
in  data_15: Scalar<BLS12-381>
in  data_16: Scalar<BLS12-381>
in  data_17: Scalar<BLS12-381>
in  data_18: Scalar<BLS12-381>
in  data_19: Scalar<BLS12-381>
in  data_20: Scalar<BLS12-381>
in  data_21: Scalar<BLS12-381>
in  data_22: Scalar<BLS12-381>
in  data_23: Scalar<BLS12-381>
in  data_24: Scalar<BLS12-381>
in  data_25: Scalar<BLS12-381>
in  data_26: Scalar<BLS12-381>
in  data_27: Scalar<BLS12-381>
in  data_28: Scalar<BLS12-381>
in  data_29: Scalar<BLS12-381>
in  data_30: Scalar<BLS12-381>
in  data_31: Scalar<BLS12-381>
in  data_32: Scalar<BLS12-381>
in  data_33: Scalar<BLS12-381>
",
    ),
    (
        "hashing::persistent(32)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
",
    ),
    (
        "hashing::persistent(64)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
",
    ),
    (
        "hashing::persistent(128)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
in  data_3: Scalar<BLS12-381>
in  data_4: Scalar<BLS12-381>
",
    ),
    (
        "hashing::persistent(256)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
in  data_3: Scalar<BLS12-381>
in  data_4: Scalar<BLS12-381>
in  data_5: Scalar<BLS12-381>
in  data_6: Scalar<BLS12-381>
in  data_7: Scalar<BLS12-381>
in  data_8: Scalar<BLS12-381>
",
    ),
    (
        "hashing::persistent(1024)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
in  data_3: Scalar<BLS12-381>
in  data_4: Scalar<BLS12-381>
in  data_5: Scalar<BLS12-381>
in  data_6: Scalar<BLS12-381>
in  data_7: Scalar<BLS12-381>
in  data_8: Scalar<BLS12-381>
in  data_9: Scalar<BLS12-381>
in  data_10: Scalar<BLS12-381>
in  data_11: Scalar<BLS12-381>
in  data_12: Scalar<BLS12-381>
in  data_13: Scalar<BLS12-381>
in  data_14: Scalar<BLS12-381>
in  data_15: Scalar<BLS12-381>
in  data_16: Scalar<BLS12-381>
in  data_17: Scalar<BLS12-381>
in  data_18: Scalar<BLS12-381>
in  data_19: Scalar<BLS12-381>
in  data_20: Scalar<BLS12-381>
in  data_21: Scalar<BLS12-381>
in  data_22: Scalar<BLS12-381>
in  data_23: Scalar<BLS12-381>
in  data_24: Scalar<BLS12-381>
in  data_25: Scalar<BLS12-381>
in  data_26: Scalar<BLS12-381>
in  data_27: Scalar<BLS12-381>
in  data_28: Scalar<BLS12-381>
in  data_29: Scalar<BLS12-381>
in  data_30: Scalar<BLS12-381>
in  data_31: Scalar<BLS12-381>
in  data_32: Scalar<BLS12-381>
in  data_33: Scalar<BLS12-381>
",
    ),
    (
        "hashing::keccak(64)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
",
    ),
    (
        "hashing::keccak(128)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
in  data_3: Scalar<BLS12-381>
in  data_4: Scalar<BLS12-381>
",
    ),
    (
        "hashing::keccak(256)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
in  data_3: Scalar<BLS12-381>
in  data_4: Scalar<BLS12-381>
in  data_5: Scalar<BLS12-381>
in  data_6: Scalar<BLS12-381>
in  data_7: Scalar<BLS12-381>
in  data_8: Scalar<BLS12-381>
",
    ),
    (
        "hashing::transient(32)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
",
    ),
    (
        "hashing::transient(256)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
in  data_3: Scalar<BLS12-381>
in  data_4: Scalar<BLS12-381>
in  data_5: Scalar<BLS12-381>
in  data_6: Scalar<BLS12-381>
in  data_7: Scalar<BLS12-381>
in  data_8: Scalar<BLS12-381>
",
    ),
    (
        "hashing::transient(1024)",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
in  data_3: Scalar<BLS12-381>
in  data_4: Scalar<BLS12-381>
in  data_5: Scalar<BLS12-381>
in  data_6: Scalar<BLS12-381>
in  data_7: Scalar<BLS12-381>
in  data_8: Scalar<BLS12-381>
in  data_9: Scalar<BLS12-381>
in  data_10: Scalar<BLS12-381>
in  data_11: Scalar<BLS12-381>
in  data_12: Scalar<BLS12-381>
in  data_13: Scalar<BLS12-381>
in  data_14: Scalar<BLS12-381>
in  data_15: Scalar<BLS12-381>
in  data_16: Scalar<BLS12-381>
in  data_17: Scalar<BLS12-381>
in  data_18: Scalar<BLS12-381>
in  data_19: Scalar<BLS12-381>
in  data_20: Scalar<BLS12-381>
in  data_21: Scalar<BLS12-381>
in  data_22: Scalar<BLS12-381>
in  data_23: Scalar<BLS12-381>
in  data_24: Scalar<BLS12-381>
in  data_25: Scalar<BLS12-381>
in  data_26: Scalar<BLS12-381>
in  data_27: Scalar<BLS12-381>
in  data_28: Scalar<BLS12-381>
in  data_29: Scalar<BLS12-381>
in  data_30: Scalar<BLS12-381>
in  data_31: Scalar<BLS12-381>
in  data_32: Scalar<BLS12-381>
in  data_33: Scalar<BLS12-381>
",
    ),
    (
        "hashing::persistent_vec8",
        "\
in  data_0_hi: Scalar<BLS12-381>
in  data_0_lo: Scalar<BLS12-381>
in  data_1_hi: Scalar<BLS12-381>
in  data_1_lo: Scalar<BLS12-381>
in  data_2_hi: Scalar<BLS12-381>
in  data_2_lo: Scalar<BLS12-381>
in  data_3_hi: Scalar<BLS12-381>
in  data_3_lo: Scalar<BLS12-381>
in  data_4_hi: Scalar<BLS12-381>
in  data_4_lo: Scalar<BLS12-381>
in  data_5_hi: Scalar<BLS12-381>
in  data_5_lo: Scalar<BLS12-381>
in  data_6_hi: Scalar<BLS12-381>
in  data_6_lo: Scalar<BLS12-381>
in  data_7_hi: Scalar<BLS12-381>
in  data_7_lo: Scalar<BLS12-381>
",
    ),
    (
        "xcall::local_base",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "xcall::call_once",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "xcall::call_twice",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "xcall::call_big",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
in  data_3: Scalar<BLS12-381>
in  data_4: Scalar<BLS12-381>
in  data_5: Scalar<BLS12-381>
in  data_6: Scalar<BLS12-381>
in  data_7: Scalar<BLS12-381>
in  data_8: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "xcall::target_deposit",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "xcall::target_deposit_emit",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "xcall::target_deposit_big",
        "\
in  data_0: Scalar<BLS12-381>
in  data_1: Scalar<BLS12-381>
in  data_2: Scalar<BLS12-381>
in  data_3: Scalar<BLS12-381>
in  data_4: Scalar<BLS12-381>
in  data_5: Scalar<BLS12-381>
in  data_6: Scalar<BLS12-381>
in  data_7: Scalar<BLS12-381>
in  data_8: Scalar<BLS12-381>
",
    ),
    (
        "xcall_with_payment::call_once",
        "\
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "xcall_with_payment::request",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "xcall_with_payment::notify",
        "\
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
",
    ),
    (
        "xcall_with_payment::pay",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
",
    ),
    (
        "xcall_with_payment::confirm_request",
        "\
in  requestId_hi: Scalar<BLS12-381>
in  requestId_lo: Scalar<BLS12-381>
",
    ),
    (
        "xcontract_events::deposit_via_vault",
        "\
in  amount: Scalar<BLS12-381>
out event hash (hi): Scalar<BLS12-381>
out event hash (lo): Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "xcontract_events::token_deposit",
        "\
in  amount: Scalar<BLS12-381>
in  caller_hi: Scalar<BLS12-381>
in  caller_lo: Scalar<BLS12-381>
out event hash (hi): Scalar<BLS12-381>
out event hash (lo): Scalar<BLS12-381>
",
    ),
    (
        "xcontract_events_borsh::token_deposit",
        "\
in  amount: Scalar<BLS12-381>
in  caller_hi: Scalar<BLS12-381>
in  caller_lo: Scalar<BLS12-381>
out event hash (hi): Scalar<BLS12-381>
out event hash (lo): Scalar<BLS12-381>
",
    ),
    (
        "mint_tokens::mint_with_recipient_argument",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
",
    ),
    (
        "mint_tokens::mint_with_recipient_own_public_key",
        "\
in  recipient_hi: Scalar<BLS12-381>
in  recipient_lo: Scalar<BLS12-381>
in  mintNonce_hi: Scalar<BLS12-381>
in  mintNonce_lo: Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "serde_builtin::check_roundtrip",
        "\
in  bytes_0: Scalar<BLS12-381>
in  bytes_1: Scalar<BLS12-381>
in  bytes_2: Scalar<BLS12-381>
in  bytes_3: Scalar<BLS12-381>
in  bytes_4: Scalar<BLS12-381>
",
    ),
    (
        "test_caller::initialise",
        "\
in  responseKey: Point<Secp256k1>
wit Scalar<BLS12-381>
wit Scalar<BLS12-381>
",
    ),
    (
        "bounded::b10",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "bounded::b300",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "bounded::b1000",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "bounded::b70000",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "bounded::b1",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "bounded::b2",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "bounded::b256",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "bounded::b255",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "bounded::b_enum",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "bounded::b_struct",
        "\
in  order_kind: Scalar<BLS12-381>
in  order_quantity: Scalar<BLS12-381>
in  order_price: Scalar<BLS12-381>
in  order_tag: Scalar<BLS12-381>
",
    ),
    (
        "bounded::b_compare",
        "\
in  a: Scalar<BLS12-381>
in  b: Scalar<BLS12-381>
",
    ),
    (
        "opaque::op_arg",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "opaque::op_ret",
        "\
in  x: Scalar<BLS12-381>
out name: Scalar<BLS12-381>
",
    ),
    (
        "opaque::op_eq",
        "\
in  a: Scalar<BLS12-381>
in  b: Scalar<BLS12-381>
out equal: Scalar<BLS12-381>
",
    ),
    (
        "opaque::op_default",
        "\
",
    ),
    (
        "opaque::op_cell",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "opaque::op_witness",
        "\
wit Scalar<BLS12-381>
",
    ),
    (
        "opaque::op_map_value",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
in  v: Scalar<BLS12-381>
",
    ),
    (
        "opaque::op_map_key",
        "\
in  k: Scalar<BLS12-381>
",
    ),
    (
        "opaque::op_set",
        "\
in  k: Scalar<BLS12-381>
out member: Scalar<BLS12-381>
",
    ),
    (
        "opaque::op_maybe",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "opaque::op_bytes",
        "\
in  x: Scalar<BLS12-381>
",
    ),
    (
        "opaque::op_struct",
        "\
in  w_tag: Scalar<BLS12-381>
in  w_name: Scalar<BLS12-381>
",
    ),
    (
        "opaque::op_point",
        "\
in  p: Point<Secp256k1>
",
    ),
    (
        "opaque::op_jubjub",
        "\
in  p: Point<Jubjub>
",
    ),
    (
        "adts::set_insert",
        "\
in  x_hi: Scalar<BLS12-381>
in  x_lo: Scalar<BLS12-381>
",
    ),
    (
        "adts::set_member",
        "\
in  x_hi: Scalar<BLS12-381>
in  x_lo: Scalar<BLS12-381>
out member: Scalar<BLS12-381>
",
    ),
    (
        "adts::set_remove",
        "\
in  x_hi: Scalar<BLS12-381>
in  x_lo: Scalar<BLS12-381>
",
    ),
    (
        "adts::set_size",
        "\
out size: Scalar<BLS12-381>
",
    ),
    (
        "adts::set_is_empty",
        "\
out empty: Scalar<BLS12-381>
",
    ),
    (
        "adts::set_reset",
        "\
",
    ),
    (
        "adts::list_push_front",
        "\
in  x_hi: Scalar<BLS12-381>
in  x_lo: Scalar<BLS12-381>
",
    ),
    (
        "adts::list_pop_front",
        "\
",
    ),
    (
        "adts::list_head",
        "\
out head (is_some): Scalar<BLS12-381>
out head (hi): Scalar<BLS12-381>
out head (lo): Scalar<BLS12-381>
",
    ),
    (
        "adts::list_length",
        "\
out length: Scalar<BLS12-381>
",
    ),
    (
        "adts::list_is_empty",
        "\
out empty: Scalar<BLS12-381>
",
    ),
    (
        "adts::list_reset",
        "\
",
    ),
    (
        "adts::map_insert_default",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
",
    ),
    (
        "adts::map_reset",
        "\
",
    ),
    (
        "adts::mt_insert",
        "\
in  x_hi: Scalar<BLS12-381>
in  x_lo: Scalar<BLS12-381>
",
    ),
    (
        "adts::mt_insert_index",
        "\
in  x_hi: Scalar<BLS12-381>
in  x_lo: Scalar<BLS12-381>
in  i: Scalar<BLS12-381>
",
    ),
    (
        "adts::mt_insert_hash",
        "\
in  h_hi: Scalar<BLS12-381>
in  h_lo: Scalar<BLS12-381>
",
    ),
    (
        "adts::mt_insert_hash_index",
        "\
in  h_hi: Scalar<BLS12-381>
in  h_lo: Scalar<BLS12-381>
in  i: Scalar<BLS12-381>
",
    ),
    (
        "adts::mt_insert_index_default",
        "\
in  i: Scalar<BLS12-381>
",
    ),
    (
        "adts::mt_check_root",
        "\
in  r: Scalar<BLS12-381>
out ok: Scalar<BLS12-381>
",
    ),
    (
        "adts::mt_is_full",
        "\
out full: Scalar<BLS12-381>
",
    ),
    (
        "adts::mt_reset",
        "\
",
    ),
    (
        "adts::hmt_insert",
        "\
in  x_hi: Scalar<BLS12-381>
in  x_lo: Scalar<BLS12-381>
",
    ),
    (
        "adts::hmt_insert_index",
        "\
in  x_hi: Scalar<BLS12-381>
in  x_lo: Scalar<BLS12-381>
in  i: Scalar<BLS12-381>
",
    ),
    (
        "adts::hmt_insert_hash",
        "\
in  h_hi: Scalar<BLS12-381>
in  h_lo: Scalar<BLS12-381>
",
    ),
    (
        "adts::hmt_insert_hash_index",
        "\
in  h_hi: Scalar<BLS12-381>
in  h_lo: Scalar<BLS12-381>
in  i: Scalar<BLS12-381>
",
    ),
    (
        "adts::hmt_insert_index_default",
        "\
in  i: Scalar<BLS12-381>
",
    ),
    (
        "adts::hmt_check_root",
        "\
in  r: Scalar<BLS12-381>
out ok: Scalar<BLS12-381>
",
    ),
    (
        "adts::hmt_is_full",
        "\
out full: Scalar<BLS12-381>
",
    ),
    (
        "adts::hmt_reset_history",
        "\
",
    ),
    (
        "adts::hmt_reset",
        "\
",
    ),
    (
        "kernel_tokens::k_mint_unshielded",
        "\
in  ds_hi: Scalar<BLS12-381>
in  ds_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::k_claim_unshielded_coin_spend",
        "\
in  color_hi: Scalar<BLS12-381>
in  color_lo: Scalar<BLS12-381>
in  addr_is_left: Scalar<BLS12-381>
in  addr_left_hi: Scalar<BLS12-381>
in  addr_left_lo: Scalar<BLS12-381>
in  addr_right_hi: Scalar<BLS12-381>
in  addr_right_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::k_inc_unshielded_outputs",
        "\
in  color_hi: Scalar<BLS12-381>
in  color_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::k_inc_unshielded_inputs",
        "\
in  color_hi: Scalar<BLS12-381>
in  color_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::k_balance",
        "\
in  color_hi: Scalar<BLS12-381>
in  color_lo: Scalar<BLS12-381>
out balance: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::k_balance_less_than",
        "\
in  color_hi: Scalar<BLS12-381>
in  color_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
out less: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::k_balance_greater_than",
        "\
in  color_hi: Scalar<BLS12-381>
in  color_lo: Scalar<BLS12-381>
in  amount: Scalar<BLS12-381>
out greater: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::k_block_time_less_than",
        "\
in  t: Scalar<BLS12-381>
out before: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::k_block_time_greater_than",
        "\
in  t: Scalar<BLS12-381>
out after: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_block_time_lt",
        "\
in  t: Scalar<BLS12-381>
out lt: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_block_time_gte",
        "\
in  t: Scalar<BLS12-381>
out gte: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_block_time_gt",
        "\
in  t: Scalar<BLS12-381>
out gt: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_block_time_lte",
        "\
in  t: Scalar<BLS12-381>
out lte: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_unshielded_balance",
        "\
in  color_hi: Scalar<BLS12-381>
in  color_lo: Scalar<BLS12-381>
out balance: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_unshielded_balance_lt",
        "\
in  color_hi: Scalar<BLS12-381>
in  color_lo: Scalar<BLS12-381>
in  a: Scalar<BLS12-381>
out lt: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_unshielded_balance_gte",
        "\
in  color_hi: Scalar<BLS12-381>
in  color_lo: Scalar<BLS12-381>
in  a: Scalar<BLS12-381>
out gte: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_unshielded_balance_gt",
        "\
in  color_hi: Scalar<BLS12-381>
in  color_lo: Scalar<BLS12-381>
in  a: Scalar<BLS12-381>
out gt: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_unshielded_balance_lte",
        "\
in  color_hi: Scalar<BLS12-381>
in  color_lo: Scalar<BLS12-381>
in  a: Scalar<BLS12-381>
out lte: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_receive_unshielded",
        "\
in  color_hi: Scalar<BLS12-381>
in  color_lo: Scalar<BLS12-381>
in  a: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_send_unshielded",
        "\
in  color_hi: Scalar<BLS12-381>
in  color_lo: Scalar<BLS12-381>
in  a: Scalar<BLS12-381>
in  r_is_left: Scalar<BLS12-381>
in  r_left_hi: Scalar<BLS12-381>
in  r_left_lo: Scalar<BLS12-381>
in  r_right_hi: Scalar<BLS12-381>
in  r_right_lo: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_mint_unshielded_token",
        "\
in  ds_hi: Scalar<BLS12-381>
in  ds_lo: Scalar<BLS12-381>
in  a: Scalar<BLS12-381>
in  r_is_left: Scalar<BLS12-381>
in  r_left_hi: Scalar<BLS12-381>
in  r_left_lo: Scalar<BLS12-381>
in  r_right_hi: Scalar<BLS12-381>
in  r_right_lo: Scalar<BLS12-381>
out color (hi): Scalar<BLS12-381>
out color (lo): Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_merge_coin",
        "\
in  a_nonce_hi: Scalar<BLS12-381>
in  a_nonce_lo: Scalar<BLS12-381>
in  a_color_hi: Scalar<BLS12-381>
in  a_color_lo: Scalar<BLS12-381>
in  a_value: Scalar<BLS12-381>
in  a_mtIndex: Scalar<BLS12-381>
in  b_nonce_hi: Scalar<BLS12-381>
in  b_nonce_lo: Scalar<BLS12-381>
in  b_color_hi: Scalar<BLS12-381>
in  b_color_lo: Scalar<BLS12-381>
in  b_value: Scalar<BLS12-381>
in  b_mtIndex: Scalar<BLS12-381>
out coin nonce (hi): Scalar<BLS12-381>
out coin nonce (lo): Scalar<BLS12-381>
out coin color (hi): Scalar<BLS12-381>
out coin color (lo): Scalar<BLS12-381>
out coin value: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_merge_coin_immediate",
        "\
in  a_nonce_hi: Scalar<BLS12-381>
in  a_nonce_lo: Scalar<BLS12-381>
in  a_color_hi: Scalar<BLS12-381>
in  a_color_lo: Scalar<BLS12-381>
in  a_value: Scalar<BLS12-381>
in  a_mtIndex: Scalar<BLS12-381>
in  b_nonce_hi: Scalar<BLS12-381>
in  b_nonce_lo: Scalar<BLS12-381>
in  b_color_hi: Scalar<BLS12-381>
in  b_color_lo: Scalar<BLS12-381>
in  b_value: Scalar<BLS12-381>
out coin nonce (hi): Scalar<BLS12-381>
out coin nonce (lo): Scalar<BLS12-381>
out coin color (hi): Scalar<BLS12-381>
out coin color (lo): Scalar<BLS12-381>
out coin value: Scalar<BLS12-381>
",
    ),
    (
        "kernel_tokens::s_send_shielded",
        "\
in  input_nonce_hi: Scalar<BLS12-381>
in  input_nonce_lo: Scalar<BLS12-381>
in  input_color_hi: Scalar<BLS12-381>
in  input_color_lo: Scalar<BLS12-381>
in  input_value: Scalar<BLS12-381>
in  input_mtIndex: Scalar<BLS12-381>
in  r_is_left: Scalar<BLS12-381>
in  r_left_hi: Scalar<BLS12-381>
in  r_left_lo: Scalar<BLS12-381>
in  r_right_hi: Scalar<BLS12-381>
in  r_right_lo: Scalar<BLS12-381>
in  v: Scalar<BLS12-381>
out result change (is_some): Scalar<BLS12-381>
out result change nonce (hi): Scalar<BLS12-381>
out result change nonce (lo): Scalar<BLS12-381>
out result change color (hi): Scalar<BLS12-381>
out result change color (lo): Scalar<BLS12-381>
out result change value: Scalar<BLS12-381>
out result sent nonce (hi): Scalar<BLS12-381>
out result sent nonce (lo): Scalar<BLS12-381>
out result sent color (hi): Scalar<BLS12-381>
out result sent color (lo): Scalar<BLS12-381>
out result sent value: Scalar<BLS12-381>
",
    ),
    (
        "coins::set_insert_coin",
        "\
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
in  r_is_left: Scalar<BLS12-381>
in  r_left_hi: Scalar<BLS12-381>
in  r_left_lo: Scalar<BLS12-381>
in  r_right_hi: Scalar<BLS12-381>
in  r_right_lo: Scalar<BLS12-381>
",
    ),
    (
        "coins::map_insert_coin",
        "\
in  k_hi: Scalar<BLS12-381>
in  k_lo: Scalar<BLS12-381>
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
in  r_is_left: Scalar<BLS12-381>
in  r_left_hi: Scalar<BLS12-381>
in  r_left_lo: Scalar<BLS12-381>
in  r_right_hi: Scalar<BLS12-381>
in  r_right_lo: Scalar<BLS12-381>
",
    ),
    (
        "coins::list_push_front_coin",
        "\
in  coin_nonce_hi: Scalar<BLS12-381>
in  coin_nonce_lo: Scalar<BLS12-381>
in  coin_color_hi: Scalar<BLS12-381>
in  coin_color_lo: Scalar<BLS12-381>
in  coin_value: Scalar<BLS12-381>
in  r_is_left: Scalar<BLS12-381>
in  r_left_hi: Scalar<BLS12-381>
in  r_left_lo: Scalar<BLS12-381>
in  r_right_hi: Scalar<BLS12-381>
in  r_right_lo: Scalar<BLS12-381>
",
    ),
    // GENERATED END
];

/// The serde name of an [`IrType`], i.e. the type column the differential
/// comparator compares (`Scalar<BLS12-381>`, `Bytes<32>`, ...).
fn type_name(ty: &IrType) -> String {
    match serde_json::to_value(ty).expect("IrType serializes") {
        serde_json::Value::String(s) => s,
        other => other.to_string(),
    }
}

/// `%evmNonce.3` → `evmNonce`. The `%` prefix and the `.index` suffix are
/// `Builder3`'s uniquifiers, not part of the declared name; anything that
/// does not have that exact shape is kept verbatim.
fn label(name: &str) -> &str {
    let name = name.strip_prefix('%').unwrap_or(name);
    match name.rsplit_once('.') {
        Some((head, index)) if !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit()) => {
            head
        }
        _ => name,
    }
}

/// One circuit's interface, one line per argument / output / witness read.
fn interface(c: &Compiled3) -> Vec<String> {
    let mut lines = Vec::new();

    let inputs = serde_json::to_value(&c.ir.inputs).expect("inputs serialize");
    for ti in inputs.as_array().expect("inputs are an array") {
        let name = ti["name"].as_str().expect("input name is a string");
        let ty = ti["type"].as_str().expect("input type is a string");
        lines.push(format!("in  {}: {ty}", label(name)));
    }

    // The IR's output signature is types only; `Circuit3::output` records one
    // `Output` disclosure per queued output, in the same order.
    let out_labels: Vec<&str> = c
        .disclosures
        .iter()
        .filter(|d| d.kind == DisclosureKind::Output)
        .map(|d| d.label.as_str())
        .collect();
    assert_eq!(
        out_labels.len(),
        c.ir.outputs.len(),
        "output disclosures do not match the IR output signature"
    );
    for (l, ty) in out_labels.iter().zip(&c.ir.outputs) {
        lines.push(format!("out {l}: {}", type_name(ty)));
    }

    let mut witnesses = 0;
    for instr in c.ir.instructions.iter() {
        if let Instruction::PrivateInput { guard, val_t, .. } = instr {
            witnesses += 1;
            let guarded = if guard.is_some() { " (guarded)" } else { "" };
            lines.push(format!("wit {}{guarded}", type_name(val_t)));
        }
    }
    assert_eq!(
        witnesses, c.witnesses,
        "private-transcript reads do not match the recorded witness count"
    );

    lines
}

/// Longest-common-subsequence table of `a` and `b` (`lcs[i][j]` = length of
/// the LCS of `a[i..]` and `b[j..]`), for the failure diff.
fn lcs_table(a: &[&str], b: &[&str]) -> Vec<Vec<usize>> {
    let mut lcs = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    lcs
}

/// A unified-style diff: `-` expected, `+` actual, ` ` unchanged.
fn diff(expected: &[&str], actual: &[&str]) -> String {
    let lcs = lcs_table(expected, actual);
    let (mut i, mut j) = (0, 0);
    let mut out = String::new();
    while i < expected.len() && j < actual.len() {
        if expected[i] == actual[j] {
            out.push_str(&format!("      {}\n", expected[i]));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            out.push_str(&format!("    - {}\n", expected[i]));
            i += 1;
        } else {
            out.push_str(&format!("    + {}\n", actual[j]));
            j += 1;
        }
    }
    for line in &expected[i..] {
        out.push_str(&format!("    - {line}\n"));
    }
    for line in &actual[j..] {
        out.push_str(&format!("    + {line}\n"));
    }
    out
}

#[test]
fn every_circuit_matches_its_frozen_interface() {
    let circuits = circuits();
    assert_eq!(
        circuits.len(),
        SNAPSHOT.len(),
        "snapshot table covers {} circuits but {} are built — add the new \
         circuit to SNAPSHOT (regenerate with the `print_interface_snapshot` \
         test)",
        SNAPSHOT.len(),
        circuits.len()
    );

    let mut failures = Vec::new();
    for ((name, build), (snap_name, snap)) in circuits.iter().zip(SNAPSHOT) {
        assert_eq!(name, snap_name, "snapshot table out of order");
        let expected: Vec<&str> = snap.lines().collect();
        let actual = interface(&build());
        let actual: Vec<&str> = actual.iter().map(String::as_str).collect();
        if expected != actual {
            failures.push(format!("  {name}:\n{}", diff(&expected, &actual)));
        }
    }
    assert!(
        failures.is_empty(),
        "circuit interface changed — argument order and types are the wire \
         contract (they feed the communications commitment and the proof \
         preimage), so any movement here breaks callers. `-` is the frozen \
         interface, `+` what this build produces:\n{}",
        failures.join("\n")
    );
}

/// The diff is the whole value of the instrument when it fires, so it gets
/// its own check: a reorder, a rename and an insertion, all at once.
#[test]
fn diff_shows_reorders_renames_and_insertions() {
    let expected = ["a", "b", "c", "d"];
    let actual = ["b", "a", "c", "new", "d2"];
    assert_eq!(
        diff(&expected, &actual),
        concat!(
            "    - a\n",
            "      b\n",
            "    + a\n",
            "      c\n",
            "    - d\n",
            "    + new\n",
            "    + d2\n",
        )
    );
}

/// Regeneration helper: rewrites the SNAPSHOT table in this file.
#[test]
#[ignore = "regeneration helper, not a check"]
fn regenerate_interface_snapshot() {
    let mut body = String::new();
    for (name, build) in circuits() {
        let lines = interface(&build());
        assert!(
            lines.iter().all(|l| !l.contains('"')),
            "{name}: a label contains a quote — it cannot go in the table verbatim"
        );
        body.push_str(&format!("    (\n        \"{name}\",\n        \"\\\n"));
        for line in lines {
            body.push_str(&line);
            body.push('\n');
        }
        body.push_str("\",\n    ),\n");
    }
    rewrite_generated_region(&test_source("interface_snapshot.rs"), &body);
}
