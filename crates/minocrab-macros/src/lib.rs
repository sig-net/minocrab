//! Derives for the MinoCrab v3 contract API.
//!
//! The crate depends on nothing of ours and emits fully-qualified
//! `::minocrab_std::v3::…` paths (notes/contract-api.org §macros). Its
//! expansions are exactly what phase 2 wrote by hand — impls a reader could
//! have written — and, by the THINNESS RULE, contain no `Circuit3` method
//! call at all: everything goes through `CircuitArg` and `ArgPath`.

use proc_macro::TokenStream;

mod circuit;
mod circuit_arg;

/// Derive [`CircuitArg`] (one nested argument) and `CircuitArgs` (a whole
/// argument list) for a struct with named fields.
///
/// **Field order is the wire contract.** The fields are declared and
/// constrained in declaration order, and that order feeds the input schema,
/// the communications commitment and the proof preimage — reordering the
/// struct silently changes the circuit's ABI.
///
/// Each field's label is its name mapped `snake_case` → `lowerCamelCase`
/// (`erc20_address` → `erc20Address`), which is the Compact field name for
/// every argument in the corpus; `#[arg(name = "…")]` overrides one field's
/// segment where the frozen label differs.
///
/// ```ignore
/// #[derive(CircuitArg)]
/// struct DepositRequest {
///     erc20_address: Bytes<20>,   // depositRequest_erc20Address
///     amount: Uint<128>,          // depositRequest_amount
/// }
/// ```
///
/// The `CircuitArgs` impl is the same list with its fields at the root
/// (`evmNonce` rather than `args_evmNonce`), so one derive serves both a
/// circuit's parameter list and a struct nested inside one.
#[proc_macro_derive(CircuitArg, attributes(arg))]
pub fn derive_circuit_arg(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);
    circuit_arg::expand(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Turn a plain typed function into a circuit entry point.
///
/// ```ignore
/// #[circuit]
/// pub fn deposit(c: &mut Circuit3, evm_nonce: Uint<64>, deposit_request: DepositRequest) {
///     let one = c.constant(1u64);
///     ..
/// }
/// ```
///
/// The parameters after `c: &mut Circuit3` are the circuit's arguments, in
/// declaration order — **which is the wire contract**, exactly as for
/// [`macro@CircuitArg`]: they become the fields of a hidden argument struct
/// carrying that derive's impls, and `deposit` becomes the familiar
/// `pub fn deposit() -> Compiled3` that declares them, constrains them from
/// their types, and runs the body. Labels are the same mechanical
/// `snake_case` → `lowerCamelCase` rule, with the same
/// `#[arg(name = "…")]` escape hatch, written on the parameter.
///
/// A function returning `()` is Compact's `: []` entry point. One that
/// returns a value discloses it, and names it with
/// `#[circuit(output = "…")]`; only `CircuitOut` types — which are `Public`
/// — can be returned, so a private value has to pass through `disclose`
/// first.
///
/// An unused argument is legitimate (a slot can exist only to be part of the
/// wire shape); silence the warning the way Rust always does, with a leading
/// underscore — the label is unaffected, since `_recovery_id` and
/// `recovery_id` both map to `recoveryId`.
#[proc_macro_attribute]
pub fn circuit(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr = syn::parse_macro_input!(attr as circuit::CircuitAttr);
    let item = syn::parse_macro_input!(item as syn::ItemFn);
    circuit::expand(attr, item)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
