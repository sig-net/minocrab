//! `#[circuit]`: the entry point phase 2 wrote as a struct + `entry` call.
//!
//! For
//!
//! ```ignore
//! #[circuit]
//! pub fn deposit(c: &mut Circuit3, evm_nonce: Uint<64>, deposit_request: DepositRequest) {
//!     // body
//! }
//! ```
//!
//! the expansion is
//!
//! ```ignore
//! pub fn deposit() -> Compiled3 {
//!     struct __deposit_Args { evm_nonce: Uint<64>, deposit_request: DepositRequest }
//!     impl CircuitArg for __deposit_Args { .. }     // the derive's own codegen
//!     impl CircuitArgs for __deposit_Args { .. }
//!     fn __deposit_body(c: &mut Circuit3, evm_nonce: Uint<64>, deposit_request: DepositRequest) {
//!         // body, verbatim
//!     }
//!     entry(|__c, __args: __deposit_Args| __deposit_body(__c, __args.evm_nonce, __args.deposit_request))
//! }
//! ```
//!
//! Everything but the public function is scoped to its body, so two circuits
//! in one module cannot collide and nothing hidden leaks into the module's
//! namespace. The body is moved, not rewritten — a real function with the
//! parameters the author wrote, so `return`, `?`-free control flow, spans and
//! type errors all behave as if the attribute were not there.
//!
//! THINNESS RULE: the generated scaffolding contains no `Circuit3` call at
//! all — it declares a struct, calls `entry`/`entry_out`, and passes `c`
//! along to the body.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::spanned::Spanned;
use syn::{FnArg, Ident, ItemFn, LitInt, LitStr, Pat, ReturnType, Signature, Type};

use crate::circuit_arg::{arg_label, impl_arg_traits, ArgField};

/// `#[circuit]` / `#[circuit(output = "…", max_k = N)]`.
#[derive(Default)]
pub struct CircuitAttr {
    /// The label the returned value is disclosed under. Required exactly
    /// when the function returns something (see [`expand`]).
    output: Option<LitStr>,
    /// The circuit's declared cost ceiling, in `k` (log2 of the proving-table
    /// rows). Generates one more test; see [`max_k_test`].
    max_k: Option<LitInt>,
}

impl Parse for CircuitAttr {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let expected = "expected `output = \"…\"` or `max_k = N` inside #[circuit(..)]";
        let mut attr = CircuitAttr::default();
        while !input.is_empty() {
            let key: Ident = input
                .parse()
                .map_err(|e| syn::Error::new(e.span(), expected))?;
            input.parse::<syn::Token![=]>()?;
            match &key {
                k if k == "output" => {
                    if attr.output.is_some() {
                        return Err(syn::Error::new(key.span(), "`output` is given twice"));
                    }
                    attr.output = Some(input.parse()?);
                }
                k if k == "max_k" => {
                    if attr.max_k.is_some() {
                        return Err(syn::Error::new(key.span(), "`max_k` is given twice"));
                    }
                    let budget: LitInt = input.parse()?;
                    // A `u8` because that is what the cost model's `k` is;
                    // parsing it here means a typo is a macro error at the
                    // attribute rather than a type error in the expansion.
                    budget.base10_parse::<u8>()?;
                    attr.max_k = Some(budget);
                }
                _ => {
                    return Err(syn::Error::new(
                        key.span(),
                        format!("unsupported #[circuit] argument `{key}`; {expected}"),
                    ))
                }
            }
            if input.is_empty() {
                break;
            }
            input.parse::<syn::Token![,]>()?;
        }
        Ok(attr)
    }
}

/// A circuit's expansion, in the two pieces that land in DIFFERENT places.
///
/// `entry` is the constructor — a free item today, an associated item inside
/// `#[contract]`'s `impl`. `tests` is the generated disclosure set-equality
/// check, which is a `mod` and therefore can NEVER go inside an `impl`; the
/// caller places it beside. That split is the whole reason this function
/// exists separately from [`expand`].
pub struct Expansion {
    pub entry: TokenStream,
    pub tests: Option<TokenStream>,
}

pub fn expand(attr: CircuitAttr, item: ItemFn) -> syn::Result<TokenStream> {
    let Expansion { entry, tests } = expand_parts(attr, item)?;
    Ok(quote! { #entry #tests })
}

pub fn expand_parts(attr: CircuitAttr, item: ItemFn) -> syn::Result<Expansion> {
    expand_in(attr, item, None)
}

/// [`expand_parts`] for a circuit that lives in a `#[contract]` block: `owner`
/// is the impl's self type, which the generated test needs in order to name
/// the constructor (`super::Vault::deposit`, not `super::deposit`).
pub fn expand_in(
    attr: CircuitAttr,
    item: ItemFn,
    owner: Option<&syn::Type>,
) -> syn::Result<Expansion> {
    check_signature(&item.sig)?;
    check_circuit_param(&item.sig)?;
    let fields = arg_fields(&item.sig)?;

    let ItemFn { attrs, vis, sig, block } = &item;
    let name = &sig.ident;
    let bare = name.to_string();
    let bare = bare.strip_prefix("r#").unwrap_or(&bare);
    let args_ty = format_ident!("__{bare}_Args", span = name.span());
    let body_fn = format_ident!("__{bare}_body", span = name.span());

    let arg_impls = impl_arg_traits(&args_ty, &syn::Generics::default(), &fields);
    let idents: Vec<&Ident> = fields.iter().map(|f| &f.ident).collect();
    let types: Vec<&Type> = fields.iter().map(|f| &f.ty).collect();

    // The body function's parameters are the author's own, minus the `#[arg]`
    // attributes this macro consumed (rustc rejects unknown ones).
    let body_inputs: Vec<FnArg> = sig
        .inputs
        .iter()
        .cloned()
        .map(|mut input| {
            if let FnArg::Typed(pat) = &mut input {
                pat.attrs.retain(|a| !a.path().is_ident("arg"));
            }
            input
        })
        .collect();
    let body_output = &sig.output;

    let root = quote!(::minocrab_std::v3);
    // `entry(closure)` and `entry_out(label, closure)` differ only in the
    // function and the argument that precedes the closure. A
    // `Discloses<D, R>` return is the R case wearing a declaration: the
    // declaration occupies no output slot, so `Discloses<D>` /
    // `Discloses<D, ()>` is as labelless as `()` — and MUST be, or a
    // disclosure declaration would move the circuit's interface.
    let (entry_fn, label_arg) = match (&attr.output, returns_a_value(&sig.output)) {
        (None, false) => (quote!(#root::entry), quote!()),
        (Some(label), true) => (quote!(#root::entry_out), quote!(#label,)),
        (Some(label), false) => {
            return Err(syn::Error::new(
                label.span(),
                "this circuit returns nothing, so there is no value for `output` to \
                 name — drop it, or return a disclosed value",
            ))
        }
        (None, true) => {
            return Err(syn::Error::new(
                sig.output.span(),
                "a circuit that returns a value must name it for the disclosure \
                 record: #[circuit(output = \"…\")]",
            ))
        }
    };
    let call = quote! {
        #entry_fn(#label_arg |__c, __args: #args_ty| #body_fn(__c #(, __args.#idents)*))
    };
    let declaration_test = discloses_test(&item.sig, name, bare, &root, owner);
    let budget_test = max_k_test(attr.max_k.as_ref(), name, bare, owner);

    let entry = quote! {
        #(#attrs)*
        #vis fn #name() -> #root::__private::Compiled3 {
            #[allow(non_camel_case_types)]
            struct #args_ty {
                #( #idents: #types, )*
            }

            #arg_impls

            #[allow(clippy::too_many_arguments)]
            fn #body_fn(#(#body_inputs),*) #body_output #block

            #call
        }
    };

    let tests = match (declaration_test, budget_test) {
        (None, None) => None,
        (a, b) => Some(quote! { #a #b }),
    };
    Ok(Expansion { entry, tests })
}

/// The generated set-equality test, for a circuit that declares what it
/// discloses (notes/contract-api.org §Disclosure declaration): build the
/// circuit and compare the labels its return type declares against the ones
/// it disclosed.
///
/// It is a module beside the entry point, not an item inside it — rustc
/// does not collect `#[test]` functions from inside function bodies — and
/// the declaration is named by copying the return type's tokens verbatim,
/// so the macro parses nothing about `D` and rustc resolves the label types
/// exactly as it does in the signature.
fn discloses_test(
    sig: &Signature,
    name: &Ident,
    bare: &str,
    root: &TokenStream,
    owner: Option<&syn::Type>,
) -> Option<TokenStream> {
    // No declaration is a STATEMENT, not an opt-out: a circuit whose return
    // type is not `Discloses<..>` gets a test asserting it disclosed nothing,
    // so a `c.disclose` in an undeclared circuit is a red test, never
    // silence (the external review's §3.5).
    let declared: Option<&syn::Type> = match &sig.output {
        ReturnType::Type(_, ty) if is_discloses(ty) => Some(ty),
        _ => None,
    };
    let module = format_ident!("__{bare}_discloses", span = name.span());
    // The constructor's path from inside the generated module: an associated
    // function of the contract, or a free function beside it.
    let build = match owner {
        Some(owner) => quote!(super::#owner::#name),
        None => quote!(super::#name),
    };
    let circuit = name.to_string();
    let circuit = circuit.strip_prefix("r#").unwrap_or(&circuit).to_string();
    let assertion = match declared {
        Some(ty) => quote! {
            #root::__private::assert_declared_disclosures::<#ty>(#circuit, &#build());
        },
        None => quote! {
            #root::__private::assert_discloses_nothing(#circuit, &#build());
        },
    };
    Some(quote! {
        #[cfg(test)]
        #[allow(non_snake_case)]
        mod #module {
            #[allow(unused_imports)]
            use super::*;

            #[test]
            fn the_declared_disclosures_are_the_ones_the_circuit_makes() {
                #assertion
            }
        }
    })
}

/// The generated cost-budget test, for `#[circuit(max_k = N)]`: build the
/// circuit and price it against the declared ceiling through minocrab-sim's
/// cost model, which is Midnight's own.
///
/// A module beside the entry point for the same reason [`discloses_test`]'s
/// is, and it names `::minocrab_sim` directly — so a crate that declares a
/// budget needs minocrab-sim among its `[dev-dependencies]`. That is the
/// only crate a `#[circuit]` expansion can require beyond minocrab-std, and
/// only when the author asks for it.
fn max_k_test(
    budget: Option<&LitInt>,
    name: &Ident,
    bare: &str,
    owner: Option<&syn::Type>,
) -> Option<TokenStream> {
    let budget = budget?;
    let module = format_ident!("__{bare}_max_k", span = name.span());
    let build = match owner {
        Some(owner) => quote!(super::#owner::#name),
        None => quote!(super::#name),
    };
    let circuit = name.to_string();
    let circuit = circuit.strip_prefix("r#").unwrap_or(&circuit).to_string();
    Some(quote! {
        #[cfg(test)]
        #[allow(non_snake_case)]
        mod #module {
            #[allow(unused_imports)]
            use super::*;

            #[test]
            fn the_circuit_is_within_its_declared_cost_budget() {
                ::minocrab_sim::v3::assert_max_k(#circuit, &#build(), #budget);
            }
        }
    })
}

/// A `Discloses<..>` return type, by the last segment of its path — the
/// same shallow reading `is_circuit_ref` gives the first parameter. An
/// aliased spelling is not recognised, deliberately: the declaration is
/// meant to be legible in the signature.
fn is_discloses(ty: &Type) -> bool {
    let Type::Path(path) = ty else {
        return false;
    };
    path.path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "Discloses")
}

/// Everything a circuit entry point may not be. Each check owns the span of
/// the token that made the function unbuildable.
fn check_signature(sig: &Signature) -> syn::Result<()> {
    if let Some(token) = sig.constness {
        return Err(syn::Error::new(
            token.span,
            "a circuit is built at run time, not in a const context",
        ));
    }
    if let Some(token) = sig.asyncness {
        return Err(syn::Error::new(
            token.span,
            "a circuit is built, not awaited: #[circuit] cannot be applied to an async fn",
        ));
    }
    if let Some(token) = sig.unsafety {
        return Err(syn::Error::new(
            token.span,
            "a circuit entry point is safe code: drop the `unsafe`",
        ));
    }
    if let Some(abi) = &sig.abi {
        return Err(syn::Error::new(
            abi.span(),
            "a circuit entry point has no foreign ABI",
        ));
    }
    if let Some(variadic) = &sig.variadic {
        return Err(syn::Error::new(
            variadic.span(),
            "a circuit's argument list is fixed: variadic parameters are not arguments",
        ));
    }
    if !sig.generics.params.is_empty() {
        return Err(syn::Error::new(
            sig.generics.span(),
            "a circuit entry point is monomorphic — its arguments ARE the ledger \
             ABI, so #[circuit] takes no generic parameters (build the circuit \
             from a generic helper instead)",
        ));
    }
    if let Some(clause) = &sig.generics.where_clause {
        return Err(syn::Error::new(
            clause.span(),
            "a circuit entry point is monomorphic: #[circuit] takes no where-clause",
        ));
    }
    Ok(())
}

/// The mandatory first parameter, `c: &mut Circuit3` — the one parameter
/// that is not an argument.
fn check_circuit_param(sig: &Signature) -> syn::Result<()> {
    let missing = || {
        syn::Error::new(
            sig.paren_token.span.join(),
            "a circuit's first parameter must be the circuit being built, \
             `c: &mut Circuit3`",
        )
    };
    let first = sig.inputs.first().ok_or_else(missing)?;
    let FnArg::Typed(pat) = first else {
        return Err(syn::Error::new(
            first.span(),
            "a circuit entry point is a free function: its first parameter must be \
             `c: &mut Circuit3`, not `self`",
        ));
    };
    if !is_circuit_ref(&pat.ty) {
        return Err(syn::Error::new(
            pat.span(),
            "a circuit's first parameter must be the circuit being built, \
             `c: &mut Circuit3`; every parameter after it is a circuit argument",
        ));
    }
    if let Some(attr) = pat.attrs.iter().find(|a| a.path().is_ident("arg")) {
        return Err(syn::Error::new_spanned(
            attr,
            "the circuit itself is not an argument, so it has no label",
        ));
    }
    Ok(())
}

/// `&mut Circuit3` — spelled as a path ending in `Circuit3`, since that is
/// the only type `entry` hands the body.
fn is_circuit_ref(ty: &Type) -> bool {
    let Type::Reference(reference) = ty else {
        return false;
    };
    if reference.mutability.is_none() {
        return false;
    }
    let Type::Path(path) = &*reference.elem else {
        return false;
    };
    path.path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "Circuit3")
}

/// The parameters after `c`: the circuit's arguments, in declaration order —
/// which IS the wire order.
fn arg_fields(sig: &Signature) -> syn::Result<Vec<ArgField>> {
    sig.inputs
        .iter()
        .skip(1)
        .map(|input| {
            let FnArg::Typed(pat) = input else {
                return Err(syn::Error::new(
                    input.span(),
                    "a circuit entry point is a free function: `self` is not an argument",
                ));
            };
            for attr in &pat.attrs {
                if !attr.path().is_ident("arg") {
                    return Err(syn::Error::new_spanned(
                        attr,
                        "unsupported attribute on a circuit argument; only \
                         #[arg(name = \"…\")] is understood here",
                    ));
                }
            }
            let Pat::Ident(binding) = &*pat.pat else {
                return Err(syn::Error::new(
                    pat.pat.span(),
                    "a circuit argument must be a plain `name: Type` parameter: its \
                     name is the argument's label",
                ));
            };
            if binding.subpat.is_some() || binding.by_ref.is_some() {
                return Err(syn::Error::new(
                    binding.span(),
                    "a circuit argument must be a plain `name: Type` parameter: its \
                     name is the argument's label",
                ));
            }
            let ident = binding.ident.clone();
            let label = arg_label(&ident, &pat.attrs)?;
            Ok(ArgField { ident, ty: (*pat.ty).clone(), label })
        })
        .collect()
}

/// Whether the function returns something that occupies output slots.
/// `-> ()` (however spelled) is the `[]` return of Compact's own entry
/// points, and so is `-> Discloses<D>` / `-> Discloses<D, ()>`: a
/// disclosure declaration is type-level, and a circuit that gains one must
/// keep the interface it had (the zero-movement rule — see the
/// `Discloses` docs).
fn returns_a_value(output: &ReturnType) -> bool {
    match output {
        ReturnType::Default => false,
        ReturnType::Type(_, ty) => !is_unit(ty) && !matches!(discloses_value(ty), Some(false)),
    }
}

fn is_unit(ty: &Type) -> bool {
    matches!(ty, Type::Tuple(t) if t.elems.is_empty())
}

/// For a `Discloses<..>` return type, whether it carries a returned VALUE:
/// `Discloses<D>` and `Discloses<D, ()>` do not, `Discloses<D, R>` does.
/// `None` for anything that is not a `Discloses`.
fn discloses_value(ty: &Type) -> Option<bool> {
    if !is_discloses(ty) {
        return None;
    }
    let Type::Path(path) = ty else {
        return None;
    };
    let segment = path.path.segments.last()?;
    let syn::PathArguments::AngleBracketed(args) = &segment.arguments else {
        return Some(false);
    };
    let types: Vec<&Type> = args
        .args
        .iter()
        .filter_map(|a| match a {
            syn::GenericArgument::Type(t) => Some(t),
            _ => None,
        })
        .collect();
    Some(match types.as_slice() {
        [_declaration, value] => !is_unit(value),
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(tokens: TokenStream) -> CircuitAttr {
        syn::parse2(tokens).expect("attribute parses")
    }

    fn expansion(item: ItemFn) -> String {
        expand(attr(quote!()), item).expect("expands").to_string()
    }

    fn error(item: ItemFn) -> String {
        expand(attr(quote!()), item).expect_err("rejected").to_string()
    }

    /// THINNESS RULE: the scaffolding builds no circuit — `c` is passed to
    /// the body function and never called on. (The body itself is the
    /// author's own code, moved verbatim, so the fixture has none.)
    #[test]
    fn the_expansion_calls_no_circuit_method() {
        let expanded = expansion(syn::parse_quote! {
            pub fn deposit(c: &mut Circuit3, evm_nonce: Uint<64>, request: DepositRequest) {}
        });
        assert!(!expanded.contains("c ."), "expansion calls a method on the circuit:\n{expanded}");
        assert!(
            !expanded.contains("Circuit3 ::"),
            "expansion calls a Circuit3 associated function:\n{expanded}"
        );
    }

    #[test]
    fn the_public_function_takes_nothing_and_returns_a_circuit() {
        let expanded = expansion(syn::parse_quote! {
            pub fn deposit(c: &mut Circuit3, evm_nonce: Uint<64>) {}
        });
        assert!(
            expanded.contains("pub fn deposit () -> :: minocrab_std :: v3 :: __private :: Compiled3"),
            "{expanded}"
        );
        assert!(expanded.contains("entry (| __c , __args : __deposit_Args |"), "{expanded}");
        assert!(expanded.contains("__deposit_body (__c , __args . evm_nonce)"), "{expanded}");
    }

    #[test]
    fn parameter_names_become_the_argument_labels() {
        let expanded = expansion(syn::parse_quote! {
            fn claim(
                c: &mut Circuit3,
                request_id: B32<Private>,
                #[arg(name = "respond")] respond_bidirectional_event: RespondSignature,
            ) {
            }
        });
        assert!(expanded.contains(r#"root ("requestId")"#), "{expanded}");
        assert!(expanded.contains(r#"root ("respond")"#), "{expanded}");
        assert!(!expanded.contains("respondBidirectionalEvent"), "{expanded}");
        // The attribute is consumed, not passed on to the body function.
        assert!(!expanded.contains("# [arg"), "{expanded}");
    }

    #[test]
    fn a_returning_circuit_needs_an_output_label() {
        let item: ItemFn = syn::parse_quote! {
            fn hash(c: &mut Circuit3) -> B32<Public> { unimplemented!() }
        };
        let err = expand(attr(quote!()), item.clone()).expect_err("label required").to_string();
        assert!(err.contains("output = "), "{err}");

        let expanded = expand(attr(quote!(output = "event hash")), item)
            .expect("expands")
            .to_string();
        assert!(expanded.contains(r#"entry_out ("event hash" ,"#), "{expanded}");
    }

    #[test]
    fn an_output_label_on_a_returnless_circuit_is_an_error() {
        let err = expand(
            attr(quote!(output = "event hash")),
            syn::parse_quote! { fn emit_it(c: &mut Circuit3) {} },
        )
        .expect_err("nothing to label")
        .to_string();
        assert!(err.contains("returns nothing"), "{err}");
    }

    #[test]
    fn the_unit_return_is_the_returnless_one() {
        let expanded = expansion(syn::parse_quote! {
            fn emit_it(c: &mut Circuit3) -> () {}
        });
        assert!(expanded.contains("v3 :: entry ("), "{expanded}");
    }

    /// A disclosure declaration is type-level: it must not turn a `[]`
    /// circuit into one with an output (that would move the IR interface).
    #[test]
    fn a_discloses_declaration_alone_needs_no_output_label() {
        let expanded = expansion(syn::parse_quote! {
            fn deposit(c: &mut Circuit3) -> Discloses<(RequestId, RequestRecord)> {
                Discloses::of(())
            }
        });
        assert!(expanded.contains("v3 :: entry ("), "{expanded}");

        let expanded = expansion(syn::parse_quote! {
            fn deposit(c: &mut Circuit3) -> Discloses<(RequestId,), ()> { Discloses::of(()) }
        });
        assert!(expanded.contains("v3 :: entry ("), "{expanded}");
    }

    #[test]
    fn a_discloses_with_a_value_still_names_its_output() {
        let item: ItemFn = syn::parse_quote! {
            fn hash(c: &mut Circuit3) -> Discloses<(EventHash,), B32<Public>> {
                unimplemented!()
            }
        };
        let err = expand(attr(quote!()), item.clone()).expect_err("label required").to_string();
        assert!(err.contains("output = "), "{err}");

        let expanded = expand(attr(quote!(output = "event hash")), item)
            .expect("expands")
            .to_string();
        assert!(expanded.contains(r#"entry_out ("event hash" ,"#), "{expanded}");
    }

    /// The generated test names the circuit, calls it, and hands the
    /// return type — the declaration — to the checker verbatim.
    #[test]
    fn a_declaring_circuit_gets_its_set_equality_test() {
        let expanded = expansion(syn::parse_quote! {
            pub fn deposit(c: &mut Circuit3, evm_nonce: Uint<64>) -> Discloses<(RequestId,)> {
                Discloses::of(())
            }
        });
        assert!(expanded.contains("mod __deposit_discloses"), "{expanded}");
        assert!(
            expanded.contains(
                "assert_declared_disclosures :: < Discloses < (RequestId ,) > > \
                 (\"deposit\" , & super :: deposit ())"
            ),
            "{expanded}"
        );
    }

    #[test]
    fn a_circuit_without_a_declaration_gets_a_discloses_nothing_test() {
        let expanded = expansion(syn::parse_quote! {
            pub fn deposit(c: &mut Circuit3, evm_nonce: Uint<64>) {}
        });
        assert!(expanded.contains("mod __deposit_discloses"), "{expanded}");
        assert!(
            expanded.contains("assert_discloses_nothing (\"deposit\" , & super :: deposit ())"),
            "{expanded}"
        );
        assert!(!expanded.contains("assert_declared_disclosures"), "{expanded}");

        let expanded = expand(
            attr(quote!(output = "event hash")),
            syn::parse_quote! { fn hash(c: &mut Circuit3) -> B32<Public> { unimplemented!() } },
        )
        .expect("expands")
        .to_string();
        assert!(expanded.contains("assert_discloses_nothing (\"hash\""), "{expanded}");
    }

    #[test]
    fn the_first_parameter_must_be_the_circuit() {
        let err = error(syn::parse_quote! { fn deposit() {} });
        assert!(err.contains("first parameter must be"), "{err}");

        let err = error(syn::parse_quote! { fn deposit(evm_nonce: Uint<64>) {} });
        assert!(err.contains("first parameter must be"), "{err}");

        let err = error(syn::parse_quote! { fn deposit(c: &Circuit3) {} });
        assert!(err.contains("first parameter must be"), "{err}");
    }

    #[test]
    fn generics_async_and_friends_are_rejected() {
        let err = error(syn::parse_quote! { async fn deposit(c: &mut Circuit3) {} });
        assert!(err.contains("not awaited"), "{err}");

        let err = error(syn::parse_quote! { fn deposit<T>(c: &mut Circuit3, a: T) {} });
        assert!(err.contains("monomorphic"), "{err}");

        let err = error(syn::parse_quote! {
            fn deposit(c: &mut Circuit3, a: Uint<64>) where Uint<64>: Copy {}
        });
        assert!(err.contains("where-clause"), "{err}");

        let err = error(syn::parse_quote! { unsafe fn deposit(c: &mut Circuit3) {} });
        assert!(err.contains("unsafe"), "{err}");
    }

    #[test]
    fn an_argument_must_be_a_named_binding() {
        let err = error(syn::parse_quote! { fn deposit(c: &mut Circuit3, _: Uint<64>) {} });
        assert!(err.contains("plain `name: Type`"), "{err}");

        let err = error(syn::parse_quote! {
            fn deposit(c: &mut Circuit3, (a, b): (Uint<64>, Uint<64>)) {}
        });
        assert!(err.contains("plain `name: Type`"), "{err}");
    }

    #[test]
    fn only_the_name_attribute_is_understood() {
        let err = error(syn::parse_quote! {
            fn deposit(c: &mut Circuit3, #[arg(rename = "x")] a: Uint<64>) {}
        });
        assert!(err.contains("expected name"), "{err}");

        let err = error(syn::parse_quote! {
            fn deposit(c: &mut Circuit3, #[allow(unused)] a: Uint<64>) {}
        });
        assert!(err.contains("unsupported attribute"), "{err}");

        let err = error(syn::parse_quote! {
            fn deposit(#[arg(name = "c")] c: &mut Circuit3) {}
        });
        assert!(err.contains("not an argument"), "{err}");
    }

    /// `max_k` generates a second test module, beside the entry point and
    /// beside the disclosure one when both are asked for.
    #[test]
    fn a_cost_budget_generates_its_own_test() {
        let expanded = expand(
            attr(quote!(max_k = 14)),
            syn::parse_quote! { pub fn deposit(c: &mut Circuit3, a: Uint<64>) {} },
        )
        .expect("expands")
        .to_string();
        assert!(expanded.contains("mod __deposit_max_k"), "{expanded}");
        assert!(
            expanded.contains(
                ":: minocrab_sim :: v3 :: assert_max_k (\"deposit\" , & super :: deposit () , 14)"
            ),
            "{expanded}"
        );

        let expanded = expand(
            attr(quote!(output = "event hash", max_k = 9)),
            syn::parse_quote! {
                fn hash(c: &mut Circuit3) -> Discloses<(EventHash,), B32<Public>> {
                    unimplemented!()
                }
            },
        )
        .expect("expands")
        .to_string();
        assert!(expanded.contains(r#"entry_out ("event hash" ,"#), "{expanded}");
        assert!(expanded.contains("mod __hash_discloses"), "{expanded}");
        assert!(expanded.contains("mod __hash_max_k"), "{expanded}");
    }

    #[test]
    fn a_circuit_without_a_budget_gets_no_budget_test() {
        let expanded = expansion(syn::parse_quote! {
            pub fn deposit(c: &mut Circuit3, a: Uint<64>) {}
        });
        assert!(!expanded.contains("max_k"), "{expanded}");
    }

    /// `k` is a `u8` in the cost model, so a budget that is not one is an
    /// error at the attribute rather than in the expansion.
    #[test]
    fn a_budget_outside_a_u8_is_rejected() {
        let err = syn::parse2::<CircuitAttr>(quote!(max_k = 300))
            .err()
            .expect("k does not fit a u8")
            .to_string();
        assert!(err.contains("too large"), "{err}");

        let err = syn::parse2::<CircuitAttr>(quote!(max_k = "14"))
            .err()
            .expect("a budget is a number")
            .to_string();
        assert!(err.contains("expected integer literal"), "{err}");
    }

    #[test]
    fn an_unknown_attribute_argument_is_an_error() {
        let err = syn::parse2::<CircuitAttr>(quote!(label = "x"))
            .err()
            .expect("only output is supported")
            .to_string();
        assert!(err.contains("unsupported #[circuit] argument"), "{err}");
    }
}
