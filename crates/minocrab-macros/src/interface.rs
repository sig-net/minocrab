//! `#[interface]`: a bodyless trait declaring a callee contract's circuits
//! becomes a typed calling handle.
//!
//! For
//!
//! ```ignore
//! #[interface]
//! pub trait Token {
//!     fn deposit(amount: Uint<128, Public>, caller: ContractAddress<Public>) -> B32<Public>;
//! }
//! ```
//!
//! the expansion REPLACES the trait (the `#[circuit]` precedent) with
//!
//! ```ignore
//! pub struct Token { callee: Callee }
//! impl Token {
//!     pub const DEPOSIT: EntryPoint = EntryPoint::new("deposit");
//!     pub const fn at_field(index: u8) -> Self { .. }
//!     pub fn at(address: ContractAddress<Public>) -> Self { .. }
//!     pub fn pin<V>(self, c, guard) -> Self { .. }
//!     pub fn deposit<V>(self, c, guard, amount, caller) -> B32<Public> {
//!         minocrab_ledger::call(c, guard, self.callee, Self::DEPOSIT, (amount, caller))
//!     }
//! }
//! ```
//!
//! A trait, rather than a macro over a struct, because a bodyless trait IS
//! the callee's declaration: one item per circuit, typed, no bodies to get
//! wrong, and it reads next to the Compact `contract Token { … }` block it
//! stands for.
//!
//! THINNESS RULE, as for every macro here: the expansion contains no
//! `Circuit3` method call — `c` is threaded to `minocrab_ledger::call` and
//! nothing else.
//!
//! WHAT THE EXPANSION DOES NOT CONTAIN: an address. `at_field` names a
//! ledger field and `at` takes one at runtime, so an interface crate can be
//! published without knowing where the callee is deployed.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::spanned::Spanned;
use syn::{
    Attribute, FnArg, Ident, ItemTrait, LitStr, Pat, ReturnType, TraitItem, TraitItemFn, Type,
    Visibility,
};

use crate::circuit_arg::lower_camel_case;

/// One declared circuit of the callee.
struct Circuit {
    /// The Rust method name.
    ident: Ident,
    /// The `SCREAMING_SNAKE_CASE` name of its `EntryPoint` const.
    const_ident: Ident,
    /// The Compact circuit name — the entry-point hash's preimage.
    entry_point: String,
    /// Doc comments and other attributes to carry onto the method.
    attrs: Vec<Attribute>,
    /// `(name, type)` per parameter, in declaration order — the wire order.
    params: Vec<(Ident, Type)>,
    /// The declared return type, or `None` for Compact's `: []`.
    result: Option<Type>,
}

pub fn expand(item: ItemTrait) -> syn::Result<TokenStream> {
    reject_trait_shape(&item)?;
    let circuits: Vec<Circuit> = item
        .items
        .iter()
        .map(|trait_item| match trait_item {
            TraitItem::Fn(f) => circuit(f),
            other => Err(syn::Error::new(
                other.span(),
                "an #[interface] trait declares circuits and nothing else: \
                 every item must be a bodyless `fn`",
            )),
        })
        .collect::<syn::Result<_>>()?;

    Ok(emit(&item.vis, &item.ident, &item.attrs, &circuits))
}

/// The trait itself must be the plain declaration it stands for.
fn reject_trait_shape(item: &ItemTrait) -> syn::Result<()> {
    if let Some(token) = &item.unsafety {
        return Err(syn::Error::new(
            token.span(),
            "an #[interface] trait is not unsafe: it declares another \
             contract's circuits, and calling one is an ordinary call",
        ));
    }
    if let Some(token) = &item.auto_token {
        return Err(syn::Error::new(token.span(), "an #[interface] trait is not an auto trait"));
    }
    if !item.generics.params.is_empty() {
        return Err(syn::Error::new(
            item.generics.span(),
            "an #[interface] trait takes no generic parameters: it stands for \
             ONE deployed contract's circuits, whose argument types are \
             concrete",
        ));
    }
    if let Some(where_clause) = &item.generics.where_clause {
        return Err(syn::Error::new(
            where_clause.span(),
            "an #[interface] trait takes no where-clause: it has nothing to \
             be generic in",
        ));
    }
    if !item.supertraits.is_empty() {
        return Err(syn::Error::new(
            item.supertraits.span(),
            "an #[interface] trait has no supertraits: the expansion replaces \
             it with a handle struct, so there is no trait left to bound",
        ));
    }
    Ok(())
}

/// One trait method → one declared circuit.
fn circuit(f: &TraitItemFn) -> syn::Result<Circuit> {
    let sig = &f.sig;
    if let Some(block) = &f.default {
        return Err(syn::Error::new(
            block.span(),
            "an #[interface] circuit has no body: it declares ANOTHER \
             contract's circuit, which this crate does not implement",
        ));
    }
    if let Some(token) = &sig.asyncness {
        return Err(syn::Error::new(
            token.span(),
            "an #[interface] circuit is not async: a cross-contract call is \
             claimed in-circuit, with the callee's results supplied as \
             witnesses — there is nothing to await",
        ));
    }
    if let Some(token) = &sig.unsafety {
        return Err(syn::Error::new(token.span(), "an #[interface] circuit is not unsafe"));
    }
    if let Some(token) = &sig.constness {
        return Err(syn::Error::new(token.span(), "an #[interface] circuit is not const"));
    }
    if let Some(abi) = &sig.abi {
        return Err(syn::Error::new(abi.span(), "an #[interface] circuit has no extern ABI"));
    }
    if let Some(token) = &sig.variadic {
        return Err(syn::Error::new(
            token.span(),
            "an #[interface] circuit has a fixed argument list: the callee's \
             parameters ARE its wire layout",
        ));
    }
    if !sig.generics.params.is_empty() {
        return Err(syn::Error::new(
            sig.generics.span(),
            "an #[interface] circuit takes no generic parameters: its \
             arguments' widths and visibilities are the callee's ABI, so they \
             are concrete",
        ));
    }
    if let Some(where_clause) = &sig.generics.where_clause {
        return Err(syn::Error::new(where_clause.span(), "an #[interface] circuit takes no where-clause"));
    }

    let mut params = Vec::new();
    for arg in &sig.inputs {
        match arg {
            FnArg::Receiver(receiver) => {
                return Err(syn::Error::new(
                    receiver.span(),
                    "an #[interface] circuit takes no `self`: it lists the \
                     callee's Compact parameters, and the handle is supplied \
                     by the generated method",
                ))
            }
            FnArg::Typed(typed) => {
                let Pat::Ident(pat) = &*typed.pat else {
                    return Err(syn::Error::new(
                        typed.pat.span(),
                        "an #[interface] circuit's parameter is a plain \
                         `name: Type` — the name is the Compact parameter's, \
                         and a pattern has none",
                    ));
                };
                if pat.subpat.is_some() || pat.by_ref.is_some() {
                    return Err(syn::Error::new(
                        pat.span(),
                        "an #[interface] circuit's parameter is a plain `name: Type`",
                    ));
                }
                reject_undisclosed(&typed.ty, "parameter")?;
                params.push((pat.ident.clone(), (*typed.ty).clone()));
            }
        }
    }

    let result = match &sig.output {
        ReturnType::Default => None,
        ReturnType::Type(_, ty) if is_unit(ty) => None,
        ReturnType::Type(_, ty) => {
            reject_undisclosed(ty, "result")?;
            Some((**ty).clone())
        }
    };

    let (entry_point, attrs) = entry_point_name(&sig.ident, &f.attrs)?;
    Ok(Circuit {
        const_ident: format_ident!("{}", screaming_snake_case(&sig.ident.to_string()), span = sig.ident.span()),
        ident: sig.ident.clone(),
        entry_point,
        attrs,
        params,
        result,
    })
}

/// The Compact circuit name — `#[entry_point(name = "…")]`, else the
/// mechanical `snake_case` → `lowerCamelCase` of the method name — plus the
/// attributes to carry onto the generated method.
fn entry_point_name(ident: &Ident, attrs: &[Attribute]) -> syn::Result<(String, Vec<Attribute>)> {
    let mut name = None;
    let mut kept = Vec::new();
    for attr in attrs {
        if !attr.path().is_ident("entry_point") {
            kept.push(attr.clone());
            continue;
        }
        if matches!(attr.meta, syn::Meta::Path(_)) {
            return Err(syn::Error::new_spanned(
                attr,
                "#[entry_point] needs the Compact circuit name: \
                 #[entry_point(name = \"…\")]",
            ));
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("name") {
                let lit: LitStr = meta.value()?.parse()?;
                name = Some(lit.value());
                Ok(())
            } else {
                Err(meta.error(
                    "unsupported entry-point attribute; expected \
                     #[entry_point(name = \"…\")]",
                ))
            }
        })?;
        if name.is_none() {
            return Err(syn::Error::new_spanned(
                attr,
                "#[entry_point] needs the Compact circuit name: \
                 #[entry_point(name = \"…\")]",
            ));
        }
    }
    let name = match name {
        Some(name) => name,
        None => {
            let derived = lower_camel_case(&ident.to_string());
            if derived.is_empty() {
                return Err(syn::Error::new(
                    ident.span(),
                    "the name yields an empty entry point; give one with \
                     #[entry_point(name = \"…\")]",
                ));
            }
            derived
        }
    };
    Ok((name, kept))
}

/// Cross-contract argument and result types are `Public`.
///
/// The check is SYNTACTIC — does the written type mention `Private`, and
/// does it mention `Public` — because the alternative is a trait-bound error
/// pointing at the generated call. It fires on the two ways to get it
/// wrong: an explicit `Private`, and a leaf whose visibility is left to
/// default (`Uint<128>` is `Uint<128, Private>`).
fn reject_undisclosed(ty: &Type, position: &str) -> syn::Result<()> {
    let tokens = quote!(#ty).to_string();
    let mentions = |ident: &str| {
        tokens
            .split(|ch: char| !ch.is_alphanumeric() && ch != '_')
            .any(|word| word == ident)
    };
    if mentions("Private") {
        return Err(syn::Error::new_spanned(
            ty,
            format!(
                "a cross-contract {position} is `Public`: passing a value to \
                 another contract DISCLOSES it — it enters the communications \
                 commitment the ledger matches in the clear. Disclose it \
                 first (`c.disclose(…)`) and write the type at `Public`."
            ),
        ));
    }
    if !mentions("Public") {
        return Err(syn::Error::new_spanned(
            ty,
            format!(
                "a cross-contract {position} must say `Public`: the leaf types \
                 default to `Private` (`Uint<128>` is `Uint<128, Private>`), \
                 and passing a value to another contract discloses it. Write \
                 `Uint<128, Public>` / `B32<Public>` / `Ty<Public>`, and \
                 `c.disclose(…)` whatever is private."
            ),
        ));
    }
    Ok(())
}

fn is_unit(ty: &Type) -> bool {
    matches!(ty, Type::Tuple(t) if t.elems.is_empty())
}

/// `sign_bidirectional` → `SIGN_BIDIRECTIONAL`.
fn screaming_snake_case(name: &str) -> String {
    name.strip_prefix("r#").unwrap_or(name).to_uppercase()
}

/// The handle struct and its inherent impl.
fn emit(vis: &Visibility, name: &Ident, attrs: &[Attribute], circuits: &[Circuit]) -> TokenStream {
    let ledger = quote!(::minocrab_ledger);
    let std_v3 = quote!(::minocrab_std::v3);
    let private = quote!(#std_v3::__private);

    let consts = circuits.iter().map(|circuit| {
        let const_ident = &circuit.const_ident;
        let entry_point = LitStr::new(&circuit.entry_point, circuit.ident.span());
        let doc = format!(
            "The callee's `{}` circuit. Its 32-byte key is DERIVED from this \
             name (`EntryPoint::hash` calls upstream's `EntryPointBuf::ep_hash`).",
            circuit.entry_point
        );
        quote! {
            #[doc = #doc]
            pub const #const_ident: #ledger::EntryPoint =
                #ledger::EntryPoint::new(#entry_point);
        }
    });

    let methods = circuits.iter().map(|circuit| {
        let Circuit { ident, const_ident, attrs, params, result, .. } = circuit;
        let names: Vec<&Ident> = params.iter().map(|(name, _)| name).collect();
        let types: Vec<&Type> = params.iter().map(|(_, ty)| ty).collect();
        let result = match result {
            Some(ty) => quote!(#ty),
            None => quote!(()),
        };
        quote! {
            #( #attrs )*
            pub fn #ident<__V: #private::OnChainGuard + ::core::marker::Copy>(
                self,
                c: &mut #private::Circuit3,
                guard: #private::Wire3<#private::FieldT, __V>,
                #( #names: #types, )*
            ) -> #result {
                #ledger::call(c, guard, self.callee, Self::#const_ident, (#( #names, )*))
            }
        }
    });

    quote! {
        #( #attrs )*
        #[derive(::core::clone::Clone, ::core::marker::Copy)]
        #vis struct #name {
            callee: #ledger::Callee,
        }

        #[automatically_derived]
        impl #name {
            #( #consts )*

            /// The callee's address lives in this ledger field (an
            /// `export sealed ledger` reference). EVERY call site re-reads
            /// the cell, uncached, as compactc does.
            pub const fn at_field(index: u8) -> Self {
                Self { callee: #ledger::Callee::Field(index) }
            }

            /// [`Self::at_field`] by ledger field PATH — the form a block of
            /// sixteen fields or more needs, since compactc segments it and
            /// its fields have no single index.
            pub const fn at_field_path(path: &[u8]) -> Self {
                ::core::assert!(!path.is_empty() && path.len() <= 3, "a ledger field path has one to three elements");
                let mut elems = [0u8; 3];
                let mut i = 0;
                while i < path.len() {
                    elems[i] = path[i];
                    i += 1;
                }
                Self { callee: #ledger::Callee::FieldPath(elems, path.len() as u8) }
            }

            /// The callee's address as data.
            pub fn at(address: #std_v3::ContractAddress<#private::Public>) -> Self {
                Self { callee: #ledger::Callee::Pinned(address.limbs()) }
            }

            /// Resolve an [`Self::at_field`] handle's address NOW — for the
            /// call whose argument expressions emit instructions, where
            /// compactc's receiver-first evaluation order is visible.
            pub fn pin<__V: #private::OnChainGuard + ::core::marker::Copy>(
                self,
                c: &mut #private::Circuit3,
                guard: #private::Wire3<#private::FieldT, __V>,
            ) -> Self {
                Self { callee: #ledger::Callee::pin(self.callee, c, guard) }
            }

            /// Where this handle's address comes from.
            pub fn callee(self) -> #ledger::Callee {
                self.callee
            }

            #( #methods )*
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expansion(item: ItemTrait) -> String {
        expand(item).expect("expands").to_string()
    }

    fn error(item: ItemTrait) -> String {
        expand(item).expect_err("rejected").to_string()
    }

    fn token_fixture() -> ItemTrait {
        syn::parse_quote! {
            pub trait Token {
                fn deposit(amount: Uint<128, Public>, caller: ContractAddress<Public>) -> B32<Public>;
                #[entry_point(name = "depositEmit")]
                fn deposit_emit(recipient: B32<Public>);
            }
        }
    }

    /// THINNESS RULE: the expansion builds no circuit — `c` is threaded to
    /// `minocrab_ledger::call` and never called on.
    #[test]
    fn the_expansion_calls_no_circuit_method() {
        let expanded = expansion(token_fixture());
        assert!(!expanded.contains("c ."), "expansion calls a method on the circuit:\n{expanded}");
        assert!(
            !expanded.contains("Circuit3 ::"),
            "expansion calls a Circuit3 associated function:\n{expanded}"
        );
    }

    #[test]
    fn entry_points_are_derived_from_the_method_names() {
        let expanded = expansion(token_fixture());
        assert!(expanded.contains(r#"const DEPOSIT : :: minocrab_ledger :: EntryPoint"#), "{expanded}");
        assert!(expanded.contains(r#"EntryPoint :: new ("deposit")"#), "{expanded}");
        // …and the escape hatch wins where the Compact name is not the
        // mechanical camel-case of the Rust one.
        assert!(expanded.contains(r#"EntryPoint :: new ("depositEmit")"#), "{expanded}");
        assert!(expanded.contains("const DEPOSIT_EMIT"), "{expanded}");
    }

    #[test]
    fn the_trait_becomes_a_handle_struct_with_both_constructors() {
        let expanded = expansion(token_fixture());
        assert!(expanded.contains("pub struct Token"), "{expanded}");
        assert!(!expanded.contains("trait Token"), "the trait must be replaced:\n{expanded}");
        assert!(expanded.contains("const fn at_field"), "{expanded}");
        assert!(expanded.contains("fn at ("), "{expanded}");
        assert!(expanded.contains("fn pin <"), "{expanded}");
    }

    #[test]
    fn arguments_are_passed_as_a_tuple_in_declaration_order() {
        let expanded = expansion(token_fixture());
        assert!(
            expanded.contains("call (c , guard , self . callee , Self :: DEPOSIT , (amount , caller ,))"),
            "{expanded}"
        );
    }

    #[test]
    fn a_returnless_circuit_returns_unit() {
        let expanded = expansion(syn::parse_quote! {
            trait T {
                fn ping();
            }
        });
        assert!(expanded.contains("-> ()"), "{expanded}");
        assert!(expanded.contains("Self :: PING , ())"), "{expanded}");
    }

    // ---- the error inventory ------------------------------------------------

    #[test]
    fn a_private_argument_names_disclose() {
        let err = error(syn::parse_quote! {
            trait T {
                fn f(x: B32<Private>);
            }
        });
        assert!(err.contains("disclose"), "{err}");
        assert!(err.contains("cross-contract parameter"), "{err}");
    }

    #[test]
    fn an_argument_with_no_visibility_is_rejected_because_it_defaults_to_private() {
        let err = error(syn::parse_quote! {
            trait T {
                fn f(amount: Uint<128>);
            }
        });
        assert!(err.contains("must say `Public`"), "{err}");
        assert!(err.contains("disclose"), "{err}");
    }

    #[test]
    fn a_private_result_names_disclose() {
        let err = error(syn::parse_quote! {
            trait T {
                fn f() -> B32<Private>;
            }
        });
        assert!(err.contains("cross-contract result"), "{err}");
    }

    #[test]
    fn a_receiver_is_rejected() {
        let err = error(syn::parse_quote! {
            trait T {
                fn f(&self, x: B32<Public>);
            }
        });
        assert!(err.contains("no `self`"), "{err}");
    }

    #[test]
    fn a_default_body_is_rejected() {
        let err = error(syn::parse_quote! {
            trait T {
                fn f(x: B32<Public>) {}
            }
        });
        assert!(err.contains("has no body"), "{err}");
    }

    #[test]
    fn method_generics_async_and_friends_are_rejected() {
        assert!(error(syn::parse_quote! {
            trait T { fn f<X>(x: B32<Public>); }
        })
        .contains("no generic parameters"));
        assert!(error(syn::parse_quote! {
            trait T { async fn f(x: B32<Public>); }
        })
        .contains("not async"));
        assert!(error(syn::parse_quote! {
            trait T { unsafe fn f(x: B32<Public>); }
        })
        .contains("not unsafe"));
        assert!(error(syn::parse_quote! {
            trait T { fn f(x: B32<Public>) where B32<Public>: Sized; }
        })
        .contains("no where-clause"));
    }

    #[test]
    fn a_pattern_parameter_is_rejected() {
        let err = error(syn::parse_quote! {
            trait T { fn f((a, b): (B32<Public>, B32<Public>)); }
        });
        assert!(err.contains("plain `name: Type`"), "{err}");
    }

    #[test]
    fn trait_generics_supertraits_and_non_fn_items_are_rejected() {
        assert!(error(syn::parse_quote! {
            trait T<X> { fn f(x: B32<Public>); }
        })
        .contains("no generic parameters"));
        assert!(error(syn::parse_quote! {
            trait T: Clone { fn f(x: B32<Public>); }
        })
        .contains("no supertraits"));
        assert!(error(syn::parse_quote! {
            trait T { const K: u8; }
        })
        .contains("must be a bodyless `fn`"));
        assert!(error(syn::parse_quote! {
            unsafe trait T { fn f(x: B32<Public>); }
        })
        .contains("not unsafe"));
    }

    #[test]
    fn a_malformed_entry_point_attribute_is_an_error() {
        assert!(error(syn::parse_quote! {
            trait T {
                #[entry_point(rename = "x")]
                fn f(x: B32<Public>);
            }
        })
        .contains("expected #[entry_point(name"));
        assert!(error(syn::parse_quote! {
            trait T {
                #[entry_point]
                fn f(x: B32<Public>);
            }
        })
        .contains("needs the Compact circuit name"));
    }
}
