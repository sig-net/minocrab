//! `#[derive(CircuitArg)]`: the struct impls phase 2 wrote by hand.
//!
//! For `struct DepositRequest { erc20_address: Bytes<20>, amount: Uint<128> }`
//! the expansion is
//!
//! ```ignore
//! impl CircuitAbi for DepositRequest {
//!     const SLOTS: usize = 0 + <Bytes<20>>::SLOTS + <Uint<128>>::SLOTS;
//!     fn push_atoms(atoms) { <Bytes<20>>::push_atoms(atoms); <Uint<128>>::push_atoms(atoms); }
//!     fn push_prims(prims) { <Bytes<20>>::push_prims(prims); <Uint<128>>::push_prims(prims); }
//! }
//! impl CircuitArg for DepositRequest {
//!     fn declare(c, path) -> Self { Self {
//!         erc20_address: <Bytes<20>>::declare(c, &path.field("erc20Address")),
//!         amount:        <Uint<128>>::declare(c, &path.field("amount")),
//!     } }
//!     fn push_slots(&self, slots) {
//!         self.erc20_address.push_slots(slots); self.amount.push_slots(slots);
//!     }
//! }
//! ```
//!
//! plus the same list as a `CircuitArgs` (fields at the root instead of
//! under a path), delegating its slots and atoms to the `CircuitArg` /
//! `CircuitAbi` impls so the three cannot disagree. There is no generated
//! `constrain`: it is `CircuitArg`'s provided body, which runs compactc's
//! ONE constraint table over `push_prims` and `push_slots`.

use proc_macro2::TokenStream;
use quote::quote;
use syn::spanned::Spanned;
use syn::{Attribute, Data, DeriveInput, Fields, Generics, Ident, LitStr, Type};

/// One field of the argument struct: where its value lives and how its slots
/// are labelled.
///
/// The same three facts describe a derived struct's field and a `#[circuit]`
/// function's parameter, which is why both go through [`impl_arg_traits`].
pub(crate) struct ArgField {
    pub(crate) ident: Ident,
    pub(crate) ty: Type,
    /// The path segment this field contributes — `lowerCamelCase` of the
    /// field name, or the `#[arg(name = "…")]` override.
    pub(crate) label: String,
}

pub fn expand(input: DeriveInput) -> syn::Result<TokenStream> {
    if let Some(attr) = input.attrs.iter().find(|a| a.path().is_ident("arg")) {
        return Err(syn::Error::new_spanned(
            attr,
            "#[arg(..)] belongs on a field: a struct is named by the field or \
             parameter that holds it, not by itself",
        ));
    }

    let fields = arg_fields(&input)?;
    let types: Vec<&Type> = fields.iter().map(|f| &f.ty).collect();
    let name = &input.ident;
    let root = quote!(::minocrab_std::v3);

    // VISIBILITY-GENERIC MODE. `struct Notification<V: Vis3>` is one
    // declaration of a type that serves BOTH directions of the wire: the
    // callee's arguments at `Private`, a caller's cross-contract call at
    // `Public`. rustc decides which impls apply, from where-clauses over the
    // FIELD types — the M11 stage-3 trick, extended to the call side — so
    // the impls are written once and hold exactly where the leaves' do.
    let (impl_generics, self_ty, bounds) = match visibility_param(&input)? {
        Some(param) => (
            quote!(<#param: #root::Vis3>),
            quote!(#name<#param>),
            ArgBounds::visibility_generic(&input.generics, &types),
        ),
        None => {
            let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
            (
                quote!(#impl_generics),
                quote!(#name #ty_generics),
                ArgBounds::plain(&quote!(#where_clause)),
            )
        }
    };
    Ok(impl_arg_traits_for(&impl_generics, &self_ty, &bounds, &fields))
}

/// Where each impl of the family applies: one where-clause per trait,
/// bounding every FIELD type by that trait.
///
/// This is the M11 stage-3 trick generalized. A struct written
/// `Notification<V: Vis3>` is ONE declaration serving both directions of
/// the wire — the callee's arguments and a caller's cross-contract call —
/// and rather than substituting the parameter, the impls are written once
/// for every `V` and rustc decides where each applies: `CircuitArg` holds
/// exactly where the leaves' `CircuitArg` impls do (`Private`), `CallArg` /
/// `CallResult` exactly where theirs do (`Public`), and `CircuitAbi`
/// everywhere, because a schema is visibility-independent.
///
/// A struct with no visibility parameter gets the same clauses; they are
/// simply always satisfied (a `Private` struct's call impls are never
/// applicable, which is correct — its fields cannot cross a contract
/// boundary undisclosed).
pub(crate) struct ArgBounds {
    pub(crate) abi: TokenStream,
    pub(crate) arg: TokenStream,
    /// `(CallArg clause, CallResult clause)`, or `None` for a struct with
    /// no visibility parameter.
    ///
    /// A plain struct's fields have ONE visibility each, and for a concrete
    /// impl rustc checks the where-clause at the definition — so an
    /// all-`Private` struct would not merely fail to be a `CallArg`, it
    /// would fail to COMPILE. The call side is therefore emitted only where
    /// it can be conditional, which is the visibility-generic mode, and
    /// that is where it belongs: a type meant to cross a contract boundary
    /// is written `Ty<V: Vis3>` precisely because it serves both sides.
    pub(crate) call: Option<(TokenStream, TokenStream)>,
}

impl ArgBounds {
    /// The struct's own where-clause for the schema and argument impls, and
    /// no call impls.
    pub(crate) fn plain(where_clause: &TokenStream) -> ArgBounds {
        ArgBounds {
            abi: where_clause.clone(),
            arg: where_clause.clone(),
            call: None,
        }
    }

    /// One clause per trait, bounding every FIELD type by that trait, so
    /// rustc decides where each impl applies.
    pub(crate) fn visibility_generic(generics: &Generics, types: &[&Type]) -> ArgBounds {
        let user: Vec<&syn::WherePredicate> = generics
            .where_clause
            .iter()
            .flat_map(|w| w.predicates.iter())
            .collect();
        let root = quote!(::minocrab_std::v3);
        let clause = |trait_path: TokenStream| quote!(where #( #types: #trait_path, )* #( #user, )*);
        ArgBounds {
            abi: clause(quote!(#root::CircuitAbi)),
            arg: clause(quote!(#root::CircuitArg)),
            call: Some((
                clause(quote!(#root::CallArg)),
                clause(quote!(#root::CallResult)),
            )),
        }
    }
}

/// The struct's visibility parameter, if it has one — the marker that puts
/// the derive in visibility-generic mode. Shared with
/// `#[derive(CircuitBorsh)]`, which needs exactly the same judgement.
pub(crate) fn visibility_param(input: &DeriveInput) -> syn::Result<Option<Ident>> {
    let params: Vec<&syn::GenericParam> = input.generics.params.iter().collect();
    match params.as_slice() {
        [] => Ok(None),
        [syn::GenericParam::Type(param)] if bounded_by_vis3(param) => Ok(Some(param.ident.clone())),
        _ => Ok(None),
    }
}

pub(crate) fn bounded_by_vis3(param: &syn::TypeParam) -> bool {
    param.bounds.iter().any(|bound| match bound {
        syn::TypeParamBound::Trait(t) => t
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "Vis3"),
        _ => false,
    })
}

/// The family, from a struct's name and its fields in wire order — the
/// whole of `#[derive(CircuitArg)]`, and the half of `#[circuit]` that
/// describes its hidden argument struct.
pub(crate) fn impl_arg_traits(
    name: &Ident,
    generics: &Generics,
    fields: &[ArgField],
) -> TokenStream {
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    impl_arg_traits_for(
        &quote!(#impl_generics),
        &quote!(#name #ty_generics),
        &ArgBounds::plain(&quote!(#where_clause)),
        fields,
    )
}

/// [`impl_arg_traits`] for a self type the caller spells itself — what
/// `#[derive(CircuitBorsh)]` needs, since a `struct Payload<V: Vis3>` is a
/// circuit ARGUMENT only at `Payload<Private>` (arguments are witness data,
/// so `CircuitArg` exists for private leaves alone).
/// See [`ArgBounds`] for where each of the emitted impls applies.
pub(crate) fn impl_arg_traits_for(
    impl_generics: &TokenStream,
    self_ty: &TokenStream,
    bounds: &ArgBounds,
    fields: &[ArgField],
) -> TokenStream {
    let ArgBounds {
        abi: abi_where,
        arg: where_clause,
        call,
    } = bounds;
    let idents: Vec<&Ident> = fields.iter().map(|f| &f.ident).collect();
    let types: Vec<&Type> = fields.iter().map(|f| &f.ty).collect();
    let labels: Vec<LitStr> = fields
        .iter()
        .map(|f| LitStr::new(&f.label, f.ident.span()))
        .collect();

    // Every path the expansion names is fully qualified, and none of them is
    // a `Circuit3` method: `c` is only ever passed along (THINNESS RULE,
    // notes/contract-api.org §macros).
    let root = quote!(::minocrab_std::v3);

    let call_impls = call.as_ref().map(|(call_arg_where, call_result_where)| {
        impl_call_traits(
            impl_generics,
            self_ty,
            call_arg_where,
            call_result_where,
            &idents,
            &types,
        )
    });

    quote! {
        #[automatically_derived]
        impl #impl_generics #root::CircuitAbi for #self_ty #abi_where {
            const SLOTS: usize = 0usize #( + <#types as #root::CircuitAbi>::SLOTS )*;

            fn push_atoms(atoms: &mut ::std::vec::Vec<#root::__private::AlignmentAtom>) {
                #( <#types as #root::CircuitAbi>::push_atoms(atoms); )*
            }

            fn push_prims(prims: &mut ::std::vec::Vec<#root::Prim>) {
                #( <#types as #root::CircuitAbi>::push_prims(prims); )*
            }
        }

        #[automatically_derived]
        impl #impl_generics #root::CircuitArg for #self_ty #where_clause {
            fn declare(
                c: &mut #root::__private::Circuit3,
                path: &#root::ArgPath,
            ) -> Self {
                Self {
                    #(
                        #idents: <#types as #root::CircuitArg>::declare(
                            c,
                            &#root::ArgPath::field(path, #labels),
                        ),
                    )*
                }
            }

            fn push_slots(
                &self,
                slots: &mut ::std::vec::Vec<
                    #root::__private::Wire3<
                        #root::__private::FieldT,
                        #root::__private::Private,
                    >,
                >,
            ) {
                #( <#types as #root::CircuitArg>::push_slots(&self.#idents, slots); )*
            }
        }

        #[automatically_derived]
        impl #impl_generics #root::CircuitArgs for #self_ty #where_clause {
            const SLOTS: usize = <Self as #root::CircuitAbi>::SLOTS;

            fn declare(c: &mut #root::__private::Circuit3) -> Self {
                Self {
                    #(
                        #idents: <#types as #root::CircuitArg>::declare(
                            c,
                            &#root::ArgPath::root(#labels),
                        ),
                    )*
                }
            }

            fn constrain(&self, c: &mut #root::__private::Circuit3) {
                <Self as #root::CircuitArg>::constrain(self, c)
            }

            fn atoms() -> ::std::vec::Vec<#root::__private::AlignmentAtom> {
                <Self as #root::CircuitAbi>::atoms()
            }
        }

        #call_impls
    }
}


/// The caller's half of the family, emitted only in visibility-generic
/// mode (see [`ArgBounds::call`]).
fn impl_call_traits(
    impl_generics: &TokenStream,
    self_ty: &TokenStream,
    call_arg_where: &TokenStream,
    call_result_where: &TokenStream,
    idents: &[&Ident],
    types: &[&Type],
) -> TokenStream {
    let root = quote!(::minocrab_std::v3);
    quote! {
        #[automatically_derived]
        impl #impl_generics #root::CallArg for #self_ty #call_arg_where {
            fn push_call_slots(
                &self,
                slots: &mut ::std::vec::Vec<
                    #root::__private::Wire3<
                        #root::__private::FieldT,
                        #root::__private::Public,
                    >,
                >,
            ) {
                #( <#types as #root::CallArg>::push_call_slots(&self.#idents, slots); )*
            }
        }

        #[automatically_derived]
        impl #impl_generics #root::CallResult for #self_ty #call_result_where {
            fn from_call_slots(
                slots: &[
                    #root::__private::Wire3<
                        #root::__private::FieldT,
                        #root::__private::Public,
                    >
                ],
            ) -> Self {
                // Struct-literal fields are evaluated in written order, which
                // is the slot order, so the running offset is the layout.
                #[allow(unused_mut, unused_variables)]
                let mut __offset = 0usize;
                Self {
                    #(
                        #idents: {
                            let __n = <#types as #root::CircuitAbi>::SLOTS;
                            let __value = <#types as #root::CallResult>::from_call_slots(
                                &slots[__offset..__offset + __n],
                            );
                            __offset += __n;
                            __value
                        },
                    )*
                }
            }
        }
    }
}

/// The fields, in declaration order — which IS the wire order.
pub(crate) fn arg_fields(input: &DeriveInput) -> syn::Result<Vec<ArgField>> {
    let fields = match &input.data {
        Data::Struct(s) => match &s.fields {
            Fields::Named(named) => &named.named,
            other => {
                return Err(syn::Error::new(
                    other.span(),
                    "CircuitArg needs named fields: a field's name is the \
                     label of the slots it declares",
                ))
            }
        },
        Data::Enum(_) | Data::Union(_) => {
            return Err(syn::Error::new(
                input.ident.span(),
                "CircuitArg can only be derived for a struct — Compact's \
                 sum types are Maybe/Either, which have their own impls",
            ))
        }
    };

    fields
        .iter()
        .map(|field| {
            let ident = field.ident.clone().expect("named fields");
            let label = arg_label(&ident, &field.attrs)?;
            Ok(ArgField { ident, ty: field.ty.clone(), label })
        })
        .collect()
}

/// The label one field or parameter contributes: its `#[arg(name = "…")]`
/// override, else the mechanical `lowerCamelCase` of its name.
pub(crate) fn arg_label(ident: &Ident, attrs: &[Attribute]) -> syn::Result<String> {
    if let Some(name) = arg_name(attrs)? {
        return Ok(name);
    }
    let name = lower_camel_case(&ident.to_string());
    if name.is_empty() {
        return Err(syn::Error::new(
            ident.span(),
            "the name yields an empty label; give one with #[arg(name = \"…\")]",
        ));
    }
    Ok(name)
}

/// The `#[arg(name = "…")]` override, if the field or parameter carries one.
fn arg_name(attrs: &[Attribute]) -> syn::Result<Option<String>> {
    let mut name = None;
    for attr in attrs.iter().filter(|a| a.path().is_ident("arg")) {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("name") {
                let lit: LitStr = meta.value()?.parse()?;
                name = Some(lit.value());
                Ok(())
            } else {
                Err(meta.error("unsupported argument attribute; expected name = \"…\""))
            }
        })?;
    }
    Ok(name)
}

/// `snake_case` → `lowerCamelCase`: the mechanical Rust-name-to-Compact-name
/// rule (`max_fee_per_gas` → `maxFeePerGas`), which reproduces the corpus's
/// existing labels. Raw identifiers lose their `r#`.
pub(crate) fn lower_camel_case(name: &str) -> String {
    let name = name.strip_prefix("r#").unwrap_or(name);
    let mut out = String::with_capacity(name.len());
    for (i, segment) in name.split('_').filter(|s| !s.is_empty()).enumerate() {
        if i == 0 {
            out.push_str(segment);
        } else {
            let mut chars = segment.chars();
            if let Some(first) = chars.next() {
                out.extend(first.to_uppercase());
                out.push_str(chars.as_str());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_names_become_compact_labels() {
        assert_eq!(lower_camel_case("amount"), "amount");
        assert_eq!(lower_camel_case("evm_nonce"), "evmNonce");
        assert_eq!(lower_camel_case("max_priority_fee_per_gas"), "maxPriorityFeePerGas");
        assert_eq!(lower_camel_case("erc20_address"), "erc20Address");
        assert_eq!(lower_camel_case("big_r"), "bigR");
        assert_eq!(lower_camel_case("recovery_id"), "recoveryId");
        assert_eq!(lower_camel_case("r#type"), "type");
        assert_eq!(lower_camel_case("_leading"), "leading");
    }

    fn expansion(input: syn::DeriveInput) -> String {
        expand(input).expect("expands").to_string()
    }

    /// THINNESS RULE: the expansion may not build any circuit — `c` is
    /// passed along and never called on.
    #[test]
    fn the_expansion_calls_no_circuit_method() {
        let expanded = expansion(syn::parse_quote! {
            struct DepositRequest {
                erc20_address: Bytes<20>,
                amount: Uint<128>,
            }
        });
        assert!(!expanded.contains("c ."), "expansion calls a method on the circuit:\n{expanded}");
        assert!(
            !expanded.contains("Circuit3 ::"),
            "expansion calls a Circuit3 associated function:\n{expanded}"
        );
    }

    #[test]
    fn labels_are_the_camel_cased_field_names() {
        let expanded = expansion(syn::parse_quote! {
            struct DepositRequest {
                erc20_address: Bytes<20>,
                amount: Uint<128>,
            }
        });
        assert!(expanded.contains(r#"field (path , "erc20Address")"#), "{expanded}");
        assert!(expanded.contains(r#"root ("erc20Address")"#), "{expanded}");
    }

    #[test]
    fn the_name_attribute_overrides_one_label() {
        let expanded = expansion(syn::parse_quote! {
            struct ClaimArgs {
                #[arg(name = "respond")]
                respond_bidirectional_event: RespondSignature,
            }
        });
        assert!(expanded.contains(r#"root ("respond")"#), "{expanded}");
        assert!(!expanded.contains("respondBidirectionalEvent"), "{expanded}");
    }

    #[test]
    fn only_structs_with_named_fields_derive() {
        let err = expand(syn::parse_quote! {
            enum Recipient { Key(B32), Contract(B32) }
        })
        .expect_err("enums are rejected");
        assert!(err.to_string().contains("only be derived for a struct"));

        let err = expand(syn::parse_quote! {
            struct Wrapper(Uint<64>);
        })
        .expect_err("tuple structs are rejected");
        assert!(err.to_string().contains("named fields"));
    }

    #[test]
    fn an_unknown_attribute_is_an_error() {
        let err = expand(syn::parse_quote! {
            struct Args {
                #[arg(rename = "x")]
                a: Uint<64>,
            }
        })
        .expect_err("only name = \"…\" is supported");
        assert!(err.to_string().contains("expected name"));
    }
}
