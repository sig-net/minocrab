//! `#[derive(CircuitArg)]`: the struct impls phase 2 wrote by hand.
//!
//! For `struct DepositRequest { erc20_address: Bytes<20>, amount: Uint<128> }`
//! the expansion is
//!
//! ```ignore
//! impl CircuitArg for DepositRequest {
//!     const SLOTS: usize = 0 + <Bytes<20>>::SLOTS + <Uint<128>>::SLOTS;
//!     fn push_atoms(atoms) { <Bytes<20>>::push_atoms(atoms); <Uint<128>>::push_atoms(atoms); }
//!     fn declare(c, path) -> Self { Self {
//!         erc20_address: <Bytes<20>>::declare(c, &path.field("erc20Address")),
//!         amount:        <Uint<128>>::declare(c, &path.field("amount")),
//!     } }
//!     fn constrain(&self, c) { self.erc20_address.constrain(c); self.amount.constrain(c); }
//! }
//! ```
//!
//! plus the same list as a `CircuitArgs` (fields at the root instead of
//! under a path), delegating its constraints and atoms to the `CircuitArg`
//! impl so the two cannot disagree.

use proc_macro2::TokenStream;
use quote::quote;
use syn::spanned::Spanned;
use syn::{Data, DeriveInput, Fields, Ident, LitStr, Type};

/// One field of the derived struct: where its value lives and how its slots
/// are labelled.
struct ArgField {
    ident: Ident,
    ty: Type,
    /// The path segment this field contributes — `lowerCamelCase` of the
    /// field name, or the `#[arg(name = "…")]` override.
    label: String,
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
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

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

    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics #root::CircuitArg for #name #ty_generics #where_clause {
            const SLOTS: usize = 0usize #( + <#types as #root::CircuitArg>::SLOTS )*;

            fn push_atoms(atoms: &mut ::std::vec::Vec<#root::__private::AlignmentAtom>) {
                #( <#types as #root::CircuitArg>::push_atoms(atoms); )*
            }

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

            fn constrain(&self, c: &mut #root::__private::Circuit3) {
                #( <#types as #root::CircuitArg>::constrain(&self.#idents, c); )*
            }
        }

        #[automatically_derived]
        impl #impl_generics #root::CircuitArgs for #name #ty_generics #where_clause {
            const SLOTS: usize = <Self as #root::CircuitArg>::SLOTS;

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
                <Self as #root::CircuitArg>::atoms()
            }
        }
    })
}

/// The fields, in declaration order — which IS the wire order.
fn arg_fields(input: &DeriveInput) -> syn::Result<Vec<ArgField>> {
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
            let label = match arg_name(field)? {
                Some(name) => name,
                None => {
                    let name = lower_camel_case(&ident.to_string());
                    if name.is_empty() {
                        return Err(syn::Error::new(
                            ident.span(),
                            "field name yields an empty label; give one with \
                             #[arg(name = \"…\")]",
                        ));
                    }
                    name
                }
            };
            Ok(ArgField { ident, ty: field.ty.clone(), label })
        })
        .collect()
}

/// The `#[arg(name = "…")]` override, if the field carries one.
fn arg_name(field: &syn::Field) -> syn::Result<Option<String>> {
    let mut name = None;
    for attr in field.attrs.iter().filter(|a| a.path().is_ident("arg")) {
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
fn lower_camel_case(name: &str) -> String {
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
