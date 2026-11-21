//! The ARGUMENT family of a record, shared by `#[derive(Value)]`,
//! `#[derive(CircuitBorsh)]` and `#[circuit]`'s hidden argument struct.
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
//! impl<__V: Visibility> Encode<__V> for DepositRequest {
//!     fn encode(&self, slots) { self.erc20_address.encode(slots); self.amount.encode(slots); }
//! }
//! impl<__V: Visibility> Decode<__V> for DepositRequest { /* the fields, at a running offset */ }
//! impl CircuitArg for DepositRequest {
//!     fn declare(c, path) -> Self { Self {
//!         erc20_address: <Bytes<20>>::declare(c, &path.field("erc20Address")),
//!         amount:        <Uint<128>>::declare(c, &path.field("amount")),
//!     } }
//! }
//! ```
//!
//! plus the same list as a `CircuitArgs` (fields at the root instead of
//! under a path), delegating its slots and atoms to the `CircuitArg` /
//! `CircuitAbi` impls so the three cannot disagree. There is no generated
//! `constrain`: it is `CircuitArg`'s provided body, which runs compactc's
//! ONE constraint table over `push_prims` and the encoded slots.

use proc_macro2::TokenStream;
use quote::quote;
use syn::spanned::Spanned;
use syn::{parse_quote, Attribute, Data, DeriveInput, Fields, Generics, Ident, LitStr, Type};

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

/// Where the impls of a record apply.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArgBounds {
    /// Under the struct's own where-clause: the schema and argument impls are
    /// unconditional, so a field that is not an argument is an error at the
    /// definition. `#[circuit]`'s hidden struct and a plain
    /// `#[derive(CircuitBorsh)]` record, both of which only ever are
    /// arguments.
    Plain,
    /// Every impl holds exactly where every FIELD's impl of the same trait
    /// holds, so rustc decides which apply. This is how one declaration of a
    /// `Notification<V: Vis>` serves the callee's arguments at `Private`
    /// and a caller's cross-contract call at `Public`, and how a record
    /// generic over its payload (`Owned<E>`) is a ledger value exactly where
    /// `E` is. Each bound is written `for<'__w> Field: Trait`: a bound with
    /// no generic parameter in it is otherwise checked at the definition,
    /// and a record of `Public` fields would fail to compile for not being
    /// a `CircuitArg` rather than simply not being one.
    PerField,
}

/// The self type and impl parameters of a record, and the where-clause each
/// trait's impl carries.
pub(crate) struct Target<'a> {
    pub(crate) generics: &'a Generics,
    pub(crate) self_ty: TokenStream,
    pub(crate) fields: &'a [ArgField],
    /// The `#[arg(skip)]` fields, rebuilt with `Default::default()`.
    pub(crate) skipped: &'a [Ident],
    pub(crate) bounds: ArgBounds,
}

impl Target<'_> {
    /// The skipped fields' initializers, for a struct literal.
    pub(crate) fn skipped_init(&self) -> TokenStream {
        let skipped = self.skipped;
        quote!(#( #skipped: ::core::default::Default::default(), )*)
    }

    /// The impl parameters: the struct's own.
    pub(crate) fn impl_generics(&self) -> TokenStream {
        let (impl_generics, _, _) = self.generics.split_for_impl();
        quote!(#impl_generics)
    }

    /// The impl parameters plus the slots' visibility `__V`, for `Encode` /
    /// `Decode`, which are written once for both visibilities.
    pub(crate) fn impl_generics_with_vis(&self) -> TokenStream {
        let mut generics = self.generics.clone();
        generics
            .params
            .push(parse_quote!(__V: ::minocrab_std::__private::Visibility));
        let (impl_generics, _, _) = generics.split_for_impl();
        quote!(#impl_generics)
    }

    /// The where-clause of the impl of `bound`: the user's predicates, and
    /// in [`ArgBounds::PerField`] mode (or when `per_field` forces it) one
    /// per field type.
    pub(crate) fn clause(&self, bound: &TokenStream, per_field: bool) -> TokenStream {
        let user = self.generics.where_clause.iter().flat_map(|w| w.predicates.iter());
        if per_field || self.bounds == ArgBounds::PerField {
            let types = self.fields.iter().map(|f| &f.ty);
            quote!(where #( for<'__w> #types: #bound, )* #( #user, )*)
        } else {
            quote!(where #( #user, )*)
        }
    }
}

pub fn expand(input: DeriveInput) -> syn::Result<TokenStream> {
    crate::value::expand_checked(input, crate::value::Check::CircuitArg)
}

/// Whether a type parameter is the struct's visibility (`V: Vis`). Shared
/// with `#[derive(CircuitBorsh)]`, which serializes such a struct at every
/// `V`.
pub(crate) fn bounded_by_vis(param: &syn::TypeParam) -> bool {
    param.bounds.iter().any(|bound| match bound {
        syn::TypeParamBound::Trait(t) => t
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "Vis" || segment.ident == crate::OLD_VIS),
        _ => false,
    })
}

/// The family for `#[circuit]`'s hidden argument struct: a struct's name and
/// its fields in wire order.
pub(crate) fn impl_arg_traits(
    name: &Ident,
    generics: &Generics,
    fields: &[ArgField],
) -> TokenStream {
    let (_, ty_generics, _) = generics.split_for_impl();
    impl_arg_traits_for(&Target {
        generics,
        self_ty: quote!(#name #ty_generics),
        fields,
        skipped: &[],
        bounds: ArgBounds::Plain,
    })
}

/// The argument family: `CircuitAbi`, `Encode`, `CircuitArg`, `CircuitArgs`,
/// and in [`ArgBounds::PerField`] mode `Decode` (a `Plain` record is only
/// ever an argument, and nothing decodes one).
pub(crate) fn impl_arg_traits_for(target: &Target) -> TokenStream {
    let fields = target.fields;
    let self_ty = &target.self_ty;
    let impl_generics = target.impl_generics();
    let impl_generics_v = target.impl_generics_with_vis();
    let idents: Vec<&Ident> = fields.iter().map(|f| &f.ident).collect();
    let types: Vec<&Type> = fields.iter().map(|f| &f.ty).collect();
    let labels: Vec<LitStr> = fields
        .iter()
        .map(|f| LitStr::new(&f.label, f.ident.span()))
        .collect();

    // Every path the expansion names is fully qualified, and none of them is
    // a `Circuit` method: `c` is only ever passed along (THINNESS RULE,
    // notes/contract-api.org §macros).
    let skipped = target.skipped_init();
    let root = quote!(::minocrab_std);
    let abi_where = target.clause(&quote!(#root::CircuitAbi), false);
    let encode_where = target.clause(&quote!(#root::Encode<__V>), true);
    let arg_where = target.clause(&quote!(#root::CircuitArg), false);
    let decode = (target.bounds == ArgBounds::PerField).then(|| {
        let decode_where = target.clause(&quote!(#root::Decode<__V>), true);
        quote! {
            #[automatically_derived]
            impl #impl_generics_v #root::Decode<__V> for #self_ty #decode_where {
                fn decode(
                    slots: &[#root::__private::Wire<#root::__private::FieldT, __V>],
                ) -> Self {
                    // Struct-literal fields are evaluated in written order,
                    // which is the slot order, so the running offset is the
                    // layout.
                    #[allow(unused_mut, unused_variables)]
                    let mut __offset = 0usize;
                    Self {
                        #(
                            #idents: {
                                let __n = <#types as #root::CircuitAbi>::SLOTS;
                                let __value = <#types as #root::Decode<__V>>::decode(
                                    &slots[__offset..__offset + __n],
                                );
                                __offset += __n;
                                __value
                            },
                        )*
                        #skipped
                    }
                }
            }
        }
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
        impl #impl_generics_v #root::Encode<__V> for #self_ty #encode_where {
            fn encode(
                &self,
                slots: &mut ::std::vec::Vec<#root::__private::Wire<#root::__private::FieldT, __V>>,
            ) {
                #( <#types as #root::Encode<__V>>::encode(&self.#idents, slots); )*
            }
        }

        #decode

        #[automatically_derived]
        impl #impl_generics #root::CircuitArg for #self_ty #arg_where {
            fn declare(
                c: &mut #root::__private::Circuit,
                path: &#root::ArgPath,
            ) -> Self {
                Self {
                    #(
                        #idents: <#types as #root::CircuitArg>::declare(
                            c,
                            &#root::ArgPath::field(path, #labels),
                        ),
                    )*
                    #skipped
                }
            }
        }

        #[automatically_derived]
        impl #impl_generics #root::CircuitArgs for #self_ty #arg_where {
            const SLOTS: usize = <Self as #root::CircuitAbi>::SLOTS;

            fn declare(c: &mut #root::__private::Circuit) -> Self {
                Self {
                    #(
                        #idents: <#types as #root::CircuitArg>::declare(
                            c,
                            &#root::ArgPath::root(#labels),
                        ),
                    )*
                    #skipped
                }
            }

            fn constrain(&self, c: &mut #root::__private::Circuit) {
                <Self as #root::CircuitArg>::constrain(self, c)
            }

            fn atoms() -> ::std::vec::Vec<#root::__private::AlignmentAtom> {
                <Self as #root::CircuitAbi>::atoms()
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
                    "a value record needs named fields: a field's name is \
                     the label of the slots it declares",
                ))
            }
        },
        Data::Enum(_) | Data::Union(_) => {
            return Err(syn::Error::new(
                input.ident.span(),
                "a value can only be derived for a struct — Compact's \
                 sum types are Maybe/Either, which have their own impls",
            ))
        }
    };

    let mut out = Vec::new();
    for field in fields {
        if is_skipped(&field.attrs)? {
            continue;
        }
        let ident = field.ident.clone().expect("named fields");
        let label = arg_label(&ident, &field.attrs)?;
        out.push(ArgField { ident, ty: field.ty.clone(), label });
    }
    Ok(out)
}

/// The fields marked `#[arg(skip)]`: a type-state marker (a `PhantomData`)
/// that is no part of the value. It contributes no slot, atom or bound, and
/// is rebuilt with `Default::default()`.
pub(crate) fn skipped_fields(input: &DeriveInput) -> syn::Result<Vec<Ident>> {
    let Data::Struct(s) = &input.data else { return Ok(Vec::new()) };
    let mut out = Vec::new();
    for field in &s.fields {
        if is_skipped(&field.attrs)? {
            out.push(field.ident.clone().expect("named fields"));
        }
    }
    Ok(out)
}

fn is_skipped(attrs: &[Attribute]) -> syn::Result<bool> {
    let mut skip = false;
    for attr in attrs.iter().filter(|a| a.path().is_ident("arg")) {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("skip") {
                skip = true;
            } else if meta.path.is_ident("name") {
                let _: LitStr = meta.value()?.parse()?;
            } else {
                return Err(meta.error(
                    "unsupported argument attribute; expected name = \"…\" or skip",
                ));
            }
            Ok(())
        })?;
    }
    Ok(skip)
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
                Err(meta.error("unsupported argument attribute; expected name = \"…\" (`skip` is for a struct field)"))
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
            !expanded.contains("Circuit ::"),
            "expansion calls a Circuit associated function:\n{expanded}"
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
