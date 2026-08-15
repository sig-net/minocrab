//! `#[derive(CircuitBorsh)]`: the serialization impls stage 1 wrote by hand.
//!
//! For
//!
//! ```ignore
//! #[derive(CircuitBorsh)]
//! #[borsh(spec = spec_types::RespondMisc)]
//! struct RespondPayload<V: Vis3> {
//!     request_id: B32<V>,
//!     recovery_id: Uint<8, V>,
//! }
//! ```
//!
//! the expansion is the `CircuitBorsh` impl (LEN, push_limbs, push_segments,
//! constrain_canonical, read, push_layout — every field in declaration order,
//! **which is the Borsh order**), the same `CircuitArg` + `CircuitArgs` impls
//! `#[derive(CircuitArg)]` emits (from the SAME code path, so the two derives
//! cannot drift), and — from `#[borsh(spec = …)]` — a generated `#[test]`
//! asserting the layout table IS `borsh::schema_container_of::<Spec>()`
//! walked into rows.
//!
//! Two label namespaces, deliberately:
//! - the ARGUMENT label is `lowerCamelCase` of the field name (Compact's
//!   convention), overridable with `#[arg(name = "…")]`;
//! - the LAYOUT path segment is the field name VERBATIM, because it is
//!   compared against borsh's own schema of the spec type, whose paths are
//!   the spec struct's Rust field names. `#[borsh(name = "…")]` overrides it
//!   where the two structs name a field differently.
//!
//! THINNESS RULE, as for every derive here: the expansion contains no
//! `Circuit3` method call at all — `c` is passed along and nothing else.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::spanned::Spanned;
use syn::{Attribute, Data, DeriveInput, Fields, GenericParam, Ident, LitStr, Path, Type};

use crate::circuit_arg::{arg_fields, impl_arg_traits_for, ArgField};

pub fn expand(input: DeriveInput) -> syn::Result<TokenStream> {
    if let Data::Enum(_) = &input.data {
        return Err(syn::Error::new(
            input.ident.span(),
            "CircuitBorsh derives for a struct: a data-carrying enum has no \
             fixed width (declare one record type per kind), and a fieldless \
             enum is Tag<K> — one Borsh byte, range-checked",
        ));
    }

    let spec = spec_attr(&input.attrs)?;
    let fields = arg_fields(&input)?;
    let spec_labels = spec_labels(&input)?;
    for field in &fields {
        reject_variable_width(&field.ty)?;
    }

    let name = &input.ident;
    let root = quote!(::minocrab_std::v3);
    let vis = visibility_param(&input)?;

    // `CircuitBorsh<V>` for the visibility the struct is written in, and the
    // argument impls only where every field is itself an argument — which is
    // at `Private`, since arguments are witness data. A visibility-generic
    // struct gets that as a where-clause rather than a substitution: the impl
    // is written once and rustc decides where it applies.
    let types: Vec<&Type> = fields.iter().map(|f| &f.ty).collect();
    let (borsh_generics, borsh_vis, self_ty, private_self_ty, arg_generics, arg_where) = match &vis
    {
        Some(param) => (
            quote!(<#param: #root::Vis3>),
            quote!(#param),
            quote!(#name<#param>),
            quote!(#name<#root::__private::Private>),
            quote!(<#param: #root::Vis3>),
            quote!(where #( #types: #root::CircuitArg, )*),
        ),
        None => (
            quote!(),
            quote!(#root::__private::Private),
            quote!(#name),
            quote!(#name),
            quote!(),
            quote!(),
        ),
    };

    let arg_impls = impl_arg_traits_for(&arg_generics, &self_ty, &arg_where, &fields);
    let borsh_impl = impl_borsh(
        &root,
        &borsh_generics,
        &borsh_vis,
        &self_ty,
        &fields,
        &spec_labels,
    );
    let spec_test = spec.map(|spec| spec_check(&root, name, &private_self_ty, &spec));

    Ok(quote! {
        #arg_impls
        #borsh_impl
        #spec_test
    })
}

/// The `CircuitBorsh` impl: every method walks the fields in declaration
/// order, which IS the Borsh order.
fn impl_borsh(
    root: &TokenStream,
    generics: &TokenStream,
    vis: &TokenStream,
    self_ty: &TokenStream,
    fields: &[ArgField],
    spec_labels: &[String],
) -> TokenStream {
    let idents: Vec<&Ident> = fields.iter().map(|f| &f.ident).collect();
    let types: Vec<&Type> = fields.iter().map(|f| &f.ty).collect();
    let labels: Vec<LitStr> = spec_labels
        .iter()
        .zip(fields)
        .map(|(label, field)| LitStr::new(label, field.ident.span()))
        .collect();

    quote! {
        #[automatically_derived]
        impl #generics #root::borsh::CircuitBorsh<#vis> for #self_ty {
            const LEN: usize = 0usize
                #( + <#types as #root::borsh::CircuitBorsh<#vis>>::LEN )*;

            fn push_limbs(&self, limbs: &mut #root::borsh::Limbs<#vis>) {
                #(
                    <#types as #root::borsh::CircuitBorsh<#vis>>::push_limbs(
                        &self.#idents, limbs,
                    );
                )*
            }

            fn push_segments(&self, out: &mut #root::Serializer<#vis>) {
                #(
                    <#types as #root::borsh::CircuitBorsh<#vis>>::push_segments(
                        &self.#idents, out,
                    );
                )*
            }

            fn constrain_canonical(&self, c: &mut #root::__private::Circuit3) {
                #(
                    <#types as #root::borsh::CircuitBorsh<#vis>>::constrain_canonical(
                        &self.#idents, c,
                    );
                )*
            }

            fn read<__R: #root::borsh::BorshReader<#vis>>(
                c: &mut #root::__private::Circuit3,
                r: &mut __R,
            ) -> Self {
                Self {
                    #(
                        #idents: <#types as #root::borsh::CircuitBorsh<#vis>>::read(c, r),
                    )*
                }
            }

            fn push_layout(
                path: &#root::borsh::LayoutPath,
                offset: &mut usize,
                out: &mut ::std::vec::Vec<#root::borsh::FieldSpec>,
            ) {
                #(
                    <#types as #root::borsh::CircuitBorsh<#vis>>::push_layout(
                        &#root::borsh::LayoutPath::field(path, #labels),
                        offset,
                        out,
                    );
                )*
            }
        }
    }
}

/// The `#[borsh(spec = …)]` cross-check: our layout table against borsh's own
/// schema of the spec type, as a generated test.
fn spec_check(
    root: &TokenStream,
    name: &Ident,
    private_self_ty: &TokenStream,
    spec: &Path,
) -> TokenStream {
    let test = format_ident!("__minocrab_borsh_spec_{}", name);
    quote! {
        #[cfg(test)]
        #[test]
        #[allow(non_snake_case)]
        fn #test() {
            #root::borsh::schema::assert_matches_schema::<#spec>(
                ::core::stringify!(#name),
                &<#private_self_ty as #root::borsh::CircuitBorsh<
                    #root::__private::Private,
                >>::layout(),
            );
        }
    }
}

/// The struct's visibility parameter, if it has one: `struct Payload<V: Vis3>`
/// serializes at every visibility, a plain struct at `Private`.
fn visibility_param(input: &DeriveInput) -> syn::Result<Option<Ident>> {
    let params: Vec<&GenericParam> = input.generics.params.iter().collect();
    match params.as_slice() {
        [] => Ok(None),
        [GenericParam::Type(param)] if bounded_by_vis3(param) => Ok(Some(param.ident.clone())),
        _ => Err(syn::Error::new(
            input.generics.span(),
            "CircuitBorsh derives for a plain struct or one generic in a \
             single visibility parameter (`struct Payload<V: Vis3>`): a wire \
             type carries its visibility, and there is nothing else for a \
             serialized record to be generic in",
        )),
    }
}

fn bounded_by_vis3(param: &syn::TypeParam) -> bool {
    param.bounds.iter().any(|bound| match bound {
        syn::TypeParamBound::Trait(t) => t
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "Vis3"),
        _ => false,
    })
}

/// Field types whose Borsh encoding is value-dependent, each with the subset's
/// replacement. The check is syntactic — the type's last path segment — which
/// catches every way the standard names are spelled in practice and never
/// fires on a user type of another name (that one fails later, on the missing
/// `CircuitBorsh` impl, which is also a clear message).
fn reject_variable_width(ty: &Type) -> syn::Result<()> {
    let Type::Path(path) = ty else { return Ok(()) };
    let Some(segment) = path.path.segments.last() else {
        return Ok(());
    };
    let replacement = match segment.ident.to_string().as_str() {
        "Option" => {
            "Option is not in the fixed-width subset: Borsh omits the payload \
             on None, so every following offset would depend on the value. Use \
             Flagged<T> — a bool tag and an ALWAYS-PRESENT payload, which is \
             what Compact's Maybe already compiles to. Maybe ↦ Flagged, never \
             Option"
        }
        "Vec" | "VecDeque" => {
            "Vec is not in the fixed-width subset: its u32 length prefix makes \
             the layout value-dependent. Use [T; K] plus a separate count \
             field, as the deployed record does with noWords"
        }
        "String" | "str" | "CString" | "OsString" => {
            "String is not in the fixed-width subset: its u32 length prefix \
             makes the layout value-dependent. Use Bytes<N> / BytesN<V, N> \
             plus a separate length field"
        }
        "HashMap" | "BTreeMap" | "HashSet" | "BTreeSet" => {
            "maps and sets are not in the fixed-width subset: the length prefix \
             makes the layout value-dependent. Use [(K, V); N] plus a count"
        }
        _ => return Ok(()),
    };
    Err(syn::Error::new(ty.span(), replacement))
}

/// The `#[borsh(spec = path::To::Type)]` attribute on the struct.
fn spec_attr(attrs: &[Attribute]) -> syn::Result<Option<Path>> {
    let mut spec = None;
    for attr in attrs.iter().filter(|a| a.path().is_ident("borsh")) {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("spec") {
                if spec.is_some() {
                    return Err(meta.error("#[borsh(spec = …)] given twice"));
                }
                spec = Some(meta.value()?.parse::<Path>()?);
                Ok(())
            } else {
                Err(meta.error(
                    "unsupported borsh attribute; expected spec = path::To::SpecType",
                ))
            }
        })?;
    }
    Ok(spec)
}

/// The LAYOUT path segment of each field: its name verbatim (the spec type's
/// own field name), or the `#[borsh(name = "…")]` override.
fn spec_labels(input: &DeriveInput) -> syn::Result<Vec<String>> {
    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new(input.ident.span(), "CircuitBorsh derives for a struct"));
    };
    let Fields::Named(named) = &data.fields else {
        return Err(syn::Error::new(
            data.fields.span(),
            "CircuitBorsh needs named fields: a field's name is its path in \
             the published layout table",
        ));
    };
    named
        .named
        .iter()
        .map(|field| {
            let ident = field.ident.clone().expect("named fields");
            if let Some(name) = spec_name(&field.attrs)? {
                return Ok(name);
            }
            Ok(ident.to_string().trim_start_matches("r#").to_string())
        })
        .collect()
}

/// A field's `#[borsh(name = "…")]` override.
fn spec_name(attrs: &[Attribute]) -> syn::Result<Option<String>> {
    let mut name = None;
    for attr in attrs.iter().filter(|a| a.path().is_ident("borsh")) {
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("name") {
                let lit: LitStr = meta.value()?.parse()?;
                name = Some(lit.value());
                Ok(())
            } else {
                Err(meta.error(
                    "unsupported borsh attribute on a field; expected name = \"…\"",
                ))
            }
        })?;
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expansion(input: DeriveInput) -> String {
        expand(input).expect("expands").to_string()
    }

    /// THINNESS RULE: the expansion may not build any circuit — `c` is
    /// passed along and never called on.
    #[test]
    fn the_expansion_calls_no_circuit_method() {
        let expanded = expansion(syn::parse_quote! {
            struct Payload {
                version: Uint<8, Private>,
                id: B32<Private>,
            }
        });
        assert!(!expanded.contains("c ."), "expansion calls a method on the circuit:\n{expanded}");
        assert!(
            !expanded.contains("Circuit3 ::"),
            "expansion calls a Circuit3 associated function:\n{expanded}"
        );
    }

    /// One derive yields BOTH families: the argument impls (from the same
    /// code path `#[derive(CircuitArg)]` uses) and the serialization impl.
    #[test]
    fn one_derive_yields_both_families() {
        let expanded = expansion(syn::parse_quote! {
            struct Payload {
                version: Uint<8, Private>,
            }
        });
        assert!(expanded.contains("CircuitArg for Payload"), "{expanded}");
        assert!(expanded.contains("CircuitArgs for Payload"), "{expanded}");
        assert!(expanded.contains("CircuitBorsh <"), "{expanded}");
    }

    /// A visibility-generic struct serializes at every visibility, but is a
    /// circuit argument only at `Private`.
    #[test]
    fn a_visibility_parameter_is_carried_into_the_impl() {
        let expanded = expansion(syn::parse_quote! {
            struct Payload<V: Vis3> {
                version: Uint<8, V>,
            }
        });
        assert!(expanded.contains("impl < V : :: minocrab_std :: v3 :: Vis3 >"), "{expanded}");
        assert!(expanded.contains("CircuitBorsh < V > for Payload < V >"), "{expanded}");
        // The argument impls apply only where every field is an argument —
        // which is at Private, stated as a where-clause.
        assert!(
            expanded.contains("CircuitArg for Payload < V > where Uint < 8 , V > : :: minocrab_std :: v3 :: CircuitArg"),
            "{expanded}"
        );
    }

    #[test]
    fn other_generic_parameters_are_rejected() {
        let err = expand(syn::parse_quote! {
            struct Payload<T> { value: T }
        })
        .expect_err("a plain type parameter is not a visibility");
        assert!(err.to_string().contains("visibility parameter"));
    }

    /// The two label namespaces: `lowerCamelCase` argument labels, verbatim
    /// layout paths.
    #[test]
    fn layout_paths_are_the_field_names_verbatim() {
        let expanded = expansion(syn::parse_quote! {
            struct Payload {
                request_id: B32<Private>,
            }
        });
        assert!(expanded.contains(r#"field (path , "request_id")"#), "{expanded}");
        assert!(expanded.contains(r#"root ("requestId")"#), "{expanded}");
    }

    #[test]
    fn the_borsh_name_attribute_overrides_one_layout_path() {
        let expanded = expansion(syn::parse_quote! {
            struct Payload {
                #[borsh(name = "big_r_x")]
                bigr_x: B32<Private>,
            }
        });
        assert!(expanded.contains(r#"field (path , "big_r_x")"#), "{expanded}");
    }

    #[test]
    fn the_spec_attribute_generates_the_cross_check() {
        let expanded = expansion(syn::parse_quote! {
            #[borsh(spec = spec_types::RespondMisc)]
            struct Payload {
                request_id: B32<Private>,
            }
        });
        assert!(expanded.contains("assert_matches_schema"), "{expanded}");
        assert!(expanded.contains("spec_types :: RespondMisc"), "{expanded}");
        assert!(expanded.contains("# [cfg (test)]"), "{expanded}");
    }

    /// The excluded shapes, each naming its replacement.
    #[test]
    fn variable_width_fields_are_rejected_by_name() {
        let cases: [(DeriveInput, &str); 4] = [
            (
                syn::parse_quote! { struct P { calldata: Option<Uint<32, Private>> } },
                "Maybe ↦ Flagged, never Option",
            ),
            (
                syn::parse_quote! { struct P { words: Vec<B32<Private>> } },
                "[T; K] plus a separate count",
            ),
            (
                syn::parse_quote! { struct P { name: String } },
                "Bytes<N> / BytesN<V, N>",
            ),
            (
                syn::parse_quote! { struct P { table: HashMap<u8, u8> } },
                "maps and sets are not in the fixed-width subset",
            ),
        ];
        for (input, expected) in cases {
            let err = expand(input).expect_err("outside the subset");
            assert!(err.to_string().contains(expected), "{}", err);
        }
    }

    #[test]
    fn an_enum_names_its_two_replacements() {
        let err = expand(syn::parse_quote! {
            enum Kind { Claim, Refund }
        })
        .expect_err("enums are rejected");
        let message = err.to_string();
        assert!(message.contains("Tag<K>"), "{message}");
        assert!(message.contains("one record type per kind"), "{message}");
    }
}
