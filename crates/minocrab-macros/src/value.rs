//! `#[derive(Value)]`: a record of value fields becomes a value — a circuit
//! argument, a cross-contract argument and result, a ledger value — in
//! DECLARATION ORDER, which is the wire contract.
//!
//! The expansion is one impl per trait, each holding exactly where every
//! field's impl of the same trait holds ([`ArgBounds::PerField`]):
//!
//! - the argument family ([`impl_arg_traits_for`]): `CircuitAbi`,
//!   `Encode<__V>`, `Decode<__V>`, `CircuitArg`, `CircuitArgs`;
//! - the ledger family: `ProofWires` and `LedgerRepr`, field by field, so a
//!   field with its own ledger form (a record of computed limbs) keeps it.
//!
//! So `struct Env { amount: Uint<64, Public> }` is a ledger value and a
//! call argument and not a circuit argument; `struct Args { amount:
//! Uint<64> }` is the reverse; `struct Notification<V: Vis3>` is each at its
//! own visibility; and `struct Owned<E> { owner: Commit, inner: E }` is a
//! ledger value exactly where `E` is. Visibility is never decided here: a
//! leaf implements each trait at the visibilities it may cross, and a
//! record inherits that.
//!
//! `#[derive(CircuitArg)]` and `#[derive(LedgerRepr)]` are this derive plus
//! a check, for a struct without generic parameters, that the record IS a
//! circuit argument (resp. a ledger value): the rejection of a `Public`
//! field in an argument, or a `Private` field in a stored record, stays at
//! the definition.
//!
//! THINNESS RULE: the expansion calls no `Circuit3` method; `c` is threaded
//! to the fields' own impls.

use proc_macro2::TokenStream;
use quote::{quote, quote_spanned};
use syn::{DeriveInput, Type};

use crate::circuit_arg::{arg_fields, impl_arg_traits_for, ArgBounds, Target};

/// What a named derive additionally checks at the definition.
#[derive(Clone, Copy)]
pub(crate) enum Check {
    /// `#[derive(Value)]`: nothing.
    None,
    /// `#[derive(CircuitArg)]`: the record is a circuit argument.
    CircuitArg,
    /// `#[derive(LedgerRepr)]`: the record is a ledger value.
    LedgerRepr,
}

pub fn expand(input: DeriveInput) -> syn::Result<TokenStream> {
    expand_checked(input, Check::None)
}

pub(crate) fn expand_checked(input: DeriveInput, check: Check) -> syn::Result<TokenStream> {
    if let Some(attr) = input.attrs.iter().find(|a| a.path().is_ident("arg")) {
        return Err(syn::Error::new_spanned(
            attr,
            "#[arg(..)] belongs on a field: a struct is named by the field or \
             parameter that holds it, not by itself",
        ));
    }

    let fields = arg_fields(&input)?;
    let name = &input.ident;
    let (_, ty_generics, _) = input.generics.split_for_impl();
    let target = Target {
        generics: &input.generics,
        self_ty: quote!(#name #ty_generics),
        fields: &fields,
        bounds: ArgBounds::PerField,
    };

    let arg_impls = impl_arg_traits_for(&target);
    let ledger_impls = impl_ledger_traits(&target);
    let check = definition_check(&input, check);
    Ok(quote! {
        #arg_impls
        #ledger_impls
        #check
    })
}

/// `ProofWires` and `LedgerRepr`, field by field.
fn impl_ledger_traits(target: &Target) -> TokenStream {
    let root = quote!(::minocrab_std::v3::__derive);
    let self_ty = &target.self_ty;
    let impl_generics = target.impl_generics();
    let wires_where = target.clause(&quote!(#root::ProofWires), true);
    let repr_where = target.clause(&quote!(#root::LedgerRepr), true);
    let idents: Vec<_> = target.fields.iter().map(|f| &f.ident).collect();
    let types: Vec<&Type> = target.fields.iter().map(|f| &f.ty).collect();

    quote! {
        #[automatically_derived]
        impl #impl_generics #root::ProofWires for #self_ty #wires_where {
            fn push_wires(&self, out: &mut ::std::vec::Vec<#root::Val>) {
                #( <#types as #root::ProofWires>::push_wires(&self.#idents, out); )*
            }
        }

        #[automatically_derived]
        impl #impl_generics #root::LedgerRepr for #self_ty #repr_where {
            fn atoms() -> ::std::vec::Vec<#root::AlignmentAtom> {
                let mut atoms = ::std::vec::Vec::new();
                #( atoms.extend(<#types as #root::LedgerRepr>::atoms()); )*
                atoms
            }

            fn push_limbs(
                &self,
                c: &mut #root::Circuit3,
                limbs: &mut ::std::vec::Vec<#root::Wire3<#root::FieldT, #root::Public>>,
            ) {
                #( <#types as #root::LedgerRepr>::push_limbs(&self.#idents, c, limbs); )*
            }

            fn from_limbs(
                limbs: ::std::vec::Vec<#root::Wire3<#root::FieldT, #root::Public>>,
            ) -> Self {
                let mut limbs = limbs.into_iter();
                let value = Self {
                    #( #idents: <#types as #root::LedgerRepr>::from_limbs(
                        limbs.by_ref().take(#root::repr_limbs::<#types>()).collect()
                    ), )*
                };
                ::core::assert!(
                    limbs.next().is_none(),
                    "{}::from_limbs was handed more limbs than its fields take",
                    ::core::stringify!(#self_ty)
                );
                value
            }
        }
    }
}

/// The named derives' check, for a struct with no generic parameters (one
/// with parameters is checked where it is instantiated). A field the record
/// cannot hold is an E0277 at the derive.
fn definition_check(input: &DeriveInput, check: Check) -> TokenStream {
    if !input.generics.params.is_empty() {
        return quote!();
    }
    let name = &input.ident;
    let bound = match check {
        Check::None => return quote!(),
        Check::CircuitArg => quote!(::minocrab_std::v3::CircuitArg),
        Check::LedgerRepr => {
            quote!(::minocrab_std::v3::__derive::LedgerRepr + ::minocrab_std::v3::__derive::ProofWires)
        }
    };
    quote_spanned! {name.span()=>
        const _: () = {
            fn __is<T: #bound>() {}
            fn __check() {
                __is::<#name>();
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expansion(input: DeriveInput) -> String {
        expand(input).expect("expands").to_string()
    }

    #[test]
    fn the_expansion_calls_no_circuit_method() {
        let expanded = expansion(syn::parse_quote! {
            struct Env { a: B32<Public>, b: Uint<64, Public> }
        });
        assert!(!expanded.contains("c ."), "{expanded}");
        assert!(!expanded.contains("Circuit3 ::"), "{expanded}");
        assert!(expanded.contains("repr_limbs :: < B32 < Public > >"), "{expanded}");
    }

    /// Every impl holds where the fields' do: one bound per field per trait,
    /// lifted over a lifetime so a bound that does not hold is not an error
    /// at the definition.
    #[test]
    fn every_impl_is_bounded_by_its_fields() {
        let expanded = expansion(syn::parse_quote! {
            struct Env { a: B32<Public>, b: Uint<64, Public> }
        });
        for bound in [
            "CircuitAbi",
            "Encode < __V >",
            "Decode < __V >",
            "CircuitArg",
            "ProofWires",
            "LedgerRepr",
        ] {
            for field in ["B32 < Public >", "Uint < 64 , Public >"] {
                let clause = format!("for < '__w > {field} : :: minocrab_std :: v3 ::");
                assert!(
                    expanded.contains(&clause) && expanded.contains(bound),
                    "no `{clause} {bound}` in\n{expanded}"
                );
            }
        }
    }

    /// A GENERIC record: the struct's own parameters, bounds and where-clause
    /// are carried into every impl, and the generic field is bounded like any
    /// other, so `Owned<E>` is a ledger value exactly where `E` is.
    #[test]
    fn a_generic_record_carries_its_parameters() {
        let expanded = expansion(syn::parse_quote! {
            struct Owned<E: Clone, const N: usize> where E: Copy {
                owner: Commit<SecretKey<Private>, OwnerTag>,
                words: [B32<Public>; N],
                inner: E,
            }
        });
        assert!(
            expanded.contains(
                "impl < E : Clone , const N : usize > :: minocrab_std :: v3 :: __derive :: LedgerRepr for Owned < E , N >"
            ),
            "{expanded}"
        );
        assert!(
            expanded.contains("impl < E : Clone , const N : usize , __V : :: minocrab_std :: v3 :: __private :: Visibility > :: minocrab_std :: v3 :: Encode < __V > for Owned < E , N >"),
            "{expanded}"
        );
        assert!(
            expanded.contains("for < '__w > E : :: minocrab_std :: v3 :: __derive :: LedgerRepr"),
            "{expanded}"
        );
        assert!(expanded.contains("E : Copy"), "the user's where-clause is kept:\n{expanded}");
        assert!(!expanded.contains("fn __check"), "a generic record is checked where used:\n{expanded}");
    }

    /// The visibility-generic leaf shape: one declaration, every impl.
    #[test]
    fn a_visibility_generic_record_is_written_once() {
        let expanded = expansion(syn::parse_quote! {
            struct Notification<V: Vis3> { version: Uint<8, V>, payload: BytesN<V, 128> }
        });
        assert!(
            expanded.contains(":: minocrab_std :: v3 :: CircuitArg for Notification < V >"),
            "{expanded}"
        );
        assert!(expanded.contains("for < '__w > Uint < 8 , V > : :: minocrab_std :: v3 :: Encode < __V >"), "{expanded}");
    }

    #[test]
    fn the_named_derives_check_a_plain_record_at_the_definition() {
        let arg = expand_checked(
            syn::parse_quote! { struct Args { a: Uint<64> } },
            Check::CircuitArg,
        )
        .expect("expands")
        .to_string();
        assert!(arg.contains("fn __is < T : :: minocrab_std :: v3 :: CircuitArg > ()"), "{arg}");
        assert!(arg.contains("__is :: < Args > ()"), "{arg}");

        let repr = expand_checked(
            syn::parse_quote! { struct Env { a: Uint<64, Public> } },
            Check::LedgerRepr,
        )
        .expect("expands")
        .to_string();
        assert!(repr.contains("LedgerRepr + :: minocrab_std :: v3 :: __derive :: ProofWires"), "{repr}");
    }
}
