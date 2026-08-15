//! `#[derive(Ledger)]`: a struct mirroring the Compact `export ledger` block
//! becomes the contract's ledger handle, with each field's index its
//! DECLARATION ORDER.
//!
//! For
//!
//! ```ignore
//! #[derive(Ledger)]
//! struct Vault {
//!     sign_bidirectional_event_map: LedgerMap<B32<Public>, VaultRecord>,  // 0
//!     signet_signer: LedgerField,                                        // 1
//!     signet_request_nonce: LedgerCounter,                               // 2
//! }
//! ```
//!
//! the expansion is
//!
//! ```ignore
//! impl Vault {
//!     pub const fn new() -> Self {
//!         Vault {
//!             sign_bidirectional_event_map: <LedgerMap<B32<Public>, VaultRecord>>::at(0u8),
//!             signet_signer: <LedgerField>::at(1u8),
//!             signet_request_nonce: <LedgerCounter>::at(2u8),
//!         }
//!     }
//! }
//! impl Default for Vault { fn default() -> Self { Self::new() } }
//! ```
//!
//! — nothing but the indices, which is the whole point: the one place a
//! ledger field's number is written down is the order it is declared in. By
//! the THINNESS RULE the expansion contains no `Circuit3` call; every
//! operation is a method on the slot types, in minocrab-std.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields};

pub fn expand(input: DeriveInput) -> syn::Result<TokenStream> {
    let name = &input.ident;

    if !input.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &input.generics,
            "#[derive(Ledger)] takes no generic parameters: a ledger block is \
             one contract's state, not a family of them",
        ));
    }

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(named) => &named.named,
            _ => {
                return Err(syn::Error::new_spanned(
                    &data.fields,
                    "#[derive(Ledger)] needs named fields: the field names are \
                     the ledger field names",
                ))
            }
        },
        Data::Enum(e) => {
            return Err(syn::Error::new_spanned(
                e.enum_token,
                "#[derive(Ledger)] is for a struct mirroring the `export ledger` block",
            ))
        }
        Data::Union(u) => {
            return Err(syn::Error::new_spanned(
                u.union_token,
                "#[derive(Ledger)] is for a struct mirroring the `export ledger` block",
            ))
        }
    };

    if fields.len() > usize::from(u8::MAX) + 1 {
        return Err(syn::Error::new_spanned(
            name,
            "a ledger block has at most 256 fields (the index is a byte)",
        ));
    }

    let inits = fields.iter().enumerate().map(|(index, field)| {
        let ident = &field.ident;
        let ty = &field.ty;
        let index = index as u8;
        quote!(#ident: <#ty>::at(#index))
    });

    Ok(quote! {
        impl #name {
            /// The ledger block: every field at its DECLARATION-ORDER index.
            ///
            /// `const`, so a contract's ledger handle is a `const` item and
            /// costs nothing at run time.
            pub const fn new() -> Self {
                #name { #(#inits),* }
            }
        }

        impl ::core::default::Default for #name {
            fn default() -> Self {
                Self::new()
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expansion(input: DeriveInput) -> String {
        expand(input).expect("expands").to_string()
    }

    /// THINNESS RULE: the expansion builds no circuit — it is indices.
    #[test]
    fn the_expansion_calls_no_circuit_method() {
        let expanded = expansion(syn::parse_quote! {
            struct Vault {
                event_map: LedgerMap<B32<Public>, VaultRecord>,
                initialized: LedgerCounter,
            }
        });
        assert!(
            !expanded.contains("c ."),
            "expansion calls a method on the circuit:\n{expanded}"
        );
        assert!(
            !expanded.contains("Circuit3 ::"),
            "expansion calls a Circuit3 associated function:\n{expanded}"
        );
    }

    /// The index IS the declaration order, and nothing else is generated.
    #[test]
    fn each_field_gets_its_declaration_order_index() {
        let expanded = expansion(syn::parse_quote! {
            struct Vault {
                event_map: LedgerMap<B32<Public>, VaultRecord>,
                signer: LedgerField,
                initialized: LedgerCounter,
            }
        });
        assert!(expanded.contains("event_map : < LedgerMap < B32 < Public > , VaultRecord > > :: at (0u8)"), "{expanded}");
        assert!(expanded.contains("signer : < LedgerField > :: at (1u8)"), "{expanded}");
        assert!(expanded.contains("initialized : < LedgerCounter > :: at (2u8)"), "{expanded}");
    }

    /// A ledger block is one contract's state.
    #[test]
    fn generics_are_rejected() {
        let error = expand(syn::parse_quote! {
            struct Vault<T> {
                event_map: LedgerMap<B32<Public>, T>,
            }
        })
        .expect_err("generics are rejected");
        assert!(error.to_string().contains("no generic parameters"), "{error}");
    }

    /// A tuple struct has no field names, and the names are the ledger's.
    #[test]
    fn a_tuple_struct_is_rejected() {
        let error = expand(syn::parse_quote! {
            struct Vault(LedgerCounter);
        })
        .expect_err("a tuple struct is rejected");
        assert!(error.to_string().contains("named fields"), "{error}");
    }
}
