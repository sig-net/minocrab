//! `#[derive(LedgerRepr)]`: [`#[derive(Value)]`](crate::value) for a record
//! meant to be STORED, with the check that it is one.
//!
//! EVERY FIELD IS PUBLIC BY CONSTRUCTION: `LedgerRepr` is implemented for
//! the `Public` leaves only (a stored value is on-chain state), so a struct
//! with a `B32<Private>` field is not a ledger value, and for a struct
//! without generic parameters that is an error at this derive — which is
//! the whole reason `signet_flow::Pending`'s environment is declared through
//! it: nothing private can be captured across a request/settle suspension by
//! accident. A generic record is checked where it is instantiated.

use proc_macro2::TokenStream;
use syn::DeriveInput;

use crate::value::{expand_checked, Check};

pub fn expand(input: DeriveInput) -> syn::Result<TokenStream> {
    expand_checked(input, Check::LedgerRepr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_record_is_checked_and_a_generic_one_accepted() {
        let plain = expand(syn::parse_quote! {
            struct Env { a: B32<Public>, b: Uint<64, Public> }
        })
        .expect("expands")
        .to_string();
        assert!(plain.contains("__is :: < Env > ()"), "{plain}");

        let generic = expand(syn::parse_quote! {
            struct Env<V: Vis> { a: B32<V> }
        })
        .expect("generics are accepted")
        .to_string();
        assert!(!generic.contains("__check"), "{generic}");
    }
}
