//! `#[contract]` — a contract's circuits, declared as an `impl` of its state.
//!
//! WHY THE BLOCK AND NOT THE RECEIVER (dmd, 2026-08-16, and
//! notes/contract-api.org §"The contract block"): the value is that the
//! LANGUAGE gets to say which circuits belong to which contract. Before this,
//! a contract was a Rust module by convention and its circuit set was a
//! hand-written list of 170 entries in a test-support module — the only
//! statement anywhere of which circuits exist, feeding both snapshots, the
//! dump instrument and the adversarial suite, with nothing asserting it was
//! complete. `CIRCUITS` is that list, derived.
//!
//! The methods take `c: &mut Circuit3` and no receiver, deliberately. A
//! `&mut self` would mean the circuit lived in the state value, which forces
//! either interior mutability (turning a borrow error into a runtime panic —
//! against the standing compile-errors-over-panics rule) or a second calling
//! convention beside the `&mut Circuit3` every gadget in `minocrab-ledger`,
//! `minocrab_std::v3::kernel` and `common` already takes.

use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::spanned::Spanned;
use syn::{FnArg, ImplItem, ItemFn, ItemImpl};

use crate::circuit::{CircuitAttr, Expansion};

pub fn expand(item: ItemImpl) -> syn::Result<TokenStream> {
    if let Some((_, path, _)) = &item.trait_ {
        return Err(syn::Error::new(
            path.span(),
            "#[contract] describes a contract's own circuits, so it goes on an \
             inherent `impl`, not a trait impl — another contract's circuits are \
             #[interface], which generates the calling side",
        ));
    }
    if !item.generics.params.is_empty() {
        return Err(syn::Error::new(
            item.generics.span(),
            "#[contract] takes no generics: a contract is one deployed thing, and \
             its circuit set has to be a value the snapshots can enumerate",
        ));
    }

    let self_ty = &item.self_ty;
    let mut items: Vec<TokenStream> = Vec::new();
    let mut tests: Vec<TokenStream> = Vec::new();
    // Declaration order IS the order the set is reported in, so a reader sees
    // the contract's circuits in the order the file writes them.
    let mut circuits: Vec<(String, syn::Ident)> = Vec::new();

    for member in &item.items {
        let ImplItem::Fn(method) = member else {
            items.push(member.to_token_stream());
            continue;
        };
        let Some(position) = method
            .attrs
            .iter()
            .position(|a| a.path().is_ident("circuit"))
        else {
            items.push(member.to_token_stream());
            continue;
        };

        let mut method = method.clone();
        let marker = method.attrs.remove(position);
        let attr: CircuitAttr = match &marker.meta {
            syn::Meta::Path(_) => CircuitAttr::default(),
            _ => marker.parse_args()?,
        };
        if method.defaultness.is_some() {
            return Err(syn::Error::new(
                method.span(),
                "a circuit cannot be `default`: there is nothing to specialize",
            ));
        }
        if let Some(FnArg::Receiver(receiver)) = method.sig.inputs.first() {
            return Err(syn::Error::new(
                receiver.span(),
                "a circuit takes `c: &mut Circuit3` and no receiver. A contract's \
                 state is a LAYOUT, not a value this function owns: a ledger read \
                 is a transcript gate and a ledger write is an Impact op, so there \
                 is nothing in `self` to borrow. Drop it and take the circuit",
            ));
        }

        let name = method.sig.ident.clone();
        let bare = name.to_string();
        let bare = bare.strip_prefix("r#").unwrap_or(&bare).to_string();
        let function = ItemFn {
            attrs: method.attrs.clone(),
            vis: method.vis.clone(),
            sig: method.sig.clone(),
            block: Box::new(method.block.clone()),
        };
        let Expansion { entry, tests: test } =
            crate::circuit::expand_in(attr, function, Some(self_ty))?;
        items.push(entry);
        tests.extend(test);
        circuits.push((bare, name));
    }

    let root = quote!(::minocrab_std::v3);
    let names = circuits.iter().map(|(bare, _)| bare);
    let idents = circuits.iter().map(|(_, ident)| ident);
    let count = circuits.len();

    Ok(quote! {
        impl #self_ty {
            #(#items)*

            /// Every circuit this contract exports, in declaration order.
            ///
            /// Derived by `#[contract]`, so it cannot drift from the file: a
            /// circuit that exists is in here, and the snapshots enumerate it
            /// without anyone maintaining a second list.
            pub const CIRCUITS: [(&'static str, fn() -> #root::__private::Compiled3); #count] =
                [ #( (#names, Self::#idents) ),* ];
        }

        #(#tests)*
    })
}
