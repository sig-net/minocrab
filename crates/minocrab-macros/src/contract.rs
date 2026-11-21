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
//! The methods take `c: &mut Circuit` and no receiver, deliberately. A
//! `&mut self` would mean the circuit lived in the state value, which forces
//! either interior mutability (turning a borrow error into a runtime panic —
//! against the standing compile-errors-over-panics rule) or a second calling
//! convention beside the `&mut Circuit` every gadget in `minocrab-ledger`,
//! `minocrab_std::kernel` and `common` already takes.
//!
//! THE TOOLING PROPERTY (M37 rung E, notes/evm-calls.org §6/§12): the
//! author's items are emitted as parsed; the macro adds siblings only. Every
//! `impl` member that is NOT a `#[circuit]` (a plain method, a `const`, an
//! associated type) is pushed through unchanged — `member.to_token_stream()`
//! re-serialises the parsed `ImplItem`, so its tokens and spans are exactly
//! the ones in the source, in the same declaration-order slot in the
//! rebuilt `impl` block. A `#[circuit]` method is handed to
//! [`crate::circuit::expand_in`], which carries the same property (see that
//! module's doc): the author's method is emitted under its own name with
//! its own signature and body verbatim, and the compiled-builder function,
//! the `CIRCUITS` const and the generated tests are the only new siblings.
//! What IS rebuilt is the `impl SelfType { .. }` shell itself (a fresh
//! `impl` token from `quote!`, not the original `ItemImpl` reused wholesale)
//! — but every member's content passes through untouched, so rust-analyzer
//! sees the same methods, in the same order, at the same spans.

//!
//! THE LOWERING (M48 rung C, notes/streamline-survey.org §7): how a circuit
//! is lowered is a property of the CONTRACT, so it is said once, on the
//! block: `#[contract(lowering = minocrab_compat::profile)]`. The macro
//! knows nothing about the path but its position: it splices a call to it on
//! the circuit as the first statement of every `#[circuit]`'s entry closure
//! (see [`crate::circuit::expand_in`]), and records it as the contract's
//! `LOWERING` const so a test can ask which contracts chose one. This works
//! because `#[contract]` expands the `#[circuit]` methods itself, so no
//! second declaration per circuit is needed and none can be forgotten.

use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::parse::{Parse, ParseStream};
use syn::spanned::Spanned;
use syn::{FnArg, Ident, ImplItem, ItemFn, ItemImpl};

use crate::circuit::{CircuitAttr, Expansion};

/// `#[contract]` / `#[contract(lowering = path)]`.
#[derive(Default)]
pub struct ContractAttr {
    /// A path to a `fn(&mut Circuit)` every circuit of the contract calls
    /// before its body. The macro only splices it; rustc checks its type.
    lowering: Option<syn::Path>,
}

impl Parse for ContractAttr {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let expected = "expected `lowering = path::to::a_fn` inside #[contract(..)], where the \
                        fn takes `&mut Circuit` (e.g. `lowering = minocrab_compat::profile`)";
        let mut attr = ContractAttr::default();
        while !input.is_empty() {
            let key: Ident = input
                .parse()
                .map_err(|e| syn::Error::new(e.span(), expected))?;
            if key != "lowering" {
                return Err(syn::Error::new(
                    key.span(),
                    format!("unsupported #[contract] argument `{key}`; {expected}"),
                ));
            }
            if attr.lowering.is_some() {
                return Err(syn::Error::new(key.span(), "`lowering` is given twice"));
            }
            input
                .parse::<syn::Token![=]>()
                .map_err(|e| syn::Error::new(e.span(), expected))?;
            // A PATH, not an expression: a closure or a call here would run
            // code the reader cannot see named, and a string would be a name
            // rustc cannot check.
            let path: syn::Path = input
                .parse()
                .map_err(|e| syn::Error::new(e.span(), expected))?;
            attr.lowering = Some(path);
            if input.is_empty() {
                break;
            }
            input.parse::<syn::Token![,]>()?;
        }
        Ok(attr)
    }
}

pub fn expand(attr: ContractAttr, item: ItemImpl) -> syn::Result<TokenStream> {
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
    let lowering = attr.lowering.as_ref();
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
                "a circuit takes `c: &mut Circuit` and no receiver. A contract's \
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
            crate::circuit::expand_in(attr, function, Some(self_ty), lowering)?;
        items.push(entry);
        tests.extend(test);
        circuits.push((bare, name));
    }

    let root = quote!(::minocrab_std);
    let names = circuits.iter().map(|(bare, _)| bare);
    let idents = circuits.iter().map(|(_, ident)| ident);
    let count = circuits.len();
    let lowering_value = match lowering {
        Some(path) => quote!(::core::option::Option::Some(#path)),
        None => quote!(::core::option::Option::None),
    };

    Ok(quote! {
        impl #self_ty {
            #(#items)*

            /// Every circuit this contract exports, in declaration order.
            ///
            /// Derived by `#[contract]`, so it cannot drift from the file: a
            /// circuit that exists is in here, and the snapshots enumerate it
            /// without anyone maintaining a second list.
            pub const CIRCUITS: [(&'static str, fn() -> #root::__private::Compiled); #count] =
                [ #( (#names, Self::#idents) ),* ];

            /// The lowering every circuit of this contract applies before its
            /// body: `#[contract(lowering = path)]`, or `None` for the
            /// defaults.
            ///
            /// Derived by `#[contract]` from its one argument, so a test can
            /// ask which contracts chose a lowering.
            pub const LOWERING: ::core::option::Option<fn(&mut #root::__private::Circuit)> =
                #lowering_value;
        }

        #(#tests)*
    })
}

#[cfg(test)]
mod tests {
    use quote::ToTokens;
    use syn::ItemImpl;

    use super::*;

    fn expansion(item: ItemImpl) -> String {
        expand(ContractAttr::default(), item).expect("expands").to_string()
    }

    /// THE TOOLING PROPERTY (notes/evm-calls.org §6/§12), for a plain
    /// (non-`#[circuit]`) member: it passes through `#[contract]`
    /// untouched, at the same declaration-order position — the same tokens
    /// `to_token_stream` would produce for the member as parsed, not a
    /// reconstruction.
    #[test]
    fn a_plain_method_passes_through_verbatim() {
        let item: ItemImpl = syn::parse_quote! {
            impl Vault {
                /// A helper the contract's circuits share.
                fn helper(x: u32) -> u32 { x + 1 }

                #[circuit]
                pub fn deposit(c: &mut Circuit, amount: Uint<64>) {}
            }
        };
        let syn::ImplItem::Fn(helper) = &item.items[0] else {
            panic!("first member is the plain method");
        };
        let expected_helper = helper.to_token_stream().to_string();

        let expanded = expansion(item);
        assert!(
            expanded.contains(&expected_helper),
            "the plain method is not present verbatim:\nexpected: {expected_helper}\ngot: {expanded}"
        );
    }

    /// The same verbatim property [`crate::circuit`] pins for a free
    /// function holds for a `#[circuit]` method inside a `#[contract]`
    /// block: same name, same signature (bar the consumed `#[arg]`), same
    /// body, and the additions (`CIRCUITS`, the compiled-builder fn, the
    /// generated test) are siblings.
    #[test]
    fn a_circuit_methods_signature_and_body_are_emitted_verbatim() {
        let item: ItemImpl = syn::parse_quote! {
            impl Vault {
                #[circuit]
                pub fn deposit(c: &mut Circuit, amount: Uint<64>) {
                    let doubled = amount;
                    TREASURY.note(c, doubled);
                }
            }
        };
        let syn::ImplItem::Fn(method) = &item.items[0] else {
            panic!("only member is the circuit method");
        };
        let expected_sig = method.sig.to_token_stream().to_string();
        let expected_block = method.block.to_token_stream().to_string();

        let expanded = expansion(item);
        assert!(
            expanded.contains(&expected_sig),
            "the method's signature is not present verbatim:\n{expanded}"
        );
        assert!(
            expanded.contains(&expected_block),
            "the method's body is not present verbatim:\n{expanded}"
        );
        assert!(!expanded.contains("_body"), "a synthesised name leaked in:\n{expanded}");
        // The sibling: the derived circuit set names the method by its own,
        // unrewritten identifier.
        assert!(expanded.contains("CIRCUITS"), "{expanded}");
        assert!(expanded.contains("(\"deposit\" , Self :: deposit)"), "{expanded}");
    }

    #[test]
    fn a_trait_impl_is_rejected() {
        let err = expand(ContractAttr::default(), syn::parse_quote! {
            impl SomeTrait for Vault {
                #[circuit]
                fn deposit(c: &mut Circuit) {}
            }
        })
        .expect_err("only an inherent impl describes a contract's own circuits")
        .to_string();
        assert!(err.contains("#[interface]"), "{err}");
    }

    fn attr(tokens: proc_macro2::TokenStream) -> syn::Result<ContractAttr> {
        syn::parse2(tokens)
    }

    fn deposit() -> ItemImpl {
        syn::parse_quote! {
            impl Vault {
                #[circuit]
                pub fn deposit(c: &mut Circuit, amount: Uint<64>) {
                    TREASURY.note(c, amount);
                }
                #[circuit]
                pub fn withdraw(c: &mut Circuit) {}
            }
        }
    }

    /// `lowering = path` puts ONE call to the path in EVERY circuit's entry
    /// closure, as its first statement, ahead of the author's body: the
    /// arguments are declared and constrained by `entry` before the closure
    /// runs, and the lowering runs before anything in the body.
    #[test]
    fn the_lowering_is_called_first_in_every_circuit() {
        let attr = attr(quote!(lowering = my_compat::profile)).expect("parses");
        let expanded = expand(attr, deposit()).expect("expands").to_string();
        let call = "my_compat :: profile (__c) ;";
        assert_eq!(expanded.matches(call).count(), 2, "{expanded}");
        assert!(
            expanded.contains(&format!("| __c , __args : __deposit_Args | {{ {call} deposit (__c , __args . amount) }}")),
            "the lowering is not the closure's first statement, before the body's call:\n{expanded}"
        );
        assert!(
            expanded.contains("pub const LOWERING : :: core :: option :: Option < fn (& mut :: minocrab_std :: __private :: Circuit) > = :: core :: option :: Option :: Some (my_compat :: profile) ;"),
            "{expanded}"
        );
    }

    /// Without the argument, the closure is the one the macro always
    /// emitted (byte identity of every contract that does not opt in), and
    /// `LOWERING` says `None`.
    #[test]
    fn without_a_lowering_the_entry_is_unchanged() {
        let expanded = expansion(deposit());
        assert!(
            expanded.contains("| __c , __args : __deposit_Args | deposit (__c , __args . amount))"),
            "{expanded}"
        );
        assert!(!expanded.contains("profile"), "{expanded}");
        assert!(expanded.contains("= :: core :: option :: Option :: None ;"), "{expanded}");
    }

    /// The malformed arguments are macro errors at the attribute, each
    /// saying what is expected.
    #[test]
    fn a_malformed_lowering_is_rejected() {
        let cases: [(proc_macro2::TokenStream, &str); 6] = [
            (quote!(lowering = "minocrab_compat::profile"), "expected `lowering = path::to::a_fn`"),
            (quote!(lowering = |c| profile(c)), "expected `lowering = path::to::a_fn`"),
            (quote!(lowering), "expected `lowering = path::to::a_fn`"),
            (quote!(lowering = ), "expected `lowering = path::to::a_fn`"),
            (quote!(lowerin = profile), "unsupported #[contract] argument `lowerin`"),
            (quote!(lowering = a::profile, lowering = b::profile), "`lowering` is given twice"),
        ];
        for (tokens, message) in cases {
            let shown = tokens.to_string();
            let err = match attr(tokens) {
                Ok(_) => panic!("`{shown}` parsed"),
                Err(e) => e.to_string(),
            };
            assert!(err.contains(message), "`{shown}`: {err}");
        }
        // A path followed by more tokens (a call, say) is not a path.
        assert!(attr(quote!(lowering = profile(c))).is_err());
        // Empty is the plain `#[contract]`.
        assert!(attr(quote!()).expect("parses").lowering.is_none());
    }
}
