//! # minocrab-compat: compactc's lowerings, for circuits ported from Compact
//!
//! WHY THIS CRATE EXISTS. A circuit ported from a Compact contract has to
//! emit compactc's instruction stream byte for byte. That equality is how a
//! port is checked against the compiler's own output (the instruction-level
//! differentials compare the two streams), and it is what keeps an artifact
//! whose verifier key is already deployed from moving. The items here are
//! the compactc-shaped lowerings that equality needs.
//!
//! NOTHING IN IT IS THE CHEAPEST CORRECT LOWERING. Each module and item says
//! what about its shape is compactc's and what the lean form is. A contract
//! with no Compact twin and no deployed key should not use this crate; it
//! uses `minocrab_std`, whose gadgets are free to get cheaper.
//!
//! | module | what |
//! |---|---|
//! | [`kernel`] | the Compact standard-library circuits over `kernel` |
//! | [`merkle`] | `insertIndexDefault` with the default leaf hashed in circuit |
//! | [`secp`] | `secp256k1EcdsaVerify` |
//! | [`normalise`] | the copy fold the differentials apply to both streams |
//!
//! Nothing in the core depends on this crate (`cargo tree -i
//! minocrab-compat` lists only the corpus of ports), so nothing compactc
//! needs can reach a contract that did not ask for it.

pub mod kernel;
pub mod merkle;
pub mod normalise;
pub mod secp;
