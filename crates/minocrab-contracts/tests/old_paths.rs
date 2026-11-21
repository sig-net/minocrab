// rename-v3: skip-file (this test spells the old paths on purpose)
//! The deprecated `v3` shims still resolve (M48 rung K).
//!
//! The `v3` module of minocrab, minocrab-ir, minocrab-std, minocrab-sim and
//! minocrab-zkir went to the crate root and its items lost their `3`
//! suffix; each crate keeps a hidden, deprecated `pub mod v3` re-exporting
//! the root, with the old names as deprecated aliases, for downstream code
//! pinned to the old paths. This test imports a representative set through
//! those paths, including every import the Vela contract makes, so a shim
//! cannot rot silently. Nothing else in the workspace may use them.
#![allow(deprecated)]

use minocrab::v3::{AnyWire3, Circuit3, Compiled3, Disclosure3, FieldT, Wire3};
use minocrab_ir::v3::passes;
use minocrab_ir::v3::Builder3;
use minocrab_sim::v3::exec::{self, Call, Executed};
use minocrab_sim::v3::{cost, rowcost, DisclosedValue3, Report3, Run3, Sim3Error};
use minocrab_std::v3::hash::upgrade_from_transient;
use minocrab_std::v3::kernel;
use minocrab_std::v3::{
    b32_newtype, contract, label, LedgerRepr, QualifiedShieldedCoinInfo3, ShieldedCoinInfo3, Uint, Vis3, B32,
};
use minocrab_zkir::v3::{IrSource, IrValue};

/// Each old name is the new item, not a lookalike.
#[test]
fn the_old_names_are_the_new_items() {
    use std::any::TypeId;
    assert_eq!(TypeId::of::<Circuit3>(), TypeId::of::<minocrab::Circuit>());
    assert_eq!(
        TypeId::of::<Wire3<FieldT, minocrab::Public>>(),
        TypeId::of::<minocrab::Wire<FieldT, minocrab::Public>>()
    );
    assert_eq!(TypeId::of::<AnyWire3<minocrab::Private>>(), TypeId::of::<minocrab::AnyWire<minocrab::Private>>());
    assert_eq!(TypeId::of::<Compiled3>(), TypeId::of::<minocrab::Compiled>());
    assert_eq!(TypeId::of::<Disclosure3>(), TypeId::of::<minocrab::Disclosure>());
    assert_eq!(TypeId::of::<Builder3>(), TypeId::of::<minocrab_ir::Builder>());
    assert_eq!(TypeId::of::<Run3>(), TypeId::of::<minocrab_sim::Run>());
    assert_eq!(TypeId::of::<Report3>(), TypeId::of::<minocrab_sim::Report>());
    assert_eq!(TypeId::of::<DisclosedValue3>(), TypeId::of::<minocrab_sim::DisclosedValue>());
    assert_eq!(TypeId::of::<Sim3Error>(), TypeId::of::<minocrab_sim::SimError>());
    assert_eq!(
        TypeId::of::<ShieldedCoinInfo3<minocrab::Public>>(),
        TypeId::of::<minocrab_std::ShieldedCoinInfo<minocrab::Public>>()
    );
    assert_eq!(
        TypeId::of::<QualifiedShieldedCoinInfo3<minocrab::Public>>(),
        TypeId::of::<minocrab_std::QualifiedShieldedCoinInfo<minocrab::Public>>()
    );
    assert_eq!(TypeId::of::<IrSource>(), TypeId::of::<minocrab_zkir::IrSource>());
    assert_eq!(TypeId::of::<IrValue>(), TypeId::of::<minocrab_zkir::IrValue>());
    assert_eq!(TypeId::of::<Executed>(), TypeId::of::<minocrab_sim::exec::Executed>());
    assert_eq!(TypeId::of::<Uint<64>>(), TypeId::of::<minocrab_std::Uint<64>>());
    assert_eq!(TypeId::of::<B32<minocrab::Public>>(), TypeId::of::<minocrab_std::B32<minocrab::Public>>());
}

/// The submodules (`v3::kernel`, `v3::hash`, `v3::exec`, `v3::rowcost`,
/// `v3::passes`) and the functions reached through them resolve.
#[test]
fn the_old_module_paths_resolve() {
    fn takes_vis<V: Vis3>() {}
    takes_vis::<minocrab::Public>();
    let _ = upgrade_from_transient::<minocrab::Private>;
    let _ = kernel::self_address;
    let _ = cost;
    let _: Option<Call<'static>> = None;
    let _ = exec::Call::new;
    let _ = rowcost::SHA256_PER_BLOCK;
    let _: &passes::ProofRef = &passes::FOLD_PROOF;
}

label!(OldPathLabel = "old path label");
b32_newtype! {
    /// A newtype declared through the old path.
    OldPathKey,
}

/// A record and a circuit written entirely against the old paths.
#[derive(LedgerRepr)]
struct OldPathRecord {
    key: B32<minocrab::Public>,
}

/// A contract whose circuit takes the old `&mut Circuit3` spelling.
struct OldPathContract;

#[contract]
impl OldPathContract {
    #[circuit]
    pub fn touch(c: &mut Circuit3, amount: Uint<64>) {
        let w: Wire3<FieldT, minocrab::Private> = amount.field();
        let _ = (c, w);
    }
}

#[test]
fn a_contract_written_against_the_old_paths_builds() {
    let built: Compiled3 = OldPathContract::touch();
    assert!(!built.ir.instructions.is_empty());
    let _ = std::mem::size_of::<OldPathRecord>();
    let _ = std::mem::size_of::<OldPathKey<minocrab::Public>>();
    let _ = std::any::type_name::<OldPathLabel>();
}
