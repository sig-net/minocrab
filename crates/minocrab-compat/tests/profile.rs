//! `profile` sets compactc's lowering, and refuses the combinations that
//! would make a ported circuit lowered half one way and half the other.

use minocrab::v3::{Circuit3, Lowering, SelfAddressReads};
use minocrab_std::v3::kernel;

fn len(c: Circuit3) -> usize {
    c.finish(true).ir.instructions.len()
}

/// The profile is compactc's: every self read emitted, no dedup.
#[test]
fn the_profile_is_compactcs() {
    let mut c = Circuit3::new();
    c.dedup_range_constraints(true);
    minocrab_compat::profile(&mut c);
    assert_eq!(c.lowering(), Lowering { self_address: SelfAddressReads::EveryCall, dedup_range_constraints: false, simplify: false });
    assert!(c.lowering_chosen());
}

/// The profile changes nothing a fresh circuit would emit (the defaults are
/// still compactc's in this rung), and two reads stay two reads.
#[test]
fn under_the_profile_every_self_read_is_emitted() {
    let mut once = Circuit3::new();
    minocrab_compat::profile(&mut once);
    kernel::self_address(&mut once);
    let one = len(once);

    let mut twice = Circuit3::new();
    minocrab_compat::profile(&mut twice);
    kernel::self_address(&mut twice);
    kernel::self_address(&mut twice);
    let two = len(twice);

    let mut plain = Circuit3::new();
    kernel::self_address(&mut plain);
    kernel::self_address(&mut plain);

    assert_eq!(two - one, one, "each call emits a full read");
    assert_eq!(two, len(plain), "the profile matches today's default");
}

/// compactc never caches: a ported circuit asking to is refused, not
/// silently overridden.
#[test]
#[should_panic(expected = "cache_self_address in a circuit whose lowering reads kernel.self() at every call")]
fn cache_after_the_profile_is_refused() {
    let mut c = Circuit3::new();
    minocrab_compat::profile(&mut c);
    kernel::cache_self_address(&mut c);
}

/// The profile must come first: after a gadget lowered under the defaults
/// it is refused.
#[test]
#[should_panic(expected = "called after a gadget already lowered")]
fn the_profile_after_a_self_read_is_refused() {
    let mut c = Circuit3::new();
    kernel::self_address(&mut c);
    minocrab_compat::profile(&mut c);
}

/// …including after a cache, which the profile would otherwise contradict.
#[test]
#[should_panic(expected = "called after a gadget already lowered")]
fn the_profile_after_a_cache_is_refused() {
    let mut c = Circuit3::new();
    kernel::cache_self_address(&mut c);
    minocrab_compat::profile(&mut c);
}
