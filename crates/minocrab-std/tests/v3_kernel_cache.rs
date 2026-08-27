//! The kernel.self cache (M18): populated only by `cache_self_address`,
//! consulted by `self_address`, invisible to circuits that never cache.

use minocrab::v3::Circuit3;
use minocrab_std::v3::kernel;

/// A cached second read emits nothing — the wires come back from the
/// circuit's gadget scratch state.
#[test]
fn a_cached_self_address_emits_no_second_read() {
    let mut once = Circuit3::new();
    kernel::cache_self_address(&mut once);
    let baseline = once.finish(true).ir.instructions.len();

    let mut twice = Circuit3::new();
    kernel::cache_self_address(&mut twice);
    kernel::self_address(&mut twice);
    // …and inside a region closure, which shares the same circuit.
    twice.region("probe", |c| {
        kernel::self_address(c);
    });
    assert_eq!(
        baseline,
        twice.finish(true).ir.instructions.len(),
        "a cached self_address call must emit nothing"
    );
}

/// A circuit that never caches reads fresh at every call — the compat
/// ports' per-call-site reads (compactc parity) cannot be affected.
#[test]
fn an_uncached_circuit_reads_fresh_every_time() {
    let mut once = Circuit3::new();
    kernel::self_address(&mut once);
    let one_read = once.finish(true).ir.instructions.len();

    let mut twice = Circuit3::new();
    kernel::self_address(&mut twice);
    kernel::self_address(&mut twice);
    let two_reads = twice.finish(true).ir.instructions.len();

    assert_eq!(
        two_reads - one_read,
        one_read,
        "without a cache, every call must emit a full read"
    );
}
