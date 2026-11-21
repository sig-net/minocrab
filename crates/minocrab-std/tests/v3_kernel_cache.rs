//! The kernel.self cache (M18): populated only by `cache_self_address`,
//! consulted by `self_address`, invisible to circuits that never cache;
//! and the `OncePerCircuit` lowering setting that keeps the first read.

use minocrab::v3::{Circuit3, SelfAddressReads};
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

fn read_count_len(setup: impl FnOnce(&mut Circuit3)) -> usize {
    let mut c = Circuit3::new();
    setup(&mut c);
    c.finish(true).ir.instructions.len()
}

fn once_per_circuit(c: &mut Circuit3) {
    let mut l = c.lowering();
    l.self_address = SelfAddressReads::OncePerCircuit;
    c.set_lowering(l);
}

/// `OncePerCircuit` keeps the first straight-line read: the stream equals
/// an explicit `cache_self_address` followed by cached reads.
#[test]
fn once_per_circuit_reads_once() {
    let cached = read_count_len(|c| {
        kernel::cache_self_address(c);
        kernel::self_address(c);
    });
    let once = read_count_len(|c| {
        once_per_circuit(c);
        kernel::self_address(c);
        kernel::self_address(c);
        kernel::self_address(c);
    });
    assert_eq!(cached, once);
}

/// A read inside a `when` is guarded, so `OncePerCircuit` never keeps it:
/// the straight-line read after it is a real read.
#[test]
fn once_per_circuit_never_keeps_a_guarded_read() {
    let fresh = read_count_len(|c| {
        let g = c.constant(1u64);
        let g = c.add(g, g);
        let _ = c.when(g, kernel::self_address);
        kernel::self_address(c);
    });
    let once = read_count_len(|c| {
        once_per_circuit(c);
        let g = c.constant(1u64);
        let g = c.add(g, g);
        let _ = c.when(g, kernel::self_address);
        kernel::self_address(c);
        kernel::self_address(c);
    });
    assert_eq!(fresh, once, "the guarded read is not kept; the first straight-line one is");
}

/// A circuit that chose `OncePerCircuit` may still cache explicitly.
#[test]
fn cache_under_once_per_circuit_is_allowed() {
    let mut c = Circuit3::new();
    once_per_circuit(&mut c);
    kernel::cache_self_address(&mut c);
}
