//! The kernel.self cache (M18): populated only by `cache_self_address`,
//! consulted by `self_address`, invisible to circuits that never cache;
//! and the `OncePerCircuit` lowering setting that keeps the first read.

use minocrab::{Circuit, SelfAddressReads};
use minocrab_std::kernel;

/// A cached second read emits nothing — the wires come back from the
/// circuit's gadget scratch state.
#[test]
fn a_cached_self_address_emits_no_second_read() {
    let mut once = Circuit::new();
    kernel::cache_self_address(&mut once);
    let baseline = once.finish(true).ir.instructions.len();

    let mut twice = Circuit::new();
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

/// Under `EveryCall` (compactc's, the compat profile's) a circuit reads
/// fresh at every call — the ports' per-call-site reads cannot be affected.
#[test]
fn an_uncached_circuit_reads_fresh_every_time() {
    let every_call = |c: &mut Circuit| {
        let mut l = c.lowering();
        l.self_address = SelfAddressReads::EveryCall;
        c.set_lowering(l);
    };
    let mut once = Circuit::new();
    every_call(&mut once);
    kernel::self_address(&mut once);
    let one_read = once.finish(true).ir.instructions.len();

    let mut twice = Circuit::new();
    every_call(&mut twice);
    kernel::self_address(&mut twice);
    kernel::self_address(&mut twice);
    let two_reads = twice.finish(true).ir.instructions.len();

    assert_eq!(
        two_reads - one_read,
        one_read,
        "without a cache, every call must emit a full read"
    );
}

fn read_count_len(setup: impl FnOnce(&mut Circuit)) -> usize {
    let mut c = Circuit::new();
    setup(&mut c);
    c.finish(true).ir.instructions.len()
}

fn once_per_circuit(c: &mut Circuit) {
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
    let mut c = Circuit::new();
    once_per_circuit(&mut c);
    kernel::cache_self_address(&mut c);
}

// ---- on the VM: which reads are emitted, which run, and what each yields ----
//
// Each circuit below takes one public argument `g`, uses it as a `when`
// guard, and returns the self addresses it read. It is run through the
// executor (`minocrab_sim::exec`: the transcript settled against
// Midnight's on-chain VM), so the facts asserted are the ledger's view: how
// many `kernel.self()` reads the circuit EMITS, which of them RUN (a guarded
// one whose guard is off is skipped, its public inputs zero), and the value
// every use of the address sees.

use midnight_onchain_state::state::StateValue;
use minocrab::{Compiled, FieldT, Lowering, Wire};
use minocrab::Fr;
use minocrab_sim::exec::{self, Call, Executed};
use minocrab_std::kernel::SelfAddress;
use minocrab_zkir::IrValue;

/// The address every run executes as.
const SELF: [u8; 32] = [0x5e; 32];

fn guard(c: &mut Circuit) -> Wire<FieldT, minocrab::Public> {
    let g = c.arg::<FieldT>("g");
    c.disclose(g, "g")
}

fn ret(c: &mut Circuit, me: SelfAddress) {
    let b = me.bytes();
    c.output(b.hi, "hi");
    c.output(b.lo, "lo");
}

fn with(lowering: Option<SelfAddressReads>, body: impl FnOnce(&mut Circuit)) -> Compiled {
    let mut c = Circuit::new();
    if let Some(reads) = lowering {
        c.set_lowering(Lowering { self_address: reads, ..c.lowering() });
    }
    body(&mut c);
    c.finish(false)
}

fn run(compiled: &Compiled, g: u64) -> Executed {
    exec::execute(&compiled.ir, &Call::new(&[Fr::from(g)], &[]), &exec::context(StateValue::Null, SELF))
        .unwrap_or_else(|e| panic!("g = {g}: {e}"))
}

/// One entry per EMITTED self read, in stream order: whether it ran. A self
/// read is three Impact blocks (`dup`, `idx`, `popeq`) under one guard.
fn self_reads(e: &Executed) -> Vec<bool> {
    assert_eq!(e.run.pi_skips.len() % 3, 0, "only self reads in these circuits");
    e.run
        .pi_skips
        .chunks(3)
        .map(|block| {
            assert!(block.iter().all(|s| s.is_none() == block[0].is_none()), "one guard per read");
            block[0].is_none()
        })
        .collect()
}

/// The address as the circuit's outputs encode it (one unguarded read).
fn address() -> Vec<IrValue> {
    let plain = with(None, |c| {
        let _ = guard(c);
        let me = kernel::self_address(c);
        ret(c, me);
    });
    run(&plain, 0).run.outputs
}

/// What a guarded read yields where its guard was off: the zero address.
fn zero() -> Vec<IrValue> {
    let zeros = with(None, |c| {
        let _ = guard(c);
        let z = c.constant(0u64);
        c.output(z, "hi");
        c.output(z, "lo");
    });
    run(&zeros, 0).run.outputs
}

fn cat(a: &[IrValue], b: &[IrValue]) -> Vec<IrValue> {
    a.iter().chain(b).cloned().collect()
}

/// THE LATENT BUG, fixed: `cache_self_address` inside a `when` used to keep
/// the GUARDED read, so every later read outside the scope got its value,
/// which is zero where the guard was off. Now it keeps nothing there: the
/// read after the scope is a real one and sees the address.
#[test]
fn caching_inside_a_when_keeps_nothing() {
    let me = address();
    for lowering in [None, Some(SelfAddressReads::OncePerCircuit)] {
        let circuit = with(lowering, |c| {
            let g = guard(c);
            let _ = c.when(g, |c| {
                kernel::cache_self_address(c);
            });
            let outside = kernel::self_address(c);
            ret(c, outside);
        });
        for (g, ran) in [(0, false), (1, true)] {
            let e = run(&circuit, g);
            assert_eq!(e.run.outputs, me, "{lowering:?}, g = {g}: the read after the scope sees the address");
            assert_eq!(self_reads(&e), vec![ran, true], "{lowering:?}, g = {g}: the guarded read, then a real one");
        }
    }
}

/// A guarded read first, then straight-line ones. Under either setting the
/// guarded read is emitted and runs only where `g` holds, its value is zero
/// where it does not, and the first straight-line read is real. Under
/// `OncePerCircuit` that read is kept and the third call emits nothing; under
/// `EveryCall` it is a third read.
#[test]
fn a_guarded_read_then_unguarded_ones() {
    let (me, zero) = (address(), zero());
    for reads in [SelfAddressReads::EveryCall, SelfAddressReads::OncePerCircuit] {
        let circuit = with(Some(reads), |c| {
            let g = guard(c);
            let inside = c.when(g, kernel::self_address).or_default();
            let outside = kernel::self_address(c);
            let again = kernel::self_address(c);
            ret(c, inside);
            ret(c, outside);
            ret(c, again);
        });
        for g in [0, 1] {
            let e = run(&circuit, g);
            let inside = if g == 1 { &me } else { &zero };
            assert_eq!(e.run.outputs, cat(&cat(inside, &me), &me), "{reads:?}, g = {g}");
            let emitted = match reads {
                SelfAddressReads::EveryCall => vec![g == 1, true, true],
                SelfAddressReads::OncePerCircuit => vec![g == 1, true],
            };
            assert_eq!(self_reads(&e), emitted, "{reads:?}, g = {g}");
        }
    }
}

/// A straight-line read first, then a guarded one. Under `EveryCall` the
/// guarded call is a second, guarded read (zero where `g` is off). Under
/// `OncePerCircuit` it is the kept address and emits NOTHING, so the value
/// taken out of the scope is the address even where `g` is off: sound (the
/// address is constant and every effect in the scope is guarded), and the
/// one behaviour that differs from the guarded read's zero, documented on
/// `kernel::self_address`.
#[test]
fn an_unguarded_read_then_a_guarded_one() {
    let (me, zero) = (address(), zero());
    for reads in [SelfAddressReads::EveryCall, SelfAddressReads::OncePerCircuit] {
        let circuit = with(Some(reads), |c| {
            let g = guard(c);
            let outside = kernel::self_address(c);
            let inside = c.when(g, kernel::self_address).or_default();
            ret(c, outside);
            ret(c, inside);
        });
        for g in [0, 1] {
            let e = run(&circuit, g);
            let (inside, emitted) = match reads {
                SelfAddressReads::EveryCall => (if g == 1 { &me } else { &zero }, vec![true, g == 1]),
                SelfAddressReads::OncePerCircuit => (&me, vec![true]),
            };
            assert_eq!(e.run.outputs, cat(&me, inside), "{reads:?}, g = {g}");
            assert_eq!(self_reads(&e), emitted, "{reads:?}, g = {g}");
        }
    }
}
