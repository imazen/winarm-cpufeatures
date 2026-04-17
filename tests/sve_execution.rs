//! SVE execution verification (nightly-only).
//!
//! If our detection reports `sve` as present, we back that up by actually
//! executing an SVE instruction (`cntb` — count bytes in an SVE vector).
//! On a CPU without SVE this faults with SIGILL; on a correctly-detecting
//! runner, it returns a positive power-of-two byte count.
//!
//! Gated by the `nightly-sve` cargo feature + nightly rustc because
//! `#[target_feature(enable = "sve")]` is unstable on aarch64. Compile
//! with `RUSTFLAGS="-C target-feature=+sve"` to make the SVE code path
//! unconditionally available.

#![cfg(all(target_arch = "aarch64", feature = "nightly-sve"))]
#![feature(aarch64_unstable_target_feature)]

use winarm_cpufeatures::detected_full;

/// SVE CNTB instruction — returns the number of bytes in an SVE vector. On
/// any SVE-capable CPU this is one of {16, 32, 64, 128, 256} (i.e. 128 bits
/// up to 2048 bits of vector width). Inline asm keeps us clear of the
/// unstable `repr(scalable)` machinery.
#[target_feature(enable = "sve")]
unsafe fn sve_cntb() -> u64 {
    let out: u64;
    // SAFETY: `cntb` is an unconditional SVE instruction; nothing to go
    // wrong as long as the CPU implements SVE.
    unsafe {
        core::arch::asm!("cntb {x}", x = out(reg) out, options(nomem, nostack, preserves_flags));
    }
    out
}

#[test]
fn sve_detect_matches_execution() {
    if !detected_full!("sve") {
        eprintln!("sve not detected on this CPU — skipping execution check");
        return;
    }
    // SAFETY: detected_full!("sve") confirmed SVE is present; the target
    // feature attribute guarantees the compiler emits valid SVE encoding.
    let vl = unsafe { sve_cntb() };
    assert!(vl > 0, "CNTB returned zero");
    assert!(
        vl.is_power_of_two(),
        "SVE byte count {vl} is not a power of two"
    );
    assert!(vl >= 16, "SVE vector must be ≥128 bits, got {}b", vl * 8);
    assert!(vl <= 256, "SVE vector must be ≤2048 bits, got {}b", vl * 8);
    eprintln!("SVE vector width = {} bytes ({} bits)", vl, vl * 8);
}
