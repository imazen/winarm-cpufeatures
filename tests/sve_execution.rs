//! SVE execution verification (nightly-only).
//!
//! If our detection reports `sve` as present, we back that up by actually
//! executing an SVE instruction (`cntb` — count bytes in an SVE vector).
//! On a CPU without SVE this faults with SIGILL; on a correctly-detecting
//! runner, it returns a positive power-of-two byte count.
//!
//! Gated by the `nightly-sve` cargo feature. Compile with
//! `RUSTFLAGS="-C target-feature=+sve"` so SVE instructions are accepted
//! by the assembler. The inline asm avoids the unstable `repr(scalable)`
//! machinery entirely.

#![cfg(all(target_arch = "aarch64", feature = "nightly-sve"))]

use winarm_cpufeatures::is_aarch64_feature_detected_full;

/// Execute SVE `cntb` — returns the number of bytes in an SVE vector.
/// Any SVE-capable CPU returns one of {16, 32, 64, 128, 256} (128b..2048b).
/// Inline asm keeps SVE types out of our Rust signatures.
unsafe fn sve_cntb() -> u64 {
    let out: u64;
    // SAFETY: caller guarantees SVE is implemented. `cntb` is side-effect-free.
    unsafe {
        core::arch::asm!(
            "cntb {x}",
            x = out(reg) out,
            options(nomem, nostack, preserves_flags),
        );
    }
    out
}

#[test]
fn sve_detect_matches_execution() {
    if !is_aarch64_feature_detected_full!("sve") {
        eprintln!("sve not is_aarch64_feature_detected on this CPU — skipping execution check");
        return;
    }
    // SAFETY: is_aarch64_feature_detected_full!("sve") confirmed SVE is present; RUSTFLAGS
    // target-feature=+sve makes the assembler accept the CNTB encoding.
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
