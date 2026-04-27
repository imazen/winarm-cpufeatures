//! Type-checks `aarch64.rs` (the std_detect drop-in replacement) under the
//! same surface API the real std_detect file imports.
//!
//! Build with:
//!     cargo build --target aarch64-pc-windows-msvc -p stdetect-aarch64-windows-check
//!
//! Nothing here gets shipped — it just verifies the patch compiles cleanly.

#![cfg(all(target_arch = "aarch64", target_os = "windows"))]
#![allow(dead_code, non_camel_case_types, clippy::upper_case_acronyms)]

pub mod detect {
    /// Mirror of `std_detect::detect::cache::Initializer` (a `u128` bitset).
    pub mod cache {
        #[derive(Default)]
        pub struct Initializer(u128);
        impl Initializer {
            pub fn set(&mut self, bit: u32) {
                self.0 |= 1u128 << bit;
            }
            pub fn test(&self, bit: u32) -> bool {
                (self.0 >> bit) & 1 != 0
            }
        }
    }

    /// Mirror of every `Feature` variant referenced by the patch. The
    /// discriminant values don't have to match real std_detect — this
    /// crate only checks that the names exist and the file compiles.
    #[repr(u32)]
    #[derive(Copy, Clone)]
    pub enum Feature {
        // IPFP-set
        fp,
        asimd,
        crc,
        lse,
        dotprod,
        jsconv,
        rcpc,
        aes,
        pmull,
        sha2,
        sve,
        sve2,
        sve2p1,
        sve2_aes,
        sve2_bitperm,
        sve_b16b16,
        sve2_sha3,
        sve2_sm4,
        // Registry-set
        rdm,
        sha3,
        sm4,
        fhm,
        flagm,
        flagm2,
        rand,
        dpb,
        dpb2,
        paca,
        pacg,
        fcma,
        rcpc2,
        rcpc3,
        frintts,
        sb,
        bf16,
        i8mm,
        wfxt,
        mops,
        hbc,
        cssc,
        fp16,
        dit,
        bti,
        ssbs,
        mte,
        sme,
        lse2,
        // SDK 26100 IPFP additions
        sme2,
        sme2p1,
        sme_b16b16,
        sme_f16f16,
        sme_f64f64,
        sme_f8f16,
        sme_f8f32,
        sme_fa64,
        sme_i16i64,
        sme_lutv2,
        ssve_fp8dot2,
        ssve_fp8dot4,
        ssve_fp8fma,
        f32mm,
        f64mm,
    }
}

#[path = "../../aarch64.rs"]
mod patched;

// Expose the entry point un-inlined so the emitted asm shows the real
// codegen for IPFP probes + registry FFI + ID-register decoding. Without
// the `no_mangle` + `inline(never)` it gets folded into the caller and
// leaves nothing to inspect in `--emit=asm`.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn detect_features_audit() -> u128 {
    let init = patched::detect_features();
    // The real Initializer is opaque; for the audit lib we mirror it as a
    // u128 so we can return the raw bitset for inspection.
    unsafe { core::mem::transmute(init) }
}
