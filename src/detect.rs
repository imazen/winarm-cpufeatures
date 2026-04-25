//! Cross-platform detection entry points.
//!
//! Split into two functions:
//!
//! - [`probe_fast`]: IPFP-only on Windows; full stdarch delegation elsewhere
//!   (non-Windows platforms have no cheap/expensive split — stdarch is
//!   always cheap).
//! - [`probe_full`]: IPFP + registry on Windows; same stdarch delegation
//!   elsewhere.
//!
//! On non-Windows aarch64 targets, we delegate to
//! `std::arch::is_aarch64_feature_detected!`. 41 of the 73 feature names
//! are `#[stable]` on Rust 1.85; the remaining 32 are gated behind the
//! `stdarch_aarch64_feature_detection` unstable feature and require
//! nightly rustc. The `build.rs` sets `cfg(winarm_rustc_nightly)` when
//! building with nightly so those names participate; on stable they
//! return `false` (our crate is explicitly MSRV 1.85-stable-compatible).

use crate::cache::Features;
#[cfg(all(target_arch = "aarch64", not(target_os = "windows")))]
use crate::features::Feature;

/// Cheap probe — no registry reads.
#[allow(clippy::needless_return, reason = "cfg-conditional bodies — explicit returns keep each branch self-contained")]
pub(crate) fn probe_fast() -> Features {
    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    {
        let mut f = Features::EMPTY;
        crate::windows::fill_ipfp(&mut f);
        return f;
    }

    #[cfg(all(not(target_os = "windows"), target_arch = "aarch64"))]
    {
        return stdarch_delegate();
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        Features::EMPTY
    }
}

/// Full probe — IPFP plus, when the `registry` Cargo feature is enabled,
/// `HKLM\…\CentralProcessor\0\CP <hex>` ID-register reads on Windows.
///
/// Without `registry` this is identical to [`probe_fast`]; the
/// `Registry`-classified feature names report `false`.
#[allow(clippy::needless_return, reason = "cfg-conditional bodies — explicit returns keep each branch self-contained")]
pub(crate) fn probe_full() -> Features {
    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    {
        let mut f = Features::EMPTY;
        crate::windows::fill_ipfp(&mut f);
        #[cfg(feature = "registry")]
        crate::windows::fill_registry(&mut f);
        return f;
    }

    #[cfg(all(not(target_os = "windows"), target_arch = "aarch64"))]
    {
        return stdarch_delegate();
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        Features::EMPTY
    }
}

/// Delegate each feature name to stdarch. Names are passed as `:tt` not
/// `:literal` — stdarch's macro matches each feature with `($lit:tt)`
/// internal patterns and a `:literal`-captured string falls through to
/// the "unknown aarch64 target feature" error arm on 1.85.
#[cfg(all(not(target_os = "windows"), target_arch = "aarch64"))]
pub(crate) fn stdarch_delegate() -> Features {
    let mut f = Features::EMPTY;
    macro_rules! probe {
        ($($name:tt => $variant:ident),* $(,)?) => {
            $(
                if std::arch::is_aarch64_feature_detected!($name) {
                    f = f.with(Feature::$variant);
                }
            )*
        };
    }
    // ── Stable on Rust 1.85 — 41 feature names ───────────────────────────
    probe! {
        "asimd"        => Asimd,
        "fp"           => Fp,
        "fp16"         => Fp16,
        "fhm"          => Fhm,
        "fcma"         => Fcma,
        "bf16"         => Bf16,
        "i8mm"         => I8mm,
        "jsconv"       => JsConv,
        "frintts"      => FrintTs,
        "rdm"          => Rdm,
        "dotprod"      => Dotprod,
        "aes"          => Aes,
        "pmull"        => Pmull,
        "sha2"         => Sha2,
        "sha3"         => Sha3,
        "sm4"          => Sm4,
        "crc"          => Crc,
        "lse"          => Lse,
        "lse2"         => Lse2,
        "rcpc"         => Rcpc,
        "rcpc2"        => Rcpc2,
        "paca"         => Paca,
        "pacg"         => Pacg,
        "bti"          => Bti,
        "dpb"          => Dpb,
        "dpb2"         => Dpb2,
        "mte"          => Mte,
        "dit"          => Dit,
        "sb"           => Sb,
        "ssbs"         => Ssbs,
        "flagm"        => FlagM,
        "rand"         => Rand,
        "tme"          => Tme,
        "sve"          => Sve,
        "sve2"         => Sve2,
        "sve2-aes"     => Sve2Aes,
        "sve2-bitperm" => Sve2Bitperm,
        "sve2-sha3"    => Sve2Sha3,
        "sve2-sm4"     => Sve2Sm4,
        "f32mm"        => F32mm,
        "f64mm"        => F64mm,
    }

    // ── Nightly-only on Rust 1.85 — require #![feature(stdarch_aarch64_feature_detection)] ─
    // build.rs emits cfg(winarm_rustc_nightly) when rustc reports nightly.
    #[cfg(winarm_rustc_nightly)]
    probe! {
        "cssc"         => Cssc,
        "ecv"          => Ecv,
        "faminmax"     => FaMinMax,
        "flagm2"       => FlagM2,
        "fp8"          => Fp8,
        "fp8dot2"      => Fp8Dot2,
        "fp8dot4"      => Fp8Dot4,
        "fp8fma"       => Fp8Fma,
        "fpmr"         => Fpmr,
        "hbc"          => Hbc,
        "lse128"       => Lse128,
        "lut"          => Lut,
        "mops"         => Mops,
        // stdarch's literal uses a dash; our user-facing name uses an underscore.
        "pauth-lr"     => PauthLr,
        "rcpc3"        => Rcpc3,
        "sme"          => Sme,
        "sme2"         => Sme2,
        "sme2p1"       => Sme2p1,
        "sme-b16b16"   => SmeB16b16,
        "sme-f16f16"   => SmeF16f16,
        "sme-f64f64"   => SmeF64f64,
        "sme-f8f16"    => SmeF8f16,
        "sme-f8f32"    => SmeF8f32,
        "sme-fa64"     => SmeFa64,
        "sme-i16i64"   => SmeI16i64,
        "sme-lutv2"    => SmeLutv2,
        "ssve-fp8dot2" => SsveFp8Dot2,
        "ssve-fp8dot4" => SsveFp8Dot4,
        "ssve-fp8fma"  => SsveFp8Fma,
        "sve2p1"       => Sve2p1,
        "sve-b16b16"   => SveB16b16,
        "wfxt"         => WfxT,
    }

    f
}
