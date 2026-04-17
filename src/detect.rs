//! Cross-platform detection entry points.
//!
//! Split into two functions:
//!
//! - [`probe_fast`]: IPFP-only on Windows; full stdarch delegation elsewhere
//!   (non-Windows platforms have no cheap/expensive split — stdarch is
//!   always cheap).
//! - [`probe_full`]: IPFP + registry on Windows; same stdarch delegation
//!   elsewhere.

use crate::cache::Features;
#[cfg(all(target_arch = "aarch64", not(target_os = "windows")))]
use crate::features::Feature;

/// Cheap probe — no registry reads.
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

/// Full probe — IPFP + registry ID-register reads on Windows.
pub(crate) fn probe_full() -> Features {
    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    {
        let mut f = Features::EMPTY;
        crate::windows::fill_ipfp(&mut f);
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

/// On non-Windows aarch64 targets, delegate each feature name to stdarch.
#[cfg(all(not(target_os = "windows"), target_arch = "aarch64"))]
pub(crate) fn stdarch_delegate() -> Features {
    let mut f = Features::EMPTY;
    macro_rules! probe {
        ($($name:literal => $variant:ident),* $(,)?) => {
            $(
                if std::arch::is_aarch64_feature_detected!($name) {
                    f = f.with(Feature::$variant);
                }
            )*
        };
    }
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
        "lse128"       => Lse128,
        "rcpc"         => Rcpc,
        "rcpc2"        => Rcpc2,
        "rcpc3"        => Rcpc3,
        "paca"         => Paca,
        "pacg"         => Pacg,
        "pauth_lr"     => PauthLr,
        "bti"          => Bti,
        "dpb"          => Dpb,
        "dpb2"         => Dpb2,
        "mte"          => Mte,
        "mops"         => Mops,
        "dit"          => Dit,
        "sb"           => Sb,
        "ssbs"         => Ssbs,
        "flagm"        => FlagM,
        "flagm2"       => FlagM2,
        "rand"         => Rand,
        "tme"          => Tme,
        "ecv"          => Ecv,
        "cssc"         => Cssc,
        "wfxt"         => WfxT,
        "hbc"          => Hbc,
        "lut"          => Lut,
        "faminmax"     => FaMinMax,
        "fp8"          => Fp8,
        "fp8dot2"      => Fp8Dot2,
        "fp8dot4"      => Fp8Dot4,
        "fp8fma"       => Fp8Fma,
        "fpmr"         => Fpmr,
        "sve"          => Sve,
        "sve2"         => Sve2,
        "sve2p1"       => Sve2p1,
        "sve2-aes"     => Sve2Aes,
        "sve2-bitperm" => Sve2Bitperm,
        "sve2-sha3"    => Sve2Sha3,
        "sve2-sm4"     => Sve2Sm4,
        "sve-b16b16"   => SveB16b16,
        "f32mm"        => F32mm,
        "f64mm"        => F64mm,
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
    }
    f
}
