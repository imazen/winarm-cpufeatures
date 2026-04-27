//! AArch64 feature enumeration and per-feature detection-method classification.
//!
//! The set of feature names mirrors `std::arch::is_aarch64_feature_detected!`
//! as of Rust 1.85 (73 names). Discriminant values are bit positions into the
//! detection cache; they are `pub` so callers can manage their own bitsets.
//!
//! Each feature has a [`DetectionMethod`] describing the cheapest backend
//! that can confirm it on Windows-on-ARM. This drives the compile-time
//! dispatch between [`crate::is_aarch64_feature_detected_fast!`] (fast, IPFP-only) and
//! [`crate::is_aarch64_feature_detected_full!`] (slow, reads the registry).

#![allow(non_camel_case_types)]

/// How a given feature is detected on Windows ARM64. Used internally to
/// decide whether the IPFP-only fast cache is sufficient or whether the
/// registry decoder must run.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum DetectionMethod {
    /// `IsProcessorFeaturePresent` covers this feature directly. Cost: one
    /// syscall per feature on first probe, then cached.
    Ipfp,
    /// Reading the `HKLM\...\CentralProcessor\0\CP <hex>` registry values is
    /// required — Microsoft has never defined a `PF_ARM_*` constant. Cost:
    /// one registry key open + ~10 value reads on first probe, then cached.
    Registry,
    /// Either path works. IPFP is used when available, registry otherwise.
    Both,
}

macro_rules! features {
    ($($variant:ident = ($bit:literal, $name:literal, $method:ident)),* $(,)?) => {
        /// One AArch64 feature name as accepted by
        /// `std::arch::is_aarch64_feature_detected!`.
        #[repr(u8)]
        #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
        #[allow(missing_docs)]
        pub enum Feature {
            $($variant = $bit,)*
        }

        /// The canonical full list of features. Source for `Feature::all()`
        /// and the compile-time bit-layout validation in this module.
        const ALL_FEATURES: &[Feature] = &[$(Feature::$variant),*];

        impl Feature {
            /// The canonical name as accepted by `std::arch::is_aarch64_feature_detected!`.
            pub const fn name(self) -> &'static str {
                match self {
                    $(Feature::$variant => $name,)*
                }
            }

            /// Which detection backend confirms this feature on Windows ARM64.
            #[allow(dead_code, reason = "consumed by internal tests; classification is informational")]
            pub(crate) const fn detection_method(self) -> DetectionMethod {
                match self {
                    $(Feature::$variant => DetectionMethod::$method,)*
                }
            }

            /// Parse a stdarch feature name into a `Feature`. `None` if unrecognized.
            #[allow(dead_code, reason = "internal-use lookup; tests exercise it")]
            pub(crate) fn from_name(name: &str) -> Option<Self> {
                match name {
                    $($name => Some(Feature::$variant),)*
                    _ => None,
                }
            }

            /// Iterator over every feature. Useful for diagnostics.
            pub fn all() -> impl Iterator<Item = Self> {
                ALL_FEATURES.iter().copied()
            }
        }
    };
}

features! {
    // ── SIMD / compute baseline ────────────────────────────────────────────
    Asimd      = (0,  "asimd",        Ipfp),
    Fp         = (1,  "fp",           Ipfp),
    // PF_ARM_V82_FP16 (#67) wired since SDK 26100; registry ID_AA64PFR0
    // covers older Windows builds too.
    Fp16       = (2,  "fp16",         Both),
    Fhm        = (3,  "fhm",          Registry),
    Fcma       = (4,  "fcma",         Registry),
    // PF_ARM_V86_BF16 (#68) wired since SDK 26100; registry ISAR1 fallback.
    Bf16       = (5,  "bf16",         Both),
    // PF_ARM_V82_I8MM (#66) wired since SDK 26100; registry ISAR1 fallback.
    I8mm       = (6,  "i8mm",         Both),
    JsConv     = (7,  "jsconv",       Ipfp),
    FrintTs    = (8,  "frintts",      Registry),
    // Microsoft has never defined PF_ARM_RDM_*. Derived from PF_ARM_V82_DP
    // or PF_ARM_V81_ATOMIC via ARM ARM K.a §D17.2.91 — same approach .NET
    // 10 ships (dotnet/runtime#109493). Registry ISAR0 confirms.
    Rdm        = (9,  "rdm",          Both),
    Dotprod    = (10, "dotprod",      Ipfp),
    // ── Crypto ─────────────────────────────────────────────────────────────
    // aes/pmull/sha2 are grouped under PF_ARM_V8_CRYPTO.
    Aes        = (11, "aes",          Ipfp),
    Pmull      = (12, "pmull",        Ipfp),
    Sha2       = (13, "sha2",         Ipfp),
    // PF_ARM_SHA3 (#64) AND PF_ARM_SHA512 (#65) wired since SDK 26100
    // (stdarch's `sha3` requires both). Registry ISAR0 fallback.
    Sha3       = (14, "sha3",         Both),
    // PF_ARM_SVE_SM4 (#56) covers SVE-form only; AdvSIMD form needs registry.
    Sm4        = (15, "sm4",          Registry),
    Crc        = (16, "crc",          Ipfp),
    // ── Atomics / memory ───────────────────────────────────────────────────
    Lse        = (17, "lse",          Ipfp),
    // PF_ARM_LSE2_AVAILABLE (#62) wired since SDK 26100; registry MMFR2 fallback.
    Lse2       = (18, "lse2",         Both),
    Lse128     = (19, "lse128",       Registry),
    Rcpc       = (20, "rcpc",         Ipfp),
    Rcpc2      = (21, "rcpc2",        Registry),
    Rcpc3      = (22, "rcpc3",        Registry),
    // ── Pointer authentication / control-flow ─────────────────────────────
    Paca       = (23, "paca",         Registry),
    Pacg       = (24, "pacg",         Registry),
    PauthLr    = (25, "pauth-lr",     Registry),
    Bti        = (26, "bti",          Registry),
    // ── Memory features ────────────────────────────────────────────────────
    Dpb        = (27, "dpb",          Registry),
    Dpb2       = (28, "dpb2",         Registry),
    Mte        = (29, "mte",          Registry),
    Mops       = (30, "mops",         Registry),
    // ── Side-channel / timing ─────────────────────────────────────────────
    Dit        = (31, "dit",          Registry),
    Sb         = (32, "sb",           Registry),
    Ssbs       = (33, "ssbs",         Registry),
    // ── Flag manipulation ─────────────────────────────────────────────────
    FlagM      = (34, "flagm",        Registry),
    FlagM2     = (35, "flagm2",       Registry),
    // ── System / misc ─────────────────────────────────────────────────────
    Rand       = (36, "rand",         Registry),
    Tme        = (37, "tme",          Registry),
    Ecv        = (38, "ecv",          Registry),
    Cssc       = (39, "cssc",         Registry),
    WfxT       = (40, "wfxt",         Registry),
    Hbc        = (41, "hbc",          Registry),
    Lut        = (42, "lut",          Registry),
    FaMinMax   = (43, "faminmax",     Registry),
    // ── FP8 ───────────────────────────────────────────────────────────────
    Fp8        = (44, "fp8",          Registry),
    Fp8Dot2    = (45, "fp8dot2",      Registry),
    Fp8Dot4    = (46, "fp8dot4",      Registry),
    Fp8Fma     = (47, "fp8fma",       Registry),
    Fpmr       = (48, "fpmr",         Registry),
    // ── SVE / SVE2 (IPFP since SDK 26100) ─────────────────────────────────
    Sve        = (49, "sve",          Ipfp),
    Sve2       = (50, "sve2",         Ipfp),
    Sve2p1     = (51, "sve2p1",       Ipfp),
    Sve2Aes    = (52, "sve2-aes",     Ipfp),
    Sve2Bitperm= (53, "sve2-bitperm", Ipfp),
    Sve2Sha3   = (54, "sve2-sha3",    Ipfp),
    Sve2Sm4    = (55, "sve2-sm4",     Ipfp),
    SveB16b16  = (56, "sve-b16b16",   Ipfp),
    F32mm      = (57, "f32mm",        Ipfp),
    F64mm      = (58, "f64mm",        Ipfp),
    // ── SME / SME2 (IPFP since SDK 26100, registry decode for `sme` only) ─
    // PF_ARM_SME (#70) maps to `sme`; registry PFR1 confirms.
    Sme        = (59, "sme",          Both),
    Sme2       = (60, "sme2",         Ipfp),
    Sme2p1     = (61, "sme2p1",       Ipfp),
    SmeB16b16  = (62, "sme-b16b16",   Ipfp),
    // Bit 63 of `lo` is reserved as `INIT_BIT` for the cache machinery
    // in `cache.rs`. Features must avoid bit 63 (lo) and bit 127 (hi).
    SmeF64f64  = (64, "sme-f64f64",   Ipfp),
    SmeF8f16   = (65, "sme-f8f16",    Ipfp),
    SmeF8f32   = (66, "sme-f8f32",    Ipfp),
    SmeFa64    = (67, "sme-fa64",     Ipfp),
    SmeI16i64  = (68, "sme-i16i64",   Ipfp),
    SmeLutv2   = (69, "sme-lutv2",    Ipfp),
    SsveFp8Dot2= (70, "ssve-fp8dot2", Ipfp),
    SsveFp8Dot4= (71, "ssve-fp8dot4", Ipfp),
    SsveFp8Fma = (72, "ssve-fp8fma",  Ipfp),
    // Moved here from bit 63 because that slot is reserved for INIT_BIT.
    SmeF16f16  = (73, "sme-f16f16",   Ipfp),
}

// ─── Compile-time bit-layout validation ───────────────────────────────────
//
// The detection cache stores feature presence as bits in two `AtomicU64`s
// (`lo` and `hi`). Each `Feature` variant's discriminant doubles as its
// bit index. Three invariants must hold for the encoding to work:
//
//   1. Every discriminant fits in `0..128`.
//   2. No discriminant equals 63 (reserved as `INIT_BIT` in `lo`)
//      or 127 (reserved as `INIT_BIT` in `hi`); see `cache::INIT_BIT`.
//   3. No two features share the same discriminant.
//
// Violating any of these silently corrupts the cache encoding. Rather
// than checking at runtime (which catches bugs after the binary
// shipped), we evaluate the invariants at compile time. Adding a feature
// at bit 63 or 127 — or duplicating an existing bit — fails the build
// with the message below.

const _: () = {
    let mut i = 0;
    while i < ALL_FEATURES.len() {
        let bit = ALL_FEATURES[i] as u8;
        assert!(bit < 128, "Feature discriminant out of range: must be in 0..128");
        assert!(
            bit != 63,
            "Feature occupies bit 63, reserved as `INIT_BIT` in `lo` — pick a different discriminant",
        );
        assert!(
            bit != 127,
            "Feature occupies bit 127, reserved as `INIT_BIT` in `hi` — pick a different discriminant",
        );
        let mut j = i + 1;
        while j < ALL_FEATURES.len() {
            assert!(
                (ALL_FEATURES[i] as u8) != (ALL_FEATURES[j] as u8),
                "Two features share the same discriminant — discriminants must be unique",
            );
            j += 1;
        }
        i += 1;
    }
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_features_roundtrip_name() {
        for f in Feature::all() {
            assert_eq!(Feature::from_name(f.name()), Some(f), "{}", f.name());
        }
    }

    #[test]
    fn every_feature_has_detection_method() {
        for f in Feature::all() {
            let _ = f.detection_method();
        }
    }
}
