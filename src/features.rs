//! AArch64 feature enumeration and per-feature detection-method classification.
//!
//! The set of feature names mirrors `std::arch::is_aarch64_feature_detected!`
//! as of Rust 1.85 (73 names). Discriminant values are bit positions into the
//! detection cache; they are `pub` so callers can manage their own bitsets.
//!
//! Each feature has a [`DetectionMethod`] describing the cheapest backend
//! that can confirm it on Windows-on-ARM. This drives the compile-time
//! dispatch between [`crate::detected!`] (fast, IPFP-only) and
//! [`crate::detected_full!`] (slow, reads the registry).

#![allow(non_camel_case_types)]

/// How a given feature is detected on Windows ARM64.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DetectionMethod {
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

        impl Feature {
            /// The canonical name as accepted by `std::arch::is_aarch64_feature_detected!`.
            pub const fn name(self) -> &'static str {
                match self {
                    $(Feature::$variant => $name,)*
                }
            }

            /// Which detection backend confirms this feature on Windows ARM64.
            pub const fn detection_method(self) -> DetectionMethod {
                match self {
                    $(Feature::$variant => DetectionMethod::$method,)*
                }
            }

            /// Parse a stdarch feature name into a `Feature`. `None` if unrecognized.
            pub fn from_name(name: &str) -> Option<Self> {
                match name {
                    $($name => Some(Feature::$variant),)*
                    _ => None,
                }
            }

            /// Iterator over every feature. Useful for diagnostics.
            pub fn all() -> impl Iterator<Item = Self> {
                const ALL: &[Feature] = &[$(Feature::$variant),*];
                ALL.iter().copied()
            }
        }
    };
}

features! {
    // ── SIMD / compute baseline ────────────────────────────────────────────
    Asimd      = (0,  "asimd",        Ipfp),
    Fp         = (1,  "fp",           Ipfp),
    Fp16       = (2,  "fp16",         Registry),
    Fhm        = (3,  "fhm",          Registry),
    Fcma       = (4,  "fcma",         Registry),
    Bf16       = (5,  "bf16",         Registry),
    I8mm       = (6,  "i8mm",         Registry),
    JsConv     = (7,  "jsconv",       Ipfp),
    FrintTs    = (8,  "frintts",      Registry),
    Rdm        = (9,  "rdm",          Registry),
    Dotprod    = (10, "dotprod",      Ipfp),
    // ── Crypto ─────────────────────────────────────────────────────────────
    // aes/pmull/sha2 are grouped under PF_ARM_V8_CRYPTO.
    Aes        = (11, "aes",          Ipfp),
    Pmull      = (12, "pmull",        Ipfp),
    Sha2       = (13, "sha2",         Ipfp),
    // sha3/sm4 advsimd: no PF_ARM_* constant. Registry (ISAR0) only.
    Sha3       = (14, "sha3",         Registry),
    Sm4        = (15, "sm4",          Registry),
    Crc        = (16, "crc",          Ipfp),
    // ── Atomics / memory ───────────────────────────────────────────────────
    Lse        = (17, "lse",          Ipfp),
    Lse2       = (18, "lse2",         Registry),
    Lse128     = (19, "lse128",       Registry),
    Rcpc       = (20, "rcpc",         Ipfp),
    Rcpc2      = (21, "rcpc2",        Registry),
    Rcpc3      = (22, "rcpc3",        Registry),
    // ── Pointer authentication / control-flow ─────────────────────────────
    Paca       = (23, "paca",         Registry),
    Pacg       = (24, "pacg",         Registry),
    PauthLr    = (25, "pauth_lr",     Registry),
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
    // ── SVE / SVE2 (most in IPFP since SDK 26100) ─────────────────────────
    Sve        = (49, "sve",          Ipfp),
    Sve2       = (50, "sve2",         Ipfp),
    Sve2p1     = (51, "sve2p1",       Ipfp),
    Sve2Aes    = (52, "sve2_aes",     Ipfp),
    Sve2Bitperm= (53, "sve2_bitperm", Ipfp),
    Sve2Sha3   = (54, "sve2_sha3",    Ipfp),
    Sve2Sm4    = (55, "sve2_sm4",     Ipfp),
    SveB16b16  = (56, "sve_b16b16",   Ipfp),
    F32mm      = (57, "f32mm",        Ipfp),
    F64mm      = (58, "f64mm",        Ipfp),
    // ── SME / SME2 ────────────────────────────────────────────────────────
    // Present in SDK 26100 winnt.h but the numeric PF values are not
    // verified in our sources yet — mark Registry until verified.
    Sme        = (59, "sme",          Registry),
    Sme2       = (60, "sme2",         Registry),
    Sme2p1     = (61, "sme2p1",       Registry),
    SmeB16b16  = (62, "sme_b16b16",   Registry),
    SmeF16f16  = (63, "sme_f16f16",   Registry),
    SmeF64f64  = (64, "sme_f64f64",   Registry),
    SmeF8f16   = (65, "sme_f8f16",    Registry),
    SmeF8f32   = (66, "sme_f8f32",    Registry),
    SmeFa64    = (67, "sme_fa64",     Registry),
    SmeI16i64  = (68, "sme_i16i64",   Registry),
    SmeLutv2   = (69, "sme_lutv2",    Registry),
    SsveFp8Dot2= (70, "ssve_fp8dot2", Registry),
    SsveFp8Dot4= (71, "ssve_fp8dot4", Registry),
    SsveFp8Fma = (72, "ssve_fp8fma",  Registry),
}

/// Total count of enumerated features.
pub const FEATURE_COUNT: usize = 73;

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
    fn feature_count_matches_const() {
        assert_eq!(Feature::all().count(), FEATURE_COUNT);
    }

    #[test]
    fn bit_positions_unique_and_sequential() {
        let mut seen = [false; FEATURE_COUNT];
        for f in Feature::all() {
            let bit = f as u8 as usize;
            assert!(bit < FEATURE_COUNT, "{} bit={}", f.name(), bit);
            assert!(!seen[bit], "duplicate bit {} ({})", bit, f.name());
            seen[bit] = true;
        }
    }

    #[test]
    fn every_feature_has_detection_method() {
        for f in Feature::all() {
            let _ = f.detection_method();
        }
    }
}
