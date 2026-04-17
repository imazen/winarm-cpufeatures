//! AArch64 CPU feature detection that fills the Windows-on-ARM gap in
//! [`std::arch::is_aarch64_feature_detected!`].
//!
//! ## Why this exists
//!
//! On `aarch64-pc-windows-msvc` with Rust 1.85, `is_aarch64_feature_detected!`
//! is a thin wrapper around `IsProcessorFeaturePresent`. Microsoft only
//! defines ~17 `PF_ARM_*` constants, so just **10 of the 73** feature names
//! the macro accepts get probed — every other call returns `false` even on
//! silicon that physically supports the feature.
//!
//! Closing the rest of the gap requires reading
//! `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0\CP <hex>`, which the
//! Windows kernel populates with cached `ID_AA64*_EL1` system-register
//! snapshots at boot. This is undocumented-but-stable since Windows 10 1709
//! and is the approach used by LLVM, pytorch/cpuinfo, and Microsoft's own
//! ONNX Runtime.
//!
//! ## Two macros, two cost tiers
//!
//! Registry reads aren't free — opening the key and pulling ten `REG_QWORD`
//! values isn't cheap on cold paths. So this crate splits detection into
//! two opt-in tiers:
//!
//! | Macro              | Backend on Windows ARM       | Compile error if feature... |
//! |--------------------|------------------------------|-----------------------------|
//! | [`detected!`]      | `IsProcessorFeaturePresent`  | needs the registry          |
//! | [`detected_full!`] | IPFP + registry CP-key reads | never                       |
//!
//! Each macro maintains its own cache. `detected!` runs `IsProcessorFeaturePresent`
//! probes once per process; `detected_full!` does the same plus a single
//! batched registry pass on first call. Both caches use `Ordering::Relaxed`
//! atomic loads — the probe is idempotent so racing initializers are fine.
//!
//! On every non-Windows-ARM platform, both macros expand to
//! `std::arch::is_aarch64_feature_detected!` directly.
//!
//! ## Quick reference
//!
//! ```no_run
//! use winarm_cpufeatures::{detected, detected_full};
//!
//! // Cheap — IPFP only.
//! if detected!("sve")   { /* SVE kernel */ }
//! if detected!("aes")   { /* AES instructions */ }
//!
//! // Slow first call (one batched registry pass), free after that.
//! if detected_full!("rdm")  { /* Rounding Doubling Multiply */ }
//! if detected_full!("bf16") { /* AdvSIMD BF16 */ }
//!
//! // Compile error: "rdm" is Registry-only.
//! // let _ = winarm_cpufeatures::detected!("rdm");
//! ```
//!
//! ## Comparison to other crates
//!
//! - [`cpufeatures`](https://crates.io/crates/cpufeatures) (RustCrypto) is the
//!   widely-used cross-platform feature detector but explicitly punts on
//!   Windows-ARM and only exposes `aes`/`sha2`/`sha3` on aarch64. Use both
//!   crates side-by-side: `cpufeatures` for x86 + Linux/macOS aarch64;
//!   this crate for Windows-on-ARM.
//! - [`aarch64-cpu`](https://crates.io/crates/aarch64-cpu) is a bare-metal
//!   register-access crate for kernel/embedded code. Different domain.

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

mod cache;
mod detect;
mod features;

#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
mod windows;

pub use cache::{Features, is_detected, is_detected_full};
pub use features::{DetectionMethod, FEATURE_COUNT, Feature};

/// Cheap detection — uses `IsProcessorFeaturePresent` only on Windows ARM64.
///
/// This macro **fails to compile** if `$name` requires registry detection
/// (i.e. its [`DetectionMethod`] is [`DetectionMethod::Registry`]). Use
/// [`detected_full!`] for those.
///
/// On non-Windows-ARM targets, expands to
/// `std::arch::is_aarch64_feature_detected!`.
///
/// ```no_run
/// if winarm_cpufeatures::detected!("sve") {
///     // SVE kernel
/// }
/// ```
#[macro_export]
macro_rules! detected {
    ($name:literal) => {{
        const _F: ::core::option::Option<$crate::Feature> =
            $crate::Feature::from_name_const($name);
        const _CHECK_VALID: () = assert!(
            _F.is_some(),
            concat!("unknown aarch64 feature name: '", $name, "'"),
        );
        const _CHECK_FAST: () = {
            if let Some(f) = _F {
                match f.detection_method() {
                    $crate::DetectionMethod::Ipfp | $crate::DetectionMethod::Both => {}
                    $crate::DetectionMethod::Registry => ::core::panic!(concat!(
                        "feature '",
                        $name,
                        "' requires registry detection — use winarm_cpufeatures::detected_full!() instead",
                    )),
                }
            }
        };
        match _F {
            ::core::option::Option::Some(f) => $crate::is_detected(f),
            ::core::option::Option::None => false,
        }
    }};
}

/// Full detection — uses `IsProcessorFeaturePresent` plus registry-cached
/// `ID_AA64*_EL1` reads on Windows ARM64. Accepts every feature name.
///
/// First call from a process triggers one registry key open + ~10 value
/// reads. Subsequent calls hit the cached bitset.
///
/// On non-Windows-ARM targets, expands to
/// `std::arch::is_aarch64_feature_detected!`.
///
/// ```no_run
/// if winarm_cpufeatures::detected_full!("rdm") {
///     // Rounding Doubling Multiply Accumulate
/// }
/// ```
#[macro_export]
macro_rules! detected_full {
    ($name:literal) => {{
        const _F: ::core::option::Option<$crate::Feature> = $crate::Feature::from_name_const($name);
        const _CHECK_VALID: () = assert!(
            _F.is_some(),
            concat!("unknown aarch64 feature name: '", $name, "'"),
        );
        match _F {
            ::core::option::Option::Some(f) => $crate::is_detected_full(f),
            ::core::option::Option::None => false,
        }
    }};
}

impl Feature {
    /// Const version of [`Feature::from_name`], used by the [`detected!`]
    /// and [`detected_full!`] macros to validate names at compile time.
    #[doc(hidden)]
    pub const fn from_name_const(name: &str) -> Option<Self> {
        const fn eq(a: &str, b: &str) -> bool {
            let a = a.as_bytes();
            let b = b.as_bytes();
            if a.len() != b.len() {
                return false;
            }
            let mut i = 0;
            while i < a.len() {
                if a[i] != b[i] {
                    return false;
                }
                i += 1;
            }
            true
        }
        let names = &[
            ("asimd", Feature::Asimd),
            ("fp", Feature::Fp),
            ("fp16", Feature::Fp16),
            ("fhm", Feature::Fhm),
            ("fcma", Feature::Fcma),
            ("bf16", Feature::Bf16),
            ("i8mm", Feature::I8mm),
            ("jsconv", Feature::JsConv),
            ("frintts", Feature::FrintTs),
            ("rdm", Feature::Rdm),
            ("dotprod", Feature::Dotprod),
            ("aes", Feature::Aes),
            ("pmull", Feature::Pmull),
            ("sha2", Feature::Sha2),
            ("sha3", Feature::Sha3),
            ("sm4", Feature::Sm4),
            ("crc", Feature::Crc),
            ("lse", Feature::Lse),
            ("lse2", Feature::Lse2),
            ("lse128", Feature::Lse128),
            ("rcpc", Feature::Rcpc),
            ("rcpc2", Feature::Rcpc2),
            ("rcpc3", Feature::Rcpc3),
            ("paca", Feature::Paca),
            ("pacg", Feature::Pacg),
            ("pauth_lr", Feature::PauthLr),
            ("bti", Feature::Bti),
            ("dpb", Feature::Dpb),
            ("dpb2", Feature::Dpb2),
            ("mte", Feature::Mte),
            ("mops", Feature::Mops),
            ("dit", Feature::Dit),
            ("sb", Feature::Sb),
            ("ssbs", Feature::Ssbs),
            ("flagm", Feature::FlagM),
            ("flagm2", Feature::FlagM2),
            ("rand", Feature::Rand),
            ("tme", Feature::Tme),
            ("ecv", Feature::Ecv),
            ("cssc", Feature::Cssc),
            ("wfxt", Feature::WfxT),
            ("hbc", Feature::Hbc),
            ("lut", Feature::Lut),
            ("faminmax", Feature::FaMinMax),
            ("fp8", Feature::Fp8),
            ("fp8dot2", Feature::Fp8Dot2),
            ("fp8dot4", Feature::Fp8Dot4),
            ("fp8fma", Feature::Fp8Fma),
            ("fpmr", Feature::Fpmr),
            ("sve", Feature::Sve),
            ("sve2", Feature::Sve2),
            ("sve2p1", Feature::Sve2p1),
            ("sve2_aes", Feature::Sve2Aes),
            ("sve2_bitperm", Feature::Sve2Bitperm),
            ("sve2_sha3", Feature::Sve2Sha3),
            ("sve2_sm4", Feature::Sve2Sm4),
            ("sve_b16b16", Feature::SveB16b16),
            ("f32mm", Feature::F32mm),
            ("f64mm", Feature::F64mm),
            ("sme", Feature::Sme),
            ("sme2", Feature::Sme2),
            ("sme2p1", Feature::Sme2p1),
            ("sme_b16b16", Feature::SmeB16b16),
            ("sme_f16f16", Feature::SmeF16f16),
            ("sme_f64f64", Feature::SmeF64f64),
            ("sme_f8f16", Feature::SmeF8f16),
            ("sme_f8f32", Feature::SmeF8f32),
            ("sme_fa64", Feature::SmeFa64),
            ("sme_i16i64", Feature::SmeI16i64),
            ("sme_lutv2", Feature::SmeLutv2),
            ("ssve_fp8dot2", Feature::SsveFp8Dot2),
            ("ssve_fp8dot4", Feature::SsveFp8Dot4),
            ("ssve_fp8fma", Feature::SsveFp8Fma),
        ];
        let mut i = 0;
        while i < names.len() {
            if eq(names[i].0, name) {
                return Some(names[i].1);
            }
            i += 1;
        }
        None
    }
}
