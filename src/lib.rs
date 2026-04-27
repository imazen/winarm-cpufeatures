//! AArch64 CPU feature detection that fills the Windows-on-ARM gap in
//! [`std::arch::is_aarch64_feature_detected!`].
//!
//! ## Why this exists
//!
//! On `aarch64-pc-windows-msvc` with Rust 1.85, `is_aarch64_feature_detected!`
//! is a thin wrapper around `IsProcessorFeaturePresent` (IPFP). Microsoft
//! defines 56 `PF_ARM_*` constants in Windows SDK 10.0.26100.0 but the
//! upstream stdarch backend only wires 17 of them, and Microsoft has never
//! exposed ~30 stdarch feature names through any `PF_ARM_*` constant at all
//! — including the headline miss `rdm`, which is mandatory on every
//! Windows-on-ARM CPU.
//!
//! ## Drop-in for std
//!
//! Same name, same dashed feature spelling, same call shape as
//! `std::arch::is_aarch64_feature_detected!`. Migration is one import
//! line:
//!
//! ```
//! # #[cfg(any())] mod _example {
//! // before
//! use std::arch::is_aarch64_feature_detected;
//! // after
//! use winarm_cpufeatures::is_aarch64_feature_detected;
//! # }
//! ```
//!
//! Every existing call site stays unchanged.
//!
//! ## How it dispatches
//!
//! - **Windows aarch64**: probes `IsProcessorFeaturePresent` (~30 names)
//!   plus the DP/LSE → RDM architectural inference (matches .NET 10's
//!   rule from ARM ARM K.a §D17.2.91 — see `dotnet/runtime#109493`). The
//!   `registry` Cargo feature adds an `HKLM\…\CentralProcessor\0\CP <hex>`
//!   decoder for the ~30 stdarch names IPFP can't reach (`fhm`, `fcma`,
//!   `frintts`, `paca`/`pacg`, `bti`, `dpb`/`dpb2`, `mte`, `mops`, `dit`,
//!   `sb`, `ssbs`, `flagm`/`flagm2`, `rand`, `cssc`, `wfxt`, `hbc`,
//!   `sm4`, `rcpc2`/`rcpc3`, `pauth-lr`, `lse128`, etc.). Both layers
//!   cache after first probe.
//! - **Non-Windows aarch64** (Linux, macOS): macros expand directly to
//!   `std::arch::is_aarch64_feature_detected!`. No added cache layer; std
//!   handles everything, including any future stdarch additions before
//!   we know about them.
//! - **Non-aarch64**: every name returns `false`. Lets cross-platform
//!   code use one spelling.
//!
//! ## Two macros, two cost tiers (Windows aarch64 only)
//!
//! - [`is_aarch64_feature_detected!`] reads the IPFP-only cache. Names
//!   IPFP can't see (Registry-classified) silently return `false`,
//!   matching std's behaviour on Windows.
//! - [`is_aarch64_feature_detected_full!`] reads the IPFP + registry
//!   cache (when the `registry` Cargo feature is on). First call opens
//!   the registry key; subsequent calls hit the cached bitset. The
//!   runtime gate ([`set_registry_enabled`]) defaults to **on** when
//!   the Cargo feature is enabled — pass `false` to suppress for
//!   sandboxed processes.
//!
//! On non-Windows aarch64 and on non-aarch64, the two macros are
//! identical (no registry layer to differ on).
//!
//! ## Quick reference
//!
//! ```no_run
//! use winarm_cpufeatures::{is_aarch64_feature_detected, is_aarch64_feature_detected_full};
//!
//! // `rdm` works because it's IPFP-derived (DP||LSE → RDM).
//! if is_aarch64_feature_detected!("rdm") { /* Rounding Doubling Multiply Accumulate */ }
//! if is_aarch64_feature_detected!("sve") { /* SVE kernel */ }
//! if is_aarch64_feature_detected!("aes") { /* AES instructions */ }
//!
//! // Registry-decoded names need _full! on Windows aarch64. Identical
//! // to the fast macro on every other target.
//! if is_aarch64_feature_detected_full!("paca") { /* Pointer Auth address-key */ }
//! ```
//!
//! ## Comparison to other crates
//!
//! - [`cpufeatures`](https://crates.io/crates/cpufeatures) (RustCrypto) is
//!   the widely-used cross-platform feature detector but explicitly punts
//!   on Windows-ARM and only exposes `aes`/`sha2`/`sha3` on aarch64. Use
//!   both crates side-by-side: `cpufeatures` for x86 + Linux/macOS aarch64;
//!   this crate for Windows-on-ARM.
//! - [`aarch64-cpu`](https://crates.io/crates/aarch64-cpu) is a bare-metal
//!   register-access crate for kernel/embedded code. Different domain.

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]
// Opt into the stdarch_aarch64_feature_detection gate when the
// `nightly-stdarch` feature is enabled, so we can delegate the 32 unstable
// stdarch feature names on non-Windows aarch64 targets. The `target_arch`
// predicate guards against the gate being unrecognized on non-aarch64
// nightly builds. Requires nightly rustc.
#![cfg_attr(
    all(feature = "nightly-stdarch", target_arch = "aarch64"),
    feature(stdarch_aarch64_feature_detection)
)]

mod cache;
mod features;

#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
mod windows;

pub use cache::{Features, is_detected, is_detected_full, set_registry_enabled};
pub use features::Feature;

// ─── Macro dispatch — per-target ─────────────────────────────────────────
//
// On Windows aarch64, each macro has 73 specific-literal arms that
// dispatch to `is_detected` / `is_detected_full` (which read the
// IPFP / IPFP+registry caches). Adding a new feature requires
// updating `features.rs::features!` AND adding arms in BOTH macros.
//
// On non-Windows aarch64, both macros are a one-arm `:tt` passthrough
// to `::std::arch::is_aarch64_feature_detected!`. Std validates names
// and dispatches; future stdarch additions Just Work without any
// crate update.
//
// On non-aarch64, both macros enumerate the same 73 specific-literal
// arms returning `false`, plus a catch-all `compile_error!` for unknown
// names. Catches typos at build time even on platforms where there's
// no hardware to actually detect.

/// Cheap detection macro.
///
/// **On Windows ARM64**, reads the IPFP-only cache. Names that
/// Microsoft has never exposed via `IsProcessorFeaturePresent`
/// (Registry-classified — `paca`, `bti`, `dpb`, `flagm`, `mte`, `fhm`,
/// `fcma`, `frintts`, `sm4`, etc.) silently return `false` — matching
/// std's behaviour. Use [`is_aarch64_feature_detected_full!`] (or
/// [`Features::current_full`]) to actually detect those.
///
/// **On non-Windows aarch64**, expands directly to
/// `std::arch::is_aarch64_feature_detected!($name)`. Any name std
/// accepts also compiles here, including future stdarch additions.
///
/// **On non-aarch64**, returns `false` for every documented name (and
/// `compile_error!` for typos).
///
/// ```no_run
/// if winarm_cpufeatures::is_aarch64_feature_detected!("aes") {
///     // AES instructions
/// }
/// ```
///
/// [`Features::current_full`]: crate::Features::current_full
#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
#[macro_export]
macro_rules! is_aarch64_feature_detected {
    ("asimd") => {
        $crate::is_detected($crate::Feature::Asimd)
    };
    ("fp") => {
        $crate::is_detected($crate::Feature::Fp)
    };
    ("fp16") => {
        $crate::is_detected($crate::Feature::Fp16)
    };
    ("fhm") => {
        $crate::is_detected($crate::Feature::Fhm)
    };
    ("fcma") => {
        $crate::is_detected($crate::Feature::Fcma)
    };
    ("bf16") => {
        $crate::is_detected($crate::Feature::Bf16)
    };
    ("i8mm") => {
        $crate::is_detected($crate::Feature::I8mm)
    };
    ("jsconv") => {
        $crate::is_detected($crate::Feature::JsConv)
    };
    ("frintts") => {
        $crate::is_detected($crate::Feature::FrintTs)
    };
    ("rdm") => {
        $crate::is_detected($crate::Feature::Rdm)
    };
    ("dotprod") => {
        $crate::is_detected($crate::Feature::Dotprod)
    };
    ("aes") => {
        $crate::is_detected($crate::Feature::Aes)
    };
    ("pmull") => {
        $crate::is_detected($crate::Feature::Pmull)
    };
    ("sha2") => {
        $crate::is_detected($crate::Feature::Sha2)
    };
    ("sha3") => {
        $crate::is_detected($crate::Feature::Sha3)
    };
    ("sm4") => {
        $crate::is_detected($crate::Feature::Sm4)
    };
    ("crc") => {
        $crate::is_detected($crate::Feature::Crc)
    };
    ("lse") => {
        $crate::is_detected($crate::Feature::Lse)
    };
    ("lse2") => {
        $crate::is_detected($crate::Feature::Lse2)
    };
    ("lse128") => {
        $crate::is_detected($crate::Feature::Lse128)
    };
    ("rcpc") => {
        $crate::is_detected($crate::Feature::Rcpc)
    };
    ("rcpc2") => {
        $crate::is_detected($crate::Feature::Rcpc2)
    };
    ("rcpc3") => {
        $crate::is_detected($crate::Feature::Rcpc3)
    };
    ("paca") => {
        $crate::is_detected($crate::Feature::Paca)
    };
    ("pacg") => {
        $crate::is_detected($crate::Feature::Pacg)
    };
    ("pauth-lr") => {
        $crate::is_detected($crate::Feature::PauthLr)
    };
    ("bti") => {
        $crate::is_detected($crate::Feature::Bti)
    };
    ("dpb") => {
        $crate::is_detected($crate::Feature::Dpb)
    };
    ("dpb2") => {
        $crate::is_detected($crate::Feature::Dpb2)
    };
    ("mte") => {
        $crate::is_detected($crate::Feature::Mte)
    };
    ("mops") => {
        $crate::is_detected($crate::Feature::Mops)
    };
    ("dit") => {
        $crate::is_detected($crate::Feature::Dit)
    };
    ("sb") => {
        $crate::is_detected($crate::Feature::Sb)
    };
    ("ssbs") => {
        $crate::is_detected($crate::Feature::Ssbs)
    };
    ("flagm") => {
        $crate::is_detected($crate::Feature::FlagM)
    };
    ("flagm2") => {
        $crate::is_detected($crate::Feature::FlagM2)
    };
    ("rand") => {
        $crate::is_detected($crate::Feature::Rand)
    };
    ("tme") => {
        $crate::is_detected($crate::Feature::Tme)
    };
    ("ecv") => {
        $crate::is_detected($crate::Feature::Ecv)
    };
    ("cssc") => {
        $crate::is_detected($crate::Feature::Cssc)
    };
    ("wfxt") => {
        $crate::is_detected($crate::Feature::WfxT)
    };
    ("hbc") => {
        $crate::is_detected($crate::Feature::Hbc)
    };
    ("lut") => {
        $crate::is_detected($crate::Feature::Lut)
    };
    ("faminmax") => {
        $crate::is_detected($crate::Feature::FaMinMax)
    };
    ("fp8") => {
        $crate::is_detected($crate::Feature::Fp8)
    };
    ("fp8dot2") => {
        $crate::is_detected($crate::Feature::Fp8Dot2)
    };
    ("fp8dot4") => {
        $crate::is_detected($crate::Feature::Fp8Dot4)
    };
    ("fp8fma") => {
        $crate::is_detected($crate::Feature::Fp8Fma)
    };
    ("fpmr") => {
        $crate::is_detected($crate::Feature::Fpmr)
    };
    ("sve") => {
        $crate::is_detected($crate::Feature::Sve)
    };
    ("sve2") => {
        $crate::is_detected($crate::Feature::Sve2)
    };
    ("sve2p1") => {
        $crate::is_detected($crate::Feature::Sve2p1)
    };
    ("sve2-aes") => {
        $crate::is_detected($crate::Feature::Sve2Aes)
    };
    ("sve2-bitperm") => {
        $crate::is_detected($crate::Feature::Sve2Bitperm)
    };
    ("sve2-sha3") => {
        $crate::is_detected($crate::Feature::Sve2Sha3)
    };
    ("sve2-sm4") => {
        $crate::is_detected($crate::Feature::Sve2Sm4)
    };
    ("sve-b16b16") => {
        $crate::is_detected($crate::Feature::SveB16b16)
    };
    ("f32mm") => {
        $crate::is_detected($crate::Feature::F32mm)
    };
    ("f64mm") => {
        $crate::is_detected($crate::Feature::F64mm)
    };
    ("sme") => {
        $crate::is_detected($crate::Feature::Sme)
    };
    ("sme2") => {
        $crate::is_detected($crate::Feature::Sme2)
    };
    ("sme2p1") => {
        $crate::is_detected($crate::Feature::Sme2p1)
    };
    ("sme-b16b16") => {
        $crate::is_detected($crate::Feature::SmeB16b16)
    };
    ("sme-f16f16") => {
        $crate::is_detected($crate::Feature::SmeF16f16)
    };
    ("sme-f64f64") => {
        $crate::is_detected($crate::Feature::SmeF64f64)
    };
    ("sme-f8f16") => {
        $crate::is_detected($crate::Feature::SmeF8f16)
    };
    ("sme-f8f32") => {
        $crate::is_detected($crate::Feature::SmeF8f32)
    };
    ("sme-fa64") => {
        $crate::is_detected($crate::Feature::SmeFa64)
    };
    ("sme-i16i64") => {
        $crate::is_detected($crate::Feature::SmeI16i64)
    };
    ("sme-lutv2") => {
        $crate::is_detected($crate::Feature::SmeLutv2)
    };
    ("ssve-fp8dot2") => {
        $crate::is_detected($crate::Feature::SsveFp8Dot2)
    };
    ("ssve-fp8dot4") => {
        $crate::is_detected($crate::Feature::SsveFp8Dot4)
    };
    ("ssve-fp8fma") => {
        $crate::is_detected($crate::Feature::SsveFp8Fma)
    };
    // Unknown name on Windows aarch64 — winarm doesn't know about it.
    // (On non-Windows aarch64 std would handle this; here we error so
    // the user knows winarm needs updating to track new names.)
    ($other:literal) => {
        ::core::compile_error!(::core::concat!(
            "unknown aarch64 feature name '",
            $other,
            "': winarm-cpufeatures does not track this name on Windows aarch64. ",
            "If std accepts it on other targets, please file an issue to add it.",
        ))
    };
}

#[cfg(all(target_arch = "aarch64", not(target_os = "windows")))]
#[macro_export]
macro_rules! is_aarch64_feature_detected {
    ($name:tt) => {
        ::std::arch::is_aarch64_feature_detected!($name)
    };
}

#[cfg(not(target_arch = "aarch64"))]
#[macro_export]
macro_rules! is_aarch64_feature_detected {
    ("asimd") => {
        false
    };
    ("fp") => {
        false
    };
    ("fp16") => {
        false
    };
    ("fhm") => {
        false
    };
    ("fcma") => {
        false
    };
    ("bf16") => {
        false
    };
    ("i8mm") => {
        false
    };
    ("jsconv") => {
        false
    };
    ("frintts") => {
        false
    };
    ("rdm") => {
        false
    };
    ("dotprod") => {
        false
    };
    ("aes") => {
        false
    };
    ("pmull") => {
        false
    };
    ("sha2") => {
        false
    };
    ("sha3") => {
        false
    };
    ("sm4") => {
        false
    };
    ("crc") => {
        false
    };
    ("lse") => {
        false
    };
    ("lse2") => {
        false
    };
    ("lse128") => {
        false
    };
    ("rcpc") => {
        false
    };
    ("rcpc2") => {
        false
    };
    ("rcpc3") => {
        false
    };
    ("paca") => {
        false
    };
    ("pacg") => {
        false
    };
    ("pauth-lr") => {
        false
    };
    ("bti") => {
        false
    };
    ("dpb") => {
        false
    };
    ("dpb2") => {
        false
    };
    ("mte") => {
        false
    };
    ("mops") => {
        false
    };
    ("dit") => {
        false
    };
    ("sb") => {
        false
    };
    ("ssbs") => {
        false
    };
    ("flagm") => {
        false
    };
    ("flagm2") => {
        false
    };
    ("rand") => {
        false
    };
    ("tme") => {
        false
    };
    ("ecv") => {
        false
    };
    ("cssc") => {
        false
    };
    ("wfxt") => {
        false
    };
    ("hbc") => {
        false
    };
    ("lut") => {
        false
    };
    ("faminmax") => {
        false
    };
    ("fp8") => {
        false
    };
    ("fp8dot2") => {
        false
    };
    ("fp8dot4") => {
        false
    };
    ("fp8fma") => {
        false
    };
    ("fpmr") => {
        false
    };
    ("sve") => {
        false
    };
    ("sve2") => {
        false
    };
    ("sve2p1") => {
        false
    };
    ("sve2-aes") => {
        false
    };
    ("sve2-bitperm") => {
        false
    };
    ("sve2-sha3") => {
        false
    };
    ("sve2-sm4") => {
        false
    };
    ("sve-b16b16") => {
        false
    };
    ("f32mm") => {
        false
    };
    ("f64mm") => {
        false
    };
    ("sme") => {
        false
    };
    ("sme2") => {
        false
    };
    ("sme2p1") => {
        false
    };
    ("sme-b16b16") => {
        false
    };
    ("sme-f16f16") => {
        false
    };
    ("sme-f64f64") => {
        false
    };
    ("sme-f8f16") => {
        false
    };
    ("sme-f8f32") => {
        false
    };
    ("sme-fa64") => {
        false
    };
    ("sme-i16i64") => {
        false
    };
    ("sme-lutv2") => {
        false
    };
    ("ssve-fp8dot2") => {
        false
    };
    ("ssve-fp8dot4") => {
        false
    };
    ("ssve-fp8fma") => {
        false
    };
    ($other:literal) => {
        ::core::compile_error!(::core::concat!(
            "unknown aarch64 feature name '",
            $other,
            "': winarm-cpufeatures does not track this name. ",
            "If std accepts it on aarch64 targets, please file an issue to add it.",
        ))
    };
}

/// Full detection macro.
///
/// **On Windows ARM64** with the `registry` Cargo feature enabled,
/// reads the IPFP + registry cache — covers the ~30 stdarch names
/// `IsProcessorFeaturePresent` can't see. Without the `registry`
/// feature (or with [`set_registry_enabled(false)`] called at startup),
/// behaves identically to [`is_aarch64_feature_detected!`].
///
/// **On every other target**, behaves identically to
/// [`is_aarch64_feature_detected!`].
///
/// ```no_run
/// if winarm_cpufeatures::is_aarch64_feature_detected_full!("paca") {
///     // Pointer Auth address-key
/// }
/// ```
///
/// [`set_registry_enabled(false)`]: set_registry_enabled
#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
#[macro_export]
macro_rules! is_aarch64_feature_detected_full {
    ("asimd") => {
        $crate::is_detected_full($crate::Feature::Asimd)
    };
    ("fp") => {
        $crate::is_detected_full($crate::Feature::Fp)
    };
    ("fp16") => {
        $crate::is_detected_full($crate::Feature::Fp16)
    };
    ("fhm") => {
        $crate::is_detected_full($crate::Feature::Fhm)
    };
    ("fcma") => {
        $crate::is_detected_full($crate::Feature::Fcma)
    };
    ("bf16") => {
        $crate::is_detected_full($crate::Feature::Bf16)
    };
    ("i8mm") => {
        $crate::is_detected_full($crate::Feature::I8mm)
    };
    ("jsconv") => {
        $crate::is_detected_full($crate::Feature::JsConv)
    };
    ("frintts") => {
        $crate::is_detected_full($crate::Feature::FrintTs)
    };
    ("rdm") => {
        $crate::is_detected_full($crate::Feature::Rdm)
    };
    ("dotprod") => {
        $crate::is_detected_full($crate::Feature::Dotprod)
    };
    ("aes") => {
        $crate::is_detected_full($crate::Feature::Aes)
    };
    ("pmull") => {
        $crate::is_detected_full($crate::Feature::Pmull)
    };
    ("sha2") => {
        $crate::is_detected_full($crate::Feature::Sha2)
    };
    ("sha3") => {
        $crate::is_detected_full($crate::Feature::Sha3)
    };
    ("sm4") => {
        $crate::is_detected_full($crate::Feature::Sm4)
    };
    ("crc") => {
        $crate::is_detected_full($crate::Feature::Crc)
    };
    ("lse") => {
        $crate::is_detected_full($crate::Feature::Lse)
    };
    ("lse2") => {
        $crate::is_detected_full($crate::Feature::Lse2)
    };
    ("lse128") => {
        $crate::is_detected_full($crate::Feature::Lse128)
    };
    ("rcpc") => {
        $crate::is_detected_full($crate::Feature::Rcpc)
    };
    ("rcpc2") => {
        $crate::is_detected_full($crate::Feature::Rcpc2)
    };
    ("rcpc3") => {
        $crate::is_detected_full($crate::Feature::Rcpc3)
    };
    ("paca") => {
        $crate::is_detected_full($crate::Feature::Paca)
    };
    ("pacg") => {
        $crate::is_detected_full($crate::Feature::Pacg)
    };
    ("pauth-lr") => {
        $crate::is_detected_full($crate::Feature::PauthLr)
    };
    ("bti") => {
        $crate::is_detected_full($crate::Feature::Bti)
    };
    ("dpb") => {
        $crate::is_detected_full($crate::Feature::Dpb)
    };
    ("dpb2") => {
        $crate::is_detected_full($crate::Feature::Dpb2)
    };
    ("mte") => {
        $crate::is_detected_full($crate::Feature::Mte)
    };
    ("mops") => {
        $crate::is_detected_full($crate::Feature::Mops)
    };
    ("dit") => {
        $crate::is_detected_full($crate::Feature::Dit)
    };
    ("sb") => {
        $crate::is_detected_full($crate::Feature::Sb)
    };
    ("ssbs") => {
        $crate::is_detected_full($crate::Feature::Ssbs)
    };
    ("flagm") => {
        $crate::is_detected_full($crate::Feature::FlagM)
    };
    ("flagm2") => {
        $crate::is_detected_full($crate::Feature::FlagM2)
    };
    ("rand") => {
        $crate::is_detected_full($crate::Feature::Rand)
    };
    ("tme") => {
        $crate::is_detected_full($crate::Feature::Tme)
    };
    ("ecv") => {
        $crate::is_detected_full($crate::Feature::Ecv)
    };
    ("cssc") => {
        $crate::is_detected_full($crate::Feature::Cssc)
    };
    ("wfxt") => {
        $crate::is_detected_full($crate::Feature::WfxT)
    };
    ("hbc") => {
        $crate::is_detected_full($crate::Feature::Hbc)
    };
    ("lut") => {
        $crate::is_detected_full($crate::Feature::Lut)
    };
    ("faminmax") => {
        $crate::is_detected_full($crate::Feature::FaMinMax)
    };
    ("fp8") => {
        $crate::is_detected_full($crate::Feature::Fp8)
    };
    ("fp8dot2") => {
        $crate::is_detected_full($crate::Feature::Fp8Dot2)
    };
    ("fp8dot4") => {
        $crate::is_detected_full($crate::Feature::Fp8Dot4)
    };
    ("fp8fma") => {
        $crate::is_detected_full($crate::Feature::Fp8Fma)
    };
    ("fpmr") => {
        $crate::is_detected_full($crate::Feature::Fpmr)
    };
    ("sve") => {
        $crate::is_detected_full($crate::Feature::Sve)
    };
    ("sve2") => {
        $crate::is_detected_full($crate::Feature::Sve2)
    };
    ("sve2p1") => {
        $crate::is_detected_full($crate::Feature::Sve2p1)
    };
    ("sve2-aes") => {
        $crate::is_detected_full($crate::Feature::Sve2Aes)
    };
    ("sve2-bitperm") => {
        $crate::is_detected_full($crate::Feature::Sve2Bitperm)
    };
    ("sve2-sha3") => {
        $crate::is_detected_full($crate::Feature::Sve2Sha3)
    };
    ("sve2-sm4") => {
        $crate::is_detected_full($crate::Feature::Sve2Sm4)
    };
    ("sve-b16b16") => {
        $crate::is_detected_full($crate::Feature::SveB16b16)
    };
    ("f32mm") => {
        $crate::is_detected_full($crate::Feature::F32mm)
    };
    ("f64mm") => {
        $crate::is_detected_full($crate::Feature::F64mm)
    };
    ("sme") => {
        $crate::is_detected_full($crate::Feature::Sme)
    };
    ("sme2") => {
        $crate::is_detected_full($crate::Feature::Sme2)
    };
    ("sme2p1") => {
        $crate::is_detected_full($crate::Feature::Sme2p1)
    };
    ("sme-b16b16") => {
        $crate::is_detected_full($crate::Feature::SmeB16b16)
    };
    ("sme-f16f16") => {
        $crate::is_detected_full($crate::Feature::SmeF16f16)
    };
    ("sme-f64f64") => {
        $crate::is_detected_full($crate::Feature::SmeF64f64)
    };
    ("sme-f8f16") => {
        $crate::is_detected_full($crate::Feature::SmeF8f16)
    };
    ("sme-f8f32") => {
        $crate::is_detected_full($crate::Feature::SmeF8f32)
    };
    ("sme-fa64") => {
        $crate::is_detected_full($crate::Feature::SmeFa64)
    };
    ("sme-i16i64") => {
        $crate::is_detected_full($crate::Feature::SmeI16i64)
    };
    ("sme-lutv2") => {
        $crate::is_detected_full($crate::Feature::SmeLutv2)
    };
    ("ssve-fp8dot2") => {
        $crate::is_detected_full($crate::Feature::SsveFp8Dot2)
    };
    ("ssve-fp8dot4") => {
        $crate::is_detected_full($crate::Feature::SsveFp8Dot4)
    };
    ("ssve-fp8fma") => {
        $crate::is_detected_full($crate::Feature::SsveFp8Fma)
    };
    ($other:literal) => {
        ::core::compile_error!(::core::concat!(
            "unknown aarch64 feature name '",
            $other,
            "': winarm-cpufeatures does not track this name on Windows aarch64. ",
            "If std accepts it on other targets, please file an issue to add it.",
        ))
    };
}

#[cfg(all(target_arch = "aarch64", not(target_os = "windows")))]
#[macro_export]
macro_rules! is_aarch64_feature_detected_full {
    ($name:tt) => {
        ::std::arch::is_aarch64_feature_detected!($name)
    };
}

#[cfg(not(target_arch = "aarch64"))]
#[macro_export]
macro_rules! is_aarch64_feature_detected_full {
    ("asimd") => {
        false
    };
    ("fp") => {
        false
    };
    ("fp16") => {
        false
    };
    ("fhm") => {
        false
    };
    ("fcma") => {
        false
    };
    ("bf16") => {
        false
    };
    ("i8mm") => {
        false
    };
    ("jsconv") => {
        false
    };
    ("frintts") => {
        false
    };
    ("rdm") => {
        false
    };
    ("dotprod") => {
        false
    };
    ("aes") => {
        false
    };
    ("pmull") => {
        false
    };
    ("sha2") => {
        false
    };
    ("sha3") => {
        false
    };
    ("sm4") => {
        false
    };
    ("crc") => {
        false
    };
    ("lse") => {
        false
    };
    ("lse2") => {
        false
    };
    ("lse128") => {
        false
    };
    ("rcpc") => {
        false
    };
    ("rcpc2") => {
        false
    };
    ("rcpc3") => {
        false
    };
    ("paca") => {
        false
    };
    ("pacg") => {
        false
    };
    ("pauth-lr") => {
        false
    };
    ("bti") => {
        false
    };
    ("dpb") => {
        false
    };
    ("dpb2") => {
        false
    };
    ("mte") => {
        false
    };
    ("mops") => {
        false
    };
    ("dit") => {
        false
    };
    ("sb") => {
        false
    };
    ("ssbs") => {
        false
    };
    ("flagm") => {
        false
    };
    ("flagm2") => {
        false
    };
    ("rand") => {
        false
    };
    ("tme") => {
        false
    };
    ("ecv") => {
        false
    };
    ("cssc") => {
        false
    };
    ("wfxt") => {
        false
    };
    ("hbc") => {
        false
    };
    ("lut") => {
        false
    };
    ("faminmax") => {
        false
    };
    ("fp8") => {
        false
    };
    ("fp8dot2") => {
        false
    };
    ("fp8dot4") => {
        false
    };
    ("fp8fma") => {
        false
    };
    ("fpmr") => {
        false
    };
    ("sve") => {
        false
    };
    ("sve2") => {
        false
    };
    ("sve2p1") => {
        false
    };
    ("sve2-aes") => {
        false
    };
    ("sve2-bitperm") => {
        false
    };
    ("sve2-sha3") => {
        false
    };
    ("sve2-sm4") => {
        false
    };
    ("sve-b16b16") => {
        false
    };
    ("f32mm") => {
        false
    };
    ("f64mm") => {
        false
    };
    ("sme") => {
        false
    };
    ("sme2") => {
        false
    };
    ("sme2p1") => {
        false
    };
    ("sme-b16b16") => {
        false
    };
    ("sme-f16f16") => {
        false
    };
    ("sme-f64f64") => {
        false
    };
    ("sme-f8f16") => {
        false
    };
    ("sme-f8f32") => {
        false
    };
    ("sme-fa64") => {
        false
    };
    ("sme-i16i64") => {
        false
    };
    ("sme-lutv2") => {
        false
    };
    ("ssve-fp8dot2") => {
        false
    };
    ("ssve-fp8dot4") => {
        false
    };
    ("ssve-fp8fma") => {
        false
    };
    ($other:literal) => {
        ::core::compile_error!(::core::concat!(
            "unknown aarch64 feature name '",
            $other,
            "': winarm-cpufeatures does not track this name. ",
            "If std accepts it on aarch64 targets, please file an issue to add it.",
        ))
    };
}
