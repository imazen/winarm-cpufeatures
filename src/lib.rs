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
//! ## Two layers, the second behind a feature flag
//!
//! 1. **Always-on (the IPFP layer).** Wires every `PF_ARM_*` constant from
//!    SDK 26100. Plus one architectural inference: `rdm` is set whenever
//!    `PF_ARM_V81_ATOMIC` (LSE) or `PF_ARM_V82_DP` (DotProd) is — the same
//!    rule .NET 10 ships in production, citing ARM ARM K.a §D17.2.91 (see
//!    [`dotnet/runtime#109493`](https://github.com/dotnet/runtime/pull/109493)).
//!    Each probe is one syscall returning a `BOOL`; the whole pass cached
//!    after first call.
//!
//! 2. **Double opt-in (`registry` Cargo feature + runtime authorisation).**
//!    Adds `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0\CP <hex>`
//!    reads that decode the cached `ID_AA64*_EL1` snapshots Windows
//!    publishes. Covers ~30 stdarch names IPFP can't reach: `fhm`, `fcma`,
//!    `frintts`, `paca`/`pacg`, `bti`, `dpb`/`dpb2`, `mte`, `mops`, `dit`,
//!    `sb`, `ssbs`, `flagm`/`flagm2`, `rand`, `cssc`, `wfxt`, `hbc`,
//!    `sm4`, `rcpc2`/`rcpc3`, `pauth_lr`, `lse128`, etc. One
//!    `RegOpenKeyExW` + a handful of `RegGetValueW` calls on first probe.
//!
//!    Cargo features union across the dependency graph — if any
//!    transitive crate enables `registry`, the FFI gets linked into your
//!    binary. The runtime gate ([`set_registry_enabled`]) is the second
//!    tier: the registry is consulted only when the application
//!    explicitly authorises it. Without that call, the registry layer
//!    is compiled-but-dormant.
//!
//! Default features: empty. Default runtime: registry off. The
//! IPFP-only-with-RDM-derivation mode matches what .NET 10,
//! pytorch/cpuinfo, and Microsoft's own Windows runtime ship.
//!
//! ## Two macros, two cost tiers
//!
//! | Macro              | Backend on Windows ARM           | Compile error if feature… |
//! |--------------------|----------------------------------|---------------------------|
//! | [`detected!`]      | IPFP only (always cheap)         | needs the registry layer  |
//! | [`detected_full!`] | IPFP + (with `registry`) CP keys | never                     |
//!
//! Without the `registry` feature, [`detected_full!`] is identical to
//! [`detected!`]. With it, [`detected_full!`] additionally consults the
//! registry-decoded bits.
//!
//! Each macro maintains its own cache. Probes are idempotent so racing
//! initializers are fine; both caches use `Ordering::Relaxed` atomic loads.
//!
//! On every non-Windows-ARM platform, both macros expand to
//! `std::arch::is_aarch64_feature_detected!` directly.
//!
//! ## Quick reference
//!
//! ```no_run
//! use winarm_cpufeatures::{detected, detected_full, set_registry_enabled};
//!
//! // Always-on. `rdm` works because it's IPFP-derived (DP||LSE → RDM).
//! if detected!("rdm") { /* Rounding Doubling Multiply Accumulate */ }
//! if detected!("sve") { /* SVE kernel */ }
//! if detected!("aes") { /* AES instructions */ }
//!
//! // Authorise registry layer at runtime (compile-time `registry` feature
//! // must also be enabled, or this is a no-op). Best done once at startup,
//! // before any `detected_full!` query.
//! set_registry_enabled(true);
//!
//! if detected_full!("paca") { /* Pointer Auth address-key */ }
//!
//! // Compile error: "paca" is registry-only.
//! // let _ = winarm_cpufeatures::detected!("paca");
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
mod detect;
mod features;

#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
mod windows;

pub use cache::{Features, is_detected, is_detected_full, set_registry_enabled};
pub use features::Feature;

// ─── Macro dispatch — one arm per feature name ───────────────────────────
//
// Both macros use direct `macro_rules!` arm dispatch instead of a const
// lookup table. Each `detected!`/`detected_full!` call site expands to
// exactly one expression — no const-eval, no `panic!`-based assertions,
// no string-compare loop. This keeps downstream compile time flat in the
// number of call sites.
//
// Source of truth for the (name, variant, detection-method) triples is
// `features.rs::features!`. If you add a feature there, add an arm here
// in BOTH macros — Registry-classified names get a `compile_error!`
// arm in `detected!` pointing at `detected_full!`. The smoke tests
// cover every name through both macros, so missing arms surface
// immediately.

/// Cheap detection — uses `IsProcessorFeaturePresent` only on Windows ARM64.
///
/// **Compile error** if `$name` is one of the ~33 features Microsoft has
/// never exposed via `IsProcessorFeaturePresent` (e.g. `paca`, `bti`,
/// `dpb`, `flagm`, `mte`). Those require registry detection — use
/// [`detected_full!`].
///
/// **Compile error** if `$name` is not a known aarch64 feature name.
///
/// On non-Windows-ARM targets, this consults the per-process cache that
/// was populated by `std::arch::is_aarch64_feature_detected!` on first
/// access.
///
/// ```no_run
/// if winarm_cpufeatures::detected!("sve") {
///     // SVE kernel
/// }
/// ```
#[macro_export]
macro_rules! detected {
    // ── Ipfp / Both — direct dispatch to `is_detected` ────────────────────
    ("asimd") => {
        $crate::is_detected($crate::Feature::Asimd)
    };
    ("fp") => {
        $crate::is_detected($crate::Feature::Fp)
    };
    ("fp16") => {
        $crate::is_detected($crate::Feature::Fp16)
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
    ("crc") => {
        $crate::is_detected($crate::Feature::Crc)
    };
    ("lse") => {
        $crate::is_detected($crate::Feature::Lse)
    };
    ("lse2") => {
        $crate::is_detected($crate::Feature::Lse2)
    };
    ("rcpc") => {
        $crate::is_detected($crate::Feature::Rcpc)
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
    ("sve2_aes") => {
        $crate::is_detected($crate::Feature::Sve2Aes)
    };
    ("sve2_bitperm") => {
        $crate::is_detected($crate::Feature::Sve2Bitperm)
    };
    ("sve2_sha3") => {
        $crate::is_detected($crate::Feature::Sve2Sha3)
    };
    ("sve2_sm4") => {
        $crate::is_detected($crate::Feature::Sve2Sm4)
    };
    ("sve_b16b16") => {
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
    ("sme_b16b16") => {
        $crate::is_detected($crate::Feature::SmeB16b16)
    };
    ("sme_f16f16") => {
        $crate::is_detected($crate::Feature::SmeF16f16)
    };
    ("sme_f64f64") => {
        $crate::is_detected($crate::Feature::SmeF64f64)
    };
    ("sme_f8f16") => {
        $crate::is_detected($crate::Feature::SmeF8f16)
    };
    ("sme_f8f32") => {
        $crate::is_detected($crate::Feature::SmeF8f32)
    };
    ("sme_fa64") => {
        $crate::is_detected($crate::Feature::SmeFa64)
    };
    ("sme_i16i64") => {
        $crate::is_detected($crate::Feature::SmeI16i64)
    };
    ("sme_lutv2") => {
        $crate::is_detected($crate::Feature::SmeLutv2)
    };
    ("ssve_fp8dot2") => {
        $crate::is_detected($crate::Feature::SsveFp8Dot2)
    };
    ("ssve_fp8dot4") => {
        $crate::is_detected($crate::Feature::SsveFp8Dot4)
    };
    ("ssve_fp8fma") => {
        $crate::is_detected($crate::Feature::SsveFp8Fma)
    };
    // ── Registry-only — compile error pointing at detected_full! ─────────
    ("fhm") => {
        ::core::compile_error!(::core::concat!("feature 'fhm' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("fcma") => {
        ::core::compile_error!(::core::concat!("feature 'fcma' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("frintts") => {
        ::core::compile_error!(::core::concat!("feature 'frintts' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("sm4") => {
        ::core::compile_error!(::core::concat!("feature 'sm4' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("lse128") => {
        ::core::compile_error!(::core::concat!("feature 'lse128' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("rcpc2") => {
        ::core::compile_error!(::core::concat!("feature 'rcpc2' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("rcpc3") => {
        ::core::compile_error!(::core::concat!("feature 'rcpc3' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("paca") => {
        ::core::compile_error!(::core::concat!("feature 'paca' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("pacg") => {
        ::core::compile_error!(::core::concat!("feature 'pacg' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("pauth_lr") => {
        ::core::compile_error!(::core::concat!("feature 'pauth_lr' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("bti") => {
        ::core::compile_error!(::core::concat!("feature 'bti' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("dpb") => {
        ::core::compile_error!(::core::concat!("feature 'dpb' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("dpb2") => {
        ::core::compile_error!(::core::concat!("feature 'dpb2' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("mte") => {
        ::core::compile_error!(::core::concat!("feature 'mte' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("mops") => {
        ::core::compile_error!(::core::concat!("feature 'mops' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("dit") => {
        ::core::compile_error!(::core::concat!("feature 'dit' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("sb") => {
        ::core::compile_error!(::core::concat!("feature 'sb' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("ssbs") => {
        ::core::compile_error!(::core::concat!("feature 'ssbs' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("flagm") => {
        ::core::compile_error!(::core::concat!("feature 'flagm' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("flagm2") => {
        ::core::compile_error!(::core::concat!("feature 'flagm2' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("rand") => {
        ::core::compile_error!(::core::concat!("feature 'rand' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("tme") => {
        ::core::compile_error!(::core::concat!("feature 'tme' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("ecv") => {
        ::core::compile_error!(::core::concat!("feature 'ecv' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("cssc") => {
        ::core::compile_error!(::core::concat!("feature 'cssc' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("wfxt") => {
        ::core::compile_error!(::core::concat!("feature 'wfxt' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("hbc") => {
        ::core::compile_error!(::core::concat!("feature 'hbc' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("lut") => {
        ::core::compile_error!(::core::concat!("feature 'lut' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("faminmax") => {
        ::core::compile_error!(::core::concat!("feature 'faminmax' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("fp8") => {
        ::core::compile_error!(::core::concat!("feature 'fp8' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("fp8dot2") => {
        ::core::compile_error!(::core::concat!("feature 'fp8dot2' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("fp8dot4") => {
        ::core::compile_error!(::core::concat!("feature 'fp8dot4' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("fp8fma") => {
        ::core::compile_error!(::core::concat!("feature 'fp8fma' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    ("fpmr") => {
        ::core::compile_error!(::core::concat!("feature 'fpmr' requires registry detection — use winarm_cpufeatures::detected_full!() instead"))
    };
    // ── Catch-all — unknown feature name ─────────────────────────────────
    ($other:literal) => {
        ::core::compile_error!(::core::concat!(
            "unknown aarch64 feature name: '",
            $other,
            "'",
        ))
    };
}

/// Full detection — uses `IsProcessorFeaturePresent` plus, when the
/// `registry` Cargo feature is enabled and [`set_registry_enabled`] has
/// been called with `true`, `HKLM\…\CentralProcessor\0\CP <hex>` registry
/// reads on Windows ARM64. Accepts every aarch64 feature name.
///
/// First call from a process triggers one registry key open + ~10 value
/// reads. Subsequent calls hit the cached bitset.
///
/// **Compile error** if `$name` is not a known aarch64 feature name.
///
/// On non-Windows-ARM targets, this consults the per-process cache that
/// was populated by `std::arch::is_aarch64_feature_detected!` on first
/// access.
///
/// ```no_run
/// if winarm_cpufeatures::detected_full!("rdm") {
///     // Rounding Doubling Multiply Accumulate
/// }
/// ```
#[macro_export]
macro_rules! detected_full {
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
    ("pauth_lr") => {
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
    ("sve2_aes") => {
        $crate::is_detected_full($crate::Feature::Sve2Aes)
    };
    ("sve2_bitperm") => {
        $crate::is_detected_full($crate::Feature::Sve2Bitperm)
    };
    ("sve2_sha3") => {
        $crate::is_detected_full($crate::Feature::Sve2Sha3)
    };
    ("sve2_sm4") => {
        $crate::is_detected_full($crate::Feature::Sve2Sm4)
    };
    ("sve_b16b16") => {
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
    ("sme_b16b16") => {
        $crate::is_detected_full($crate::Feature::SmeB16b16)
    };
    ("sme_f16f16") => {
        $crate::is_detected_full($crate::Feature::SmeF16f16)
    };
    ("sme_f64f64") => {
        $crate::is_detected_full($crate::Feature::SmeF64f64)
    };
    ("sme_f8f16") => {
        $crate::is_detected_full($crate::Feature::SmeF8f16)
    };
    ("sme_f8f32") => {
        $crate::is_detected_full($crate::Feature::SmeF8f32)
    };
    ("sme_fa64") => {
        $crate::is_detected_full($crate::Feature::SmeFa64)
    };
    ("sme_i16i64") => {
        $crate::is_detected_full($crate::Feature::SmeI16i64)
    };
    ("sme_lutv2") => {
        $crate::is_detected_full($crate::Feature::SmeLutv2)
    };
    ("ssve_fp8dot2") => {
        $crate::is_detected_full($crate::Feature::SsveFp8Dot2)
    };
    ("ssve_fp8dot4") => {
        $crate::is_detected_full($crate::Feature::SsveFp8Dot4)
    };
    ("ssve_fp8fma") => {
        $crate::is_detected_full($crate::Feature::SsveFp8Fma)
    };
    // ── Catch-all — unknown feature name ─────────────────────────────────
    ($other:literal) => {
        ::core::compile_error!(::core::concat!(
            "unknown aarch64 feature name: '",
            $other,
            "'",
        ))
    };
}
