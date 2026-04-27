//! AArch64 CPU feature detection that fills the Windows-on-ARM gap in
//! [`std::arch::is_aarch64_feature_detected!`].
//!
//! ## Why this exists
//!
//! On `aarch64-pc-windows-msvc` with Rust 1.85, std's
//! `is_aarch64_feature_detected!` is a thin wrapper around
//! `IsProcessorFeaturePresent` (IPFP). Microsoft defines 56 `PF_ARM_*`
//! constants in Windows SDK 10.0.26100.0 but the upstream stdarch backend
//! only wires ~10 of them, and Microsoft has never exposed ~30 stdarch
//! feature names through any `PF_ARM_*` constant at all — including the
//! headline miss `rdm`, which is mandatory on every Windows-on-ARM CPU.
//! [`rust-lang/rust#155856`](https://github.com/rust-lang/rust/pull/155856)
//! closes 8 more once it lands stable; the registry-decoded names need a
//! different mechanism, which this crate provides.
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
//! use winarm_cpufeatures::is_aarch64_feature_detected_fast;
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
//! ## Two query paths
//!
//! - [`is_aarch64_feature_detected_fast!`] — single-call macro for
//!   IPFP-only detection. Names IPFP can't see (Registry-classified)
//!   silently return `false`, matching std's behaviour on Windows.
//! - [`Features::current_full`] — snapshot for full detection. On
//!   Windows ARM64 with the `registry` Cargo feature enabled,
//!   includes registry-decoded features that IPFP can't see. First
//!   call opens the registry key; subsequent calls hit the cached
//!   bitset. The runtime gate ([`set_registry_enabled`]) defaults to
//!   **on** when the Cargo feature is enabled — pass `false` to
//!   suppress for sandboxed processes.
//!
//! On non-Windows aarch64 and on non-aarch64, `Features::current_full`
//! is identical to `Features::current` (no registry layer).
//!
//! ## Quick reference
//!
//! ```no_run
//! use winarm_cpufeatures::{is_aarch64_feature_detected_fast, Features, Feature};
//!
//! // Single-feature checks via macro. `rdm` works because it's
//! // IPFP-derived (DP||LSE → RDM).
//! if is_aarch64_feature_detected_fast!("rdm") { /* Rounding Doubling Multiply Accumulate */ }
//! if is_aarch64_feature_detected_fast!("sve") { /* SVE kernel */ }
//! if is_aarch64_feature_detected_fast!("aes") { /* AES instructions */ }
//!
//! // Registry-decoded names use the full snapshot. One snapshot, then
//! // any number of bit tests — better codegen for multi-feature checks.
//! let cpu = Features::current_full();
//! if cpu.has(Feature::Paca) && cpu.has(Feature::Pacg) { /* PAuth */ }
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
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

mod cache;
mod features;

#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
mod windows;

pub use cache::{Features, is_detected, set_registry_enabled};
pub use features::Feature;

// ─── Macro dispatch — per-target ─────────────────────────────────────────
//
// On Windows aarch64, the macro has 73 specific-literal arms that
// dispatch to `is_detected` (reading the IPFP-only cache). Adding a
// new feature requires updating `features.rs::features!` AND adding
// an arm here.
//
// On non-Windows aarch64, the macro is a pure passthrough to
// `::std::arch::is_aarch64_feature_detected!` — std validates and
// dispatches; new stable names Just Work without crate updates.
//
// On non-aarch64, the macro is a single `:literal` arm accepting any
// string literal and returning `false`. Std's macro doesn't compile
// on non-aarch64, so we can't passthrough; we accept any future name
// silently rather than block cross-platform code on a crate update.
// Cross-platform CI on aarch64 targets catches typos via std's
// validation there.

/// Drop-in single-feature check, same call shape as
/// `std::arch::is_aarch64_feature_detected!`.
///
/// **On Windows ARM64**, reads the IPFP-only cache (one syscall on
/// first probe, one Acquire load and a bit test thereafter). Names
/// Microsoft has never exposed via `IsProcessorFeaturePresent`
/// (Registry-classified — `paca`, `bti`, `dpb`, `flagm`, `mte`, `fhm`,
/// `fcma`, `frintts`, `sm4`, …) silently return `false`, matching
/// std's behaviour. Use [`Features::current_full`] to actually detect
/// those (requires the `registry` Cargo feature).
///
/// **On non-Windows aarch64**, expands directly to
/// `std::arch::is_aarch64_feature_detected!($name)`.
///
/// **On non-aarch64**, accepts any string literal and returns `false`.
/// Std's macro doesn't compile on non-aarch64, so we can't passthrough
/// to validate; cross-platform CI on aarch64 catches typos there.
///
/// ```no_run
/// if winarm_cpufeatures::is_aarch64_feature_detected_fast!("aes") {
///     // AES instructions
/// }
/// ```
///
/// [`Features::current_full`]: crate::Features::current_full
#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
#[macro_export]
macro_rules! is_aarch64_feature_detected_fast {
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
    // Catch-all: defer to std for names we don't track. Std validates
    // and dispatches; future stdarch additions Just Work without any
    // crate update. (Today this is a narrow gap — std doesn't yet
    // wire most PF_ARM_* on Windows — but it's growing, e.g. via
    // rust-lang/rust#155856.)
    ($other:tt) => {
        ::std::arch::is_aarch64_feature_detected!($other)
    };
}

/// Drop-in single-feature check (non-Windows aarch64 cfg).
///
/// On Linux/macOS aarch64 this expands directly to
/// `std::arch::is_aarch64_feature_detected!($name)`. Std handles those
/// targets correctly via HWCAP / sysctl, so this crate adds nothing.
///
/// Unstable feature names (`sme`, `cssc`, `sve2p1`, `pauth-lr`, …)
/// require nightly + the user's own
/// `#![feature(stdarch_aarch64_feature_detection)]` gate — same as
/// calling std directly. On Linux/macOS aarch64 use [`Features::current`]
/// for those names so the unstable gate stays inside this crate.
#[cfg(all(target_arch = "aarch64", not(target_os = "windows")))]
#[macro_export]
macro_rules! is_aarch64_feature_detected_fast {
    ($name:tt) => {
        ::std::arch::is_aarch64_feature_detected!($name)
    };
}

/// Drop-in single-feature check (non-aarch64 cfg).
///
/// On non-aarch64 targets, accepts any string literal and returns
/// `false`. Std's `is_aarch64_feature_detected!` doesn't compile on
/// non-aarch64, so we can't passthrough to validate; we accept any
/// future name silently rather than block cross-platform code on a
/// crate update. Cross-platform CI on aarch64 catches typos there.
#[cfg(not(target_arch = "aarch64"))]
#[macro_export]
macro_rules! is_aarch64_feature_detected_fast {
    ($name:literal) => {{
        const _: &str = $name;
        false
    }};
}
