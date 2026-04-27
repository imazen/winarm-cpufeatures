//! Detection state and per-target dispatch.
//!
//! The detection cache exists only on Windows aarch64 — that's the only
//! target where probe cost matters (IPFP is a syscall per probe; registry
//! reads are file I/O). On non-Windows aarch64, we dispatch directly to
//! `std::arch::is_aarch64_feature_detected!`, which has its own internal
//! HWCAP-based cache; layering our own on top would be redundant. On
//! non-aarch64 targets, every feature reads `false`.

use crate::features::Feature;

/// A snapshot of detected features. Cheap to copy; `has` is a pure bit test.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Features {
    pub(crate) lo: u64,
    pub(crate) hi: u64,
}

impl Features {
    /// The empty feature set (all features absent).
    pub const EMPTY: Self = Self { lo: 0, hi: 0 };

    /// Read the fast detection state.
    ///
    /// On Windows ARM64, populates a cached IPFP probe on first call and
    /// returns the cached snapshot thereafter. On non-Windows aarch64,
    /// builds the snapshot by querying every feature through
    /// `std::arch::is_aarch64_feature_detected!` (std's internal cache
    /// amortizes). On non-aarch64 targets, returns [`Features::EMPTY`].
    #[inline]
    pub fn current() -> Self {
        #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
        {
            windows_cache::ensure_fast();
            Self {
                lo: windows_cache::FAST_LO.load(::core::sync::atomic::Ordering::Relaxed),
                hi: windows_cache::FAST_HI.load(::core::sync::atomic::Ordering::Relaxed),
            }
        }
        #[cfg(not(all(target_os = "windows", target_arch = "aarch64")))]
        {
            snapshot()
        }
    }

    /// Read the full detection state — same as [`Features::current`]
    /// except on Windows ARM64 with the `registry` Cargo feature and
    /// after [`set_registry_enabled(true)`], it also includes
    /// registry-decoded features that IPFP can't see.
    ///
    /// [`set_registry_enabled(true)`]: set_registry_enabled
    #[inline]
    pub fn current_full() -> Self {
        #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
        {
            windows_cache::ensure_full();
            Self {
                lo: windows_cache::FULL_LO.load(::core::sync::atomic::Ordering::Relaxed),
                hi: windows_cache::FULL_HI.load(::core::sync::atomic::Ordering::Relaxed),
            }
        }
        #[cfg(not(all(target_os = "windows", target_arch = "aarch64")))]
        {
            snapshot()
        }
    }

    /// Returns `true` if this snapshot claims the given feature is detected.
    #[inline]
    pub const fn has(&self, feature: Feature) -> bool {
        let bit = feature as u8;
        if bit < 64 {
            (self.lo >> bit) & 1 != 0
        } else {
            (self.hi >> (bit - 64)) & 1 != 0
        }
    }

    /// Set a feature bit. Used by the IPFP and registry decoders to
    /// populate the cache.
    #[inline]
    pub(crate) const fn with(mut self, feature: Feature) -> Self {
        let bit = feature as u8;
        if bit < 64 {
            self.lo |= 1u64 << bit;
        } else {
            self.hi |= 1u64 << (bit - 64);
        }
        self
    }

    /// Iterator over set features, in enum-discriminant order.
    pub fn iter(&self) -> impl Iterator<Item = Feature> + '_ {
        Feature::all().filter(move |f| self.has(*f))
    }
}

/// Build a `Features` snapshot by querying every feature via the
/// per-target dispatch in [`is_detected`]. Used on non-Windows-aarch64
/// targets where there's no cache layer to read.
#[cfg(not(all(target_os = "windows", target_arch = "aarch64")))]
#[inline]
fn snapshot() -> Features {
    let mut f = Features::EMPTY;
    for feat in Feature::all() {
        if is_detected(feat) {
            f = f.with(feat);
        }
    }
    f
}

/// Macro implementation detail: returns whether `feature` is detected on
/// this target. Users should reach for [`is_aarch64_feature_detected!`]
/// or [`Features::current().has(feature)`].
///
/// [`is_aarch64_feature_detected!`]: crate::is_aarch64_feature_detected!
#[doc(hidden)]
#[inline]
pub fn is_detected(feature: Feature) -> bool {
    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    {
        windows_cache::ensure_fast();
        let bit = feature as u8;
        if bit < 64 {
            (windows_cache::FAST_LO.load(::core::sync::atomic::Ordering::Relaxed) >> bit) & 1 != 0
        } else {
            (windows_cache::FAST_HI.load(::core::sync::atomic::Ordering::Relaxed) >> (bit - 64)) & 1
                != 0
        }
    }
    #[cfg(all(target_arch = "aarch64", not(target_os = "windows")))]
    {
        stdarch_dispatch(feature)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = feature;
        false
    }
}

/// Macro implementation detail: full-cache version of [`is_detected`].
/// Identical to [`is_detected`] on every target except Windows ARM64
/// with the `registry` Cargo feature, where it additionally consults
/// the registry decoder when the runtime gate is on.
#[doc(hidden)]
#[inline]
pub fn is_detected_full(feature: Feature) -> bool {
    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    {
        windows_cache::ensure_full();
        let bit = feature as u8;
        if bit < 64 {
            (windows_cache::FULL_LO.load(::core::sync::atomic::Ordering::Relaxed) >> bit) & 1 != 0
        } else {
            (windows_cache::FULL_HI.load(::core::sync::atomic::Ordering::Relaxed) >> (bit - 64)) & 1
                != 0
        }
    }
    #[cfg(not(all(target_os = "windows", target_arch = "aarch64")))]
    {
        is_detected(feature)
    }
}

/// Per-feature dispatch to `std::arch::is_aarch64_feature_detected!` on
/// non-Windows aarch64 targets. Stable feature names dispatch directly;
/// unstable feature names are gated on the `nightly-stdarch` Cargo
/// feature and return `false` without it.
#[cfg(all(target_arch = "aarch64", not(target_os = "windows")))]
#[inline]
fn stdarch_dispatch(feature: Feature) -> bool {
    match feature {
        // ── Stable on Rust 1.85 — 41 names ─────────────────────────────────
        Feature::Asimd => std::arch::is_aarch64_feature_detected!("asimd"),
        Feature::Fp => std::arch::is_aarch64_feature_detected!("fp"),
        Feature::Fp16 => std::arch::is_aarch64_feature_detected!("fp16"),
        Feature::Fhm => std::arch::is_aarch64_feature_detected!("fhm"),
        Feature::Fcma => std::arch::is_aarch64_feature_detected!("fcma"),
        Feature::Bf16 => std::arch::is_aarch64_feature_detected!("bf16"),
        Feature::I8mm => std::arch::is_aarch64_feature_detected!("i8mm"),
        Feature::JsConv => std::arch::is_aarch64_feature_detected!("jsconv"),
        Feature::FrintTs => std::arch::is_aarch64_feature_detected!("frintts"),
        Feature::Rdm => std::arch::is_aarch64_feature_detected!("rdm"),
        Feature::Dotprod => std::arch::is_aarch64_feature_detected!("dotprod"),
        Feature::Aes => std::arch::is_aarch64_feature_detected!("aes"),
        Feature::Pmull => std::arch::is_aarch64_feature_detected!("pmull"),
        Feature::Sha2 => std::arch::is_aarch64_feature_detected!("sha2"),
        Feature::Sha3 => std::arch::is_aarch64_feature_detected!("sha3"),
        Feature::Sm4 => std::arch::is_aarch64_feature_detected!("sm4"),
        Feature::Crc => std::arch::is_aarch64_feature_detected!("crc"),
        Feature::Lse => std::arch::is_aarch64_feature_detected!("lse"),
        Feature::Lse2 => std::arch::is_aarch64_feature_detected!("lse2"),
        Feature::Rcpc => std::arch::is_aarch64_feature_detected!("rcpc"),
        Feature::Rcpc2 => std::arch::is_aarch64_feature_detected!("rcpc2"),
        Feature::Paca => std::arch::is_aarch64_feature_detected!("paca"),
        Feature::Pacg => std::arch::is_aarch64_feature_detected!("pacg"),
        Feature::Bti => std::arch::is_aarch64_feature_detected!("bti"),
        Feature::Dpb => std::arch::is_aarch64_feature_detected!("dpb"),
        Feature::Dpb2 => std::arch::is_aarch64_feature_detected!("dpb2"),
        Feature::Mte => std::arch::is_aarch64_feature_detected!("mte"),
        Feature::Dit => std::arch::is_aarch64_feature_detected!("dit"),
        Feature::Sb => std::arch::is_aarch64_feature_detected!("sb"),
        Feature::Ssbs => std::arch::is_aarch64_feature_detected!("ssbs"),
        Feature::FlagM => std::arch::is_aarch64_feature_detected!("flagm"),
        Feature::Rand => std::arch::is_aarch64_feature_detected!("rand"),
        Feature::Tme => std::arch::is_aarch64_feature_detected!("tme"),
        Feature::Sve => std::arch::is_aarch64_feature_detected!("sve"),
        Feature::Sve2 => std::arch::is_aarch64_feature_detected!("sve2"),
        Feature::Sve2Aes => std::arch::is_aarch64_feature_detected!("sve2-aes"),
        Feature::Sve2Bitperm => std::arch::is_aarch64_feature_detected!("sve2-bitperm"),
        Feature::Sve2Sha3 => std::arch::is_aarch64_feature_detected!("sve2-sha3"),
        Feature::Sve2Sm4 => std::arch::is_aarch64_feature_detected!("sve2-sm4"),
        Feature::F32mm => std::arch::is_aarch64_feature_detected!("f32mm"),
        Feature::F64mm => std::arch::is_aarch64_feature_detected!("f64mm"),
        // ── Nightly-only on Rust 1.85 — 32 names ──────────────────────────
        // Require `#![feature(stdarch_aarch64_feature_detection)]`; gated
        // on the `nightly-stdarch` Cargo feature.
        #[cfg(feature = "nightly-stdarch")]
        Feature::Cssc => std::arch::is_aarch64_feature_detected!("cssc"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::Ecv => std::arch::is_aarch64_feature_detected!("ecv"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::FaMinMax => std::arch::is_aarch64_feature_detected!("faminmax"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::FlagM2 => std::arch::is_aarch64_feature_detected!("flagm2"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::Fp8 => std::arch::is_aarch64_feature_detected!("fp8"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::Fp8Dot2 => std::arch::is_aarch64_feature_detected!("fp8dot2"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::Fp8Dot4 => std::arch::is_aarch64_feature_detected!("fp8dot4"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::Fp8Fma => std::arch::is_aarch64_feature_detected!("fp8fma"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::Fpmr => std::arch::is_aarch64_feature_detected!("fpmr"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::Hbc => std::arch::is_aarch64_feature_detected!("hbc"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::Lse128 => std::arch::is_aarch64_feature_detected!("lse128"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::Lut => std::arch::is_aarch64_feature_detected!("lut"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::Mops => std::arch::is_aarch64_feature_detected!("mops"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::PauthLr => std::arch::is_aarch64_feature_detected!("pauth-lr"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::Rcpc3 => std::arch::is_aarch64_feature_detected!("rcpc3"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::Sme => std::arch::is_aarch64_feature_detected!("sme"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::Sme2 => std::arch::is_aarch64_feature_detected!("sme2"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::Sme2p1 => std::arch::is_aarch64_feature_detected!("sme2p1"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::SmeB16b16 => std::arch::is_aarch64_feature_detected!("sme-b16b16"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::SmeF16f16 => std::arch::is_aarch64_feature_detected!("sme-f16f16"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::SmeF64f64 => std::arch::is_aarch64_feature_detected!("sme-f64f64"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::SmeF8f16 => std::arch::is_aarch64_feature_detected!("sme-f8f16"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::SmeF8f32 => std::arch::is_aarch64_feature_detected!("sme-f8f32"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::SmeFa64 => std::arch::is_aarch64_feature_detected!("sme-fa64"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::SmeI16i64 => std::arch::is_aarch64_feature_detected!("sme-i16i64"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::SmeLutv2 => std::arch::is_aarch64_feature_detected!("sme-lutv2"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::SsveFp8Dot2 => std::arch::is_aarch64_feature_detected!("ssve-fp8dot2"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::SsveFp8Dot4 => std::arch::is_aarch64_feature_detected!("ssve-fp8dot4"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::SsveFp8Fma => std::arch::is_aarch64_feature_detected!("ssve-fp8fma"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::Sve2p1 => std::arch::is_aarch64_feature_detected!("sve2p1"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::SveB16b16 => std::arch::is_aarch64_feature_detected!("sve-b16b16"),
        #[cfg(feature = "nightly-stdarch")]
        Feature::WfxT => std::arch::is_aarch64_feature_detected!("wfxt"),
        // Without `nightly-stdarch`, the unstable names fall through to false.
        #[cfg(not(feature = "nightly-stdarch"))]
        _ => false,
    }
}

/// Authorise the registry-based detection layer at runtime.
///
/// **Compile-time + runtime double opt-in.** The registry FFI is only
/// linked into your binary when *some* crate enables the
/// `winarm-cpufeatures/registry` Cargo feature; this function is the
/// second tier — it must be called before any
/// [`is_aarch64_feature_detected_full!`] / [`Features::current_full`]
/// call for the registry to actually be consulted. Without it, the
/// registry code stays untouched even when it's compiled in.
///
/// On builds where the registry layer doesn't apply (non-Windows-aarch64,
/// or the `registry` Cargo feature is off), this function is a no-op
/// kept available for API stability.
///
/// [`is_aarch64_feature_detected_full!`]: crate::is_aarch64_feature_detected_full!
#[inline]
pub fn set_registry_enabled(enabled: bool) {
    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    windows_cache::set_registry_enabled(enabled);
    #[cfg(not(all(target_os = "windows", target_arch = "aarch64")))]
    {
        let _ = enabled;
    }
}

// ─── Windows ARM64 cache machinery ─────────────────────────────────────────
//
// Only this target needs a cache: IPFP probes are syscalls, and registry
// reads are file I/O. Everywhere else we dispatch directly to std's
// macro, which has its own internal cache.
#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
mod windows_cache {
    use super::Features;
    use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

    const INIT_UNSET: u8 = 0;
    const INIT_DONE: u8 = 2;

    /// Fast cache — IPFP probes only.
    static FAST_INIT: AtomicU8 = AtomicU8::new(INIT_UNSET);
    pub(super) static FAST_LO: AtomicU64 = AtomicU64::new(0);
    pub(super) static FAST_HI: AtomicU64 = AtomicU64::new(0);

    /// Full cache — IPFP plus, when both the `registry` Cargo feature is
    /// enabled AND `set_registry_enabled(true)` has been called, registry
    /// CP-key reads.
    static FULL_INIT: AtomicU8 = AtomicU8::new(INIT_UNSET);
    pub(super) static FULL_LO: AtomicU64 = AtomicU64::new(0);
    pub(super) static FULL_HI: AtomicU64 = AtomicU64::new(0);

    /// Runtime opt-in for the registry layer. Defaults to `false` so the
    /// registry path is *never touched* unless the application explicitly
    /// asks for it — even when transitive dependencies have enabled the
    /// `registry` Cargo feature.
    static REGISTRY_RUNTIME_ENABLED: AtomicBool = AtomicBool::new(false);

    #[inline]
    pub(super) fn ensure_fast() {
        if FAST_INIT.load(Ordering::Acquire) == INIT_DONE {
            return;
        }
        let f = probe_fast();
        FAST_LO.store(f.lo, Ordering::Relaxed);
        FAST_HI.store(f.hi, Ordering::Relaxed);
        FAST_INIT.store(INIT_DONE, Ordering::Release);
    }

    #[inline]
    pub(super) fn ensure_full() {
        if FULL_INIT.load(Ordering::Acquire) == INIT_DONE {
            return;
        }
        let f = probe_full();
        FULL_LO.store(f.lo, Ordering::Relaxed);
        FULL_HI.store(f.hi, Ordering::Relaxed);
        FULL_INIT.store(INIT_DONE, Ordering::Release);
    }

    fn probe_fast() -> Features {
        let mut f = Features::EMPTY;
        crate::windows::fill_ipfp(&mut f);
        f
    }

    fn probe_full() -> Features {
        let mut f = Features::EMPTY;
        crate::windows::fill_ipfp(&mut f);
        // Registry layer is double-opt-in: the `registry` Cargo feature
        // links the FFI, and `set_registry_enabled(true)` authorises it
        // at runtime. Both must be in effect.
        #[cfg(feature = "registry")]
        if REGISTRY_RUNTIME_ENABLED.load(Ordering::Acquire) {
            crate::windows::fill_registry(&mut f);
        }
        f
    }

    #[inline]
    pub(super) fn set_registry_enabled(enabled: bool) {
        REGISTRY_RUNTIME_ENABLED.store(enabled, Ordering::Release);
        // Invalidate the full cache so the next probe re-runs with the new
        // policy.
        FULL_INIT.store(INIT_UNSET, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_has_nothing() {
        let f = Features::EMPTY;
        for feat in Feature::all() {
            assert!(!f.has(feat), "{}", feat.name());
        }
    }

    #[test]
    fn with_sets_only_target_bit() {
        let f = Features::EMPTY.with(Feature::Rdm);
        assert!(f.has(Feature::Rdm));
        assert!(!f.has(Feature::Sve));
    }

    #[test]
    fn high_bit_features_round_trip() {
        // Pick a feature with discriminant ≥ 64 to exercise the hi word.
        let f = Features::EMPTY.with(Feature::SmeF64f64);
        assert!(f.has(Feature::SmeF64f64));
        // No low-word bits should be set when only a high-word feature is added.
        for feat in Feature::all() {
            if (feat as u8) < 64 {
                assert!(!f.has(feat), "{} unexpectedly set", feat.name());
            }
        }
    }

    #[test]
    fn full_implies_fast_for_ipfp_features() {
        use crate::features::DetectionMethod;
        // For Ipfp-classified features, both query paths must agree.
        for f in Feature::all() {
            if f.detection_method() == DetectionMethod::Ipfp {
                assert_eq!(
                    is_detected(f),
                    is_detected_full(f),
                    "fast/full disagree for IPFP feature {}",
                    f.name()
                );
            }
        }
    }

    #[test]
    fn current_snapshot_matches_individual_calls() {
        use crate::features::DetectionMethod;
        let snap = Features::current();
        for f in Feature::all() {
            if f.detection_method() != DetectionMethod::Registry {
                assert_eq!(snap.has(f), is_detected(f), "fast {} disagrees", f.name());
            }
        }

        let snap_full = Features::current_full();
        for f in Feature::all() {
            assert_eq!(
                snap_full.has(f),
                is_detected_full(f),
                "full {} disagrees",
                f.name()
            );
        }
    }
}
