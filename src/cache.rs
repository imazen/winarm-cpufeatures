//! Detection state and per-target dispatch.
//!
//! The detection cache exists only on Windows aarch64 — that's the only
//! target where probe cost matters (IPFP is a syscall per probe; registry
//! reads are file I/O). On non-Windows aarch64, we dispatch directly to
//! `std::arch::is_aarch64_feature_detected!`, which has its own internal
//! HWCAP-based cache; layering our own on top would be redundant. On
//! non-aarch64 targets, every feature reads `false`.
//!
//! ## Single-load query path on Windows aarch64
//!
//! Init state is encoded *into* the cache words rather than tracked in
//! a separate atomic — bit 63 of `lo` and bit 63 of `hi` are reserved
//! as `INIT_BIT`. A query is one Acquire load on the relevant word: if
//! `INIT_BIT` is clear, run the probe and retry; otherwise mask out
//! `INIT_BIT` and bit-test. No separate init-gate load.
//!
//! Probes store HI first then LO with `INIT_BIT` set. So a reader that
//! sees `LO & INIT_BIT != 0` is guaranteed HI is also fresh. Snapshot
//! readers (`Features::current_full`) can use Acquire on LO and Relaxed
//! on HI as a result.

use crate::features::Feature;

/// Bit reserved in each cache word as the "initialized" sentinel.
/// `Feature` discriminants must avoid bit 63 (lo) and bit 127 (hi).
/// See the `bit_positions_unique_and_avoid_init_slots` test in
/// `features.rs` for the enforcement.
#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
const INIT_BIT: u64 = 1 << 63;

/// A snapshot of detected features. Cheap to copy; `has` is a pure bit test.
///
/// The bit-packed representation (`lo` low 64 features, `hi` high 64
/// features) is an implementation detail. Fields are visible only
/// inside `crate::cache` so the cache machinery can publish/load words
/// directly with `INIT_BIT` masking; every other consumer goes through
/// type-safe [`Features::has`] / [`Features::iter`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Features {
    pub(in crate::cache) lo: u64,
    pub(in crate::cache) hi: u64,
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
            windows_cache::snapshot_fast()
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
            windows_cache::snapshot_full()
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
/// this target. Users should reach for [`is_aarch64_feature_detected_fast!`]
/// or [`Features::current().has(feature)`].
///
/// [`is_aarch64_feature_detected_fast!`]: crate::is_aarch64_feature_detected_fast!
#[doc(hidden)]
#[inline]
pub fn is_detected(feature: Feature) -> bool {
    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    {
        windows_cache::query_fast(feature)
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

/// Macro implementation detail: returns whether `feature` is detected on
/// this target via the *full* path — i.e., on Windows ARM64 with the
/// `registry` Cargo feature enabled and `set_registry_enabled(true)`
/// (the default), this consults the registry-backed
/// `ID_AA64*_EL1` decoder in addition to IPFP. Users should reach for
/// [`is_aarch64_feature_detected_full!`] or
/// [`Features::current_full().has(feature)`].
///
/// [`is_aarch64_feature_detected_full!`]: crate::is_aarch64_feature_detected_full!
/// [`Features::current_full().has(feature)`]: crate::Features::current_full
#[doc(hidden)]
#[inline]
pub fn is_detected_full(feature: Feature) -> bool {
    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    {
        windows_cache::query_full(feature)
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

/// Per-feature dispatch to `std::arch::is_aarch64_feature_detected!` on
/// non-Windows aarch64 targets. Only the 41 names that std accepts on
/// stable Rust 1.85 are wired here; the 32 names std gates behind
/// `#![feature(stdarch_aarch64_feature_detection)]` always read `false`
/// in our `Features::current()` snapshot. Users wanting real detection
/// for those should call `std::arch::is_aarch64_feature_detected!`
/// directly with their own nightly feature gate enabled.
#[cfg(all(target_arch = "aarch64", not(target_os = "windows")))]
#[inline]
fn stdarch_dispatch(feature: Feature) -> bool {
    match feature {
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
        // The 32 names std gates behind `stdarch_aarch64_feature_detection`
        // always read `false` here. We don't try to wire them — std works
        // perfectly on these targets when the user opts into nightly with
        // their own feature gate, and that's where they should go.
        _ => false,
    }
}

/// Set the runtime authorisation for the registry-based detection layer.
///
/// The `registry` Cargo feature is the actual gate — it controls
/// whether the registry FFI is linked at all. When that feature is on,
/// the runtime gate defaults to `true`, so the registry IS consulted
/// without any setup. Pass `false` here at startup to suppress it
/// (sandboxed processes without `HKLM` read access; deterministic
/// IPFP-only diagnostics; tests).
///
/// On builds where the registry layer doesn't apply (non-Windows
/// aarch64, or the `registry` Cargo feature off), this function is a
/// no-op kept available for API stability.
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
//
// **Single-load query path.** Bit 63 of each `lo`/`hi` cache word is
// reserved as `INIT_BIT`. A cache word is "initialized" iff `INIT_BIT`
// is set; a query is one Acquire load that doubles as the init check.
// Probes write HI first, then LO with `INIT_BIT` set in both — so a
// reader who sees `INIT_BIT` in LO knows HI is already published. No
// separate init-gate atomic.
//
// `Feature` discriminants must avoid bit 63 of lo (= 63) and bit 63
// of hi (= 127). Enforced by the `bit_positions_unique_and_avoid_init_slots`
// test in `features.rs`.
#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
mod windows_cache {
    use super::{Features, INIT_BIT};
    use crate::features::Feature;
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    /// Fast cache — IPFP probes only. Initialized when bit 63 of LO is set.
    static FAST_LO: AtomicU64 = AtomicU64::new(0);
    static FAST_HI: AtomicU64 = AtomicU64::new(0);

    /// Full cache — IPFP plus, when both the `registry` Cargo feature is
    /// enabled AND `set_registry_enabled(true)` has been called, registry
    /// CP-key reads. Initialized when bit 63 of LO is set.
    static FULL_LO: AtomicU64 = AtomicU64::new(0);
    static FULL_HI: AtomicU64 = AtomicU64::new(0);

    /// Runtime opt-out for the registry layer. The `registry` Cargo
    /// feature is the actual gate — it controls whether the registry FFI
    /// is linked at all. When that feature is on, the registry IS
    /// consulted by default; sandboxed callers (no permission to read
    /// `HKLM`, or wanting deterministic IPFP-only behavior) can call
    /// `set_registry_enabled(false)` once at startup to suppress it.
    ///
    /// Defaulting this to `true` removes a silent footgun: previously a
    /// user could enable `features = ["registry"]` and still see
    /// registry-only features report `false` because they didn't also
    /// know to call `set_registry_enabled(true)`.
    static REGISTRY_RUNTIME_ENABLED: AtomicBool = AtomicBool::new(true);

    /// Single-load query against the fast cache. Loops only on the cold
    /// path (cache uninitialized) — the hot path is one Acquire load and
    /// a bit test.
    #[inline]
    pub(super) fn query_fast(feature: Feature) -> bool {
        let bit = feature as u8;
        let (atomic, pos) = if bit < 64 {
            (&FAST_LO, bit)
        } else {
            (&FAST_HI, bit - 64)
        };
        loop {
            let word = atomic.load(Ordering::Acquire);
            if word & INIT_BIT != 0 {
                return (word >> pos) & 1 != 0;
            }
            populate_fast();
        }
    }

    /// Single-load query against the full cache (IPFP + registry, when
    /// authorized). Same shape as [`query_fast`] but reads
    /// `FULL_LO`/`FULL_HI`, which `populate_full` fills with the union
    /// of IPFP and registry-decoded `ID_AA64*_EL1` bits.
    #[inline]
    pub(super) fn query_full(feature: Feature) -> bool {
        let bit = feature as u8;
        let (atomic, pos) = if bit < 64 {
            (&FULL_LO, bit)
        } else {
            (&FULL_HI, bit - 64)
        };
        loop {
            let word = atomic.load(Ordering::Acquire);
            if word & INIT_BIT != 0 {
                return (word >> pos) & 1 != 0;
            }
            populate_full();
        }
    }

    /// Take a `Features` snapshot from the fast cache. One Acquire load
    /// on LO synchronizes; HI is then a Relaxed load (publication of LO
    /// happens-after publication of HI, so HI is already visible).
    #[inline]
    pub(super) fn snapshot_fast() -> Features {
        loop {
            let lo = FAST_LO.load(Ordering::Acquire);
            if lo & INIT_BIT == 0 {
                populate_fast();
                continue;
            }
            let hi = FAST_HI.load(Ordering::Relaxed);
            return Features {
                lo: lo & !INIT_BIT,
                hi: hi & !INIT_BIT,
            };
        }
    }

    /// Take a `Features` snapshot from the full cache.
    #[inline]
    pub(super) fn snapshot_full() -> Features {
        loop {
            let lo = FULL_LO.load(Ordering::Acquire);
            if lo & INIT_BIT == 0 {
                populate_full();
                continue;
            }
            let hi = FULL_HI.load(Ordering::Relaxed);
            return Features {
                lo: lo & !INIT_BIT,
                hi: hi & !INIT_BIT,
            };
        }
    }

    /// Probe IPFP and publish the result. Stores HI first then LO so a
    /// reader that sees `INIT_BIT` in LO knows HI is already up-to-date.
    /// Idempotent — racing writers produce the same bitset, last writer
    /// wins with the same value.
    fn populate_fast() {
        let mut f = Features::EMPTY;
        crate::windows::fill_ipfp(&mut f);
        FAST_HI.store(f.hi | INIT_BIT, Ordering::Release);
        FAST_LO.store(f.lo | INIT_BIT, Ordering::Release);
    }

    /// Probe IPFP + (when authorized) registry, then publish.
    fn populate_full() {
        let mut f = Features::EMPTY;
        crate::windows::fill_ipfp(&mut f);
        // Registry layer is double-opt-in: the `registry` Cargo feature
        // links the FFI, and `set_registry_enabled(true)` authorises it
        // at runtime. Both must be in effect.
        #[cfg(feature = "registry")]
        if REGISTRY_RUNTIME_ENABLED.load(Ordering::Acquire) {
            crate::windows::fill_registry(&mut f);
        }
        FULL_HI.store(f.hi | INIT_BIT, Ordering::Release);
        FULL_LO.store(f.lo | INIT_BIT, Ordering::Release);
    }

    #[inline]
    pub(super) fn set_registry_enabled(enabled: bool) {
        REGISTRY_RUNTIME_ENABLED.store(enabled, Ordering::Release);
        // Invalidate the full cache by clearing INIT_BIT on both halves.
        // The next query re-populates with the new policy. Order: clear
        // LO first (so any concurrent reader sees uninit on LO) then HI.
        FULL_LO.store(0, Ordering::Release);
        FULL_HI.store(0, Ordering::Release);
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
    fn full_snapshot_implies_fast_for_ipfp_features() {
        use crate::features::DetectionMethod;
        // For Ipfp-classified features, fast and full must agree.
        let fast = Features::current();
        let full = Features::current_full();
        for f in Feature::all() {
            if f.detection_method() == DetectionMethod::Ipfp {
                assert_eq!(
                    fast.has(f),
                    full.has(f),
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
    }
}
