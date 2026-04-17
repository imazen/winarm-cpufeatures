//! Two-tier feature detection cache.
//!
//! The crate maintains two independent caches:
//!
//! - **Fast cache**: populated by IPFP probes only. Queried by [`detected!`].
//! - **Full cache**: populated by IPFP + registry reads. Queried by
//!   [`detected_full!`]. More expensive to initialize (one registry key open,
//!   ~10 `REG_QWORD` reads) but covers every feature.
//!
//! Both caches use `AtomicU64` bitsets with `Ordering::Relaxed` loads and
//! stores. The probe functions are idempotent — racing writers all produce
//! the same bitset, so stepping on each other's stores is fine. An `AtomicU8`
//! init gate with `Release`/`Acquire` ordering paper-overs the publish.
//!
//! [`detected!`]: crate::detected!
//! [`detected_full!`]: crate::detected_full!

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

#[cfg(test)]
use crate::features::FEATURE_COUNT;
use crate::features::Feature;

const INIT_UNSET: u8 = 0;
const INIT_DONE: u8 = 2;

/// Fast cache — IPFP probes only, queried by [`crate::detected!`].
static FAST_INIT: AtomicU8 = AtomicU8::new(INIT_UNSET);
static FAST_LO: AtomicU64 = AtomicU64::new(0);
static FAST_HI: AtomicU64 = AtomicU64::new(0);

/// Full cache — IPFP + registry, queried by [`crate::detected_full!`].
static FULL_INIT: AtomicU8 = AtomicU8::new(INIT_UNSET);
static FULL_LO: AtomicU64 = AtomicU64::new(0);
static FULL_HI: AtomicU64 = AtomicU64::new(0);

/// A snapshot of a detection cache. Cheap to copy; `has` is a pure bit test.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Features {
    lo: u64,
    hi: u64,
}

impl Features {
    /// The empty feature set (all features absent).
    pub const EMPTY: Self = Self { lo: 0, hi: 0 };

    /// Read the fast cache, triggering an IPFP-only probe on first access.
    #[inline]
    pub fn current() -> Self {
        ensure_fast();
        Self {
            lo: FAST_LO.load(Ordering::Relaxed),
            hi: FAST_HI.load(Ordering::Relaxed),
        }
    }

    /// Read the full cache, triggering an IPFP + registry probe on first
    /// access. Equivalent to [`detected_full!`] for every feature.
    ///
    /// [`detected_full!`]: crate::detected_full!
    #[inline]
    pub fn current_full() -> Self {
        ensure_full();
        Self {
            lo: FULL_LO.load(Ordering::Relaxed),
            hi: FULL_HI.load(Ordering::Relaxed),
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

    /// Set a feature bit. Intended for constructing test fixtures.
    #[inline]
    pub const fn with(mut self, feature: Feature) -> Self {
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

    /// Raw bits. Low 64 bits cover `Feature` discriminants 0..64; high 64
    /// bits cover 64..128.
    pub const fn raw(&self) -> (u64, u64) {
        (self.lo, self.hi)
    }

    /// Construct from raw bits.
    pub const fn from_raw(lo: u64, hi: u64) -> Self {
        Self { lo, hi }
    }
}

/// Read from the fast (IPFP-only) cache. Use for features classified as
/// [`DetectionMethod::Ipfp`].
///
/// [`DetectionMethod::Ipfp`]: crate::DetectionMethod::Ipfp
#[inline]
pub fn is_detected(feature: Feature) -> bool {
    ensure_fast();
    let bit = feature as u8;
    if bit < 64 {
        (FAST_LO.load(Ordering::Relaxed) >> bit) & 1 != 0
    } else {
        (FAST_HI.load(Ordering::Relaxed) >> (bit - 64)) & 1 != 0
    }
}

/// Read from the full (IPFP + registry) cache. Use for features classified
/// as [`DetectionMethod::Registry`] or when the caller has opted into the
/// slow probe via [`detected_full!`].
///
/// [`DetectionMethod::Registry`]: crate::DetectionMethod::Registry
/// [`detected_full!`]: crate::detected_full!
#[inline]
pub fn is_detected_full(feature: Feature) -> bool {
    ensure_full();
    let bit = feature as u8;
    if bit < 64 {
        (FULL_LO.load(Ordering::Relaxed) >> bit) & 1 != 0
    } else {
        (FULL_HI.load(Ordering::Relaxed) >> (bit - 64)) & 1 != 0
    }
}

#[inline]
fn ensure_fast() {
    if FAST_INIT.load(Ordering::Acquire) == INIT_DONE {
        return;
    }
    let f = crate::detect::probe_fast();
    FAST_LO.store(f.lo, Ordering::Relaxed);
    FAST_HI.store(f.hi, Ordering::Relaxed);
    FAST_INIT.store(INIT_DONE, Ordering::Release);
}

#[inline]
fn ensure_full() {
    if FULL_INIT.load(Ordering::Acquire) == INIT_DONE {
        return;
    }
    let f = crate::detect::probe_full();
    FULL_LO.store(f.lo, Ordering::Relaxed);
    FULL_HI.store(f.hi, Ordering::Relaxed);
    FULL_INIT.store(INIT_DONE, Ordering::Release);
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
        let (lo, hi) = f.raw();
        assert_eq!(lo, 0);
        assert_ne!(hi, 0);
        assert!(f.has(Feature::SmeF64f64));
    }

    const _: () = assert!(FEATURE_COUNT <= 128);
}
