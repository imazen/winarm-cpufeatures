//! Smoke tests that compile and run on every supported target.

use winarm_cpufeatures::{
    DetectionMethod, Feature, Features, detected, detected_full, is_detected, is_detected_full,
};

#[test]
fn fast_macro_compiles_for_ipfp_features() {
    // All these features have DetectionMethod::Ipfp; the fast macro accepts them.
    let _ = detected!("asimd");
    let _ = detected!("fp");
    let _ = detected!("aes");
    let _ = detected!("crc");
    let _ = detected!("lse");
    let _ = detected!("dotprod");
    let _ = detected!("jsconv");
    let _ = detected!("rcpc");
    let _ = detected!("sve");
    let _ = detected!("sve2");
    let _ = detected!("sve2p1");
}

#[test]
fn full_macro_compiles_for_all_features() {
    // detected_full! accepts every known name regardless of detection method.
    let _ = detected_full!("rdm");
    let _ = detected_full!("bf16");
    let _ = detected_full!("i8mm");
    let _ = detected_full!("sve");
    let _ = detected_full!("sme");
    let _ = detected_full!("paca");
    let _ = detected_full!("dpb2");
    let _ = detected_full!("flagm2");
    let _ = detected_full!("frintts");
}

#[test]
fn function_form_matches_macro() {
    assert_eq!(detected!("sve"), is_detected(Feature::Sve));
    assert_eq!(detected!("dotprod"), is_detected(Feature::Dotprod));
    assert_eq!(detected_full!("rdm"), is_detected_full(Feature::Rdm));
}

#[test]
fn full_implies_fast_for_ipfp_features() {
    // For Ipfp-classified features, both caches must agree.
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

#[cfg(not(target_arch = "aarch64"))]
#[test]
fn non_aarch64_targets_detect_nothing() {
    let snap = Features::current();
    let count = Feature::all().filter(|f| snap.has(*f)).count();
    assert_eq!(count, 0, "non-aarch64 targets must not claim any features");
}

#[cfg(all(target_arch = "aarch64", not(target_os = "windows")))]
#[test]
fn non_windows_aarch64_matches_stdarch() {
    assert_eq!(
        detected!("asimd"),
        std::arch::is_aarch64_feature_detected!("asimd")
    );
    assert_eq!(
        detected_full!("aes"),
        std::arch::is_aarch64_feature_detected!("aes")
    );
}
