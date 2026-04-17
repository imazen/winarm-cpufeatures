//! Detect whether we're building with nightly rustc so the crate can
//! opt into feature names that `is_aarch64_feature_detected!` gates
//! behind `#![feature(stdarch_aarch64_feature_detection)]`.

fn main() {
    // Teach cargo that this cfg is ours so it doesn't warn.
    println!("cargo::rustc-check-cfg=cfg(winarm_rustc_nightly)");

    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let Ok(output) = std::process::Command::new(&rustc)
        .args(["--version", "--verbose"])
        .output()
    else {
        return;
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    // `rustc 1.93.0-nightly (...)` or `release: 1.93.0-nightly`
    let is_nightly = stdout.contains("nightly") || stdout.contains("-dev");
    if is_nightly {
        println!("cargo::rustc-cfg=winarm_rustc_nightly");
    }

    println!("cargo:rerun-if-env-changed=RUSTC");
    println!("cargo:rerun-if-env-changed=RUSTC_BOOTSTRAP");
}
