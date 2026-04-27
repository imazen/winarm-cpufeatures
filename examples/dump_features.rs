//! Dump every detected aarch64 feature with its detection state.
//!
//! Run via `cargo run --example dump_features`. Output is plain text, one
//! line per feature, suitable for committing to a runner-feature matrix or
//! attaching as a CI artifact.

use winarm_cpufeatures::{Feature, Features};

fn main() {
    let f = Features::current();
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    println!("# winarm-cpufeatures dump");
    println!("# arch={arch} os={os}");
    println!("# feature_count={}", Feature::all().count());
    println!();
    let detected_count = Feature::all().filter(|x| f.has(*x)).count();
    println!("# {detected_count} features detected:");
    for feat in Feature::all() {
        let mark = if f.has(feat) { "[+]" } else { "[ ]" };
        println!("{mark} {}", feat.name());
    }
}
