//! Dump features using BOTH cargo `registry` feature AND runtime
//! `set_registry_enabled(true)`. Compares fast (IPFP) vs full (IPFP+registry).

use winarm_cpufeatures::{Feature, Features, set_registry_enabled};

fn main() {
    let fast = Features::current();
    set_registry_enabled(true);
    let full = Features::current_full();

    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    let fast_count = Feature::all().filter(|x| fast.has(*x)).count();
    let full_count = Feature::all().filter(|x| full.has(*x)).count();
    println!("# winarm-cpufeatures dump (fast vs full)");
    println!("# arch={arch} os={os}");
    println!("# fast={fast_count} full={full_count}");
    println!();
    println!("FAST FULL feature");
    for feat in Feature::all() {
        let f = if fast.has(feat) { "[+]" } else { "[ ]" };
        let g = if full.has(feat) { "[+]" } else { "[ ]" };
        let new = if !fast.has(feat) && full.has(feat) {
            "  <- registry-only"
        } else {
            ""
        };
        println!("{f} {g} {}{}", feat.name(), new);
    }
}
