//! Measure first-check latency for fast (IPFP) and full (IPFP+registry) paths,
//! plus cached re-probe cost. Each run is a fresh process so the cache is cold.

use std::env;
use std::time::Instant;
use winarm_cpufeatures::{Features, set_registry_enabled};

fn main() {
    let mode = env::args().nth(1).unwrap_or_else(|| "fast".to_string());
    match mode.as_str() {
        "fast" => {
            let t = Instant::now();
            let f = Features::current();
            let cold = t.elapsed();
            let t = Instant::now();
            let _ = Features::current();
            let warm = t.elapsed();
            std::hint::black_box(f);
            println!("fast cold={:?} warm={:?}", cold, warm);
        }
        "full_no_registry" => {
            // Cargo `registry` feature may or may not be on; runtime gate OFF.
            let t = Instant::now();
            let f = Features::current_full();
            let cold = t.elapsed();
            let t = Instant::now();
            let _ = Features::current_full();
            let warm = t.elapsed();
            std::hint::black_box(f);
            println!("full(runtime-off) cold={:?} warm={:?}", cold, warm);
        }
        "full_registry" => {
            set_registry_enabled(true);
            let t = Instant::now();
            let f = Features::current_full();
            let cold = t.elapsed();
            let t = Instant::now();
            let _ = Features::current_full();
            let warm = t.elapsed();
            std::hint::black_box(f);
            println!("full(registry-on) cold={:?} warm={:?}", cold, warm);
        }
        "split" => {
            // Measure IPFP cold first, then registry incremental.
            let t = Instant::now();
            let _ = Features::current();
            let ipfp_cold = t.elapsed();
            set_registry_enabled(true);
            let t = Instant::now();
            let _ = Features::current_full();
            let registry_cold = t.elapsed();
            let t = Instant::now();
            let _ = Features::current_full();
            let warm = t.elapsed();
            println!(
                "ipfp_cold={:?} registry_cold(after ipfp)={:?} warm={:?}",
                ipfp_cold, registry_cold, warm
            );
        }
        _ => eprintln!("usage: latency [fast|full_no_registry|full_registry|split]"),
    }
}
