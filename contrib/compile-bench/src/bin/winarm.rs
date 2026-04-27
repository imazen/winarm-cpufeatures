//! Compile-time benchmark: ~480 invocations of `winarm_cpufeatures::is_aarch64_feature_detected_fast!`.
//!
//! Apples-to-apples with `bin/stdlib.rs`, which exercises the same number
//! of `std::arch::is_aarch64_feature_detected!` invocations on the same
//! 40 stable stdarch feature names. We restrict to stable names because
//! on non-Windows aarch64 our macro is a passthrough to std, and stable
//! Rust rejects unstable names there — same constraint stdlib.rs faces.

use std::hint::black_box;

use winarm_cpufeatures::is_aarch64_feature_detected_fast;

#[inline(never)]
fn block() -> u32 {
    let mut acc: u32 = 0;
    macro_rules! probe { ($($n:tt),* $(,)?) => { $( acc ^= is_aarch64_feature_detected_fast!($n) as u32; )* } }
    macro_rules! batch {
        () => {
            probe!(
                "asimd", "fp", "fp16", "fhm", "fcma", "bf16", "i8mm",
                "jsconv", "frintts", "rdm", "dotprod",
                "aes", "pmull", "sha2", "sha3", "sm4", "crc",
                "lse", "lse2", "rcpc", "rcpc2",
                "paca", "pacg", "bti", "dpb", "dpb2", "mte",
                "dit", "sb", "ssbs", "flagm", "rand", "tme",
                "sve", "sve2", "sve2-aes", "sve2-bitperm", "sve2-sha3", "sve2-sm4",
                "f32mm", "f64mm",
            );
        };
    }
    // 12 batches × 40 names = 480 invocations — matches bin/stdlib.rs.
    batch!(); batch!(); batch!(); batch!();
    batch!(); batch!(); batch!(); batch!();
    batch!(); batch!(); batch!(); batch!();
    acc
}

fn main() {
    println!("{}", black_box(block()));
}
