//! Compile-time benchmark: ~480 invocations of `winarm_cpufeatures::is_aarch64_feature_detected!`.
//!
//! Apples-to-apples with `bin/stdlib.rs`, which exercises the same number
//! of `std::arch::is_aarch64_feature_detected!` invocations on the same
//! 40 stable stdarch feature names.

use std::hint::black_box;

use winarm_cpufeatures::is_aarch64_feature_detected;

#[inline(never)]
fn block() -> u32 {
    let mut acc: u32 = 0;
    macro_rules! probe { ($($n:tt),* $(,)?) => { $( acc ^= is_aarch64_feature_detected!($n) as u32; )* } }
    macro_rules! batch {
        () => {
            probe!(
                "asimd", "fp", "fp16", "bf16", "i8mm", "jsconv", "rdm", "dotprod",
                "aes", "pmull", "sha2", "sha3", "crc",
                "lse", "lse2", "rcpc",
                "sve", "sve2", "sve2-aes", "sve2-bitperm", "sve2-sha3", "sve2-sm4",
                "f32mm", "f64mm",
                // Pad to 40 names so the call count matches bin/stdlib.rs.
                "sve2p1", "sve-b16b16",
                "sme", "sme2", "sme2p1",
                "sme-b16b16", "sme-f16f16", "sme-f64f64", "sme-f8f16", "sme-f8f32",
                "sme-fa64", "sme-i16i64", "sme-lutv2",
                "ssve-fp8dot2", "ssve-fp8dot4", "ssve-fp8fma",
            );
        };
    }
    batch!(); batch!(); batch!(); batch!();
    batch!(); batch!(); batch!(); batch!();
    batch!(); batch!(); batch!(); batch!();
    acc
}

fn main() {
    println!("{}", black_box(block()));
}
