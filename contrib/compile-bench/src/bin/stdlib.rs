//! Compile-time benchmark: ~480 invocations of
//! `std::arch::is_aarch64_feature_detected!`.
//!
//! Apples-to-apples with `bin/winarm.rs` — same call count, same number
//! of distinct feature names. Names use the stdarch spelling (dashes,
//! not underscores) and are restricted to the 40 stable names that don't
//! require `#![feature(stdarch_aarch64_feature_detection)]` on Rust 1.85.

use std::hint::black_box;

#[inline(never)]
fn block() -> u32 {
    let mut acc: u32 = 0;
    macro_rules! probe {
        ($($n:tt),* $(,)?) => {
            $( acc ^= ::std::arch::is_aarch64_feature_detected!($n) as u32; )*
        };
    }
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
    // 12 batches × 40 names = 480 invocations — matches bin/winarm.rs.
    batch!(); batch!(); batch!(); batch!();
    batch!(); batch!(); batch!(); batch!();
    batch!(); batch!(); batch!(); batch!();
    acc
}

fn main() {
    println!("{}", black_box(block()));
}
