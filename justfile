default:
    @just --list

build:
    cargo build

test:
    cargo test

dump:
    cargo run --example dump_features

ci: fmt clippy test docs

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

clippy:
    cargo clippy --all-targets -- -D warnings

docs:
    RUSTDOCFLAGS=-Dwarnings cargo doc --no-deps

cross-build target:
    cargo build --target {{target}}
