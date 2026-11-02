#!/bin/sh
# Regenerate the UniFFI Kotlin sources from the Rust library.
#   bindings/kotlin/generate.sh [cargo build args...]
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
cargo build -p yggdrasil-uniffi "$@"
cargo run -q -p yggdrasil-uniffi --features cli --bin uniffi-bindgen -- \
    generate --library target/debug/libyggdrasil_uniffi.so \
    --language kotlin --no-format \
    --out-dir bindings/kotlin/src/main/kotlin
