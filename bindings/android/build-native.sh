#!/bin/sh
# Build libyggdrasil_uniffi.so for Android into bindings/android/build/jniLibs.
#   ABIS="arm64-v8a x86_64" bindings/android/build-native.sh [extra cargo args]
# Needs cargo-ndk (cargo install cargo-ndk), the Rust targets
# (rustup target add x86_64-linux-android ...) and ANDROID_NDK_HOME.
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
targets=""
for abi in ${ABIS:-x86_64}; do
    targets="$targets -t $abi"
done
# shellcheck disable=SC2086
cargo ndk $targets -o bindings/android/build/jniLibs build --release -p yggdrasil-uniffi "$@"
