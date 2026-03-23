#!/bin/sh
# GCC wrapper that resolves bare CRT object filenames to full paths.
# Fixes cross-rs/cross#1422: rustc passes -nostartfiles with bare CRT
# filenames that GCC cannot find without its normal search logic.
REAL_GCC="$(basename "$CROSS_MUSL_SYSROOT")-gcc"
for arg in "$@"; do
    case "$arg" in
        crt*.o|Scrt*.o|rcrt*.o) set -- "$@" "$($REAL_GCC -print-file-name="$arg")" ;;
        *) set -- "$@" "$arg" ;;
    esac
    shift
done
exec "$REAL_GCC" "$@"
