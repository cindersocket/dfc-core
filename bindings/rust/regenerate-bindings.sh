#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
bindgen "$repo/ffi/dfc_ffi.h" \
    --allowlist-function 'dfc_.*' \
    --allowlist-type 'DfcFfi.*' \
    --allowlist-var 'DFC_FFI_.*' \
    --use-core \
    --no-layout-tests \
    --with-derive-default \
    --output "$repo/bindings/rust/dfc-core-sys/src/bindings.rs"
