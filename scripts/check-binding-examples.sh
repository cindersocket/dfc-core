#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

build=$(mktemp -d "${TMPDIR:-/tmp}/dfc-binding-examples.XXXXXX")
cleanup() {
    status=$?
    rm -rf "$build"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM
cmake -S . -B "$build" -DDFC_BUILD_TESTS=OFF \
    -DDFC_CRYPTO="${DFC_EXAMPLE_CRYPTO:-mbedtls}"
cmake --build "$build" --parallel
library=$(find "$build" -type f \( -name 'libdfc*.so' -o -name 'libdfc*.dylib' -o -name 'libdfc*.dll' \) \
    -print -quit)
test -n "$library"

DFC_LIBRARY_PATH="$library" uv run --project bindings/python --frozen \
    python examples/python/virtual_card.py
DFC_LIBRARY_PATH="$library" uv run --project bindings/python --frozen \
    python examples/python/verify_backend.py
cargo run --quiet --manifest-path examples/rust-virtual-picc/Cargo.toml \
    --bin dfc-rust-virtual-picc-example -- examples/credentials/v6-minimal.dfcb
cargo run --quiet --manifest-path examples/rust-virtual-picc/Cargo.toml --bin verify_backend
