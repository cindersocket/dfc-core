#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
tiny_dir=${DFC_TINY_CRYPTO_DIR:-"$repo_root/../../third_party/tiny-crypto-c"}
build_root=$(mktemp -d "${TMPDIR:-/tmp}/dfc-cipher-matrix.XXXXXX")
trap 'rm -rf "$build_root"' EXIT

build_case() {
    local name=$1
    local features=$2
    local expect_aes=$3
    local expect_des=$4
    local build_dir="$build_root/$name"

    cmake -S "$repo_root" -B "$build_dir" \
        -DDFC_ROLE=target \
        -DDFC_PROFILE=minimal_ev1 \
        -DDFC_CRYPTO=tiny \
        -DDFC_TINY_CRYPTO_DIR="$tiny_dir" \
        -DDFC_BUILD_SHARED=OFF \
        -DDFC_BUILD_TESTS=ON \
        -DDFC_FEATURE_DEFINITIONS="$features" >/dev/null
    cmake --build "$build_dir" --parallel >/dev/null
    ctest --test-dir "$build_dir" --output-on-failure

    local archive="$build_dir/libdfc_core.a"
    local has_aes=0
    local has_des=0
    nm -g "$archive" | grep -Eq ' T _?TC_AES_init$' && has_aes=1
    nm -g "$archive" | grep -Eq ' T _?TC_DES_init$' && has_des=1
    test "$has_aes" -eq "$expect_aes"
    test "$has_des" -eq "$expect_des"
}

build_case des-only \
    'DFC_ENABLE_AUTH_D40=1;DFC_ENABLE_AUTH_ISO=0;DFC_ENABLE_AUTH_AES=0;DFC_ENABLE_ISO7816=0;DFC_ENABLE_ISO7816_AUTH=0' \
    0 1
build_case aes-only \
    'DFC_ENABLE_AUTH_D40=0;DFC_ENABLE_AUTH_ISO=0;DFC_ENABLE_AUTH_AES=1;DFC_ENABLE_ISO7816=0;DFC_ENABLE_ISO7816_AUTH=0' \
    1 0
build_case neither \
    'DFC_ENABLE_AUTH_D40=0;DFC_ENABLE_AUTH_ISO=0;DFC_ENABLE_AUTH_AES=0;DFC_ENABLE_ISO7816=0;DFC_ENABLE_ISO7816_AUTH=0' \
    0 0

# The release profile remains the control: both families and both KATs run.
full_build="$build_root/full"
cmake -S "$repo_root" -B "$full_build" \
    -DDFC_ROLE=target -DDFC_PROFILE=full_ev3 -DDFC_CRYPTO=tiny \
    -DDFC_TINY_CRYPTO_DIR="$tiny_dir" -DDFC_BUILD_SHARED=OFF -DDFC_BUILD_TESTS=ON >/dev/null
cmake --build "$full_build" --parallel >/dev/null
ctest --test-dir "$full_build" --output-on-failure
nm -g "$full_build/libdfc_core.a" | grep -Eq ' T _?TC_AES_init$'
nm -g "$full_build/libdfc_core.a" | grep -Eq ' T _?TC_DES_init$'
