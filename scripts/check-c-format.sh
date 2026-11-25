#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

# Keep this directory-based so newly added maintained C files join the gate.
# munit is vendored; generated bindings and unrelated languages live elsewhere.
find src ffi port bindings/jni tests -type f \( -name '*.c' -o -name '*.h' \) \
    ! -path 'tests/munit/*' -print0 \
    | xargs -0 uvx --from clang-format==22.1.8 clang-format --dry-run --Werror
