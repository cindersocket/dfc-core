#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

# Keep this directory-based so newly added maintained C files join the gate.
# munit is vendored; generated bindings and unrelated languages live elsewhere.
git ls-files -z -- \
    ':(glob)src/**/*.[ch]' \
    ':(glob)ffi/**/*.[ch]' \
    ':(glob)port/**/*.[ch]' \
    ':(glob)bindings/jni/**/*.[ch]' \
    ':(glob)tests/**/*.[ch]' \
    ':(exclude,glob)tests/munit/**' \
    | xargs -0 uvx --from clang-format==21.1.7 clang-format --dry-run --Werror
