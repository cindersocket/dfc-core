#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

git ls-files -z 'ffi/*.c' 'ffi/*.h' 'bindings/jni/*.c' \
    | xargs -0 clang-format --dry-run --Werror
git ls-files -z 'bindings/java/**/*.java' 'bindings/android/**/*.java' \
    | xargs -0 clang-format --dry-run --Werror
dotnet format bindings/dotnet/Dfc.sln --verify-no-changes
(cd bindings/python && uv run --frozen --extra test ruff format --check src tests)
cargo fmt --all -- --check
