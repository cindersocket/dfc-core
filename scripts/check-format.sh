#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

git ls-files -z 'ffi/*.c' 'ffi/*.h' 'bindings/jni/*.c' \
    | xargs -0 uvx --from clang-format==21.1.7 clang-format --dry-run --Werror
git ls-files -z 'bindings/java/**/*.java' 'bindings/android/**/*.java' \
    'examples/java/*.java' 'examples/java/**/*.java' 'examples/android/**/*.java' \
    | xargs -0 uvx --from clang-format==21.1.7 clang-format --dry-run --Werror
dotnet format bindings/dotnet/Dfc.sln --verify-no-changes
dotnet format examples/dotnet/Dfc.TransceiveExample.csproj --verify-no-changes
(cd bindings/python && uv run --frozen --extra test ruff format --check src tests ../../examples/python)
(cd bindings/python && uv run --frozen --extra test ruff check src tests ../../examples/python)
cargo fmt --all -- --check
cargo fmt --manifest-path examples/rust-virtual-picc/Cargo.toml -- --check
