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
(cd bindings/python && uv run --frozen --extra test ruff format --check \
    src tests ../../examples/python ../../scripts/check-docs.py \
    ../../scripts/check-cmake-pic.py ../../scripts/check-stack-usage.py \
    ../../scripts/check-version.py ../../scripts/checksums.py \
    ../../scripts/release-notes.py \
    ../../tests/test_check_docs.py ../../tests/test_check_stack_usage.py \
    ../../tests/test_cargo_package.py ../../tests/test_ci_unit_workflow.py \
    ../../tests/test_check_version.py \
    ../../tests/test_checksums.py ../../tests/test_release_process.py)
(cd bindings/python && uv run --frozen --extra test ruff check \
    src tests ../../examples/python ../../scripts/check-docs.py \
    ../../scripts/check-cmake-pic.py ../../scripts/check-stack-usage.py \
    ../../scripts/check-version.py ../../scripts/checksums.py \
    ../../scripts/release-notes.py \
    ../../tests/test_check_docs.py ../../tests/test_check_stack_usage.py \
    ../../tests/test_cargo_package.py ../../tests/test_ci_unit_workflow.py \
    ../../tests/test_check_version.py \
    ../../tests/test_checksums.py ../../tests/test_release_process.py)
cargo fmt --all -- --check
cargo fmt --manifest-path examples/rust-virtual-picc/Cargo.toml -- --check
