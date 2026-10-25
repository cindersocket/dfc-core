#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

./scripts/check-c-format.sh
python3 scripts/generate-ffi-layout.py --check
git ls-files -z 'bindings/java/**/*.java' 'bindings/android/**/*.java' \
    'examples/java/*.java' 'examples/java/**/*.java' 'examples/android/**/*.java' \
    | xargs -0 uvx --from clang-format==21.1.7 clang-format --dry-run --Werror
dotnet format whitespace bindings/dotnet/Dfc.sln --verify-no-changes
dotnet format whitespace examples/dotnet/Dfc.TransceiveExample.csproj --verify-no-changes
python_paths="bindings/python/src bindings/python/tests examples/python scripts tests"
uvx --from ruff==0.17.1 ruff format --check \
    --config bindings/python/pyproject.toml \
    --config "src = ['bindings/python/src']" $python_paths
uvx --from ruff==0.17.1 ruff check \
    --config bindings/python/pyproject.toml \
    --config "src = ['bindings/python/src']" $python_paths
cargo fmt --all -- --check
cargo fmt --manifest-path examples/rust-virtual-picc/Cargo.toml -- --check
