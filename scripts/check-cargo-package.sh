#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

python3 tests/test_cargo_package.py
cargo publish --dry-run --locked --package dfc-core-sys "$@"
