#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
output_dir=${DFC_COVERAGE_DIR:-"$repo_root/build-native-coverage"}
requested_work_dir=${DFC_COVERAGE_WORK_DIR:-}

if [[ -n "$requested_work_dir" ]]; then
    work_dir=$requested_work_dir
    if [[ -e "$work_dir" ]]; then
        echo "DFC_COVERAGE_WORK_DIR must name a path that does not exist: $work_dir" >&2
        exit 2
    fi
    mkdir -p "$work_dir"
    cleanup=false
else
    work_dir=$(mktemp -d "${TMPDIR:-/tmp}/dfc-native-coverage.XXXXXX")
    cleanup=true
fi
trap 'if [[ $cleanup == true ]]; then rm -rf "$work_dir"; fi' EXIT

mkdir -p "$output_dir"

# Copy the live tree, including uncommitted work, while keeping every generated
# executable and profile outside the developer's active test directory.
tar -C "$repo_root" \
    --exclude=.git \
    --exclude=build-native-coverage \
    -cf - . | tar -C "$work_dir" -xf -

make -C "$work_dir/tests" clean
make -C "$work_dir/tests" coverage COVERAGE_DIR="$output_dir" CC=clang
