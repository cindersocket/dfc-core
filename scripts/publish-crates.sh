#!/usr/bin/env bash
set -euo pipefail

version=$(python3 -c 'import json; print(json.load(open("release-artifacts.json"))["version"])')
: "${CARGO_REGISTRY_TOKEN:?Cargo registry token is required}"
root=${1:?usage: publish-crates.sh VERIFIED_ARTIFACT_DIRECTORY}

published() {
    curl --fail --silent --show-error --user-agent "dfc-core-release/$version" \
        "https://crates.io/api/v1/crates/$1/$version" >/dev/null
}

publish() {
    local package=$1
    if published "$package"; then
        echo "$package $version is already published"
    else
        python3 scripts/publish-crate.py "$root/$package-$version.crate"
    fi
}

publish dfc-core-sys
for _ in {1..30}; do
    if published dfc-core-sys; then
        break
    fi
    sleep 10
done
published dfc-core-sys
publish dfc-core
