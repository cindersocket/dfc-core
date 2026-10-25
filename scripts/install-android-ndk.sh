#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
properties="$repo_root/bindings/android/gradle.properties"
ndk_version="$(sed -n 's/^dfc\.ndkVersion=//p' "$properties")"

case "$ndk_version" in
    "" | *[!0-9.]*)
        echo "invalid dfc.ndkVersion in $properties" >&2
        exit 1
        ;;
esac

: "${ANDROID_SDK_ROOT:?ANDROID_SDK_ROOT must name the Android SDK directory}"
sdkmanager_command="${SDKMANAGER:-sdkmanager}"
attempt=1
max_attempts=3

while ! "$sdkmanager_command" --sdk_root="$ANDROID_SDK_ROOT" "ndk;$ndk_version"; do
    if ((attempt >= max_attempts)); then
        exit 1
    fi
    rm -rf "$ANDROID_SDK_ROOT/ndk/$ndk_version"
    attempt=$((attempt + 1))
done
