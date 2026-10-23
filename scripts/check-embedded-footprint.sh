#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
build_dir=${DFC_FOOTPRINT_BUILD_DIR:-"$repo_root/build-embedded-footprint"}
tiny_dir=${TINY_CRYPTO_DIR:-}
cc=${ARM_NONE_EABI_CC:-arm-none-eabi-gcc}
tool_prefix=${cc%gcc}
ld=${tool_prefix}ld
nm=${tool_prefix}nm
size=${tool_prefix}size

readonly toolchain_release=13.3.Rel1
readonly toolchain_version=13.3.1
readonly target_triple=arm-none-eabi
readonly tiny_revision=64fccd69ae2405574575f971f8b72f5e3e403f56

if [[ -z "$tiny_dir" || ! -f "$tiny_dir/src/aes.c" ]]; then
    echo "TINY_CRYPTO_DIR must name the pinned tiny-crypto-c checkout" >&2
    exit 2
fi
tiny_dir=$(cd "$tiny_dir" && pwd -P)
if [[ $(git -C "$tiny_dir" rev-parse HEAD) != "$tiny_revision" ]] ||
    [[ -n $(git -C "$tiny_dir" status --porcelain --untracked-files=all -- src) ]]; then
    echo "tiny-crypto-c must be a clean checkout at $tiny_revision" >&2
    exit 2
fi

toolchain_banner=$($cc --version | sed -n '1p')
if [[ $($cc -dumpfullversion) != "$toolchain_version" ]] ||
    [[ $($cc -dumpmachine) != "$target_triple" ]] ||
    [[ $toolchain_banner != *"Arm GNU Toolchain $toolchain_release"* ]]; then
    echo "Arm GNU Toolchain $toolchain_release for $target_triple is required" >&2
    "$cc" --version >&2
    exit 2
fi

cmake --fresh -S "$repo_root" -B "$build_dir" \
    -DCMAKE_SYSTEM_NAME=Generic \
    -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
    -DCMAKE_C_COMPILER="$cc" \
    -DCMAKE_BUILD_TYPE=MinSizeRel \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DCMAKE_C_FLAGS="-mcpu=cortex-m4 -mthumb -mfloat-abi=soft -ffunction-sections -fdata-sections -fstack-usage" \
    -DDFC_ROLE=target \
    -DDFC_PROFILE=full_ev3 \
    -DDFC_CRYPTO=tiny \
    -DDFC_TINY_CRYPTO_DIR="$tiny_dir" \
    -DDFC_BUILD_SHARED=OFF \
    -DDFC_BUILD_STATIC_FFI=OFF \
    -DDFC_BUILD_RUST_TARGET_BRIDGE=OFF \
    -DDFC_BUILD_TESTS=OFF \
    -DDFC_BUILD_JNI=OFF \
    -DDFC_BUILD_FOOTPRINT_PROBE=ON
cmake --build "$build_dir" --target dfc_core dfc_footprint_probe

if grep -q -- '-fPIC' "$build_dir/compile_commands.json"; then
    echo "target objects unexpectedly use position-independent code" >&2
    exit 2
fi

object_root="$build_dir/CMakeFiles/dfc_objects.dir"
core_objects=()
tiny_objects=()
stack_files=()
while IFS= read -r object; do
    core_objects[${#core_objects[@]}]=$object
done < <(find "$object_root/src" -type f \( -name '*.o' -o -name '*.obj' \) | sort)
while IFS= read -r object; do
    tiny_objects[${#tiny_objects[@]}]=$object
done < <(find "$object_root" -type f \( -name '*.o' -o -name '*.obj' \) ! -path "$object_root/src/*" | sort)
while IFS= read -r usage; do
    stack_files[${#stack_files[@]}]=$usage
done < <(find "$object_root" -type f -name '*.su' | sort)

if ((${#core_objects[@]} == 0 || ${#tiny_objects[@]} != 6)); then
    echo "CMake did not produce the expected core and tiny objects" >&2
    exit 2
fi
expected_stack_files=$((${#core_objects[@]} + ${#tiny_objects[@]}))
if ((${#stack_files[@]} != expected_stack_files)); then
    echo "CMake produced ${#stack_files[@]} stack-usage files for $expected_stack_files objects" >&2
    exit 2
fi

"$ld" -r -o "$build_dir/dfc-core.o" "${core_objects[@]}"
"$ld" -r -o "$build_dir/tiny-crypto-c.o" "${tiny_objects[@]}"
"$ld" -r -o "$build_dir/full-ev3-tiny.o" "${core_objects[@]}" "${tiny_objects[@]}"

object_sizes() {
    "$size" "$1" | awk 'NR == 2 { print $1, $2, $3 }'
}

read -r core_text core_data core_bss < <(object_sizes "$build_dir/dfc-core.o")
read -r tiny_text tiny_data tiny_bss < <(object_sizes "$build_dir/tiny-crypto-c.o")
read -r linked_text linked_data linked_bss < <(object_sizes "$build_dir/full-ev3-tiny.o")
stack_report=$(python3 "$repo_root/scripts/check-stack-usage.py" \
    --expected-file-count "$expected_stack_files" "${stack_files[@]}")
max_stack=$(printf '%s\n' "$stack_report" | sed -n '1p')

probe_object=
while IFS= read -r object; do
    probe_object=$object
    break
done < <(find "$build_dir/CMakeFiles/dfc_footprint_probe.dir" \
    -type f \( -name '*.o' -o -name '*.obj' \))
if [[ -z "$probe_object" ]]; then
    echo "CMake did not produce the footprint probe object" >&2
    exit 2
fi

symbol_size() {
    local name=$1
    local hex
    hex=$($nm -S "$probe_object" | awk -v wanted="$name" '$4 == wanted { print $2 }')
    if [[ -z "$hex" ]]; then
        echo "footprint probe did not emit $name" >&2
        exit 2
    fi
    printf '%d\n' "$((16#$hex))"
}

size_application=$(symbol_size dfc_footprint_DfcApplication)
size_credential=$(symbol_size dfc_footprint_DfcCredential)
size_emulator=$(symbol_size dfc_footprint_DfcEmulator)
size_file=$(symbol_size dfc_footprint_DfcFile)
size_secure_messaging=$(symbol_size dfc_footprint_DfcSecureMessaging)
size_virtual_picc=$(symbol_size dfc_footprint_DfcVirtualPiccSession)
capacity_apps=$(symbol_size dfc_footprint_application_capacity)
capacity_files=$(symbol_size dfc_footprint_file_capacity)
capacity_keys=$(symbol_size dfc_footprint_key_capacity)
capacity_file_pool=$(symbol_size dfc_footprint_file_pool)
capacity_key_pool=$(symbol_size dfc_footprint_key_pool)
capacity_file_data=$(symbol_size dfc_footprint_max_file_data)

# Measured record transport and timer lifecycle with Arm GNU 13.3.Rel1.
readonly max_core_text=58454
readonly max_core_data=0
readonly max_core_bss=0
readonly max_tiny_text=5496
readonly max_tiny_data=0
readonly max_tiny_bss=0
readonly max_linked_text=63950
readonly max_linked_data=0
readonly max_linked_bss=0
readonly max_static_stack=1472

{
    echo "core_revision=$(git -C "$repo_root" rev-parse HEAD)"
    echo "tiny_revision=$tiny_revision"
    echo "toolchain_release=$toolchain_release"
    echo "toolchain_version=$toolchain_version"
    echo "toolchain_target=$target_triple"
    echo "target=cortex-m4"
    echo "instruction_set=thumb"
    echo "float_abi=soft"
    echo "cmake_build_type=MinSizeRel"
    echo "optimization=-Os"
    echo "profile=full_ev3"
    echo "role=target"
    echo "backend=tiny"
    echo "core_text=$core_text"
    echo "core_data=$core_data"
    echo "core_bss=$core_bss"
    echo "tiny_text=$tiny_text"
    echo "tiny_data=$tiny_data"
    echo "tiny_bss=$tiny_bss"
    echo "linked_text=$linked_text"
    echo "linked_data=$linked_data"
    echo "linked_bss=$linked_bss"
    echo "maximum_static_frame=$max_stack"
    echo
    echo "public structures and capacities (bytes or element count)"
    echo "dfc_footprint_DfcApplication=$size_application"
    echo "dfc_footprint_DfcCredential=$size_credential"
    echo "dfc_footprint_DfcEmulator=$size_emulator"
    echo "dfc_footprint_DfcFile=$size_file"
    echo "dfc_footprint_DfcSecureMessaging=$size_secure_messaging"
    echo "dfc_footprint_DfcVirtualPiccSession=$size_virtual_picc"
    echo "dfc_footprint_application_capacity=$capacity_apps"
    echo "dfc_footprint_file_capacity=$capacity_files"
    echo "dfc_footprint_key_capacity=$capacity_keys"
    echo "dfc_footprint_file_pool=$capacity_file_pool"
    echo "dfc_footprint_key_pool=$capacity_key_pool"
    echo "dfc_footprint_max_file_data=$capacity_file_data"
    echo
    echo "per-object text, data and BSS"
    "$size" "${core_objects[@]}" "${tiny_objects[@]}" | \
        sed -e "s|$build_dir/||g" -e "s|$repo_root/||g" -e "s|$tiny_dir/|/tiny-crypto-c/|g"
    echo
    echo "largest static frames"
    printf '%s\n' "$stack_report" | sed -n '2,21p' | \
        sed -e "s|$repo_root/||g" -e "s|$tiny_dir/|tiny-crypto-c/|g"
} | tee "$build_dir/report.txt"

status=0
check_maximum() {
    local label=$1 actual=$2 maximum=$3
    if ((actual > maximum)); then
        echo "$label grew from $maximum to $actual" >&2
        status=1
    fi
}
check_exact() {
    local label=$1 actual=$2 expected=$3
    if ((actual != expected)); then
        echo "$label changed from $expected to $actual" >&2
        status=1
    fi
}

check_maximum core_text "$core_text" "$max_core_text"
check_maximum core_data "$core_data" "$max_core_data"
check_maximum core_bss "$core_bss" "$max_core_bss"
check_maximum tiny_text "$tiny_text" "$max_tiny_text"
check_maximum tiny_data "$tiny_data" "$max_tiny_data"
check_maximum tiny_bss "$tiny_bss" "$max_tiny_bss"
check_maximum linked_text "$linked_text" "$max_linked_text"
check_maximum linked_data "$linked_data" "$max_linked_data"
check_maximum linked_bss "$linked_bss" "$max_linked_bss"
check_maximum maximum_static_frame "$max_stack" "$max_static_stack"
check_maximum DfcApplication "$size_application" 360
check_maximum DfcCredential "$size_credential" 28512
check_maximum DfcEmulator "$size_emulator" 3272
check_maximum DfcFile "$size_file" 180
check_maximum DfcSecureMessaging "$size_secure_messaging" 52
check_maximum DfcVirtualPiccSession "$size_virtual_picc" 364
check_exact application_capacity "$capacity_apps" 28
check_exact file_capacity "$capacity_files" 32
check_exact key_capacity "$capacity_keys" 14
check_exact file_pool "$capacity_file_pool" 8192
check_exact key_pool "$capacity_key_pool" 4096
check_exact maximum_file_data "$capacity_file_data" 2048
exit "$status"
