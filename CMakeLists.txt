# Library build for DFC core.
#
# The Makefile under tests/ runs the unit suites. This build produces the
# library a product links: a static archive of the core for C projects, and
# the shared library with the flat interface in ffi/ that foreign runtimes
# load.
#
#   cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
#   cmake --build build
#   ctest --test-dir build

cmake_minimum_required(VERSION 3.24)
project(dfc-core VERSION 2.0.0 LANGUAGES C)

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(DFC_ROLE "simulator" CACHE STRING "Build role: target, host or simulator")
set_property(CACHE DFC_ROLE PROPERTY STRINGS target host simulator)
set(DFC_PROFILE "full_ev3" CACHE STRING
    "Feature profile: minimal_ev1, full_ev1, full_ev2, full_ev3 or minimal_ev3")
set_property(CACHE DFC_PROFILE PROPERTY STRINGS minimal_ev1 full_ev1 full_ev2 full_ev3 minimal_ev3)
set(DFC_CRYPTO "tiny" CACHE STRING "Crypto backend: tiny (tiny-crypto-c) or mbedtls (mbedTLS 3.x)")
set_property(CACHE DFC_CRYPTO PROPERTY STRINGS tiny mbedtls)
set(DFC_TINY_CRYPTO_DIR "" CACHE PATH
    "A tiny-crypto-c checkout to build from; empty fetches the pinned release")
if(DFC_ROLE STREQUAL "target")
    set(DFC_DEFAULT_BUILD_SHARED OFF)
else()
    set(DFC_DEFAULT_BUILD_SHARED ON)
endif()
option(DFC_BUILD_SHARED "Build the shared library with the flat interface" ${DFC_DEFAULT_BUILD_SHARED})
option(DFC_BUILD_STATIC_FFI "Build a static library with the flat interface" OFF)
option(DFC_BUILD_RUST_TARGET_BRIDGE "Build the allocation-neutral Rust target bridge" OFF)
option(DFC_BUILD_TESTS "Build the smoke test for the shared library" ${DFC_BUILD_SHARED})
option(DFC_BUILD_JNI "Build the self-contained Java/Android JNI library" OFF)
option(DFC_BUILD_FOOTPRINT_PROBE "Build the embedded footprint metadata probe" OFF)
# Workstation sizes for the credential model. A device build keeps the small
# defaults in dfc_common.h.
if(DFC_ROLE STREQUAL "target")
    set(DFC_DEFAULT_HOST_CAPACITY OFF)
else()
    set(DFC_DEFAULT_HOST_CAPACITY ON)
endif()

option(DFC_HOST_CAPACITY "Size the credential model for a workstation" ${DFC_DEFAULT_HOST_CAPACITY})
set(DFC_FEATURE_DEFINITIONS "" CACHE STRING
    "Semicolon-separated DFC_ENABLE_* overrides, each ending in =0 or =1")

string(TOUPPER "${DFC_ROLE}" DFC_ROLE_UPPER)
string(TOUPPER "${DFC_PROFILE}" DFC_PROFILE_UPPER)

set(DFC_CORE_SOURCES
    src/dfc_an10922.c
    src/dfc_command.c
    src/dfc_common.c
    src/dfc_credential.c
    src/dfc_crypto.c
    src/dfc_crypto_disabled.c
    src/dfc_der.c
    src/dfc_emulator.c
    src/dfc_emulator_access.c
    src/dfc_emulator_commands.c
    src/dfc_emulator_commands_auth.c
    src/dfc_emulator_commands_data.c
    src/dfc_emulator_commands_keys.c
    src/dfc_emulator_commands_lifecycle.c
    src/dfc_emulator_commands_metadata.c
    src/dfc_emulator_commands_proximity.c
    src/dfc_emulator_commands_records.c
    src/dfc_emulator_commands_transactions.c
    src/dfc_emulator_crypto.c
    src/dfc_emulator_iso7816.c
    src/dfc_ev2.c
    src/dfc_ev2_crypto.c
    src/dfc_profile.c
    src/dfc_reader.c
    src/dfc_response.c
    src/dfc_sdm.c
    src/dfc_secure_messaging.c
    src/dfc_text.c
    src/dfc_transaction_mac.c
    src/dfc_virtual_picc.c)

set(DFC_DEFINITIONS
    DFC_BUILD_ROLE=DFC_ROLE_${DFC_ROLE_UPPER}
    DFC_BUILD_PROFILE=DFC_PROFILE_${DFC_PROFILE_UPPER})
foreach(DFC_FEATURE_DEFINITION IN LISTS DFC_FEATURE_DEFINITIONS)
    if(NOT DFC_FEATURE_DEFINITION MATCHES "^DFC_ENABLE_[A-Z0-9_]+=[01]$")
        message(FATAL_ERROR "Invalid feature override: ${DFC_FEATURE_DEFINITION}")
    endif()
    list(APPEND DFC_DEFINITIONS ${DFC_FEATURE_DEFINITION})
endforeach()

# Resolve the feature values that decide which cipher families are reachable.
# Keep this beside DFC_DEFINITIONS so profile defaults and explicit overrides
# cannot select different source sets.
set(DFC_PROFILE_FULL_EV1 OFF)
set(DFC_PROFILE_EV2 OFF)
set(DFC_PROFILE_EV3 OFF)
if(DFC_PROFILE STREQUAL "full_ev1" OR DFC_PROFILE STREQUAL "full_ev2" OR
   DFC_PROFILE STREQUAL "full_ev3")
    set(DFC_PROFILE_FULL_EV1 ON)
endif()
if(DFC_PROFILE STREQUAL "full_ev2" OR DFC_PROFILE STREQUAL "full_ev3")
    set(DFC_PROFILE_EV2 ON)
endif()
if(DFC_PROFILE STREQUAL "full_ev3" OR DFC_PROFILE STREQUAL "minimal_ev3")
    set(DFC_PROFILE_EV3 ON)
endif()

function(dfc_resolve_feature name default_value output)
    set(value "${default_value}")
    foreach(definition IN LISTS DFC_FEATURE_DEFINITIONS)
        if(definition MATCHES "^${name}=([01])$")
            set(value "${CMAKE_MATCH_1}")
        endif()
    endforeach()
    set(${output} "${value}" PARENT_SCOPE)
endfunction()

dfc_resolve_feature(DFC_ENABLE_AUTH_D40 1 DFC_FEATURE_AUTH_D40)
dfc_resolve_feature(DFC_ENABLE_AUTH_ISO ${DFC_PROFILE_FULL_EV1} DFC_FEATURE_AUTH_ISO)
dfc_resolve_feature(DFC_ENABLE_AUTH_AES ${DFC_PROFILE_FULL_EV1} DFC_FEATURE_AUTH_AES)
dfc_resolve_feature(DFC_ENABLE_ISO7816 ${DFC_PROFILE_FULL_EV1} DFC_FEATURE_ISO7816)
dfc_resolve_feature(DFC_ENABLE_ISO7816_AUTH ${DFC_FEATURE_ISO7816} DFC_FEATURE_ISO7816_AUTH)
dfc_resolve_feature(DFC_ENABLE_EV2_SECURE_MESSAGING ${DFC_PROFILE_EV2} DFC_FEATURE_EV2_SM)
dfc_resolve_feature(DFC_ENABLE_TRANSACTION_MAC ${DFC_PROFILE_EV2} DFC_FEATURE_TRANSACTION_MAC)
dfc_resolve_feature(DFC_ENABLE_SDM 0 DFC_FEATURE_SDM)
if(DFC_PROFILE STREQUAL "full_ev3")
    dfc_resolve_feature(DFC_ENABLE_SDM 1 DFC_FEATURE_SDM)
endif()
dfc_resolve_feature(DFC_ENABLE_PROXIMITY_CHECK ${DFC_PROFILE_EV3} DFC_FEATURE_PROXIMITY)
dfc_resolve_feature(DFC_ENABLE_VIRTUAL_CARD ${DFC_PROFILE_EV2} DFC_FEATURE_VIRTUAL_CARD)
dfc_resolve_feature(DFC_ENABLE_KEY_SETS ${DFC_PROFILE_EV2} DFC_FEATURE_KEY_SETS)
dfc_resolve_feature(DFC_ENABLE_DELEGATED_APPLICATIONS ${DFC_PROFILE_EV2} DFC_FEATURE_DELEGATED)

set(DFC_NEEDS_AES OFF)
foreach(feature IN ITEMS DFC_FEATURE_AUTH_AES DFC_FEATURE_ISO7816_AUTH DFC_FEATURE_EV2_SM
        DFC_FEATURE_TRANSACTION_MAC DFC_FEATURE_SDM DFC_FEATURE_PROXIMITY
        DFC_FEATURE_VIRTUAL_CARD DFC_FEATURE_KEY_SETS DFC_FEATURE_DELEGATED)
    if(${feature})
        set(DFC_NEEDS_AES ON)
    endif()
endforeach()
if(DFC_FEATURE_AUTH_D40 OR DFC_FEATURE_AUTH_ISO OR DFC_FEATURE_ISO7816_AUTH)
    set(DFC_NEEDS_DES ON)
else()
    set(DFC_NEEDS_DES OFF)
endif()

if(DFC_NEEDS_AES)
    list(APPEND DFC_CORE_SOURCES src/aes_cmac.c)
endif()
if(DFC_NEEDS_DES)
    list(APPEND DFC_CORE_SOURCES src/des_cmac.c src/dfc_crypto_des_chain.c)
endif()
set(DFC_HOST_MAX_FILES 512)
set(DFC_HOST_FILE_POOL_SIZE 65536)
set(DFC_HOST_KEY_POOL_SIZE 16384)
set(DFC_HOST_MAX_FILE_DATA 8192)
foreach(DFC_CAPACITY IN ITEMS
        DFC_MAX_APPS DFC_MAX_FILES DFC_MAX_KEYS DFC_FILE_POOL_SIZE
        DFC_KEY_POOL_SIZE DFC_MAX_FILE_DATA)
    string(REGEX REPLACE "^DFC_" "" DFC_CAPACITY_SUFFIX "${DFC_CAPACITY}")
    set(${DFC_CAPACITY} "" CACHE STRING "Override ${DFC_CAPACITY} for this build")
    if(NOT "${${DFC_CAPACITY}}" STREQUAL "")
        if(NOT "${${DFC_CAPACITY}}" MATCHES "^[1-9][0-9]*$")
            message(FATAL_ERROR "${DFC_CAPACITY} must be a positive integer")
        endif()
        list(APPEND DFC_DEFINITIONS ${DFC_CAPACITY}=${${DFC_CAPACITY}})
    elseif(DFC_HOST_CAPACITY AND DEFINED DFC_HOST_${DFC_CAPACITY_SUFFIX})
        list(APPEND DFC_DEFINITIONS ${DFC_CAPACITY}=${DFC_HOST_${DFC_CAPACITY_SUFFIX}})
    endif()
endforeach()

# ------------------------------------------------------------------ crypto ---

if(DFC_CRYPTO STREQUAL "tiny")
    if(DFC_TINY_CRYPTO_DIR)
        set(tiny_crypto_SOURCE_DIR "${DFC_TINY_CRYPTO_DIR}")
    else()
        include(FetchContent)
        FetchContent_Declare(tiny_crypto
            GIT_REPOSITORY https://github.com/mistial-dev/tiny-crypto-c.git
            GIT_TAG 64fccd69ae2405574575f971f8b72f5e3e403f56
            # Only the sources are used, compiled with the macros below.
            SOURCE_SUBDIR _sources_only)
        FetchContent_MakeAvailable(tiny_crypto)
    endif()
    set(DFC_CRYPTO_SOURCES
        ${tiny_crypto_SOURCE_DIR}/src/common.c
        ${tiny_crypto_SOURCE_DIR}/src/block_modes.c)
    if(DFC_NEEDS_AES)
        list(APPEND DFC_CRYPTO_SOURCES
            ${tiny_crypto_SOURCE_DIR}/src/aes.c
            ${tiny_crypto_SOURCE_DIR}/src/aes_modes.c)
    endif()
    if(DFC_NEEDS_DES)
        list(APPEND DFC_CRYPTO_SOURCES
            ${tiny_crypto_SOURCE_DIR}/src/des.c
            ${tiny_crypto_SOURCE_DIR}/src/des_modes.c)
    endif()
    set(DFC_CRYPTO_INCLUDES ${tiny_crypto_SOURCE_DIR}/src)
    list(APPEND DFC_DEFINITIONS
        DFC_CRYPTO_BACKEND_TINY=1
        TC_ENABLE_AES=$<BOOL:${DFC_NEEDS_AES}> TC_AES_ENABLE_CBC=$<BOOL:${DFC_NEEDS_AES}> TC_AES_ENABLE_CTR=0
        TC_ENABLE_DES=$<BOOL:${DFC_NEEDS_DES}> TC_DES_ENABLE_ECB=$<BOOL:${DFC_NEEDS_DES}> TC_DES_ENABLE_CBC=$<BOOL:${DFC_NEEDS_DES}> TC_DES_ENABLE_CTR=0
        TC_DES_ENABLE_TDES=1 TC_ENABLE_SHA256=0)
elseif(DFC_CRYPTO STREQUAL "mbedtls")
    find_path(DFC_MBEDTLS_INCLUDE mbedtls/des.h
        HINTS /opt/homebrew/opt/mbedtls@3/include /usr/local/opt/mbedtls@3/include)
    find_library(DFC_MBEDCRYPTO mbedcrypto
        HINTS /opt/homebrew/opt/mbedtls@3/lib /usr/local/opt/mbedtls@3/lib)
    if(NOT DFC_MBEDTLS_INCLUDE OR NOT DFC_MBEDCRYPTO)
        message(FATAL_ERROR "mbedTLS 3.x not found; set DFC_MBEDTLS_INCLUDE and DFC_MBEDCRYPTO")
    endif()
    set(DFC_CRYPTO_INCLUDES ${DFC_MBEDTLS_INCLUDE})
    set(DFC_CRYPTO_LIBRARIES ${DFC_MBEDCRYPTO})
    list(APPEND DFC_DEFINITIONS DFC_CRYPTO_BACKEND_MBEDTLS=1)
else()
    message(FATAL_ERROR "DFC_CRYPTO must be tiny or mbedtls")
endif()

if(MSVC)
    set(DFC_WARNINGS /W4 /wd4100 /wd4127 /wd4200 /wd4204 /wd4221 /wd4244 /wd4267 /wd4389)
else()
    set(DFC_WARNINGS -Wall -Wextra)
    if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
        list(APPEND DFC_WARNINGS -Werror=maybe-uninitialized)
    endif()
endif()

# -------------------------------------------------------------- libraries ---

# Compiled once, then archived for C projects that bring their own platform
# port and linked whole into the shared library.
add_library(dfc_objects OBJECT ${DFC_CORE_SOURCES} ${DFC_CRYPTO_SOURCES})
target_include_directories(dfc_objects PUBLIC src port PRIVATE ${DFC_CRYPTO_INCLUDES})
target_compile_definitions(dfc_objects PUBLIC ${DFC_DEFINITIONS})
target_compile_options(dfc_objects PRIVATE ${DFC_WARNINGS})
set_target_properties(dfc_objects PROPERTIES C_VISIBILITY_PRESET default)
if(DFC_BUILD_SHARED OR DFC_BUILD_JNI)
    set_property(TARGET dfc_objects PROPERTY POSITION_INDEPENDENT_CODE ON)
endif()

add_library(dfc_core STATIC $<TARGET_OBJECTS:dfc_objects>)
target_include_directories(dfc_core PUBLIC src port)
target_compile_definitions(dfc_core PUBLIC ${DFC_DEFINITIONS})
target_link_libraries(dfc_core PUBLIC ${DFC_CRYPTO_LIBRARIES})

if(DFC_BUILD_TESTS)
    enable_testing()
    add_executable(test_cipher_profile tests/test_cipher_profile.c)
    target_link_libraries(test_cipher_profile PRIVATE dfc_core)
    add_test(NAME cipher-profile COMMAND test_cipher_profile)
endif()

if(DFC_BUILD_FOOTPRINT_PROBE)
    add_library(dfc_footprint_probe OBJECT tests/embedded_footprint_probe.c)
    target_include_directories(dfc_footprint_probe PRIVATE src port)
    target_compile_definitions(dfc_footprint_probe PRIVATE ${DFC_DEFINITIONS})
    target_compile_options(dfc_footprint_probe PRIVATE ${DFC_WARNINGS})
endif()

set(DFC_FFI_IMPLEMENTATION_SOURCES
        ffi/dfc_ffi.c
        ffi/dfc_ffi_an10922.c
        ffi/dfc_ffi_response.c
        ffi/dfc_ffi_sdm.c
        ffi/dfc_ffi_transaction_mac.c)

set(DFC_FFI_SOURCES
        $<TARGET_OBJECTS:dfc_objects>
        ${DFC_FFI_IMPLEMENTATION_SOURCES}
        port/ffi/dfc_port_ffi.c
        port/host/dfc_bytebuf_host.c)

function(dfc_configure_ffi_target target)
    target_include_directories(${target}
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/ffi>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/port>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/dfc>
        PRIVATE port/ffi port/host)
    target_compile_definitions(
        ${target} PUBLIC ${DFC_DEFINITIONS} DFC_ENABLE_FFI=1 PRIVATE DFC_FFI_BUILD=1)
    target_compile_options(${target} PRIVATE ${DFC_WARNINGS})
    target_link_libraries(${target} PRIVATE ${DFC_CRYPTO_LIBRARIES})
    if(WIN32)
        target_link_libraries(${target} PRIVATE bcrypt)
        # Export every function, so a binding can call the plain encoders
        # (dfc_command_*) as well as the flat interface.
        set_target_properties(${target} PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
    endif()
endfunction()

if(DFC_BUILD_SHARED)
    add_library(dfc SHARED ${DFC_FFI_SOURCES})
    dfc_configure_ffi_target(dfc)
    # libdfc on every platform. On Windows a plain dfc.dll collides with the
    # managed Dfc.dll beside it: file names ignore case there, and the loader
    # hands back the already-loaded assembly instead of the native library.
    set_target_properties(dfc PROPERTIES
        PREFIX "lib"
        C_VISIBILITY_PRESET default
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR})
    install(TARGETS dfc EXPORT dfc-core-targets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
    install(FILES ffi/dfc_ffi.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/dfc)
    set(DFC_HAS_INSTALLABLE_FFI ON)

    if(DFC_BUILD_TESTS)
        add_executable(test_dfc_ffi tests/test_dfc_ffi.c)
        target_link_libraries(test_dfc_ffi PRIVATE dfc)
        add_test(NAME ffi COMMAND test_dfc_ffi)
    endif()
endif()

if(DFC_BUILD_STATIC_FFI)
    add_library(dfc_ffi_static STATIC ${DFC_FFI_SOURCES})
    dfc_configure_ffi_target(dfc_ffi_static)
    set_target_properties(dfc_ffi_static PROPERTIES OUTPUT_NAME dfc)
    if(NOT DFC_BUILD_SHARED)
        set_target_properties(dfc_ffi_static PROPERTIES EXPORT_NAME dfc)
    endif()
    install(TARGETS dfc_ffi_static EXPORT dfc-core-targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
    install(FILES ffi/dfc_ffi.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/dfc)
    set(DFC_HAS_INSTALLABLE_FFI ON)
endif()

if(DFC_HAS_INSTALLABLE_FFI)
    configure_package_config_file(
        cmake/dfc-core-config.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/dfc-core-config.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/dfc-core)
    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/dfc-core-config-version.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion)
    install(EXPORT dfc-core-targets
        FILE dfc-core-targets.cmake
        NAMESPACE dfc::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/dfc-core)
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/dfc-core-config.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/dfc-core-config-version.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/dfc-core)
endif()

if(DFC_BUILD_RUST_TARGET_BRIDGE)
    if(NOT DFC_ROLE STREQUAL "target")
        message(FATAL_ERROR "DFC_BUILD_RUST_TARGET_BRIDGE requires DFC_ROLE=target")
    endif()
    add_library(dfc_rust_target STATIC ffi/dfc_target_ffi.c)
    target_include_directories(dfc_rust_target PUBLIC ffi src port)
    target_compile_definitions(dfc_rust_target PUBLIC ${DFC_DEFINITIONS})
    target_compile_options(dfc_rust_target PRIVATE ${DFC_WARNINGS})
    target_link_libraries(dfc_rust_target PUBLIC dfc_core)
    install(TARGETS dfc_core dfc_rust_target ARCHIVE DESTINATION lib)
    install(FILES ffi/dfc_target_ffi.h DESTINATION include)
endif()

if(DFC_BUILD_JNI)
    if(NOT ANDROID)
        find_package(JNI REQUIRED)
    endif()
    add_library(dfc_jni SHARED
        $<TARGET_OBJECTS:dfc_objects>
        ${DFC_FFI_IMPLEMENTATION_SOURCES}
        port/ffi/dfc_port_ffi.c
        port/host/dfc_bytebuf_host.c
        bindings/jni/dfc_jni.c)
    target_include_directories(dfc_jni PRIVATE
        ffi src port port/ffi port/host ${JNI_INCLUDE_DIRS})
    target_compile_definitions(dfc_jni PUBLIC ${DFC_DEFINITIONS} DFC_ENABLE_FFI=1
        PRIVATE DFC_FFI_BUILD=1)
    target_compile_options(dfc_jni PRIVATE ${DFC_WARNINGS})
    # JNI calls arrive through the VM-provided function table; linking a host
    # JVM library would also prevent cross-compiling platform classifier jars.
    target_link_libraries(dfc_jni PRIVATE ${DFC_CRYPTO_LIBRARIES})
    if(WIN32)
        target_link_libraries(dfc_jni PRIVATE bcrypt)
    endif()
    set_target_properties(dfc_jni PROPERTIES C_VISIBILITY_PRESET default)
    install(TARGETS dfc_jni LIBRARY DESTINATION lib RUNTIME DESTINATION bin)

    if(DFC_BUILD_TESTS)
        enable_testing()
        add_executable(test_dfc_jni_queue tests/java/test_dfc_jni_queue.c)
        target_include_directories(test_dfc_jni_queue PRIVATE bindings/jni)
        target_compile_options(test_dfc_jni_queue PRIVATE ${DFC_WARNINGS})
        add_test(NAME jni_replay_queue COMMAND test_dfc_jni_queue)
    endif()
endif()
