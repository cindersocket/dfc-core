# Integration

This document explains how to add DFC core to a C project.

## 1. Add the source files

Add these include directories:

```text
dfc-core/src
dfc-core/port
```

Compile all `.c` files in `dfc-core/src`.

## 2. Add a platform port

Implement the interfaces in these headers:

- `port/dfc_port.h` provides assertions, logging, random data, memory, and user
  notifications.
- `port/dfc_bytebuf.h` provides an append-only byte buffer.

Do not use a predictable random generator. DESFire authentication requires
unpredictable random data.

For a hosted build, compile these example files:

```text
port/host/dfc_port_host.c
port/host/dfc_bytebuf_host.c
```

## 3. Select a crypto backend

For mbedTLS 3.x, compile with:

```sh
-DDFC_CRYPTO_BACKEND_MBEDTLS=1
```

Link `libmbedcrypto`, or compile the target's mbedTLS AES and DES sources.
mbedTLS 4 removed DES, so DFC requires mbedTLS 3.x.

For tiny-crypto-c, compile `src/aes.c`, `src/des.c`, and `src/common.c` and use:

```sh
-DDFC_CRYPTO_BACKEND_TINY=1 -I/path/to/tiny-crypto-c/src \
-DTC_ENABLE_AES=1 -DTC_AES_ENABLE_CBC=1 -DTC_AES_ENABLE_CTR=0 \
-DTC_ENABLE_DES=1 -DTC_DES_ENABLE_ECB=1 -DTC_DES_ENABLE_CBC=1 \
-DTC_DES_ENABLE_CTR=0 -DTC_DES_ENABLE_TDES=1 -DTC_ENABLE_SHA256=0
```

Select exactly one backend. The tiny-crypto-c feature macros must match across
DFC and the library sources because they affect context layouts.

## 4. Select a feature profile

Set `DFC_BUILD_PROFILE` to one value from `src/dfc_build_config.h`. The default
value is `DFC_PROFILE_FULL_EV3`.

Example:

```sh
-DDFC_BUILD_PROFILE=DFC_PROFILE_FULL_EV2
```

You can override individual `DFC_ENABLE_*` macros. The header checks invalid
feature combinations during compilation.

## 5. Verify the integration

Run the host tests before you build for the target:

```sh
make -C tests test
```

On the target, verify these items:

- The random-data function returns unpredictable data.
- Allocation failures have the required product behavior.
- Assertions have the required product behavior.
- AES, DES, 2-key 3DES, and 3-key 3DES authentication pass known vectors.
- Sensitive log output is disabled in production.
