# Integration

This document explains how to add DFC core to a C project.

## 1. Add the source files

Add these include directories:

```text
dfc-core/src
dfc-core/port
```

Compile all `.c` files in `dfc-core/src`. Each file compiles to nothing when
the build role or profile leaves its feature out, so the source list never
changes with the configuration.

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

## 5. Select a build role

Set `DFC_BUILD_ROLE` to choose which parts of the library a build carries. The
role is independent of the profile: the profile selects a card generation, and
the role selects the halves of the library.

| Role | Carries | Use |
|---|---|---|
| `DFC_ROLE_TARGET` | Emulator, `.dfcb` decoder and encoder | The card itself, on a device |
| `DFC_ROLE_HOST` | Reader, command encoder, `.dfc` and `.dfcb` | A client that drives a card |
| `DFC_ROLE_SIMULATOR` | Everything | A workstation that runs the card and drives it |

The default value is `DFC_ROLE_SIMULATOR`.

A target never parses text. A host compiles `.dfc` to `.dfcb` with
`dfc_text_parse` and `dfc_der_encode`, then loads the octets onto the target,
which reads them with `dfc_der_decode`. A target that never dumps its
credential can also drop the encoder:

```sh
-DDFC_BUILD_ROLE=DFC_ROLE_TARGET -DDFC_ENABLE_DER_ENCODER=0
```

These macros override single parts of a role:

| Macro | Part |
|---|---|
| `DFC_ENABLE_EMULATOR` | The card emulator and the virtual PICC |
| `DFC_ENABLE_READER` | The reader session and the command encoder |
| `DFC_ENABLE_DER_DECODER` | `dfc_der_decode` and `dfc_der_length` |
| `DFC_ENABLE_DER_ENCODER` | `dfc_der_encode` and `dfc_der_encoded_size` |
| `DFC_ENABLE_TEXT_CODEC` | `dfc_text_*` and `dfc_credential_load`. It requires both directions of `.dfcb` |
| `DFC_ENABLE_BINARY_CODEC` | Both directions of `.dfcb` at once. It is kept for older builds |

A declaration is visible only when its part is built, so a call into an omitted
part fails at compile time.

Storage for the credential model is fixed at compile time. Override
`DFC_FILE_POOL_SIZE`, `DFC_KEY_POOL_SIZE`, `DFC_MAX_APPS`, `DFC_MAX_FILES`, and
`DFC_MAX_KEYS` in the same way to trade memory against card capacity.

## 6. Verify the integration

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
