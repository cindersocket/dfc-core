# DFC core

DFC core is a portable DESFire-compatible engine. It provides these parts:

- A credential data model
- `.dfc` text encoding and decoding
- `.dfcb` binary encoding and decoding
- Secure messaging
- A virtual card emulator
- A reader: a command encoder and secure messaging for every session kind
- A flat interface for foreign runtimes, and a .NET library over it

It is suitable for hosted systems and freestanding C targets. A build role
selects the parts one product carries. A card carries the emulator and the
`.dfcb` codec. A host-side client carries the reader and both encodings. A
simulator carries everything.

## Requirements

Use a C11 compiler and select either mbedTLS 3.x or
[tiny-crypto-c](https://github.com/mistial-dev/tiny-crypto-c). See
[Integration](docs/integration.md) for compiler options.

## Run the tests

With mbedTLS 3.x installed:

```sh
make -C tests test
```

With tiny-crypto-c checked out:

```sh
make -C tests test CRYPTO_BACKEND=tiny TINY_CRYPTO_DIR=/path/to/tiny-crypto-c
```

Run the suite under a sanitizer. AddressSanitizer and UndefinedBehaviorSanitizer
work with gcc or clang on any host; MemorySanitizer needs clang on Linux:

```sh
make -C tests test SANITIZE=address,undefined
make -C tests test CC=clang SANITIZE=memory
```

The test command builds and runs every unit suite and checks that each
reduced build profile compiles.

## Integrate the library

Add `src/` and `port/` to the compiler include path. Compile all files in
`src/`. Also compile one platform implementation and the crypto libraries.

For a complete procedure, see [Integration](docs/integration.md).

Use `port/dfc_port.h` to implement the platform services. Use
`port/dfc_bytebuf.h` to implement the response buffer. The `port/host/`
directory contains workstation implementations that you can use as examples.

Use `src/dfc_build_config.h` to select a feature profile. A reduced profile
rejects a known feature when the profile does not support that feature. It does
not silently discard data.

## EV2 credential fields

`PICC EV2 Card Capabilities:` holds six card capability bytes. During
`AuthenticateEV2First` at PICC level, the emulator returns these bytes after
the transaction identifier and rotated reader random. It then returns the
reader capability bytes from the command, padded with zeros to six bytes.
The supplied length must match the command data; bytes beyond the first six
are accepted as future extensions and are not echoed. An absent field yields
six zero card capability bytes. At application level, application capability
data takes the card capability slot when present.

`Card Static Signature:` holds a 56-byte originality signature read from a
card. The full EV2 and EV3 profiles return it through `Read_Sig` (`0x3C`,
address `0x00`). The emulator returns the stored bytes; it does not create or
verify a signature. Omit the field when no signature is available.

## Build the shared library

The CMake build produces the core as a static archive and as a shared library
that exports `ffi/dfc_ffi.h`:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build
```

## Use it from .NET

`bindings/dotnet` holds the `Dfc` library, which runs every rule in native code.
It provides the credential records and codec, `DfcVirtualPicc` and
`DfcReader`. See its [README](bindings/dotnet/README.md).

## License

DFC core is licensed under the GNU General Public License, version 2 or (at
your option) any later version (`GPL-2.0-or-later`). See [LICENSE](LICENSE).
