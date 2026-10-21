# Changelog

## Unreleased

- Add Java and Android JNI bindings, an Android library, and a sample application.
- Add blocking Python bindings and safe Rust bindings for hosted and `no_std`
  target builds, with ABI-layout checks and caller-owned target storage.
- Add runnable transceive examples for .NET, Java, Android, Python, and Rust.
- Correct Python application selection to encode application identifiers in wire order.
- Add one-command formatting and documentation-link verification for every
  supported binding language.
- Refactor credential validation and serialization around explicit model invariants.
- Harden authentication comparisons, secret cleanup, key updates, and SDM range validation.
- Reuse prepared cipher contexts during CMAC and legacy CBC operations.
- Stream EV2 MAC input segments instead of assembling a 519-byte temporary message.
- Propagate every CMAC cipher failure and reject overflowing message lengths.
- Make random providers fallible in ABI 4 and fail random-dependent operations
  atomically, with consistent error propagation through every binding.
- Make credential factory and blank initialization, and virtual-card
  anticollision, report random-source failures through boolean return values.

## 1.2.1 (2026-10-01)

- Adapt the tiny-crypto-c backend to its split mode sources and buffer-based API.
- Document EV2 feature coverage.

## 1.2.0 (2026-09-25)

- Add a native reader, flat C interface, CMake build, and .NET library.
- Add build roles and smaller feature profiles for embedded targets.
- Correct command framing, secure messaging, and record transactions against physical card behavior.
- Expand native, managed, and conformance test coverage.

## 1.0.2 (2026-09-15)

- Fix DER parsing in optimized builds and expand crypto backend CI coverage.

## 1.0.1 (2026-09-15)

- Add selectable mbedTLS and tiny-crypto-c backends.
- Preserve emulator storage and improve ISO-DEP framing and recovery.

## 1.0.0 (2026-09-15)

- Initial release of the credential model, text and binary codecs, secure messaging, and virtual card.
