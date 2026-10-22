# Changelog

## 2.0.0 (Unreleased)

- Add Java and Android JNI bindings, an Android library, and a sample application.
- Add blocking Python bindings and safe Rust bindings for hosted and `no_std`
  target builds, with ABI-layout checks and caller-owned target storage.
- Add runnable transceive examples for .NET, Java, Android, Python, and Rust.
- Make semantic application-selection helpers consistently accept the
  human-readable application identifier order in every binding.
- Correct Java communication-mode values and validate key-set storage widths
  at the FFI boundary.
- Add one-command formatting and documentation-link verification for every
  supported binding language.
- Generate target and Rust static libraries with the toolchain's native code
  model, and reserve position-independent objects for shared and JNI libraries.
- Refactor credential validation and serialization around explicit model invariants.
- Accept zero-initialized credentials with empty file and key pools.
- Make credential and file-pool updates transactional.
- Reuse prepared cipher contexts and stream segmented AES, DES, and TDEA MAC input,
  removing message-sized secure-messaging scratch buffers.
- Propagate cipher and MAC failures, reject overflowing or malformed inputs,
  and wipe staged output and secret material consistently.
- Make reader, native, ISO, ISO-DEP, EV1, and EV2 retries state-atomic across
  authentication, response-capacity, chaining, and transport failures.
- Roll back failed SDM, delegated-application, transaction-MAC, CommitReaderID,
  value, file-creation, and key-update operations.
- Reuse authenticated-session allocations and keep pending authentication identity
  separate from active authorization state.
- Reduce each secure-messaging and reader-session object by 2,256 bytes by
  eliminating message-sized scratch storage.
- Harden .NET virtual-card lifetime ownership across disposal, finalization, and
  concurrent native calls.
- Use constant-time authentication-secret comparisons and expand teardown and
  JNI secret-wipe verification.
- Standardize replay-random exhaustion across the hosted bindings.
- Make random providers fallible in ABI 4 and fail random-dependent operations
  atomically, with consistent error propagation through every binding.
- Make credential factory and blank initialization, and virtual-card
  anticollision, report random-source failures through boolean return values.
- Abort rejected ISO authentication handshakes and require a fresh challenge.
- Expand fault-injection, sanitizer, reduced-profile, teardown-wipe, capacity,
  long-transfer, and cross-binding corpus coverage.

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
