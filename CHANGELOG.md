# Changelog

## 2.0.0 (Unreleased)

- Add Java and Android JNI bindings and an Android library.
- Add blocking Python bindings and safe Rust bindings for hosted and `no_std`
  target builds, with ABI-layout checks and caller-owned target storage.
- Add runnable transceive examples for .NET, Java, Android, Python, and Rust.
- Make semantic application-selection helpers consistently accept the
  human-readable application identifier order in every binding.
- Correct Java communication-mode values and Python reader FFI declarations,
  validate key-set storage widths at the FFI boundary, and enforce Rust 1.85
  compatibility in CI.
- Check formatting and documentation links across C and every binding.
- Bound encrypted clear-header lengths before reader state changes and cover the
  full byte-sized input domain across authenticated session families (#116).
- Make every credential decoder leave an empty, securely wiped credential after
  any failure, and enforce decoder coverage with a registry check and fuzz
  invariant (#115).
- Document and verify the 2.0 source-release process and artifacts.
- Generate target and Rust static libraries with the toolchain's native code
  model, and reserve position-independent objects for shared and JNI libraries.
- Add a reproducible Cortex-M4 footprint gate for code, static data, stack
  frames, model structures, and configured storage capacities.
- Refactor credential validation and serialization around explicit model invariants.
- Accept zero-initialized credentials with empty file and key pools.
- Make credential and file-pool updates transactional.
- Reuse prepared cipher contexts and stream segmented AES, DES, and TDEA MAC input,
  removing message-sized secure-messaging scratch buffers.
- Propagate cipher and MAC failures, reject overflowing or malformed inputs,
  and consistently wipe staged output, retired ISO-DEP requests, file-pool
  bytes, replay buffers, and secret scratch storage.
- Make reader, native, ISO, ISO-DEP, EV1, and EV2 retries state-atomic across
  authentication, response-capacity, chaining, and transport failures.
- Report required JNI response lengths, wipe invalidated ISO-DEP responses,
  reset expired activations, and support ISO-DEP record commands.
- Roll back failed SDM, delegated-application, transaction-MAC, CommitReaderID,
  value, file-creation, and key-update operations.
- Preserve transactions across current-key changes while aborting them on
  application changes and terminal command failures.
- Correct transaction snapshots, rollback, Transaction-MAC lifecycle, and ISO
  update publication.
- Apply the effective communication mode after access-right evaluation.
- Validate SDM counter keys, metadata-mirroring applicability, reset layouts,
  and reserved access-rights values, and reset the SDM read counter when its
  configuration changes.
- Reuse authenticated-session allocations and keep pending authentication identity
  separate from active authorization state.
- Reduce each secure-messaging and reader-session object by 2,256 bytes by
  eliminating message-sized scratch storage.
- Harden Python and .NET native-handle ownership across construction,
  closed-object access, callback reentry, disposal, finalization, and concurrent
  calls.
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
