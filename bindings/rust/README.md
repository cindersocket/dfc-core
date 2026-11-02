# dfc-core for Rust

`dfc-core` is the safe Rust interface to DFC credentials, virtual cards, and
reader sessions. `dfc-core-sys` exposes the raw C ABI for integrations that
cannot use the safe crate.

## Hosted applications

The default features build the native library with the simulator role and full
EV3 profile. No preinstalled `libdfc` is required:

```toml
[dependencies]
dfc-core = "2.0.0"
```

Load a text or binary credential, validate it, and transfer ownership into a
virtual PICC:

```rust,no_run
use dfc_core::{Credential, VirtualPicc};

let credential = Credential::load(include_bytes!("card.dfcb"))?;
credential.validate()?;

// Moving the credential avoids duplicating its application, file, and key pools.
let mut picc = VirtualPicc::from_credential(credential)?;
let activation = picc.activate()?;
let response = picc.exchange(&[0x90, 0x60, 0x00, 0x00, 0x00])?;

assert!(activation.0.uid_len > 0);
assert_eq!(&response[response.len() - 2..], &[0x91, 0xAF]);
# Ok::<(), dfc_core::Error>(())
```

The complete [virtual PICC example](https://github.com/cindersocket/dfc-core/tree/master/examples/rust-virtual-picc)
loads the checked-in synthetic credential, activates it, performs the
three-frame `GetVersion` exchange, parses the returned card information, and
turns the RF field off. Run it from the repository root:

```sh
cargo run --manifest-path examples/rust-virtual-picc/Cargo.toml
cargo test --manifest-path examples/rust-virtual-picc/Cargo.toml
```

Use `VirtualPicc::new(&credential)` only when the caller must retain the
credential. `VirtualPicc::from_credential` is preferable for an emulator
because native code takes ownership without cloning the credential pools.

`Reader<T>` drives real hardware through the blocking `Transport` trait. The
transport owns device I/O; DFC owns command framing, authentication state, and
secure messaging. A transport failure clears the protocol session before the
error is returned. Handles are `Send`, but deliberately not `Sync`.
`Command::select_application` accepts the same human-readable AID byte order
returned by `Credential::application` and converts it to wire order.
The reader keeps one short-APDU output buffer, grows it only as needed up to the
261-byte wire limit, and wipes it after each transport call.

To link an installed library instead of compiling the bundled source, disable
defaults and enable `system` plus one role and profile. Set `DFC_LIB_DIR` when
the library is outside the platform linker search path.

## Firmware and `no_std`

Target builds are `no_std` with `alloc`. Select exactly one role and profile:

```toml
[dependencies]
dfc-core = { version = "2.0.0", default-features = false, features = [
    "bundled",
    "role-target",
    "profile-minimal-ev3",
] }
```

The target API exports `TargetCredential` and `TargetVirtualPicc`. It accepts
caller-provided exchange buffers and asks native code for the exact credential
and wrapper layouts before allocating them. The selected native profile keeps
its normal application, file, key, and data capacities; the binding does not
replace those pools with workstation-sized storage. The platform must provide
an allocator and DFC port functions, including the protocol-session allocation.

Check a firmware configuration without linking an executable:

```sh
rustup target add thumbv7em-none-eabihf
cargo check --package dfc-core --target thumbv7em-none-eabihf \
  --no-default-features \
  --features bundled,role-target,profile-minimal-ev3
```

## Backend verification

The hosted crate exposes `diversify_key`, typed response decoders, `verify_sdm`,
and `TransactionMacVerifier`. Verified SDM fields are returned only after the
MAC succeeds. The transaction verifier accepts structured operations in card
order and clears its native key and transcript on drop. Applications still own
replay detection and counter persistence.
The [native transaction-input contract](../../src/dfc_transaction_mac.h)
defines the supported commands, fields, padding, and ordering used unchanged by
these methods.

Run the backend example, which also transceives a virtual-card transaction and
verifies the returned commit receipt, with:

```sh
cargo run --manifest-path examples/rust-virtual-picc/Cargo.toml --bin verify_backend
```

## Development checks

From the repository root:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo rustdoc -p dfc-core --lib -- -D warnings
cargo rustdoc -p dfc-core --lib --no-default-features \
  --features system,role-target,profile-full-ev3 -- -D warnings
```

The safe crate denies missing rustdoc and broken intra-doc links at the crate
root, so these commands are durable API-documentation gates. The
`dfc-core-sys` declarations are generated from `ffi/dfc_ffi.h`; edit the native
header and rerun `bindings/rust/regenerate-bindings.sh` rather than hand-editing
the hosted raw bindings.

The safe crate checks the native ABI version, structure sizes, and complete
generated layout fingerprint before creating hosted handles. Random callbacks are contained at
the FFI boundary: they must return exactly the requested byte count, and panic
or length mismatch is reported after native control returns.

## Security

Report suspected vulnerabilities through the project's
[private reporting process](https://github.com/cindersocket/dfc-core/security/policy).

## Reader clear-header length

`Reader::exchange(command, mode, clear_header)` derives the clear head of an
encrypted field from the instruction when `clear_header` is `None`. `Some(n)` is
a head length no larger than `DFC_FFI_READER_MAX_CLEAR_HEADER_LENGTH`.
The native core refuses a larger value, and a value that does not fit the native
`int32_t` is refused before the call, both as `Error::InvalidArgument`; the
session stays usable.


## Conformance vectors

The DESFire conformance vectors replay through this binding's virtual card: `cargo test -p dfc-core --test replay_plans -- --nocapture`. It reports how many vectors it replayed and skipped. See [Replay plans](../../docs/conformance-vector-format.md#replay-plans).

## Secret lifetime

Ordinary card snapshots exclude session keys. `DiagnosticSnapshot` exists for
diagnostics and conformance tests and wipes its native storage on drop. A caller
that copies one of its slices owns and must clear that copy. `CredentialKey`
similarly wipes key material returned from a credential when it is dropped, as
do the PICC-settings and file wrappers. Encoded `Vec<u8>` values belong to the
caller and must be cleared after use.
