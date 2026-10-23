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

The complete [virtual PICC example](../../examples/rust-virtual-picc/README.md)
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

## Development checks

From the repository root:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The safe crate checks the native ABI version, structure sizes, and layout
fingerprint before creating hosted handles. Random callbacks are contained at
the FFI boundary: they must return exactly the requested byte count, and panic
or length mismatch is reported after native control returns.

## Reader clear-header length

`Reader::exchange(command, mode, clear_header)` derives the clear head of an
encrypted field from the instruction when `clear_header` is `None`. `Some(n)` is
a head length no larger than `DFC_FFI_READER_MAX_CLEAR_HEADER_LENGTH`.
The native core refuses a larger value, and a value that does not fit the native
`int32_t` is refused before the call, both as `Error::InvalidArgument`; the
session stays usable.
