# Rust virtual PICC example

This application loads the repository's synthetic minimal credential, validates
it, activates a virtual PICC, and sends a real three-frame `GetVersion` command.
It parses and prints the returned hardware and software revisions, storage code,
UID, production batch, week, and year before ending the RF session.

From the repository root:

```sh
cargo run --manifest-path examples/rust-virtual-picc/Cargo.toml
```

Expected output starts with the card identity and ends with the full 28-byte
version payload. Exact values come from
[`v6-minimal.dfcb`](../credentials/v6-minimal.dfcb), a public synthetic test
credential.

Pass another `.dfc` or `.dfcb` credential to inspect it instead:

```sh
cargo run --manifest-path examples/rust-virtual-picc/Cargo.toml -- card.dfcb
```

Run the same lifecycle as an assertion-based test:

```sh
cargo test --manifest-path examples/rust-virtual-picc/Cargo.toml
```

The example uses only the safe `dfc-core` API. Feed credential bytes from your
application to the same lifecycle, then pass device responses through a
`dfc_core::Reader` transport when moving from virtual-card testing to a physical
reader.
