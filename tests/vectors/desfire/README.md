# DESFire conformance vectors

This directory contains public protocol vectors for testing DESFire-compatible
implementations. Some were captured from physical cards. Others are synthetic
cases built to exercise protocol boundaries, error handling, and model state.
Each vector declares its origin and source in its header.

The vectors are organized by credential format version and by provenance:

- `hardware/` contains byte-exact exchanges captured from physical cards.
- `synthetic/` contains generated edge cases.
- `emulator/` contains complete replay scenarios, including scenarios derived
  from hardware captures.

Run every replayable vector with:

```sh
make -C tests vectors
```

Validate vector structure and the SHA-256 manifest with:

```sh
python3 tests/check_desfire_vectors.py
```

Every language binding replays the same vectors from generated plans; see
"Replay plans" in the format document below. After changing a vector, run
`make -C tests replay-plans` and commit the result.

The format is documented in
[`docs/conformance-vector-format.md`](../../../docs/conformance-vector-format.md).
The corpus is licensed with dfc-core under `GPL-2.0-or-later`.
