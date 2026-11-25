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

## Emulator coverage contract

`tests/native_coverage_contract.json` is the checked inventory that connects
emulator behavior to evidence. Each behavior family names replayable physical
vectors or deterministic tests. The same file classifies every function that
unit tests reach beyond the physical replay corpus.

`./scripts/run-native-coverage.sh` rejects missing behavior families, unknown or
nonreplayable vector references, new unclassified gaps, and stale classifications.
Coverage minimums are an append-only history: a later entry may raise a floor,
but cannot lower one. The run writes `ratchet-minimums.json` with the next floors
rounded down to one decimal place.

Gap categories have narrow meanings:

- `capture-required`: a wire-visible path still needs more replayable card evidence.
- `capture-derived`: an internal branch inherits evidence from its enclosing exchange.
- `fault-only`: deterministic injection covers a condition a transcript cannot control.
- `library-only`: a host-side builder or verifier is outside the card front door.
- `profile-only`: a compile-time variant is covered by its dedicated build.

Remove a classification when the gap closes. New entries require a concrete
rationale; dead code is removed instead of classified.

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
