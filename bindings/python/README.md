# dfc-core for Python

`dfc_core` provides blocking Python 3.11+ bindings for credential handling,
virtual-card emulation, and reader-side command exchange. Protocol processing,
cryptography, credential validation, and secure messaging stay in the native
dfc-core library.

Install the wheel, which carries the matching native library:

```sh
python -m pip install dfc-core==2.0.0
```

## Install and load the native library

Build from the repository root while developing:

```sh
cmake -S . -B build -DDFC_BUILD_SHARED=ON -DDFC_BUILD_TESTS=OFF
cmake --build build
uv sync --project bindings/python --extra test
```

Point the binding at that exact library before running Python:

```sh
export DFC_LIBRARY_PATH="$PWD/build/libdfc.dylib"  # macOS
# export DFC_LIBRARY_PATH="$PWD/build/libdfc.so"   # Linux
```

Production wheels include their matching native library under `dfc_core/lib/`.
Loading stops before constructing a native handle when the ABI version or the
complete generated layout fingerprint does not match. The fingerprint covers
all shared fields and binding-visible numeric constants.

## Run a complete exchange

The repository's [virtual-card example](https://github.com/cindersocket/dfc-core/tree/master/examples/python) loads a
credential, activates it, selects an application, and reads a data file through
the public reader API:

```sh
DFC_LIBRARY_PATH="$PWD/build/libdfc.dylib" \
  uv run --project bindings/python python examples/python/virtual_card.py
```

Expected file data is `de ad be ef`. The example uses `VirtualPicc` as the
transport, but the same `Reader` calls work with a physical adapter:

```python
class Device:
    def transceive(self, command: bytes) -> bytes:
        return send_to_device(command)
```

`Reader.exchange(command, comm_mode, header_len)` takes a `header_len` of -1 to
derive the clear head of an encrypted field. Explicit values may not exceed
`DFC_FFI_READER_MAX_CLEAR_HEADER_LENGTH`. Invalid values raise
`InvalidArgumentError` without changing the reader session.

Integers passed to fixed-width native parameters are range-checked before the
call. Values that do not fit raise `InvalidArgumentError` instead of wrapping.

`transceive` must return the complete response bytes or raise an exception. A
transport exception clears the reader's authentication state before it is
re-raised.

## Credential and handle lifecycle

Load binary or text credentials with `Credential.load`, or use `decode` and
`parse` when the format is already known. `model()` returns immutable card,
application, file, and key values for inspection.

`Credential`, `VirtualPicc`, and `Reader` are context managers. Close them
promptly: finalizers are only a fallback. Creating a `VirtualPicc` consumes its
credential on current ABIs, so the original credential handle is closed after a
successful construction. Export the card state to a new credential when changes
need to be saved:

```python
with VirtualPicc(Credential.load(content)) as picc:
    # ...transceive commands...
    with picc.export() as updated:
        persisted = updated.encode()
    picc.mark_persisted()
```

Calling `Reader.close()` more than once is safe. Other reader operations raise
`RuntimeError` after the reader is closed.

`VirtualPicc.close()` is idempotent and marks the card closed immediately. An
operation already in progress finishes before its native handle is released.

Calls on one handle are serialized. A physical transport remains responsible for
its own thread safety.

## Security

Report suspected vulnerabilities through the project's
[private reporting process](https://github.com/cindersocket/dfc-core/security/policy).

## Reader commands and errors

Use the named `Command` constructors for common operations, such as
`get_version`, `select_application`, and `read_data`. Application IDs use the
same readable byte order as credential files; the binding performs the protocol
byte-order conversion.

Successful responses contain the card status and returned data. Terminal card
errors raise `CardError`; its `card_status` identifies the card's status byte.
Special-success statuses from ReadSignature and proximity-check commands remain
on `Response`. Other binding failures raise a subclass of `DfcError`, and
transport exceptions pass through unchanged.

## Random sources and secret lifetime

Pass a callable to `VirtualPicc` only when deterministic randomness is needed for
testing. It must return exactly the requested number of bytes. Callback failures
or short results abort the current operation without committing card state and
raise `RandomSourceError` with status `-5` after the native call returns. The
original callback exception is available as its cause. A caller may retry if its
source can satisfy the next request; deterministic replay should use a new card
with a complete script.

Key and generated-challenge copies held in mutable native or Python buffers are
wiped after use. Python cannot wipe immutable `bytes` supplied by an application,
so applications with strict secret-lifetime requirements should avoid retaining
extra immutable copies.

## Backend verification

The binding exposes the core's key diversification, typed response decoders,
SDM verification, and Transaction MAC verifier. `verify_sdm` publishes mirrored
fields only after authentication. `TransactionMacVerifier` accepts structured
operations in card order and owns its native key and transcript until closed.
The binding wipes its mutable ctypes copies of keys, transaction inputs, MACs,
and decrypted SDM data after each native call. Returned immutable `bytes` remain
owned by the application.
Replay detection and transaction-counter persistence remain application policy.
The [native transaction-input contract](../../src/dfc_transaction_mac.h)
defines the supported commands, fields, padding, and ordering used unchanged by
these methods.

See [`examples/python/verify_backend.py`](https://github.com/cindersocket/dfc-core/blob/master/examples/python/verify_backend.py)
for captured SDM verification plus an actual virtual-card transaction, decoded
file settings, commit response parsing, and receipt verification.

## Verify the binding

With `DFC_LIBRARY_PATH` set to the shared library:

```sh
(cd bindings/python && uv run ruff format --check src tests ../../examples/python)
(cd bindings/python && uv run ruff check src tests ../../examples/python)
MYPYPATH=bindings/python/src uv run --project bindings/python \
  mypy --config-file bindings/python/pyproject.toml -p dfc_core
MYPYPATH=bindings/python/src \
  uv run --project bindings/python mypy \
  --config-file bindings/python/pyproject.toml examples/python/virtual_card.py
uv run --project bindings/python pytest bindings/python/tests
python3 scripts/check-docs.py
```


## Conformance vectors

The DESFire conformance vectors replay through this binding's virtual card: `pytest bindings/python/tests/test_replay_plans.py -s`. It reports how many vectors it replayed and skipped. See [Replay plans](../../docs/conformance-vector-format.md#replay-plans).

## Secret lifetime

Ordinary card snapshots exclude session keys. The private conformance helper
returns mutable buffers that callers must consume only inside its context. The
context clears those buffers and its native temporary on exit. Python may retain
immutable copies created by callers, so applications should avoid converting
secret buffers to `bytes`. Native key temporaries are cleared after the Python
model has been built. Model key fields, encoded credentials, and text results
are immutable runtime copies that Python cannot wipe; keep them short-lived.
