from __future__ import annotations

import ctypes as C
from enum import IntEnum

from . import _native


class DiversificationAlgorithm(IntEnum):
    """Key algorithm used by the diversification operation.

    Values:
        AES128: Produce a 16-byte AES key.
        TDEA2: Produce a 16-byte two-key TDEA key.
        TDEA3: Produce a 24-byte three-key TDEA key.
    """

    AES128 = 0
    TDEA2 = 1
    TDEA3 = 2


def diversify_key(
    algorithm: DiversificationAlgorithm,
    master_key: bytes,
    diversification_input: bytes,
) -> bytes:
    """Derive one key from a master key and diversification input.

    Native copies of the master key, input, and result are wiped before return.
    The immutable Python inputs and returned key remain owned by the caller.

    Args:
        algorithm: Output-key algorithm and length.
        master_key: AES or TDEA master key accepted by the selected algorithm.
        diversification_input: Application-defined diversification bytes.

    Returns:
        A 16-byte AES/two-key TDEA key or 24-byte three-key TDEA key.

    Raises:
        ValueError: If ``algorithm`` is not a supported enum value.
        DfcError: If a key length or input is invalid, or derivation fails.
    """
    key_length = {
        DiversificationAlgorithm.AES128: 16,
        DiversificationAlgorithm.TDEA2: 16,
        DiversificationAlgorithm.TDEA3: 24,
    }[algorithm]
    master_raw, master_pointer = _native.byte_pointer(master_key)
    input_raw, input_pointer = _native.byte_pointer(diversification_input)
    output = (C.c_uint8 * key_length)()
    produced = C.c_size_t()
    try:
        status = _native.library().dfc_ffi_an10922_diversify(
            int(algorithm),
            master_pointer,
            len(master_key),
            input_pointer,
            len(diversification_input),
            output,
            len(output),
            C.byref(produced),
        )
        _native.raise_status(status)
        return bytes(output[: produced.value])
    finally:
        _native.secure_zero(master_raw)
        _native.secure_zero(input_raw)
        _native.secure_zero(output)
