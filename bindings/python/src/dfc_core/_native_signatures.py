"""Apply generated, named ctypes declarations to the native library."""

from __future__ import annotations

import ctypes as C
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ._native_reader_signatures_generated import signatures as reader_signatures
from ._native_signatures_generated import signatures as core_signatures


@dataclass(frozen=True)
class Parameter:
    """One named native parameter and its ctypes representation."""

    name: str
    ctype: Any


@dataclass(frozen=True)
class Signature:
    """One native function result and its ordered, named parameters."""

    name: str
    result: Any
    parameters: tuple[Parameter, ...]


def signatures(types: Mapping[str, Any]) -> tuple[Signature, ...]:
    """Build the typed registry generated from the public C header."""

    generated = core_signatures(types) + reader_signatures(types)
    return tuple(
        Signature(name, result, tuple(Parameter(parameter, ctype) for parameter, ctype in values))
        for name, result, values in generated
    )


def declare(lib: C.CDLL, types: Mapping[str, Any]) -> tuple[Signature, ...]:
    """Declare every exported function from the generated public-header contract."""

    registry = signatures(types)
    for signature in registry:
        function = getattr(lib, signature.name)
        function.argtypes = [parameter.ctype for parameter in signature.parameters]
        function.restype = signature.result
    return registry
