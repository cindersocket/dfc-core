from __future__ import annotations

from ._layout import VALUES as FFI_VALUES


class DfcError(Exception):
    """Base error carrying the stable native status code."""

    def __init__(self, status: int, message: str | None = None) -> None:
        """Create an error from a stable native status.

        Args:
            status: Native FFI status code.
            message: Optional operation-specific explanation.
        """

        self.status = status
        super().__init__(message or f"dfc operation failed with status {status}")


class InvalidArgumentError(DfcError, ValueError):
    """A caller value cannot be represented or is invalid for the operation."""


class BufferTooSmallError(DfcError):
    """Caller-provided storage cannot hold the complete result."""


class DfcMemoryError(DfcError, MemoryError):
    """Native allocation or bounded scratch storage was unavailable."""


class UnsupportedError(DfcError):
    """The loaded role or profile does not support the requested operation."""


class RandomSourceError(DfcError):
    """A random source failed or returned the wrong number of bytes."""


class CredentialError(DfcError):
    """Credential parsing, decoding, encoding, or model validation failed."""

    def __init__(self, status: int, message: str, line: int = 0) -> None:
        """Create a credential error with optional source location.

        Args:
            status: Native FFI status code.
            message: Parse, codec, or validation detail.
            line: One-based text line, or zero when no line applies.
        """

        self.line = line
        super().__init__(status, f"line {line}: {message}" if line else message)


class ProtocolError(DfcError):
    """Reader or virtual-card protocol processing failed."""


class CardError(ProtocolError):
    """A card returned a terminal status byte instead of command data."""

    def __init__(self, status: int, card_status: int) -> None:
        """Create an error from binding and card statuses.

        Args:
            status: Binding-level reader status.
            card_status: One-byte status returned by the card.
        """

        self.card_status = card_status
        super().__init__(status, f"card returned status 0x{card_status:02X}")


def exception_for_status(status: int) -> DfcError:
    return {
        FFI_VALUES["DFC_FFI_INVALID_ARGUMENT"]: InvalidArgumentError,
        FFI_VALUES["DFC_FFI_BUFFER_TOO_SMALL"]: BufferTooSmallError,
        FFI_VALUES["DFC_FFI_OUT_OF_MEMORY"]: DfcMemoryError,
        FFI_VALUES["DFC_FFI_UNSUPPORTED"]: UnsupportedError,
        FFI_VALUES["DFC_FFI_RANDOM_FAILED"]: RandomSourceError,
    }.get(status, ProtocolError)(status)
