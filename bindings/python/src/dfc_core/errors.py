from __future__ import annotations


class DfcError(Exception):
    def __init__(self, status: int, message: str | None = None) -> None:
        self.status = status
        super().__init__(message or f"dfc operation failed with status {status}")


class InvalidArgumentError(DfcError, ValueError):
    pass


class BufferTooSmallError(DfcError):
    pass


class DfcMemoryError(DfcError, MemoryError):
    pass


class UnsupportedError(DfcError):
    pass


class RandomSourceError(DfcError):
    pass


class CredentialError(DfcError):
    def __init__(self, status: int, message: str, line: int = 0) -> None:
        self.line = line
        super().__init__(status, f"line {line}: {message}" if line else message)


class ProtocolError(DfcError):
    pass


class CardError(ProtocolError):
    def __init__(self, status: int, card_status: int) -> None:
        self.card_status = card_status
        super().__init__(status, f"card returned status 0x{card_status:02X}")


def exception_for_status(status: int) -> DfcError:
    return {
        -1: InvalidArgumentError,
        -2: BufferTooSmallError,
        -3: DfcMemoryError,
        -4: UnsupportedError,
        -5: RandomSourceError,
    }.get(status, ProtocolError)(status)
