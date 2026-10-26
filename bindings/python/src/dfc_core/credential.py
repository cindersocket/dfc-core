from __future__ import annotations

import ctypes as C
import threading
import weakref
from typing import Self

from . import _native as N
from .errors import CredentialError
from .models import (
    Application,
    Card,
    CommunicationMode,
    CredentialModel,
    File,
    FileType,
    Key,
    PiccSettings,
)


def _take(a: object, length: int) -> bytes:
    return bytes(a[:length])  # type: ignore[index]


def _copy(dst: object, data: bytes, limit: int) -> None:
    if len(data) > limit:
        raise ValueError(f"field is limited to {limit} bytes")
    for i, value in enumerate(data):
        dst[i] = value  # type: ignore[index]


def _wipe_native(value: C.Structure) -> None:
    N.library().dfc_ffi_secure_zero(C.byref(value), C.sizeof(value))


def _file_model(f: N.File, data: bytes) -> File:
    sdm = (
        f.sdm_enabled,
        f.sdm_options,
        f.sdm_access_rights,
        f.sdm_uid_offset,
        f.sdm_counter_offset,
        f.sdm_picc_data_offset,
        f.sdm_mac_input_offset,
        f.sdm_mac_offset,
        f.sdm_encrypted_file_offset,
        f.sdm_encrypted_file_length,
        f.sdm_counter_limit,
        f.sdm_read_counter,
        f.transaction_counter,
    )
    return File(
        owner=f.owner,
        number=f.number,
        type=FileType(f.type),
        comm_settings=CommunicationMode(f.comm_settings),
        access_rights=f.access_rights,
        data=data,
        declared_size=f.declared_size,
        values=(f.value_lower_limit, f.value_upper_limit, f.value, f.value_pending_delta),
        record_size=f.record_size,
        max_records=f.max_records,
        record_count=f.record_count,
        iso_file_id=f.iso_file_id if f.has_iso_file_id else None,
        contents_complete=bool(f.contents_complete),
        transaction_pending=bool(f.transaction_pending),
        limited_credit=f.limited_credit,
        limited_credit_value=f.limited_credit_value,
        value_pending=bool(f.value_pending),
        sdm=sdm,
        transaction_mac_key_type=f.transaction_mac_key_type,
        transaction_mac_key_version=f.transaction_mac_key_version,
        transaction_mac_key=bytes(f.transaction_mac_key),
        transaction_mac=bytes(f.transaction_mac),
        previous_reader_id=bytes(f.previous_reader_id),
    )


def _picc_model(picc: N.PiccSettings) -> PiccSettings:
    return PiccSettings(
        picc.num_keys,
        picc.key_len,
        picc.key_settings_1,
        picc.key_settings_2,
        picc.auth_command,
        bool(picc.random_id),
        bool(picc.random_id_legacy),
        bool(picc.format_disabled),
        _take(picc.ats, picc.ats_len),
        picc.sak if picc.has_sak else None,
        bytes(picc.atqa) if picc.has_atqa else None,
        picc.sm_disable if picc.has_sm_disable else None,
        bytes(picc.ev2_capabilities) if picc.has_ev2_capabilities else None,
        bytes(picc.proximity_key) if picc.has_proximity_key else None,
        picc.proximity_option,
        picc.proximity_bitrate if picc.has_proximity_bitrate else None,
        picc.proximity_published_response_time,
        _take(picc.virtual_card_installation_id, picc.virtual_card_installation_id_len)
        if picc.virtual_card_configured
        else None,
        picc.virtual_card_information,
        bytes(picc.virtual_card_capabilities),
        _take(picc.virtual_card_uid, picc.virtual_card_uid_len),
        bytes(picc.virtual_card_select_mac_key),
        bytes(picc.virtual_card_select_encryption_key),
        bool(picc.virtual_card_authentication_mandatory),
        bool(picc.virtual_card_proximity_mandatory),
        bytes(picc.dam_auth_key) if picc.has_dam_keys else None,
        bytes(picc.dam_mac_key) if picc.has_dam_keys else None,
        bytes(picc.dam_encryption_key) if picc.has_dam_keys else None,
        picc.auth_commands if picc.has_auth_commands else None,
        picc.preferred_auth_command if picc.has_preferred_auth_command else None,
    )


class Credential:
    """An owned native credential. Close it promptly or use it as a context manager."""

    def __init__(self, handle: N.Handle) -> None:
        """Take ownership of a non-null native credential handle.

        Applications normally use ``parse``, ``decode``, or ``load`` rather than
        constructing this low-level ownership wrapper directly.

        Args:
            handle: Non-null native credential handle whose ownership is transferred.

        Raises:
            ValueError: If ``handle`` is null.
        """

        if not handle:
            raise ValueError("null credential handle")
        self._handle = handle
        self._lock = threading.RLock()
        self._finalizer = weakref.finalize(self, N.library().dfc_ffi_credential_free, handle)

    @classmethod
    def _read(cls, function: str, content: bytes) -> Credential:
        lib = N.library()
        handle = N.Handle()
        error = N.Error()
        _raw, pointer = N.byte_pointer(content)
        if function == "parse_text":
            status = lib.dfc_ffi_credential_parse_text(
                content, len(content), C.byref(handle), C.byref(error)
            )
        else:
            status = getattr(lib, f"dfc_ffi_credential_{function}")(
                pointer, len(content), C.byref(handle), C.byref(error)
            )
        if status:
            message = bytes(error.message).split(b"\0", 1)[0].decode("utf-8", "replace")
            raise CredentialError(error.status or status, message, error.line)
        return cls(handle)

    @classmethod
    def parse(cls, text: str) -> Credential:
        """Parse one textual credential.

        Args:
            text: Complete credential text.

        Returns:
            A newly owned credential that must be closed.

        Raises:
            CredentialError: If parsing or model validation fails.
        """

        return cls._read("parse_text", text.encode("utf-8"))

    @classmethod
    def decode(cls, content: bytes) -> Credential:
        """Decode one binary credential.

        Args:
            content: Complete encoded credential.

        Returns:
            A newly owned credential that must be closed.

        Raises:
            CredentialError: If decoding or model validation fails.
        """

        return cls._read("decode", content)

    @classmethod
    def load(cls, content: bytes | str) -> Credential:
        """Load text or binary credential content.

        Byte input is detected by its first octet; string input is parsed as text.

        Args:
            content: Complete text or binary credential.

        Returns:
            A newly owned credential that must be closed.

        Raises:
            CredentialError: If decoding, parsing, or validation fails.
        """

        return cls._read("load", content.encode() if isinstance(content, str) else content)

    @property
    def closed(self) -> bool:
        """Report whether this object released or transferred its handle.

        Returns:
            ``True`` when no native credential remains owned by this object.
        """

        return not self._finalizer.alive

    def _open(self) -> N.Handle:
        if self.closed:
            raise RuntimeError("credential is closed")
        return self._handle

    def close(self) -> None:
        """Release the native credential; repeated calls are safe."""

        with self._lock:
            self._finalizer()

    def __enter__(self) -> Self:
        self._open()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def encode(self) -> bytes:
        """Encode the validated credential in canonical binary form.

        Returns:
            A Python-owned binary credential.

        Raises:
            CredentialError: If the model is invalid or encoding fails.
            RuntimeError: If this credential is closed.
        """

        with self._lock:
            return N.variable_output(N.library().dfc_ffi_credential_encode, self._open())

    def to_text(self) -> str:
        """Render the validated credential as canonical UTF-8 text.

        Returns:
            A Python-owned credential string.

        Raises:
            CredentialError: If the model is invalid or rendering fails.
            RuntimeError: If this credential is closed.
        """

        with self._lock:
            return N.variable_output(
                N.library().dfc_ffi_credential_write_text, self._open()
            ).decode()

    def validate(self) -> None:
        """Validate the current native model.

        Raises:
            CredentialError: If the model violates a credential constraint.
            RuntimeError: If this credential is closed.
        """

        with self._lock:
            N.raise_status(N.library().dfc_ffi_credential_validate(self._open()))

    def model(self) -> CredentialModel:
        """Copy the credential into immutable Python values.

        The returned model owns its byte strings. Closing this credential does
        not invalidate them, and Python cannot securely wipe those immutable
        copies.

        Returns:
            An immutable Python snapshot of the complete credential model.

        Raises:
            RuntimeError: If this credential is closed.
            DfcError: If the native model cannot be read.
        """

        with self._lock:
            lib, handle = N.library(), self._open()
            card, picc = N.Card(), N.PiccSettings()
            N.raise_status(lib.dfc_ffi_credential_get_card(handle, C.byref(card)))
            try:
                N.raise_status(lib.dfc_ffi_credential_get_picc(handle, C.byref(picc)))
                picc_model = _picc_model(picc)
                picc_key_count = picc.num_keys
            finally:
                _wipe_native(picc)
            applications: list[Application] = []
            for i in range(lib.dfc_ffi_credential_application_count(handle)):
                a = N.Application()
                N.raise_status(lib.dfc_ffi_credential_get_application(handle, i, C.byref(a)))
                applications.append(
                    Application(
                        aid=bytes(a.aid),
                        num_keys=a.num_keys,
                        key_len=a.key_len,
                        df_name=_take(a.df_name, a.df_name_len),
                        num_key_sets=a.num_key_sets,
                        iso_file_id=a.iso_file_id if a.has_iso_file_id else None,
                        delegated_slot_number=a.delegated_slot_number,
                        delegated_quota_limit=a.delegated_quota_limit,
                        delegated_free_blocks=a.delegated_free_blocks,
                        key_settings_1=a.key_settings_1,
                        key_settings_2=a.key_settings_2,
                        auth_command=a.auth_command,
                        key_set_max_size=a.key_set_max_size,
                        key_set_settings=a.key_set_settings,
                        key_set_versions=bytes(a.key_set_versions),
                        key_set_types=bytes(a.key_set_types),
                        key_set_initialized=bytes(a.key_set_initialized),
                        capability_data=bytes(a.capability_data) if a.has_capability_data else None,
                        delegated=bool(a.delegated),
                        delegated_slot_version=a.delegated_slot_version,
                        delegated_format_disabled=bool(a.delegated_format_disabled),
                        auth_commands=a.auth_commands if a.has_auth_commands else None,
                        preferred_auth_command=a.preferred_auth_command
                        if a.has_preferred_auth_command
                        else None,
                        sm_disable=a.sm_disable if a.has_sm_disable else None,
                    )
                )
            files: list[File] = []
            for i in range(lib.dfc_ffi_credential_file_count(handle)):
                f = N.File()
                try:
                    N.raise_status(lib.dfc_ffi_credential_get_file(handle, i, C.byref(f)))
                    data = N.variable_output(lib.dfc_ffi_credential_get_file_data, handle, i)
                    files.append(_file_model(f, data))
                finally:
                    _wipe_native(f)
            # Key slots are bounded by each owner's declared key count.
            keys: list[Key] = []
            owners = [(N.OWNER_PICC, picc_key_count, 1)] + [
                (i, a.num_keys, max(1, a.num_key_sets)) for i, a in enumerate(applications)
            ]
            for owner, count, sets in owners:
                for key_set in range(sets):
                    for slot in range(count):
                        k = N.Key()
                        try:
                            N.raise_status(
                                lib.dfc_ffi_credential_get_key(
                                    handle, owner, key_set, slot, C.byref(k)
                                )
                            )
                            keys.append(Key(owner, slot, _take(k.value, k.len), k.version, key_set))
                        finally:
                            _wipe_native(k)
            result = CredentialModel(
                Card(
                    card.generation,
                    card.storage,
                    card.uid_provenance,
                    _take(card.uid, card.uid_len),
                    bytes(card.hardware_version) if card.has_hardware_version else None,
                    bytes(card.software_version) if card.has_software_version else None,
                    bytes(card.static_signature) if card.has_static_signature else None,
                ),
                picc_model,
                tuple(applications),
                tuple(files),
                tuple(keys),
            )
            return result
