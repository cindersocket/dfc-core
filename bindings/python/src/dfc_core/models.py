from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Protocol, runtime_checkable


class BuildRole(IntEnum):
    UNKNOWN = 0
    TARGET = 1
    HOST = 2
    SIMULATOR = 3


class BuildProfile(IntEnum):
    UNKNOWN = 0
    MINIMAL = 1
    EV1 = 2
    EV2 = 3
    FULL_EV3 = 4
    CUSTOM = 5


@dataclass(frozen=True, slots=True)
class Capabilities:
    abi_version: int
    build_role: int
    build_profile: int
    features: frozenset[str]
    max_applications: int
    max_files: int
    max_keys: int
    file_pool_size: int
    key_pool_size: int


@dataclass(frozen=True, slots=True)
class Card:
    generation: int
    storage: int
    uid_provenance: int
    uid: bytes
    hardware_version: bytes | None = None
    software_version: bytes | None = None
    static_signature: bytes | None = None


@dataclass(frozen=True, slots=True)
class PiccSettings:
    num_keys: int
    key_len: int
    key_settings_1: int = 0
    key_settings_2: int = 0
    auth_command: int = 0
    random_id: bool = False
    format_disabled: bool = False
    ats: bytes = b""
    sak: int | None = None
    atqa: bytes | None = None
    sm_disable: int | None = None
    ev2_capabilities: bytes | None = None
    proximity_key: bytes | None = field(default=None, repr=False)
    proximity_option: int = 0
    proximity_bitrate: int | None = None
    proximity_published_response_time: int = 0
    virtual_card_installation_id: bytes | None = None
    virtual_card_information: int = 0
    virtual_card_capabilities: bytes = b""
    virtual_card_uid: bytes = b""
    virtual_card_select_mac_key: bytes = field(default=b"", repr=False)
    virtual_card_select_encryption_key: bytes = field(default=b"", repr=False)
    virtual_card_authentication_mandatory: bool = False
    virtual_card_proximity_mandatory: bool = False
    dam_auth_key: bytes | None = field(default=None, repr=False)
    dam_mac_key: bytes | None = field(default=None, repr=False)
    dam_encryption_key: bytes | None = field(default=None, repr=False)
    auth_commands: int | None = None
    preferred_auth_command: int | None = None


@dataclass(frozen=True, slots=True)
class Application:
    aid: bytes
    num_keys: int
    key_len: int
    df_name: bytes = b""
    num_key_sets: int = 0
    iso_file_id: int | None = None
    delegated_slot_number: int = 0
    delegated_quota_limit: int = 0
    delegated_free_blocks: int = 0
    key_settings_1: int = 0
    key_settings_2: int = 0
    auth_command: int = 0
    key_set_max_size: int = 0
    key_set_settings: int = 0
    key_set_versions: bytes = b""
    key_set_types: bytes = b""
    key_set_initialized: bytes = b""
    capability_data: bytes | None = None
    delegated: bool = False
    delegated_slot_version: int = 0
    auth_commands: int | None = None
    preferred_auth_command: int | None = None
    sm_disable: int | None = None


@dataclass(frozen=True, slots=True)
class File:
    owner: int
    number: int
    type: int
    comm_settings: int
    access_rights: int
    data: bytes = field(default=b"", repr=False)
    declared_size: int = 0
    values: tuple[int, int, int, int] = (0, 0, 0, 0)
    record_size: int = 0
    max_records: int = 0
    record_count: int = 0
    iso_file_id: int | None = None
    contents_complete: bool = True
    transaction_pending: bool = False
    limited_credit: bool = False
    value_pending: bool = False
    sdm: tuple[int, ...] = ()
    transaction_mac_key_type: int = 0
    transaction_mac_key_version: int = 0
    transaction_mac_key: bytes = field(default=b"", repr=False)
    transaction_mac: bytes = b""
    previous_reader_id: bytes = b""


@dataclass(frozen=True, slots=True)
class Key:
    owner: int
    slot: int
    value: bytes = field(repr=False)
    version: int = 0
    key_set: int = 0


@dataclass(frozen=True, slots=True)
class CredentialModel:
    card: Card
    picc: PiccSettings
    applications: tuple[Application, ...] = ()
    files: tuple[File, ...] = ()
    keys: tuple[Key, ...] = field(default=(), repr=False)


@dataclass(frozen=True, slots=True)
class Activation:
    uid: bytes
    ats: bytes
    atqa: bytes
    sak: int
    protocol: bytes
    rf_detail: bytes


@dataclass(frozen=True, slots=True)
class Snapshot:
    selected: int
    selected_application_index: int
    selected_aid: bytes
    dirty: bool
    auth_mode: int
    auth_key_no: int
    ev2_active: bool
    ev2_key_no: int
    ev2_command_counter: int
    ev2_transaction_identifier: bytes
    ev2_encryption_key: bytes = field(repr=False)
    ev2_mac_key: bytes = field(repr=False)
    virtual_card_selected: bool = False
    proximity_verified: bool = False


@dataclass(frozen=True, slots=True)
class ReaderState:
    auth_mode: int
    key_no: int
    ev2_command_counter: int
    ev2_transaction_identifier: bytes
    ev2_card_capabilities: bytes
    ev2_reader_capabilities: bytes


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    data: bytes


@runtime_checkable
class Transport(Protocol):
    def transceive(self, command: bytes) -> bytes: ...
