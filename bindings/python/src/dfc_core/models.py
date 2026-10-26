from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Protocol, runtime_checkable


class BuildRole(IntEnum):
    """Native library deployment role.

    Values:
        UNKNOWN: The loaded library did not report a recognized role.
        TARGET: Embedded target build.
        HOST: Hosted library build.
        SIMULATOR: Virtual-card simulator build.
    """

    UNKNOWN = 0
    TARGET = 1
    HOST = 2
    SIMULATOR = 3


class BuildProfile(IntEnum):
    """Feature and model-capacity profile compiled into the native library.

    Values:
        UNKNOWN: The loaded library did not report a recognized profile.
        MINIMAL_EV1: Minimal EV1-compatible profile.
        FULL_EV1: Full EV1-compatible profile.
        FULL_EV2: Full EV2-compatible profile.
        FULL_EV3: Full EV3-compatible profile.
        MINIMAL_EV3: Minimal EV3-compatible profile.
    """

    UNKNOWN = 0
    MINIMAL_EV1 = 1
    FULL_EV1 = 2
    FULL_EV2 = 3
    FULL_EV3 = 4
    MINIMAL_EV3 = 5


class Framing(IntEnum):
    """Wire framing used by a reader transport.

    Values:
        ISO_7816: Complete ISO command and response APDUs.
        NATIVE: Native ``instruction || data`` commands and ``status || data`` responses.
    """

    ISO_7816 = 0
    NATIVE = 1


class CommunicationMode(IntEnum):
    """Secure-messaging protection requested for a command or configured file.

    Values:
        PLAIN: No command-data encryption or message authentication.
        MAC: Authenticate the command or response without encrypting its data.
        ENCIPHERED: Encrypt and authenticate protected command or response data.
    """

    PLAIN = 0
    MAC = 1
    ENCIPHERED = 3


class FileType(IntEnum):
    """Type-specific storage and command behavior of a credential file.

    Values:
        STANDARD_DATA: Directly written data file.
        BACKUP_DATA: Transactional data file.
        VALUE: Transactional signed-value file.
        LINEAR_RECORD: Append-only record file until capacity is reached.
        CYCLIC_RECORD: Record file that overwrites its oldest record at capacity.
        TRANSACTION_MAC: Transaction receipt and counter file.
    """

    STANDARD_DATA = 0
    BACKUP_DATA = 1
    VALUE = 2
    LINEAR_RECORD = 3
    CYCLIC_RECORD = 4
    TRANSACTION_MAC = 5


class Selection(IntEnum):
    """Selected card level reported by a virtual PICC.

    Values:
        NONE: No active protocol selection.
        PICC: Card master level selected.
        APPLICATION: One application selected.
    """

    NONE = 0
    PICC = 1
    APPLICATION = 2


class PiccAuthenticationMode(IntEnum):
    """Native authentication cipher active in a PICC session.

    Values:
        LEGACY: Legacy DES authentication.
        ISO: ISO DES or TDEA authentication.
        AES: AES-family authentication. Check ``Snapshot.ev2_command_counter`` for EV2 state.
    """

    LEGACY = 0x0A
    ISO = 0x1A
    AES = 0xAA


class ReaderAuthenticationMode(IntEnum):
    """Authentication family active in a reader session.

    Values:
        LEGACY: Legacy DES authentication.
        ISO: ISO DES or TDEA authentication.
        AES: AES authentication without EV2 command counters.
        EV2: EV2 authentication and secure messaging.
    """

    LEGACY = 0x0A
    ISO = 0x1A
    AES = 0xAA
    EV2 = 0x71


@dataclass(frozen=True, slots=True)
class Capabilities:
    """Capabilities and fixed limits reported by the loaded native library.

    Attributes:
        abi_version: Stable native FFI ABI version.
        build_role: Deployment role compiled into the library.
        build_profile: Feature/capacity profile compiled into the library.
        features: Names of enabled optional features.
        max_applications: Maximum applications in one credential model.
        max_files: Maximum files across the model.
        max_keys: Maximum keys owned by one PICC or application.
        file_pool_size: Bytes available for file contents.
        key_pool_size: Bytes available for key material and key-set metadata.
    """

    abi_version: int
    build_role: BuildRole
    build_profile: BuildProfile
    features: frozenset[str]
    max_applications: int
    max_files: int
    max_keys: int
    file_pool_size: int
    key_pool_size: int


@dataclass(frozen=True, slots=True)
class Card:
    """Immutable card identity and manufacturing metadata.

    Attributes:
        generation: Card-generation identifier encoded by the credential format.
        storage: Card storage-size identifier encoded by the credential format.
        uid_provenance: UID provenance identifier encoded by the credential format.
        uid: Four-, seven-, or ten-byte UID in display/model order.
        hardware_version: Optional seven-byte hardware version block.
        software_version: Optional seven-byte software version block.
        static_signature: Optional 56-byte originality signature.
    """

    generation: int
    storage: int
    uid_provenance: int
    uid: bytes
    hardware_version: bytes | None = None
    software_version: bytes | None = None
    static_signature: bytes | None = None


@dataclass(frozen=True, slots=True)
class PiccSettings:
    """Card-master settings copied from a credential.

    Secret byte strings are immutable Python copies and cannot be securely recalled.

    Attributes:
        num_keys: Number of card-master key slots.
        key_len: Bytes stored for each card-master key.
        key_settings_1: First raw card-master key-settings byte.
        key_settings_2: Second raw card-master key-settings byte.
        auth_command: Preferred native authentication instruction.
        random_id: Whether activation may expose a random identifier.
        random_id_legacy: Whether legacy random-ID behavior is enabled.
        format_disabled: Whether card formatting is disabled.
        ats: ISO activation answer bytes.
        sak: Optional select-acknowledge byte.
        atqa: Optional two-byte answer-to-request value.
        sm_disable: Optional secure-messaging disable policy byte.
        ev2_capabilities: Optional six-byte EV2 capability block.
        proximity_key: Optional secret 16-byte proximity key.
        proximity_option: Raw proximity-check option byte.
        proximity_bitrate: Optional proximity-check bitrate byte.
        proximity_published_response_time: Published response time in native timer units.
        virtual_card_installation_id: Optional virtual-card installation identifier.
        virtual_card_information: Raw virtual-card information byte.
        virtual_card_capabilities: Two-byte virtual-card capability block.
        virtual_card_uid: Virtual-card UID in model order.
        virtual_card_select_mac_key: Secret virtual-card selection MAC key.
        virtual_card_select_encryption_key: Secret virtual-card selection encryption key.
        virtual_card_authentication_mandatory: Whether virtual-card authentication is required.
        virtual_card_proximity_mandatory: Whether virtual-card proximity verification is required.
        dam_auth_key: Optional secret delegated-application authentication key.
        dam_mac_key: Optional secret delegated-application MAC key.
        dam_encryption_key: Optional secret delegated-application encryption key.
        auth_commands: Optional bit set of permitted authentication instructions.
        preferred_auth_command: Optional preferred authentication instruction.
    """

    num_keys: int
    key_len: int
    key_settings_1: int = 0
    key_settings_2: int = 0
    auth_command: int = 0
    random_id: bool = False
    random_id_legacy: bool = False
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
    """Immutable application settings copied from a credential.

    Attributes:
        aid: Three-byte application identifier in display/model order.
        num_keys: Number of application key slots.
        key_len: Bytes stored for each application key.
        df_name: Optional ISO dedicated-file name.
        num_key_sets: Configured key-set count, including the active set.
        iso_file_id: Optional ISO dedicated-file identifier.
        delegated_slot_number: Delegated-application slot number.
        delegated_quota_limit: Delegated quota limit in blocks.
        delegated_free_blocks: Remaining delegated blocks.
        key_settings_1: First raw application key-settings byte.
        key_settings_2: Second raw application key-settings byte.
        auth_command: Preferred native authentication instruction.
        key_set_max_size: Maximum keys per key set.
        key_set_settings: Raw key-set policy byte.
        key_set_versions: Version byte for each possible key set.
        key_set_types: Key-type byte for each possible key set.
        key_set_initialized: Nonzero byte for each initialized key set.
        capability_data: Optional application capability bytes.
        delegated: Whether this is a delegated application.
        delegated_slot_version: Delegated slot version.
        delegated_format_disabled: Whether delegated formatting is disabled.
        auth_commands: Optional bit set of permitted authentication instructions.
        preferred_auth_command: Optional preferred authentication instruction.
        sm_disable: Optional secure-messaging disable policy byte.
    """

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
    delegated_format_disabled: bool = False
    auth_commands: int | None = None
    preferred_auth_command: int | None = None
    sm_disable: int | None = None


@dataclass(frozen=True, slots=True)
class File:
    """Immutable file settings and contents copied from a credential.

    Attributes:
        owner: Application index, or ``-1`` for a PICC-level file.
        number: Native file number.
        type: File storage/command type.
        comm_settings: Configured communication protection.
        access_rights: Packed raw access-rights value.
        data: File-pool bytes. Immutable copies cannot be securely recalled.
        declared_size: Configured data-file size in bytes.
        values: Lower limit, upper limit, current value, and pending delta.
        record_size: Bytes per record.
        max_records: Configured record capacity.
        record_count: Currently committed record count.
        iso_file_id: Optional ISO elementary-file identifier.
        contents_complete: Whether all declared contents are present.
        transaction_pending: Whether transactional data is uncommitted.
        limited_credit: Raw limited-credit policy value.
        limited_credit_value: Configured limited-credit amount.
        value_pending: Whether a value-file delta is uncommitted.
        sdm: Raw stable SDM field tuple from the credential ABI.
        transaction_mac_key_type: Transaction-MAC key-type byte.
        transaction_mac_key_version: Transaction-MAC key version.
        transaction_mac_key: Secret Transaction-MAC key copy.
        transaction_mac: Most recently stored eight-byte Transaction MAC.
        previous_reader_id: Most recently stored 16-byte reader identifier.
    """

    owner: int
    number: int
    type: FileType
    comm_settings: CommunicationMode
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
    limited_credit: int = 0
    limited_credit_value: int = 0
    value_pending: bool = False
    sdm: tuple[int, ...] = ()
    transaction_mac_key_type: int = 0
    transaction_mac_key_version: int = 0
    transaction_mac_key: bytes = field(default=b"", repr=False)
    transaction_mac: bytes = b""
    previous_reader_id: bytes = b""


@dataclass(frozen=True, slots=True)
class Key:
    """One credential key copied into immutable Python storage.

    Attributes:
        owner: Application index, or ``-1`` for a PICC-level key.
        slot: Key number within its owner and key set.
        value: Secret key bytes. Immutable copies cannot be securely recalled.
        version: Key version byte.
        key_set: Key-set number, zero for the primary set.
    """

    owner: int
    slot: int
    value: bytes = field(repr=False)
    version: int = 0
    key_set: int = 0


@dataclass(frozen=True, slots=True)
class CredentialModel:
    """Complete immutable Python copy of a native credential model.

    Attributes:
        card: Card identity and version metadata.
        picc: Card-master settings.
        applications: Applications in model index order.
        files: Files across the PICC and applications.
        keys: Secret key copies. Immutable copies cannot be securely recalled.
    """

    card: Card
    picc: PiccSettings
    applications: tuple[Application, ...] = ()
    files: tuple[File, ...] = ()
    keys: tuple[Key, ...] = field(default=(), repr=False)


@dataclass(frozen=True, slots=True)
class Activation:
    """Activation values returned by a virtual PICC.

    Attributes:
        uid: Active UID in transmitted order.
        ats: ISO activation answer bytes.
        atqa: Two-byte answer-to-request value.
        sak: Select-acknowledge byte.
        protocol: Protocol-identification bytes.
        rf_detail: RF implementation detail bytes.
    """

    uid: bytes
    ats: bytes
    atqa: bytes
    sak: int
    protocol: bytes
    rf_detail: bytes


@dataclass(frozen=True, slots=True)
class Snapshot:
    """Non-secret virtual-PICC session state.

    Attributes:
        selection: Current selection level.
        selected_application_index: Model index only while an application is selected.
        selected_aid: Selected three-byte AID in model order, otherwise empty.
        dirty: Whether persistent card state changed since it was marked persisted.
        authentication: Active PICC authentication cipher, or ``None``.
        authenticated_key_no: Active native key number, or ``None``.
        ev2_key_no: EV2 key number only while EV2 messaging is active.
        ev2_command_counter: EV2 command counter only while EV2 messaging is active.
        virtual_card_selected: Whether virtual-card selection completed.
        proximity_verified: Whether proximity verification completed.
    """

    selection: Selection
    selected_application_index: int | None
    selected_aid: bytes
    dirty: bool
    authentication: PiccAuthenticationMode | None
    authenticated_key_no: int | None
    ev2_key_no: int | None
    ev2_command_counter: int | None
    virtual_card_selected: bool = False
    proximity_verified: bool = False


@dataclass(frozen=True, slots=True)
class ReaderState:
    """Non-secret state of a reader secure-messaging session.

    Attributes:
        authentication: Active authentication family, or ``None``.
        key_no: Active key number, or ``None`` when unauthenticated.
        ev2_command_counter: Counter only while EV2 messaging is active.
        ev2_transaction_identifier: Four-byte EV2 identifier, otherwise empty.
        ev2_card_capabilities: Six-byte EV2 card capabilities, otherwise empty.
        ev2_reader_capabilities: Six-byte EV2 reader capabilities, otherwise empty.
    """

    authentication: ReaderAuthenticationMode | None
    key_no: int | None
    ev2_command_counter: int | None
    ev2_transaction_identifier: bytes
    ev2_card_capabilities: bytes
    ev2_reader_capabilities: bytes


@dataclass(frozen=True, slots=True)
class Response:
    """One completed reader response.

    Attributes:
        status: Native card status byte promoted to an integer.
        data: Response bytes with framing and status removed.
    """

    status: int
    data: bytes


@runtime_checkable
class Transport(Protocol):
    """Exchange one card frame.

    ISO framing carries complete command and response APDUs. Native framing
    carries ``INS || data`` and returns ``status || data``.
    """

    def transceive(self, command: bytes) -> bytes:
        """Send one frame and receive its complete response.

        Args:
            command: Complete frame in the reader's configured framing.

        Returns:
            Complete response frame using the same framing convention.
        """

        ...
