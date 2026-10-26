use alloc::vec::Vec;

use dfc_core_sys as sys;

use crate::{Error, ensure_abi, layout, reader::CommunicationMode};

#[derive(Debug, Clone, PartialEq, Eq)]
/// Failure returned when a clear command response cannot be decoded.
pub enum DecodeError {
    /// The loaded native library is incompatible with this crate.
    Abi(Error),
    /// The response is truncated or has invalid field encoding.
    Malformed,
    /// The response describes a form this build does not support.
    Unsupported,
    /// The destination required by the native decoder was too small.
    BufferTooSmall,
    /// The native decoder failed with this status code.
    Native(i32),
}

fn ensure() -> Result<(), DecodeError> {
    ensure_abi().map_err(DecodeError::Abi)
}

fn decode_status(value: i32) -> Result<(), DecodeError> {
    match value {
        value if value == layout::DFC_FFI_RESPONSE_OK as i32 => Ok(()),
        value if value == layout::DFC_FFI_RESPONSE_MALFORMED as i32 => Err(DecodeError::Malformed),
        value if value == layout::DFC_FFI_RESPONSE_UNSUPPORTED as i32 => {
            Err(DecodeError::Unsupported)
        }
        value if value == layout::DFC_FFI_RESPONSE_BUFFER_TOO_SMALL as i32 => {
            Err(DecodeError::BufferTooSmall)
        }
        other => Err(DecodeError::Native(other)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Seven-byte hardware or software version tuple.
pub struct VersionPart {
    /// Manufacturer identifier.
    pub vendor_id: u8,
    /// Product type identifier.
    pub kind: u8,
    /// Product subtype identifier.
    pub subtype: u8,
    /// Major version number.
    pub major_version: u8,
    /// Minor version number.
    pub minor_version: u8,
    /// Encoded storage-size field.
    pub storage_size: u8,
    /// Protocol identifier.
    pub protocol: u8,
}

fn version_part(bytes: &[u8]) -> VersionPart {
    VersionPart {
        vendor_id: bytes[0],
        kind: bytes[1],
        subtype: bytes[2],
        major_version: bytes[3],
        minor_version: bytes[4],
        storage_size: bytes[5],
        protocol: bytes[6],
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Fully assembled GetVersion response.
pub struct Version {
    /// Hardware version tuple.
    pub hardware: VersionPart,
    /// Software version tuple.
    pub software: VersionPart,
    /// Seven-byte card UID.
    pub uid: [u8; 7],
    /// Five-byte production batch identifier.
    pub batch_number: [u8; 5],
    /// Production week as encoded by the card.
    pub production_week: u8,
    /// Production year as encoded by the card.
    pub production_year: u8,
}

/// Decodes an assembled 28-byte GetVersion response.
pub fn decode_version(response: &[u8]) -> Result<Version, DecodeError> {
    ensure()?;
    let mut bytes = [0; 28];
    decode_status(unsafe {
        sys::dfc_ffi_response_decode_version(
            response.as_ptr(),
            response.len(),
            bytes.as_mut_ptr(),
            bytes.len(),
        )
    })?;
    Ok(Version {
        hardware: version_part(&bytes[..7]),
        software: version_part(&bytes[7..14]),
        uid: bytes[14..21].try_into().expect("fixed slice"),
        batch_number: bytes[21..26].try_into().expect("fixed slice"),
        production_week: bytes[26],
        production_year: bytes[27],
    })
}

/// Decodes application identifiers into model order.
///
/// Each returned AID is most-significant byte first, matching the credential
/// model rather than the least-significant-byte-first wire representation.
pub fn decode_application_ids(response: &[u8]) -> Result<Vec<[u8; 3]>, DecodeError> {
    ensure()?;
    let mut bytes = vec![0; response.len()];
    let mut length = 0;
    decode_status(unsafe {
        sys::dfc_ffi_response_decode_application_ids(
            response.as_ptr(),
            response.len(),
            bytes.as_mut_ptr(),
            bytes.len(),
            &mut length,
        )
    })?;
    bytes.truncate(length);
    Ok(bytes
        .chunks_exact(3)
        .map(|aid| aid.try_into().expect("three-byte chunk"))
        .collect())
}

/// Decodes the list returned by GetFileIDs.
pub fn decode_file_ids(response: &[u8]) -> Result<Vec<u8>, DecodeError> {
    ensure()?;
    let mut bytes = vec![0; response.len()];
    let mut length = 0;
    decode_status(unsafe {
        sys::dfc_ffi_response_decode_file_ids(
            response.as_ptr(),
            response.len(),
            bytes.as_mut_ptr(),
            bytes.len(),
            &mut length,
        )
    })?;
    bytes.truncate(length);
    Ok(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Decoded two-bit access-right value.
pub enum Access {
    /// Authentication with the given key number is required.
    Key(u8),
    /// Access is allowed without authentication.
    Free,
    /// Access is denied.
    Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
/// File type returned by GetFileSettings.
pub enum FileType {
    /// Standard data file.
    StandardData = 0,
    /// Transactional backup data file.
    BackupData = 1,
    /// Signed value file.
    Value = 2,
    /// Linear record file.
    LinearRecord = 3,
    /// Cyclic record file.
    CyclicRecord = 4,
}

fn file_type(value: u8) -> Result<FileType, DecodeError> {
    match value {
        0 => Ok(FileType::StandardData),
        1 => Ok(FileType::BackupData),
        2 => Ok(FileType::Value),
        3 => Ok(FileType::LinearRecord),
        4 => Ok(FileType::CyclicRecord),
        _ => Err(DecodeError::Unsupported),
    }
}

fn communication_mode(value: u8) -> Result<CommunicationMode, DecodeError> {
    match value {
        0 => Ok(CommunicationMode::Plain),
        1 => Ok(CommunicationMode::Mac),
        3 => Ok(CommunicationMode::Enciphered),
        _ => Err(DecodeError::Unsupported),
    }
}

fn access(bytes: &[u8]) -> Result<Access, DecodeError> {
    match bytes[0] {
        0 => Ok(Access::Key(bytes[1])),
        1 => Ok(Access::Free),
        2 => Ok(Access::Denied),
        _ => Err(DecodeError::Native(-1)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Fields specific to the decoded file type.
pub enum FileSettingsKind {
    /// Standard or backup data file settings.
    Data {
        /// Declared data length in bytes.
        size: u32,
    },
    /// Value-file limits and limited-credit configuration.
    Value {
        /// Smallest permitted signed value.
        lower_limit: i32,
        /// Largest permitted signed value.
        upper_limit: i32,
        /// Maximum limited-credit amount.
        limited_credit_value: i32,
        /// Whether limited credit is enabled.
        limited_credit_enabled: bool,
    },
    /// Linear or cyclic record-file settings.
    Records {
        /// Size of one record in bytes.
        record_size: u32,
        /// Maximum number of records.
        max_records: u32,
        /// Number of records currently present.
        current_records: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Decoded GetFileSettings response.
pub struct FileSettings {
    /// File storage and update semantics.
    pub file_type: FileType,
    /// Communication protection configured for the file.
    pub communication_mode: CommunicationMode,
    /// Unmodified 16-bit access-right field.
    pub access_rights_raw: u16,
    /// Read access requirement.
    pub read: Access,
    /// Write access requirement.
    pub write: Access,
    /// Combined read/write access requirement.
    pub read_write: Access,
    /// Change-settings access requirement.
    pub change: Access,
    /// File-type-specific settings.
    pub kind: FileSettingsKind,
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("fixed slice"))
}

fn i32_at(bytes: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("fixed slice"))
}

/// Decodes a GetFileSettings response.
pub fn decode_file_settings(response: &[u8]) -> Result<FileSettings, DecodeError> {
    ensure()?;
    let mut bytes = [0; 32];
    decode_status(unsafe {
        sys::dfc_ffi_response_decode_file_settings(
            response.as_ptr(),
            response.len(),
            bytes.as_mut_ptr(),
            bytes.len(),
        )
    })?;
    let kind = match bytes[0] {
        0 | 1 => FileSettingsKind::Data {
            size: u32_at(&bytes, 14),
        },
        2 => FileSettingsKind::Value {
            lower_limit: i32_at(&bytes, 14),
            upper_limit: i32_at(&bytes, 18),
            limited_credit_value: i32_at(&bytes, 22),
            limited_credit_enabled: bytes[26] != 0,
        },
        _ => FileSettingsKind::Records {
            record_size: u32_at(&bytes, 14),
            max_records: u32_at(&bytes, 18),
            current_records: u32_at(&bytes, 22),
        },
    };
    Ok(FileSettings {
        file_type: file_type(bytes[0])?,
        communication_mode: communication_mode(bytes[1])?,
        access_rights_raw: u16::from_le_bytes([bytes[4], bytes[5]]),
        read: access(&bytes[6..8])?,
        write: access(&bytes[8..10])?,
        read_write: access(&bytes[10..12])?,
        change: access(&bytes[12..14])?,
        kind,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Decoded application or PICC key settings.
pub struct KeySettings {
    /// First key-settings byte.
    pub settings_1: u8,
    /// Second key-settings byte.
    pub settings_2: u8,
    /// Native key-family identifier.
    pub key_type: u8,
    /// Number of configured keys.
    pub key_count: u8,
    /// Optional `(active_version, count, max_size, settings)` key-set tuple.
    pub key_set: Option<(u8, u8, u8, u8)>,
}

/// Decodes a GetKeySettings response.
pub fn decode_key_settings(response: &[u8]) -> Result<KeySettings, DecodeError> {
    ensure()?;
    let mut bytes = [0; 9];
    decode_status(unsafe {
        sys::dfc_ffi_response_decode_key_settings(
            response.as_ptr(),
            response.len(),
            bytes.as_mut_ptr(),
            bytes.len(),
        )
    })?;
    Ok(KeySettings {
        settings_1: bytes[0],
        settings_2: bytes[1],
        key_type: bytes[2],
        key_count: bytes[3],
        key_set: (bytes[4] != 0).then_some((bytes[5], bytes[6], bytes[7], bytes[8])),
    })
}

/// Decodes the single version byte returned by GetKeyVersion.
pub fn decode_key_version(response: &[u8]) -> Result<u8, DecodeError> {
    ensure()?;
    let mut version = 0;
    decode_status(unsafe {
        sys::dfc_ffi_response_decode_key_version(response.as_ptr(), response.len(), &mut version)
    })?;
    Ok(version)
}
