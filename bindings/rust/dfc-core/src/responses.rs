use alloc::vec::Vec;

use dfc_core_sys as sys;

use crate::{Error, ensure_abi};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    Abi(Error),
    Malformed,
    Unsupported,
    BufferTooSmall,
    Native(i32),
}

fn ensure() -> Result<(), DecodeError> {
    ensure_abi().map_err(DecodeError::Abi)
}

fn decode_status(value: i32) -> Result<(), DecodeError> {
    match value {
        0 => Ok(()),
        1 => Err(DecodeError::Malformed),
        2 => Err(DecodeError::Unsupported),
        3 => Err(DecodeError::BufferTooSmall),
        other => Err(DecodeError::Native(other)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionPart {
    pub vendor_id: u8,
    pub kind: u8,
    pub subtype: u8,
    pub major_version: u8,
    pub minor_version: u8,
    pub storage_size: u8,
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
pub struct Version {
    pub hardware: VersionPart,
    pub software: VersionPart,
    pub uid: [u8; 7],
    pub batch_number: [u8; 5],
    pub production_week: u8,
    pub production_year: u8,
}

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
pub enum Access {
    Key(u8),
    Free,
    Denied,
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
pub enum FileSettingsKind {
    Data {
        size: u32,
    },
    Value {
        lower_limit: i32,
        upper_limit: i32,
        limited_credit_value: i32,
        limited_credit_enabled: bool,
    },
    Records {
        record_size: u32,
        max_records: u32,
        current_records: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSettings {
    pub file_type: u8,
    pub communication_mode: u8,
    pub access_rights_raw: u16,
    pub read: Access,
    pub write: Access,
    pub read_write: Access,
    pub change: Access,
    pub kind: FileSettingsKind,
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("fixed slice"))
}

fn i32_at(bytes: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("fixed slice"))
}

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
        file_type: bytes[0],
        communication_mode: bytes[1],
        access_rights_raw: u16::from_le_bytes([bytes[4], bytes[5]]),
        read: access(&bytes[6..8])?,
        write: access(&bytes[8..10])?,
        read_write: access(&bytes[10..12])?,
        change: access(&bytes[12..14])?,
        kind,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySettings {
    pub settings_1: u8,
    pub settings_2: u8,
    pub key_type: u8,
    pub key_count: u8,
    pub key_set: Option<(u8, u8, u8, u8)>,
}

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

pub fn decode_key_version(response: &[u8]) -> Result<u8, DecodeError> {
    ensure()?;
    let mut version = 0;
    decode_status(unsafe {
        sys::dfc_ffi_response_decode_key_version(response.as_ptr(), response.len(), &mut version)
    })?;
    Ok(version)
}
