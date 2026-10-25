use alloc::vec;
use alloc::vec::Vec;

use dfc_core_sys as sys;

use crate::{Error, ensure_abi};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SdmField {
    pub offset: usize,
    pub length: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SdmConfig {
    pub mac_input_offset: usize,
    pub mac_offset: usize,
    pub plain_uid: Option<SdmField>,
    pub plain_read_counter_offset: Option<usize>,
    pub encrypted_picc_data: Option<SdmField>,
    pub encrypted_file_data: Option<SdmField>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdmResult {
    pub uid: Option<Vec<u8>>,
    pub read_counter: Option<u32>,
    pub decrypted_file_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdmError {
    Abi(Error),
    InvalidConfig,
    Native(i32),
}

fn field_is_valid(field: Option<SdmField>, message_len: usize, scale: usize) -> bool {
    field.is_none_or(|field| {
        field
            .length
            .checked_mul(scale)
            .and_then(|length| field.offset.checked_add(length))
            .is_some_and(|end| end <= message_len)
    })
}

pub fn verify_sdm(
    message: &[u8],
    config: SdmConfig,
    file_read_key: &[u8; 16],
    meta_read_key: Option<&[u8; 16]>,
) -> Result<SdmResult, SdmError> {
    ensure_abi().map_err(SdmError::Abi)?;
    let mac_is_valid = config.mac_input_offset <= config.mac_offset
        && config
            .mac_offset
            .checked_add(16)
            .is_some_and(|end| end <= message.len());
    let counter_is_valid = config.plain_read_counter_offset.is_none_or(|offset| {
        offset
            .checked_add(6)
            .is_some_and(|end| end <= message.len())
    });
    let encrypted_lengths_are_even = config
        .encrypted_picc_data
        .is_none_or(|field| field.length % 2 == 0)
        && config
            .encrypted_file_data
            .is_none_or(|field| field.length % 2 == 0);
    if !mac_is_valid
        || !counter_is_valid
        || !field_is_valid(config.plain_uid, message.len(), 2)
        || !field_is_valid(config.encrypted_picc_data, message.len(), 1)
        || !field_is_valid(config.encrypted_file_data, message.len(), 1)
        || !encrypted_lengths_are_even
    {
        return Err(SdmError::InvalidConfig);
    }
    let uid = config.plain_uid.unwrap_or(SdmField {
        offset: 0,
        length: 0,
    });
    let picc = config.encrypted_picc_data.unwrap_or(SdmField {
        offset: 0,
        length: 0,
    });
    let file = config.encrypted_file_data.unwrap_or(SdmField {
        offset: 0,
        length: 0,
    });
    let fields = u32::from(config.plain_uid.is_some())
        | (u32::from(config.plain_read_counter_offset.is_some()) << 1)
        | (u32::from(config.encrypted_picc_data.is_some()) << 2)
        | (u32::from(config.encrypted_file_data.is_some()) << 3);
    let mut decrypted = vec![0; file.length / 2];
    let mut required = 0;
    let mut packed = [0; 20];
    let status = unsafe {
        sys::dfc_ffi_sdm_verify_ascii(
            message.as_ptr(),
            message.len(),
            fields,
            uid.offset,
            uid.length,
            config.plain_read_counter_offset.unwrap_or(0),
            picc.offset,
            picc.length,
            file.offset,
            file.length,
            config.mac_input_offset,
            config.mac_offset,
            meta_read_key.map_or(core::ptr::null(), |key| key.as_ptr()),
            file_read_key.as_ptr(),
            decrypted.as_mut_ptr(),
            decrypted.len(),
            &mut required,
            packed.as_mut_ptr(),
            packed.len(),
        )
    };
    if status != 0 {
        return Err(SdmError::Native(status));
    }
    decrypted.truncate(required);
    Ok(SdmResult {
        uid: (packed[0] != 0).then(|| packed[2..2 + usize::from(packed[1])].to_vec()),
        read_counter: (packed[12] != 0)
            .then(|| u32::from_le_bytes(packed[16..20].try_into().expect("fixed result field"))),
        decrypted_file_data: decrypted,
    })
}
