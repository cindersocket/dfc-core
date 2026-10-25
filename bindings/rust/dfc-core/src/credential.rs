use crate::{Error, ensure_abi, output, status, wipe};
use core::{ffi::c_char, mem::MaybeUninit, ptr::NonNull};
use dfc_core_sys as sys;

/// A key copied from a credential. Its native buffer is wiped on drop.
pub struct CredentialKey(sys::DfcFfiKey);

/// PICC settings copied from a credential. Secret fields are wiped on drop.
pub struct CredentialPiccSettings(sys::DfcFfiPiccSettings);

/// File metadata copied from a credential. Transaction-MAC material is wiped on drop.
pub struct CredentialFile(sys::DfcFfiFile);

impl CredentialKey {
    fn clear(&mut self) {
        wipe(&mut self.0);
    }
}
impl CredentialPiccSettings {
    fn clear(&mut self) {
        wipe(&mut self.0);
    }
}
impl CredentialFile {
    fn clear(&mut self) {
        wipe(&mut self.0);
    }
}

impl core::ops::Deref for CredentialPiccSettings {
    type Target = sys::DfcFfiPiccSettings;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl core::ops::DerefMut for CredentialPiccSettings {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for CredentialPiccSettings {
    fn drop(&mut self) {
        self.clear();
    }
}
impl core::ops::Deref for CredentialFile {
    type Target = sys::DfcFfiFile;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl core::ops::DerefMut for CredentialFile {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for CredentialFile {
    fn drop(&mut self) {
        self.clear();
    }
}

impl core::ops::Deref for CredentialKey {
    type Target = sys::DfcFfiKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for CredentialKey {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Native indices are `uint32_t`; a larger caller index is refused, never wrapped
/// onto a different (valid) entry.
fn native_index(index: usize) -> Result<u32, Error> {
    u32::try_from(index).map_err(|_| Error::InvalidArgument)
}

pub struct Credential {
    raw: NonNull<sys::DfcFfiCredential>,
}

unsafe impl Send for Credential {}

impl Credential {
    pub fn new() -> Result<Self, Error> {
        ensure_abi()?;
        let mut raw = core::ptr::null_mut();
        status(unsafe { sys::dfc_ffi_credential_new(&mut raw) })?;
        Self::from_raw(raw)
    }

    pub fn parse_text(text: &str) -> Result<Self, Error> {
        ensure_abi()?;
        let mut raw = core::ptr::null_mut();
        status(unsafe {
            sys::dfc_ffi_credential_parse_text(
                text.as_ptr().cast::<c_char>(),
                text.len(),
                &mut raw,
                core::ptr::null_mut(),
            )
        })?;
        Self::from_raw(raw)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        ensure_abi()?;
        let mut raw = core::ptr::null_mut();
        status(unsafe {
            sys::dfc_ffi_credential_decode(
                bytes.as_ptr(),
                bytes.len(),
                &mut raw,
                core::ptr::null_mut(),
            )
        })?;
        Self::from_raw(raw)
    }

    pub fn load(bytes: &[u8]) -> Result<Self, Error> {
        ensure_abi()?;
        let mut raw = core::ptr::null_mut();
        status(unsafe {
            sys::dfc_ffi_credential_load(
                bytes.as_ptr(),
                bytes.len(),
                &mut raw,
                core::ptr::null_mut(),
            )
        })?;
        Self::from_raw(raw)
    }

    pub fn validate(&self) -> Result<(), Error> {
        status(unsafe { sys::dfc_ffi_credential_validate(self.raw.as_ptr()) })
    }

    pub fn card(&self) -> Result<sys::DfcFfiCard, Error> {
        let mut value = MaybeUninit::uninit();
        status(unsafe { sys::dfc_ffi_credential_get_card(self.raw.as_ptr(), value.as_mut_ptr()) })?;
        Ok(unsafe { value.assume_init() })
    }

    pub fn picc_settings(&self) -> Result<CredentialPiccSettings, Error> {
        let mut value = sys::DfcFfiPiccSettings::default();
        if let Err(error) =
            status(unsafe { sys::dfc_ffi_credential_get_picc(self.raw.as_ptr(), &mut value) })
        {
            wipe(&mut value);
            return Err(error);
        }
        Ok(CredentialPiccSettings(value))
    }

    pub fn application_count(&self) -> usize {
        unsafe { sys::dfc_ffi_credential_application_count(self.raw.as_ptr()) as usize }
    }

    pub fn application(&self, index: usize) -> Result<sys::DfcFfiApplication, Error> {
        let index = native_index(index)?;
        let mut value = MaybeUninit::uninit();
        status(unsafe {
            sys::dfc_ffi_credential_get_application(self.raw.as_ptr(), index, value.as_mut_ptr())
        })?;
        Ok(unsafe { value.assume_init() })
    }

    pub fn file_count(&self) -> usize {
        unsafe { sys::dfc_ffi_credential_file_count(self.raw.as_ptr()) as usize }
    }

    pub fn file(&self, index: usize) -> Result<CredentialFile, Error> {
        let index = native_index(index)?;
        let mut value = sys::DfcFfiFile::default();
        if let Err(error) = status(unsafe {
            sys::dfc_ffi_credential_get_file(self.raw.as_ptr(), index, &mut value)
        }) {
            wipe(&mut value);
            return Err(error);
        }
        Ok(CredentialFile(value))
    }

    pub fn file_data(&self, index: usize) -> Result<Vec<u8>, Error> {
        let index = native_index(index)?;
        output(|out, cap, len| unsafe {
            sys::dfc_ffi_credential_get_file_data(self.raw.as_ptr(), index, out, cap, len)
        })
    }

    pub fn key(&self, owner: i32, key_set: u32, slot: u32) -> Result<CredentialKey, Error> {
        let mut value = sys::DfcFfiKey::default();
        let result = status(unsafe {
            sys::dfc_ffi_credential_get_key(self.raw.as_ptr(), owner, key_set, slot, &mut value)
        });
        if let Err(error) = result {
            wipe(&mut value);
            return Err(error);
        }
        Ok(CredentialKey(value))
    }

    pub fn set_card(&mut self, card: &sys::DfcFfiCard) -> Result<(), Error> {
        status(unsafe { sys::dfc_ffi_credential_set_card(self.raw.as_ptr(), card) })
    }

    pub fn set_picc_settings(&mut self, picc: &sys::DfcFfiPiccSettings) -> Result<(), Error> {
        status(unsafe { sys::dfc_ffi_credential_set_picc(self.raw.as_ptr(), picc) })
    }

    pub fn add_application(&mut self, application: &sys::DfcFfiApplication) -> Result<u32, Error> {
        let mut index = 0;
        status(unsafe {
            sys::dfc_ffi_credential_add_application(self.raw.as_ptr(), application, &mut index)
        })?;
        Ok(index)
    }

    pub fn add_file(&mut self, file: &sys::DfcFfiFile) -> Result<u32, Error> {
        let mut index = 0;
        status(unsafe { sys::dfc_ffi_credential_add_file(self.raw.as_ptr(), file, &mut index) })?;
        Ok(index)
    }

    pub fn set_file_data(&mut self, index: u32, data: &[u8]) -> Result<(), Error> {
        status(unsafe {
            sys::dfc_ffi_credential_set_file_data(
                self.raw.as_ptr(),
                index,
                data.as_ptr(),
                data.len(),
            )
        })
    }

    pub fn set_key(
        &mut self,
        owner: i32,
        key_set: u32,
        slot: u32,
        key: &sys::DfcFfiKey,
    ) -> Result<(), Error> {
        status(unsafe {
            sys::dfc_ffi_credential_set_key(self.raw.as_ptr(), owner, key_set, slot, key)
        })
    }

    pub fn finish(&mut self) -> Result<(), Error> {
        status(unsafe { sys::dfc_ffi_credential_finish(self.raw.as_ptr(), core::ptr::null_mut()) })
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        output(|out, cap, len| unsafe {
            sys::dfc_ffi_credential_encode(self.raw.as_ptr(), out, cap, len)
        })
    }

    pub fn write_text(&self) -> Result<String, Error> {
        let bytes = output(|out, cap, len| unsafe {
            sys::dfc_ffi_credential_write_text(self.raw.as_ptr(), out.cast(), cap, len)
        })?;
        match String::from_utf8(bytes) {
            Ok(text) => Ok(text),
            Err(error) => {
                let mut bytes = error.into_bytes();
                bytes.fill(0);
                Err(Error::Native(-1))
            }
        }
    }

    pub(crate) fn from_raw(raw: *mut sys::DfcFfiCredential) -> Result<Self, Error> {
        Ok(Self {
            raw: NonNull::new(raw).ok_or(Error::OutOfMemory)?,
        })
    }

    pub(crate) fn as_ptr(&self) -> *const sys::DfcFfiCredential {
        self.raw.as_ptr()
    }

    pub(crate) fn into_raw(self) -> *mut sys::DfcFfiCredential {
        let raw = self.raw.as_ptr();
        core::mem::forget(self);
        raw
    }
}

impl Drop for Credential {
    fn drop(&mut self) {
        unsafe { sys::dfc_ffi_credential_free(self.raw.as_ptr()) }
    }
}

#[cfg(test)]
mod lifetime_tests {
    use super::*;

    #[test]
    fn secret_bearing_values_clear_their_storage() {
        let mut key = CredentialKey(sys::DfcFfiKey::default());
        key.0.value.fill(0xa1);
        key.clear();
        assert!(key.0.value.iter().all(|byte| *byte == 0));

        let mut picc = CredentialPiccSettings(sys::DfcFfiPiccSettings::default());
        picc.0.proximity_key.fill(0xa2);
        picc.0.virtual_card_select_mac_key.fill(0xa3);
        picc.clear();
        assert!(picc.0.proximity_key.iter().all(|byte| *byte == 0));
        assert!(
            picc.0
                .virtual_card_select_mac_key
                .iter()
                .all(|byte| *byte == 0)
        );

        let mut file = CredentialFile(sys::DfcFfiFile::default());
        file.0.transaction_mac_key.fill(0xa4);
        file.clear();
        assert!(file.0.transaction_mac_key.iter().all(|byte| *byte == 0));
    }
}
