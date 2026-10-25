use core::ptr::NonNull;

use dfc_core_sys as sys;

use crate::{Error, ensure_abi};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionMacError {
    Abi(Error),
    Native(i32),
}

pub struct TransactionMacVerifier(NonNull<sys::DfcFfiTransactionMacVerifier>);

impl TransactionMacVerifier {
    pub fn new(
        key: &[u8; 16],
        uid: &[u8],
        counter: u32,
        capacity: usize,
    ) -> Result<Self, TransactionMacError> {
        ensure_abi().map_err(TransactionMacError::Abi)?;
        let mut pointer = core::ptr::null_mut();
        let status = unsafe {
            sys::dfc_ffi_transaction_mac_verifier_new(
                capacity,
                key.as_ptr(),
                uid.as_ptr(),
                uid.len(),
                counter,
                &mut pointer,
            )
        };
        if status != 0 {
            return Err(TransactionMacError::Native(status));
        }
        NonNull::new(pointer)
            .map(Self)
            .ok_or(TransactionMacError::Native(-1))
    }

    fn check(status: i32) -> Result<(), TransactionMacError> {
        if status == 0 {
            Ok(())
        } else {
            Err(TransactionMacError::Native(status))
        }
    }

    pub fn add_data(
        &mut self,
        command: u8,
        file: u8,
        offset: u32,
        length: u32,
        data: &[u8],
    ) -> Result<(), TransactionMacError> {
        Self::check(unsafe {
            sys::dfc_ffi_transaction_mac_add_data(
                self.0.as_ptr(),
                command,
                file,
                offset,
                length,
                data.as_ptr(),
                data.len(),
            )
        })
    }

    pub fn add_record_update(
        &mut self,
        command: u8,
        file: u8,
        record: u32,
        offset: u32,
        length: u32,
        data: &[u8],
    ) -> Result<(), TransactionMacError> {
        Self::check(unsafe {
            sys::dfc_ffi_transaction_mac_add_record_update(
                self.0.as_ptr(),
                command,
                file,
                record,
                offset,
                length,
                data.as_ptr(),
                data.len(),
            )
        })
    }

    pub fn add_value(
        &mut self,
        command: u8,
        file: u8,
        value: u32,
    ) -> Result<(), TransactionMacError> {
        Self::check(unsafe {
            sys::dfc_ffi_transaction_mac_add_value(self.0.as_ptr(), command, file, value)
        })
    }

    pub fn add_clear_record(&mut self, file: u8) -> Result<(), TransactionMacError> {
        Self::check(unsafe { sys::dfc_ffi_transaction_mac_add_clear_record(self.0.as_ptr(), file) })
    }

    pub fn add_reader_id(
        &mut self,
        current: &[u8; 16],
        encrypted_previous: &[u8; 16],
    ) -> Result<(), TransactionMacError> {
        Self::check(unsafe {
            sys::dfc_ffi_transaction_mac_add_reader_id(
                self.0.as_ptr(),
                current.as_ptr(),
                encrypted_previous.as_ptr(),
            )
        })
    }

    pub fn verify(&self, mac: &[u8; 8]) -> Result<bool, TransactionMacError> {
        let mut verified = 0;
        Self::check(unsafe {
            sys::dfc_ffi_transaction_mac_verify(self.0.as_ptr(), mac.as_ptr(), &mut verified)
        })?;
        Ok(verified != 0)
    }
}

impl Drop for TransactionMacVerifier {
    fn drop(&mut self) {
        unsafe { sys::dfc_ffi_transaction_mac_verifier_free(self.0.as_ptr()) }
    }
}
