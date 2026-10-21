use alloc::alloc::{alloc_zeroed, dealloc};
use core::{alloc::Layout, mem::MaybeUninit, ptr::NonNull};

use dfc_core_sys as sys;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetError {
    InvalidArgument,
    OutOfMemory,
    Native(i32),
}

pub type Error = TargetError;

fn layout(value: sys::DfcTargetLayout) -> Result<Layout, Error> {
    Layout::from_size_align(value.size, value.alignment).map_err(|_| Error::InvalidArgument)
}

fn checked(status: i32) -> Result<(), Error> {
    if status == 0 {
        Ok(())
    } else {
        Err(Error::Native(status))
    }
}

pub struct TargetCredential {
    storage: NonNull<u8>,
    layout: Layout,
}

unsafe impl Send for TargetCredential {}

impl TargetCredential {
    pub fn decode(content: &[u8]) -> Result<Self, Error> {
        let layout = layout(unsafe { sys::dfc_target_credential_layout() })?;
        let storage = NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(Error::OutOfMemory)?;
        unsafe { sys::dfc_target_credential_init(storage.as_ptr().cast()) };
        if let Err(error) = checked(unsafe {
            sys::dfc_target_credential_decode(
                storage.as_ptr().cast(),
                content.as_ptr(),
                content.len(),
            )
        }) {
            unsafe {
                sys::dfc_target_credential_destroy(storage.as_ptr().cast());
                dealloc(storage.as_ptr(), layout);
            }
            return Err(error);
        }
        Ok(Self { storage, layout })
    }

    pub fn validate(&self) -> Result<(), Error> {
        checked(unsafe { sys::dfc_target_credential_validate(self.storage.as_ptr().cast()) })
    }

    pub fn encoded_len(&self) -> Result<usize, Error> {
        let mut len = 0;
        checked(unsafe {
            sys::dfc_target_credential_encode(
                self.storage.as_ptr().cast(),
                core::ptr::null_mut(),
                0,
                &mut len,
            )
        })?;
        Ok(len)
    }

    pub fn encode_into(&self, output: &mut [u8]) -> Result<usize, Error> {
        let mut len = output.len();
        checked(unsafe {
            sys::dfc_target_credential_encode(
                self.storage.as_ptr().cast(),
                output.as_mut_ptr(),
                output.len(),
                &mut len,
            )
        })?;
        Ok(len)
    }
}

impl Drop for TargetCredential {
    fn drop(&mut self) {
        unsafe {
            sys::dfc_target_credential_destroy(self.storage.as_ptr().cast());
            dealloc(self.storage.as_ptr(), self.layout);
        }
    }
}

pub struct TargetActivation(pub sys::DfcTargetActivation);
pub struct TargetSnapshot(pub sys::DfcTargetSnapshot);

pub struct TargetVirtualPicc {
    raw: NonNull<sys::DfcTargetPicc>,
    storage: NonNull<u8>,
    layout: Layout,
    credential: TargetCredential,
}

unsafe impl Send for TargetVirtualPicc {}

impl TargetVirtualPicc {
    pub fn new(credential: TargetCredential) -> Result<Self, Error> {
        credential.validate()?;
        let layout = layout(unsafe { sys::dfc_target_picc_layout() })?;
        let storage = NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(Error::OutOfMemory)?;
        let mut raw = core::ptr::null_mut();
        if let Err(error) = checked(unsafe {
            sys::dfc_target_picc_init(
                storage.as_ptr().cast(),
                credential.storage.as_ptr().cast(),
                &mut raw,
            )
        }) {
            unsafe { dealloc(storage.as_ptr(), layout) };
            return Err(error);
        }
        let Some(raw) = NonNull::new(raw) else {
            unsafe { dealloc(storage.as_ptr(), layout) };
            return Err(Error::OutOfMemory);
        };
        Ok(Self {
            raw,
            storage,
            layout,
            credential,
        })
    }

    pub fn activate(&mut self) -> Result<TargetActivation, Error> {
        let mut value = MaybeUninit::uninit();
        checked(unsafe { sys::dfc_target_picc_activate(self.raw.as_ptr(), value.as_mut_ptr()) })?;
        Ok(TargetActivation(unsafe { value.assume_init() }))
    }

    pub fn exchange_into(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize, Error> {
        self.exchange_inner(command, response, false)
    }

    pub fn frame_exchange_into(
        &mut self,
        frame: &[u8],
        response: &mut [u8],
    ) -> Result<usize, Error> {
        self.exchange_inner(frame, response, true)
    }

    fn exchange_inner(
        &mut self,
        input: &[u8],
        response: &mut [u8],
        framed: bool,
    ) -> Result<usize, Error> {
        let mut len = 0;
        let status = unsafe {
            if framed {
                sys::dfc_target_picc_frame_exchange(
                    self.raw.as_ptr(),
                    input.as_ptr(),
                    input.len(),
                    response.as_mut_ptr(),
                    response.len(),
                    &mut len,
                )
            } else {
                sys::dfc_target_picc_exchange(
                    self.raw.as_ptr(),
                    input.as_ptr(),
                    input.len(),
                    response.as_mut_ptr(),
                    response.len(),
                    &mut len,
                )
            }
        };
        checked(status)?;
        Ok(len)
    }

    pub fn field_off(&mut self) -> Result<(), Error> {
        checked(unsafe { sys::dfc_target_picc_field_off(self.raw.as_ptr()) })
    }
    pub fn reset_protocol(&mut self) -> Result<(), Error> {
        checked(unsafe { sys::dfc_target_picc_reset_protocol(self.raw.as_ptr()) })
    }
    pub fn advance_time(&mut self, milliseconds: u32) -> Result<(), Error> {
        checked(unsafe { sys::dfc_target_picc_advance_time(self.raw.as_ptr(), milliseconds) })
    }
    pub fn mark_persisted(&mut self) -> Result<(), Error> {
        checked(unsafe { sys::dfc_target_picc_mark_persisted(self.raw.as_ptr()) })
    }
    pub fn snapshot(&self) -> Result<TargetSnapshot, Error> {
        let mut value = MaybeUninit::uninit();
        checked(unsafe { sys::dfc_target_picc_snapshot(self.raw.as_ptr(), value.as_mut_ptr()) })?;
        Ok(TargetSnapshot(unsafe { value.assume_init() }))
    }
    pub fn credential(&self) -> &TargetCredential {
        &self.credential
    }
}

impl Drop for TargetVirtualPicc {
    fn drop(&mut self) {
        unsafe {
            sys::dfc_target_picc_destroy(self.raw.as_ptr());
            dealloc(self.storage.as_ptr(), self.layout);
        }
    }
}
