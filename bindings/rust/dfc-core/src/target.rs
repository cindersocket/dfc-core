use alloc::alloc::{alloc_zeroed, dealloc};
use core::{alloc::Layout, mem::MaybeUninit, ptr::NonNull};

use dfc_core_sys as sys;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Error returned by the allocation-free target-facing API.
pub enum TargetError {
    /// An input, output buffer, or native layout value is invalid.
    InvalidArgument,
    /// Storage for a credential or virtual card could not be allocated.
    OutOfMemory,
    /// The target API failed with this native status code.
    Native(i32),
}

/// Result error used by target-role operations.
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

/// Owned credential storage for a `role-target` build.
///
/// The credential is destroyed and its allocation released on drop.
pub struct TargetCredential {
    storage: NonNull<u8>,
    layout: Layout,
}

// SAFETY: target credential storage is uniquely owned by this wrapper and the
// native API does not retain thread-local pointers into it.
unsafe impl Send for TargetCredential {}

impl TargetCredential {
    /// Decodes a binary credential into target-owned storage.
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

    /// Revalidates all model invariants.
    pub fn validate(&self) -> Result<(), Error> {
        checked(unsafe { sys::dfc_target_credential_validate(self.storage.as_ptr().cast()) })
    }

    /// Returns the exact number of bytes required by [`Self::encode_into`].
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

    /// Encodes the credential into caller-owned storage.
    ///
    /// Returns the number of bytes written. A short buffer is reported as a
    /// native error and is not partially published.
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

/// Activation parameters produced by the target virtual card.
pub struct TargetActivation(pub sys::DfcTargetActivation);
/// Public state snapshot produced by the target virtual card.
pub struct TargetSnapshot(pub sys::DfcTargetSnapshot);

/// Virtual card backed by Rust-owned native storage for `role-target` builds.
///
/// The card owns its credential and releases both allocations on drop.
pub struct TargetVirtualPicc {
    raw: NonNull<sys::DfcTargetPicc>,
    storage: NonNull<u8>,
    layout: Layout,
    credential: TargetCredential,
}

// SAFETY: the native handle and its backing allocation are uniquely owned, and
// every state-changing operation requires `&mut self`.
unsafe impl Send for TargetVirtualPicc {}

impl TargetVirtualPicc {
    /// Creates a virtual card and takes ownership of `credential`.
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

    /// Starts a new RF activation and returns its transport parameters.
    pub fn activate(&mut self) -> Result<TargetActivation, Error> {
        let mut value = MaybeUninit::uninit();
        checked(unsafe { sys::dfc_target_picc_activate(self.raw.as_ptr(), value.as_mut_ptr()) })?;
        Ok(TargetActivation(unsafe { value.assume_init() }))
    }

    /// Exchanges one complete native or ISO-wrapped command.
    ///
    /// The returned value is the number of response bytes written.
    pub fn exchange_into(&mut self, command: &[u8], response: &mut [u8]) -> Result<usize, Error> {
        self.exchange_inner(command, response, false)
    }

    /// Exchanges one ISO-DEP frame and writes the response frame in place.
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

    /// Ends the RF field and clears protocol and authentication state.
    pub fn field_off(&mut self) -> Result<(), Error> {
        checked(unsafe { sys::dfc_target_picc_field_off(self.raw.as_ptr()) })
    }
    /// Resets transport state while retaining the credential model.
    pub fn reset_protocol(&mut self) -> Result<(), Error> {
        checked(unsafe { sys::dfc_target_picc_reset_protocol(self.raw.as_ptr()) })
    }
    /// Advances the virtual card's monotonic clock by `milliseconds`.
    pub fn advance_time(&mut self, milliseconds: u32) -> Result<(), Error> {
        checked(unsafe { sys::dfc_target_picc_advance_time(self.raw.as_ptr(), milliseconds) })
    }
    /// Marks the current credential state as persisted by the caller.
    pub fn mark_persisted(&mut self) -> Result<(), Error> {
        checked(unsafe { sys::dfc_target_picc_mark_persisted(self.raw.as_ptr()) })
    }
    /// Returns a public, non-secret state snapshot.
    pub fn snapshot(&self) -> Result<TargetSnapshot, Error> {
        let mut value = MaybeUninit::uninit();
        checked(unsafe { sys::dfc_target_picc_snapshot(self.raw.as_ptr(), value.as_mut_ptr()) })?;
        Ok(TargetSnapshot(unsafe { value.assume_init() }))
    }
    /// Borrows the credential owned by this virtual card.
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
