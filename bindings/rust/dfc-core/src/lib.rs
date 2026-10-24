//! Safe bindings for DFC credentials, virtual cards, and reader sessions.
#![cfg_attr(feature = "role-target", no_std)]

extern crate alloc;

#[cfg(feature = "role-target")]
mod target;
#[cfg(feature = "role-target")]
pub use target::{
    TargetActivation, TargetCredential, TargetError, TargetSnapshot, TargetVirtualPicc,
};

#[cfg(not(feature = "role-target"))]
mod credential;
#[cfg(not(feature = "role-target"))]
mod layout;
#[cfg(not(feature = "role-target"))]
mod reader;

#[cfg(not(feature = "role-target"))]
use core::{
    fmt,
    mem::MaybeUninit,
    ptr::NonNull,
    sync::atomic::{AtomicU8, Ordering},
};
#[cfg(not(feature = "role-target"))]
use dfc_core_sys as sys;

#[cfg(not(feature = "role-target"))]
pub use credential::Credential;
#[cfg(not(feature = "role-target"))]
pub use reader::{
    Command, CommunicationMode, Framing, Reader, ReaderError, ReaderState, Response, Transport,
};

#[cfg(not(feature = "role-target"))]
static ABI_STATE: AtomicU8 = AtomicU8::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(not(feature = "role-target"))]
pub enum Error {
    InvalidArgument,
    BufferTooSmall,
    OutOfMemory,
    Unsupported,
    RandomSourceFailed,
    AbiMismatch { expected: u32, actual: u32 },
    LayoutMismatch { expected: u64, actual: u64 },
    Native(i32),
}

#[cfg(not(feature = "role-target"))]
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument => f.write_str("invalid argument"),
            Self::BufferTooSmall => f.write_str("buffer too small"),
            Self::OutOfMemory => f.write_str("native allocation failed"),
            Self::Unsupported => f.write_str("operation unsupported by this build"),
            Self::RandomSourceFailed => f.write_str("virtual PICC random source failed"),
            Self::AbiMismatch { expected, actual } => {
                write!(f, "dfc ABI mismatch: expected {expected}, found {actual}")
            }
            Self::LayoutMismatch { expected, actual } => write!(
                f,
                "dfc native layout fingerprint mismatch: expected {expected:#018x}, found {actual:#018x}"
            ),
            Self::Native(status) => write!(f, "dfc operation failed with status {status}"),
        }
    }
}

#[cfg(not(feature = "role-target"))]
impl std::error::Error for Error {}

#[cfg(not(feature = "role-target"))]
fn status(value: i32) -> Result<(), Error> {
    match value {
        0 => Ok(()),
        -1 => Err(Error::InvalidArgument),
        -2 => Err(Error::BufferTooSmall),
        -3 => Err(Error::OutOfMemory),
        -4 => Err(Error::Unsupported),
        -5 => Err(Error::RandomSourceFailed),
        other => Err(Error::Native(other)),
    }
}

#[cfg(not(feature = "role-target"))]
fn picc_retry_capacity(initial: usize, reported: usize) -> Option<usize> {
    (reported > initial && reported <= isize::MAX as usize).then_some(reported)
}

#[cfg(not(feature = "role-target"))]
fn require_layout_fingerprint(actual: u64) -> Result<(), Error> {
    let expected = layout::expected_layout_fingerprint();
    if actual != expected {
        return Err(Error::LayoutMismatch { expected, actual });
    }
    Ok(())
}

#[cfg(not(feature = "role-target"))]
fn ensure_abi() -> Result<(), Error> {
    match ABI_STATE.load(Ordering::Acquire) {
        1 => return Ok(()),
        2 => {
            let actual = unsafe { sys::dfc_ffi_abi_version() };
            return Err(Error::AbiMismatch {
                expected: sys::DFC_FFI_ABI_VERSION,
                actual,
            });
        }
        3 => {
            let actual = unsafe { sys::dfc_ffi_layout_fingerprint() };
            return Err(Error::LayoutMismatch {
                expected: layout::expected_layout_fingerprint(),
                actual,
            });
        }
        _ => {}
    }
    let actual = unsafe { sys::dfc_ffi_abi_version() };
    if actual != sys::DFC_FFI_ABI_VERSION {
        ABI_STATE.store(2, Ordering::Release);
        return Err(Error::AbiMismatch {
            expected: sys::DFC_FFI_ABI_VERSION,
            actual,
        });
    }
    let native_fingerprint = unsafe { sys::dfc_ffi_layout_fingerprint() };
    if let Err(error) = require_layout_fingerprint(native_fingerprint) {
        ABI_STATE.store(3, Ordering::Release);
        return Err(error);
    }
    let mut native = MaybeUninit::<sys::DfcFfiStructSizes>::uninit();
    unsafe { sys::dfc_ffi_struct_sizes(native.as_mut_ptr()) };
    let native = unsafe { native.assume_init() };
    let expected = [
        (native.capabilities, size_of::<sys::DfcFfiCapabilities>()),
        (native.error, size_of::<sys::DfcFfiError>()),
        (native.card, size_of::<sys::DfcFfiCard>()),
        (native.picc, size_of::<sys::DfcFfiPiccSettings>()),
        (native.application, size_of::<sys::DfcFfiApplication>()),
        (native.file, size_of::<sys::DfcFfiFile>()),
        (native.key, size_of::<sys::DfcFfiKey>()),
        (native.activation, size_of::<sys::DfcFfiActivation>()),
        (native.snapshot, size_of::<sys::DfcFfiSnapshot>()),
        (native.reader_state, size_of::<sys::DfcFfiReaderState>()),
    ];
    if expected
        .iter()
        .any(|(native, rust)| *native as usize != *rust)
    {
        ABI_STATE.store(3, Ordering::Release);
        return Err(Error::LayoutMismatch {
            expected: layout::expected_layout_fingerprint(),
            actual: native_fingerprint,
        });
    }
    ABI_STATE.store(1, Ordering::Release);
    Ok(())
}

#[cfg(not(feature = "role-target"))]
fn output(mut call: impl FnMut(*mut u8, usize, *mut usize) -> i32) -> Result<Vec<u8>, Error> {
    let mut len = 0;
    status(call(core::ptr::null_mut(), 0, &mut len))?;
    let mut bytes = vec![0; len];
    status(call(bytes.as_mut_ptr(), bytes.len(), &mut len))?;
    bytes.truncate(len);
    Ok(bytes)
}

#[derive(Debug, Clone)]
#[cfg(not(feature = "role-target"))]
pub struct Capabilities(pub sys::DfcFfiCapabilities);

#[cfg(not(feature = "role-target"))]
impl Capabilities {
    pub fn get() -> Result<Self, Error> {
        ensure_abi()?;
        let mut value = MaybeUninit::uninit();
        unsafe { sys::dfc_ffi_capabilities(value.as_mut_ptr()) };
        Ok(Self(unsafe { value.assume_init() }))
    }
}

#[cfg(not(feature = "role-target"))]
pub struct Activation(pub sys::DfcFfiActivation);
#[cfg(not(feature = "role-target"))]
pub struct Snapshot(pub sys::DfcFfiSnapshot);

#[cfg(not(feature = "role-target"))]
struct RandomContext {
    source: Box<dyn FnMut(usize) -> Vec<u8> + Send>,
}

#[cfg(not(feature = "role-target"))]
unsafe extern "C" fn random_callback(
    context: *mut core::ffi::c_void,
    buffer: *mut u8,
    len: usize,
) -> i32 {
    let context = unsafe { &mut *context.cast::<RandomContext>() };
    let generated =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (context.source)(len)));
    if let Ok(bytes) = generated {
        if bytes.len() == len {
            unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, len) };
            return 0;
        }
    }
    -5
}

#[cfg(not(feature = "role-target"))]
pub struct VirtualPicc {
    raw: NonNull<sys::DfcFfiPicc>,
    // Keeps the callback context alive for as long as native code may use it.
    _random_context: Option<Box<RandomContext>>,
}

#[cfg(not(feature = "role-target"))]
unsafe impl Send for VirtualPicc {}

#[cfg(not(feature = "role-target"))]
impl VirtualPicc {
    pub fn new(credential: &Credential) -> Result<Self, Error> {
        ensure_abi()?;
        let mut raw = core::ptr::null_mut();
        status(unsafe {
            sys::dfc_ffi_picc_create(credential.as_ptr(), None, core::ptr::null_mut(), &mut raw)
        })?;
        Ok(Self {
            raw: NonNull::new(raw).ok_or(Error::OutOfMemory)?,
            _random_context: None,
        })
    }

    /// Creates a virtual card without duplicating the credential's data pools.
    ///
    /// Ownership is returned to Rust and freed if native construction fails.
    pub fn from_credential(credential: Credential) -> Result<Self, Error> {
        ensure_abi()?;
        let raw_credential = credential.into_raw();
        let mut owned_credential = raw_credential;
        let mut raw = core::ptr::null_mut();
        let result = status(unsafe {
            sys::dfc_ffi_picc_create_take(
                &mut owned_credential,
                None,
                core::ptr::null_mut(),
                &mut raw,
            )
        });
        if let Err(error) = result {
            if !owned_credential.is_null() {
                unsafe { sys::dfc_ffi_credential_free(owned_credential) };
            }
            return Err(error);
        }
        Ok(Self {
            raw: NonNull::new(raw).ok_or(Error::OutOfMemory)?,
            _random_context: None,
        })
    }

    pub fn from_credential_with_random<F>(credential: Credential, random: F) -> Result<Self, Error>
    where
        F: FnMut(usize) -> Vec<u8> + Send + 'static,
    {
        ensure_abi()?;
        let raw_credential = credential.into_raw();
        let mut owned_credential = raw_credential;
        let mut context = Box::new(RandomContext {
            source: Box::new(random),
        });
        let mut raw = core::ptr::null_mut();
        let result = status(unsafe {
            sys::dfc_ffi_picc_create_take(
                &mut owned_credential,
                Some(random_callback),
                (&mut *context as *mut RandomContext).cast(),
                &mut raw,
            )
        });
        if let Err(error) = result {
            if !owned_credential.is_null() {
                unsafe { sys::dfc_ffi_credential_free(owned_credential) };
            }
            return Err(error);
        }
        Ok(Self {
            raw: NonNull::new(raw).ok_or(Error::OutOfMemory)?,
            _random_context: Some(context),
        })
    }

    pub fn activate(&mut self) -> Result<Activation, Error> {
        let mut value = MaybeUninit::uninit();
        let result =
            status(unsafe { sys::dfc_ffi_picc_activate(self.raw.as_ptr(), value.as_mut_ptr()) });
        result?;
        Ok(Activation(unsafe { value.assume_init() }))
    }

    pub fn exchange(&mut self, command: &[u8]) -> Result<Vec<u8>, Error> {
        self.exchange_inner(command, false)
    }

    pub fn frame_exchange(&mut self, frame: &[u8]) -> Result<Vec<u8>, Error> {
        self.exchange_inner(frame, true)
    }

    fn exchange_inner(&mut self, input: &[u8], frame: bool) -> Result<Vec<u8>, Error> {
        const INITIAL_RESPONSE_CAPACITY: usize = 256;
        let mut response = vec![0; INITIAL_RESPONSE_CAPACITY];
        let mut len = 0;
        let call = if frame {
            sys::dfc_ffi_picc_frame_exchange
        } else {
            sys::dfc_ffi_picc_exchange
        };
        let mut result = unsafe {
            call(
                self.raw.as_ptr(),
                input.as_ptr(),
                input.len(),
                response.as_mut_ptr(),
                response.len(),
                &mut len,
            )
        };
        if result == sys::DFC_FFI_PICC_BUFFER_TOO_SMALL as i32 {
            let capacity = unsafe { sys::dfc_ffi_picc_response_capacity() };
            let Some(capacity) = picc_retry_capacity(response.len(), capacity) else {
                return Err(Error::Native(result));
            };
            response
                .try_reserve_exact(capacity - response.len())
                .map_err(|_| Error::OutOfMemory)?;
            response.resize(capacity, 0);
            len = 0;
            result = unsafe {
                call(
                    self.raw.as_ptr(),
                    input.as_ptr(),
                    input.len(),
                    response.as_mut_ptr(),
                    response.len(),
                    &mut len,
                )
            };
        }
        status(result)?;
        if len > response.len() {
            return Err(Error::InvalidArgument);
        }
        response.truncate(len);
        Ok(response)
    }

    pub fn field_off(&mut self) -> Result<(), Error> {
        status(unsafe { sys::dfc_ffi_picc_field_off(self.raw.as_ptr()) })
    }
    pub fn reset_protocol(&mut self) -> Result<(), Error> {
        status(unsafe { sys::dfc_ffi_picc_reset_protocol(self.raw.as_ptr()) })
    }
    pub fn advance_time(&mut self, milliseconds: u32) -> Result<(), Error> {
        status(unsafe { sys::dfc_ffi_picc_advance_time(self.raw.as_ptr(), milliseconds) })
    }
    pub fn mark_persisted(&mut self) -> Result<(), Error> {
        status(unsafe { sys::dfc_ffi_picc_mark_persisted(self.raw.as_ptr()) })
    }

    pub fn snapshot(&self) -> Result<Snapshot, Error> {
        let mut value = MaybeUninit::uninit();
        status(unsafe { sys::dfc_ffi_picc_snapshot(self.raw.as_ptr(), value.as_mut_ptr()) })?;
        Ok(Snapshot(unsafe { value.assume_init() }))
    }

    pub fn export(&self) -> Result<Credential, Error> {
        let mut raw = core::ptr::null_mut();
        status(unsafe { sys::dfc_ffi_picc_export(self.raw.as_ptr(), &mut raw) })?;
        Credential::from_raw(raw)
    }
}

#[cfg(not(feature = "role-target"))]
impl Drop for VirtualPicc {
    fn drop(&mut self) {
        unsafe { sys::dfc_ffi_picc_free(self.raw.as_ptr()) }
    }
}

#[cfg(all(test, not(feature = "role-target")))]
mod tests {
    use super::*;

    #[test]
    fn picc_retry_capacity_is_larger_and_representable() {
        assert_eq!(picc_retry_capacity(256, 257), Some(257));
        assert_eq!(picc_retry_capacity(256, 8193), Some(8193));
        assert_eq!(picc_retry_capacity(256, 0), None);
        assert_eq!(picc_retry_capacity(256, 256), None);
        assert_eq!(picc_retry_capacity(256, usize::MAX), None);
    }

    #[test]
    fn native_layout_and_capabilities_are_compatible() {
        let capabilities = Capabilities::get().expect("compatible native ABI");
        assert_eq!(capabilities.0.abi_version, sys::DFC_FFI_ABI_VERSION);
        assert_ne!(capabilities.0.emulator, 0);
        assert_ne!(capabilities.0.reader, 0);
    }

    #[test]
    fn mismatched_native_layout_is_rejected_before_handles() {
        let expected = layout::expected_layout_fingerprint();
        assert_eq!(
            require_layout_fingerprint(expected ^ 1),
            Err(Error::LayoutMismatch {
                expected,
                actual: expected ^ 1,
            })
        );
    }

    #[test]
    fn random_failure_aborts_without_mutating_picc() {
        let credential = Credential::decode(include_bytes!(
            "../../../../examples/credentials/v6-minimal.dfcb"
        ))
        .expect("fixture");
        let mut picc =
            VirtualPicc::from_credential_with_random(credential, |_| Vec::new()).expect("PICC");
        picc.activate().expect("activation");
        let before = picc.snapshot().expect("snapshot").0;
        assert_eq!(
            picc.exchange(&[0x90, 0x1A, 0, 0, 1, 0, 0]),
            Err(Error::RandomSourceFailed)
        );
        let after = picc.snapshot().expect("snapshot").0;
        assert_eq!(before.selected, after.selected);
        assert_eq!(before.auth_mode, after.auth_mode);
        assert_eq!(before.ev2_active, after.ev2_active);
        assert_eq!(before.proximity_verified, after.proximity_verified);
    }

    #[test]
    fn random_failure_is_reported_by_each_operation() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        let credential = Credential::decode(include_bytes!(
            "../../../../examples/credentials/v6-minimal.dfcb"
        ))
        .expect("fixture");
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let mut picc = VirtualPicc::from_credential_with_random(credential, move |length| {
            observed.fetch_add(1, Ordering::Relaxed);
            vec![0; length.saturating_sub(1)]
        })
        .expect("PICC");
        picc.activate().expect("activation");

        for _ in 0..2 {
            assert_eq!(
                picc.exchange(&[0x90, 0x1A, 0, 0, 1, 0, 0]),
                Err(Error::RandomSourceFailed)
            );
        }
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        picc.reset_protocol().expect("reset after random failure");
        assert!(picc.exchange(&[0x90, 0x60, 0, 0, 0]).is_ok());
    }

    struct PiccTransport(VirtualPicc);

    impl Transport for PiccTransport {
        type Error = Error;
        fn transceive(&mut self, command: &[u8]) -> Result<Vec<u8>, Error> {
            self.0.exchange(command)
        }
    }

    #[test]
    fn reader_clear_header_is_never_narrowed_before_native_check() {
        const NATIVE_MAX_CLEAR_HEADER: u32 = 10;
        let credential = Credential::decode(include_bytes!(
            "../../../../examples/credentials/v6-minimal.dfcb"
        ))
        .expect("fixture");
        let mut picc = VirtualPicc::from_credential(credential).expect("PICC");
        picc.activate().expect("activation");
        let mut reader = Reader::new(PiccTransport(picc), Framing::Iso7816).expect("reader");
        let version = Command {
            instruction: 0x60,
            data: Vec::new(),
        };

        assert_eq!(
            reader
                .exchange(&version, CommunicationMode::Plain, None)
                .expect("derived")
                .status,
            0
        );
        assert_eq!(
            reader
                .exchange(
                    &version,
                    CommunicationMode::Plain,
                    Some(NATIVE_MAX_CLEAR_HEADER),
                )
                .expect("maximum")
                .status,
            0
        );
        for bad in [
            NATIVE_MAX_CLEAR_HEADER + 1,
            i32::MAX as u32,
            i32::MAX as u32 + 1,
            u32::MAX,
        ] {
            assert!(matches!(
                reader.exchange(&version, CommunicationMode::Plain, Some(bad)),
                Err(ReaderError::Dfc(Error::InvalidArgument))
            ));
        }
        assert_eq!(
            reader
                .exchange(&version, CommunicationMode::Plain, None)
                .expect("session usable")
                .status,
            0
        );
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn credential_index_above_u32_is_refused_not_wrapped() {
        let credential = Credential::decode(include_bytes!(
            "../../../../examples/credentials/v6-maximal.dfcb"
        ))
        .expect("fixture");
        let wrapped = u32::MAX as usize + 1;
        assert!(credential.application(0).is_ok());
        assert!(credential.file(0).is_ok());
        assert_eq!(
            credential.application(wrapped).map(|_| ()),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            credential.file(wrapped).map(|_| ()),
            Err(Error::InvalidArgument)
        );
        assert_eq!(credential.file_data(wrapped), Err(Error::InvalidArgument));
    }
}
pub use dfc_core_sys as raw;
