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

#[cfg(not(feature = "role-target"))]
fn layout_fingerprint() -> u64 {
    fn word(mut hash: u64, value: u64) -> u64 {
        for byte in value.to_le_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(1_099_511_628_211);
        }
        hash
    }
    macro_rules! size {
        ($hash:expr, $ty:ty) => {
            word($hash, size_of::<$ty>() as u64)
        };
    }
    macro_rules! field {
        ($hash:expr, $ty:ty, $field:ident) => {
            word($hash, core::mem::offset_of!($ty, $field) as u64)
        };
    }
    let mut hash = 14_695_981_039_346_656_037;
    hash = word(hash, u64::from(sys::DFC_FFI_ABI_VERSION));
    hash = size!(hash, sys::DfcFfiCapabilities);
    hash = field!(hash, sys::DfcFfiCapabilities, generation_ev1);
    hash = field!(hash, sys::DfcFfiCapabilities, max_applications);
    hash = field!(hash, sys::DfcFfiCapabilities, key_pool_size);
    hash = size!(hash, sys::DfcFfiError);
    hash = field!(hash, sys::DfcFfiError, line);
    hash = field!(hash, sys::DfcFfiError, message);
    hash = size!(hash, sys::DfcFfiCard);
    hash = field!(hash, sys::DfcFfiCard, uid);
    hash = field!(hash, sys::DfcFfiCard, hardware_version);
    hash = field!(hash, sys::DfcFfiCard, static_signature);
    hash = size!(hash, sys::DfcFfiPiccSettings);
    hash = field!(hash, sys::DfcFfiPiccSettings, ats);
    hash = field!(hash, sys::DfcFfiPiccSettings, ev2_capabilities);
    hash = field!(hash, sys::DfcFfiPiccSettings, virtual_card_installation_id);
    hash = field!(hash, sys::DfcFfiPiccSettings, dam_auth_key);
    hash = field!(hash, sys::DfcFfiPiccSettings, preferred_auth_command);
    hash = size!(hash, sys::DfcFfiApplication);
    hash = field!(hash, sys::DfcFfiApplication, aid);
    hash = field!(hash, sys::DfcFfiApplication, key_set_versions);
    hash = field!(hash, sys::DfcFfiApplication, capability_data);
    hash = field!(hash, sys::DfcFfiApplication, preferred_auth_command);
    hash = size!(hash, sys::DfcFfiFile);
    hash = field!(hash, sys::DfcFfiFile, access_rights);
    hash = field!(hash, sys::DfcFfiFile, number);
    hash = field!(hash, sys::DfcFfiFile, transaction_mac_key);
    hash = field!(hash, sys::DfcFfiFile, previous_reader_id);
    hash = size!(hash, sys::DfcFfiKey);
    hash = field!(hash, sys::DfcFfiKey, value);
    hash = field!(hash, sys::DfcFfiKey, version);
    hash = size!(hash, sys::DfcFfiActivation);
    hash = field!(hash, sys::DfcFfiActivation, uid);
    hash = field!(hash, sys::DfcFfiActivation, protocol);
    hash = field!(hash, sys::DfcFfiActivation, rf_detail);
    hash = size!(hash, sys::DfcFfiSnapshot);
    hash = field!(hash, sys::DfcFfiSnapshot, selected_aid);
    hash = field!(hash, sys::DfcFfiSnapshot, ev2_transaction_identifier);
    hash = field!(hash, sys::DfcFfiSnapshot, ev2_mac_key);
    hash = field!(hash, sys::DfcFfiSnapshot, proximity_verified);
    hash = size!(hash, sys::DfcFfiReaderState);
    hash = field!(hash, sys::DfcFfiReaderState, auth_mode);
    hash = field!(hash, sys::DfcFfiReaderState, ev2_transaction_identifier);
    hash = field!(hash, sys::DfcFfiReaderState, ev2_reader_capabilities);
    hash
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(not(feature = "role-target"))]
pub enum Error {
    InvalidArgument,
    BufferTooSmall,
    OutOfMemory,
    Unsupported,
    RandomSourceFailed,
    AbiMismatch { expected: u32, actual: u32 },
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
        ABI_STATE.store(2, Ordering::Release);
        return Err(Error::AbiMismatch {
            expected: sys::DFC_FFI_ABI_VERSION,
            actual,
        });
    }
    if unsafe { sys::dfc_ffi_layout_fingerprint() } != layout_fingerprint() {
        ABI_STATE.store(2, Ordering::Release);
        return Err(Error::AbiMismatch {
            expected: sys::DFC_FFI_ABI_VERSION,
            actual,
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
        let mut response = vec![0; 8192];
        let mut len = 0;
        let call = if frame {
            sys::dfc_ffi_picc_frame_exchange
        } else {
            sys::dfc_ffi_picc_exchange
        };
        let result = status(unsafe {
            call(
                self.raw.as_ptr(),
                input.as_ptr(),
                input.len(),
                response.as_mut_ptr(),
                response.len(),
                &mut len,
            )
        });
        result?;
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
    fn native_layout_and_capabilities_are_compatible() {
        let capabilities = Capabilities::get().expect("compatible native ABI");
        assert_eq!(capabilities.0.abi_version, sys::DFC_FFI_ABI_VERSION);
        assert_ne!(capabilities.0.emulator, 0);
        assert_ne!(capabilities.0.reader, 0);
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
}
pub use dfc_core_sys as raw;
