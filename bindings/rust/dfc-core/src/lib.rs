//! Safe bindings for DFC credentials, virtual cards, and reader sessions.
#![cfg_attr(feature = "role-target", no_std)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

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
mod crypto;
#[cfg(not(feature = "role-target"))]
mod layout;
#[cfg(not(feature = "role-target"))]
mod reader;
#[cfg(not(feature = "role-target"))]
mod responses;
#[cfg(not(feature = "role-target"))]
mod sdm;
#[cfg(not(feature = "role-target"))]
mod transaction_mac;

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
pub use credential::{Credential, CredentialFile, CredentialKey, CredentialPiccSettings};
#[cfg(not(feature = "role-target"))]
pub use crypto::{DiversificationAlgorithm, diversify_key};
#[cfg(not(feature = "role-target"))]
pub use reader::{
    AuthenticationMode, Command, CommunicationMode, Framing, Reader, ReaderError, ReaderState,
    Response, Transport, iso_append_record_apdu, parse_iso7816_response,
};
#[cfg(not(feature = "role-target"))]
pub use responses::{
    Access, DecodeError, FileSettings, FileSettingsKind, FileType, KeySettings, Version,
    VersionPart, decode_application_ids, decode_file_ids, decode_file_settings,
    decode_key_settings, decode_key_version, decode_version,
};
#[cfg(not(feature = "role-target"))]
pub use sdm::{SdmConfig, SdmError, SdmField, SdmResult, verify_sdm};
#[cfg(not(feature = "role-target"))]
pub use transaction_mac::{TransactionMacError, TransactionMacVerifier};

#[cfg(not(feature = "role-target"))]
static ABI_STATE: AtomicU8 = AtomicU8::new(0);

#[cfg(not(feature = "role-target"))]
fn wipe<T>(value: &mut T) {
    unsafe {
        sys::dfc_ffi_secure_zero((value as *mut T).cast(), core::mem::size_of::<T>());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(not(feature = "role-target"))]
/// Failure returned by the safe binding layer.
pub enum Error {
    /// An argument is outside its documented range or has the wrong length.
    InvalidArgument,
    /// Caller-provided or internally bounded storage is too small.
    BufferTooSmall,
    /// Native or Rust-owned storage could not be allocated.
    OutOfMemory,
    /// The selected operation is unavailable in the linked build profile.
    Unsupported,
    /// The configured random source failed or returned the wrong byte count.
    RandomSourceFailed,
    /// The native library exposes a different FFI ABI version.
    AbiMismatch {
        /// ABI version compiled into this crate.
        expected: u32,
        /// ABI version reported by the loaded native library.
        actual: u32,
    },
    /// Native structure offsets differ from the generated Rust declarations.
    LayoutMismatch {
        /// Layout fingerprint compiled into this crate.
        expected: u64,
        /// Layout fingerprint reported by the loaded native library.
        actual: u64,
    },
    /// One generated Rust structure has a different size from its native peer.
    StructSizeMismatch {
        /// Stable name of the mismatched structure.
        structure: &'static str,
        /// Size compiled into this crate.
        expected: u32,
        /// Size reported by the loaded native library.
        actual: u32,
    },
    /// Native operation failed with an otherwise unmapped status code.
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
            Self::StructSizeMismatch {
                structure,
                expected,
                actual,
            } => write!(
                f,
                "dfc native {structure} structure size mismatch: expected {expected}, found {actual}"
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
        value if value == sys::DFC_FFI_OK as i32 => Ok(()),
        sys::DFC_FFI_INVALID_ARGUMENT => Err(Error::InvalidArgument),
        sys::DFC_FFI_BUFFER_TOO_SMALL => Err(Error::BufferTooSmall),
        sys::DFC_FFI_OUT_OF_MEMORY => Err(Error::OutOfMemory),
        sys::DFC_FFI_UNSUPPORTED => Err(Error::Unsupported),
        sys::DFC_FFI_RANDOM_FAILED => Err(Error::RandomSourceFailed),
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
fn struct_size_mismatch(native: &sys::DfcFfiStructSizes) -> Option<Error> {
    macro_rules! require_size {
        ($field:ident, $type:ty) => {{
            let expected = size_of::<$type>() as u32;
            if native.$field != expected {
                return Some(Error::StructSizeMismatch {
                    structure: stringify!($field),
                    expected,
                    actual: native.$field,
                });
            }
        }};
    }
    require_size!(capabilities, sys::DfcFfiCapabilities);
    require_size!(error, sys::DfcFfiError);
    require_size!(card, sys::DfcFfiCard);
    require_size!(picc, sys::DfcFfiPiccSettings);
    require_size!(application, sys::DfcFfiApplication);
    require_size!(file, sys::DfcFfiFile);
    require_size!(key, sys::DfcFfiKey);
    require_size!(activation, sys::DfcFfiActivation);
    require_size!(snapshot, sys::DfcFfiSnapshot);
    require_size!(diagnostic_snapshot, sys::DfcFfiDiagnosticSnapshot);
    require_size!(reader_state, sys::DfcFfiReaderState);
    None
}

#[cfg(not(feature = "role-target"))]
fn require_struct_sizes() -> Result<(), Error> {
    let mut native = MaybeUninit::<sys::DfcFfiStructSizes>::uninit();
    unsafe { sys::dfc_ffi_struct_sizes(native.as_mut_ptr()) };
    let native = unsafe { native.assume_init() };
    struct_size_mismatch(&native).map_or(Ok(()), Err)
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
        4 => return require_struct_sizes(),
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
    if let Err(error) = require_struct_sizes() {
        ABI_STATE.store(4, Ordering::Release);
        return Err(error);
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
/// Feature and capacity report for the linked native build.
pub struct Capabilities(sys::DfcFfiCapabilities);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(not(feature = "role-target"))]
/// Code included in the linked native build.
pub enum BuildRole {
    /// Card-side emulator and binary codec.
    Target,
    /// Reader-side client and credential codecs.
    Host,
    /// Combined emulator and reader build.
    Simulator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(not(feature = "role-target"))]
/// Card-generation feature set selected for the native build.
pub enum BuildProfile {
    /// Small EV1-compatible feature set.
    MinimalEv1,
    /// Complete EV1-compatible feature set.
    FullEv1,
    /// Complete EV2-compatible feature set.
    FullEv2,
    /// Complete EV3-compatible feature set.
    FullEv3,
    /// Small EV3-compatible feature set.
    MinimalEv3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(not(feature = "role-target"))]
/// Optional native capability queried through [`Capabilities::supports`].
pub enum Capability {
    /// EV1 behavior.
    GenerationEv1,
    /// EV2 behavior.
    GenerationEv2,
    /// EV3 behavior.
    GenerationEv3,
    /// Two-kilobyte card models.
    Storage2k,
    /// Four-kilobyte card models.
    Storage4k,
    /// Eight-kilobyte card models.
    Storage8k,
    /// EV2 secure messaging.
    Ev2SecureMessaging,
    /// ISO 7816 commands.
    Iso7816,
    /// Transaction MAC files.
    TransactionMac,
    /// Secure Dynamic Messaging.
    SecureDynamicMessaging,
    /// Proximity checks.
    ProximityCheck,
    /// Virtual Card selection.
    VirtualCard,
    /// Multiple application key sets.
    KeySets,
    /// Delegated applications.
    DelegatedApplications,
    /// Transaction timers.
    TransactionTimer,
    /// Application capability data.
    ApplicationCapabilityData,
    /// Static card signatures.
    StaticSignature,
    /// Legacy D40 authentication.
    AuthD40,
    /// ISO authentication.
    AuthIso,
    /// AES authentication.
    AuthAes,
    /// Virtual-card emulator APIs.
    Emulator,
    /// Reader APIs.
    Reader,
    /// Binary credential decoding.
    DerDecoder,
    /// Binary credential encoding.
    DerEncoder,
    /// Text credential codec.
    TextCodec,
}

#[cfg(not(feature = "role-target"))]
impl Capabilities {
    /// Reads capabilities after verifying ABI, layout, and structure sizes.
    pub fn get() -> Result<Self, Error> {
        ensure_abi()?;
        let mut value = MaybeUninit::uninit();
        unsafe { sys::dfc_ffi_capabilities(value.as_mut_ptr()) };
        Ok(Self(unsafe { value.assume_init() }))
    }

    /// Returns the native ABI version.
    pub fn abi_version(&self) -> u32 {
        self.0.abi_version
    }

    /// Returns the native build role.
    pub fn build_role(&self) -> BuildRole {
        match self.0.build_role {
            1 => BuildRole::Target,
            2 => BuildRole::Host,
            3 => BuildRole::Simulator,
            _ => unreachable!("native ABI returned an invalid build role"),
        }
    }

    /// Returns the native build profile.
    pub fn build_profile(&self) -> BuildProfile {
        match self.0.build_profile {
            1 => BuildProfile::MinimalEv1,
            2 => BuildProfile::FullEv1,
            3 => BuildProfile::FullEv2,
            4 => BuildProfile::FullEv3,
            5 => BuildProfile::MinimalEv3,
            _ => unreachable!("native ABI returned an invalid build profile"),
        }
    }

    /// Reports whether the native build includes one optional capability.
    pub fn supports(&self, capability: Capability) -> bool {
        let value = match capability {
            Capability::GenerationEv1 => self.0.generation_ev1,
            Capability::GenerationEv2 => self.0.generation_ev2,
            Capability::GenerationEv3 => self.0.generation_ev3,
            Capability::Storage2k => self.0.storage_2k,
            Capability::Storage4k => self.0.storage_4k,
            Capability::Storage8k => self.0.storage_8k,
            Capability::Ev2SecureMessaging => self.0.ev2_secure_messaging,
            Capability::Iso7816 => self.0.iso7816,
            Capability::TransactionMac => self.0.transaction_mac,
            Capability::SecureDynamicMessaging => self.0.secure_dynamic_messaging,
            Capability::ProximityCheck => self.0.proximity_check,
            Capability::VirtualCard => self.0.virtual_card,
            Capability::KeySets => self.0.key_sets,
            Capability::DelegatedApplications => self.0.delegated_applications,
            Capability::TransactionTimer => self.0.transaction_timer,
            Capability::ApplicationCapabilityData => self.0.application_capability_data,
            Capability::StaticSignature => self.0.static_signature,
            Capability::AuthD40 => self.0.auth_d40,
            Capability::AuthIso => self.0.auth_iso,
            Capability::AuthAes => self.0.auth_aes,
            Capability::Emulator => self.0.emulator,
            Capability::Reader => self.0.reader,
            Capability::DerDecoder => self.0.der_decoder,
            Capability::DerEncoder => self.0.der_encoder,
            Capability::TextCodec => self.0.text_codec,
        };
        value != 0
    }

    /// Reports whether virtual-card emulator APIs are available.
    pub fn has_emulator(&self) -> bool {
        self.supports(Capability::Emulator)
    }

    /// Reports whether reader APIs are available.
    pub fn has_reader(&self) -> bool {
        self.supports(Capability::Reader)
    }

    /// Returns the maximum number of applications in a credential.
    pub fn max_applications(&self) -> u32 {
        self.0.max_applications
    }

    /// Returns the maximum number of files in a credential.
    pub fn max_files(&self) -> u32 {
        self.0.max_files
    }

    /// Returns the maximum number of keys in a credential.
    pub fn max_keys(&self) -> u32 {
        self.0.max_keys
    }

    /// Returns the credential file-data pool size in bytes.
    pub fn file_pool_size(&self) -> u32 {
        self.0.file_pool_size
    }

    /// Returns the credential key-data pool size in bytes.
    pub fn key_pool_size(&self) -> u32 {
        self.0.key_pool_size
    }
}

#[cfg(not(feature = "role-target"))]
/// RF activation parameters returned by a virtual card.
pub struct Activation(pub sys::DfcFfiActivation);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Selection level reported by a virtual card.
pub enum Selection {
    /// No application is selected.
    None,
    /// The PICC master application is selected.
    Picc,
    /// A credential-model application is selected.
    Application,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
/// Native authentication cipher reported by a virtual card.
pub enum PiccAuthenticationMode {
    /// Legacy D40 authentication.
    Legacy = 0x0a,
    /// ISO authentication.
    Iso = 0x1a,
    /// AES authentication. An active EV2 command counter in the snapshot distinguishes EV2.
    Aes = 0xaa,
}

#[cfg(not(feature = "role-target"))]
/// Public, non-secret virtual-card state snapshot.
pub struct Snapshot(sys::DfcFfiSnapshot);

#[cfg(not(feature = "role-target"))]
impl Snapshot {
    /// Returns the current selection level.
    pub fn selection(&self) -> Selection {
        match self.0.selected {
            0 => Selection::None,
            1 => Selection::Picc,
            2 => Selection::Application,
            _ => unreachable!("native PICC returned an invalid selection state"),
        }
    }

    /// Returns the selected model index and AID, or `None` outside application selection.
    ///
    /// The AID is in credential-model order, most-significant octet first.
    pub fn selected_application(&self) -> Option<(u32, &[u8; 3])> {
        (self.selection() == Selection::Application)
            .then_some((self.0.selected_application_index, &self.0.selected_aid))
    }

    /// Returns whether persistent card state has changed since export.
    pub fn is_dirty(&self) -> bool {
        self.0.dirty != 0
    }

    /// Returns the active native authentication cipher, or `None` while unauthenticated.
    pub fn authentication(&self) -> Option<PiccAuthenticationMode> {
        match self.0.auth_mode {
            0 => None,
            value if value == PiccAuthenticationMode::Legacy as u8 => {
                Some(PiccAuthenticationMode::Legacy)
            }
            value if value == PiccAuthenticationMode::Iso as u8 => {
                Some(PiccAuthenticationMode::Iso)
            }
            value if value == PiccAuthenticationMode::Aes as u8 => {
                Some(PiccAuthenticationMode::Aes)
            }
            _ => unreachable!("native PICC returned an invalid authentication mode"),
        }
    }

    /// Returns the authenticated key number, or `None` while unauthenticated.
    pub fn authenticated_key_number(&self) -> Option<u8> {
        self.authentication().map(|_| self.0.auth_key_no)
    }

    /// Returns the EV2 command counter, or `None` outside EV2.
    pub fn ev2_command_counter(&self) -> Option<u32> {
        (self.0.ev2_active != 0).then_some(self.0.ev2_command_counter)
    }

    /// Returns the EV2 key number, or `None` outside EV2.
    pub fn ev2_key_number(&self) -> Option<u8> {
        (self.0.ev2_active != 0).then_some(self.0.ev2_key_no)
    }

    /// Returns whether virtual-card selection completed.
    pub fn virtual_card_selected(&self) -> bool {
        self.0.virtual_card_selected != 0
    }

    /// Returns whether proximity verification completed.
    pub fn proximity_verified(&self) -> bool {
        self.0.proximity_verified != 0
    }
}

/// Secret-bearing state for diagnostics and conformance tests.
///
/// The backing storage is wiped when this value is dropped. Code that copies a
/// returned slice is responsible for the lifetime of its own copy.
#[cfg(not(feature = "role-target"))]
pub struct DiagnosticSnapshot(sys::DfcFfiDiagnosticSnapshot);

#[cfg(not(feature = "role-target"))]
impl DiagnosticSnapshot {
    fn clear(&mut self) {
        wipe(&mut self.0);
    }
    /// Four-byte EV2 transaction identifier, or all zeroes outside EV2.
    pub fn transaction_identifier(&self) -> &[u8; 4] {
        &self.0.transaction_identifier
    }
    /// Current diagnostic session encryption key.
    pub fn encryption_key(&self) -> &[u8; 16] {
        &self.0.encryption_key
    }
    /// Current diagnostic session MAC key.
    pub fn mac_key(&self) -> &[u8; 16] {
        &self.0.mac_key
    }
}

#[cfg(not(feature = "role-target"))]
impl Drop for DiagnosticSnapshot {
    fn drop(&mut self) {
        self.clear();
    }
}

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
    if let Ok(mut bytes) = generated {
        if bytes.len() == len {
            unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, len) };
            bytes.fill(0);
            return 0;
        }
        bytes.fill(0);
    }
    -5
}

#[cfg(not(feature = "role-target"))]
/// Stateful virtual card that owns a native emulator and credential model.
///
/// Native state and secrets are wiped and freed on drop.
pub struct VirtualPicc {
    raw: NonNull<sys::DfcFfiPicc>,
    // Keeps the callback context alive for as long as native code may use it.
    _random_context: Option<Box<RandomContext>>,
}

#[cfg(not(feature = "role-target"))]
// SAFETY: the native card handle is uniquely owned and every operation requires
// `&mut self`; the retained random callback is also required to be `Send`.
unsafe impl Send for VirtualPicc {}

#[cfg(not(feature = "role-target"))]
impl VirtualPicc {
    /// Creates a virtual card by cloning `credential` into native ownership.
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

    /// Creates a virtual card with a caller-provided random source.
    ///
    /// The closure must return exactly the requested number of bytes. A panic
    /// or wrong-length result becomes [`Error::RandomSourceFailed`]. The closure
    /// is retained until the card is dropped.
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

    /// Starts a new RF activation and returns its transport parameters.
    pub fn activate(&mut self) -> Result<Activation, Error> {
        let mut value = MaybeUninit::uninit();
        let result =
            status(unsafe { sys::dfc_ffi_picc_activate(self.raw.as_ptr(), value.as_mut_ptr()) });
        result?;
        Ok(Activation(unsafe { value.assume_init() }))
    }

    /// Exchanges one complete native or ISO-wrapped command.
    pub fn exchange(&mut self, command: &[u8]) -> Result<Vec<u8>, Error> {
        let mut response = Vec::new();
        self.exchange_into(command, &mut response)?;
        Ok(response)
    }

    /// Exchanges one command into caller-owned storage that can be reused.
    pub fn exchange_into(&mut self, command: &[u8], response: &mut Vec<u8>) -> Result<(), Error> {
        self.exchange_inner(command, false, response)
    }

    /// Exchanges one ISO-DEP frame, including transport chaining and retries.
    pub fn frame_exchange(&mut self, frame: &[u8]) -> Result<Vec<u8>, Error> {
        let mut response = Vec::new();
        self.frame_exchange_into(frame, &mut response)?;
        Ok(response)
    }

    /// Exchanges one ISO-DEP frame into caller-owned reusable storage.
    pub fn frame_exchange_into(
        &mut self,
        frame: &[u8],
        response: &mut Vec<u8>,
    ) -> Result<(), Error> {
        self.exchange_inner(frame, true, response)
    }

    fn exchange_inner(
        &mut self,
        input: &[u8],
        frame: bool,
        response: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let result = self.exchange_inner_unchecked(input, frame, response);
        if result.is_err() {
            unsafe { sys::dfc_ffi_secure_zero(response.as_mut_ptr().cast(), response.len()) };
            response.clear();
        }
        result
    }

    fn exchange_inner_unchecked(
        &mut self,
        input: &[u8],
        frame: bool,
        response: &mut Vec<u8>,
    ) -> Result<(), Error> {
        const INITIAL_RESPONSE_CAPACITY: usize = 256;
        unsafe { sys::dfc_ffi_secure_zero(response.as_mut_ptr().cast(), response.len()) };
        if response.capacity() < INITIAL_RESPONSE_CAPACITY {
            response
                .try_reserve_exact(INITIAL_RESPONSE_CAPACITY - response.capacity())
                .map_err(|_| Error::OutOfMemory)?;
        }
        response.resize(INITIAL_RESPONSE_CAPACITY, 0);
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
        unsafe {
            sys::dfc_ffi_secure_zero(response.as_mut_ptr().add(len).cast(), response.len() - len)
        };
        response.truncate(len);
        Ok(())
    }

    /// Ends the RF field and clears protocol and authentication state.
    pub fn field_off(&mut self) -> Result<(), Error> {
        status(unsafe { sys::dfc_ffi_picc_field_off(self.raw.as_ptr()) })
    }
    /// Resets transport state while retaining the credential model.
    pub fn reset_protocol(&mut self) -> Result<(), Error> {
        status(unsafe { sys::dfc_ffi_picc_reset_protocol(self.raw.as_ptr()) })
    }
    /// Advances the virtual card's monotonic clock by `milliseconds`.
    pub fn advance_time(&mut self, milliseconds: u32) -> Result<(), Error> {
        status(unsafe { sys::dfc_ffi_picc_advance_time(self.raw.as_ptr(), milliseconds) })
    }
    /// Marks current credential state as persisted by the caller.
    pub fn mark_persisted(&mut self) -> Result<(), Error> {
        status(unsafe { sys::dfc_ffi_picc_mark_persisted(self.raw.as_ptr()) })
    }

    /// Returns a public, non-secret state snapshot.
    pub fn snapshot(&self) -> Result<Snapshot, Error> {
        let mut value = MaybeUninit::uninit();
        status(unsafe { sys::dfc_ffi_picc_snapshot(self.raw.as_ptr(), value.as_mut_ptr()) })?;
        Ok(Snapshot(unsafe { value.assume_init() }))
    }

    /// Returns secret-bearing diagnostic session state.
    ///
    /// The returned value wipes its storage on drop.
    pub fn diagnostic_snapshot(&self) -> Result<DiagnosticSnapshot, Error> {
        let mut value = MaybeUninit::zeroed();
        status(unsafe {
            sys::dfc_ffi_picc_diagnostic_snapshot(self.raw.as_ptr(), value.as_mut_ptr())
        })?;
        Ok(DiagnosticSnapshot(unsafe { value.assume_init() }))
    }

    /// Clones the card's current credential model into Rust ownership.
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
        assert_eq!(capabilities.abi_version(), sys::DFC_FFI_ABI_VERSION);
        assert!(capabilities.has_emulator());
        assert!(capabilities.has_reader());
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
    fn struct_size_mismatch_names_the_structure_and_sizes() {
        let mut sizes = sys::DfcFfiStructSizes {
            capabilities: size_of::<sys::DfcFfiCapabilities>() as u32,
            error: size_of::<sys::DfcFfiError>() as u32,
            card: size_of::<sys::DfcFfiCard>() as u32,
            picc: size_of::<sys::DfcFfiPiccSettings>() as u32,
            application: size_of::<sys::DfcFfiApplication>() as u32,
            file: size_of::<sys::DfcFfiFile>() as u32,
            key: size_of::<sys::DfcFfiKey>() as u32,
            activation: size_of::<sys::DfcFfiActivation>() as u32,
            snapshot: size_of::<sys::DfcFfiSnapshot>() as u32,
            diagnostic_snapshot: size_of::<sys::DfcFfiDiagnosticSnapshot>() as u32,
            reader_state: size_of::<sys::DfcFfiReaderState>() as u32,
        };
        assert_eq!(struct_size_mismatch(&sizes), None);

        let expected = sizes.file;
        sizes.file += 4;
        let mismatch = Error::StructSizeMismatch {
            structure: "file",
            expected,
            actual: expected + 4,
        };
        assert_eq!(struct_size_mismatch(&sizes), Some(mismatch.clone()));
        assert_eq!(
            mismatch.to_string(),
            format!(
                "dfc native file structure size mismatch: expected {expected}, found {}",
                expected + 4
            )
        );
    }

    #[test]
    fn random_failure_aborts_without_mutating_picc() {
        let credential = Credential::decode(include_bytes!("../tests/fixtures/v6-minimal.dfcb"))
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

        let credential = Credential::decode(include_bytes!("../tests/fixtures/v6-minimal.dfcb"))
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

    #[test]
    fn picc_exchange_reuses_caller_owned_response_storage() {
        let credential = Credential::decode(include_bytes!("../tests/fixtures/v6-minimal.dfcb"))
            .expect("fixture");
        let mut picc = VirtualPicc::from_credential(credential).expect("PICC");
        picc.activate().expect("activation");
        let mut response = Vec::with_capacity(256);
        let allocation = response.as_ptr();

        picc.exchange_into(&[0x90, 0x60, 0, 0, 0], &mut response)
            .expect("first exchange");
        assert_eq!(response.as_ptr(), allocation);
        picc.exchange_into(&[0x90, 0x60, 0, 0, 0], &mut response)
            .expect("second exchange");
        assert_eq!(response.as_ptr(), allocation);
    }

    #[test]
    fn picc_exchange_wipes_unused_reused_response_storage() {
        let credential = Credential::decode(include_bytes!("../tests/fixtures/v6-minimal.dfcb"))
            .expect("fixture");
        let mut picc = VirtualPicc::from_credential(credential).expect("PICC");
        picc.activate().expect("activation");
        let mut response = vec![0xA5; 256];

        picc.exchange_into(&[0x90, 0x60, 0, 0, 0], &mut response)
            .expect("exchange");
        let initialized_capacity =
            unsafe { std::slice::from_raw_parts(response.as_ptr(), response.capacity()) };
        assert!(
            initialized_capacity[response.len()..]
                .iter()
                .all(|byte| *byte == 0)
        );
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
        let credential = Credential::decode(include_bytes!("../tests/fixtures/v6-minimal.dfcb"))
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
        let credential = Credential::decode(include_bytes!("../tests/fixtures/v6-maximal.dfcb"))
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

    #[test]
    fn limited_credit_value_is_exposed_by_the_public_file_model() {
        let text = include_str!("../tests/fixtures/v6-maximal.dfc").replace(
            "Application 00 File 02 Limited Credit: 01\n",
            "Application 00 File 02 Limited Credit: 01\nApplication 00 File 02 Limited Credit Value: 37\n",
        );
        let credential = Credential::parse_text(&text).expect("fixture");
        let file = (0..credential.file_count())
            .map(|index| credential.file(index).expect("file"))
            .find(|file| file.type_ == 2)
            .expect("value file");
        assert_eq!(file.limited_credit_value, 37);
    }

    #[test]
    fn diagnostic_snapshot_clear_wipes_every_field() {
        let mut snapshot = DiagnosticSnapshot(sys::DfcFfiDiagnosticSnapshot {
            transaction_identifier: [0xa1; 4],
            encryption_key: [0xa2; 16],
            mac_key: [0xa3; 16],
        });
        snapshot.clear();
        assert_eq!(snapshot.transaction_identifier(), &[0; 4]);
        assert_eq!(snapshot.encryption_key(), &[0; 16]);
        assert_eq!(snapshot.mac_key(), &[0; 16]);
    }
}
/// Raw generated FFI declarations for advanced integrations.
///
/// Prefer the safe types in this crate. Raw functions require callers to uphold
/// the pointer, lifetime, buffer-size, and ownership contracts documented by
/// the native FFI header.
pub use dfc_core_sys as raw;
