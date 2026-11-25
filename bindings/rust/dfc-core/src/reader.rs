use crate::{Error, ensure_abi, output, status};
use core::{marker::PhantomData, mem::MaybeUninit, ptr::NonNull};
use dfc_core_sys as sys;

const INITIAL_OUTPUT_CAPACITY: usize = 64;
const SELECT_APPLICATION_INSTRUCTION: u8 = 0x5a;
const MAX_FILE_NUMBER: u8 = 31;
const MAX_U24: u32 = 0x00ff_ffff;
const MAX_RANGE_DATA: usize = 255 - 7;
const MAX_UPDATE_DATA: usize = 255 - 10;
// Native commands carry at most 255 data bytes. ISO 7816 wrapping adds five
// header bytes and Le; native framing needs less space than this same bound.
const MAX_OUTPUT_CAPACITY: usize = 261;

/// Builds a standard ISO/IEC 7816 APPEND RECORD command APDU.
pub fn iso_append_record_apdu(short_file_id: u8, data: &[u8]) -> Result<Vec<u8>, Error> {
    if short_file_id > 0x1e || data.is_empty() || data.len() > u16::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    let header_len = if data.len() <= u8::MAX as usize { 5 } else { 7 };
    let mut apdu = Vec::new();
    apdu.try_reserve_exact(header_len + data.len())
        .map_err(|_| Error::OutOfMemory)?;
    apdu.extend_from_slice(&[0x00, 0xe2, 0x00, short_file_id << 3]);
    if header_len == 5 {
        apdu.push(data.len() as u8);
    } else {
        apdu.push(0x00);
        apdu.extend_from_slice(&(data.len() as u16).to_be_bytes());
    }
    apdu.extend_from_slice(data);
    Ok(apdu)
}

/// Splits a standard ISO response APDU into its data and two-byte status word.
pub fn parse_iso7816_response(response: &[u8]) -> Result<(&[u8], u16), Error> {
    if response.len() < 2 {
        return Err(Error::InvalidArgument);
    }
    let data_len = response.len() - 2;
    Ok((
        &response[..data_len],
        u16::from_be_bytes([response[data_len], response[data_len + 1]]),
    ))
}

fn native_auth_challenge_length(cipher: u8, key_length: usize) -> Option<usize> {
    match (cipher, key_length) {
        (0x0a, 8 | 16) | (0x1a, 8 | 16) => Some(8),
        (0x1a, 24) | (0xaa, 16) => Some(16),
        _ => None,
    }
}

struct ApduBuffer {
    bytes: Vec<u8>,
}

impl ApduBuffer {
    fn new() -> Result<Self, Error> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(INITIAL_OUTPUT_CAPACITY)
            .map_err(|_| Error::OutOfMemory)?;
        bytes.resize(INITIAL_OUTPUT_CAPACITY, 0);
        Ok(Self { bytes })
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    fn command(&self, len: usize) -> Result<&[u8], Error> {
        self.bytes.get(..len).ok_or(Error::InvalidArgument)
    }

    fn grow(&mut self) -> Result<(), Error> {
        if self.bytes.len() >= MAX_OUTPUT_CAPACITY {
            return Err(Error::BufferTooSmall);
        }
        let capacity = self
            .bytes
            .len()
            .checked_mul(2)
            .map(|capacity| capacity.min(MAX_OUTPUT_CAPACITY))
            .ok_or(Error::BufferTooSmall)?;
        self.bytes
            .try_reserve_exact(capacity - self.bytes.len())
            .map_err(|_| Error::OutOfMemory)?;
        self.bytes.resize(capacity, 0);
        Ok(())
    }

    fn wipe(&mut self) {
        wipe_slice(&mut self.bytes);
    }
}

impl Drop for ApduBuffer {
    fn drop(&mut self) {
        self.wipe();
    }
}

fn wipe_slice(bytes: &mut [u8]) {
    unsafe { sys::dfc_ffi_secure_zero(bytes.as_mut_ptr().cast(), bytes.len()) }
}

fn grow_after_response(apdu: &mut ApduBuffer, incoming: &mut [u8]) -> Result<(), Error> {
    match apdu.grow() {
        Ok(()) => Ok(()),
        Err(error) => {
            wipe_slice(incoming);
            apdu.wipe();
            Err(error)
        }
    }
}

/// Transport used by [`Reader`] to exchange one card frame.
///
/// [`Framing::Iso7816`] supplies complete ISO 7816 command and response APDUs.
/// [`Framing::Native`] supplies `INS || data` and receives `status || data`.
pub trait Transport {
    /// Transport-specific failure.
    type Error;
    /// Exchanges one frame in the reader's selected framing.
    ///
    /// ISO framing uses complete APDUs. Native framing uses `INS || data` for
    /// the command and `status || data` for the response.
    fn transceive(&mut self, command: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
/// Framing used on the card transport.
pub enum Framing {
    /// ISO 7816 command and response APDUs.
    Iso7816 = crate::layout::DFC_FFI_READER_FRAMING_ISO7816 as u32,
    /// Native command bytes without ISO 7816 wrapping.
    Native = crate::layout::DFC_FFI_READER_FRAMING_NATIVE as u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
/// Secure-messaging mode requested for a command.
pub enum CommunicationMode {
    /// No command encryption or command MAC.
    Plain = crate::layout::DFC_FFI_COMM_PLAIN as u8,
    /// Authenticate the command and response without encrypting their data.
    Mac = crate::layout::DFC_FFI_COMM_MAC as u8,
    /// Encrypt and authenticate the protected command and response data.
    Enciphered = crate::layout::DFC_FFI_COMM_ENCIPHERED as u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Native command instruction and its data field.
pub struct Command {
    /// Native instruction byte.
    pub instruction: u8,
    /// Command data excluding framing and status bytes.
    pub data: Vec<u8>,
}

impl Command {
    fn empty(instruction: u8) -> Self {
        Self {
            instruction,
            data: Vec::new(),
        }
    }

    fn one_file(instruction: u8, file_number: u8) -> Result<Self, Error> {
        if file_number > MAX_FILE_NUMBER {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            instruction,
            data: vec![file_number],
        })
    }

    /// Select an application using the AID order stored by the credential model.
    pub fn select_application(aid: [u8; 3]) -> Self {
        Self {
            instruction: SELECT_APPLICATION_INSTRUCTION,
            data: aid.into_iter().rev().collect(),
        }
    }

    /// Builds GetVersion.
    pub fn get_version() -> Self {
        Self::empty(0x60)
    }

    /// Builds GetFreeMemory.
    pub fn get_free_memory() -> Self {
        Self::empty(0x6e)
    }

    /// Builds FormatPICC.
    pub fn format_picc() -> Self {
        Self::empty(0xfc)
    }

    /// Builds GetKeySettings for the current selection.
    pub fn get_key_settings() -> Self {
        Self::empty(0x45)
    }

    /// Builds GetApplicationIDs.
    pub fn get_application_ids() -> Self {
        Self::empty(0x6a)
    }

    /// Builds GetDFNames.
    pub fn get_df_names() -> Self {
        Self::empty(0x6d)
    }

    /// Builds GetFileIDs for the current selection.
    pub fn get_file_ids() -> Self {
        Self::empty(0x6f)
    }

    /// Builds GetISOFileIDs.
    pub fn get_iso_file_ids() -> Self {
        Self::empty(0x61)
    }

    /// Builds GetCardUID.
    pub fn get_card_uid() -> Self {
        Self::empty(0x51)
    }

    /// Builds ReadSignature.
    pub fn read_signature(signature_id: u8) -> Self {
        Self {
            instruction: 0x3c,
            data: vec![signature_id],
        }
    }

    /// Builds GetKeyVersion.
    pub fn get_key_version(key_number: u8) -> Self {
        Self {
            instruction: 0x64,
            data: vec![key_number],
        }
    }

    /// Builds GetFileSettings.
    pub fn get_file_settings(file_number: u8) -> Result<Self, Error> {
        Self::one_file(0xf5, file_number)
    }

    /// Builds GetFileCounters.
    pub fn get_file_counters(file_number: u8) -> Result<Self, Error> {
        Self::one_file(0xf6, file_number)
    }

    /// Builds DeleteFile.
    pub fn delete_file(file_number: u8) -> Result<Self, Error> {
        Self::one_file(0xdf, file_number)
    }

    /// Builds ClearRecordFile.
    pub fn clear_record_file(file_number: u8) -> Result<Self, Error> {
        Self::one_file(0xeb, file_number)
    }

    /// Builds GetValue.
    pub fn get_value(file_number: u8) -> Result<Self, Error> {
        Self::one_file(0x6c, file_number)
    }

    /// Builds ReadData with little-endian unsigned 24-bit fields.
    pub fn read_data(file_number: u8, offset: u32, length: u32) -> Result<Self, Error> {
        Self::read_data_with_instruction(0xbd, file_number, offset, length)
    }

    fn read_data_with_instruction(
        instruction: u8,
        file_number: u8,
        offset: u32,
        length: u32,
    ) -> Result<Self, Error> {
        if file_number > MAX_FILE_NUMBER || offset > MAX_U24 || length > MAX_U24 {
            return Err(Error::InvalidArgument);
        }
        let mut data = Vec::with_capacity(7);
        data.push(file_number);
        data.extend_from_slice(&offset.to_le_bytes()[..3]);
        data.extend_from_slice(&length.to_le_bytes()[..3]);
        Ok(Self { instruction, data })
    }

    /// Builds ReadData with ISO-DEP command chaining.
    pub fn read_data_iso_chaining(
        file_number: u8,
        offset: u32,
        length: u32,
    ) -> Result<Self, Error> {
        Self::read_data_with_instruction(0xad, file_number, offset, length)
    }

    fn range_with_data(
        instruction: u8,
        file_number: u8,
        offset: u32,
        data: &[u8],
    ) -> Result<Self, Error> {
        if file_number > MAX_FILE_NUMBER || offset > MAX_U24 || data.len() > MAX_RANGE_DATA {
            return Err(Error::InvalidArgument);
        }
        let mut command_data = Vec::with_capacity(7 + data.len());
        command_data.push(file_number);
        command_data.extend_from_slice(&offset.to_le_bytes()[..3]);
        command_data.extend_from_slice(&(data.len() as u32).to_le_bytes()[..3]);
        command_data.extend_from_slice(data);
        Ok(Self {
            instruction,
            data: command_data,
        })
    }

    /// Builds WriteData.
    pub fn write_data(file_number: u8, offset: u32, data: &[u8]) -> Result<Self, Error> {
        Self::range_with_data(0x3d, file_number, offset, data)
    }

    /// Builds WriteData with ISO-DEP command chaining.
    pub fn write_data_iso_chaining(
        file_number: u8,
        offset: u32,
        data: &[u8],
    ) -> Result<Self, Error> {
        Self::range_with_data(0x8d, file_number, offset, data)
    }

    /// Builds ReadRecords.
    pub fn read_records(file_number: u8, record_number: u32, count: u32) -> Result<Self, Error> {
        let mut command = Self::read_data(file_number, record_number, count)?;
        command.instruction = 0xbb;
        Ok(command)
    }

    /// Builds ReadRecords with ISO-DEP response chaining.
    pub fn read_records_iso_chaining(
        file_number: u8,
        record_number: u32,
        count: u32,
    ) -> Result<Self, Error> {
        let mut command = Self::read_data(file_number, record_number, count)?;
        command.instruction = 0xab;
        Ok(command)
    }

    /// Builds WriteRecord.
    pub fn write_record(file_number: u8, offset: u32, data: &[u8]) -> Result<Self, Error> {
        Self::range_with_data(0x3b, file_number, offset, data)
    }

    /// Builds WriteRecord with ISO-DEP command chaining.
    pub fn write_record_iso_chaining(
        file_number: u8,
        offset: u32,
        data: &[u8],
    ) -> Result<Self, Error> {
        Self::range_with_data(0x8b, file_number, offset, data)
    }

    /// Builds UpdateRecord.
    pub fn update_record(
        file_number: u8,
        record_number: u32,
        offset: u32,
        data: &[u8],
    ) -> Result<Self, Error> {
        Self::update_record_with_instruction(0xdb, file_number, record_number, offset, data)
    }

    fn update_record_with_instruction(
        instruction: u8,
        file_number: u8,
        record_number: u32,
        offset: u32,
        data: &[u8],
    ) -> Result<Self, Error> {
        if record_number > MAX_U24 || data.len() > MAX_UPDATE_DATA {
            return Err(Error::InvalidArgument);
        }
        let tail = Self::range_with_data(instruction, file_number, offset, data)?.data;
        let mut command_data = Vec::with_capacity(tail.len() + 3);
        command_data.push(file_number);
        command_data.extend_from_slice(&record_number.to_le_bytes()[..3]);
        command_data.extend_from_slice(&tail[1..]);
        Ok(Self {
            instruction,
            data: command_data,
        })
    }

    /// Builds UpdateRecord with ISO-DEP command chaining.
    pub fn update_record_iso_chaining(
        file_number: u8,
        record_number: u32,
        offset: u32,
        data: &[u8],
    ) -> Result<Self, Error> {
        Self::update_record_with_instruction(0xba, file_number, record_number, offset, data)
    }

    fn value_operation(instruction: u8, file_number: u8, amount: i32) -> Result<Self, Error> {
        if file_number > MAX_FILE_NUMBER {
            return Err(Error::InvalidArgument);
        }
        let mut data = Vec::with_capacity(5);
        data.push(file_number);
        data.extend_from_slice(&amount.to_le_bytes());
        Ok(Self { instruction, data })
    }

    /// Builds Credit.
    pub fn credit(file_number: u8, amount: i32) -> Result<Self, Error> {
        Self::value_operation(0x0c, file_number, amount)
    }

    /// Builds Debit.
    pub fn debit(file_number: u8, amount: i32) -> Result<Self, Error> {
        Self::value_operation(0xdc, file_number, amount)
    }

    /// Builds LimitedCredit.
    pub fn limited_credit(file_number: u8, amount: i32) -> Result<Self, Error> {
        Self::value_operation(0x1c, file_number, amount)
    }

    /// Builds CommitTransaction, optionally carrying its option octet.
    pub fn commit_transaction(option: Option<u8>) -> Self {
        Self {
            instruction: 0xc7,
            data: option.into_iter().collect(),
        }
    }

    /// Builds AbortTransaction.
    pub fn abort_transaction() -> Self {
        Self::empty(0xa7)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Completed command response with status separated from response data.
pub struct Response {
    /// Native card status byte.
    pub status: u8,
    /// Response data excluding the status byte.
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
/// Authentication family active in a reader session.
pub enum AuthenticationMode {
    /// The reader is unauthenticated.
    None = 0,
    /// Legacy D40 authentication.
    Legacy = crate::PiccAuthenticationMode::Legacy as u8,
    /// ISO authentication.
    Iso = crate::PiccAuthenticationMode::Iso as u8,
    /// AES authentication with EV1 secure messaging.
    Aes = crate::PiccAuthenticationMode::Aes as u8,
    /// EV2 secure messaging.
    Ev2 = 0x71,
}

/// Snapshot of the reader's authentication and chaining state.
pub struct ReaderState(sys::DfcFfiReaderState);

impl ReaderState {
    /// Returns the active authentication family.
    pub fn authentication(&self) -> AuthenticationMode {
        match self.0.auth_mode {
            0 => AuthenticationMode::None,
            value if value == AuthenticationMode::Legacy as u8 => AuthenticationMode::Legacy,
            value if value == AuthenticationMode::Iso as u8 => AuthenticationMode::Iso,
            value if value == AuthenticationMode::Aes as u8 => AuthenticationMode::Aes,
            value if value == AuthenticationMode::Ev2 as u8 => AuthenticationMode::Ev2,
            _ => unreachable!("native reader returned an invalid authentication mode"),
        }
    }

    /// Returns the authenticated key number, or `None` while unauthenticated.
    pub fn key_number(&self) -> Option<u8> {
        (self.authentication() != AuthenticationMode::None).then_some(self.0.key_no)
    }

    /// Returns the EV2 command counter, or `None` outside EV2.
    pub fn ev2_command_counter(&self) -> Option<u32> {
        (self.authentication() == AuthenticationMode::Ev2).then_some(self.0.ev2_command_counter)
    }

    /// Returns the EV2 transaction identifier, or `None` outside EV2.
    pub fn ev2_transaction_identifier(&self) -> Option<&[u8; 4]> {
        (self.authentication() == AuthenticationMode::Ev2)
            .then_some(&self.0.ev2_transaction_identifier)
    }

    /// Returns the card capabilities negotiated by EV2, or `None` outside EV2.
    pub fn ev2_card_capabilities(&self) -> Option<&[u8; 6]> {
        (self.authentication() == AuthenticationMode::Ev2).then_some(&self.0.ev2_card_capabilities)
    }

    /// Returns the reader capabilities negotiated by EV2, or `None` outside EV2.
    pub fn ev2_reader_capabilities(&self) -> Option<&[u8; 6]> {
        (self.authentication() == AuthenticationMode::Ev2)
            .then_some(&self.0.ev2_reader_capabilities)
    }
}

#[derive(Debug)]
/// Error from reader processing, the card, or the supplied transport.
pub enum ReaderError<E> {
    /// Local reader or native-library failure.
    Dfc(Error),
    /// Terminal status byte returned by the card.
    Card(u8),
    /// Failure reported by [`Transport::transceive`].
    Transport(E),
}

impl<E: core::fmt::Display> core::fmt::Display for ReaderError<E> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Dfc(error) => error.fmt(formatter),
            Self::Card(status) => write!(formatter, "card returned status {status:#04x}"),
            Self::Transport(error) => write!(formatter, "transport failed: {error}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for ReaderError<E> {}

/// Stateful command reader over a caller-supplied transport.
///
/// The reader owns the native session and exchange handles. It is `Send` when
/// its transport is `Send`, but intentionally not `Sync`.
pub struct Reader<T> {
    transport: T,
    framing: Framing,
    session: NonNull<sys::DfcFfiReaderSession>,
    exchange: NonNull<sys::DfcFfiReaderExchange>,
    apdu: ApduBuffer,
    _not_sync: PhantomData<core::cell::Cell<()>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReaderStepStatus {
    Complete,
    Pending,
}

pub(crate) fn reader_step_status(value: i32) -> Result<ReaderStepStatus, Error> {
    if value == sys::DFC_FFI_READER_PENDING as i32 {
        return Ok(ReaderStepStatus::Pending);
    }
    status(value)?;
    Ok(ReaderStepStatus::Complete)
}

// SAFETY: the native session and exchange handles are uniquely owned. All
// operations require `&mut self`, and moving the reader also moves its transport.
unsafe impl<T: Send> Send for Reader<T> {}

impl<T: Transport> Reader<T> {
    /// Creates a reader using `transport` and the selected wire framing.
    pub fn new(transport: T, framing: Framing) -> Result<Self, Error> {
        ensure_abi()?;
        let apdu = ApduBuffer::new()?;
        let mut session = core::ptr::null_mut();
        status(unsafe { sys::dfc_ffi_reader_session_new(&mut session) })?;
        let Some(session) = NonNull::new(session) else {
            return Err(Error::OutOfMemory);
        };
        let mut exchange = core::ptr::null_mut();
        if let Err(error) = status(unsafe { sys::dfc_ffi_reader_exchange_new(&mut exchange) }) {
            unsafe { sys::dfc_ffi_reader_session_free(session.as_ptr()) };
            return Err(error);
        }
        let Some(exchange) = NonNull::new(exchange) else {
            unsafe { sys::dfc_ffi_reader_session_free(session.as_ptr()) };
            return Err(Error::OutOfMemory);
        };
        Ok(Self {
            transport,
            framing,
            session,
            exchange,
            apdu,
            _not_sync: PhantomData,
        })
    }

    /// Returns a copy of the reader's current public state.
    pub fn state(&self) -> Result<ReaderState, Error> {
        let mut value = MaybeUninit::uninit();
        status(unsafe {
            sys::dfc_ffi_reader_session_state(self.session.as_ptr(), value.as_mut_ptr())
        })?;
        Ok(ReaderState(unsafe { value.assume_init() }))
    }

    /// Clears authentication, chaining, and buffered APDU state.
    pub fn clear(&mut self) {
        unsafe { sys::dfc_ffi_reader_session_clear(self.session.as_ptr()) }
        self.apdu.wipe();
    }

    /// Mutably borrows the transport, for example to configure timeouts.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Exchange one command.
    ///
    /// `clear_header` of `None` derives the clear head of an encrypted field from
    /// the instruction. `Some(n)` is a head length no larger than the core's
    /// `DFC_READER_MAX_CLEAR_HEADER_LENGTH`; the native core refuses a larger
    /// value, and a value that does not fit the native `int32_t` is refused
    /// before the call, both as [`Error::InvalidArgument`]. The session stays
    /// usable after a refusal.
    pub fn exchange(
        &mut self,
        command: &Command,
        mode: CommunicationMode,
        clear_header: Option<u32>,
    ) -> Result<Response, ReaderError<T::Error>> {
        let header_len = match clear_header {
            None => -1,
            Some(n) => i32::try_from(n).map_err(|_| ReaderError::Dfc(Error::InvalidArgument))?,
        };
        status(unsafe {
            sys::dfc_ffi_reader_exchange_begin(
                self.exchange.as_ptr(),
                self.session.as_ptr(),
                self.framing as u32,
                command.instruction,
                command.data.as_ptr(),
                command.data.len(),
                mode as u8,
                header_len,
            )
        })
        .map_err(ReaderError::Dfc)?;
        self.run()
    }

    /// Runs native D40, ISO, or AES authentication.
    ///
    /// `cipher` is the native authentication instruction, `key_no` selects the
    /// card key, and `random_a` must have the challenge length for that cipher.
    pub fn authenticate(
        &mut self,
        cipher: u8,
        key_no: u8,
        key: &[u8],
        random_a: &[u8],
    ) -> Result<Response, ReaderError<T::Error>> {
        if native_auth_challenge_length(cipher, key.len()) != Some(random_a.len()) {
            return Err(ReaderError::Dfc(Error::InvalidArgument));
        }
        status(unsafe {
            sys::dfc_ffi_reader_authenticate_begin(
                self.exchange.as_ptr(),
                self.session.as_ptr(),
                self.framing as u32,
                cipher,
                key_no,
                key.as_ptr(),
                key.len(),
                random_a.as_ptr(),
                random_a.len(),
            )
        })
        .map_err(ReaderError::Dfc)?;
        self.run()
    }

    /// Runs EV2 First or NonFirst authentication with caller-supplied RndA.
    ///
    /// `capabilities` is the optional reader capability block sent during EV2
    /// First authentication and must be empty for NonFirst where required.
    pub fn authenticate_ev2(
        &mut self,
        first: bool,
        key_no: u8,
        key: &[u8; 16],
        random_a: &[u8; 16],
        capabilities: &[u8],
    ) -> Result<Response, ReaderError<T::Error>> {
        status(unsafe {
            sys::dfc_ffi_reader_authenticate_ev2_begin(
                self.exchange.as_ptr(),
                self.session.as_ptr(),
                self.framing as u32,
                first.into(),
                key_no,
                key.as_ptr(),
                random_a.as_ptr(),
                capabilities.as_ptr(),
                capabilities.len(),
            )
        })
        .map_err(ReaderError::Dfc)?;
        self.run()
    }

    /// Runs the ISO 7816 challenge/authenticate sequence.
    ///
    /// Both random values must have the same algorithm-specific length.
    pub fn authenticate_iso7816(
        &mut self,
        key_reference: u8,
        key: &[u8],
        algorithm: u8,
        random_first: &[u8],
        random_second: &[u8],
    ) -> Result<Response, ReaderError<T::Error>> {
        if random_first.len() != random_second.len() {
            return Err(ReaderError::Dfc(Error::InvalidArgument));
        }
        status(unsafe {
            sys::dfc_ffi_reader_authenticate_iso7816_begin(
                self.exchange.as_ptr(),
                self.session.as_ptr(),
                key_reference,
                key.as_ptr(),
                key.len(),
                algorithm,
                random_first.as_ptr(),
                random_second.as_ptr(),
                random_first.len(),
            )
        })
        .map_err(ReaderError::Dfc)?;
        self.run()
    }

    /// Writes bytes to a standard or backup data file.
    pub fn write_data(
        &mut self,
        file_number: u8,
        offset: u32,
        data: &[u8],
        mode: CommunicationMode,
    ) -> Result<Response, ReaderError<T::Error>> {
        status(unsafe {
            sys::dfc_ffi_reader_write_data_begin(
                self.exchange.as_ptr(),
                self.session.as_ptr(),
                self.framing as u32,
                file_number,
                offset,
                data.as_ptr(),
                data.len(),
                mode as u8,
            )
        })
        .map_err(ReaderError::Dfc)?;
        self.run()
    }

    /// Appends or writes bytes in a record file.
    pub fn write_record(
        &mut self,
        file_number: u8,
        offset: u32,
        data: &[u8],
        mode: CommunicationMode,
    ) -> Result<Response, ReaderError<T::Error>> {
        status(unsafe {
            sys::dfc_ffi_reader_write_record_begin(
                self.exchange.as_ptr(),
                self.session.as_ptr(),
                self.framing as u32,
                file_number,
                offset,
                data.as_ptr(),
                data.len(),
                mode as u8,
            )
        })
        .map_err(ReaderError::Dfc)?;
        self.run()
    }

    /// Updates bytes in an existing record.
    pub fn update_record(
        &mut self,
        file_number: u8,
        record_number: u32,
        offset: u32,
        data: &[u8],
        mode: CommunicationMode,
    ) -> Result<Response, ReaderError<T::Error>> {
        status(unsafe {
            sys::dfc_ffi_reader_update_record_begin(
                self.exchange.as_ptr(),
                self.session.as_ptr(),
                self.framing as u32,
                file_number,
                record_number,
                offset,
                data.as_ptr(),
                data.len(),
                mode as u8,
            )
        })
        .map_err(ReaderError::Dfc)?;
        self.run()
    }

    #[allow(clippy::too_many_arguments)]
    /// Creates a delegated application from a preassembled command header.
    ///
    /// The header and key inputs are consumed only for this exchange and are
    /// not retained by the reader.
    pub fn create_delegated_application(
        &mut self,
        header: &[u8],
        dam_encryption_key: &[u8; 16],
        dam_mac_key: &[u8; 16],
        random_prefix: &[u8],
        initial_key: &[u8],
        initial_version: u8,
    ) -> Result<Response, ReaderError<T::Error>> {
        status(unsafe {
            sys::dfc_ffi_reader_create_delegated_application_begin(
                self.exchange.as_ptr(),
                self.session.as_ptr(),
                self.framing as u32,
                header.as_ptr(),
                header.len(),
                dam_encryption_key.as_ptr(),
                dam_mac_key.as_ptr(),
                random_prefix.as_ptr(),
                initial_key.as_ptr(),
                initial_key.len(),
                initial_version,
            )
        })
        .map_err(ReaderError::Dfc)?;
        self.run()
    }

    /// Builds the protected ChangeKey payload for the active legacy/EV1 session.
    ///
    /// `current_key` is required when changing a key other than the one used to
    /// authenticate. The returned bytes exclude the command instruction.
    pub fn change_key_cryptogram(
        &self,
        key_no: u8,
        new_key: &[u8],
        current_key: Option<&[u8]>,
        aes_key: bool,
        new_version: u8,
    ) -> Result<Vec<u8>, Error> {
        output(|out, cap, len| unsafe {
            sys::dfc_ffi_reader_change_key_cryptogram(
                self.session.as_ptr(),
                key_no,
                new_key.as_ptr(),
                new_key.len(),
                current_key.map_or(core::ptr::null(), |key| key.as_ptr()),
                aes_key.into(),
                new_version,
                out,
                cap,
                len,
            )
        })
    }

    /// Builds the protected ChangeKey payload for the active EV2 session.
    ///
    /// `current_key` is required when the changed key differs from the
    /// authenticated key. The returned bytes exclude the command instruction.
    pub fn change_key_ev2_data(
        &self,
        key_set_no: u8,
        key_no: u8,
        new_key: &[u8; 16],
        current_key: Option<&[u8; 16]>,
        new_version: u8,
    ) -> Result<Vec<u8>, Error> {
        output(|out, cap, len| unsafe {
            sys::dfc_ffi_reader_change_key_ev2_data(
                self.session.as_ptr(),
                key_set_no,
                key_no,
                new_key.as_ptr(),
                current_key.map_or(core::ptr::null(), |key| key.as_ptr()),
                new_version,
                out,
                cap,
                len,
            )
        })
    }

    fn run(&mut self) -> Result<Response, ReaderError<T::Error>> {
        let mut incoming = Vec::new();
        loop {
            let (result, len) = loop {
                let mut len = 0;
                let outgoing = self.apdu.as_mut_slice();
                let result = unsafe {
                    sys::dfc_ffi_reader_step(
                        self.exchange.as_ptr(),
                        incoming.as_ptr(),
                        incoming.len(),
                        outgoing.as_mut_ptr(),
                        outgoing.len(),
                        &mut len,
                    )
                };
                if result != sys::DFC_FFI_READER_BUFFER_TOO_SMALL as i32 {
                    break (result, len);
                }
                if let Err(error) = grow_after_response(&mut self.apdu, &mut incoming) {
                    incoming.clear();
                    self.clear();
                    return Err(ReaderError::Dfc(error));
                }
            };
            wipe_slice(&mut incoming);
            incoming.clear();
            if result == sys::DFC_FFI_READER_CARD_ERROR as i32 {
                self.apdu.wipe();
                let status = unsafe { sys::dfc_ffi_reader_result_status(self.exchange.as_ptr()) };
                return Err(ReaderError::Card(status));
            }
            let step = match reader_step_status(result) {
                Ok(step) => step,
                Err(error) => {
                    self.apdu.wipe();
                    return Err(ReaderError::Dfc(error));
                }
            };
            if step == ReaderStepStatus::Complete {
                self.apdu.wipe();
                let data = output(|out, cap, len| unsafe {
                    sys::dfc_ffi_reader_result_data(self.exchange.as_ptr(), out, cap, len)
                })
                .map_err(ReaderError::Dfc)?;
                let status = unsafe { sys::dfc_ffi_reader_result_status(self.exchange.as_ptr()) };
                return Ok(Response { status, data });
            }
            let command = match self.apdu.command(len) {
                Ok(command) => command,
                Err(error) => {
                    self.apdu.wipe();
                    return Err(ReaderError::Dfc(error));
                }
            };
            let transceive = self.transport.transceive(command);
            self.apdu.wipe();
            incoming = match transceive {
                Ok(response) => response,
                Err(error) => {
                    self.clear();
                    return Err(ReaderError::Transport(error));
                }
            };
        }
    }
}

#[cfg(test)]
mod authentication_boundary_tests {
    use super::native_auth_challenge_length;

    #[test]
    fn native_authentication_boundaries_match_shared_contract() {
        for line in include_str!("../tests/fixtures/authentication-boundaries.txt").lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<_> = line.split('|').collect();
            let cipher = match fields[0] {
                "legacy" => 0x0a,
                "iso" => 0x1a,
                "aes" => 0xaa,
                other => panic!("unknown cipher {other}"),
            };
            let key_length = fields[1].parse().expect("key length");
            let challenge_length = fields[2].parse().expect("challenge length");
            let accepted =
                native_auth_challenge_length(cipher, key_length) == Some(challenge_length);
            assert_eq!(accepted, fields[3] == "yes", "{line}");
        }
    }
}

impl<T> Drop for Reader<T> {
    fn drop(&mut self) {
        unsafe {
            sys::dfc_ffi_reader_exchange_free(self.exchange.as_ptr());
            sys::dfc_ffi_reader_session_free(self.session.as_ptr());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apdu_buffer_reuses_bounded_storage_and_wipes_it() {
        let mut buffer = ApduBuffer::new().expect("initial APDU storage");
        let initial = buffer.bytes.as_ptr();
        buffer.bytes.fill(0xa5);
        buffer.wipe();
        assert!(buffer.bytes.iter().all(|byte| *byte == 0));
        assert_eq!(buffer.bytes.as_ptr(), initial);

        while buffer.bytes.len() < MAX_OUTPUT_CAPACITY {
            buffer.grow().expect("capacity below the APDU bound");
        }
        assert_eq!(buffer.bytes.len(), MAX_OUTPUT_CAPACITY);
        assert_eq!(buffer.grow(), Err(Error::BufferTooSmall));
    }

    #[test]
    fn retry_growth_failure_wipes_received_data() {
        let mut buffer = ApduBuffer::new().expect("initial APDU storage");
        while buffer.bytes.len() < MAX_OUTPUT_CAPACITY {
            buffer.grow().expect("capacity below the APDU bound");
        }
        buffer.bytes.fill(0xa5);
        let mut incoming = [0x5a; 32];

        assert_eq!(
            grow_after_response(&mut buffer, &mut incoming),
            Err(Error::BufferTooSmall)
        );
        assert!(incoming.iter().all(|byte| *byte == 0));
        assert!(buffer.bytes.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn step_status_maps_the_complete_abi_family() {
        assert_eq!(
            reader_step_status(sys::DFC_FFI_READER_OK as i32),
            Ok(ReaderStepStatus::Complete)
        );
        assert_eq!(
            reader_step_status(sys::DFC_FFI_READER_PENDING as i32),
            Ok(ReaderStepStatus::Pending)
        );
        for terminal in [
            sys::DFC_FFI_READER_INVALID,
            sys::DFC_FFI_READER_PROTOCOL_ERROR,
            sys::DFC_FFI_READER_INTEGRITY_ERROR,
            sys::DFC_FFI_READER_CARD_ERROR,
            sys::DFC_FFI_READER_UNSUPPORTED,
        ] {
            assert_eq!(
                reader_step_status(terminal as i32),
                Err(Error::Native(terminal as i32))
            );
        }
        assert_eq!(reader_step_status(-5), Err(Error::RandomSourceFailed));
    }
}
