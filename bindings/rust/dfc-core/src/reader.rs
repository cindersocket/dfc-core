use crate::{Error, ensure_abi, output, status};
use core::{marker::PhantomData, mem::MaybeUninit, ptr::NonNull};
use dfc_core_sys as sys;

const INITIAL_OUTPUT_CAPACITY: usize = 64;

pub trait Transport {
    type Error;
    fn transceive(&mut self, command: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Framing {
    Iso7816 = 0,
    Native = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CommunicationMode {
    Plain = 0,
    Mac = 1,
    Enciphered = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub instruction: u8,
    pub data: Vec<u8>,
}

impl Command {
    /// Select an application using the AID order stored by the credential model.
    pub fn select_application(aid: [u8; 3]) -> Self {
        Self {
            instruction: 0x5a,
            data: aid.into_iter().rev().collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u8,
    pub data: Vec<u8>,
}

pub struct ReaderState(pub sys::DfcFfiReaderState);

#[derive(Debug)]
pub enum ReaderError<E> {
    Dfc(Error),
    Card(u8),
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

pub struct Reader<T> {
    transport: T,
    framing: Framing,
    session: NonNull<sys::DfcFfiReaderSession>,
    exchange: NonNull<sys::DfcFfiReaderExchange>,
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

unsafe impl<T: Send> Send for Reader<T> {}

impl<T: Transport> Reader<T> {
    pub fn new(transport: T, framing: Framing) -> Result<Self, Error> {
        ensure_abi()?;
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
            _not_sync: PhantomData,
        })
    }

    pub fn state(&self) -> Result<ReaderState, Error> {
        let mut value = MaybeUninit::uninit();
        status(unsafe {
            sys::dfc_ffi_reader_session_state(self.session.as_ptr(), value.as_mut_ptr())
        })?;
        Ok(ReaderState(unsafe { value.assume_init() }))
    }

    pub fn clear(&mut self) {
        unsafe { sys::dfc_ffi_reader_session_clear(self.session.as_ptr()) }
    }

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

    pub fn authenticate(
        &mut self,
        cipher: u8,
        key_no: u8,
        key: &[u8],
        random_a: &[u8],
    ) -> Result<Response, ReaderError<T::Error>> {
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
            let mut outgoing = vec![0; INITIAL_OUTPUT_CAPACITY];
            let (result, len) = loop {
                let mut len = 0;
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
                let capacity = outgoing
                    .len()
                    .checked_mul(2)
                    .ok_or(ReaderError::Dfc(Error::BufferTooSmall))?;
                outgoing.resize(capacity, 0);
            };
            outgoing.truncate(len);
            if result == sys::DFC_FFI_READER_CARD_ERROR as i32 {
                let status = unsafe { sys::dfc_ffi_reader_result_status(self.exchange.as_ptr()) };
                return Err(ReaderError::Card(status));
            }
            if reader_step_status(result).map_err(ReaderError::Dfc)? == ReaderStepStatus::Complete {
                let data = output(|out, cap, len| unsafe {
                    sys::dfc_ffi_reader_result_data(self.exchange.as_ptr(), out, cap, len)
                })
                .map_err(ReaderError::Dfc)?;
                let status = unsafe { sys::dfc_ffi_reader_result_status(self.exchange.as_ptr()) };
                return Ok(Response { status, data });
            }
            incoming = match self.transport.transceive(&outgoing) {
                Ok(response) => response,
                Err(error) => {
                    self.clear();
                    return Err(ReaderError::Transport(error));
                }
            };
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
