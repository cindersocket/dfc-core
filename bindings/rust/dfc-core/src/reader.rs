use crate::{Error, ensure_abi, output, status};
use core::{marker::PhantomData, mem::MaybeUninit, ptr::NonNull};
use dfc_core_sys as sys;

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
    Transport(E),
}

impl<E: core::fmt::Display> core::fmt::Display for ReaderError<E> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Dfc(error) => error.fmt(formatter),
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

    pub fn exchange(
        &mut self,
        command: &Command,
        mode: CommunicationMode,
        clear_header: Option<u32>,
    ) -> Result<Response, ReaderError<T::Error>> {
        status(unsafe {
            sys::dfc_ffi_reader_exchange_begin(
                self.exchange.as_ptr(),
                self.session.as_ptr(),
                self.framing as u32,
                command.instruction,
                command.data.as_ptr(),
                command.data.len(),
                mode as u8,
                clear_header.map_or(-1, |n| n as i32),
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
            let mut outgoing = vec![0; 1024];
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
            if result < 0 {
                return Err(ReaderError::Dfc(crate::status(result).unwrap_err()));
            }
            outgoing.truncate(len);
            if result == 0 {
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
