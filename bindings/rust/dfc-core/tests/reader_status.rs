use dfc_core::{
    Command, CommunicationMode, Credential, Error, Framing, Reader, ReaderError, Transport,
    VirtualPicc, raw,
};

struct MalformedTransport {
    calls: usize,
}

impl Transport for MalformedTransport {
    type Error = &'static str;

    fn transceive(&mut self, _command: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.calls += 1;
        if self.calls == 1 {
            Ok(vec![0])
        } else {
            Err("terminal reader status was retransmitted")
        }
    }
}

#[test]
fn terminal_status_does_not_retransmit() {
    let mut reader =
        Reader::new(MalformedTransport { calls: 0 }, Framing::Iso7816).expect("reader");
    let version = Command {
        instruction: 0x60,
        data: Vec::new(),
    };

    assert!(matches!(
        reader.exchange(&version, CommunicationMode::Plain, None),
        Err(ReaderError::Dfc(Error::Native(status)))
            if status == raw::DFC_FFI_READER_PROTOCOL_ERROR as i32
    ));
    assert_eq!(reader.transport_mut().calls, 1);
}

struct RejectingTransport {
    command_len: usize,
}

impl Transport for RejectingTransport {
    type Error = &'static str;

    fn transceive(&mut self, command: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.command_len = command.len();
        Ok(vec![0x91, 0x1c])
    }
}

#[test]
fn card_status_survives_a_grown_command_buffer() {
    let mut reader =
        Reader::new(RejectingTransport { command_len: 0 }, Framing::Iso7816).expect("reader");
    let command = Command {
        instruction: 0x3d,
        data: vec![0; 200],
    };

    let result = reader.exchange(&command, CommunicationMode::Plain, None);

    assert!(matches!(result, Err(ReaderError::Card(0x1c))), "{result:?}");
    assert!(reader.transport_mut().command_len > 64);
}

struct CorruptD40MacTransport {
    picc: VirtualPicc,
    calls: usize,
    forge_empty: bool,
    forged: usize,
}

impl Transport for CorruptD40MacTransport {
    type Error = Error;

    fn transceive(&mut self, command: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.calls += 1;
        let mut response = self.picc.exchange(command)?;
        let is_read = command.first() == Some(&0xbd) || command.get(1) == Some(&0xbd);
        if is_read {
            if self.forge_empty {
                response = vec![0, 0, 0, 0, 0x91, 0];
                self.forged += 1;
            } else if response.len() >= 6 {
                response[0] ^= 1;
            }
        }
        Ok(response)
    }
}

fn d40_reader(forge_empty: bool) -> Reader<CorruptD40MacTransport> {
    let credential = Credential::decode(include_bytes!(
        "../../../../examples/credentials/v6-auth-commands.dfcb"
    ))
    .expect("fixture");
    let mut picc = VirtualPicc::from_credential(credential).expect("PICC");
    picc.activate().expect("activation");
    let mut reader = Reader::new(
        CorruptD40MacTransport {
            picc,
            calls: 0,
            forge_empty,
            forged: 0,
        },
        Framing::Iso7816,
    )
    .expect("reader");

    reader
        .exchange(
            &Command::select_application([0xf1, 0x49, 0x47]),
            CommunicationMode::Plain,
            None,
        )
        .expect("select D40 application");
    reader
        .authenticate(0x0a, 0, &[0; 8], &[0; 8])
        .expect("D40 authentication");
    assert_ne!(reader.state().expect("authenticated state").0.auth_mode, 0);
    reader
        .exchange(
            &Command {
                instruction: 0xcd,
                data: vec![1, 1, 0xee, 0xee, 4, 0, 0],
            },
            CommunicationMode::Plain,
            None,
        )
        .expect("create MAC-mode data file");
    reader
}

#[test]
fn d40_integrity_failure_is_terminal_and_retires_session() {
    let mut reader = d40_reader(false);

    let calls = reader.transport_mut().calls;
    let result = reader.exchange(
        &Command {
            instruction: 0xbd,
            data: vec![1, 0, 0, 0, 1, 0, 0],
        },
        CommunicationMode::Mac,
        None,
    );
    assert!(
        matches!(
            result,
            Err(ReaderError::Dfc(Error::Native(status)))
                if status == raw::DFC_FFI_READER_INTEGRITY_ERROR as i32
        ),
        "{result:?}"
    );
    assert_eq!(reader.transport_mut().calls, calls + 1);
    assert_eq!(reader.state().expect("retired state").0.auth_mode, 0);
}

#[test]
fn d40_empty_mac_forge_is_terminal_and_retires_session() {
    let mut reader = d40_reader(true);
    let calls = reader.transport_mut().calls;

    let result = reader.exchange(
        &Command {
            instruction: 0xbd,
            data: vec![1, 0, 0, 0, 1, 0, 0],
        },
        CommunicationMode::Mac,
        None,
    );

    assert_eq!(reader.transport_mut().forged, 1);
    assert!(
        matches!(
            result,
            Err(ReaderError::Dfc(Error::Native(status)))
                if status == raw::DFC_FFI_READER_PROTOCOL_ERROR as i32
        ),
        "{result:?}"
    );
    assert_eq!(reader.transport_mut().calls, calls + 1);
    assert_eq!(reader.state().expect("retired state").0.auth_mode, 0);
}
