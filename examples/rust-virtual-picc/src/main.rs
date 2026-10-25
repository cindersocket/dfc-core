use dfc_core::{Credential, Error, VirtualPicc, decode_version};

const GET_VERSION: &[u8] = &[0x90, 0x60, 0x00, 0x00, 0x00];
const ADDITIONAL_FRAME: &[u8] = &[0x90, 0xAF, 0x00, 0x00, 0x00];
const MORE_DATA: [u8; 2] = [0x91, 0xAF];
const OK: [u8; 2] = [0x91, 0x00];

#[derive(Debug, PartialEq, Eq)]
struct VersionReport {
    hardware_version: (u8, u8),
    software_version: (u8, u8),
    storage_size_code: u8,
    uid: [u8; 7],
    production_batch: [u8; 5],
    production_week: u8,
    production_year: u8,
    raw: [u8; 28],
}

#[derive(Debug)]
enum ExampleError {
    Dfc(Error),
    Protocol(&'static str),
}

impl From<Error> for ExampleError {
    fn from(error: Error) -> Self {
        Self::Dfc(error)
    }
}

impl core::fmt::Display for ExampleError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Dfc(error) => error.fmt(formatter),
            Self::Protocol(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for ExampleError {}

fn transceive_version(picc: &mut VirtualPicc) -> Result<[u8; 28], ExampleError> {
    let mut payload = Vec::with_capacity(28);
    let mut command = GET_VERSION;

    for frame_index in 0..3 {
        let response = picc.exchange(command)?;
        let Some((data, status)) = response.split_last_chunk::<2>() else {
            return Err(ExampleError::Protocol(
                "GetVersion response has no status word",
            ));
        };

        let expected_status = if frame_index < 2 { MORE_DATA } else { OK };
        if *status != expected_status {
            return Err(ExampleError::Protocol("unexpected GetVersion status word"));
        }

        payload.extend_from_slice(data);
        command = ADDITIONAL_FRAME;
    }

    payload
        .try_into()
        .map_err(|_| ExampleError::Protocol("GetVersion payload is not 28 bytes"))
}

fn inspect_virtual_card(credential_bytes: &[u8]) -> Result<VersionReport, ExampleError> {
    let credential = Credential::load(credential_bytes)?;
    credential.validate()?;

    // Moving the credential keeps its data pools single-owned while the PICC runs.
    let mut picc = VirtualPicc::from_credential(credential)?;
    let activation = picc.activate()?;
    if activation.0.uid_len == 0 {
        return Err(ExampleError::Protocol("activation returned an empty UID"));
    }

    let raw = transceive_version(&mut picc)?;
    let decoded = decode_version(&raw)
        .map_err(|_| ExampleError::Protocol("GetVersion response could not be decoded"))?;
    let report = VersionReport {
        hardware_version: (
            decoded.hardware.major_version,
            decoded.hardware.minor_version,
        ),
        software_version: (
            decoded.software.major_version,
            decoded.software.minor_version,
        ),
        storage_size_code: decoded.hardware.storage_size,
        uid: decoded.uid,
        production_batch: decoded.batch_number,
        production_week: decoded.production_week,
        production_year: decoded.production_year,
        raw,
    };

    // Field-off clears volatile protocol and authentication state for the next tap.
    picc.field_off()?;
    Ok(report)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os().nth(1);
    let credential = match &path {
        Some(path) => std::fs::read(path)?,
        None => include_bytes!("../../credentials/v6-minimal.dfcb").to_vec(),
    };
    let report = inspect_virtual_card(&credential)?;
    println!("UID: {}", hex(&report.uid));
    println!(
        "Hardware: {:02X}.{:02X}, software: {:02X}.{:02X}, storage code: 0x{:02X}",
        report.hardware_version.0,
        report.hardware_version.1,
        report.software_version.0,
        report.software_version.1,
        report.storage_size_code
    );
    println!(
        "Production batch: {}, week: {:02X}, year: {:02X}",
        hex(&report.production_batch),
        report.production_week,
        report.production_year
    );
    println!("GetVersion payload: {}", hex(&report.raw));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_card_completes_the_get_version_lifecycle() {
        let report = inspect_virtual_card(include_bytes!("../../credentials/v6-minimal.dfcb"))
            .expect("virtual-card lifecycle");

        assert_eq!(report.raw.len(), 28);
        assert_eq!(report.uid, [0x04, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        assert_eq!(report.hardware_version, (0x33, 0));
        assert_eq!(report.software_version, (3, 0));
    }
}
