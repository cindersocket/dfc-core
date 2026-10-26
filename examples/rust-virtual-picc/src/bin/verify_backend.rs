use dfc_core::{
    Credential, SdmConfig, SdmField, TransactionMacVerifier, VirtualPicc, decode_file_settings,
    verify_sdm,
};

fn exchange(picc: &mut VirtualPicc, command: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let response = picc.exchange(command)?;
    let Some((data, status)) = response.split_last_chunk::<2>() else {
        return Err("response has no status word".into());
    };
    if status != &[0x91, 0x00] {
        return Err(format!("card returned status {:02X?}", status).into());
    }
    Ok(data.to_vec())
}

fn apdu(instruction: u8, data: &[u8]) -> Vec<u8> {
    let mut command = vec![0x90, instruction, 0, 0, data.len() as u8];
    command.extend_from_slice(data);
    command.push(0);
    command
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let message = b"0483B4F2CF1890000001163F0AC4319102F37F4B61FE6BFDE1469CF53E287D682A2E";
    let sdm = verify_sdm(
        message,
        SdmConfig {
            mac_input_offset: 20,
            mac_offset: 52,
            plain_uid: Some(SdmField {
                offset: 0,
                length: 7,
            }),
            plain_read_counter_offset: Some(14),
            encrypted_picc_data: None,
            encrypted_file_data: Some(SdmField {
                offset: 20,
                length: 32,
            }),
        },
        &[0; 16],
        None,
    )
    .map_err(|error| format!("SDM: {error:?}"))?;
    println!(
        "verified SDM UID={:02X?}, counter={:?}",
        sdm.uid, sdm.read_counter
    );

    // The example does not submit a reader ID, so disable that optional policy
    // in its private credential copy before starting the virtual card.
    let credential_text = include_str!("../../../credentials/v6-maximal.dfc").replace(
        "Application 00 File 05 Access Rights: 1F 00",
        "Application 00 File 05 Access Rights: FF FF",
    );
    let credential = Credential::parse_text(&credential_text)?;
    let card = credential.card()?;
    let transaction_file = (0..credential.file_count())
        .find_map(|index| credential.file(index).ok().filter(|file| file.type_ == 5))
        .ok_or("credential has no transaction MAC file")?;
    let transaction_key = transaction_file.transaction_mac_key;
    let uid = &card.uid[..card.uid_len as usize];

    let mut picc = VirtualPicc::from_credential(credential)?;
    picc.activate()?;
    exchange(&mut picc, &apdu(0x5a, &[3, 2, 1]))?;

    let settings_response = exchange(&mut picc, &apdu(0xf5, &[3]))?;
    let settings = decode_file_settings(&settings_response)
        .map_err(|error| format!("file settings: {error:?}"))?;
    println!(
        "file type={:?}, communication={:?}",
        settings.file_type, settings.communication_mode
    );

    let mut credit = vec![3];
    credit.extend_from_slice(&1_u32.to_le_bytes());
    exchange(&mut picc, &apdu(0x0c, &credit))?;
    let commit = exchange(&mut picc, &apdu(0xc7, &[1]))?;
    if commit.len() != 12 {
        return Err("commit did not return a counter and transaction MAC".into());
    }
    let counter = u32::from_le_bytes(commit[..4].try_into()?);
    let mut receipt = TransactionMacVerifier::new(&transaction_key, uid, counter, 128)
        .map_err(|error| format!("transaction verifier: {error:?}"))?;
    receipt
        .add_value(0x0c, 3, 1)
        .map_err(|error| format!("transaction input: {error:?}"))?;
    if !receipt
        .verify(commit[4..].try_into()?)
        .map_err(|error| format!("transaction receipt: {error:?}"))?
    {
        return Err("transaction receipt did not match".into());
    }
    println!("transaction receipt {counter} verified");
    Ok(())
}
