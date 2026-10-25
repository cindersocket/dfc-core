use dfc_core::{
    Access, DecodeError, DiversificationAlgorithm, FileSettingsKind, SdmConfig, SdmError, SdmField,
    TransactionMacVerifier, decode_application_ids, decode_file_settings, decode_version,
    diversify_key, verify_sdm,
};

#[test]
fn diversification_and_response_decoding_use_native_core() {
    let master = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let input = [
        0x04, 0x78, 0x2e, 0x21, 0x80, 0x1d, 0x80, 0x30, 0x42, 0xf5, 0x4e, 0x58, 0x50, 0x20, 0x41,
        0x62, 0x75,
    ];
    assert_eq!(
        diversify_key(DiversificationAlgorithm::Aes128, &master, &input).unwrap(),
        [
            0xa8, 0xdd, 0x63, 0xa3, 0xb8, 0x9d, 0x54, 0xb3, 0x7c, 0xa8, 0x02, 0x47, 0x3f, 0xda,
            0x91, 0x75
        ]
    );
    assert_eq!(
        decode_application_ids(&[0x03, 0x02, 0x01, 0xcc, 0xbb, 0xaa]).unwrap(),
        [[1, 2, 3], [0xaa, 0xbb, 0xcc]]
    );
    let settings = decode_file_settings(&[0, 3, 0x12, 0xef, 0x80, 0, 0]).unwrap();
    assert_eq!(settings.read, Access::Free);
    assert_eq!(settings.write, Access::Denied);
    assert_eq!(settings.kind, FileSettingsKind::Data { size: 128 });
    assert_eq!(decode_version(&[0; 27]), Err(DecodeError::Malformed));
    assert_eq!(
        decode_file_settings(&[0xff, 0, 0, 0]),
        Err(DecodeError::Unsupported)
    );
}

#[test]
fn captured_sdm_and_transaction_receipts_verify() {
    let message = b"0483B4F2CF1890000001163F0AC4319102F37F4B61FE6BFDE1469CF53E287D682A2E";
    let config = SdmConfig {
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
    };
    let result = verify_sdm(message, config, &[0; 16], None).unwrap();
    assert_eq!(
        result.uid.unwrap(),
        [0x04, 0x83, 0xb4, 0xf2, 0xcf, 0x18, 0x90]
    );
    assert_eq!(result.read_counter, Some(1));
    assert_eq!(
        result.decrypted_file_data,
        (0..16).map(|n| n * 0x11).collect::<Vec<_>>()
    );
    let mut modified = *message;
    modified[modified.len() - 1] ^= 1;
    assert!(verify_sdm(&modified, config, &[0; 16], None).is_err());
    assert_eq!(
        verify_sdm(
            message,
            SdmConfig {
                encrypted_file_data: Some(SdmField {
                    offset: 0,
                    length: usize::MAX,
                }),
                ..config
            },
            &[0; 16],
            None,
        ),
        Err(SdmError::InvalidConfig)
    );
    let wrong_key = [1; 16];
    assert!(
        verify_sdm(
            message,
            SdmConfig {
                mac_input_offset: 20,
                mac_offset: 52,
                plain_uid: Some(SdmField {
                    offset: 0,
                    length: 7
                }),
                plain_read_counter_offset: Some(14),
                encrypted_picc_data: None,
                encrypted_file_data: Some(SdmField {
                    offset: 20,
                    length: 32
                }),
            },
            &wrong_key,
            None,
        )
        .is_err()
    );

    let mut verifier =
        TransactionMacVerifier::new(&[0; 16], &[0x04, 0x83, 0xb4, 0xf2, 0xcf, 0x18, 0x90], 1, 64)
            .unwrap();
    verifier.add_value(0x0c, 5, 1).unwrap();
    assert!(
        verifier
            .verify(&[0x35, 0x2e, 0x57, 0xad, 0xda, 0x91, 0x1e, 0xdc])
            .unwrap()
    );
    assert!(
        !verifier
            .verify(&[0x35, 0x2e, 0x57, 0xad, 0xda, 0x91, 0x1e, 0xdd])
            .unwrap()
    );

    let mut wrong_counter =
        TransactionMacVerifier::new(&[0; 16], &[0x04, 0x83, 0xb4, 0xf2, 0xcf, 0x18, 0x90], 2, 64)
            .unwrap();
    wrong_counter.add_value(0x0c, 5, 1).unwrap();
    assert!(
        !wrong_counter
            .verify(&[0x35, 0x2e, 0x57, 0xad, 0xda, 0x91, 0x1e, 0xdc])
            .unwrap()
    );

    let mut wrong_key_bytes = [0; 16];
    wrong_key_bytes[0] = 1;
    let mut wrong_key = TransactionMacVerifier::new(
        &wrong_key_bytes,
        &[0x04, 0x83, 0xb4, 0xf2, 0xcf, 0x18, 0x90],
        1,
        64,
    )
    .unwrap();
    wrong_key.add_value(0x0c, 5, 1).unwrap();
    assert!(
        !wrong_key
            .verify(&[0x35, 0x2e, 0x57, 0xad, 0xda, 0x91, 0x1e, 0xdc])
            .unwrap()
    );

    let mut reordered =
        TransactionMacVerifier::new(&[0; 16], &[0x04, 0x83, 0xb4, 0xf2, 0xcf, 0x18, 0x90], 1, 64)
            .unwrap();
    reordered.add_value(0xdc, 5, 2).unwrap();
    reordered.add_value(0x0c, 5, 1).unwrap();
    assert!(
        !reordered
            .verify(&[0x7b, 0xee, 0x57, 0x7d, 0x5d, 0x8d, 0x0c, 0x69])
            .unwrap()
    );

    let omitted =
        TransactionMacVerifier::new(&[0; 16], &[0x04, 0x83, 0xb4, 0xf2, 0xcf, 0x18, 0x90], 1, 64)
            .unwrap();
    assert!(
        omitted
            .verify(&[0x35, 0x2e, 0x57, 0xad, 0xda, 0x91, 0x1e, 0xdc])
            .is_err()
    );
}

fn assert_sdm_config_reaches_native(config: SdmConfig, meta_key: Option<&[u8; 16]>) {
    let result = verify_sdm(&[b'0'; 128], config, &[0; 16], meta_key);
    assert_ne!(result, Err(SdmError::InvalidConfig));
}

#[test]
fn sdm_field_lengths_use_slot_specific_units() {
    let base = SdmConfig {
        mac_input_offset: 80,
        mac_offset: 96,
        plain_uid: None,
        plain_read_counter_offset: None,
        encrypted_picc_data: None,
        encrypted_file_data: None,
    };
    for length in [7, 10] {
        assert_sdm_config_reaches_native(
            SdmConfig {
                plain_uid: Some(SdmField { offset: 0, length }),
                ..base
            },
            None,
        );
    }
    assert_eq!(
        verify_sdm(
            &[b'0'; 128],
            SdmConfig {
                plain_uid: Some(SdmField {
                    offset: 0,
                    length: 14,
                }),
                ..base
            },
            &[0; 16],
            None,
        ),
        Err(SdmError::InvalidConfig)
    );
    assert_sdm_config_reaches_native(
        SdmConfig {
            plain_uid: Some(SdmField {
                offset: 108,
                length: 10,
            }),
            ..base
        },
        None,
    );
    assert_eq!(
        verify_sdm(
            &[b'0'; 128],
            SdmConfig {
                plain_uid: Some(SdmField {
                    offset: 109,
                    length: 10,
                }),
                ..base
            },
            &[0; 16],
            None,
        ),
        Err(SdmError::InvalidConfig)
    );

    for length in [32, 64] {
        assert_sdm_config_reaches_native(
            SdmConfig {
                encrypted_picc_data: Some(SdmField { offset: 0, length }),
                ..base
            },
            Some(&[0; 16]),
        );
    }
    assert_eq!(
        verify_sdm(
            &[b'0'; 128],
            SdmConfig {
                encrypted_picc_data: Some(SdmField {
                    offset: 0,
                    length: 16,
                }),
                ..base
            },
            &[0; 16],
            Some(&[0; 16]),
        ),
        Err(SdmError::InvalidConfig)
    );
    for length in [32, 64] {
        assert_sdm_config_reaches_native(
            SdmConfig {
                mac_input_offset: 0,
                mac_offset: 96,
                encrypted_file_data: Some(SdmField { offset: 0, length }),
                ..base
            },
            None,
        );
    }
    for field in [
        SdmField {
            offset: 0,
            length: 16,
        },
        SdmField {
            offset: 0,
            length: 0,
        },
    ] {
        assert_eq!(
            verify_sdm(
                &[b'0'; 128],
                SdmConfig {
                    mac_input_offset: 0,
                    mac_offset: 96,
                    encrypted_file_data: Some(field),
                    ..base
                },
                &[0; 16],
                None,
            ),
            Err(SdmError::InvalidConfig)
        );
    }
}
