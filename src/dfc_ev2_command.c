#include "dfc_ev2_command.h"

DfcEv2CommandMetadata dfc_ev2_command_metadata(uint8_t command) {
    DfcEv2CommandMetadata metadata = {.encrypted_header_length = DfcEv2NoEncryptedHeader};
    uint8_t base = dfc_file_command_base(command);

    switch(base) {
    case DFC_CMD_READ_DATA:
    case DFC_CMD_READ_RECORDS:
    case DFC_CMD_GET_VALUE:
        metadata.flags = DfcEv2CommandFile | DfcEv2CommandFileRead | DfcEv2CommandTargetsFile |
                         DfcEv2CommandSupportsEffectivePlain;
        break;
    case DFC_CMD_WRITE_DATA:
    case DFC_CMD_WRITE_RECORD:
        metadata.flags = DfcEv2CommandFile | DfcEv2CommandTargetsFile |
                         DfcEv2CommandSupportsEffectivePlain;
        metadata.encrypted_header_length = DfcEv2FileHeaderLength;
        break;
    case DFC_CMD_UPDATE_RECORD:
        metadata.flags = DfcEv2CommandFile | DfcEv2CommandTargetsFile |
                         DfcEv2CommandSupportsEffectivePlain;
        metadata.encrypted_header_length = DfcEv2UpdateRecordHeaderLength;
        break;
    case DFC_CMD_CREDIT:
    case DFC_CMD_DEBIT:
    case DFC_CMD_LIMITED_CREDIT:
        metadata.flags = DfcEv2CommandFile | DfcEv2CommandTargetsFile |
                         DfcEv2CommandSupportsEffectivePlain;
        metadata.encrypted_header_length = DfcEv2ValueHeaderLength;
        break;
    case DFC_CMD_GET_FILE_COUNTERS:
        metadata.flags = DfcEv2CommandTargetsFile;
        break;
    case DFC_CMD_CHANGE_FILE_SETTINGS:
        metadata.flags = DfcEv2CommandTargetsFile | DfcEv2CommandSupportsEffectivePlain;
        metadata.encrypted_header_length = DfcEv2ChangeFileSettingsHeaderLength;
        break;
    default:
        break;
    }

    switch(command) {
    case DFC_CMD_SET_CONFIGURATION:
        metadata.encrypted_header_length = DfcEv2SetConfigurationHeaderLength;
        break;
    case DFC_CMD_CREATE_TRANSACTION_MAC_FILE:
        metadata.encrypted_header_length = DfcEv2CreateTransactionMacHeaderLength;
        break;
    case DFC_CMD_CHANGE_KEY_EV2:
        metadata.encrypted_header_length = DfcEv2ChangeKeyHeaderLength;
        break;
    case DFC_CMD_CHANGE_KEY_SETTINGS:
        metadata.encrypted_header_length = 0;
        break;
    case DFC_CMD_ADDITIONAL_FRAME:
        metadata.flags |= DfcEv2CommandReaderBypass | DfcEv2CommandEmulatorBypass;
        break;
    case DFC_CMD_AUTHENTICATE_EV2_FIRST:
    case DFC_CMD_AUTHENTICATE_EV2_NON_FIRST:
        metadata.flags |= DfcEv2CommandReaderBypass | DfcEv2CommandEmulatorBypass;
        break;
    case DFC_CMD_AUTHENTICATE_LEGACY:
    case DFC_CMD_AUTHENTICATE_ISO:
    case DFC_CMD_AUTHENTICATE_AES:
        metadata.flags |= DfcEv2CommandEmulatorBypass;
        break;
    case DFC_CMD_SELECT_APPLICATION:
        // SelectApplication is always sent in CommMode.Plain and terminates any
        // active authentication; the emulator must not try to verify an EV2
        // command MAC on it. The handler resets the session.
        metadata.flags |= DfcEv2CommandReaderBypass | DfcEv2CommandEmulatorBypass;
        break;
    case DFC_CMD_CREATE_DELEGATED_APPLICATION:
        metadata.flags |= DfcEv2CommandReaderBypass;
#if DFC_ENABLE_DELEGATED_APPLICATIONS
        metadata.flags |= DfcEv2CommandEmulatorBypass;
#endif
        break;
#if DFC_ENABLE_PROXIMITY_CHECK
    case DFC_CMD_PREPARE_PROXIMITY_CHECK:
    case DFC_CMD_PROXIMITY_CHECK:
    case DFC_CMD_VERIFY_PROXIMITY_CHECK:
        // The Proximity Check (anti-relay) runs in CommMode.Plain even inside an
        // active EV2 session: it carries its own proximity-key MAC (verified in
        // VerifyPC), not a session CMAC. Without this bypass the EV2 layer tries
        // to verify a session MAC the reader never appends and rejects PreparePC
        // with INTEGRITY_ERROR (0x1E).
        metadata.flags |= DfcEv2CommandReaderBypass | DfcEv2CommandEmulatorBypass;
        break;
#endif
    default:
        break;
    }

    return metadata;
}
