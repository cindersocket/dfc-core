#include "dfc_emulator_i.h"

#if DFC_ENABLE_EMULATOR

DfcEmulator* dfc_emulator_alloc(DfcCredential* credential) {
    if(!credential) return NULL;

    DfcEmulator* emulator = dfc_platform_alloc(sizeof(DfcEmulator), DfcAllocEmulator);
    if(!emulator) return NULL;
    memset(emulator, 0, sizeof(DfcEmulator));

    emulator->credential = credential;
    emulator->tx_buffer = dfc_bytebuf_alloc(DFC_WORKER_MAX_BUFFER_SIZE);
    if(!emulator->tx_buffer) {
        dfc_platform_free(emulator);
        return NULL;
    }
    emulator->selected_application = DfcEmulatorSelectedApplicationPicc;

    return emulator;
}

void dfc_emulator_free(DfcEmulator* emulator) {
    DFC_ASSERT(emulator);

    dfc_emulator_discard_command_chain(emulator);
#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
    dfc_emulator_discard_transaction_snapshot(emulator);
#endif
    if(emulator->secure_messaging) {
        dfc_secure_messaging_free(emulator->secure_messaging);
    }

    if(emulator->tx_buffer) {
        dfc_secure_wipe(emulator->tx_buffer, sizeof(*emulator->tx_buffer));
        dfc_bytebuf_free(emulator->tx_buffer);
    }
    dfc_secure_wipe(emulator, sizeof(*emulator));
    dfc_platform_free(emulator);
}

void dfc_emulator_discard_command_chain(DfcEmulator* emulator) {
    if(emulator->command_chain) {
        dfc_secure_wipe(emulator->command_chain, emulator->command_chain_len);
        dfc_platform_free(emulator->command_chain);
    }
    emulator->command_chain = NULL;
    emulator->command_chain_active = false;
    emulator->command_chain_len = 0;
    emulator->command_chain_expected = 0;
}

#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
void dfc_emulator_discard_transaction_snapshot(DfcEmulator* emulator) {
    if(emulator->transaction_snapshot_pool) {
        dfc_secure_wipe(
            emulator->transaction_snapshot_pool, emulator->transaction_snapshot_pool_length);
        dfc_platform_free(emulator->transaction_snapshot_pool);
    }
    emulator->transaction_snapshot_pool = NULL;
    emulator->transaction_snapshot_pool_length = 0;
}
#endif

DfcApplication* dfc_emulator_current_app(DfcEmulator* emulator) {
    if(emulator->selected_application != DfcEmulatorSelectedApplicationApp) return NULL;
    return dfc_credential_get_application(emulator->credential, emulator->selected_app_index);
}

bool dfc_emulator_accepts_auth_cipher(DfcEmulator* emulator, uint8_t cipher) {
    DfcApplication* app = dfc_emulator_current_app(emulator);
    uint8_t commands = app ? dfc_credential_app_auth_commands(emulator->credential, app) :
                             dfc_credential_picc_auth_commands(emulator->credential);
    uint8_t disabled =
        emulator->credential->picc_has_sm_disable ? emulator->credential->picc_sm_disable : 0;
    if(app && app->has_sm_disable) disabled |= app->sm_disable;
    uint8_t bit;
    switch(cipher) {
    case DFC_CMD_AUTHENTICATE_LEGACY:
        bit = DFC_AUTH_COMMAND_D40;
        if(disabled & DFC_SM_DISABLE_D40) return false;
        break;
    case DFC_CMD_AUTHENTICATE_ISO:
        bit = DFC_AUTH_COMMAND_ISO_NATIVE;
        if(disabled & DFC_SM_DISABLE_EV1) return false;
        break;
    case DFC_CMD_AUTHENTICATE_AES:
        bit = DFC_AUTH_COMMAND_AES;
        if(disabled & DFC_SM_DISABLE_EV1) return false;
        break;
    case DFC_CMD_AUTHENTICATE_EV2_FIRST:
        bit = DFC_AUTH_COMMAND_EV2_FIRST;
        break;
    case DFC_CMD_AUTHENTICATE_EV2_NON_FIRST:
        bit = DFC_AUTH_COMMAND_EV2_NON_FIRST;
        break;
    default:
        return false;
    }
    return (commands & bit) != 0;
}

static void clear_native_authentication(DfcEmulator* emulator) {
    if(emulator->secure_messaging) {
        dfc_secure_wipe(emulator->secure_messaging, sizeof(*emulator->secure_messaging));
    }
    emulator->auth_cipher = 0;
    emulator->auth_key_no = 0;
    dfc_secure_wipe(emulator->rnd_a, sizeof(emulator->rnd_a));
}

#if DFC_ENABLE_EV2_SECURE_MESSAGING
static void clear_ev2_authentication(DfcEmulator* emulator, bool keep_transaction_context) {
    emulator->ev2_session_active = false;
    emulator->ev2_authenticated_key_no = 0;
    emulator->ev2_command_counter = 0;
    dfc_secure_wipe(
        emulator->ev2_session_encryption_key, sizeof(emulator->ev2_session_encryption_key));
    dfc_secure_wipe(emulator->ev2_session_mac_key, sizeof(emulator->ev2_session_mac_key));
    if(!keep_transaction_context) {
        dfc_secure_wipe(
            emulator->ev2_transaction_identifier, sizeof(emulator->ev2_transaction_identifier));
        dfc_secure_wipe(emulator->ev2_card_capabilities, sizeof(emulator->ev2_card_capabilities));
        dfc_secure_wipe(
            emulator->ev2_reader_capabilities, sizeof(emulator->ev2_reader_capabilities));
    }
}
#endif

void dfc_emulator_clear_active_authentication(DfcEmulator* emulator) {
    clear_native_authentication(emulator);
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    clear_ev2_authentication(emulator, false);
#endif
}

#if DFC_ENABLE_EV2_SECURE_MESSAGING
void dfc_emulator_retire_ev2_non_first_authentication(DfcEmulator* emulator) {
    clear_native_authentication(emulator);
    clear_ev2_authentication(emulator, true);
}
#endif

void dfc_emulator_commit_auth_family(DfcEmulator* emulator, DfcEmulatorAuthFamily family) {
    if(family == DfcEmulatorAuthFamilyEv2) {
        clear_native_authentication(emulator);
        return;
    }

#if DFC_ENABLE_EV2_SECURE_MESSAGING
    clear_ev2_authentication(emulator, false);
#else
    DFC_UNUSED(emulator);
#endif
}

size_t dfc_emulator_key_len(DfcEmulator* emulator) {
    DfcApplication* app = dfc_emulator_current_app(emulator);
#if DFC_ENABLE_KEY_SETS
    if(app && app->num_key_sets >= DFC_KEY_SET_MINIMUM_COUNT) {
        return dfc_key_set_type_length(app->key_set_types[0]);
    }
#endif
    return app ? app->key_len : emulator->credential->picc_key_len;
}

size_t dfc_emulator_num_keys(DfcEmulator* emulator) {
    DfcApplication* app = dfc_emulator_current_app(emulator);
    // Every object has a master key whether or not the credential records one:
    // an absent entry is the factory default, not an absent slot.
    if(!app) return 1;
    return app->num_keys ? app->num_keys : 1;
}

uint8_t* dfc_emulator_key(DfcEmulator* emulator, uint8_t key_no) {
    DfcApplication* app = dfc_emulator_current_app(emulator);
    // dfc_emulator_num_keys reports 1 at PICC level, so only slot 0 is reachable.
    return dfc_credential_key(emulator->credential, app, app ? key_no : 0);
}

uint8_t* dfc_emulator_key_version(DfcEmulator* emulator, uint8_t key_no) {
    DfcApplication* app = dfc_emulator_current_app(emulator);
    return app ? &app->key_versions[key_no] : &emulator->credential->picc_key_versions[0];
}

static void dfc_emulator_clear_pending_value_transactions(DfcEmulator* emulator) {
    for(size_t i = 0; i < emulator->credential->num_files; i++) {
        DfcFile* file = &emulator->credential->files[i];
        if(file->type != DFC_FILE_TYPE_VALUE) continue;
        file->value_pending = false;
        file->value_pending_delta = 0;
    }
}

void dfc_emulator_clear_iso_authentication(DfcEmulator* emulator) {
#if DFC_ENABLE_ISO7816_AUTH
    emulator->iso_auth_phase = 0;
    emulator->iso_auth_challenge_len = 0;
    emulator->iso_auth_key_no = 0;
    emulator->iso_auth_cipher = 0;
    emulator->iso_auth_reference = 0;
    emulator->iso_auth_key_len = 0;
    dfc_secure_wipe(emulator->iso_auth_card_first, sizeof(emulator->iso_auth_card_first));
    dfc_secure_wipe(emulator->iso_auth_host_first, sizeof(emulator->iso_auth_host_first));
    dfc_secure_wipe(emulator->iso_auth_external_iv, sizeof(emulator->iso_auth_external_iv));
    dfc_secure_wipe(emulator->iso_auth_key, sizeof(emulator->iso_auth_key));
#else
    (void)emulator;
#endif
}

void dfc_emulator_reset_session(DfcEmulator* emulator) {
    emulator->awaiting_step2 = false;
    dfc_emulator_clear_iso_authentication(emulator);
    clear_native_authentication(emulator);
    emulator->pending_auth_cipher = 0;
    emulator->pending_auth_key_no = 0;
    dfc_secure_wipe(emulator->rnd_b, sizeof(emulator->rnd_b));
    dfc_secure_wipe(emulator->enc_rnd_b, sizeof(emulator->enc_rnd_b));
    emulator->get_version_frame = 0;
    emulator->pending_chain_len = 0;
    emulator->pending_chain_offset = 0;
    emulator->pending_chain_frame = 0;
    emulator->pending_chain_last = 0;
    emulator->pending_chain_chunk_count = 0;
    emulator->pending_chain_chunk_index = 0;
    dfc_secure_wipe(emulator->pending_chain, sizeof(emulator->pending_chain));
    dfc_secure_wipe(emulator->pending_chain_chunks, sizeof(emulator->pending_chain_chunks));
    dfc_emulator_discard_command_chain(emulator);
    emulator->df_names_pending = false;
    emulator->df_names_next = 0;
#if DFC_ENABLE_DELEGATED_APPLICATIONS
    emulator->delegated_creation_pending = false;
    emulator->delegated_creation_header_length = 0;
    dfc_secure_wipe(
        emulator->delegated_creation_header, sizeof(emulator->delegated_creation_header));
#endif
#if DFC_ENABLE_PROXIMITY_CHECK
    emulator->proximity_active = false;
    emulator->proximity_verified = false;
    emulator->proximity_offset = 0;
    emulator->proximity_published_len = 0;
    emulator->proximity_transcript_len = 0;
    dfc_secure_wipe(emulator->proximity_random, sizeof(emulator->proximity_random));
    dfc_secure_wipe(emulator->proximity_published, sizeof(emulator->proximity_published));
    dfc_secure_wipe(emulator->proximity_transcript, sizeof(emulator->proximity_transcript));
#endif
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    emulator->ev2_authentication_pending = false;
    emulator->ev2_authentication_non_first = false;
    emulator->ev2_session_active = false;
    emulator->ev2_authenticated_key_no = 0;
    emulator->ev2_pending_authenticated_key_no = 0;
    emulator->ev2_command_counter = 0;
    dfc_secure_wipe(emulator->ev2_static_key, sizeof(emulator->ev2_static_key));
    dfc_secure_wipe(emulator->ev2_random_b, sizeof(emulator->ev2_random_b));
    dfc_secure_wipe(
        emulator->ev2_transaction_identifier, sizeof(emulator->ev2_transaction_identifier));
    dfc_secure_wipe(
        emulator->ev2_pending_transaction_identifier,
        sizeof(emulator->ev2_pending_transaction_identifier));
    dfc_secure_wipe(emulator->ev2_card_capabilities, sizeof(emulator->ev2_card_capabilities));
    dfc_secure_wipe(emulator->ev2_reader_capabilities, sizeof(emulator->ev2_reader_capabilities));
    dfc_secure_wipe(
        emulator->ev2_pending_card_capabilities,
        sizeof(emulator->ev2_pending_card_capabilities));
    dfc_secure_wipe(
        emulator->ev2_pending_reader_capabilities,
        sizeof(emulator->ev2_pending_reader_capabilities));
    dfc_secure_wipe(
        emulator->ev2_session_encryption_key, sizeof(emulator->ev2_session_encryption_key));
    dfc_secure_wipe(emulator->ev2_session_mac_key, sizeof(emulator->ev2_session_mac_key));
#endif
#if DFC_ENABLE_SDM
    emulator->sdm_read_cache_valid = false;
    emulator->sdm_read_cache_file_number = 0;
    emulator->sdm_read_cache_len = 0;
    dfc_secure_wipe(emulator->sdm_read_cache, sizeof(emulator->sdm_read_cache));
#endif
#if DFC_ENABLE_TRANSACTION_MAC
    emulator->transaction_input_len = 0;
    dfc_secure_wipe(emulator->transaction_input, sizeof(emulator->transaction_input));
#endif
    dfc_emulator_clear_pending_value_transactions(emulator);
    dfc_secure_wipe(emulator->rnd_b, sizeof(emulator->rnd_b));
    dfc_secure_wipe(emulator->enc_rnd_b, sizeof(emulator->enc_rnd_b));
}

void dfc_emulator_reset_activation(DfcEmulator* emulator) {
    DFC_ASSERT(emulator);

    DfcCredential* credential = emulator->credential;
    DfcByteBuf* tx_buffer = emulator->tx_buffer;
    DfcSecureMessaging* secure_messaging = emulator->secure_messaging;
    if(secure_messaging) dfc_secure_wipe(secure_messaging, sizeof(*secure_messaging));
    dfc_emulator_discard_command_chain(emulator);
#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
    dfc_emulator_discard_transaction_snapshot(emulator);
#endif

    if(tx_buffer) dfc_secure_wipe(tx_buffer, sizeof(*tx_buffer));
    memset(emulator, 0, sizeof(*emulator));
    emulator->credential = credential;
    emulator->tx_buffer = tx_buffer;
    emulator->secure_messaging = secure_messaging;
    emulator->selected_application = DfcEmulatorSelectedApplicationPicc;
    if(tx_buffer) {
        dfc_bytebuf_reset(tx_buffer);
    }
}

void dfc_emulator_advance_time(DfcEmulator* emulator, uint32_t elapsed_milliseconds) {
#if DFC_ENABLE_TRANSACTION_TIMER
    if(!emulator || !emulator->transaction_timer_enabled) return;
    if(UINT32_MAX - emulator->transaction_timer_elapsed_milliseconds < elapsed_milliseconds)
        emulator->transaction_timer_elapsed_milliseconds = UINT32_MAX;
    else
        emulator->transaction_timer_elapsed_milliseconds += elapsed_milliseconds;
    if(emulator->transaction_timer_elapsed_milliseconds >=
       DFC_TRANSACTION_TIMER_EXPIRY_MILLISECONDS) {
        dfc_emulator_reset_session(emulator);
        emulator->selected_application = DfcEmulatorSelectedApplicationPicc;
        emulator->selected_app_index = 0;
        emulator->transaction_timer_enabled = false;
    }
#else
    DFC_UNUSED(emulator);
    DFC_UNUSED(elapsed_milliseconds);
#endif
}

#endif // DFC_ENABLE_EMULATOR
