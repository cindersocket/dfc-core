#include "dfc_ffi_internal.h"

#include <stdlib.h>
#include <string.h>

#include "dfc_der.h"

static DfcFfiCredential* credential_alloc(void) {
    DfcFfiCredential* credential = dfc_ffi_credential_alloc_uninitialized();
    if(credential) dfc_credential_clear(&credential->model);
    return credential;
}

// ------------------------------------------------------ model: reading ---

int32_t dfc_ffi_credential_get_card(const DfcFfiCredential* credential, DfcFfiCard* out) {
    if(!credential || !out) return DFC_FFI_INVALID_ARGUMENT;
    const DfcCredential* c = &credential->model;
    memset(out, 0, sizeof(*out));
    out->generation = (uint32_t)c->card.generation;
    out->storage = c->card.storage;
    out->uid_provenance = (uint32_t)c->card.uid_provenance;
    out->uid_len = (uint32_t)c->uid_len;
    memcpy(out->uid, c->uid, c->uid_len);
    out->has_hardware_version = c->card.has_hardware_version;
    memcpy(out->hardware_version, c->card.hardware_version, sizeof(out->hardware_version));
    out->has_software_version = c->card.has_software_version;
    memcpy(out->software_version, c->card.software_version, sizeof(out->software_version));
#if DFC_ENABLE_STATIC_SIGNATURE
    out->has_static_signature = c->picc_has_static_signature;
    memcpy(out->static_signature, c->picc_static_signature, sizeof(out->static_signature));
#endif
    return DfcDerOk;
}

int32_t dfc_ffi_credential_get_picc(const DfcFfiCredential* credential, DfcFfiPiccSettings* out) {
    if(!credential || !out) return DFC_FFI_INVALID_ARGUMENT;
    const DfcCredential* c = &credential->model;
    memset(out, 0, sizeof(*out));
    out->num_keys = (uint32_t)c->picc_num_keys;
    out->key_len = (uint32_t)c->picc_key_len;
    out->key_settings_1 = c->picc_key_settings_1;
    out->key_settings_2 = c->picc_key_settings_2;
    out->auth_command = c->picc_auth_command;
    out->has_auth_commands = c->picc_has_auth_commands;
    out->auth_commands = c->picc_auth_commands;
    out->has_preferred_auth_command = c->picc_has_preferred_auth_command;
    out->preferred_auth_command = c->picc_preferred_auth_command;
    out->random_id = c->picc_random_id;
    out->random_id_legacy = c->picc_random_id_legacy;
    out->format_disabled = c->picc_format_disabled;
    out->ats_len = (uint8_t)c->picc_ats_len;
    memcpy(out->ats, c->picc_ats, c->picc_ats_len);
    out->has_sak = c->picc_has_sak;
    out->sak = c->picc_sak;
    out->has_atqa = c->picc_has_atqa;
    memcpy(out->atqa, c->picc_atqa, sizeof(out->atqa));
    out->has_sm_disable = c->picc_has_sm_disable;
    out->sm_disable = c->picc_sm_disable;
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    out->has_ev2_capabilities = c->picc_has_ev2_capabilities;
    memcpy(out->ev2_capabilities, c->picc_ev2_capabilities, sizeof(out->ev2_capabilities));
#endif
#if DFC_ENABLE_PROXIMITY_CHECK
    out->has_proximity_key = c->picc_has_proximity_key;
    memcpy(out->proximity_key, c->picc_proximity_key, sizeof(out->proximity_key));
    out->proximity_option = c->picc_proximity_option;
    out->proximity_published_response_time = c->picc_proximity_published_response_time;
    out->has_proximity_bitrate = c->picc_has_proximity_bitrate;
    out->proximity_bitrate = c->picc_proximity_bitrate;
#endif
#if DFC_ENABLE_VIRTUAL_CARD
    out->virtual_card_configured = c->virtual_card_configured;
    out->virtual_card_installation_id_len = (uint8_t)c->virtual_card_installation_id_len;
    memcpy(
        out->virtual_card_installation_id,
        c->virtual_card_installation_id,
        sizeof(out->virtual_card_installation_id));
    out->virtual_card_information = c->virtual_card_information;
    memcpy(
        out->virtual_card_capabilities,
        c->virtual_card_capabilities,
        sizeof(out->virtual_card_capabilities));
    out->virtual_card_uid_len = (uint8_t)c->virtual_card_uid_len;
    memcpy(out->virtual_card_uid, c->virtual_card_uid, sizeof(out->virtual_card_uid));
    memcpy(
        out->virtual_card_select_mac_key,
        c->virtual_card_select_mac_key,
        sizeof(out->virtual_card_select_mac_key));
    memcpy(
        out->virtual_card_select_encryption_key,
        c->virtual_card_select_encryption_key,
        sizeof(out->virtual_card_select_encryption_key));
    out->virtual_card_authentication_mandatory = c->virtual_card_authentication_mandatory;
    out->virtual_card_proximity_mandatory = c->virtual_card_proximity_mandatory;
#endif
#if DFC_ENABLE_DELEGATED_APPLICATIONS
    out->has_dam_keys = c->picc_has_dam_keys;
    memcpy(out->dam_auth_key, c->picc_dam_auth_key, sizeof(out->dam_auth_key));
    memcpy(out->dam_mac_key, c->picc_dam_mac_key, sizeof(out->dam_mac_key));
    memcpy(out->dam_encryption_key, c->picc_dam_encryption_key, sizeof(out->dam_encryption_key));
#endif
    return DfcDerOk;
}

uint32_t dfc_ffi_credential_application_count(const DfcFfiCredential* credential) {
    return credential ? (uint32_t)credential->model.num_apps : 0;
}

int32_t dfc_ffi_credential_get_application(
    const DfcFfiCredential* credential,
    uint32_t index,
    DfcFfiApplication* out) {
    if(!credential || !out || index >= credential->model.num_apps) return DFC_FFI_INVALID_ARGUMENT;
    const DfcApplication* a = &credential->model.apps[index];
    memset(out, 0, sizeof(*out));
    memcpy(out->aid, a->aid, sizeof(out->aid));
    out->has_iso_file_id = a->has_iso_file_id;
    out->iso_file_id = a->iso_file_id;
    out->df_name_len = (uint32_t)a->iso_aid_len;
    memcpy(out->df_name, a->iso_aid, a->iso_aid_len);
    out->key_settings_1 = a->key_settings_1;
    out->key_settings_2 = a->key_settings_2;
    out->auth_command = a->auth_command;
    out->has_auth_commands = a->has_auth_commands;
    out->auth_commands = a->auth_commands;
    out->has_preferred_auth_command = a->has_preferred_auth_command;
    out->preferred_auth_command = a->preferred_auth_command;
    out->has_sm_disable = a->has_sm_disable;
    out->sm_disable = a->sm_disable;
    out->num_keys = (uint32_t)a->num_keys;
    out->key_len = (uint32_t)a->key_len;
#if DFC_ENABLE_KEY_SETS
    if(a->num_key_sets >= DFC_KEY_SET_MINIMUM_COUNT) {
        out->num_key_sets = a->num_key_sets;
        out->key_set_max_size = a->max_key_size;
        out->key_set_settings = a->key_set_settings;
        for(size_t i = 0; i < a->num_key_sets; i++) {
            const uint8_t* version =
                dfc_credential_key_set_version_const(&credential->model, a, i);
            const uint8_t* type = dfc_credential_key_set_type_const(&credential->model, a, i);
            if(!version || !type) return DFC_FFI_INVALID_ARGUMENT;
            out->key_set_versions[i] = *version;
            out->key_set_types[i] = *type;
            out->key_set_initialized[i] =
                dfc_credential_key_set_is_initialized(&credential->model, a, i);
        }
    }
#endif
#if DFC_ENABLE_APPLICATION_CAPABILITY_DATA
    out->has_capability_data = a->has_capability_data;
    memcpy(out->capability_data, a->capability_data, sizeof(out->capability_data));
#endif
#if DFC_ENABLE_DELEGATED_APPLICATIONS
    out->delegated = a->delegated;
    out->delegated_slot_number = a->delegated_slot_number;
    out->delegated_slot_version = a->delegated_slot_version;
    out->delegated_quota_limit = a->delegated_quota_limit;
    out->delegated_free_blocks = a->delegated_free_blocks;
    out->delegated_format_disabled = a->delegated_format_disabled;
#endif
    return DfcDerOk;
}

uint32_t dfc_ffi_credential_file_count(const DfcFfiCredential* credential) {
    return credential ? (uint32_t)credential->model.num_files : 0;
}

int32_t dfc_ffi_credential_get_file(
    const DfcFfiCredential* credential,
    uint32_t index,
    DfcFfiFile* out) {
    if(!credential || !out || index >= credential->model.num_files)
        return DFC_FFI_INVALID_ARGUMENT;
    const DfcFile* f = &credential->model.files[index];
    memset(out, 0, sizeof(*out));
    out->owner = f->app_index == DFC_FILE_OWNER_PICC ? DFC_FFI_OWNER_PICC : (int32_t)f->app_index;
    out->number = f->number;
    out->type = f->type;
    out->comm_settings = f->comm_settings;
    out->access_rights = f->access_rights;
    out->has_iso_file_id = f->has_iso_file_id;
    out->iso_file_id = f->iso_file_id;
    if(f->type == DFC_FILE_TYPE_STANDARD_DATA || f->type == DFC_FILE_TYPE_BACKUP_DATA) {
        if(!dfc_file_get_declared_size(f, &out->declared_size)) return DfcDerMalformed;
    } else if(f->type == DFC_FILE_TYPE_TRANSACTION_MAC) {
        out->declared_size = (uint32_t)f->data_len;
    }
    out->data_len = (uint32_t)f->data_len;
    out->contents_complete = f->contents_complete;
    out->transaction_pending = f->transaction_pending;
    if(f->type == DFC_FILE_TYPE_VALUE) {
        out->value_lower_limit = f->state.value.lower_limit;
        out->value_upper_limit = f->state.value.upper_limit;
        out->value = f->state.value.current;
        out->limited_credit_value = f->state.value.limited_credit_value;
        out->limited_credit = f->state.value.limited_credit;
        out->value_pending = f->state.value.pending;
        out->value_pending_delta = f->state.value.pending_delta;
    } else if(f->type == DFC_FILE_TYPE_LINEAR_RECORD || f->type == DFC_FILE_TYPE_CYCLIC_RECORD) {
        out->record_size = f->state.record.size;
        out->max_records = f->state.record.max_records;
        out->record_count = f->state.record.count;
    }
#if DFC_ENABLE_SDM
    if(f->type == DFC_FILE_TYPE_STANDARD_DATA) {
        out->sdm_enabled = dfc_file_sdm_flag_is_set(f, DfcSdmFlagEnabled);
        out->sdm_options = f->state.data.sdm.options;
        out->sdm_access_rights = f->state.data.sdm.access_rights;
        out->sdm_has_uid_offset = dfc_file_sdm_flag_is_set(f, DfcSdmFlagUidOffset);
        out->sdm_uid_offset = f->state.data.sdm.uid_offset;
        out->sdm_has_counter_offset = dfc_file_sdm_flag_is_set(f, DfcSdmFlagCounterOffset);
        out->sdm_counter_offset = f->state.data.sdm.counter_offset;
        out->sdm_has_picc_data_offset = dfc_file_sdm_flag_is_set(f, DfcSdmFlagPiccDataOffset);
        out->sdm_picc_data_offset = f->state.data.sdm.picc_data_offset;
        out->sdm_has_mac_input_offset = dfc_file_sdm_flag_is_set(f, DfcSdmFlagMacInputOffset);
        out->sdm_mac_input_offset = f->state.data.sdm.mac_input_offset;
        out->sdm_has_mac_offset = dfc_file_sdm_flag_is_set(f, DfcSdmFlagMacOffset);
        out->sdm_mac_offset = f->state.data.sdm.mac_offset;
        out->sdm_has_encrypted_file_offset = dfc_file_sdm_flag_is_set(f, DfcSdmFlagEncryptedFile);
        out->sdm_encrypted_file_offset = f->state.data.sdm.encrypted_file_offset;
        out->sdm_encrypted_file_length = f->state.data.sdm.encrypted_file_length;
        out->sdm_has_counter_limit = dfc_file_sdm_flag_is_set(f, DfcSdmFlagCounterLimit);
        out->sdm_counter_limit = f->state.data.sdm.counter_limit;
        out->sdm_read_counter = f->state.data.sdm_read_counter;
    }
#endif
#if DFC_ENABLE_TRANSACTION_MAC
    if(f->type == DFC_FILE_TYPE_TRANSACTION_MAC) {
        memcpy(
            out->transaction_mac_key,
            f->state.transaction_mac.key,
            sizeof(out->transaction_mac_key));
        out->transaction_mac_key_type = f->state.transaction_mac.key_type;
        out->transaction_mac_key_version = f->state.transaction_mac.key_version;
        out->transaction_counter = f->state.transaction_mac.counter;
        memcpy(out->transaction_mac, f->state.transaction_mac.mac, sizeof(out->transaction_mac));
        memcpy(
            out->previous_reader_id,
            f->state.transaction_mac.previous_reader_id,
            sizeof(out->previous_reader_id));
    }
#endif
    return DfcDerOk;
}

int32_t dfc_ffi_credential_get_file_data(
    const DfcFfiCredential* credential,
    uint32_t index,
    uint8_t* out,
    size_t cap,
    size_t* len) {
    if(!credential || !len || (!out && cap) || index >= credential->model.num_files) {
        return DFC_FFI_INVALID_ARGUMENT;
    }
    const DfcFile* f = &credential->model.files[index];
    *len = f->data_len;
    if(!out) return DfcDerOk;
    if(f->data_len > cap) return DFC_FFI_BUFFER_TOO_SMALL;
    const uint8_t* data = dfc_file_data_const(&credential->model, f);
    if(f->data_len && data) memcpy(out, data, f->data_len);
    return DfcDerOk;
}

// The owner's application, or NULL for the PICC. False for a bad index.
static bool owner_application(const DfcCredential* c, int32_t owner, const DfcApplication** app) {
    if(owner == DFC_FFI_OWNER_PICC) {
        *app = NULL;
        return true;
    }
    if(owner < 0 || (size_t)owner >= c->num_apps) return false;
    *app = &c->apps[owner];
    return true;
}

int32_t dfc_ffi_credential_get_key(
    const DfcFfiCredential* credential,
    int32_t owner,
    uint32_t key_set,
    uint32_t slot,
    DfcFfiKey* out) {
    if(!credential || !out) return DFC_FFI_INVALID_ARGUMENT;
    const DfcCredential* c = &credential->model;
    const DfcApplication* app;
    if(!owner_application(c, owner, &app)) return DFC_FFI_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if(key_set == 0) {
        size_t num_keys = app ? app->num_keys : c->picc_num_keys;
        size_t key_len = app ? app->key_len : c->picc_key_len;
#if DFC_ENABLE_KEY_SETS
        if(app && app->num_key_sets >= DFC_KEY_SET_MINIMUM_COUNT) {
            const uint8_t* active_type = dfc_credential_key_set_type_const(c, app, 0);
            if(!active_type) return DFC_FFI_INVALID_ARGUMENT;
            size_t active_len = dfc_key_set_type_length(*active_type);
            if(active_len == 0 || active_len > app->key_storage_len || active_len != key_len) {
                return DFC_FFI_INVALID_ARGUMENT;
            }
        }
#endif
        if(slot >= num_keys) return DFC_FFI_INVALID_ARGUMENT;
        const uint8_t* key = dfc_credential_key_const(c, app, slot);
        out->len = (uint32_t)key_len;
        if(key) memcpy(out->value, key, key_len);
        out->version = app ? app->key_versions[slot] : c->picc_key_versions[slot];
        return DfcDerOk;
    }
#if DFC_ENABLE_KEY_SETS
    if(!app || key_set >= app->num_key_sets || slot >= app->num_keys) {
        return DFC_FFI_INVALID_ARGUMENT;
    }
    const uint8_t* key = dfc_credential_key_in_set_const(c, app, key_set, slot);
    const uint8_t* version = dfc_credential_key_version_in_set_const(c, app, key_set, slot);
    const uint8_t* type = dfc_credential_key_set_type_const(c, app, key_set);
    if(!type) return DFC_FFI_INVALID_ARGUMENT;
    size_t key_len = dfc_key_set_type_length(*type);
    if(key_len == 0) return DFC_FFI_INVALID_ARGUMENT;
    out->len = (uint32_t)key_len;
    if(key) memcpy(out->value, key, key_len);
    if(version) out->version = *version;
    return DfcDerOk;
#else
    return DFC_FFI_UNSUPPORTED;
#endif
}

// ----------------------------------------------------- model: building ---

int32_t dfc_ffi_credential_new(DfcFfiCredential** out) {
    if(!out) return DFC_FFI_INVALID_ARGUMENT;
    *out = credential_alloc();
    if(!*out) return DFC_FFI_OUT_OF_MEMORY;
    // Start from nothing rather than the seeded master key, so the builder's
    // model is exactly what the caller sets.
    dfc_credential_keys_release(&(*out)->model, NULL);
    return DfcDerOk;
}

int32_t dfc_ffi_credential_set_card(DfcFfiCredential* credential, const DfcFfiCard* card) {
    if(!credential || !card || !dfc_uid_length_is_valid(card->uid_len)) {
        return DFC_FFI_INVALID_ARGUMENT;
    }
#if !DFC_ENABLE_STATIC_SIGNATURE
    if(card->has_static_signature) return DfcDerUnsupported;
#endif
    DfcCredential* c = &credential->model;
    c->card.generation = (DfcGeneration)card->generation;
    c->card.storage = card->storage;
    c->card.uid_provenance = (DfcUidProvenance)card->uid_provenance;
    memcpy(c->uid, card->uid, card->uid_len);
    c->uid_len = (uint8_t)card->uid_len;
    c->card.has_hardware_version = card->has_hardware_version != 0;
    memcpy(c->card.hardware_version, card->hardware_version, sizeof(c->card.hardware_version));
    c->card.has_software_version = card->has_software_version != 0;
    memcpy(c->card.software_version, card->software_version, sizeof(c->card.software_version));
#if DFC_ENABLE_STATIC_SIGNATURE
    c->picc_has_static_signature = card->has_static_signature != 0;
    if(card->has_static_signature) {
        memcpy(c->picc_static_signature, card->static_signature, sizeof(c->picc_static_signature));
    } else {
        memset(c->picc_static_signature, 0, sizeof(c->picc_static_signature));
    }
#endif
    return DfcDerOk;
}

int32_t dfc_ffi_credential_set_picc(DfcFfiCredential* credential, const DfcFfiPiccSettings* p) {
    if(!credential || !p || p->ats_len > DFC_PICC_ATS_MAX || p->num_keys > DFC_MAX_KEYS ||
       p->key_len > DFC_MAX_KEY_LEN || (p->random_id_legacy && !p->random_id)) {
        return DFC_FFI_INVALID_ARGUMENT;
    }
#if !DFC_ENABLE_EV2_SECURE_MESSAGING
    if(p->has_ev2_capabilities) return DfcDerUnsupported;
#endif
#if !DFC_ENABLE_PROXIMITY_CHECK
    if(p->has_proximity_key) return DfcDerUnsupported;
#endif
#if DFC_ENABLE_VIRTUAL_CARD
    if(p->virtual_card_configured &&
       (p->virtual_card_installation_id_len > DFC_VIRTUAL_CARD_MAX_INSTALLATION_ID_LENGTH ||
        !dfc_uid_length_is_valid(p->virtual_card_uid_len))) {
        return DFC_FFI_INVALID_ARGUMENT;
    }
#else
    if(p->virtual_card_configured) return DfcDerUnsupported;
#endif
#if !DFC_ENABLE_DELEGATED_APPLICATIONS
    if(p->has_dam_keys) return DfcDerUnsupported;
#endif
    DfcCredential* c = &credential->model;
    if(p->num_keys == 0) {
        dfc_credential_keys_release(c, NULL);
    } else if(!dfc_credential_keys_resize(c, NULL, p->num_keys, p->key_len)) {
        return DfcDerCapacity;
    }
    c->picc_key_settings_1 = p->key_settings_1;
    c->picc_key_settings_2 = p->key_settings_2;
    c->picc_auth_command = p->auth_command;
    c->picc_has_auth_commands = p->has_auth_commands != 0;
    c->picc_auth_commands = p->auth_commands;
    c->picc_has_preferred_auth_command = p->has_preferred_auth_command != 0;
    c->picc_preferred_auth_command = p->preferred_auth_command;
    c->picc_random_id = p->random_id != 0;
    c->picc_random_id_legacy = p->random_id_legacy != 0;
    c->picc_format_disabled = p->format_disabled != 0;
    c->picc_ats_len = (uint8_t)p->ats_len;
    memcpy(c->picc_ats, p->ats, p->ats_len);
    c->picc_has_sak = p->has_sak != 0;
    c->picc_sak = p->sak;
    c->picc_has_atqa = p->has_atqa != 0;
    memcpy(c->picc_atqa, p->atqa, sizeof(c->picc_atqa));
    c->picc_has_sm_disable = p->has_sm_disable != 0;
    c->picc_sm_disable = p->sm_disable;
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    c->picc_has_ev2_capabilities = p->has_ev2_capabilities != 0;
    if(p->has_ev2_capabilities) {
        memcpy(c->picc_ev2_capabilities, p->ev2_capabilities, sizeof(c->picc_ev2_capabilities));
    } else {
        memset(c->picc_ev2_capabilities, 0, sizeof(c->picc_ev2_capabilities));
    }
#endif
#if DFC_ENABLE_PROXIMITY_CHECK
    c->picc_has_proximity_key = p->has_proximity_key != 0;
    if(p->has_proximity_key) {
        memcpy(c->picc_proximity_key, p->proximity_key, sizeof(c->picc_proximity_key));
        c->picc_proximity_option = p->proximity_option;
        c->picc_proximity_published_response_time = p->proximity_published_response_time;
        c->picc_has_proximity_bitrate = p->has_proximity_bitrate != 0;
        c->picc_proximity_bitrate = p->proximity_bitrate;
    } else {
        memset(c->picc_proximity_key, 0, sizeof(c->picc_proximity_key));
        c->picc_proximity_option = 0;
        c->picc_proximity_published_response_time = 0;
        c->picc_has_proximity_bitrate = false;
        c->picc_proximity_bitrate = 0;
    }
#endif
#if DFC_ENABLE_VIRTUAL_CARD
    c->virtual_card_configured = p->virtual_card_configured != 0;
    if(p->virtual_card_configured) {
        c->virtual_card_installation_id_len = (uint8_t)p->virtual_card_installation_id_len;
        memcpy(
            c->virtual_card_installation_id,
            p->virtual_card_installation_id,
            sizeof(c->virtual_card_installation_id));
        c->virtual_card_information = p->virtual_card_information;
        memcpy(
            c->virtual_card_capabilities,
            p->virtual_card_capabilities,
            sizeof(c->virtual_card_capabilities));
        c->virtual_card_uid_len = (uint8_t)p->virtual_card_uid_len;
        memcpy(c->virtual_card_uid, p->virtual_card_uid, sizeof(c->virtual_card_uid));
        memcpy(
            c->virtual_card_select_mac_key,
            p->virtual_card_select_mac_key,
            sizeof(c->virtual_card_select_mac_key));
        memcpy(
            c->virtual_card_select_encryption_key,
            p->virtual_card_select_encryption_key,
            sizeof(c->virtual_card_select_encryption_key));
        c->virtual_card_authentication_mandatory = p->virtual_card_authentication_mandatory != 0;
        c->virtual_card_proximity_mandatory = p->virtual_card_proximity_mandatory != 0;
    } else {
        c->virtual_card_installation_id_len = 0;
        memset(c->virtual_card_installation_id, 0, sizeof(c->virtual_card_installation_id));
        c->virtual_card_information = 0;
        memset(c->virtual_card_capabilities, 0, sizeof(c->virtual_card_capabilities));
        c->virtual_card_uid_len = 0;
        memset(c->virtual_card_uid, 0, sizeof(c->virtual_card_uid));
        memset(c->virtual_card_select_mac_key, 0, sizeof(c->virtual_card_select_mac_key));
        memset(
            c->virtual_card_select_encryption_key,
            0,
            sizeof(c->virtual_card_select_encryption_key));
        c->virtual_card_authentication_mandatory = false;
        c->virtual_card_proximity_mandatory = false;
    }
#endif
#if DFC_ENABLE_DELEGATED_APPLICATIONS
    c->picc_has_dam_keys = p->has_dam_keys != 0;
    if(p->has_dam_keys) {
        memcpy(c->picc_dam_auth_key, p->dam_auth_key, sizeof(c->picc_dam_auth_key));
        memcpy(c->picc_dam_mac_key, p->dam_mac_key, sizeof(c->picc_dam_mac_key));
        memcpy(
            c->picc_dam_encryption_key, p->dam_encryption_key, sizeof(c->picc_dam_encryption_key));
    } else {
        memset(c->picc_dam_auth_key, 0, sizeof(c->picc_dam_auth_key));
        memset(c->picc_dam_mac_key, 0, sizeof(c->picc_dam_mac_key));
        memset(c->picc_dam_encryption_key, 0, sizeof(c->picc_dam_encryption_key));
    }
#endif
    return DfcDerOk;
}

int32_t dfc_ffi_credential_add_application(
    DfcFfiCredential* credential,
    const DfcFfiApplication* a,
    uint32_t* index) {
    if(!credential || !a || a->df_name_len > 16 || a->num_keys > DFC_MAX_KEYS ||
       a->key_len > DFC_MAX_KEY_LEN ||
       (a->has_iso_file_id && dfc_iso_file_id_is_reserved(a->iso_file_id))) {
        return DFC_FFI_INVALID_ARGUMENT;
    }
    if(a->num_key_sets >= DFC_KEY_SET_MINIMUM_COUNT) {
#if DFC_ENABLE_KEY_SETS
        if(a->num_key_sets > DFC_MAX_KEY_SETS) return DfcDerCapacity;
        if(a->key_set_max_size != DFC_KEY_SET_MAXIMUM_16_BYTE &&
           a->key_set_max_size != DFC_KEY_SET_MAXIMUM_24_BYTE) {
            return DFC_FFI_INVALID_ARGUMENT;
        }
        size_t active_width = dfc_key_set_type_length(a->key_set_types[0]);
        if(a->key_len > a->key_set_max_size || active_width != a->key_len) {
            return DFC_FFI_INVALID_ARGUMENT;
        }
        for(size_t i = 0; i < a->num_key_sets; i++) {
            size_t width = dfc_key_set_type_length(a->key_set_types[i]);
            if(width == 0 || width > a->key_set_max_size) return DFC_FFI_INVALID_ARGUMENT;
        }
#else
        return DfcDerUnsupported;
#endif
    }
#if !DFC_ENABLE_APPLICATION_CAPABILITY_DATA
    if(a->has_capability_data) return DfcDerUnsupported;
#endif
#if !DFC_ENABLE_DELEGATED_APPLICATIONS
    if(a->delegated) return DfcDerUnsupported;
#endif
    DfcCredential* c = &credential->model;
    if(c->num_apps >= DFC_MAX_APPS) return DfcDerCapacity;
    for(size_t i = 0; i < c->num_apps; i++) {
        if(memcmp(c->apps[i].aid, a->aid, 3) == 0) return DfcDerMalformed;
    }
    DfcApplication* app = &c->apps[c->num_apps];
    dfc_credential_reset_application(app);
    memcpy(app->aid, a->aid, sizeof(app->aid));
    app->has_iso_file_id = a->has_iso_file_id != 0;
    app->iso_file_id = a->iso_file_id;
    app->iso_aid_len = a->df_name_len;
    memcpy(app->iso_aid, a->df_name, a->df_name_len);
    app->key_settings_1 = a->key_settings_1;
    app->key_settings_2 = a->key_settings_2;
    app->auth_command = a->auth_command;
    app->has_auth_commands = a->has_auth_commands != 0;
    app->auth_commands = a->auth_commands;
    app->has_preferred_auth_command = a->has_preferred_auth_command != 0;
    app->preferred_auth_command = a->preferred_auth_command;
    app->has_sm_disable = a->has_sm_disable != 0;
    app->sm_disable = a->sm_disable;
    app->key_len = a->key_len;

    if(a->num_key_sets >= DFC_KEY_SET_MINIMUM_COUNT) {
#if DFC_ENABLE_KEY_SETS
        if(!dfc_credential_key_sets_resize(
               c, app, a->num_key_sets, a->num_keys, a->key_len, a->key_set_max_size)) {
            dfc_credential_reset_application(app);
            return DfcDerCapacity;
        }
        app->key_set_settings = a->key_set_settings;
        for(size_t i = 0; i < a->num_key_sets; i++) {
            uint8_t* version = dfc_credential_key_set_version(c, app, i);
            uint8_t* type = dfc_credential_key_set_type(c, app, i);
            if(!version || !type ||
               !dfc_credential_key_set_set_initialized(c, app, i, a->key_set_initialized[i] != 0)) {
                dfc_credential_keys_release(c, app);
                dfc_credential_reset_application(app);
                return DfcDerCapacity;
            }
            *version = a->key_set_versions[i];
            *type = a->key_set_types[i];
        }
#endif
    } else if(a->num_keys > 0) {
        if(!dfc_credential_keys_resize(c, app, a->num_keys, a->key_len)) {
            dfc_credential_reset_application(app);
            return DfcDerCapacity;
        }
    }
    if(a->has_capability_data) {
#if DFC_ENABLE_APPLICATION_CAPABILITY_DATA
        app->has_capability_data = true;
        memcpy(app->capability_data, a->capability_data, sizeof(app->capability_data));
#endif
    }
    if(a->delegated) {
#if DFC_ENABLE_DELEGATED_APPLICATIONS
        app->delegated = true;
        app->delegated_slot_number = a->delegated_slot_number;
        app->delegated_slot_version = a->delegated_slot_version;
        app->delegated_quota_limit = a->delegated_quota_limit;
        app->delegated_free_blocks = a->delegated_free_blocks;
        app->delegated_format_disabled = a->delegated_format_disabled != 0;
#endif
    }
    if(index) *index = (uint32_t)c->num_apps;
    c->num_apps++;
    return DfcDerOk;
}

int32_t dfc_ffi_credential_add_file(
    DfcFfiCredential* credential,
    const DfcFfiFile* f,
    uint32_t* index) {
    if(!credential || !f || (f->has_iso_file_id && dfc_iso_file_id_is_reserved(f->iso_file_id))) {
        return DFC_FFI_INVALID_ARGUMENT;
    }
#if !DFC_ENABLE_SDM
    if(f->sdm_enabled) return DfcDerUnsupported;
#endif
#if !DFC_ENABLE_TRANSACTION_MAC
    if(f->type == DFC_FILE_TYPE_TRANSACTION_MAC) return DfcDerUnsupported;
#endif
#if DFC_ENABLE_TRANSACTION_MAC
    if(f->type > DFC_FILE_TYPE_TRANSACTION_MAC) return DfcDerUnsupported;
#else
    if(f->type > DFC_FILE_TYPE_CYCLIC_RECORD) return DfcDerUnsupported;
#endif
    DfcCredential* c = &credential->model;
    size_t owner;
    if(f->owner == DFC_FFI_OWNER_PICC) {
        owner = DFC_FILE_OWNER_PICC;
    } else if(f->owner >= 0 && (size_t)f->owner < c->num_apps) {
        owner = (size_t)f->owner;
    } else {
        return DFC_FFI_INVALID_ARGUMENT;
    }
    size_t key_count = owner == DFC_FILE_OWNER_PICC ? c->picc_num_keys : c->apps[owner].num_keys;
    if(c->num_files >= DFC_MAX_FILES) return DfcDerCapacity;
    // Reject domains before publishing anything into the next model slot.
    if(f->number > DFC_EV1_MAX_FILE_NUMBER ||
       !dfc_communication_settings_is_valid(f->comm_settings) ||
#if DFC_ENABLE_SDM
       ((f->comm_settings & DFC_SDM_ENABLED_MASK) != 0 && !f->sdm_enabled) ||
#endif
       (f->type == DFC_FILE_TYPE_TRANSACTION_MAC ?
            !dfc_transaction_mac_access_rights_are_valid(f->access_rights, key_count) :
            !dfc_access_rights_are_valid(f->access_rights, key_count)) ||
       (f->type == DFC_FILE_TYPE_VALUE &&
        (f->limited_credit > 3 || f->limited_credit_value < 0 ||
         ((f->limited_credit & 1) == 0 && f->limited_credit_value != 0)))) {
        return DfcDerMalformed;
    }
#if DFC_ENABLE_TRANSACTION_MAC
    if(f->type == DFC_FILE_TYPE_TRANSACTION_MAC &&
       !dfc_transaction_mac_key_type_is_valid(f->transaction_mac_key_type)) {
        return DfcDerMalformed;
    }
#endif
#if DFC_ENABLE_SDM
    if(f->sdm_enabled &&
       (f->type != DFC_FILE_TYPE_STANDARD_DATA ||
        (f->sdm_options &
         (uint8_t)~(
             DFC_SDM_UID_MIRROR_MASK | DFC_SDM_COUNTER_MIRROR_MASK | DFC_SDM_COUNTER_LIMIT_MASK |
             DFC_SDM_ENCRYPTED_FILE_MASK | DFC_SDM_ASCII_ENCODING_MASK)) != 0 ||
        !dfc_sdm_access_rights_are_valid(f->sdm_access_rights, key_count))) {
        return DfcDerMalformed;
    }
#endif
    for(size_t i = 0; i < c->num_files; i++) {
        if(c->files[i].app_index == owner && c->files[i].number == f->number)
            return DfcDerMalformed;
    }
    DfcFile* file = &c->files[c->num_files];
    memset(file, 0, sizeof(*file));
    file->app_index = owner;
    file->data_offset = DFC_FILE_POOL_NONE;
    file->number = f->number;
    file->type = f->type;
    file->comm_settings = f->comm_settings;
    file->access_rights = f->access_rights;
    file->has_iso_file_id = f->has_iso_file_id != 0;
    file->iso_file_id = f->iso_file_id;
    if(dfc_file_type_is_data(file->type) && !dfc_file_set_declared_size(file, f->declared_size)) {
        return DfcDerMalformed;
    }
    file->contents_complete = f->contents_complete != 0;
    file->transaction_pending = f->transaction_pending != 0;
    if(f->type == DFC_FILE_TYPE_VALUE) {
        file->state.value.lower_limit = f->value_lower_limit;
        file->state.value.upper_limit = f->value_upper_limit;
        file->state.value.current = f->value;
        file->state.value.limited_credit_value = f->limited_credit_value;
        file->state.value.limited_credit = f->limited_credit;
        file->state.value.pending = f->value_pending != 0;
        file->state.value.pending_delta = f->value_pending_delta;
    } else if(f->type == DFC_FILE_TYPE_LINEAR_RECORD || f->type == DFC_FILE_TYPE_CYCLIC_RECORD) {
        file->state.record.size = f->record_size;
        file->state.record.max_records = f->max_records;
        file->state.record.count = f->record_count;
    }
    if(f->sdm_enabled) {
#if DFC_ENABLE_SDM
        dfc_file_sdm_flag_set(file, DfcSdmFlagEnabled, true);
        file->state.data.sdm.options = f->sdm_options;
        file->state.data.sdm.access_rights = f->sdm_access_rights;
        dfc_file_sdm_flag_set(file, DfcSdmFlagUidOffset, f->sdm_has_uid_offset != 0);
        file->state.data.sdm.uid_offset = f->sdm_uid_offset;
        dfc_file_sdm_flag_set(file, DfcSdmFlagCounterOffset, f->sdm_has_counter_offset != 0);
        file->state.data.sdm.counter_offset = f->sdm_counter_offset;
        dfc_file_sdm_flag_set(file, DfcSdmFlagPiccDataOffset, f->sdm_has_picc_data_offset != 0);
        file->state.data.sdm.picc_data_offset = f->sdm_picc_data_offset;
        dfc_file_sdm_flag_set(file, DfcSdmFlagMacInputOffset, f->sdm_has_mac_input_offset != 0);
        file->state.data.sdm.mac_input_offset = f->sdm_mac_input_offset;
        dfc_file_sdm_flag_set(file, DfcSdmFlagMacOffset, f->sdm_has_mac_offset != 0);
        file->state.data.sdm.mac_offset = f->sdm_mac_offset;
        dfc_file_sdm_flag_set(
            file, DfcSdmFlagEncryptedFile, f->sdm_has_encrypted_file_offset != 0);
        file->state.data.sdm.encrypted_file_offset = f->sdm_encrypted_file_offset;
        file->state.data.sdm.encrypted_file_length = f->sdm_encrypted_file_length;
        dfc_file_sdm_flag_set(file, DfcSdmFlagCounterLimit, f->sdm_has_counter_limit != 0);
        file->state.data.sdm.counter_limit = f->sdm_counter_limit;
        file->state.data.sdm_read_counter = f->sdm_read_counter;
#endif
    }
    if(f->type == DFC_FILE_TYPE_TRANSACTION_MAC) {
#if DFC_ENABLE_TRANSACTION_MAC
        memcpy(
            file->state.transaction_mac.key,
            f->transaction_mac_key,
            sizeof(file->state.transaction_mac.key));
        file->state.transaction_mac.key_type = f->transaction_mac_key_type;
        file->state.transaction_mac.key_version = f->transaction_mac_key_version;
        file->state.transaction_mac.counter = f->transaction_counter;
        memcpy(
            file->state.transaction_mac.mac,
            f->transaction_mac,
            sizeof(file->state.transaction_mac.mac));
        memcpy(
            file->state.transaction_mac.previous_reader_id,
            f->previous_reader_id,
            sizeof(file->state.transaction_mac.previous_reader_id));
#endif
    }
    if(index) *index = (uint32_t)c->num_files;
    c->num_files++;
    return DfcDerOk;
}

int32_t dfc_ffi_credential_set_file_data(
    DfcFfiCredential* credential,
    uint32_t index,
    const uint8_t* data,
    size_t len) {
    if(!credential || (!data && len) || index >= credential->model.num_files) {
        return DFC_FFI_INVALID_ARGUMENT;
    }
    DfcCredential* c = &credential->model;
    DfcFile* file = &c->files[index];
    if(len == 0) {
        dfc_file_release(c, file);
        return DfcDerOk;
    }
    if(!dfc_file_resize(c, file, len)) return DfcDerCapacity;
    uint8_t* dst = dfc_file_data(c, file);
    if(!dst) return DfcDerCapacity;
    memcpy(dst, data, len);
    return DfcDerOk;
}

int32_t dfc_ffi_credential_set_key(
    DfcFfiCredential* credential,
    int32_t owner,
    uint32_t key_set,
    uint32_t slot,
    const DfcFfiKey* key) {
    if(!credential || !key || key->len > sizeof(key->value)) return DFC_FFI_INVALID_ARGUMENT;
    DfcCredential* c = &credential->model;
    const DfcApplication* found;
    if(!owner_application(c, owner, &found)) return DFC_FFI_INVALID_ARGUMENT;
    DfcApplication* app = (DfcApplication*)found;
    if(key_set == 0) {
        size_t num_keys = app ? app->num_keys : c->picc_num_keys;
        size_t key_len = app ? app->key_len : c->picc_key_len;
#if DFC_ENABLE_KEY_SETS
        if(app && app->num_key_sets >= DFC_KEY_SET_MINIMUM_COUNT) {
            const uint8_t* active_type = dfc_credential_key_set_type_const(c, app, 0);
            if(!active_type) return DFC_FFI_INVALID_ARGUMENT;
            size_t active_len = dfc_key_set_type_length(*active_type);
            if(active_len == 0 || active_len > app->key_storage_len || active_len != key_len) {
                return DFC_FFI_INVALID_ARGUMENT;
            }
        }
#endif
        if(slot >= num_keys || key->len != key_len) return DFC_FFI_INVALID_ARGUMENT;
        uint8_t* dst = dfc_credential_key(c, app, slot);
        if(!dst) return DfcDerCapacity;
        memcpy(dst, key->value, key_len);
        if(app) {
            app->key_versions[slot] = key->version;
        } else {
            c->picc_key_versions[slot] = key->version;
        }
        return DfcDerOk;
    }
#if DFC_ENABLE_KEY_SETS
    if(!app || key_set >= app->num_key_sets || slot >= app->num_keys) {
        return DFC_FFI_INVALID_ARGUMENT;
    }
    const uint8_t* type = dfc_credential_key_set_type_const(c, app, key_set);
    if(!type) return DFC_FFI_INVALID_ARGUMENT;
    size_t key_len = dfc_key_set_type_length(*type);
    if(key_len == 0) return DFC_FFI_INVALID_ARGUMENT;
    if(key->len != key_len) return DFC_FFI_INVALID_ARGUMENT;
    uint8_t* dst = dfc_credential_key_in_set(c, app, key_set, slot);
    uint8_t* version = dfc_credential_key_version_in_set(c, app, key_set, slot);
    if(!dst || !version) return DfcDerCapacity;
    memcpy(dst, key->value, key_len);
    *version = key->version;
    return DfcDerOk;
#else
    return DFC_FFI_UNSUPPORTED;
#endif
}

int32_t dfc_ffi_credential_finish(DfcFfiCredential* credential, DfcFfiError* error) {
    dfc_ffi_set_error(error, DfcDerOk, 0, NULL);
    if(!credential) return DFC_FFI_INVALID_ARGUMENT;
    DfcModelStatus st = dfc_credential_validate_model(&credential->model);
    if(st != DfcDerOk) {
        dfc_ffi_set_error(error, st, 0, dfc_der_status_name(st));
        return st;
    }
    credential->model.dirty = false;
    return DfcDerOk;
}
