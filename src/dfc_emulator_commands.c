#include "dfc_emulator_i.h"
#include "dfc_credential_i.h"
#include "dfc_ev2.h"
#include "dfc_ev2_crypto.h"

#if DFC_ENABLE_EMULATOR

#define TAG                          DFC_EMULATOR_TAG
#define ISO14443_4A_CID_MASK         DFC_ISO14443_4A_CID_MASK
#define ISO14443_4A_NAD_MASK         DFC_ISO14443_4A_NAD_MASK
#define emulator_current_app         dfc_emulator_current_app
#define emulator_accepts_auth_cipher dfc_emulator_accepts_auth_cipher
#define emulator_key_len             dfc_emulator_key_len
#define emulator_num_keys            dfc_emulator_num_keys
#define emulator_key                 dfc_emulator_key
#define emulator_key_version         dfc_emulator_key_version
#define read_uint24_le               dfc_emulator_read_uint24_le
#define crc16_iso14443               dfc_crc16_iso14443
#define crc32_dfc                    dfc_crc32
#define d40_receive_plain            dfc_emulator_d40_receive_plain
#define des_key_version              dfc_emulator_des_key_version

static void
    apply_ev1_response_secure_messaging(DfcEmulator* emulator, uint8_t cmd, DfcByteBuf* tx_buffer);

static int32_t read_int32_le(const uint8_t* data) {
    return (int32_t)((uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) |
                     ((uint32_t)data[3] << 24));
}

static void append_int32_le(DfcByteBuf* tx_buffer, int32_t value) {
    uint32_t raw = (uint32_t)value;
    dfc_bytebuf_append_byte(tx_buffer, (uint8_t)(raw & 0xFF));
    dfc_bytebuf_append_byte(tx_buffer, (uint8_t)((raw >> 8) & 0xFF));
    dfc_bytebuf_append_byte(tx_buffer, (uint8_t)((raw >> 16) & 0xFF));
    dfc_bytebuf_append_byte(tx_buffer, (uint8_t)((raw >> 24) & 0xFF));
}

#if DFC_ENABLE_TRANSACTION_MAC
static void write_uint32_le(uint8_t output[DFC_UINT32_BYTE_COUNT], uint32_t value) {
    for(size_t index = 0; index < DFC_UINT32_BYTE_COUNT; index++) {
        output[index] = (uint8_t)(value >> (index * DFC_BITS_PER_BYTE));
    }
}
#endif

static bool value_delta_result(const DfcFile* file, int32_t delta, int32_t* result) {
    int64_t current = file->value_pending ?
                          (file->value_pending_absolute ?
                               file->value_pending_value :
                               (int64_t)file->value + file->value_pending_delta) :
                          file->value;
    int64_t next = current + delta;
    if(next < file->value_lower_limit || next > file->value_upper_limit) return false;
    *result = (int32_t)next;
    return true;
}

static void handle_select_application(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    DfcByteBuf* tx_buffer,
    Dfc* dfc) {
    const uint8_t* req_aid = apdu + 1;
    DfcApplication* app =
        dfc_credential_find_application_desfire_order(emulator->credential, req_aid);

    bool is_picc = req_aid[0] == 0x00 && req_aid[1] == 0x00 && req_aid[2] == 0x00;
    bool is_app = app != NULL;

    if(is_picc || is_app) {
        dfc_emulator_select_application(
            emulator,
            is_app ? DfcEmulatorSelectedApplicationApp : DfcEmulatorSelectedApplicationPicc,
            is_app ? dfc_credential_application_index(emulator->credential, app) : 0);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
        if(dfc && is_app) {
            dfc_port_notify(dfc, DfcEventApplicationSelected);
        }
    } else {
        DFC_LOG_I(TAG, "SelectApplication: unknown AID");
        dfc_emulator_reset_session(emulator);
        emulator->selected_application = DfcEmulatorSelectedApplicationPicc;
        emulator->selected_app_index = 0;
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_APPLICATION_NOT_FOUND);
    }
}

static bool require_selected_application(DfcEmulator* emulator, DfcByteBuf* tx_buffer) {
    if(emulator->selected_application == DfcEmulatorSelectedApplicationApp) {
        return true;
    }

    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
    return false;
}

static bool is_authenticated_with_key(const DfcEmulator* emulator, uint8_t key_no) {
    return (dfc_emulator_native_authentication_active(emulator) && emulator->auth_key_no == key_no)
#if DFC_ENABLE_EV2_SECURE_MESSAGING
           || (emulator->ev2_session_active && emulator->ev2_authenticated_key_no == key_no)
#endif
        ;
}

static bool is_authenticated_as_master(const DfcEmulator* emulator) {
    return is_authenticated_with_key(emulator, 0x00);
}

static uint8_t current_key_settings_1(DfcEmulator* emulator) {
    DfcApplication* app = dfc_emulator_current_app(emulator);
    if(app) return app->key_settings_1;
    return emulator->credential->picc_key_settings_1;
}

static uint8_t current_key_settings_2(DfcEmulator* emulator) {
    DfcApplication* app = dfc_emulator_current_app(emulator);
    if(app) return app->key_settings_2;
    return emulator->credential->picc_key_settings_2;
}

// A slot with no key entry carries the factory
// default, every octet zero at the length the key type gives. The default is
// supplied here, where the key is used, so a credential that omits the entry is
// never rewritten to carry it. `factory` is the caller's scratch, used only when
// the credential holds no material for this slot.
static const uint8_t* emulator_auth_key(
    DfcEmulator* emulator,
    uint8_t key_no,
    uint8_t* factory,
    size_t factory_cap,
    size_t* out_key_len) {
#if DFC_ENABLE_DELEGATED_APPLICATIONS
    if(emulator->selected_application == DfcEmulatorSelectedApplicationPicc &&
       emulator->credential->picc_has_dam_keys && key_no == DFC_DAM_AUTH_KEY_NUMBER) {
        *out_key_len = DFC_AES_KEY_LENGTH;
        return emulator->credential->picc_dam_auth_key;
    }
#endif
    size_t key_len = emulator_key_len(emulator);
    if(key_len == 0 || key_len > factory_cap) {
        key_len = dfc_credential_key_length(current_key_settings_2(emulator));
    }
    if(key_len > factory_cap) key_len = factory_cap;
    *out_key_len = key_len;

    const uint8_t* key = emulator_key(emulator, key_no);
    if(key) return key;
    memset(factory, 0, key_len);
    return factory;
}

#if DFC_ENABLE_SPECIAL_KEY_STATUS
static bool picc_disabled_special_key(DfcEmulator* emulator, uint8_t key_no) {
    if(emulator->selected_application != DfcEmulatorSelectedApplicationPicc) return false;
    if(key_no == DFC_DAM_AUTH_KEY_NUMBER) {
#if DFC_ENABLE_DELEGATED_APPLICATIONS
        return !emulator->credential->picc_has_dam_keys;
#else
        return true;
#endif
    }
    if(key_no == DFC_VC_CONFIGURATION_KEY_NUMBER) {
        return true;
    }
    return false;
}
#endif

static bool allows_free_directory_access(uint8_t key_settings_1) {
    return (key_settings_1 & DFC_KS1_FREE_DIRECTORY_ACCESS) != 0;
}

#if DFC_ENABLE_EV2_SECURE_MESSAGING
static bool is_available_authentication_key(DfcEmulator* emulator, uint8_t key_no) {
#if DFC_ENABLE_DELEGATED_APPLICATIONS
    if(emulator->selected_application == DfcEmulatorSelectedApplicationPicc &&
       emulator->credential->picc_has_dam_keys && key_no == DFC_DAM_AUTH_KEY_NUMBER)
        return true;
#endif
    return key_no < emulator_num_keys(emulator);
}
#endif

static bool allows_free_create_delete(uint8_t key_settings_1) {
    return (key_settings_1 & DFC_KS1_FREE_CREATE_DELETE) != 0;
}

static bool require_directory_access(DfcEmulator* emulator, DfcByteBuf* tx_buffer) {
    if(allows_free_directory_access(current_key_settings_1(emulator)) ||
       is_authenticated_as_master(emulator)) {
        return true;
    }

    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
    return false;
}

static bool require_create_delete_access(DfcEmulator* emulator, DfcByteBuf* tx_buffer) {
    if(allows_free_create_delete(current_key_settings_1(emulator)) ||
       is_authenticated_as_master(emulator)) {
        return true;
    }

    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
    return false;
}

static bool require_picc_authentication(DfcEmulator* emulator, DfcByteBuf* tx_buffer) {
    if(emulator->selected_application == DfcEmulatorSelectedApplicationPicc &&
       is_authenticated_as_master(emulator)) {
        return true;
    }

    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
    return false;
}

static uint8_t access_nibble(uint16_t access_rights, unsigned shift) {
    return (uint8_t)((access_rights >> shift) & 0x0F);
}

// DfcFile::access_rights holds the logical nibble order:
// read at shift 12, write at shift 8, read&write at shift 4, change at shift 0.
// The wire carries the same value least-significant octet first, so the APDU
// boundary swaps the two octets on the way in (access_rights_from_wire) and back
// out (access_rights_to_wire); nothing between those two points sees wire order.
// AIDs use the same boundary conversion. Every access-rights decision below
// goes through these four accessors; never a bare shift.
static uint8_t access_read_nibble(uint16_t access_rights) {
    return access_nibble(access_rights, 12);
}

static uint8_t access_write_nibble(uint16_t access_rights) {
    return access_nibble(access_rights, 8);
}

static uint8_t access_read_write_nibble(uint16_t access_rights) {
    return access_nibble(access_rights, 4);
}

static uint8_t access_change_nibble(uint16_t access_rights) {
    return access_nibble(access_rights, 0);
}

static bool key_references_exist(uint32_t references, size_t reference_count, size_t key_count) {
    while(reference_count-- > 0) {
        uint8_t key = (uint8_t)(references & 0x0F);
        if(key < DFC_ACCESS_FREE && key >= key_count) return false;
        references >>= 4;
    }
    return true;
}

#if DFC_ENABLE_SDM
enum {
    DfcSdmFieldUidOffset,
    DfcSdmFieldCounterOffset,
    DfcSdmFieldPiccDataOffset,
    DfcSdmFieldMacInputOffset,
    DfcSdmFieldEncryptedFileOffset,
    DfcSdmFieldEncryptedFileLength,
    DfcSdmFieldMacOffset,
    DfcSdmFieldCounterLimit,
    DfcSdmFieldCount,
};

_Static_assert(
    offsetof(DfcFile, sdm_counter_offset) - offsetof(DfcFile, sdm_uid_offset) ==
        DfcSdmFieldCounterOffset * sizeof(uint32_t),
    "SDM counter offset layout changed");
_Static_assert(
    offsetof(DfcFile, sdm_picc_data_offset) - offsetof(DfcFile, sdm_uid_offset) ==
        DfcSdmFieldPiccDataOffset * sizeof(uint32_t),
    "SDM PICC data offset layout changed");
_Static_assert(
    offsetof(DfcFile, sdm_mac_input_offset) - offsetof(DfcFile, sdm_uid_offset) ==
        DfcSdmFieldMacInputOffset * sizeof(uint32_t),
    "SDM MAC input offset layout changed");
_Static_assert(
    offsetof(DfcFile, sdm_encrypted_file_offset) - offsetof(DfcFile, sdm_uid_offset) ==
        DfcSdmFieldEncryptedFileOffset * sizeof(uint32_t),
    "SDM encrypted file offset layout changed");
_Static_assert(
    offsetof(DfcFile, sdm_encrypted_file_length) - offsetof(DfcFile, sdm_uid_offset) ==
        DfcSdmFieldEncryptedFileLength * sizeof(uint32_t),
    "SDM encrypted file length layout changed");
_Static_assert(
    offsetof(DfcFile, sdm_mac_offset) - offsetof(DfcFile, sdm_uid_offset) ==
        DfcSdmFieldMacOffset * sizeof(uint32_t),
    "SDM MAC offset layout changed");
_Static_assert(
    offsetof(DfcFile, sdm_counter_limit) - offsetof(DfcFile, sdm_uid_offset) ==
        DfcSdmFieldCounterLimit * sizeof(uint32_t),
    "SDM counter limit layout changed");
_Static_assert(
    offsetof(DfcFile, sdm_has_counter_offset) - offsetof(DfcFile, sdm_has_uid_offset) ==
        DfcSdmFieldCounterOffset * sizeof(bool),
    "SDM counter presence layout changed");
_Static_assert(
    offsetof(DfcFile, sdm_has_picc_data_offset) - offsetof(DfcFile, sdm_has_uid_offset) ==
        DfcSdmFieldPiccDataOffset * sizeof(bool),
    "SDM PICC data presence layout changed");
_Static_assert(
    offsetof(DfcFile, sdm_has_mac_input_offset) - offsetof(DfcFile, sdm_has_uid_offset) ==
        DfcSdmFieldMacInputOffset * sizeof(bool),
    "SDM MAC input presence layout changed");
_Static_assert(
    offsetof(DfcFile, sdm_has_encrypted_file_offset) - offsetof(DfcFile, sdm_has_uid_offset) ==
        DfcSdmFieldEncryptedFileOffset * sizeof(bool),
    "SDM encrypted file presence layout changed");
_Static_assert(
    offsetof(DfcFile, sdm_has_mac_offset) - offsetof(DfcFile, sdm_has_uid_offset) ==
        (DfcSdmFieldMacOffset - 1) * sizeof(bool),
    "SDM MAC presence layout changed");
_Static_assert(
    offsetof(DfcFile, sdm_has_counter_limit) - offsetof(DfcFile, sdm_has_uid_offset) ==
        (DfcSdmFieldCounterLimit - 1) * sizeof(bool),
    "SDM counter limit presence layout changed");
#endif

// APDU boundary conversions. `first` is the first access-rights octet on the
// wire, which is the low octet of the logical value.
static uint16_t access_rights_from_wire(uint8_t first, uint8_t second) {
    return (uint16_t)(((uint16_t)second << 8) | first);
}

static void access_rights_to_wire(uint16_t access_rights, uint8_t out[2]) {
    out[0] = (uint8_t)(access_rights & 0xFF);
    out[1] = (uint8_t)(access_rights >> 8);
}

// The nibble that governs `write` when true and `read` when false. The
// read&write nibble is a second, independent path to either and is checked
// alongside it, never in place of it.
static uint8_t access_primary_nibble(uint16_t access_rights, bool write) {
    return write ? access_write_nibble(access_rights) : access_read_nibble(access_rights);
}

static bool access_nibble_allows(uint8_t nibble, const DfcEmulator* emulator) {
    if(nibble == DFC_ACCESS_FREE) return true;
    if(nibble == DFC_ACCESS_DENY) return false;
    return is_authenticated_with_key(emulator, nibble);
}

static bool file_allows_read(const DfcFile* file, const DfcEmulator* emulator) {
    return dfc_emulator_file_access_allowed(emulator, file, DfcFileAccessRead);
}

static bool file_allows_write(const DfcFile* file, const DfcEmulator* emulator) {
    return dfc_emulator_file_access_allowed(emulator, file, DfcFileAccessWrite);
}

#if DFC_ENABLE_RECORD_FILES
static bool file_allows_read_write(const DfcFile* file, const DfcEmulator* emulator) {
    return dfc_emulator_file_access_allowed(emulator, file, DfcFileAccessReadWrite);
}
#endif

// Status for an operation the file's access rights refuse. Genuine silicon
// separates two reasons, so this must too, and it consults exactly the nibbles
// file_allows_read / file_allows_write consulted.
//
// A nibble naming a key (0x0..0xD) means the caller could have been let in by
// authenticating with that key and simply is not; a card answers that with the
// authentication error. Measured on a genuine EV1 4K: ReadData on a file whose
// access rights are 0x1230 (read = key 1, read&write = key 3), with no session
// open, answers 0xAE.
//
// A nibble of 0xF permits nobody, so no authentication can ever satisfy it and
// the authentication error would invite a retry that cannot succeed. That case
// keeps permission denied. There is no hardware measurement behind it — it is
// the status this engine has always returned and is left alone deliberately.
//
// A refusal because the operation does not fit the object at all (a value
// command on a standard data file, LimitedCredit on a file without the flag) is
// not an access-rights refusal and does not come here; those stay permission
// denied, which hardware confirms.
static uint8_t file_access_refusal_status(const DfcFile* file, bool write) {
    uint8_t primary = access_primary_nibble(file->access_rights, write);
    uint8_t read_write = access_read_write_nibble(file->access_rights);
    if(primary < DFC_ACCESS_FREE || read_write < DFC_ACCESS_FREE) {
        return DFC_STATUS_AUTHENTICATION_ERR;
    }
    return DFC_STATUS_PERMISSION_DENIED;
}

// True when every nibble that can authorize `write` is free (0xE) — no key-gated path.
// EV1/EV3: if only free access applies but file is Full, treat as Plain-with-auth.
static size_t allocated_file_bytes(const DfcCredential* credential) {
    size_t used = 0;
    for(size_t i = 0; i < credential->num_files; i++) {
        const DfcFile* file = &credential->files[i];
        if(file->type == DFC_FILE_TYPE_STANDARD_DATA || file->type == DFC_FILE_TYPE_BACKUP_DATA) {
            used += file->declared_size;
        } else if(
            file->type == DFC_FILE_TYPE_LINEAR_RECORD ||
            file->type == DFC_FILE_TYPE_CYCLIC_RECORD) {
            used += (size_t)file->record_size * file->max_records;
        }
    }
    return used;
}

static size_t card_file_capacity_bytes(const DfcCard* card) {
    if(card->generation == DfcGenerationEv3 && card->storage == DfcStorage4KByteCount)
        return DFC_EV3_4K_FREE_MEMORY_BYTES;
    // A zeroed card has no configured storage. Keep the legacy EV1 fallback.
    return card->storage ? card->storage : DFC_EV1_PICC_STORAGE_BYTES;
}

static bool has_card_file_capacity(const DfcCredential* credential, size_t allocation) {
    size_t capacity = card_file_capacity_bytes(&credential->card);
    size_t used = allocated_file_bytes(credential);
    return used <= capacity && allocation <= capacity - used;
}

static void clear_pending_chain(DfcEmulator* emulator) {
    if(emulator->pending_chain_len <= sizeof(emulator->pending_chain)) {
        dfc_secure_wipe(emulator->pending_chain, emulator->pending_chain_len);
    }
    emulator->pending_chain_len = 0;
    emulator->pending_chain_offset = 0;
    emulator->pending_chain_frame = 0;
    emulator->pending_chain_last = 0;
    emulator->pending_chain_chunk_count = 0;
    emulator->pending_chain_chunk_index = 0;
    emulator->df_names_pending = false;
    emulator->df_names_next = 0;
    emulator->get_version_frame = 0;
}

static bool has_pending_additional_work(const DfcEmulator* emulator) {
    return emulator->awaiting_step2 ||
#if DFC_ENABLE_DELEGATED_APPLICATIONS
           emulator->delegated_creation_pending ||
#endif
#if DFC_ENABLE_EV2_SECURE_MESSAGING
           emulator->ev2_authentication_pending ||
#endif
           emulator->get_version_frame != 0 || emulator->df_names_pending ||
           emulator->pending_chain_len > emulator->pending_chain_offset;
}

static void append_status_payload(
    DfcByteBuf* tx_buffer,
    uint8_t status,
    const uint8_t* payload,
    size_t payload_len) {
    dfc_bytebuf_append_byte(tx_buffer, status);
    if(payload_len > 0 && payload) {
        dfc_bytebuf_append_bytes(tx_buffer, payload, payload_len);
    }
}

// Encrypted responses end intermediate frames on cipher-block boundaries.
// Clear and MACed listings use every octet they can without splitting entries.
static size_t ev1_frame_payload(const DfcEmulator* emulator, size_t entry, bool block_aligned) {
    size_t limit = emulator->credential->card.generation == DfcGenerationEv3 ?
                       DFC_EV3_MAX_RESPONSE_PAYLOAD :
                       DFC_EV1_MAX_FRAME_PAYLOAD;
    if(block_aligned) {
        size_t block = emulator->secure_messaging->cipher == DFC_CMD_AUTHENTICATE_AES ? 16 : 8;
        return (limit / block) * block;
    }
    if(entry == 0) entry = 1;
    return (limit / entry) * entry;
}

// `entry` is the size of one listing entry, so no frame splits one; 1 for data.
// `comm` is the communication mode the answer is returned under: an enciphered
// file's records come back enciphered, and a legacy session secures by that mode.
static void emit_payload_with_chaining_comm(
    DfcEmulator* emulator,
    DfcByteBuf* tx_buffer,
    uint8_t cmd,
    const uint8_t* payload,
    size_t payload_len,
    size_t entry,
    uint8_t comm,
    bool length_unknown) {
    bool iso_transport = emulator->pending_chain_last == DFC_ISO_DEP_RESPONSE_PENDING;
    clear_pending_chain(emulator);

    // Secure the whole answer once, then split the result; intermediate frames
    // carry secured octets and the final frame carries the MAC where there is one.
    bool secured_in_pending = false;
    size_t pending_used = 0;
    bool ev1 = dfc_emulator_native_authentication_active(emulator) &&
               dfc_secure_messaging_applies_ev1(emulator->secure_messaging, cmd);
    bool legacy = dfc_emulator_native_authentication_active(emulator) && !ev1;
    bool is_secured = false;
    bool block_aligned = false;
    if(ev1 && comm == DFC_COMM_ENCIPHERED) {
        if(payload_len > sizeof(emulator->pending_chain) - DFC_SM_MAX_CIPHER_BLOCK_SIZE) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
            return;
        }
        pending_used = payload_len + DFC_SM_MAX_CIPHER_BLOCK_SIZE;
        payload_len = dfc_secure_messaging_generate_response_with_length_marker(
            emulator->secure_messaging,
            DFC_COMM_ENCIPHERED,
            DFC_STATUS_OK,
            payload,
            payload_len,
            emulator->pending_chain,
            sizeof(emulator->pending_chain),
            length_unknown);
        if(payload_len == 0) goto crypto_failure;
        pending_used = payload_len;
        payload = emulator->pending_chain;
        secured_in_pending = true;
        is_secured = true;
        block_aligned = true;
    } else if(ev1) {
        if(payload_len > sizeof(emulator->pending_chain) - DFC_WORKER_CMAC_SIZE) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
            return;
        }
        memcpy(emulator->pending_chain, payload, payload_len);
        pending_used = payload_len + DFC_WORKER_CMAC_SIZE;
        payload_len = dfc_secure_messaging_generate_ev1_response_in_place(
            emulator->secure_messaging,
            DFC_STATUS_OK,
            emulator->pending_chain,
            payload_len,
            sizeof(emulator->pending_chain));
        if(payload_len == 0) goto crypto_failure;
        pending_used = payload_len;
        payload = emulator->pending_chain;
        secured_in_pending = true;
        is_secured = true;
        block_aligned = comm == DFC_COMM_ENCIPHERED;
    } else if(legacy && comm != DFC_COMM_PLAIN) {
        if(payload_len > sizeof(emulator->pending_chain) - DFC_SM_MAX_CIPHER_BLOCK_SIZE) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
            return;
        }
        pending_used = payload_len + DFC_SM_MAX_CIPHER_BLOCK_SIZE;
        payload_len = dfc_secure_messaging_generate_response_with_length_marker(
            emulator->secure_messaging,
            comm,
            DFC_STATUS_OK,
            payload,
            payload_len,
            emulator->pending_chain,
            sizeof(emulator->pending_chain),
            length_unknown);
        if(payload_len == 0) goto crypto_failure;
        pending_used = payload_len;
        payload = emulator->pending_chain;
        secured_in_pending = true;
        is_secured = true;
    }
    if(is_secured) emulator->response_secured = true;

    // The alternate ReadRecords instruction delegates continuation to ISO-DEP.
    // Return its complete logical response so the transport can split I-blocks.
    if(cmd == DFC_CMD_READ_RECORDS_ISO) {
        if(!iso_transport) {
            size_t used = dfc_bytebuf_get_size_bytes(tx_buffer);
            if(used < DFC_BYTEBUF_MAX && payload_len < DFC_BYTEBUF_MAX - used)
                append_status_payload(tx_buffer, DFC_STATUS_OK, payload, payload_len);
            else
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
            if(secured_in_pending) dfc_secure_wipe(emulator->pending_chain, pending_used);
            return;
        }
        if(payload_len > sizeof(emulator->pending_chain) - DFC_ISO7816_STATUS_WORD_LENGTH) {
            if(secured_in_pending) dfc_secure_wipe(emulator->pending_chain, pending_used);
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
            return;
        }
        if(!secured_in_pending) memcpy(emulator->pending_chain, payload, payload_len);
        emulator->pending_chain_len = payload_len;
        emulator->pending_chain_frame = DFC_ISO_DEP_RESPONSE_PENDING;
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
        return;
    }

    if((ev1 || (legacy && comm != DFC_COMM_PLAIN)) &&
       (cmd == DFC_CMD_READ_DATA || cmd == DFC_CMD_READ_RECORDS)) {
        block_aligned = true;
    }

    size_t frame = ev1_frame_payload(emulator, entry, block_aligned);
    // The EV3 card caps the ISO file-ID list at 27 two-octet entries per frame.
    if(cmd == DFC_CMD_GET_ISO_FILE_IDS &&
       emulator->credential->card.generation == DfcGenerationEv3 &&
       frame > DFC_EV3_ISO_FIDS_PER_FRAME * DFC_ISO_FID_SIZE) {
        frame = DFC_EV3_ISO_FIDS_PER_FRAME * DFC_ISO_FID_SIZE;
    }
    // A secured answer runs its final frame to the wire limit, carrying the MAC
    // after the last block; an unsecured one ends on a whole entry.
    size_t last = is_secured ? (emulator->credential->card.generation == DfcGenerationEv3 ?
                                    DFC_EV3_MAX_RESPONSE_PAYLOAD :
                                    DFC_EV1_MAX_FRAME_PAYLOAD) :
                               frame;
    emulator->pending_chain_frame = frame;
    emulator->pending_chain_last = last;
    if(payload_len <= last) {
        append_status_payload(tx_buffer, DFC_STATUS_OK, payload, payload_len);
        if(secured_in_pending) dfc_secure_wipe(emulator->pending_chain, pending_used);
        return;
    }

    size_t remaining = payload_len - frame;
    if(secured_in_pending) {
        emulator->pending_chain_len = payload_len;
        emulator->pending_chain_offset = frame;
        append_status_payload(tx_buffer, DFC_CMD_ADDITIONAL_FRAME, payload, frame);
        return;
    }
    if(remaining > sizeof(emulator->pending_chain)) {
        remaining = sizeof(emulator->pending_chain);
    }
    memcpy(emulator->pending_chain, payload + frame, remaining);
    emulator->pending_chain_len = remaining;
    emulator->pending_chain_offset = 0;
    append_status_payload(tx_buffer, DFC_CMD_ADDITIONAL_FRAME, payload, frame);
    return;

crypto_failure:
    dfc_secure_wipe(emulator->pending_chain, pending_used);
    clear_pending_chain(emulator);
    dfc_emulator_reset_session(emulator);
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
}

// Most answers are returned plain or under the session default; a file read
// passes its own communication mode through the *_comm form above.
static void emit_payload_with_chaining(
    DfcEmulator* emulator,
    DfcByteBuf* tx_buffer,
    uint8_t cmd,
    const uint8_t* payload,
    size_t payload_len,
    size_t entry) {
    emit_payload_with_chaining_comm(
        emulator, tx_buffer, cmd, payload, payload_len, entry, DFC_COMM_PLAIN, false);
}

static void handle_pending_chain_continuation(DfcEmulator* emulator, DfcByteBuf* tx_buffer) {
    if(emulator->pending_chain_frame == DFC_ISO_DEP_RESPONSE_PENDING) {
        clear_pending_chain(emulator);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_ILLEGAL_COMMAND_CODE);
        return;
    }
    if(emulator->pending_chain_offset >= emulator->pending_chain_len) {
        clear_pending_chain(emulator);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_ILLEGAL_COMMAND_CODE);
        return;
    }

    size_t frame = emulator->pending_chain_frame ? emulator->pending_chain_frame :
                                                   ev1_frame_payload(emulator, 1, false);
    size_t last = emulator->pending_chain_last ? emulator->pending_chain_last : frame;
    size_t remaining = emulator->pending_chain_len - emulator->pending_chain_offset;
    size_t chunk;
    if(emulator->pending_chain_chunk_index < emulator->pending_chain_chunk_count) {
        chunk = emulator->pending_chain_chunks[emulator->pending_chain_chunk_index++];
        if(chunk > remaining) chunk = remaining;
    } else {
        chunk = remaining <= last ? remaining : frame;
    }
    bool final_frame = chunk == remaining;
    // These octets were secured as one response before being split.
    if(dfc_emulator_native_authentication_active(emulator)) emulator->response_secured = true;
    uint8_t status = final_frame ? DFC_STATUS_OK : DFC_CMD_ADDITIONAL_FRAME;
    append_status_payload(
        tx_buffer, status, emulator->pending_chain + emulator->pending_chain_offset, chunk);
    emulator->pending_chain_offset += chunk;
    if(status == DFC_STATUS_OK) {
        clear_pending_chain(emulator);
    }
}

static void handle_free_mem(DfcEmulator* emulator, DfcByteBuf* tx_buffer) {
    // Report the same logical capacity used to admit file allocations.
    size_t used = allocated_file_bytes(emulator->credential);
    size_t advertised_capacity = card_file_capacity_bytes(&emulator->credential->card);
    uint32_t free_bytes = 0;
    if(used >= advertised_capacity) {
        free_bytes = 0;
    } else {
        free_bytes = (uint32_t)(advertised_capacity - used);
    }
    uint8_t free_mem[3] = {
        (uint8_t)(free_bytes & 0xFF),
        (uint8_t)((free_bytes >> 8) & 0xFF),
        (uint8_t)((free_bytes >> 16) & 0xFF),
    };
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
    dfc_bytebuf_append_bytes(tx_buffer, free_mem, sizeof(free_mem));
}

// The next GetDFNames record, one application per frame: AID, little-endian
// ISO file ID and DF name, for each application with an ISO file ID.
static void handle_df_names_continuation(DfcEmulator* emulator, DfcByteBuf* tx_buffer) {
    const DfcCredential* credential = emulator->credential;
    size_t index = emulator->df_names_next;
    while(index < credential->num_apps && !credential->apps[index].has_iso_file_id)
        index++;
    if(index >= credential->num_apps) {
        clear_pending_chain(emulator);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
        return;
    }
    size_t next = index + 1;
    while(next < credential->num_apps && !credential->apps[next].has_iso_file_id)
        next++;
    bool more = next < credential->num_apps;
    const DfcApplication* app = &credential->apps[index];
    dfc_bytebuf_append_byte(tx_buffer, more ? DFC_CMD_ADDITIONAL_FRAME : DFC_STATUS_OK);
    dfc_bytebuf_append_byte(tx_buffer, app->aid[2]);
    dfc_bytebuf_append_byte(tx_buffer, app->aid[1]);
    dfc_bytebuf_append_byte(tx_buffer, app->aid[0]);
    dfc_bytebuf_append_byte(tx_buffer, (uint8_t)(app->iso_file_id & 0xFF));
    dfc_bytebuf_append_byte(tx_buffer, (uint8_t)(app->iso_file_id >> 8));
    dfc_bytebuf_append_bytes(tx_buffer, app->iso_aid, app->iso_aid_len);
    emulator->df_names_pending = more;
    emulator->df_names_next = next;
}

static void handle_get_df_names(DfcEmulator* emulator, DfcByteBuf* tx_buffer) {
    if(emulator->selected_application != DfcEmulatorSelectedApplicationPicc) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
    if(!require_directory_access(emulator, tx_buffer)) return;

    bool ev1 = dfc_emulator_native_authentication_active(emulator) &&
               dfc_secure_messaging_applies_ev1(emulator->secure_messaging, DFC_CMD_GET_DF_NAMES);
    // D40 does not add a response CMAC here. Every application still occupies
    // one frame, whether or not authentication is active.
    if(!ev1) {
        clear_pending_chain(emulator);
        emulator->df_names_next = 0;
        handle_df_names_continuation(emulator, tx_buffer);
        return;
    }

    // Records contain the AID, the little-endian ISO file ID, and the DF name.
    // An application is listed when it carries an ISO file ID; the DF name is
    // whatever it has, and an application without one is listed all the same.
    uint8_t* records = emulator->pending_chain;
    uint8_t record_lengths[DFC_MAX_APPS];
    size_t record_count = 0;
    size_t records_len = 0;
    for(size_t i = 0; i < emulator->credential->num_apps; i++) {
        const DfcApplication* app = &emulator->credential->apps[i];
        if(!app->has_iso_file_id) continue;
        if(records_len + 5 + app->iso_aid_len + DFC_WORKER_CMAC_SIZE >
           sizeof(emulator->pending_chain))
            break;
        records[records_len++] = app->aid[2];
        records[records_len++] = app->aid[1];
        records[records_len++] = app->aid[0];
        records[records_len++] = (uint8_t)(app->iso_file_id & 0xFF);
        records[records_len++] = (uint8_t)(app->iso_file_id >> 8);
        memcpy(records + records_len, app->iso_aid, app->iso_aid_len);
        records_len += app->iso_aid_len;
        record_lengths[record_count++] = (uint8_t)(5 + app->iso_aid_len);
    }

    // Secure the complete logical response, then retain each application's
    // frame boundary. The final application's frame also carries the CMAC.
    size_t secured_len = dfc_secure_messaging_generate_ev1_response_in_place(
        emulator->secure_messaging,
        DFC_STATUS_OK,
        records,
        records_len,
        sizeof(emulator->pending_chain));
    if(secured_len == 0) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OUT_OF_EEPROM);
        return;
    }
    emulator->response_secured = true;
    if(record_count <= 1) {
        append_status_payload(tx_buffer, DFC_STATUS_OK, records, secured_len);
        return;
    }

    clear_pending_chain(emulator);
    emulator->response_secured = true;
    size_t first_len = record_lengths[0];
    emulator->pending_chain_len = secured_len;
    emulator->pending_chain_offset = first_len;
    emulator->pending_chain_chunk_count = (uint8_t)(record_count - 1);
    emulator->pending_chain_chunk_index = 0;
    for(size_t index = 1; index < record_count; index++) {
        size_t chunk = record_lengths[index];
        if(index + 1 == record_count) chunk += secured_len - records_len;
        emulator->pending_chain_chunks[index - 1] = (uint8_t)chunk;
    }
    append_status_payload(tx_buffer, DFC_CMD_ADDITIONAL_FRAME, records, first_len);
}

static void handle_get_card_uid(DfcEmulator* emulator, DfcByteBuf* tx_buffer) {
    bool authenticated = dfc_emulator_native_authentication_active(emulator);
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    authenticated = authenticated || emulator->ev2_session_active;
#endif
    if(!authenticated) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return;
    }

    uint8_t response[DFC_SM_MAX_CIPHER_BLOCK_SIZE];
    size_t uid_len = emulator->credential->uid_len;
    size_t response_len = uid_len;
    size_t uid_offset = 0;
    if(uid_len != DFC_DESFIRE_UID_LEN) {
        response[0] = 0x00;
        response[1] = (uint8_t)uid_len;
        uid_offset = 2;
        response_len += 2;
    }
    memcpy(response + uid_offset, emulator->credential->uid, uid_len);

#if DFC_ENABLE_EV2_SECURE_MESSAGING
    if(emulator->ev2_session_active) {
        // The transport layer applies EV2 Full protection after dispatch.
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
        dfc_bytebuf_append_bytes(tx_buffer, response, response_len);
        dfc_secure_wipe(response, sizeof(response));
        return;
    }
#endif

    response_len = dfc_secure_messaging_generate_response(
        emulator->secure_messaging,
        DFC_COMM_ENCIPHERED,
        DFC_STATUS_OK,
        response,
        response_len,
        response,
        sizeof(response));
    if(response_len == 0) {
        dfc_secure_wipe(response, sizeof(response));
        dfc_emulator_reset_session(emulator);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        return;
    }
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
    dfc_bytebuf_append_bytes(tx_buffer, response, response_len);
    emulator->response_secured = true;
    dfc_secure_wipe(response, sizeof(response));
}

static void handle_format_picc(DfcEmulator* emulator, DfcByteBuf* tx_buffer) {
    if(!require_picc_authentication(emulator, tx_buffer)) return;

    if(emulator->credential->picc_format_disabled) {
        // Format disabled in the PICC configuration: the operation is not
        // permitted even for the authenticated master, so it answers with the
        // same status this command already uses to refuse one, and the
        // credential is left alone.
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return;
    }

    dfc_credential_format_picc(emulator->credential);
    dfc_credential_mark_dirty(emulator->credential);
    dfc_emulator_reset_session(emulator);
    emulator->selected_application = DfcEmulatorSelectedApplicationPicc;
    emulator->selected_app_index = 0;
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
}

static void handle_get_key_settings(DfcEmulator* emulator, DfcByteBuf* tx_buffer) {
    if(!require_directory_access(emulator, tx_buffer)) return;

    DfcCredential* credential = emulator->credential;
    DfcApplication* app = emulator_current_app(emulator);

    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
    if(emulator->selected_application == DfcEmulatorSelectedApplicationPicc) {
        dfc_bytebuf_append_byte(tx_buffer, credential->picc_key_settings_1);
        dfc_bytebuf_append_byte(
            tx_buffer, (credential->picc_key_settings_2 & DFC_KEY_TYPE_MASK) | 0x01);
    } else if(app) {
        dfc_bytebuf_append_byte(tx_buffer, app->key_settings_1);
        // Bit 5 is a modifier on CreateApplication rather than state an
        // application holds, so it is not reported back. It is still kept in the
        // stored settings, where the file commands read it.
        dfc_bytebuf_append_byte(
            tx_buffer, app->key_settings_2 & (DFC_KEY_TYPE_MASK | DFC_NUM_KEYS_MASK));
#if DFC_ENABLE_KEY_SETS
        if(app->num_key_sets > 1) {
            dfc_bytebuf_append_byte(tx_buffer, app->key_set_versions[0]);
            dfc_bytebuf_append_byte(tx_buffer, app->num_key_sets);
            dfc_bytebuf_append_byte(tx_buffer, app->max_key_size);
            dfc_bytebuf_append_byte(tx_buffer, app->key_set_settings);
        }
#endif
    }
}

static void handle_get_key_version(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    DfcByteBuf* tx_buffer) {
    uint8_t key_no = apdu[1];
#if DFC_ENABLE_KEY_SETS
    DfcApplication* app = emulator_current_app(emulator);
    if(app && (key_no & DFC_KEY_SET_NUMBER_PRESENT_MASK) != 0) {
        if(app->num_key_sets <= 1) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
            return;
        }
        if(apdu_len != 3) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return;
        }
        uint8_t key_set_selector = apdu[2];
        if((key_no & DFC_KEY_SET_SECOND_APPLICATION_MASK) != 0) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
            return;
        }
        if((key_set_selector & DFC_KEY_SET_RETRIEVAL_MASK) != 0) {
            if((key_no & DFC_KEY_NUMBER_MASK) != 0 ||
               (key_set_selector & DFC_KEY_SET_NUMBER_MASK) != 0) {
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
                return;
            }
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
            dfc_bytebuf_append_bytes(tx_buffer, app->key_set_versions, app->num_key_sets);
            return;
        }
        size_t key_set_number = key_set_selector & DFC_KEY_SET_NUMBER_MASK;
        size_t slot = key_no & DFC_KEY_NUMBER_MASK;
        uint8_t* version = dfc_credential_key_version_in_set(app, key_set_number, slot);
        if(!version) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_NO_SUCH_KEY);
            return;
        }
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
        dfc_bytebuf_append_byte(tx_buffer, *version);
        return;
    }
#else
    DFC_UNUSED(apdu_len);
#endif
    if(apdu_len != 2) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }
#if DFC_ENABLE_SPECIAL_KEY_STATUS
    if(picc_disabled_special_key(emulator, key_no)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
#endif
    if(key_no >= emulator_num_keys(emulator)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_NO_SUCH_KEY);
        return;
    }

    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
    dfc_bytebuf_append_byte(tx_buffer, *emulator_key_version(emulator, key_no));
}

static bool can_change_key(DfcEmulator* emulator, uint8_t target_key_no) {
    uint8_t ks1 = current_key_settings_1(emulator);
    uint8_t auth = emulator->auth_key_no;
    if(target_key_no == 0x00) {
        return ((ks1 & DFC_KS1_MASTER_KEY_CHANGEABLE) != 0) && auth == 0x00;
    }
    uint8_t change_access = (uint8_t)(ks1 >> DFC_KS1_CHANGE_KEY_ACCESS_SHIFT);
    if(change_access == DFC_CHANGE_KEY_ACCESS_FROZEN) return false;
    if(change_access == DFC_CHANGE_KEY_ACCESS_SAME) return auth == target_key_no;
    if(change_access == 0x00) return auth == 0x00;
    return auth == change_access;
}

static bool is_aes_key_context(DfcEmulator* emulator) {
    DfcApplication* app = emulator_current_app(emulator);
    uint8_t ks2 = app ? app->key_settings_2 : emulator->credential->picc_key_settings_2;
    return (ks2 & DFC_KEY_TYPE_MASK) == DFC_KEY_TYPE_AES;
}

static bool
    change_key_d40_padding_valid(const uint8_t* clear, size_t content_len, size_t clear_len) {
    if(content_len > clear_len) return false;
    for(size_t i = content_len; i < clear_len; i++) {
        if(clear[i] != 0) return false;
    }
    return true;
}

static void mark_key_change_dirty(DfcEmulator* emulator) {
    dfc_credential_mark_dirty(emulator->credential);
#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
    // A later file rollback must still leave this immediate key update dirty.
    if(emulator->transaction_snapshot_active) emulator->transaction_snapshot_dirty = true;
#endif
}

static void handle_change_key_d40(
    DfcEmulator* emulator,
    uint8_t key_no,
    const uint8_t* encrypted,
    size_t encrypted_len,
    DfcByteBuf* tx_buffer) {
    size_t key_len = emulator_key_len(emulator);
    uint8_t clear[DFC_MAX_KEY_LEN + 8];
    if((encrypted_len % 8) != 0 || encrypted_len < key_len + 2 || encrypted_len > sizeof(clear)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }

    memset(clear, 0, sizeof(clear));
    if(!d40_receive_plain(
           emulator->secure_messaging->session_key,
           emulator->secure_messaging->session_key_len,
           encrypted,
           encrypted_len,
           clear)) {
        dfc_secure_wipe(clear, sizeof(clear));
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        return;
    }

    uint16_t expected_crc = crc16_iso14443(clear, key_len);
    uint16_t actual_crc = (uint16_t)clear[key_len] | ((uint16_t)clear[key_len + 1] << 8);
    if(expected_crc != actual_crc) {
        dfc_secure_wipe(clear, sizeof(clear));
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        return;
    }

    if(key_no != emulator->auth_key_no) {
        size_t crc2_offset = key_len + 2;
        if(encrypted_len < key_len + 4) {
            dfc_secure_wipe(clear, sizeof(clear));
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return;
        }

        uint8_t new_key[DFC_MAX_KEY_LEN] = {0};
        uint8_t* old_key = emulator_key(emulator, key_no);
        if(!old_key) {
            dfc_secure_wipe(new_key, sizeof(new_key));
            dfc_secure_wipe(clear, sizeof(clear));
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_NO_SUCH_KEY);
            return;
        }
        for(size_t i = 0; i < key_len; i++) {
            new_key[i] = clear[i] ^ old_key[i];
        }

        uint16_t expected_new_crc = crc16_iso14443(new_key, key_len);
        uint16_t actual_new_crc = (uint16_t)clear[crc2_offset] |
                                  ((uint16_t)clear[crc2_offset + 1] << 8);
        if(expected_new_crc != actual_new_crc) {
            dfc_secure_wipe(new_key, sizeof(new_key));
            dfc_secure_wipe(clear, sizeof(clear));
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
            return;
        }
        if(!change_key_d40_padding_valid(clear, key_len + 4, encrypted_len)) {
            dfc_secure_wipe(new_key, sizeof(new_key));
            dfc_secure_wipe(clear, sizeof(clear));
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
            return;
        }

        memcpy(old_key, new_key, key_len);
        *emulator_key_version(emulator, key_no) = des_key_version(new_key);
        mark_key_change_dirty(emulator);
        dfc_secure_wipe(new_key, sizeof(new_key));
        dfc_secure_wipe(clear, sizeof(clear));
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
        return;
    }

    if(!change_key_d40_padding_valid(clear, key_len + 2, encrypted_len)) {
        dfc_secure_wipe(clear, sizeof(clear));
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        return;
    }

    uint8_t* target = emulator_key(emulator, key_no);
    if(!target) {
        dfc_secure_wipe(clear, sizeof(clear));
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_NO_SUCH_KEY);
        return;
    }
    dfc_emulator_retire_authentication(emulator);
    memcpy(target, clear, key_len);
    *emulator_key_version(emulator, key_no) = des_key_version(clear);
    mark_key_change_dirty(emulator);
    dfc_secure_wipe(clear, sizeof(clear));
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
}

static void handle_change_key_ev1(
    DfcEmulator* emulator,
    uint8_t key_no,
    const uint8_t* encrypted,
    size_t encrypted_len,
    DfcByteBuf* tx_buffer) {
    DfcSecureMessaging* sm = emulator->secure_messaging;
    size_t key_len = emulator_key_len(emulator);
    bool aes_key = is_aes_key_context(emulator);
    size_t block = sm->cipher == DFC_CMD_AUTHENTICATE_AES ? 16 : 8;
    size_t version_len = aes_key ? 1 : 0;
    bool different = key_no != emulator->auth_key_no;
    size_t content = key_len + version_len + 4 + (different ? 4 : 0);

    uint8_t clear[48];
    if(encrypted_len < content || encrypted_len > sizeof(clear) || (encrypted_len % block) != 0) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }

    memset(clear, 0, sizeof(clear));
    uint8_t candidate_iv[sizeof(sm->iv)];
    memcpy(candidate_iv, sm->iv, sizeof(candidate_iv));
    // Decrypt with the current session IV; CBC mutates IV to the last CT block,
    // which is the EV1 next-IV for ChangeKey (encrypted-plain command).
    bool decrypted = sm->cipher == DFC_CMD_AUTHENTICATE_AES ? dfc_worker_aes_cbc_decrypt(
                                                                  sm->session_key,
                                                                  sm->session_key_len,
                                                                  candidate_iv,
                                                                  encrypted_len,
                                                                  encrypted,
                                                                  clear) :
                                                              dfc_worker_des_cbc_decrypt(
                                                                  sm->session_key,
                                                                  sm->session_key_len,
                                                                  candidate_iv,
                                                                  encrypted_len,
                                                                  encrypted,
                                                                  clear);
    if(!decrypted) {
        dfc_secure_wipe(clear, sizeof(clear));
        dfc_secure_wipe(candidate_iv, sizeof(candidate_iv));
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        return;
    }

    size_t cursor = key_len;
    uint8_t new_version = 0;
    if(aes_key) {
        new_version = clear[cursor++];
    }

    uint8_t crc_input[2 + DFC_MAX_KEY_LEN + 1];
    crc_input[0] = DFC_CMD_CHANGE_KEY;
    crc_input[1] = key_no;
    memcpy(crc_input + 2, clear, cursor);
    uint32_t expected_crc = crc32_dfc(crc_input, 2 + cursor);
    uint32_t actual_crc = (uint32_t)clear[cursor] | ((uint32_t)clear[cursor + 1] << 8) |
                          ((uint32_t)clear[cursor + 2] << 16) |
                          ((uint32_t)clear[cursor + 3] << 24);
    if(expected_crc != actual_crc) {
        dfc_secure_wipe(crc_input, sizeof(crc_input));
        dfc_secure_wipe(clear, sizeof(clear));
        dfc_secure_wipe(candidate_iv, sizeof(candidate_iv));
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        return;
    }
    cursor += 4;

    uint8_t new_key[DFC_MAX_KEY_LEN];
    uint8_t* old_key = emulator_key(emulator, key_no);
    if(!old_key) {
        dfc_secure_wipe(new_key, sizeof(new_key));
        dfc_secure_wipe(crc_input, sizeof(crc_input));
        dfc_secure_wipe(clear, sizeof(clear));
        dfc_secure_wipe(candidate_iv, sizeof(candidate_iv));
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_NO_SUCH_KEY);
        return;
    }
    if(different) {
        for(size_t i = 0; i < key_len; i++) {
            new_key[i] = clear[i] ^ old_key[i];
        }
        uint32_t expected_new_crc = crc32_dfc(new_key, key_len);
        uint32_t actual_new_crc = (uint32_t)clear[cursor] | ((uint32_t)clear[cursor + 1] << 8) |
                                  ((uint32_t)clear[cursor + 2] << 16) |
                                  ((uint32_t)clear[cursor + 3] << 24);
        if(expected_new_crc != actual_new_crc) {
            dfc_secure_wipe(new_key, sizeof(new_key));
            dfc_secure_wipe(crc_input, sizeof(crc_input));
            dfc_secure_wipe(clear, sizeof(clear));
            dfc_secure_wipe(candidate_iv, sizeof(candidate_iv));
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
            return;
        }
        cursor += 4;
    } else {
        memcpy(new_key, clear, key_len);
    }

    for(size_t i = cursor; i < encrypted_len; i++) {
        if(clear[i] != 0x00) {
            dfc_secure_wipe(new_key, sizeof(new_key));
            dfc_secure_wipe(crc_input, sizeof(crc_input));
            dfc_secure_wipe(clear, sizeof(clear));
            dfc_secure_wipe(candidate_iv, sizeof(candidate_iv));
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
            return;
        }
    }

    if(different) {
        memcpy(sm->iv, candidate_iv, sizeof(sm->iv));
    } else {
        dfc_emulator_retire_authentication(emulator);
    }
    dfc_secure_wipe(candidate_iv, sizeof(candidate_iv));
    memcpy(old_key, new_key, key_len);
    if(aes_key) {
        *emulator_key_version(emulator, key_no) = new_version;
    } else {
        *emulator_key_version(emulator, key_no) = des_key_version(new_key);
    }
    mark_key_change_dirty(emulator);
    dfc_secure_wipe(new_key, sizeof(new_key));
    dfc_secure_wipe(crc_input, sizeof(crc_input));
    dfc_secure_wipe(clear, sizeof(clear));

    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
    if(different) {
        // Keep session; response CMAC uses IV left from CBC (last cryptogram block).
        apply_ev1_response_secure_messaging(emulator, DFC_CMD_CHANGE_KEY, tx_buffer);
    }
}

static void handle_change_key(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    DfcByteBuf* tx_buffer) {
    if(apdu_len < 3) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }
    if(!dfc_emulator_native_authentication_active(emulator)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return;
    }

    uint8_t key_no = apdu[1] & 0x3F;
    if(key_no >= emulator_num_keys(emulator)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_NO_SUCH_KEY);
        return;
    }
    if(!can_change_key(emulator, key_no)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }

    const uint8_t* encrypted = apdu + 2;
    size_t encrypted_len = apdu_len - 2;
    uint8_t cipher = emulator->secure_messaging->cipher;
    if(cipher == DFC_CMD_AUTHENTICATE_LEGACY) {
        handle_change_key_d40(emulator, key_no, encrypted, encrypted_len, tx_buffer);
    } else if(cipher == DFC_CMD_AUTHENTICATE_ISO || cipher == DFC_CMD_AUTHENTICATE_AES) {
        handle_change_key_ev1(emulator, key_no, encrypted, encrypted_len, tx_buffer);
    } else {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
    }
}

static size_t unwrap_write_payload(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    size_t header_len,
    uint8_t comm,
    uint8_t* out,
    size_t out_cap);

static void handle_change_key_settings(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    DfcByteBuf* tx_buffer) {
    if(!is_authenticated_as_master(emulator)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return;
    }
    if((current_key_settings_1(emulator) & DFC_KS1_CONFIGURATION_CHANGEABLE) == 0) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }

    const uint8_t* settings = apdu + 1;
    size_t settings_len = apdu_len - 1;
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    bool ev2_active = emulator->ev2_session_active;
#else
    bool ev2_active = false;
#endif
    size_t clear_len = 0;
    if(!ev2_active) {
        clear_len = unwrap_write_payload(
            emulator,
            apdu,
            apdu_len,
            0,
            DFC_COMM_ENCIPHERED,
            emulator->pending_chain,
            sizeof(emulator->pending_chain));
        if(clear_len == SIZE_MAX) {
            dfc_emulator_reset_session(emulator);
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
            return;
        }
        settings = emulator->pending_chain;
        settings_len = clear_len;
    }
    if(settings_len != 1) {
        dfc_secure_wipe(emulator->pending_chain, clear_len);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }

    DfcApplication* app = emulator_current_app(emulator);
    if(app) {
        app->key_settings_1 = settings[0];
    } else {
        emulator->credential->picc_key_settings_1 = settings[0];
    }
    dfc_credential_mark_dirty(emulator->credential);
    dfc_secure_wipe(emulator->pending_chain, clear_len);
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
}

static void handle_get_file_ids(DfcEmulator* emulator, DfcByteBuf* tx_buffer) {
    if(!require_directory_access(emulator, tx_buffer)) return;

    DfcCredential* credential = emulator->credential;
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
    for(size_t i = 0; i < credential->num_files; i++) {
        if(credential->files[i].app_index == emulator->selected_app_index) {
            dfc_bytebuf_append_byte(tx_buffer, credential->files[i].number);
        }
    }
}

static void handle_get_iso_file_ids(DfcEmulator* emulator, DfcByteBuf* tx_buffer) {
    if(!require_directory_access(emulator, tx_buffer)) return;

    DfcCredential* credential = emulator->credential;
    uint8_t fids[DFC_MAX_FILES * 2];
    size_t fids_len = 0;
    for(size_t i = 0; i < credential->num_files; i++) {
        DfcFile* file = &credential->files[i];
        if(file->app_index == emulator->selected_app_index && file->has_iso_file_id) {
            if(fids_len + 2 > sizeof(fids)) break;
            // LE 16-bit ISO file IDs (matches CreateStdDataFile optional FID).
            fids[fids_len++] = (uint8_t)(file->iso_file_id & 0xFF);
            fids[fids_len++] = (uint8_t)(file->iso_file_id >> 8);
        }
    }
    emit_payload_with_chaining(emulator, tx_buffer, DFC_CMD_GET_ISO_FILE_IDS, fids, fids_len, 2);
}

static void
    handle_get_file_settings(DfcEmulator* emulator, const uint8_t* apdu, DfcByteBuf* tx_buffer) {
    if(!require_directory_access(emulator, tx_buffer)) return;

    uint8_t file_no = apdu[1];
    DfcFile* file = dfc_credential_find_file_in_app(
        emulator->credential, emulator->selected_app_index, file_no);
    if(!file) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
        return;
    }

    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
    if(file->type == 0x02) {
        dfc_bytebuf_append_byte(tx_buffer, file->type);
        dfc_bytebuf_append_byte(tx_buffer, file->comm_settings);
        uint8_t rights_wire[2];
        access_rights_to_wire(file->access_rights, rights_wire);
        dfc_bytebuf_append_bytes(tx_buffer, rights_wire, sizeof(rights_wire));
        append_int32_le(tx_buffer, file->value_lower_limit);
        append_int32_le(tx_buffer, file->value_upper_limit);
        // File settings expose the committed reusable limit, not the balance
        // and not a debit that is still pending in the current transaction.
        append_int32_le(tx_buffer, file->limited_credit_value);
        dfc_bytebuf_append_byte(tx_buffer, file->limited_credit);
    } else {
        uint8_t settings[7];
        dfc_encode_standard_data_file_settings(
            file->type, file->comm_settings, file->access_rights, file->data_len, settings);
        dfc_bytebuf_append_bytes(tx_buffer, settings, sizeof(settings));
    }
}

// Unwraps commands that carry a clear header followed by a protected body.
// The caller owns command-IV advancement, so these commands must be deferred
// by the dispatcher. SIZE_MAX means the body failed authentication.
static size_t unwrap_write_payload(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    size_t header_len,
    uint8_t comm,
    uint8_t* out,
    size_t out_cap) {
    size_t cmd_header = 1 + header_len;
    if(apdu_len < cmd_header) return SIZE_MAX;
    const uint8_t* wrapped = apdu + cmd_header;
    size_t wrapped_len = apdu_len - cmd_header;
    if(!dfc_emulator_native_authentication_active(emulator)) {
        if(wrapped_len > out_cap) return SIZE_MAX;
        memcpy(out, wrapped, wrapped_len);
        return wrapped_len;
    }
    bool ev1_sm = dfc_secure_messaging_applies_ev1(emulator->secure_messaging, apdu[0]);
    if(ev1_sm && comm == DFC_COMM_MAC && dfc_secure_messaging_ev1_transmits_command_mac(apdu[0])) {
        size_t clear_body = dfc_secure_messaging_verify_ev1_transmitted_command_mac(
            emulator->secure_messaging, apdu[0], apdu + 1, apdu_len - 1);
        if(clear_body == SIZE_MAX || clear_body < header_len) return SIZE_MAX;
        size_t data_len = clear_body - header_len;
        if(data_len > out_cap) return SIZE_MAX;
        if(data_len) memcpy(out, apdu + cmd_header, data_len);
        return data_len;
    }
    if(ev1_sm && comm == DFC_COMM_ENCIPHERED) {
        size_t data_len = dfc_secure_messaging_verify_command(
            emulator->secure_messaging,
            DFC_COMM_ENCIPHERED,
            apdu,
            cmd_header,
            wrapped,
            wrapped_len,
            out,
            out_cap);
        if(data_len == 0 && wrapped_len > 0) return SIZE_MAX;
        return data_len;
    }
    if(ev1_sm) {
        if(wrapped_len > out_cap) return SIZE_MAX;
        memcpy(out, wrapped, wrapped_len);
        if(!dfc_secure_messaging_update_ev1_command(
               emulator->secure_messaging, apdu[0], apdu + 1, apdu_len - 1)) {
            dfc_secure_wipe(out, wrapped_len);
            return SIZE_MAX;
        }
        return wrapped_len;
    }
    if(comm == DFC_COMM_PLAIN) {
        if(wrapped_len > out_cap) return SIZE_MAX;
        memcpy(out, wrapped, wrapped_len);
        return wrapped_len;
    }
    size_t data_len = dfc_secure_messaging_verify_command(
        emulator->secure_messaging, comm, apdu, cmd_header, wrapped, wrapped_len, out, out_cap);
    if(data_len == 0 && wrapped_len > 0) return SIZE_MAX;
    return data_len;
}

static void apply_change_file_settings(
    DfcEmulator* emulator,
    DfcFile* file,
    const uint8_t* body,
    size_t body_len,
    DfcByteBuf* tx_buffer) {
    size_t key_count = emulator_num_keys(emulator);

    if(body_len != 3) {
#if DFC_ENABLE_SDM
        if(body_len == 0 || (body[0] & DFC_SDM_ENABLED_MASK) == 0) {
#endif
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return;
#if DFC_ENABLE_SDM
        }
#endif
    }
    uint8_t comm_settings = body[0];
    uint16_t access_rights = access_rights_from_wire(body[1], body[2]);
#if DFC_ENABLE_SDM
    const uint8_t* settings = NULL;
    uint8_t sdm_options = 0;
    uint8_t sdm_fields = 0;
    uint16_t sdm_access_rights = 0;
    if((comm_settings & DFC_SDM_ENABLED_MASK) != 0) {
        if(body_len < 3 + DFC_SDM_BASE_SETTINGS_LENGTH) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return;
        }
        settings = body + 3;
        sdm_options = settings[DFC_SDM_OPTIONS_OFFSET];
        sdm_access_rights =
            (uint16_t)(settings[DFC_SDM_ACCESS_RIGHTS_OFFSET] |
                       ((uint16_t)settings[DFC_SDM_ACCESS_RIGHTS_OFFSET + 1] << 8));
        uint8_t meta_read = (uint8_t)(sdm_access_rights >> DFC_SDM_META_READ_SHIFT);
        uint8_t sdm_file_read =
            (uint8_t)((sdm_access_rights >> DFC_SDM_FILE_READ_SHIFT) & DFC_SDM_ACCESS_MASK);
        if(meta_read == DFC_SDM_FREE_ACCESS) {
            if((sdm_options & DFC_SDM_UID_MIRROR_MASK) != 0)
                sdm_fields |= 1u << DfcSdmFieldUidOffset;
            if((sdm_options & DFC_SDM_COUNTER_MIRROR_MASK) != 0)
                sdm_fields |= 1u << DfcSdmFieldCounterOffset;
        } else if(meta_read < DFC_SDM_FREE_ACCESS) {
            sdm_fields |= 1u << DfcSdmFieldPiccDataOffset;
        }
        if(sdm_file_read != DFC_SDM_DENIED_ACCESS) {
            sdm_fields |= (1u << DfcSdmFieldMacInputOffset) | (1u << DfcSdmFieldMacOffset);
            if((sdm_options & DFC_SDM_ENCRYPTED_FILE_MASK) != 0)
                sdm_fields |= (1u << DfcSdmFieldEncryptedFileOffset) |
                              (1u << DfcSdmFieldEncryptedFileLength);
        }
        if((sdm_options & DFC_SDM_COUNTER_LIMIT_MASK) != 0)
            sdm_fields |= 1u << DfcSdmFieldCounterLimit;
        size_t expected_len = 3 + DFC_SDM_BASE_SETTINGS_LENGTH;
        for(uint8_t fields = sdm_fields; fields != 0; fields >>= 1) {
            if((fields & 1u) != 0) expected_len += DFC_SDM_OFFSET_LENGTH;
        }
        if(body_len != expected_len) {
            dfc_bytebuf_append_byte(
                tx_buffer,
                body_len < expected_len ? DFC_STATUS_LENGTH_ERROR : DFC_STATUS_PARAMETER_ERROR);
            return;
        }
        if((sdm_access_rights & 0x00F0u) != 0x00F0u) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
            return;
        }
        if(((sdm_options & (DFC_SDM_UID_MIRROR_MASK | DFC_SDM_COUNTER_MIRROR_MASK)) == 0 &&
            meta_read != DFC_SDM_DENIED_ACCESS) ||
           ((sdm_options & DFC_SDM_UID_MIRROR_MASK) != 0 && meta_read == DFC_SDM_DENIED_ACCESS)) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
            return;
        }
        if((sdm_options & DFC_SDM_ASCII_ENCODING_MASK) == 0) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
            return;
        }
        if((sdm_options & DFC_SDM_COUNTER_MIRROR_MASK) == 0 &&
           (sdm_access_rights & DFC_SDM_ACCESS_MASK) != DFC_SDM_DENIED_ACCESS) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
            return;
        }
        if((sdm_fields & (1u << DfcSdmFieldMacInputOffset)) != 0 && sdm_file_read >= key_count) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
            return;
        }
    }
#endif
    uint32_t key_references = access_rights;
#if DFC_ENABLE_SDM
    if(settings) {
        key_references |= (uint32_t)(sdm_access_rights & 0xF000u) << 4;
        key_references |= (uint32_t)(sdm_access_rights & DFC_SDM_ACCESS_MASK) << 20;
    }
    const size_t reference_count = 6;
#else
    const size_t reference_count = 4;
#endif
    if(!key_references_exist(key_references, reference_count, key_count)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
        return;
    }
    file->comm_settings = comm_settings;
    file->access_rights = access_rights;
#if DFC_ENABLE_SDM
    memset(&file->sdm_resettable, 0, sizeof(file->sdm_resettable));
    if(settings) {
        file->sdm_options = sdm_options;
        file->sdm_access_rights = sdm_access_rights;
        const uint8_t* cursor = settings + DFC_SDM_BASE_SETTINGS_LENGTH;
        for(size_t i = 0; i < DfcSdmFieldCount; i++, sdm_fields >>= 1) {
            if((sdm_fields & 1u) == 0) continue;
            uint32_t value = read_uint24_le(cursor);
            cursor += DFC_SDM_OFFSET_LENGTH;
            (&file->sdm_uid_offset)[i] = value;
            if(i != DfcSdmFieldEncryptedFileLength) {
                bool present = i != DfcSdmFieldCounterOffset ||
                               value != DFC_SDM_HIDDEN_COUNTER_OFFSET;
                size_t has_index = i < DfcSdmFieldEncryptedFileLength ? i : i - 1;
                (&file->sdm_has_uid_offset)[has_index] = present;
            }
        }
        file->sdm_enabled = true;
        file->sdm_read_counter = 0;
    }
    emulator->sdm_read_cache_valid = false;
#endif
    dfc_credential_mark_dirty(emulator->credential);
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
}

static void handle_change_file_settings(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    DfcByteBuf* tx_buffer) {
    DfcFile* file = dfc_credential_find_file_in_app(
        emulator->credential, emulator->selected_app_index, apdu[1]);
    if(!file) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
        return;
    }

    uint8_t change_key = access_change_nibble(file->access_rights);
    if(change_key == DFC_ACCESS_DENY) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
    if(!access_nibble_allows(change_key, emulator)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return;
    }

    const uint8_t* body = apdu + 2;
    size_t body_len = apdu_len - 2;
    size_t clear_len = 0;
    bool ev2_active = false;
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    ev2_active = emulator->ev2_session_active;
#endif
    if(dfc_emulator_native_authentication_active(emulator) && !ev2_active) {
        // Free access stays plain; key-gated settings use the secure-write Full path.
        uint8_t protection = change_key == DFC_ACCESS_FREE ? DFC_COMM_PLAIN : DFC_COMM_ENCIPHERED;
        clear_len = unwrap_write_payload(
            emulator,
            apdu,
            apdu_len,
            1,
            protection,
            emulator->pending_chain,
            sizeof(emulator->pending_chain));
        if(clear_len == SIZE_MAX) {
            dfc_emulator_reset_session(emulator);
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
            return;
        }
        body = emulator->pending_chain;
        body_len = clear_len;
    }

    apply_change_file_settings(emulator, file, body, body_len, tx_buffer);
    dfc_secure_wipe(emulator->pending_chain, clear_len);
}

static bool storage_version_code(const DfcCard* card, uint8_t* code) {
    // Match the legacy 8 KiB capacity of a zeroed, not yet configured card.
    uint32_t storage = card->storage ? card->storage : DFC_EV1_PICC_STORAGE_BYTES;
    // EV3 Tables 108 and 112 list only 2, 4, and 8 KiB devices.
    if(card->generation == DfcGenerationEv3 && storage != 2048 && storage != 4096 &&
       storage != 8192) {
        return false;
    }
    switch(storage) {
    case 1024:
        *code = 0x14;
        return true;
    case 2048:
        *code = 0x16;
        return true;
    case 4096:
        *code = 0x18;
        return true;
    case 8192:
        *code = 0x1A;
        return true;
    case 16384:
        *code = 0x1C;
        return true;
    case 32768:
        *code = 0x1E;
        return true;
    case 65536:
        *code = 0x20;
        return true;
    case 131072:
        *code = 0x22;
        return true;
    default:
        return false;
    }
}

static bool build_default_version_frame(const DfcCard* card, bool software, uint8_t frame[7]) {
    static const uint8_t version[3][2][2] = {
        {{0x01, 0x00}, {0x01, 0x03}},
        {{0x12, 0x00}, {0x02, 0x01}},
        {{0x33, 0x00}, {0x03, 0x00}},
    };
    size_t generation = 0;
    if(card->generation == DfcGenerationEv2) generation = 1;
    if(card->generation == DfcGenerationEv3) generation = 2;
    frame[0] = 0x04;
    frame[1] = 0x01;
    frame[2] = 0x01;
    frame[3] = version[generation][software ? 1 : 0][0];
    frame[4] = version[generation][software ? 1 : 0][1];
    if(!storage_version_code(card, &frame[5])) return false;
    frame[6] = 0x05;
    return true;
}

static void handle_get_version(DfcEmulator* emulator, DfcByteBuf* tx_buffer) {
    uint8_t default_version[7];
    const DfcCard* card = &emulator->credential->card;
    clear_pending_chain(emulator);
    emulator->get_version_frame = 0;
    if(!card->has_hardware_version && !build_default_version_frame(card, false, default_version)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
        return;
    }
    const uint8_t* hardware_version = card->has_hardware_version ? card->hardware_version :
                                                                   default_version;
    emulator->get_version_frame = 1;
    dfc_bytebuf_append_byte(tx_buffer, DFC_CMD_ADDITIONAL_FRAME);
    dfc_bytebuf_append_bytes(tx_buffer, hardware_version, sizeof(default_version));
}

static void handle_get_version_continuation(DfcEmulator* emulator, DfcByteBuf* tx_buffer) {
    static const uint8_t production_legacy[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x24};
    static const uint8_t production_ev3[] = {0x00, 0x00, 0x00, '0', '0', 0x01, 0x24};

    if(emulator->get_version_frame == 1) {
        uint8_t default_version[7];
        const DfcCard* card = &emulator->credential->card;
        if(!card->has_software_version &&
           !build_default_version_frame(card, true, default_version)) {
            emulator->get_version_frame = 0;
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
            return;
        }
        const uint8_t* software_version = card->has_software_version ? card->software_version :
                                                                       default_version;
        emulator->get_version_frame = 2;
        dfc_bytebuf_append_byte(tx_buffer, DFC_CMD_ADDITIONAL_FRAME);
        dfc_bytebuf_append_bytes(tx_buffer, software_version, sizeof(default_version));
        return;
    }

    if(emulator->get_version_frame == 2) {
        emulator->get_version_frame = 0;
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
        if(emulator->credential->picc_random_id) {
            // With random ID enabled this frame carries zeros: the real UID is
            // reachable only through GetCardUID under an authenticated session
            // identifier is generated rather than allocated.
            static const uint8_t zero_uid[DFC_DESFIRE_UID_LEN] = {0};
            dfc_bytebuf_append_bytes(tx_buffer, zero_uid, DFC_DESFIRE_UID_LEN);
        } else {
            dfc_bytebuf_append_bytes(tx_buffer, emulator->credential->uid, DFC_DESFIRE_UID_LEN);
        }
        const uint8_t* production = emulator->credential->card.generation == DfcGenerationEv3 ?
                                        production_ev3 :
                                        production_legacy;
        dfc_bytebuf_append_bytes(tx_buffer, production, sizeof(production_legacy));
        return;
    }

    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_ILLEGAL_COMMAND_CODE);
}

#if DFC_ENABLE_STATIC_SIGNATURE
static void handle_read_signature(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer) {
    if(emulator->credential->card.generation < DfcGenerationEv2) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_ILLEGAL_COMMAND_CODE);
        return;
    }
    if(buffer_len != 2) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }
    if(buffer[1] != 0) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
        return;
    }
    if(!emulator->credential->picc_has_static_signature) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_ILLEGAL_COMMAND_CODE);
        return;
    }
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_SPECIAL_SUCCESS);
    dfc_bytebuf_append_bytes(
        tx_buffer, emulator->credential->picc_static_signature, DFC_STATIC_SIGNATURE_LENGTH);
}
#endif

#if DFC_ENABLE_PROXIMITY_CHECK
static void proximity_abort(DfcEmulator* emulator, DfcByteBuf* tx_buffer, uint8_t status) {
    emulator->proximity_active = false;
    emulator->proximity_offset = 0;
    dfc_secure_wipe(emulator->proximity_random, sizeof(emulator->proximity_random));
    dfc_secure_wipe(emulator->proximity_transcript, sizeof(emulator->proximity_transcript));
    emulator->proximity_transcript_len = 0;
    dfc_bytebuf_append_byte(tx_buffer, status);
}

static bool proximity_wire_mac(
    const uint8_t key[DFC_AES_KEY_LENGTH],
    uint8_t prefix,
    const DfcEmulator* emulator,
    uint8_t output[DFC_WIRE_MAC_LENGTH]) {
    if(!key || !output) return false;
    memset(output, 0, DFC_WIRE_MAC_LENGTH);
    uint8_t input[1 + sizeof(emulator->proximity_published) + DFC_PROXIMITY_TRANSCRIPT_MAX] = {0};
    size_t input_len = 0;
    input[input_len++] = prefix;
    memcpy(input + input_len, emulator->proximity_published, emulator->proximity_published_len);
    input_len += emulator->proximity_published_len;
    memcpy(input + input_len, emulator->proximity_transcript, emulator->proximity_transcript_len);
    input_len += emulator->proximity_transcript_len;

    uint8_t full_mac[DFC_AES_CMAC_LENGTH] = {0};
    bool ok = aes_cmac((uint8_t*)key, DFC_AES_KEY_LENGTH, input, input_len, full_mac);
    if(ok) dfc_truncate_aes_wire_mac(full_mac, output);
    dfc_secure_wipe(input, sizeof(input));
    dfc_secure_wipe(full_mac, sizeof(full_mac));
    return ok;
}

static bool handle_prepare_proximity_check(DfcEmulator* emulator, DfcByteBuf* tx_buffer) {
    DfcCredential* credential = emulator->credential;
    if(!credential->picc_has_proximity_key) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PROXIMITY_KEY_DISABLED);
        return true;
    }

    uint8_t proximity_random[DFC_PROXIMITY_RANDOM_LENGTH] = {0};
    if(!dfc_random_fill(proximity_random, sizeof(proximity_random))) {
        dfc_secure_wipe(proximity_random, sizeof(proximity_random));
        return false;
    }
    memcpy(emulator->proximity_random, proximity_random, sizeof(proximity_random));
    emulator->proximity_offset = 0;
    emulator->proximity_transcript_len = 0;
    emulator->proximity_published[0] = credential->picc_proximity_option;
    emulator->proximity_published[1] =
        (uint8_t)(credential->picc_proximity_published_response_time >> 8);
    emulator->proximity_published[2] = (uint8_t)credential->picc_proximity_published_response_time;
    emulator->proximity_published_len = 1 + DFC_PROXIMITY_PUBLISHED_TIME_LENGTH;
    if(credential->picc_has_proximity_bitrate) {
        emulator->proximity_published[emulator->proximity_published_len++] =
            credential->picc_proximity_bitrate;
    }
    emulator->proximity_active = true;
    emulator->proximity_verified = false;

    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_SPECIAL_SUCCESS);
    dfc_bytebuf_append_bytes(
        tx_buffer, emulator->proximity_published, emulator->proximity_published_len);
    dfc_secure_wipe(proximity_random, sizeof(proximity_random));
    return true;
}

static void handle_proximity_check(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer) {
    if(!emulator->proximity_active) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_ILLEGAL_COMMAND_CODE);
        return;
    }
    if(buffer_len < 2) {
        proximity_abort(emulator, tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }

    size_t round_len = buffer[1];
    if(round_len == 0 || round_len > DFC_PROXIMITY_RANDOM_LENGTH || buffer_len != round_len + 2 ||
       emulator->proximity_offset + round_len > DFC_PROXIMITY_RANDOM_LENGTH ||
       emulator->proximity_transcript_len + round_len * 2 >
           sizeof(emulator->proximity_transcript)) {
        proximity_abort(emulator, tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }

    const uint8_t* response = emulator->proximity_random + emulator->proximity_offset;
    memcpy(
        emulator->proximity_transcript + emulator->proximity_transcript_len, response, round_len);
    emulator->proximity_transcript_len += round_len;
    memcpy(
        emulator->proximity_transcript + emulator->proximity_transcript_len,
        buffer + 2,
        round_len);
    emulator->proximity_transcript_len += round_len;
    emulator->proximity_offset += round_len;

    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_SPECIAL_SUCCESS);
    dfc_bytebuf_append_bytes(tx_buffer, response, round_len);
}

static void handle_verify_proximity_check(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer) {
    if(!emulator->credential->picc_has_proximity_key) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PROXIMITY_KEY_DISABLED);
        return;
    }
    if(!emulator->proximity_active) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_ILLEGAL_COMMAND_CODE);
        return;
    }
    if(emulator->proximity_offset != DFC_PROXIMITY_RANDOM_LENGTH ||
       buffer_len != 1 + DFC_WIRE_MAC_LENGTH) {
        proximity_abort(emulator, tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }

    uint8_t expected[DFC_WIRE_MAC_LENGTH] = {0};
    if(!proximity_wire_mac(
           emulator->credential->picc_proximity_key,
           DFC_CMD_VERIFY_PROXIMITY_CHECK,
           emulator,
           expected)) {
        proximity_abort(emulator, tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        goto cleanup;
    }
    if(!dfc_ct_equal(expected, buffer + 1, sizeof(expected))) {
        proximity_abort(emulator, tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        goto cleanup;
    }

    uint8_t response[DFC_WIRE_MAC_LENGTH] = {0};
    if(!proximity_wire_mac(
           emulator->credential->picc_proximity_key,
           DFC_STATUS_SPECIAL_SUCCESS,
           emulator,
           response)) {
        proximity_abort(emulator, tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        goto cleanup_response;
    }
    emulator->proximity_active = false;
    emulator->proximity_verified = true;
    emulator->proximity_offset = 0;
    emulator->proximity_transcript_len = 0;
    dfc_secure_wipe(emulator->proximity_random, sizeof(emulator->proximity_random));
    dfc_secure_wipe(emulator->proximity_transcript, sizeof(emulator->proximity_transcript));
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_SPECIAL_SUCCESS);
    dfc_bytebuf_append_bytes(tx_buffer, response, sizeof(response));
cleanup_response:
    dfc_secure_wipe(response, sizeof(response));
cleanup:
    dfc_secure_wipe(expected, sizeof(expected));
}
#endif

static void
    reject_authentication_start(DfcEmulator* emulator, DfcByteBuf* tx_buffer, uint8_t status) {
    dfc_emulator_clear_active_authentication(emulator);
    dfc_bytebuf_append_byte(tx_buffer, status);
}

#if DFC_ENABLE_EV2_SECURE_MESSAGING
static void clear_pending_ev2_authentication(DfcEmulator* emulator) {
    emulator->ev2_authentication_pending = false;
    emulator->ev2_authentication_non_first = false;
    emulator->ev2_pending_authenticated_key_no = 0;
    dfc_secure_wipe(emulator->ev2_static_key, sizeof(emulator->ev2_static_key));
    dfc_secure_wipe(emulator->ev2_random_b, sizeof(emulator->ev2_random_b));
    dfc_secure_wipe(
        emulator->ev2_pending_transaction_identifier,
        sizeof(emulator->ev2_pending_transaction_identifier));
    dfc_secure_wipe(
        emulator->ev2_pending_card_capabilities, sizeof(emulator->ev2_pending_card_capabilities));
    dfc_secure_wipe(
        emulator->ev2_pending_reader_capabilities,
        sizeof(emulator->ev2_pending_reader_capabilities));
}

static void fail_pending_ev2_authentication(DfcEmulator* emulator) {
    clear_pending_ev2_authentication(emulator);
    dfc_emulator_clear_active_authentication(emulator);
}

static bool handle_authenticate_ev2_start(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    bool non_first,
    DfcByteBuf* tx_buffer) {
    clear_pending_ev2_authentication(emulator);
    if(emulator->credential->card.generation < DfcGenerationEv2) {
        reject_authentication_start(emulator, tx_buffer, DFC_STATUS_ILLEGAL_COMMAND_CODE);
        return true;
    }
    if((non_first && apdu_len != 2) || (!non_first && apdu_len < 3) ||
       (!non_first && apdu_len != (size_t)3 + apdu[2])) {
        reject_authentication_start(emulator, tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return true;
    }
    if(non_first && !emulator->ev2_session_active) {
        reject_authentication_start(emulator, tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return true;
    }
    uint8_t key_no = apdu[1];
#if DFC_ENABLE_SPECIAL_KEY_STATUS
    if(picc_disabled_special_key(emulator, key_no)) {
        reject_authentication_start(emulator, tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return true;
    }
#endif
    if(!is_available_authentication_key(emulator, key_no) ||
       !emulator_accepts_auth_cipher(
           emulator,
           non_first ? DFC_CMD_AUTHENTICATE_EV2_NON_FIRST : DFC_CMD_AUTHENTICATE_EV2_FIRST)) {
        reject_authentication_start(emulator, tx_buffer, DFC_STATUS_NO_SUCH_KEY);
        return true;
    }

    uint8_t factory[DFC_MAX_KEY_LEN];
    size_t key_len = 0;
    const uint8_t* key = emulator_auth_key(emulator, key_no, factory, sizeof(factory), &key_len);
    if(key_len != DFC_AES_KEY_LENGTH) {
        dfc_secure_wipe(factory, sizeof(factory));
        reject_authentication_start(emulator, tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return true;
    }
    uint8_t random_material[DFC_EV2_RANDOM_LENGTH + DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH];
    size_t random_material_len = non_first ? DFC_EV2_RANDOM_LENGTH : sizeof(random_material);
    if(!dfc_random_fill(random_material, random_material_len)) {
        dfc_secure_wipe(factory, sizeof(factory));
        dfc_secure_wipe(random_material, sizeof(random_material));
        return false;
    }
    const uint8_t* random_b = random_material;
    const uint8_t* transaction_identifier = random_material + DFC_EV2_RANDOM_LENGTH;
    uint8_t iv[DFC_AES_KEY_LENGTH] = {0};
    uint8_t encrypted[DFC_EV2_RANDOM_LENGTH];
    if(!dfc_worker_aes_cbc_encrypt(key, key_len, iv, DFC_EV2_RANDOM_LENGTH, random_b, encrypted)) {
        dfc_secure_wipe(factory, sizeof(factory));
        dfc_secure_wipe(random_material, sizeof(random_material));
        dfc_secure_wipe(iv, sizeof(iv));
        dfc_secure_wipe(encrypted, sizeof(encrypted));
        return false;
    }

    if(non_first) {
        dfc_emulator_retire_ev2_non_first_authentication(emulator);
    } else {
        dfc_emulator_clear_active_authentication(emulator);
    }

    memcpy(emulator->ev2_static_key, key, DFC_AES_KEY_LENGTH);
    emulator->ev2_pending_authenticated_key_no = key_no;
    emulator->ev2_authentication_non_first = non_first;
    emulator->ev2_authentication_pending = true;
    memcpy(emulator->ev2_random_b, random_b, DFC_EV2_RANDOM_LENGTH);
    if(!non_first) {
        memcpy(
            emulator->ev2_pending_transaction_identifier,
            transaction_identifier,
            DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH);
#if DFC_ENABLE_APPLICATION_CAPABILITY_DATA
        DfcApplication* app = dfc_emulator_current_app(emulator);
        if(app && app->has_capability_data) {
            memcpy(
                emulator->ev2_pending_card_capabilities,
                app->capability_data + DFC_APPLICATION_CARD_CAPABILITY_OFFSET,
                DFC_EV2_CAPABILITY_LENGTH);
        } else
#endif
        {
            memset(
                emulator->ev2_pending_card_capabilities,
                0,
                sizeof(emulator->ev2_pending_card_capabilities));
            if(emulator->selected_application == DfcEmulatorSelectedApplicationPicc &&
               emulator->credential->picc_has_ev2_capabilities) {
                memcpy(
                    emulator->ev2_pending_card_capabilities,
                    emulator->credential->picc_ev2_capabilities,
                    DFC_EV2_CAPABILITY_LENGTH);
            }
        }
        memset(
            emulator->ev2_pending_reader_capabilities,
            0,
            sizeof(emulator->ev2_pending_reader_capabilities));
        size_t reader_capability_len = apdu[2];
        if(reader_capability_len > DFC_EV2_CAPABILITY_LENGTH) {
            reader_capability_len = DFC_EV2_CAPABILITY_LENGTH;
        }
        memcpy(emulator->ev2_pending_reader_capabilities, apdu + 3, reader_capability_len);
    }

    dfc_bytebuf_append_byte(tx_buffer, DFC_CMD_ADDITIONAL_FRAME);
    dfc_bytebuf_append_bytes(tx_buffer, encrypted, sizeof(encrypted));
    dfc_secure_wipe(factory, sizeof(factory));
    dfc_secure_wipe(random_material, sizeof(random_material));
    dfc_secure_wipe(iv, sizeof(iv));
    dfc_secure_wipe(encrypted, sizeof(encrypted));
    return true;
}

static void handle_authenticate_ev2_continuation(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    DfcByteBuf* tx_buffer) {
    if(!emulator->ev2_authentication_pending) {
        clear_pending_ev2_authentication(emulator);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return;
    }
    if(apdu_len != 1 + DFC_EV2_AUTHENTICATION_RESPONSE_LENGTH) {
        fail_pending_ev2_authentication(emulator);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return;
    }
    uint8_t iv[DFC_AES_KEY_LENGTH] = {0};
    uint8_t clear[DFC_EV2_AUTHENTICATION_RESPONSE_LENGTH];
    if(!dfc_worker_aes_cbc_decrypt(
           emulator->ev2_static_key, DFC_AES_KEY_LENGTH, iv, sizeof(clear), apdu + 1, clear)) {
        fail_pending_ev2_authentication(emulator);
        dfc_secure_wipe(clear, sizeof(clear));
        dfc_secure_wipe(iv, sizeof(iv));
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        return;
    }
    uint8_t rotated_b[DFC_EV2_RANDOM_LENGTH];
    dfc_ev2_rotate_left(emulator->ev2_random_b, rotated_b);
    if(!dfc_ct_equal(clear + DFC_EV2_RANDOM_LENGTH, rotated_b, sizeof(rotated_b))) {
        fail_pending_ev2_authentication(emulator);
        dfc_secure_wipe(clear, sizeof(clear));
        dfc_secure_wipe(rotated_b, sizeof(rotated_b));
        dfc_secure_wipe(iv, sizeof(iv));
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return;
    }
    uint8_t candidate_random_a[DFC_EV2_RANDOM_LENGTH];
    uint8_t candidate_encryption_key[DFC_AES_KEY_LENGTH];
    uint8_t candidate_mac_key[DFC_AES_KEY_LENGTH];
    memcpy(candidate_random_a, clear, sizeof(candidate_random_a));
    if(!dfc_ev2_derive_session_keys(
           emulator->ev2_static_key,
           candidate_random_a,
           emulator->ev2_random_b,
           candidate_encryption_key,
           candidate_mac_key)) {
        fail_pending_ev2_authentication(emulator);
        dfc_secure_wipe(clear, sizeof(clear));
        dfc_secure_wipe(rotated_b, sizeof(rotated_b));
        dfc_secure_wipe(candidate_random_a, sizeof(candidate_random_a));
        dfc_secure_wipe(candidate_encryption_key, sizeof(candidate_encryption_key));
        dfc_secure_wipe(candidate_mac_key, sizeof(candidate_mac_key));
        dfc_secure_wipe(iv, sizeof(iv));
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        return;
    }

    uint8_t rotated_a[DFC_EV2_RANDOM_LENGTH];
    dfc_ev2_rotate_left(candidate_random_a, rotated_a);
    uint8_t response[DFC_EV2_AUTHENTICATION_RESPONSE_LENGTH] = {0};
    size_t response_len = DFC_EV2_RANDOM_LENGTH;
    if(emulator->ev2_authentication_non_first) {
        memcpy(response, rotated_a, sizeof(rotated_a));
    } else {
        memcpy(
            response,
            emulator->ev2_pending_transaction_identifier,
            DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH);
        memcpy(response + DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH, rotated_a, sizeof(rotated_a));
        memcpy(
            response + DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH + DFC_EV2_RANDOM_LENGTH,
            emulator->ev2_pending_card_capabilities,
            DFC_EV2_CAPABILITY_LENGTH);
        memcpy(
            response + DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH + DFC_EV2_RANDOM_LENGTH +
                DFC_EV2_CAPABILITY_LENGTH,
            emulator->ev2_pending_reader_capabilities,
            DFC_EV2_CAPABILITY_LENGTH);
        response_len = sizeof(response);
    }
    memset(iv, 0, sizeof(iv));
    uint8_t encrypted[DFC_EV2_AUTHENTICATION_RESPONSE_LENGTH];
    if(!dfc_worker_aes_cbc_encrypt(
           emulator->ev2_static_key, DFC_AES_KEY_LENGTH, iv, response_len, response, encrypted)) {
        fail_pending_ev2_authentication(emulator);
        dfc_secure_wipe(candidate_random_a, sizeof(candidate_random_a));
        dfc_secure_wipe(candidate_encryption_key, sizeof(candidate_encryption_key));
        dfc_secure_wipe(candidate_mac_key, sizeof(candidate_mac_key));
        dfc_secure_wipe(clear, sizeof(clear));
        dfc_secure_wipe(rotated_b, sizeof(rotated_b));
        dfc_secure_wipe(rotated_a, sizeof(rotated_a));
        dfc_secure_wipe(response, sizeof(response));
        dfc_secure_wipe(iv, sizeof(iv));
        dfc_secure_wipe(encrypted, sizeof(encrypted));
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        return;
    }
    memcpy(
        emulator->ev2_session_encryption_key,
        candidate_encryption_key,
        sizeof(candidate_encryption_key));
    memcpy(emulator->ev2_session_mac_key, candidate_mac_key, sizeof(candidate_mac_key));
    emulator->ev2_authenticated_key_no = emulator->ev2_pending_authenticated_key_no;
    if(!emulator->ev2_authentication_non_first) {
        memcpy(
            emulator->ev2_transaction_identifier,
            emulator->ev2_pending_transaction_identifier,
            sizeof(emulator->ev2_transaction_identifier));
        memcpy(
            emulator->ev2_card_capabilities,
            emulator->ev2_pending_card_capabilities,
            sizeof(emulator->ev2_card_capabilities));
        memcpy(
            emulator->ev2_reader_capabilities,
            emulator->ev2_pending_reader_capabilities,
            sizeof(emulator->ev2_reader_capabilities));
    }
    emulator->ev2_session_active = true;
    emulator->ev2_command_counter = 0;
    dfc_emulator_commit_auth_family(emulator, DfcEmulatorAuthFamilyEv2);
    dfc_secure_wipe(clear, sizeof(clear));
    dfc_secure_wipe(rotated_b, sizeof(rotated_b));
    dfc_secure_wipe(candidate_random_a, sizeof(candidate_random_a));
    dfc_secure_wipe(candidate_encryption_key, sizeof(candidate_encryption_key));
    dfc_secure_wipe(candidate_mac_key, sizeof(candidate_mac_key));
    dfc_secure_wipe(rotated_a, sizeof(rotated_a));
    dfc_secure_wipe(response, sizeof(response));
    dfc_secure_wipe(iv, sizeof(iv));
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
    dfc_bytebuf_append_bytes(tx_buffer, encrypted, response_len);
    dfc_secure_wipe(encrypted, sizeof(encrypted));
    clear_pending_ev2_authentication(emulator);
}
#endif

// A 3K3DES key answers ISO authentication with sixteen-octet challenges over
// its eight-octet block, which is what its session-key derivation reads.
static size_t auth_challenge_length(uint8_t cipher, size_t key_len) {
    if(cipher == DFC_CMD_AUTHENTICATE_AES) return 16;
    if(cipher == DFC_CMD_AUTHENTICATE_ISO && key_len == 24) return 16;
    return 8;
}

static void clear_pending_authentication(DfcEmulator* emulator) {
    emulator->awaiting_step2 = false;
    emulator->pending_auth_cipher = 0;
    emulator->pending_auth_key_no = 0;
    dfc_secure_wipe(emulator->rnd_b, sizeof(emulator->rnd_b));
    dfc_secure_wipe(emulator->enc_rnd_b, sizeof(emulator->enc_rnd_b));
}

static void fail_pending_authentication(DfcEmulator* emulator) {
    clear_pending_authentication(emulator);
    dfc_emulator_clear_active_authentication(emulator);
}

bool dfc_emulator_abort_pending_native_work(DfcEmulator* emulator) {
    if(!emulator || (!emulator->command_chain_active && !has_pending_additional_work(emulator))) {
        return false;
    }

    dfc_emulator_discard_command_chain(emulator);
    if(emulator->awaiting_step2) {
        fail_pending_authentication(emulator);
    } else {
        clear_pending_authentication(emulator);
    }
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    if(emulator->ev2_authentication_pending) {
        fail_pending_ev2_authentication(emulator);
    } else {
        clear_pending_ev2_authentication(emulator);
    }
#endif
#if DFC_ENABLE_DELEGATED_APPLICATIONS
    emulator->delegated_creation_pending = false;
    emulator->delegated_creation_header_length = 0;
    dfc_secure_wipe(
        emulator->delegated_creation_header, sizeof(emulator->delegated_creation_header));
#endif
    clear_pending_chain(emulator);
    return true;
}

static void handle_authenticate_step1(
    DfcEmulator* emulator,
    uint8_t cipher,
    const uint8_t* apdu,
    DfcByteBuf* tx_buffer) {
    uint8_t key_no = apdu[1];
    clear_pending_authentication(emulator);

#if DFC_ENABLE_SPECIAL_KEY_STATUS
    if(picc_disabled_special_key(emulator, key_no)) {
        reject_authentication_start(emulator, tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
#endif

    if(key_no >= emulator_num_keys(emulator)) {
        DFC_LOG_W(TAG, "Authenticate: key_no %u beyond the key count", key_no);
        reject_authentication_start(emulator, tx_buffer, DFC_STATUS_NO_SUCH_KEY);
        return;
    }
    if(!emulator_accepts_auth_cipher(emulator, cipher)) {
        // A handshake the key type does not answer is an authentication failure,
        // not a missing key: the two statuses say different things and the key
        // number here is perfectly valid.
        DFC_LOG_W(TAG, "Authenticate: cipher %02X not this key type's", cipher);
        reject_authentication_start(emulator, tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return;
    }

    uint8_t factory[DFC_MAX_KEY_LEN];
    size_t key_len = 0;
    const uint8_t* key = emulator_auth_key(emulator, key_no, factory, sizeof(factory), &key_len);
    size_t challenge_len = auth_challenge_length(cipher, key_len);
    uint8_t rnd_b[DFC_EV2_RANDOM_LENGTH];
    if(!dfc_random_fill(rnd_b, challenge_len)) {
        dfc_secure_wipe(factory, sizeof(factory));
        dfc_secure_wipe(rnd_b, sizeof(rnd_b));
        return;
    }

    uint8_t iv[16];
    memset(iv, 0, sizeof(iv));
    uint8_t encrypted[16];
    bool encrypted_ok =
        cipher == DFC_CMD_AUTHENTICATE_AES ?
            dfc_worker_aes_cbc_encrypt(key, key_len, iv, challenge_len, rnd_b, encrypted) :
            dfc_worker_des_cbc_encrypt(key, key_len, iv, challenge_len, rnd_b, encrypted);
    if(!encrypted_ok) {
        dfc_secure_wipe(factory, sizeof(factory));
        dfc_secure_wipe(rnd_b, sizeof(rnd_b));
        dfc_secure_wipe(iv, sizeof(iv));
        dfc_secure_wipe(encrypted, sizeof(encrypted));
        return;
    }
    dfc_emulator_clear_active_authentication(emulator);
    memcpy(emulator->rnd_b, rnd_b, challenge_len);
    memcpy(emulator->enc_rnd_b, encrypted, challenge_len);

    emulator->pending_auth_cipher = cipher;
    emulator->pending_auth_key_no = key_no;
    emulator->awaiting_step2 = true;

    dfc_bytebuf_append_byte(tx_buffer, DFC_CMD_ADDITIONAL_FRAME);
    dfc_bytebuf_append_bytes(tx_buffer, encrypted, challenge_len);
    dfc_secure_wipe(factory, sizeof(factory));
    dfc_secure_wipe(rnd_b, sizeof(rnd_b));
    dfc_secure_wipe(iv, sizeof(iv));
    dfc_secure_wipe(encrypted, sizeof(encrypted));
}

static void handle_authenticate_step2(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    DfcByteBuf* tx_buffer,
    Dfc* dfc) {
    if(!emulator->awaiting_step2) {
        DFC_LOG_W(TAG, "Authenticate step 2: no authentication pending");
        clear_pending_authentication(emulator);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return;
    }
    uint8_t cipher = emulator->pending_auth_cipher;
    size_t block_size = dfc_block_size_for_cipher(cipher);

    uint8_t factory[DFC_MAX_KEY_LEN];
    size_t key_len = 0;
    const uint8_t* key = emulator_auth_key(
        emulator, emulator->pending_auth_key_no, factory, sizeof(factory), &key_len);
    size_t challenge_len = auth_challenge_length(cipher, key_len);

    if(apdu_len != 1 + challenge_len * 2) {
        DFC_LOG_W(TAG, "Authenticate step 2: unexpected frame");
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        fail_pending_authentication(emulator);
        dfc_secure_wipe(factory, sizeof(factory));
        return;
    }

    // ISO and AES chain from the last block of the challenge this card sent.
    uint8_t iv[16];
    memset(iv, 0, sizeof(iv));
    if(cipher != DFC_CMD_AUTHENTICATE_LEGACY) {
        memcpy(iv, emulator->enc_rnd_b + challenge_len - block_size, block_size);
    }

    uint8_t plain[32];
    bool decrypted_ok = true;
    if(cipher == DFC_CMD_AUTHENTICATE_AES) {
        decrypted_ok =
            dfc_worker_aes_cbc_decrypt(key, key_len, iv, challenge_len * 2, apdu + 1, plain);
    } else if(cipher == DFC_CMD_AUTHENTICATE_LEGACY) {
        decrypted_ok = d40_receive_plain(key, key_len, apdu + 1, challenge_len * 2, plain);
    } else {
        decrypted_ok =
            dfc_worker_des_cbc_decrypt(key, key_len, iv, challenge_len * 2, apdu + 1, plain);
    }
    if(!decrypted_ok) {
        fail_pending_authentication(emulator);
        dfc_secure_wipe(plain, sizeof(plain));
        dfc_secure_wipe(iv, sizeof(iv));
        dfc_secure_wipe(factory, sizeof(factory));
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        return;
    }

    uint8_t* rnd_a = plain;
    uint8_t* rnd_b_rot = plain + challenge_len;

    uint8_t expected_rnd_b_rot[16];
    memcpy(expected_rnd_b_rot, emulator->rnd_b, challenge_len);
    dfc_rotate_left(expected_rnd_b_rot, challenge_len);

    if(!dfc_ct_equal(rnd_b_rot, expected_rnd_b_rot, challenge_len)) {
        DFC_LOG_W(TAG, "Authenticate step 2: RndB' mismatch");
        fail_pending_authentication(emulator);
        dfc_secure_wipe(expected_rnd_b_rot, sizeof(expected_rnd_b_rot));
        dfc_secure_wipe(plain, sizeof(plain));
        dfc_secure_wipe(iv, sizeof(iv));
        dfc_secure_wipe(factory, sizeof(factory));
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return;
    }

    uint8_t rnd_a_rot[16];
    memcpy(rnd_a_rot, rnd_a, challenge_len);
    dfc_rotate_left(rnd_a_rot, challenge_len);

    if(cipher == DFC_CMD_AUTHENTICATE_LEGACY) {
        memset(iv, 0, sizeof(iv));
    }

    uint8_t encrypted[16];
    bool response_ok =
        cipher == DFC_CMD_AUTHENTICATE_AES ?
            dfc_worker_aes_cbc_encrypt(key, key_len, iv, challenge_len, rnd_a_rot, encrypted) :
            dfc_worker_des_cbc_encrypt(key, key_len, iv, challenge_len, rnd_a_rot, encrypted);
    if(!response_ok) {
        fail_pending_authentication(emulator);
        dfc_secure_wipe(encrypted, sizeof(encrypted));
        dfc_secure_wipe(rnd_a_rot, sizeof(rnd_a_rot));
        dfc_secure_wipe(expected_rnd_b_rot, sizeof(expected_rnd_b_rot));
        dfc_secure_wipe(plain, sizeof(plain));
        dfc_secure_wipe(iv, sizeof(iv));
        dfc_secure_wipe(factory, sizeof(factory));
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        return;
    }

    uint8_t session_key[DFC_MAX_KEY_LEN];
    size_t session_key_len = 0;
    dfc_derive_session_key(
        cipher, key, key_len, rnd_a, emulator->rnd_b, session_key, &session_key_len);

    DfcSecureMessaging candidate;
    if(!dfc_secure_messaging_init(&candidate, cipher, session_key, session_key_len, NULL)) {
        fail_pending_authentication(emulator);
        dfc_secure_wipe(session_key, sizeof(session_key));
        dfc_secure_wipe(encrypted, sizeof(encrypted));
        dfc_secure_wipe(rnd_a_rot, sizeof(rnd_a_rot));
        dfc_secure_wipe(expected_rnd_b_rot, sizeof(expected_rnd_b_rot));
        dfc_secure_wipe(plain, sizeof(plain));
        dfc_secure_wipe(iv, sizeof(iv));
        dfc_secure_wipe(factory, sizeof(factory));
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        return;
    }
    if(!emulator->secure_messaging) {
        emulator->secure_messaging =
            dfc_secure_messaging_alloc(cipher, session_key, session_key_len, NULL);
        if(!emulator->secure_messaging) {
            fail_pending_authentication(emulator);
            dfc_secure_wipe(&candidate, sizeof(candidate));
            dfc_secure_wipe(session_key, sizeof(session_key));
            dfc_secure_wipe(encrypted, sizeof(encrypted));
            dfc_secure_wipe(rnd_a_rot, sizeof(rnd_a_rot));
            dfc_secure_wipe(expected_rnd_b_rot, sizeof(expected_rnd_b_rot));
            dfc_secure_wipe(plain, sizeof(plain));
            dfc_secure_wipe(iv, sizeof(iv));
            dfc_secure_wipe(factory, sizeof(factory));
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
            return;
        }
    }
    *emulator->secure_messaging = candidate;
    dfc_secure_wipe(&candidate, sizeof(candidate));
    emulator->auth_cipher = cipher;
    emulator->auth_key_no = emulator->pending_auth_key_no;
    memcpy(emulator->rnd_a, rnd_a, challenge_len);
    dfc_emulator_commit_auth_family(emulator, DfcEmulatorAuthFamilyNative);
    clear_pending_authentication(emulator);

    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
    dfc_bytebuf_append_bytes(tx_buffer, encrypted, challenge_len);

    if(dfc) {
        dfc_port_notify(dfc, DfcEventAuthenticated);
    }
    dfc_secure_wipe(session_key, sizeof(session_key));
    dfc_secure_wipe(encrypted, sizeof(encrypted));
    dfc_secure_wipe(rnd_a_rot, sizeof(rnd_a_rot));
    dfc_secure_wipe(expected_rnd_b_rot, sizeof(expected_rnd_b_rot));
    dfc_secure_wipe(plain, sizeof(plain));
    dfc_secure_wipe(iv, sizeof(iv));
    dfc_secure_wipe(factory, sizeof(factory));
}

static void handle_get_application_ids(DfcEmulator* emulator, DfcByteBuf* tx_buffer) {
    if(emulator->selected_application != DfcEmulatorSelectedApplicationPicc) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
    if(!require_directory_access(emulator, tx_buffer)) return;

    uint8_t aids[DFC_MAX_APPS * 3];
    size_t aids_len = 0;
    for(size_t i = 0; i < emulator->credential->num_apps; i++) {
        const DfcApplication* app = &emulator->credential->apps[i];
        aids[aids_len++] = app->aid[2];
        aids[aids_len++] = app->aid[1];
        aids[aids_len++] = app->aid[0];
    }
    emit_payload_with_chaining(
        emulator, tx_buffer, DFC_CMD_GET_APPLICATION_IDS, aids, aids_len, 3);
}

static bool iso_file_id_in_use(const DfcCredential* credential, uint16_t iso_file_id) {
    for(size_t i = 0; i < credential->num_apps; i++) {
        const DfcApplication* app = &credential->apps[i];
        if(app->has_iso_file_id && app->iso_file_id == iso_file_id) return true;
    }
    return false;
}

static bool iso_df_name_in_use(
    const DfcCredential* credential,
    const uint8_t* df_name,
    size_t df_name_len) {
    if(df_name_len == 0) return false;
    for(size_t i = 0; i < credential->num_apps; i++) {
        const DfcApplication* app = &credential->apps[i];
        if(app->iso_aid_len == df_name_len && memcmp(app->iso_aid, df_name, df_name_len) == 0) {
            return true;
        }
    }
    return false;
}

static void handle_create_application(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    DfcByteBuf* tx_buffer) {
    if(emulator->selected_application != DfcEmulatorSelectedApplicationPicc) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
    if(!require_create_delete_access(emulator, tx_buffer)) return;

    // Native payload: AID(3) + KS1 + KS2 [+ ISO FID(2) [+ DF name]]
    if(apdu_len < 6) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }
    size_t payload_len = apdu_len - 1;
    if(payload_len != 5 && payload_len < 7) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }

    DfcCredential* credential = emulator->credential;
    const uint8_t* aid = apdu + 1;
    if(aid[0] == 0x00 && aid[1] == 0x00 && aid[2] == 0x00) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
        return;
    }
    if(dfc_credential_find_application_desfire_order(credential, aid)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_DUPLICATE_ERROR);
        return;
    }

    size_t key_count = apdu[5] & DFC_NUM_KEYS_MASK;
    if(key_count == 0 || key_count > DFC_EV1_MAX_KEYS_PER_APP) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
        return;
    }
    if(credential->num_apps >= DFC_MAX_APPS || credential->num_apps >= DFC_EV1_MAX_APPLICATIONS) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_COUNT_ERROR);
        return;
    }

    size_t optional_offset = 6;
#if DFC_ENABLE_KEY_SETS
    bool has_key_sets = false;
    uint8_t active_key_set_version = DFC_KEY_SET_INITIAL_VERSION;
    uint8_t key_set_count = 1;
    uint8_t max_key_size =
        (uint8_t)dfc_credential_stored_key_length(dfc_credential_key_length(apdu[5]));
    uint8_t key_set_settings = 0;
#endif
    if((apdu[5] & DFC_KS2_EXTENDED_SETTINGS) != 0) {
        if(apdu_len <= optional_offset) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return;
        }
        uint8_t extended_settings = apdu[optional_offset++];
#if DFC_ENABLE_KEY_SETS
        has_key_sets = (extended_settings & DFC_EXTENDED_SETTINGS_KEY_SETS) != 0;
        if(has_key_sets) {
            const size_t key_set_parameter_count = DFC_CREATE_APPLICATION_KEY_SET_PARAMETER_COUNT;
            if(apdu_len < optional_offset + key_set_parameter_count) {
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
                return;
            }
            active_key_set_version = apdu[optional_offset++];
            key_set_count = apdu[optional_offset++];
            max_key_size = apdu[optional_offset++];
            key_set_settings = apdu[optional_offset++];
            size_t active_key_size =
                dfc_credential_stored_key_length(dfc_credential_key_length(apdu[5]));
            if(key_set_count < DFC_KEY_SET_MINIMUM_COUNT || key_set_count > DFC_MAX_KEY_SETS ||
               (max_key_size != DFC_KEY_SET_MAXIMUM_16_BYTE &&
                max_key_size != DFC_KEY_SET_MAXIMUM_24_BYTE) ||
               max_key_size < active_key_size) {
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
                return;
            }
        }
#else
        if((extended_settings & DFC_EXTENDED_SETTINGS_KEY_SETS) != 0) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_ILLEGAL_COMMAND_CODE);
            return;
        }
#endif
    }
    bool has_iso_file_id = apdu_len >= optional_offset + 2;
    uint16_t iso_file_id = 0;
    const uint8_t* df_name = NULL;
    size_t df_name_len = 0;
    if(has_iso_file_id) {
        iso_file_id =
            (uint16_t)(apdu[optional_offset] | ((uint16_t)apdu[optional_offset + 1] << 8));
        if(iso_file_id_in_use(credential, iso_file_id)) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_DUPLICATE_ERROR);
            return;
        }
        if(apdu_len > optional_offset + 2) {
            df_name = apdu + optional_offset + 2;
            df_name_len = apdu_len - (optional_offset + 2);
            if(df_name_len > sizeof(((DfcApplication*)0)->iso_aid)) {
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
                return;
            }
            if(iso_df_name_in_use(credential, df_name, df_name_len)) {
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_DUPLICATE_ERROR);
                return;
            }
        }
    }

    uint8_t key_settings_2 = apdu[5];
    // Presence of app ISO FID implies file ISO FID support (KS2 bit 5).
    if(has_iso_file_id) {
        key_settings_2 = (uint8_t)(key_settings_2 | DFC_KS2_ISO_FILE_IDS);
    }
    DfcApplication* app =
        dfc_credential_create_application_desfire_order(credential, aid, apdu[4], key_settings_2);
    if(!app) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
        return;
    }
    app->has_auth_commands = true;
    app->auth_commands =
        dfc_credential_default_auth_commands(key_settings_2, credential->card.generation) |
        (DFC_ENABLE_ISO7816_AUTH ? DFC_AUTH_COMMAND_ISO7816 : 0);
#if DFC_ENABLE_KEY_SETS
    if(has_key_sets) {
        if(!dfc_credential_key_sets_resize(
               credential,
               app,
               key_set_count,
               key_count,
               dfc_credential_key_length(key_settings_2),
               max_key_size)) {
            size_t app_index = dfc_credential_application_index(credential, app);
            dfc_credential_delete_application_at(credential, app_index);
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OUT_OF_EEPROM);
            return;
        }
        app->key_set_settings = key_set_settings;
        app->key_set_versions[0] = active_key_set_version;
        uint8_t active_type =
            (uint8_t)((key_settings_2 & DFC_KEY_TYPE_MASK) >> DFC_KEY_TYPE_SHIFT);
        for(size_t index = 0; index < app->num_key_sets; index++) {
            app->key_set_types[index] = active_type;
        }
    }
#endif
    if(has_iso_file_id) {
        app->has_iso_file_id = true;
        app->iso_file_id = iso_file_id;
    }
    if(df_name_len > 0) {
        memcpy(app->iso_aid, df_name, df_name_len);
        app->iso_aid_len = df_name_len;
    }
    dfc_credential_mark_dirty(credential);
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
}

static void
    handle_delete_application(DfcEmulator* emulator, const uint8_t* apdu, DfcByteBuf* tx_buffer) {
    DfcCredential* credential = emulator->credential;
    DfcApplication* app = dfc_credential_find_application_desfire_order(credential, apdu + 1);
    if(!app) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_APPLICATION_NOT_FOUND);
        return;
    }

    size_t app_index = dfc_credential_application_index(credential, app);
    bool authorized = false;
    if(emulator->selected_application == DfcEmulatorSelectedApplicationPicc) {
        authorized = is_authenticated_as_master(emulator);
    } else if(
        emulator->selected_application == DfcEmulatorSelectedApplicationApp &&
        emulator->selected_app_index == app_index) {
        authorized = is_authenticated_as_master(emulator);
    }
    if(!authorized) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return;
    }

    dfc_emulator_select_application(emulator, DfcEmulatorSelectedApplicationPicc, 0);
    dfc_credential_delete_application_at(credential, app_index);
    dfc_credential_mark_dirty(credential);
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
}

static bool file_iso_id_in_use(const DfcCredential* credential, uint16_t iso_file_id) {
    for(size_t i = 0; i < credential->num_files; i++) {
        const DfcFile* file = &credential->files[i];
        if(file->has_iso_file_id && file->iso_file_id == iso_file_id) return true;
    }
    return false;
}

static void handle_create_std_data_file(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    uint8_t file_type,
    DfcByteBuf* tx_buffer) {
    if(!require_create_delete_access(emulator, tx_buffer)) return;

    DfcCredential* credential = emulator->credential;
    // Native payload: FileNo + [ISO FID LE 2] + Comm + AR(2) + Size(3)
    // Without ISO FID: 7 bytes; with ISO FID: 9 bytes.
    size_t payload_len = apdu_len - 1;
    bool has_iso_file_id = payload_len == 9;
    if(payload_len != 7 && payload_len != 9) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }

    uint8_t file_no = apdu[1];
    size_t settings_offset = has_iso_file_id ? 4 : 2;
    uint16_t iso_file_id = 0;
    if(has_iso_file_id) {
        DfcApplication* app = emulator_current_app(emulator);
        if(!app || (app->key_settings_2 & DFC_KS2_ISO_FILE_IDS) == 0) {
            // ISO FID only when KS2 bit 5 enabled for the application.
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
            return;
        }
        iso_file_id = (uint16_t)(apdu[2] | ((uint16_t)apdu[3] << 8));
        if(file_iso_id_in_use(credential, iso_file_id)) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_DUPLICATE_ERROR);
            return;
        }
    }

    if(file_no > DFC_EV1_MAX_FILE_NUMBER) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
        return;
    }
    if(dfc_credential_find_file_in_app(credential, emulator->selected_app_index, file_no)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_DUPLICATE_ERROR);
        return;
    }
    if(dfc_credential_count_files_in_app(credential, emulator->selected_app_index) >=
           DFC_EV1_MAX_FILES_PER_APP ||
       credential->num_files >= DFC_MAX_FILES) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_COUNT_ERROR);
        return;
    }

    uint8_t comm_settings = apdu[settings_offset];
    uint16_t access_rights =
        access_rights_from_wire(apdu[settings_offset + 1], apdu[settings_offset + 2]);
    uint32_t file_size = read_uint24_le(apdu + settings_offset + 3);
    if(file_size > DFC_MAX_FILE_DATA || file_size > DFC_FILE_POOL_SIZE) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OUT_OF_EEPROM);
        return;
    }
    if(file_size > dfc_credential_file_pool_free(credential) ||
       !has_card_file_capacity(credential, file_size)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OUT_OF_EEPROM);
        return;
    }

    DfcFile* file = dfc_credential_create_file(credential, emulator->selected_app_index, file_no);
    if(!file) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
        return;
    }
    file->type = file_type;
    file->comm_settings = comm_settings;
    file->access_rights = access_rights;
    if(has_iso_file_id) {
        file->has_iso_file_id = true;
        file->iso_file_id = iso_file_id;
    }
    if(!dfc_file_set_data_size(credential, file, file_size)) {
        (void)dfc_credential_delete_file(credential, emulator->selected_app_index, file_no);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OUT_OF_EEPROM);
        return;
    }
    if(!dfc_emulator_transaction_snapshot_insert_file(
           emulator, (size_t)(file - credential->files))) {
        (void)dfc_credential_delete_file(credential, emulator->selected_app_index, file_no);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OUT_OF_EEPROM);
        return;
    }
    dfc_credential_mark_dirty(credential);
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
}

#if DFC_ENABLE_RECORD_FILES
static void handle_create_record_file(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    uint8_t file_type,
    DfcByteBuf* tx_buffer) {
    if(!require_create_delete_access(emulator, tx_buffer)) return;

    size_t payload_len = apdu_len - 1;
    bool has_iso_file_id = payload_len == 12;
    if(payload_len != 10 && payload_len != 12) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }

    DfcCredential* credential = emulator->credential;
    uint8_t file_no = apdu[1];
    size_t settings_offset = has_iso_file_id ? 4 : 2;
    if(file_no > DFC_EV1_MAX_FILE_NUMBER) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
        return;
    }
    if(dfc_credential_find_file_in_app(credential, emulator->selected_app_index, file_no)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_DUPLICATE_ERROR);
        return;
    }

    uint16_t iso_file_id = 0;
    if(has_iso_file_id) {
        DfcApplication* app = emulator_current_app(emulator);
        if(!app || (app->key_settings_2 & DFC_KS2_ISO_FILE_IDS) == 0) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
            return;
        }
        iso_file_id = (uint16_t)(apdu[2] | ((uint16_t)apdu[3] << 8));
        if(file_iso_id_in_use(credential, iso_file_id)) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_DUPLICATE_ERROR);
            return;
        }
    }

    uint32_t record_size = read_uint24_le(apdu + settings_offset + 3);
    uint32_t max_records = read_uint24_le(apdu + settings_offset + 6);
    uint64_t allocation = (uint64_t)record_size * max_records;
    if(file_type == DFC_FILE_TYPE_CYCLIC_RECORD && max_records == 1) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
        return;
    }
    if(record_size == 0 || max_records == 0 || allocation > DFC_MAX_FILE_DATA ||
       allocation > dfc_credential_file_pool_free(credential) ||
       !has_card_file_capacity(credential, (size_t)allocation)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OUT_OF_EEPROM);
        return;
    }

    DfcFile* file = dfc_credential_create_file(credential, emulator->selected_app_index, file_no);
    if(!file) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_COUNT_ERROR);
        return;
    }
    file->type = file_type;
    file->comm_settings = apdu[settings_offset];
    file->access_rights =
        access_rights_from_wire(apdu[settings_offset + 1], apdu[settings_offset + 2]);
    file->record_size = record_size;
    file->max_records = max_records;
    file->record_count = 0;
    if(has_iso_file_id) {
        file->has_iso_file_id = true;
        file->iso_file_id = iso_file_id;
    }
    if(!dfc_file_resize(credential, file, (size_t)allocation)) {
        (void)dfc_credential_delete_file(credential, emulator->selected_app_index, file_no);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OUT_OF_EEPROM);
        return;
    }
    if(!dfc_emulator_transaction_snapshot_insert_file(
           emulator, (size_t)(file - credential->files))) {
        (void)dfc_credential_delete_file(credential, emulator->selected_app_index, file_no);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OUT_OF_EEPROM);
        return;
    }
    dfc_credential_mark_dirty(credential);
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
}
#endif

static void
    handle_create_value_file(DfcEmulator* emulator, const uint8_t* apdu, DfcByteBuf* tx_buffer) {
    if(!require_create_delete_access(emulator, tx_buffer)) return;

    DfcCredential* credential = emulator->credential;
    uint8_t file_no = apdu[1];
    if(file_no > DFC_EV1_MAX_FILE_NUMBER) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
        return;
    }
    if(dfc_credential_find_file_in_app(credential, emulator->selected_app_index, file_no)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_DUPLICATE_ERROR);
        return;
    }
    if(dfc_credential_count_files_in_app(credential, emulator->selected_app_index) >=
           DFC_EV1_MAX_FILES_PER_APP ||
       credential->num_files >= DFC_MAX_FILES) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_COUNT_ERROR);
        return;
    }

    int32_t lower_limit = read_int32_le(apdu + 5);
    int32_t upper_limit = read_int32_le(apdu + 9);
    int32_t value = read_int32_le(apdu + 13);
    if(lower_limit > upper_limit || value < lower_limit || value > upper_limit) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
        return;
    }

    DfcFile* file = dfc_credential_create_file(credential, emulator->selected_app_index, file_no);
    if(!file) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
        return;
    }
    file->type = 0x02;
    file->comm_settings = apdu[2];
    file->access_rights = access_rights_from_wire(apdu[3], apdu[4]);
    file->value_lower_limit = lower_limit;
    file->value_upper_limit = upper_limit;
    file->value = value;
    file->limited_credit = apdu[17];
    file->limited_credit_value = 0;
    file->limited_credit_pending = 0;
    file->value_pending = false;
    file->value_pending_delta = 0;
    file->value_pending_value = 0;
    file->value_pending_absolute = false;
    if(!dfc_emulator_transaction_snapshot_insert_file(
           emulator, (size_t)(file - credential->files))) {
        (void)dfc_credential_delete_file(credential, emulator->selected_app_index, file_no);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OUT_OF_EEPROM);
        return;
    }
    dfc_credential_mark_dirty(credential);
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
}

static void handle_delete_file(DfcEmulator* emulator, const uint8_t* apdu, DfcByteBuf* tx_buffer) {
    if(!require_create_delete_access(emulator, tx_buffer)) return;

    uint8_t file_no = apdu[1];
    DfcFile* file = dfc_credential_find_file_in_app(
        emulator->credential, emulator->selected_app_index, file_no);
    bool deletes_transaction_mac = file && file->type == DFC_FILE_TYPE_TRANSACTION_MAC;
    if(deletes_transaction_mac) {
        (void)dfc_emulator_abort_transaction(emulator);
    } else if(file) {
        dfc_emulator_transaction_snapshot_delete_file(
            emulator, (size_t)(file - emulator->credential->files));
    }
    if(dfc_credential_delete_file(emulator->credential, emulator->selected_app_index, file_no)) {
        dfc_credential_mark_dirty(emulator->credential);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
        return;
    }

    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
}

static void handle_get_value(DfcEmulator* emulator, const uint8_t* apdu, DfcByteBuf* tx_buffer) {
    DfcFile* file = dfc_credential_find_file_in_app(
        emulator->credential, emulator->selected_app_index, apdu[1]);
    if(!file) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
        return;
    }
    if(file->type != 0x02) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
    if(!file_allows_read(file, emulator)) {
        dfc_bytebuf_append_byte(tx_buffer, file_access_refusal_status(file, false));
        return;
    }

    uint8_t value_bytes[4] = {0};
    uint32_t raw = (uint32_t)file->value;
    value_bytes[0] = (uint8_t)(raw & 0xFF);
    value_bytes[1] = (uint8_t)((raw >> 8) & 0xFF);
    value_bytes[2] = (uint8_t)((raw >> 16) & 0xFF);
    value_bytes[3] = (uint8_t)((raw >> 24) & 0xFF);

    uint8_t comm = dfc_emulator_file_effective_comm_settings(
        emulator, file, DfcFileAccessRead, file->comm_settings);
    bool ev1_sm = dfc_emulator_native_authentication_active(emulator) &&
                  dfc_secure_messaging_applies_ev1(emulator->secure_messaging, DFC_CMD_GET_VALUE);

    bool protect_here = dfc_emulator_native_authentication_active(emulator) &&
                        comm != DFC_COMM_PLAIN && (!ev1_sm || comm == DFC_COMM_ENCIPHERED);
    if(protect_here) {
        uint8_t wrapped[DFC_SM_MAX_CIPHER_BLOCK_SIZE] = {0};
        size_t wrapped_len = dfc_secure_messaging_generate_response(
            emulator->secure_messaging,
            comm,
            DFC_STATUS_OK,
            value_bytes,
            sizeof(value_bytes),
            wrapped,
            sizeof(wrapped));
        dfc_secure_wipe(value_bytes, sizeof(value_bytes));
        if(wrapped_len == 0) {
            dfc_secure_wipe(wrapped, sizeof(wrapped));
            dfc_emulator_reset_session(emulator);
            dfc_bytebuf_reset(tx_buffer);
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
            return;
        }
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
        dfc_bytebuf_append_bytes(tx_buffer, wrapped, wrapped_len);
        emulator->response_secured = true;
        dfc_secure_wipe(wrapped, sizeof(wrapped));
        return;
    }

    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
    dfc_bytebuf_append_bytes(tx_buffer, value_bytes, sizeof(value_bytes));
    dfc_secure_wipe(value_bytes, sizeof(value_bytes));
}

#if DFC_ENABLE_TRANSACTION_MAC
static bool transaction_input_append_segments(
    DfcEmulator* emulator,
    const DfcCryptoSegment* segments,
    size_t segment_count) {
    size_t entry_len = 0;
    for(size_t i = 0; i < segment_count; i++) {
        if((segments[i].length && !segments[i].data) || segments[i].length > SIZE_MAX - entry_len)
            return false;
        entry_len += segments[i].length;
    }
    if(entry_len > SIZE_MAX - (DFC_AES_KEY_LENGTH - 1)) return false;
    size_t padded_len =
        ((entry_len + DFC_AES_KEY_LENGTH - 1) / DFC_AES_KEY_LENGTH) * DFC_AES_KEY_LENGTH;
    if(emulator->transaction_input_len > sizeof(emulator->transaction_input) ||
       padded_len > sizeof(emulator->transaction_input) - emulator->transaction_input_len)
        return false;

    size_t offset = emulator->transaction_input_len;
    for(size_t i = 0; i < segment_count; i++) {
        if(segments[i].length) {
            memcpy(emulator->transaction_input + offset, segments[i].data, segments[i].length);
            offset += segments[i].length;
        }
    }
    memset(emulator->transaction_input + offset, 0, padded_len - entry_len);
    emulator->transaction_input_len += padded_len;
    return true;
}
#endif

static void handle_value_delta(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    DfcByteBuf* tx_buffer,
    uint8_t cmd,
    bool debit,
    bool limited_credit) {
    DfcFile* file = dfc_credential_find_file_in_app(
        emulator->credential, emulator->selected_app_index, apdu[1]);
    if(!file) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
        return;
    }
    if(file->type != 0x02) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
    if(!file_allows_write(file, emulator)) {
        dfc_bytebuf_append_byte(tx_buffer, file_access_refusal_status(file, true));
        return;
    }

    // Native body after cmd: FileNo || Amount(4) [|| MACt / Enc(Amount)].
    const uint8_t* body = apdu + 1;
    size_t body_len = apdu_len - 1;
    int32_t amount = 0;

    if(dfc_emulator_native_authentication_active(emulator) &&
       dfc_secure_messaging_applies_ev1(emulator->secure_messaging, cmd)) {
        uint8_t comm = dfc_emulator_file_effective_comm_settings(
            emulator, file, DfcFileAccessWrite, file->comm_settings);
        if(comm == DFC_COMM_MAC && dfc_secure_messaging_ev1_transmits_command_mac(cmd)) {
            size_t clear_len = dfc_secure_messaging_verify_ev1_transmitted_command_mac(
                emulator->secure_messaging, cmd, body, body_len);
            if(clear_len == SIZE_MAX || clear_len < 5) {
                dfc_emulator_reset_session(emulator);
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
                return;
            }
            amount = read_int32_le(body + 1);
        } else if(comm == DFC_COMM_ENCIPHERED) {
            // Full: clear FileNo + encrypted Amount. CRC covers Cmd||FileNo||Amount.
            if(body_len < 1 + 8) {
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
                return;
            }
            uint8_t header[2] = {cmd, body[0]};
            if(body_len - 1 > DFC_SM_MAX_CIPHER_BLOCK_SIZE) {
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
                return;
            }
            uint8_t clear[DFC_SM_MAX_CIPHER_BLOCK_SIZE];
            size_t clear_len = dfc_secure_messaging_verify_command(
                emulator->secure_messaging,
                DFC_COMM_ENCIPHERED,
                header,
                sizeof(header),
                body + 1,
                body_len - 1,
                clear,
                sizeof(clear));
            if(clear_len < 4) {
                dfc_emulator_reset_session(emulator);
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
                return;
            }
            amount = read_int32_le(clear);
        } else {
            if(!dfc_secure_messaging_update_ev1_command(
                   emulator->secure_messaging, cmd, body, body_len)) {
                dfc_emulator_reset_session(emulator);
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
                return;
            }
            if(body_len < 5) {
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
                return;
            }
            amount = read_int32_le(body + 1);
        }
    } else if(
        dfc_emulator_native_authentication_active(emulator) &&
        !dfc_secure_messaging_applies_ev1(emulator->secure_messaging, cmd)) {
        // D40: Amount may be MAC/ENC under file comm mode.
        uint8_t comm = dfc_emulator_file_effective_comm_settings(
            emulator, file, DfcFileAccessWrite, file->comm_settings);
        if(body_len < 1) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return;
        }
        if(body_len - 1 > DFC_SM_MAX_CIPHER_BLOCK_SIZE) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return;
        }
        uint8_t clear[DFC_SM_MAX_CIPHER_BLOCK_SIZE];
        uint8_t header[2] = {cmd, body[0]};
        size_t clear_len = dfc_secure_messaging_verify_command(
            emulator->secure_messaging,
            comm,
            header,
            sizeof(header),
            body + 1,
            body_len - 1,
            clear,
            sizeof(clear));
        if(clear_len < 4 && comm != DFC_COMM_PLAIN) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
            return;
        }
        if(comm == DFC_COMM_PLAIN) {
            if(body_len < 5) {
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
                return;
            }
            amount = read_int32_le(body + 1);
        } else {
            amount = read_int32_le(clear);
        }
    } else {
        if(body_len < 5) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return;
        }
        amount = read_int32_le(body + 1);
    }

    if(amount < 0) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
        return;
    }

    int32_t delta = debit ? -amount : amount;
    if(limited_credit) {
        if((file->limited_credit & 0x01u) == 0) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
            return;
        }
        int32_t available = file->limited_credit_pending > 0 ? file->limited_credit_pending :
                                                               file->limited_credit_value;
        if(file->limited_credit_pending == DFC_LIMITED_CREDIT_TRANSACTION_CONSUMED ||
           amount > available) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
            return;
        }
    }
    int32_t next_value;
    if(!value_delta_result(file, delta, &next_value)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        return;
    }

#if DFC_ENABLE_TRANSACTION_MAC
    DfcCryptoSegment transaction_segments[] = {
        {.data = &cmd, .length = 1},
        {.data = apdu + 1, .length = 5},
    };
    if(!transaction_input_append_segments(emulator, transaction_segments, 2)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        return;
    }
#endif
    int64_t aggregate = (int64_t)next_value - file->value;
    file->value_pending = true;
    file->value_pending_value = next_value;
    file->value_pending_absolute = true;
    file->value_pending_delta = aggregate > INT32_MAX ? INT32_MAX :
                                aggregate < INT32_MIN ? INT32_MIN :
                                                        (int32_t)aggregate;
    if(limited_credit) {
        file->limited_credit_pending = DFC_LIMITED_CREDIT_TRANSACTION_CONSUMED;
    } else if(debit && file->limited_credit_pending >= 0) {
        if(amount > INT32_MAX - file->limited_credit_pending) {
            file->limited_credit_pending = INT32_MAX;
        } else {
            file->limited_credit_pending += amount;
        }
    }
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
}

#if DFC_ENABLE_TRANSACTION_MAC
static DfcFile* transaction_mac_file(DfcEmulator* emulator) {
    return dfc_credential_find_transaction_mac_file(
        emulator->credential, emulator->selected_app_index);
}

static bool transaction_mac_file_create_ready(
    DfcEmulator* emulator,
    uint8_t file_number,
    DfcByteBuf* tx_buffer) {
    DfcCredential* credential = emulator->credential;
    if(file_number > DFC_EV1_MAX_FILE_NUMBER ||
       dfc_credential_find_file_in_app(credential, emulator->selected_app_index, file_number)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
        return false;
    }
    if(dfc_credential_count_files_in_app(credential, emulator->selected_app_index) >=
           DFC_EV1_MAX_FILES_PER_APP ||
       credential->num_files >= DFC_MAX_FILES) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_COUNT_ERROR);
        return false;
    }
    if(credential->file_pool_used > DFC_FILE_POOL_SIZE ||
       DFC_TRANSACTION_MAC_FILE_LENGTH > DFC_FILE_POOL_SIZE - credential->file_pool_used) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OUT_OF_EEPROM);
        return false;
    }
    return true;
}

static void handle_create_transaction_mac_file(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer) {
    if(!require_create_delete_access(emulator, tx_buffer)) return;

    const size_t command_length = 1 + 5 + DFC_AES_KEY_LENGTH + 1;
    if(buffer_len != command_length || transaction_mac_file(emulator)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
        return;
    }
    const DfcApplication* app = &emulator->credential->apps[emulator->selected_app_index];
    uint16_t access_rights = access_rights_from_wire(buffer[3], buffer[4]);
    if(!dfc_communication_settings_is_valid(buffer[2]) ||
       !dfc_transaction_mac_access_rights_are_valid(access_rights, app->num_keys) ||
       !dfc_transaction_mac_key_type_is_valid(buffer[5])) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
        return;
    }
    if(!transaction_mac_file_create_ready(emulator, buffer[1], tx_buffer)) return;

    /* No fallible operation remains after the transaction boundary moves. */
    (void)dfc_emulator_abort_transaction(emulator);
    DfcFile* file =
        dfc_credential_create_file(emulator->credential, emulator->selected_app_index, buffer[1]);
    DFC_ASSERT(file);
    bool resized = dfc_file_resize(emulator->credential, file, DFC_TRANSACTION_MAC_FILE_LENGTH);
    DFC_ASSERT(resized);
    DFC_UNUSED(resized);
    file->number = buffer[1];
    file->type = DFC_FILE_TYPE_TRANSACTION_MAC;
    file->comm_settings = buffer[2];
    file->access_rights = access_rights;
    file->transaction_mac_key_type = buffer[5];
    file->declared_size = DFC_TRANSACTION_MAC_FILE_LENGTH;
    file->contents_complete = true;
    memcpy(file->transaction_mac_key, buffer + 6, DFC_AES_KEY_LENGTH);
    file->transaction_mac_key_version = buffer[6 + DFC_AES_KEY_LENGTH];
    dfc_credential_mark_dirty(emulator->credential);
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
}

static bool transaction_mac_calculate(
    DfcEmulator* emulator,
    DfcFile* file,
    uint8_t mac[DFC_WIRE_MAC_LENGTH],
    uint32_t* next_counter) {
    if(file->transaction_counter == UINT32_MAX) {
        memset(mac, 0, DFC_WIRE_MAC_LENGTH);
        return false;
    }
    *next_counter = file->transaction_counter + 1;
    uint8_t vector[DFC_AES_KEY_LENGTH] = {0};
    vector[0] = DFC_TRANSACTION_MAC_DERIVATION_LABEL;
    vector[1] = DFC_DERIVATION_COUNTER_HIGH;
    vector[2] = DFC_DERIVATION_COUNTER_LOW;
    vector[3] = DFC_DERIVED_AES_KEY_LENGTH_HIGH;
    vector[4] = DFC_DERIVED_AES_KEY_LENGTH_LOW;
    write_uint32_le(vector + DFC_TRANSACTION_VECTOR_COUNTER_OFFSET, *next_counter);
    memcpy(
        vector + DFC_TRANSACTION_VECTOR_UID_OFFSET,
        emulator->credential->uid,
        emulator->credential->uid_len);
    uint8_t session_key[DFC_AES_CMAC_LENGTH] = {0};
    uint8_t full_mac[DFC_AES_CMAC_LENGTH] = {0};
    bool ok =
        aes_cmac(
            file->transaction_mac_key, DFC_AES_KEY_LENGTH, vector, sizeof(vector), session_key) &&
        aes_cmac(
            session_key,
            DFC_AES_KEY_LENGTH,
            emulator->transaction_input,
            emulator->transaction_input_len,
            full_mac);
    if(ok) {
        dfc_truncate_aes_wire_mac(full_mac, mac);
    } else {
        memset(mac, 0, DFC_WIRE_MAC_LENGTH);
    }
    dfc_secure_wipe(vector, sizeof(vector));
    dfc_secure_wipe(session_key, sizeof(session_key));
    dfc_secure_wipe(full_mac, sizeof(full_mac));
    return ok;
}

static bool transaction_pending_reader_id(
    const DfcEmulator* emulator,
    uint8_t reader_id[DFC_TRANSACTION_READER_ID_LENGTH]) {
    bool found = false;
    size_t offset = 0;
    while(offset < emulator->transaction_input_len) {
        size_t entry_len = DFC_AES_KEY_LENGTH;
        if(emulator->transaction_input[offset] == DFC_CMD_COMMIT_READER_ID) {
            entry_len = 3 * DFC_AES_KEY_LENGTH;
            if(entry_len > emulator->transaction_input_len - offset) return false;
            memcpy(
                reader_id,
                emulator->transaction_input + offset + 1,
                DFC_TRANSACTION_READER_ID_LENGTH);
            found = true;
        }
        if(entry_len > emulator->transaction_input_len - offset) return false;
        offset += entry_len;
    }
    return found;
}

static void handle_commit_reader_id(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer) {
    DfcFile* file = transaction_mac_file(emulator);
    if(!file) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
        return;
    }
    if(buffer_len != 1 + DFC_TRANSACTION_READER_ID_LENGTH) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }
    if(file->transaction_counter == UINT32_MAX) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        return;
    }
    uint32_t next_counter = file->transaction_counter + 1;
    uint8_t vector[DFC_AES_KEY_LENGTH] = {0};
    vector[0] = DFC_TRANSACTION_ENCRYPTION_DERIVATION_LABEL;
    vector[1] = DFC_DERIVATION_COUNTER_HIGH;
    vector[2] = DFC_DERIVATION_COUNTER_LOW;
    vector[3] = DFC_DERIVED_AES_KEY_LENGTH_HIGH;
    vector[4] = DFC_DERIVED_AES_KEY_LENGTH_LOW;
    write_uint32_le(vector + DFC_TRANSACTION_VECTOR_COUNTER_OFFSET, next_counter);
    memcpy(
        vector + DFC_TRANSACTION_VECTOR_UID_OFFSET,
        emulator->credential->uid,
        emulator->credential->uid_len);
    uint8_t session_key[DFC_AES_KEY_LENGTH] = {0};
    uint8_t zero_iv[DFC_AES_KEY_LENGTH] = {0};
    uint8_t encrypted[DFC_TRANSACTION_READER_ID_LENGTH] = {0};
    if(!aes_cmac(
           file->transaction_mac_key, DFC_AES_KEY_LENGTH, vector, sizeof(vector), session_key)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        goto cleanup;
    }
    if(!dfc_worker_aes_cbc_encrypt(
           session_key,
           DFC_AES_KEY_LENGTH,
           zero_iv,
           sizeof(file->previous_reader_id),
           file->previous_reader_id,
           encrypted)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        goto cleanup;
    }
    const uint8_t command = DFC_CMD_COMMIT_READER_ID;
    DfcCryptoSegment transaction_segments[] = {
        {.data = &command, .length = 1},
        {.data = buffer + 1, .length = DFC_TRANSACTION_READER_ID_LENGTH},
        {.data = encrypted, .length = sizeof(encrypted)},
    };
    if(!transaction_input_append_segments(emulator, transaction_segments, 3)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        goto cleanup;
    }
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
    dfc_bytebuf_append_bytes(tx_buffer, encrypted, sizeof(encrypted));
cleanup:
    dfc_secure_wipe(vector, sizeof(vector));
    dfc_secure_wipe(session_key, sizeof(session_key));
    dfc_secure_wipe(zero_iv, sizeof(zero_iv));
    dfc_secure_wipe(encrypted, sizeof(encrypted));
}
#endif

#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
enum {
    RecordTransactionNone = 0,
    RecordTransactionWrite,
    RecordTransactionUpdate,
    RecordTransactionClear,
};

static bool transaction_snapshot_begin(DfcEmulator* emulator) {
    if(emulator->transaction_snapshot_active) {
        return emulator->transaction_snapshot_app_index == emulator->selected_app_index;
    }

    size_t length = emulator->credential->file_pool_used;
    uint8_t* snapshot = dfc_platform_alloc(length ? length : 1, DfcAllocEmulator);
    if(!snapshot) return false;
    emulator->transaction_snapshot_pool = snapshot;
    emulator->transaction_snapshot_active = true;
    emulator->transaction_snapshot_app_index = emulator->selected_app_index;
    emulator->transaction_snapshot_pool_length = length;
    emulator->transaction_snapshot_dirty = emulator->credential->dirty;
    memcpy(
        emulator->transaction_snapshot_pool,
        emulator->credential->file_pool,
        emulator->transaction_snapshot_pool_length);
    for(size_t index = 0; index < emulator->credential->num_files; index++) {
        const DfcFile* file = &emulator->credential->files[index];
        emulator->transaction_snapshot_record_counts[index] =
            (file->type == DFC_FILE_TYPE_LINEAR_RECORD ||
             file->type == DFC_FILE_TYPE_CYCLIC_RECORD) ?
                file->record_count :
                0;
    }
    memset(
        emulator->transaction_record_operations,
        RecordTransactionNone,
        sizeof(emulator->transaction_record_operations));
    memset(emulator->transaction_record_numbers, 0, sizeof(emulator->transaction_record_numbers));
    return true;
}

static size_t transaction_file_index(const DfcEmulator* emulator, const DfcFile* file) {
    return (size_t)(file - emulator->credential->files);
}

static uint8_t transaction_record_operation(const DfcEmulator* emulator, const DfcFile* file) {
    size_t index = transaction_file_index(emulator, file);
    return index < DFC_MAX_FILES ? emulator->transaction_record_operations[index] :
                                   RecordTransactionNone;
}

static void transaction_set_record_operation(
    DfcEmulator* emulator,
    const DfcFile* file,
    uint8_t operation,
    uint32_t record_number) {
    size_t index = transaction_file_index(emulator, file);
    if(index >= DFC_MAX_FILES) return;
    emulator->transaction_record_operations[index] = operation;
    emulator->transaction_record_numbers[index] = record_number;
}
#endif

static void handle_commit_transaction(
    DfcEmulator* emulator,
    bool return_transaction_mac,
    DfcByteBuf* tx_buffer) {
    bool changed = false;
#if DFC_ENABLE_TRANSACTION_MAC
    if(emulator->transaction_input_len > 0) changed = true;
#endif
    for(size_t i = 0; i < emulator->credential->num_files; i++) {
        DfcFile* file = &emulator->credential->files[i];
        if(file->app_index != emulator->selected_app_index) continue;
        if((file->type == DFC_FILE_TYPE_VALUE && file->value_pending) || file->transaction_pending)
            changed = true;
    }

    if(!changed) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_NO_CHANGES);
        return;
    }

#if DFC_ENABLE_TRANSACTION_MAC
    DfcFile* transaction_file = transaction_mac_file(emulator);
    uint8_t mac[DFC_WIRE_MAC_LENGTH] = {0};
    uint8_t pending_reader_id[DFC_TRANSACTION_READER_ID_LENGTH] = {0};
    bool has_pending_reader_id = transaction_pending_reader_id(emulator, pending_reader_id);
    uint32_t next_counter = 0;
    if(transaction_file) {
        if(!transaction_mac_calculate(emulator, transaction_file, mac, &next_counter)) {
            dfc_secure_wipe(mac, sizeof(mac));
            dfc_secure_wipe(pending_reader_id, sizeof(pending_reader_id));
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
            return;
        }
    }
#else
    DFC_UNUSED(return_transaction_mac);
#endif

    dfc_emulator_publish_transaction(emulator);
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
#if DFC_ENABLE_TRANSACTION_MAC
    if(transaction_file) {
        if(has_pending_reader_id) {
            memcpy(
                transaction_file->previous_reader_id,
                pending_reader_id,
                sizeof(transaction_file->previous_reader_id));
        }
        transaction_file->transaction_counter = next_counter;
        if(return_transaction_mac) {
            const uint8_t counter[] = {
                (uint8_t)next_counter,
                (uint8_t)(next_counter >> 8),
                (uint8_t)(next_counter >> 16),
                (uint8_t)(next_counter >> 24),
            };
            dfc_bytebuf_append_bytes(tx_buffer, counter, sizeof(counter));
            dfc_bytebuf_append_bytes(tx_buffer, mac, sizeof(mac));
        }
    }
    dfc_secure_wipe(mac, sizeof(mac));
    dfc_secure_wipe(pending_reader_id, sizeof(pending_reader_id));
#endif
}

static void handle_abort_transaction(DfcEmulator* emulator, DfcByteBuf* tx_buffer) {
    bool changed = dfc_emulator_abort_transaction(emulator);
    dfc_bytebuf_append_byte(tx_buffer, changed ? DFC_STATUS_OK : DFC_STATUS_NO_CHANGES);
}

#if DFC_ENABLE_KEY_SETS
static bool key_set_change_authorized(const DfcEmulator* emulator, const DfcApplication* app) {
    uint8_t access = (uint8_t)((app->key_settings_1 & DFC_KS1_CHANGE_KEY_ACCESS_MASK) >>
                               DFC_KS1_CHANGE_KEY_ACCESS_SHIFT);
    if(access == DFC_CHANGE_KEY_ACCESS_FROZEN) return false;
    if(access == DFC_CHANGE_KEY_ACCESS_SAME) return is_authenticated_with_key(emulator, 0);
    return access < app->num_keys && is_authenticated_with_key(emulator, access);
}

static DfcApplication* key_set_target_application(
    DfcEmulator* emulator,
    uint8_t key_set_selector,
    DfcByteBuf* tx_buffer) {
    if(emulator->selected_application != DfcEmulatorSelectedApplicationApp) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return NULL;
    }
    if((key_set_selector & DFC_KEY_SET_SECOND_APPLICATION_MASK) != 0) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return NULL;
    }
    DfcApplication* app = emulator_current_app(emulator);
    if(!app || app->num_key_sets <= 1) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_NO_SUCH_KEY);
        return NULL;
    }
    size_t key_set_number = key_set_selector & DFC_KEY_SET_NUMBER_MASK;
    if(key_set_number == 0) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
        return NULL;
    }
    if(key_set_number >= app->num_key_sets) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_NO_SUCH_KEY);
        return NULL;
    }
    return app;
}

static void handle_initialize_key_set(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer) {
    if(buffer_len != 3) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }
    DfcApplication* app = key_set_target_application(emulator, buffer[1], tx_buffer);
    if(!app) return;
    if(!key_set_change_authorized(emulator, app)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return;
    }
    uint8_t target_type = buffer[2];
    if((target_type & (uint8_t)~DFC_KEY_SET_TYPE_MASK) != 0 ||
       target_type > DFC_KEY_SET_TYPE_AES ||
       dfc_key_set_type_length(target_type) > app->max_key_size) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
        return;
    }
    size_t key_set_number = buffer[1] & DFC_KEY_SET_NUMBER_MASK;
    size_t storage_length = dfc_credential_stored_key_length(app->key_storage_len);
    size_t source_length = dfc_key_set_type_length(app->key_set_types[0]);
    size_t target_length = dfc_key_set_type_length(target_type);
    size_t copy_length = source_length < target_length ? source_length : target_length;
    for(size_t slot = 0; slot < app->num_keys; slot++) {
        uint8_t* target =
            dfc_credential_key_in_set(emulator->credential, app, key_set_number, slot);
        const uint8_t* source =
            dfc_credential_key_in_set_const(emulator->credential, app, 0, slot);
        uint8_t* target_version = dfc_credential_key_version_in_set(app, key_set_number, slot);
        if(!target || !source || !target_version) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OUT_OF_EEPROM);
            return;
        }
        memset(target, 0, storage_length);
        memcpy(target, source, copy_length);
        *target_version = app->key_versions[slot];
    }
    app->key_set_types[key_set_number] = target_type;
    app->key_set_versions[key_set_number] = DFC_KEY_SET_INITIAL_VERSION;
    app->key_set_initialized[key_set_number] = true;
    dfc_credential_mark_dirty(emulator->credential);
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
}

static void handle_finalize_key_set(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer) {
    if(buffer_len != 3) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }
    DfcApplication* app = key_set_target_application(emulator, buffer[1], tx_buffer);
    if(!app) return;
    if(!key_set_change_authorized(emulator, app)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return;
    }
    size_t key_set_number = buffer[1] & DFC_KEY_SET_NUMBER_MASK;
    if(buffer[2] == DFC_KEY_SET_INITIAL_VERSION) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
        return;
    }
    if(!app->key_set_initialized[key_set_number] ||
       app->key_set_versions[key_set_number] != DFC_KEY_SET_INITIAL_VERSION) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
    app->key_set_versions[key_set_number] = buffer[2];
    dfc_credential_mark_dirty(emulator->credential);
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
}

static void handle_roll_key_set(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer) {
    if(buffer_len != 2) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }
    DfcApplication* app = key_set_target_application(emulator, buffer[1], tx_buffer);
    if(!app) return;
    uint8_t roll_key = app->key_set_settings & DFC_KEY_SET_NUMBER_MASK;
    if(roll_key >= app->num_keys || !is_authenticated_with_key(emulator, roll_key)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return;
    }
    size_t key_set_number = buffer[1] & DFC_KEY_SET_NUMBER_MASK;
    if(app->key_set_versions[key_set_number] <= app->key_set_versions[0] ||
       app->key_set_types[key_set_number] < app->key_set_types[0]) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
    if(!dfc_credential_roll_key_set(emulator->credential, app, key_set_number)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OUT_OF_EEPROM);
        return;
    }
    handle_abort_transaction(emulator, tx_buffer);
    dfc_bytebuf_reset(tx_buffer);
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
    dfc_credential_mark_dirty(emulator->credential);
    dfc_emulator_reset_session(emulator);
    emulator->ev2_response_plain = true;
}

static bool change_key_ev2_length_valid(size_t buffer_len) {
    if(buffer_len < DFC_CHANGE_KEY_EV2_HEADER_LENGTH) return false;
    size_t cryptogram_length = buffer_len - DFC_CHANGE_KEY_EV2_HEADER_LENGTH;
    return cryptogram_length == DFC_CHANGE_KEY_EV2_AES_SHORT_CRYPTOGRAM_LENGTH ||
           cryptogram_length == DFC_CHANGE_KEY_EV2_AES_CRYPTOGRAM_LENGTH ||
           cryptogram_length == DFC_CHANGE_KEY_EV2_LONG_CRYPTOGRAM_LENGTH;
}

static void handle_change_key_ev2(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer) {
    if(emulator->selected_application != DfcEmulatorSelectedApplicationApp) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
    if(!emulator->ev2_session_active) {
        if(!change_key_ev2_length_valid(buffer_len)) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return;
        }
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return;
    }
    if(buffer_len != DFC_CHANGE_KEY_EV2_SAME_KEY_CLEAR_LENGTH &&
       buffer_len != DFC_CHANGE_KEY_EV2_OTHER_KEY_CLEAR_LENGTH) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }

    DfcApplication* app = emulator_current_app(emulator);
    uint8_t key_set_selector = buffer[1];
    uint8_t key_number = buffer[2];
    if(!app || (key_set_selector & DFC_KEY_SET_SECOND_APPLICATION_MASK) != 0 ||
       key_number >= app->num_keys) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_NO_SUCH_KEY);
        return;
    }
    size_t key_set_number = key_set_selector & DFC_KEY_SET_NUMBER_MASK;
    if(key_set_number >= app->num_key_sets || !app->key_set_initialized[key_set_number]) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_NO_SUCH_KEY);
        return;
    }
    if(!key_set_change_authorized(emulator, app)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return;
    }
    if(app->key_set_types[key_set_number] != DFC_KEY_SET_TYPE_AES) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
        return;
    }

    bool changes_authenticated_key = key_set_number == 0 &&
                                     key_number == emulator->ev2_authenticated_key_no;
    size_t expected_len = changes_authenticated_key ? DFC_CHANGE_KEY_EV2_SAME_KEY_CLEAR_LENGTH :
                                                      DFC_CHANGE_KEY_EV2_OTHER_KEY_CLEAR_LENGTH;
    if(buffer_len != expected_len) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }

    uint8_t* stored_key =
        dfc_credential_key_in_set(emulator->credential, app, key_set_number, key_number);
    uint8_t* stored_version = dfc_credential_key_version_in_set(app, key_set_number, key_number);
    if(!stored_key || !stored_version) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OUT_OF_EEPROM);
        return;
    }

    const uint8_t* clear_key = buffer + DFC_CHANGE_KEY_EV2_HEADER_LENGTH;
    uint8_t new_key[DFC_AES_KEY_LENGTH];
    if(changes_authenticated_key) {
        memcpy(new_key, clear_key, sizeof(new_key));
    } else {
        for(size_t i = 0; i < sizeof(new_key); i++)
            new_key[i] = clear_key[i] ^ stored_key[i];
        const uint8_t* crc_bytes =
            clear_key + DFC_AES_KEY_LENGTH + DFC_CHANGE_KEY_EV2_VERSION_LENGTH;
        uint32_t supplied_crc = (uint32_t)read_int32_le(crc_bytes);
        if(supplied_crc != crc32_dfc(new_key, sizeof(new_key))) {
            dfc_secure_wipe(new_key, sizeof(new_key));
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
            return;
        }
    }

    if(changes_authenticated_key) dfc_emulator_retire_authentication(emulator);
    memcpy(stored_key, new_key, sizeof(new_key));
    *stored_version = clear_key[DFC_AES_KEY_LENGTH];
    mark_key_change_dirty(emulator);
    dfc_secure_wipe(new_key, sizeof(new_key));
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
    if(changes_authenticated_key) emulator->ev2_response_plain = true;
}
#endif

#if DFC_ENABLE_DELEGATED_APPLICATIONS
static uint16_t delegated_application_overhead_blocks(uint8_t num_keys, size_t key_length) {
    if(num_keys == 0)
        return DFC_APPLICATION_GENERAL_OVERHEAD_BLOCKS + DFC_DELEGATED_APPLICATION_OVERHEAD_BLOCKS;

    uint16_t key_storage_units = (uint16_t)num_keys * (key_length > DFC_AES_KEY_LENGTH ?
                                                           DFC_KEY_STORAGE_UNITS_PER_24_BYTE_KEY :
                                                           DFC_KEY_STORAGE_UNITS_PER_16_BYTE_KEY);
    uint16_t key_data_blocks =
        (uint16_t)((key_storage_units + DFC_KEY_STORAGE_KEYS_PER_DATA_BLOCK - 1) /
                   DFC_KEY_STORAGE_KEYS_PER_DATA_BLOCK);
    uint16_t key_index_blocks = DFC_KEY_STORAGE_INDEX_BLOCKS;
    if(num_keys > DFC_KEY_STORAGE_SECOND_INDEX_THRESHOLD) key_index_blocks++;
    if(num_keys > DFC_KEY_STORAGE_THIRD_INDEX_THRESHOLD) key_index_blocks++;

    return DFC_APPLICATION_GENERAL_OVERHEAD_BLOCKS + DFC_DELEGATED_APPLICATION_OVERHEAD_BLOCKS +
           key_index_blocks + key_data_blocks;
}

static void handle_create_delegated_application(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer) {
    if(buffer_len < DFC_DELEGATED_CREATE_HEADER_LENGTH ||
       buffer_len > DFC_DELEGATED_CREATE_MAX_HEADER_LENGTH) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }
    memcpy(emulator->delegated_creation_header, buffer, buffer_len);
    emulator->delegated_creation_header_length = buffer_len;
    emulator->delegated_creation_pending = true;
    dfc_bytebuf_append_byte(tx_buffer, DFC_CMD_ADDITIONAL_FRAME);
}

static bool delegated_wire_mac(
    const uint8_t key[DFC_AES_KEY_LENGTH],
    const uint8_t* data,
    size_t data_len,
    uint8_t output[DFC_DELEGATED_MAC_LENGTH]) {
    if(!output) return false;
    memset(output, 0, DFC_DELEGATED_MAC_LENGTH);
    if(!key || (data_len != 0 && !data)) return false;
    uint8_t full_mac[DFC_AES_CMAC_LENGTH] = {0};
    if(!aes_cmac((uint8_t*)key, DFC_AES_KEY_LENGTH, (uint8_t*)data, data_len, full_mac)) {
        dfc_secure_wipe(full_mac, sizeof(full_mac));
        return false;
    }
    for(size_t index = 0; index < DFC_DELEGATED_MAC_LENGTH; index++)
        output[index] = full_mac[(index * 2) + 1];
    dfc_secure_wipe(full_mac, sizeof(full_mac));
    return true;
}

static void handle_create_delegated_application_continuation(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer) {
    uint8_t chained_data
        [DFC_DELEGATED_CREATE_MAX_HEADER_LENGTH - 1 + DFC_DELEGATED_ENCRYPTED_KEY_LENGTH +
         DFC_DELEGATED_MAC_LENGTH] = {0};
    uint8_t dam_input[DFC_DELEGATED_CREATE_MAX_HEADER_LENGTH + DFC_DELEGATED_ENCRYPTED_KEY_LENGTH] =
        {0};
    uint8_t expected_dam_mac[DFC_DELEGATED_MAC_LENGTH] = {0};
    uint8_t initial_key_data[DFC_DELEGATED_ENCRYPTED_KEY_LENGTH] = {0};
    uint8_t zero_iv[DFC_AES_KEY_LENGTH] = {0};
    uint8_t secured_response[1 + DFC_WIRE_MAC_LENGTH] = {0};
    DfcByteBuf* create_response = NULL;
    size_t created_app_index = SIZE_MAX;
    bool credential_was_dirty = emulator->credential->dirty;
    bool success = false;
    emulator->delegated_creation_pending = false;
    if(buffer_len != DFC_DELEGATED_SECOND_FRAME_LENGTH + DFC_WIRE_MAC_LENGTH) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        goto cleanup;
    }
    if(!emulator->credential->picc_has_dam_keys || !emulator->ev2_session_active ||
       emulator->ev2_authenticated_key_no != DFC_DAM_AUTH_KEY_NUMBER) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        goto cleanup;
    }

    const uint8_t* encrypted_key = buffer + 1;
    const uint8_t* dam_mac = encrypted_key + DFC_DELEGATED_ENCRYPTED_KEY_LENGTH;
    const uint8_t* secure_mac = dam_mac + DFC_DELEGATED_MAC_LENGTH;
    size_t chained_data_len = emulator->delegated_creation_header_length - 1;
    memcpy(chained_data, emulator->delegated_creation_header + 1, chained_data_len);
    memcpy(
        chained_data + chained_data_len,
        encrypted_key,
        DFC_DELEGATED_ENCRYPTED_KEY_LENGTH + DFC_DELEGATED_MAC_LENGTH);
    chained_data_len += DFC_DELEGATED_ENCRYPTED_KEY_LENGTH + DFC_DELEGATED_MAC_LENGTH;
    if(!dfc_ev2_verify_chained_command_mac(
           emulator,
           DFC_CMD_CREATE_DELEGATED_APPLICATION,
           chained_data,
           chained_data_len,
           secure_mac)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        goto cleanup;
    }

    size_t dam_input_len = emulator->delegated_creation_header_length;
    memcpy(dam_input, emulator->delegated_creation_header, dam_input_len);
    memcpy(dam_input + dam_input_len, encrypted_key, DFC_DELEGATED_ENCRYPTED_KEY_LENGTH);
    dam_input_len += DFC_DELEGATED_ENCRYPTED_KEY_LENGTH;
    if(!delegated_wire_mac(
           emulator->credential->picc_dam_mac_key, dam_input, dam_input_len, expected_dam_mac) ||
       !dfc_ct_equal(expected_dam_mac, dam_mac, sizeof(expected_dam_mac))) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        goto cleanup;
    }

    if(!dfc_worker_aes_cbc_decrypt(
           emulator->credential->picc_dam_encryption_key,
           DFC_AES_KEY_LENGTH,
           zero_iv,
           sizeof(initial_key_data),
           encrypted_key,
           initial_key_data)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        goto cleanup;
    }

    const uint8_t* header = emulator->delegated_creation_header;
    uint8_t key_settings_2 = header[DFC_DELEGATED_KEY_SETTINGS_2_OFFSET];
    uint8_t num_keys = key_settings_2 & DFC_NUM_KEYS_MASK;
    size_t key_length = (key_settings_2 & DFC_KEY_TYPE_MASK) == DFC_KEY_TYPE_3K3DES ?
                            DFC_MAX_KEY_LEN :
                            DFC_AES_KEY_LENGTH;
    uint16_t quota_limit = (uint16_t)(header[DFC_DELEGATED_QUOTA_OFFSET] |
                                      ((uint16_t)header[DFC_DELEGATED_QUOTA_OFFSET + 1] << 8));
    uint16_t overhead_blocks = delegated_application_overhead_blocks(num_keys, key_length);
    if(quota_limit < overhead_blocks) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        goto cleanup;
    }
    uint8_t create_command[] = {
        DFC_CMD_CREATE_APPLICATION,
        header[DFC_DELEGATED_AID_OFFSET],
        header[DFC_DELEGATED_AID_OFFSET + 1],
        header[DFC_DELEGATED_AID_OFFSET + 2],
        header[DFC_DELEGATED_KEY_SETTINGS_1_OFFSET],
        key_settings_2,
    };
    create_response = dfc_bytebuf_alloc(DFC_WORKER_MAX_BUFFER_SIZE);
    if(!create_response) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OUT_OF_EEPROM);
        goto cleanup;
    }
    handle_create_application(emulator, create_command, sizeof(create_command), create_response);
    const uint8_t* create_status = dfc_bytebuf_get_data(create_response);
    if(dfc_bytebuf_get_size_bytes(create_response) != 1 || create_status[0] != DFC_STATUS_OK) {
        dfc_bytebuf_append_byte(
            tx_buffer,
            dfc_bytebuf_get_size_bytes(create_response) == 1 ? create_status[0] :
                                                               DFC_STATUS_PARAMETER_ERROR);
        goto cleanup;
    }
    dfc_bytebuf_free(create_response);
    create_response = NULL;
    if(emulator->credential->num_apps == 0) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OUT_OF_EEPROM);
        goto cleanup;
    }
    created_app_index = emulator->credential->num_apps - 1;

    DfcApplication* app = dfc_credential_find_application_desfire_order(
        emulator->credential, header + DFC_DELEGATED_AID_OFFSET);
    if(!app) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OUT_OF_EEPROM);
        goto cleanup;
    }
    const uint8_t* initial_key = initial_key_data + DFC_DELEGATED_RANDOM_PREFIX_LENGTH;
    uint8_t initial_version = initial_key_data[DFC_DELEGATED_ENCRYPTED_KEY_LENGTH - 1];
    for(size_t key_number = 0; key_number < app->num_keys; key_number++) {
        uint8_t* key = dfc_credential_key(emulator->credential, app, key_number);
        if(key) memcpy(key, initial_key, app->key_len);
        app->key_versions[key_number] = initial_version;
    }
    app->delegated = true;
    app->delegated_slot_number =
        (uint16_t)(header[DFC_DELEGATED_SLOT_OFFSET] |
                   ((uint16_t)header[DFC_DELEGATED_SLOT_OFFSET + 1] << 8));
    app->delegated_slot_version = header[DFC_DELEGATED_SLOT_VERSION_OFFSET];
    app->delegated_quota_limit = quota_limit;
    app->delegated_free_blocks = quota_limit - overhead_blocks;
    const uint8_t clear_command[] = {DFC_CMD_CREATE_DELEGATED_APPLICATION};
    const uint8_t clear_response[] = {DFC_STATUS_OK};
    size_t secured_response_len = 0;
    if(!dfc_ev2_protect_response(
           emulator,
           clear_command,
           sizeof(clear_command),
           clear_response,
           sizeof(clear_response),
           secured_response,
           sizeof(secured_response),
           &secured_response_len)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        goto cleanup;
    }
    dfc_bytebuf_append_bytes(tx_buffer, secured_response, secured_response_len);
    success = true;

cleanup:
    if(create_response) dfc_bytebuf_free(create_response);
    if(!success && created_app_index != SIZE_MAX) {
        dfc_credential_delete_application_at(emulator->credential, created_app_index);
        emulator->credential->dirty = credential_was_dirty;
    }
    dfc_secure_wipe(chained_data, sizeof(chained_data));
    dfc_secure_wipe(dam_input, sizeof(dam_input));
    dfc_secure_wipe(expected_dam_mac, sizeof(expected_dam_mac));
    dfc_secure_wipe(initial_key_data, sizeof(initial_key_data));
    dfc_secure_wipe(zero_iv, sizeof(zero_iv));
    dfc_secure_wipe(secured_response, sizeof(secured_response));
    dfc_secure_wipe(
        emulator->delegated_creation_header, sizeof(emulator->delegated_creation_header));
    emulator->delegated_creation_header_length = 0;
}

static void handle_get_delegated_info(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer) {
    if(buffer_len != DFC_DELEGATED_INFO_COMMAND_LENGTH) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }
    if(emulator->selected_application != DfcEmulatorSelectedApplicationPicc) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
    uint16_t slot_number = (uint16_t)(buffer[1] | ((uint16_t)buffer[2] << 8));
    for(size_t index = 0; index < emulator->credential->num_apps; index++) {
        const DfcApplication* app = &emulator->credential->apps[index];
        if(!app->delegated || app->delegated_slot_number != slot_number) continue;
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
        dfc_bytebuf_append_byte(tx_buffer, app->delegated_slot_version);
        dfc_bytebuf_append_byte(tx_buffer, (uint8_t)app->delegated_quota_limit);
        dfc_bytebuf_append_byte(tx_buffer, (uint8_t)(app->delegated_quota_limit >> 8));
        dfc_bytebuf_append_byte(tx_buffer, (uint8_t)app->delegated_free_blocks);
        dfc_bytebuf_append_byte(tx_buffer, (uint8_t)(app->delegated_free_blocks >> 8));
        dfc_bytebuf_append_byte(tx_buffer, app->aid[2]);
        dfc_bytebuf_append_byte(tx_buffer, app->aid[1]);
        dfc_bytebuf_append_byte(tx_buffer, app->aid[0]);
        return;
    }
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_APPLICATION_NOT_FOUND);
}
#endif

#if DFC_ENABLE_TRANSACTION_TIMER
static void handle_set_configuration(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer) {
    if(buffer_len != DFC_SET_CONFIGURATION_CAPABILITY_COMMAND_LENGTH) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }
    if(buffer[DFC_SET_CONFIGURATION_OPTION_OFFSET] != DFC_CONFIGURATION_APPLICATION_CAPABILITIES) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
        return;
    }
    if(!emulator->ev2_session_active ||
       emulator->ev2_authenticated_key_no != DFC_MASTER_KEY_NUMBER) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return;
    }
    DfcApplication* app = dfc_emulator_current_app(emulator);
    if(!app) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
    memcpy(
        app->capability_data,
        buffer + DFC_SET_CONFIGURATION_DATA_OFFSET,
        DFC_APPLICATION_CAPABILITY_DATA_LENGTH);
    app->has_capability_data = true;
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
}
#endif

static void clear_selected_app_pending_values(DfcEmulator* emulator) {
    for(size_t i = 0; i < emulator->credential->num_files; i++) {
        DfcFile* file = &emulator->credential->files[i];
        if(file->app_index != emulator->selected_app_index || file->type != DFC_FILE_TYPE_VALUE) {
            continue;
        }
        file->value_pending = false;
        file->value_pending_delta = 0;
        file->value_pending_value = 0;
        file->value_pending_absolute = false;
        file->limited_credit_pending = 0;
    }
#if DFC_ENABLE_TRANSACTION_MAC
    dfc_secure_wipe(emulator->transaction_input, sizeof(emulator->transaction_input));
    emulator->transaction_input_len = 0;
#endif
}

#if DFC_ENABLE_SDM
static void sdm_write_ascii_hex(uint8_t* output, const uint8_t* input, size_t input_len) {
    static const uint8_t alphabet[] = "0123456789ABCDEF";
    for(size_t i = 0; i < input_len; i++) {
        output[i * DFC_SDM_HEX_EXPANSION] = alphabet[input[i] >> 4];
        output[(i * DFC_SDM_HEX_EXPANSION) + 1] = alphabet[input[i] & 0x0F];
    }
}

static bool sdm_derive_key(
    const uint8_t* static_key,
    uint8_t label_high,
    uint8_t label_low,
    const DfcCredential* credential,
    const DfcFile* file,
    uint32_t counter,
    uint8_t output[DFC_AES_KEY_LENGTH]) {
    uint8_t vector[DFC_AES_KEY_LENGTH * 2] = {0};
    size_t length = 0;
    const uint8_t prefix[] = {
        label_high,
        label_low,
        DFC_DERIVATION_COUNTER_HIGH,
        DFC_DERIVATION_COUNTER_LOW,
        DFC_DERIVED_AES_KEY_LENGTH_HIGH,
        DFC_DERIVED_AES_KEY_LENGTH_LOW,
    };
    memcpy(vector, prefix, sizeof(prefix));
    length += sizeof(prefix);
    if((file->sdm_options & DFC_SDM_UID_MIRROR_MASK) != 0) {
        memcpy(vector + length, credential->uid, credential->uid_len);
        length += credential->uid_len;
    }
    uint8_t meta_read = (uint8_t)(file->sdm_access_rights >> DFC_SDM_META_READ_SHIFT);
    bool includes_counter = (file->sdm_options & DFC_SDM_COUNTER_MIRROR_MASK) != 0 &&
                            (meta_read != DFC_SDM_FREE_ACCESS || file->sdm_has_counter_offset);
    if(includes_counter) {
        vector[length++] = (uint8_t)counter;
        vector[length++] = (uint8_t)(counter >> 8);
        vector[length++] = (uint8_t)(counter >> 16);
    }
    length = ((length + DFC_AES_KEY_LENGTH - 1) / DFC_AES_KEY_LENGTH) * DFC_AES_KEY_LENGTH;
    bool success = aes_cmac((uint8_t*)static_key, DFC_AES_KEY_LENGTH, vector, length, output);
    dfc_secure_wipe(vector, sizeof(vector));
    if(!success && output) dfc_secure_wipe(output, DFC_AES_KEY_LENGTH);
    return success;
}

static bool sdm_range_fits(const DfcFile* file, uint32_t offset, size_t length) {
    return offset <= file->data_len && length <= file->data_len - offset;
}

static bool render_sdm_read_in_place(DfcEmulator* emulator, DfcFile* file) {
    if(emulator->sdm_read_cache_valid && emulator->sdm_read_cache_file_number == file->number)
        return true;
    bool success = false;
    size_t pending_scratch_len = 0;
    uint8_t picc_clear[DFC_SDM_PICC_DATA_BLOCK_LENGTH * 2] = {0};
    uint8_t picc_encrypted[DFC_SDM_PICC_DATA_BLOCK_LENGTH * 2] = {0};
    uint8_t session_mac_key[DFC_AES_KEY_LENGTH] = {0};
    uint8_t full_mac[DFC_AES_CMAC_LENGTH] = {0};
    uint8_t wire_mac[DFC_WIRE_MAC_LENGTH] = {0};
    uint8_t session_encryption_key[DFC_AES_KEY_LENGTH] = {0};
    uint8_t counter_block[DFC_AES_KEY_LENGTH] = {0};
    uint8_t picc_iv[DFC_AES_KEY_LENGTH] = {0};
    uint8_t zero_iv[DFC_AES_KEY_LENGTH] = {0};
    uint8_t file_iv[DFC_AES_KEY_LENGTH] = {0};

    if(file->sdm_read_counter >= 0xFFFFFFu) goto cleanup;
    if(file->data_len > sizeof(emulator->sdm_read_cache)) goto cleanup;
    size_t picc_clear_len = emulator->credential->uid_len == DFC_DESFIRE_UID_MAX_LENGTH ?
                                DFC_SDM_PICC_DATA_BLOCK_LENGTH * 2 :
                                DFC_SDM_PICC_DATA_BLOCK_LENGTH;
    if(file->sdm_has_uid_offset &&
       !sdm_range_fits(
           file, file->sdm_uid_offset, emulator->credential->uid_len * DFC_SDM_HEX_EXPANSION))
        goto cleanup;
    if(file->sdm_has_counter_offset && !sdm_range_fits(file, file->sdm_counter_offset, 6))
        goto cleanup;
    if(file->sdm_has_picc_data_offset &&
       !sdm_range_fits(file, file->sdm_picc_data_offset, picc_clear_len * DFC_SDM_HEX_EXPANSION))
        goto cleanup;
    if(file->sdm_has_mac_input_offset && file->sdm_has_mac_offset &&
       (file->sdm_mac_offset < file->sdm_mac_input_offset ||
        !sdm_range_fits(file, file->sdm_mac_offset, DFC_WIRE_MAC_LENGTH * DFC_SDM_HEX_EXPANSION)))
        goto cleanup;
    if(file->sdm_has_encrypted_file_offset &&
       (file->sdm_encrypted_file_length == 0 ||
        file->sdm_encrypted_file_length % (DFC_AES_KEY_LENGTH * DFC_SDM_HEX_EXPANSION) != 0 ||
        !sdm_range_fits(file, file->sdm_encrypted_file_offset, file->sdm_encrypted_file_length) ||
        file->sdm_encrypted_file_length / DFC_SDM_HEX_EXPANSION > DFC_SDM_READ_CACHE_SIZE))
        goto cleanup;
    const uint8_t* source = dfc_file_data_const(emulator->credential, file);
    if(!source) goto cleanup;
    size_t random_padding_len = 0;
    if(file->sdm_has_picc_data_offset) {
        size_t clear_len = picc_clear_len;
        random_padding_len = clear_len - 1 - emulator->credential->uid_len;
        if((file->sdm_options & DFC_SDM_COUNTER_MIRROR_MASK) != 0) random_padding_len -= 3;
        size_t random_offset =
            emulator->credential->uid_len == DFC_DESFIRE_UID_MAX_LENGTH &&
                    (file->sdm_options & DFC_SDM_COUNTER_MIRROR_MASK) == 0 ?
                1 :
                1 + emulator->credential->uid_len +
                    ((file->sdm_options & DFC_SDM_COUNTER_MIRROR_MASK) != 0 ? 3 : 0);
        if(!dfc_random_fill(picc_clear + random_offset, random_padding_len)) goto cleanup;
    }
    memcpy(emulator->sdm_read_cache, source, file->data_len);

    uint32_t counter = ++file->sdm_read_counter;
    if(file->sdm_has_counter_limit && counter > file->sdm_counter_limit) goto cleanup;
    if(file->sdm_has_uid_offset) {
        size_t encoded_uid_len = emulator->credential->uid_len * DFC_SDM_HEX_EXPANSION;
        if(!sdm_range_fits(file, file->sdm_uid_offset, encoded_uid_len)) goto cleanup;
        uint8_t uid[DFC_DESFIRE_UID_MAX_LENGTH] = {0};
        if(!emulator->credential->picc_random_id)
            memcpy(uid, emulator->credential->uid, emulator->credential->uid_len);
        sdm_write_ascii_hex(
            emulator->sdm_read_cache + file->sdm_uid_offset, uid, emulator->credential->uid_len);
        dfc_secure_wipe(uid, sizeof(uid));
    }
    if(file->sdm_has_counter_offset) {
        if(!sdm_range_fits(file, file->sdm_counter_offset, 6)) goto cleanup;
        uint8_t counter_bytes[] = {
            (uint8_t)(counter >> 16), (uint8_t)(counter >> 8), (uint8_t)counter};
        sdm_write_ascii_hex(
            emulator->sdm_read_cache + file->sdm_counter_offset,
            counter_bytes,
            sizeof(counter_bytes));
        dfc_secure_wipe(counter_bytes, sizeof(counter_bytes));
    }

    if(file->sdm_has_picc_data_offset) {
        size_t clear_len = picc_clear_len;
        size_t encoded_len = clear_len * DFC_SDM_HEX_EXPANSION;
        if(!sdm_range_fits(file, file->sdm_picc_data_offset, encoded_len)) goto cleanup;
        picc_clear[0] = (uint8_t)(DFC_SDM_PICC_UID_TAG_MASK |
                                  ((file->sdm_options & DFC_SDM_COUNTER_MIRROR_MASK) != 0 ?
                                       DFC_SDM_COUNTER_MIRROR_MASK :
                                       0) |
                                  emulator->credential->uid_len);
        size_t padding_len = clear_len - 1 - emulator->credential->uid_len;
        if((file->sdm_options & DFC_SDM_COUNTER_MIRROR_MASK) != 0) padding_len -= 3;
        if(emulator->credential->uid_len == DFC_DESFIRE_UID_MAX_LENGTH &&
           (file->sdm_options & DFC_SDM_COUNTER_MIRROR_MASK) == 0) {
            memcpy(
                picc_clear + 1 + padding_len,
                emulator->credential->uid,
                emulator->credential->uid_len);
        } else {
            size_t payload_offset = 1;
            memcpy(
                picc_clear + payload_offset,
                emulator->credential->uid,
                emulator->credential->uid_len);
            payload_offset += emulator->credential->uid_len;
            if((file->sdm_options & DFC_SDM_COUNTER_MIRROR_MASK) != 0) {
                picc_clear[payload_offset++] = (uint8_t)counter;
                picc_clear[payload_offset++] = (uint8_t)(counter >> 8);
                picc_clear[payload_offset++] = (uint8_t)(counter >> 16);
            }
        }
        DfcApplication* app = dfc_emulator_current_app(emulator);
        uint8_t* meta_key = app ? dfc_credential_key(emulator->credential, app, 0) : NULL;
        if(!meta_key) goto cleanup;
        if(!dfc_worker_aes_cbc_encrypt(
               meta_key, DFC_AES_KEY_LENGTH, picc_iv, clear_len, picc_clear, picc_encrypted))
            goto cleanup;
        sdm_write_ascii_hex(
            emulator->sdm_read_cache + file->sdm_picc_data_offset, picc_encrypted, clear_len);

        if(file->sdm_has_mac_input_offset && file->sdm_has_mac_offset) {
            uint8_t file_read_key_number =
                (uint8_t)((file->sdm_access_rights >> DFC_SDM_FILE_READ_SHIFT) &
                          DFC_SDM_ACCESS_MASK);
            uint8_t* file_read_key =
                app ? dfc_credential_key(emulator->credential, app, file_read_key_number) : NULL;
            if(!file_read_key) goto cleanup;
            if(!sdm_derive_key(
                   file_read_key,
                   DFC_SDM_MAC_LABEL_HIGH,
                   DFC_SDM_MAC_LABEL_LOW,
                   emulator->credential,
                   file,
                   counter,
                   session_mac_key))
                goto cleanup;
            if(file->sdm_mac_offset < file->sdm_mac_input_offset ||
               !sdm_range_fits(
                   file, file->sdm_mac_offset, DFC_WIRE_MAC_LENGTH * DFC_SDM_HEX_EXPANSION))
                goto cleanup;
            if(!aes_cmac(
                   session_mac_key,
                   DFC_AES_KEY_LENGTH,
                   emulator->sdm_read_cache + file->sdm_mac_input_offset,
                   file->sdm_mac_offset - file->sdm_mac_input_offset,
                   full_mac))
                goto cleanup;
            dfc_truncate_aes_wire_mac(full_mac, wire_mac);
            sdm_write_ascii_hex(
                emulator->sdm_read_cache + file->sdm_mac_offset, wire_mac, sizeof(wire_mac));
        }
    }
    if(file->sdm_has_encrypted_file_offset) {
        if(file->sdm_encrypted_file_length == 0 ||
           file->sdm_encrypted_file_length % (DFC_AES_KEY_LENGTH * DFC_SDM_HEX_EXPANSION) != 0 ||
           !sdm_range_fits(
               file, file->sdm_encrypted_file_offset, file->sdm_encrypted_file_length) ||
           file->sdm_encrypted_file_length / DFC_SDM_HEX_EXPANSION >
               sizeof(emulator->sdm_read_cache))
            goto cleanup;
        DfcApplication* app = dfc_emulator_current_app(emulator);
        uint8_t file_read_key_number =
            (uint8_t)((file->sdm_access_rights >> DFC_SDM_FILE_READ_SHIFT) & DFC_SDM_ACCESS_MASK);
        uint8_t* file_read_key =
            app ? dfc_credential_key(emulator->credential, app, file_read_key_number) : NULL;
        if(!file_read_key) goto cleanup;
        if(!sdm_derive_key(
               file_read_key,
               DFC_SDM_ENCRYPTION_LABEL_HIGH,
               DFC_SDM_ENCRYPTION_LABEL_LOW,
               emulator->credential,
               file,
               counter,
               session_encryption_key))
            goto cleanup;
        size_t clear_len = file->sdm_encrypted_file_length / DFC_SDM_HEX_EXPANSION;
        if(clear_len > DFC_SDM_READ_CACHE_SIZE) goto cleanup;
        uint8_t* encrypted = emulator->pending_chain;
        memcpy(encrypted, source + file->sdm_encrypted_file_offset, clear_len);
        pending_scratch_len = clear_len;
        counter_block[0] = (uint8_t)counter;
        counter_block[1] = (uint8_t)(counter >> 8);
        counter_block[2] = (uint8_t)(counter >> 16);
        if(!dfc_worker_aes_cbc_encrypt(
               session_encryption_key,
               DFC_AES_KEY_LENGTH,
               zero_iv,
               sizeof(counter_block),
               counter_block,
               file_iv) ||
           !dfc_worker_aes_cbc_encrypt(
               session_encryption_key, DFC_AES_KEY_LENGTH, file_iv, clear_len, encrypted, encrypted))
            goto cleanup;
        sdm_write_ascii_hex(
            emulator->sdm_read_cache + file->sdm_encrypted_file_offset, encrypted, clear_len);
    }
    if(!file->sdm_has_picc_data_offset && file->sdm_has_mac_input_offset &&
       file->sdm_has_mac_offset) {
        DfcApplication* app = dfc_emulator_current_app(emulator);
        uint8_t file_read_key_number =
            (uint8_t)((file->sdm_access_rights >> DFC_SDM_FILE_READ_SHIFT) & DFC_SDM_ACCESS_MASK);
        uint8_t* file_read_key =
            app ? dfc_credential_key(emulator->credential, app, file_read_key_number) : NULL;
        if(!file_read_key ||
           !sdm_derive_key(
               file_read_key,
               DFC_SDM_MAC_LABEL_HIGH,
               DFC_SDM_MAC_LABEL_LOW,
               emulator->credential,
               file,
               counter,
               session_mac_key) ||
           file->sdm_mac_offset < file->sdm_mac_input_offset ||
           !sdm_range_fits(
               file, file->sdm_mac_offset, DFC_WIRE_MAC_LENGTH * DFC_SDM_HEX_EXPANSION) ||
           !aes_cmac(
               session_mac_key,
               DFC_AES_KEY_LENGTH,
               emulator->sdm_read_cache + file->sdm_mac_input_offset,
               file->sdm_mac_offset - file->sdm_mac_input_offset,
               full_mac))
            goto cleanup;
        dfc_truncate_aes_wire_mac(full_mac, wire_mac);
        sdm_write_ascii_hex(
            emulator->sdm_read_cache + file->sdm_mac_offset, wire_mac, sizeof(wire_mac));
    }
    DFC_UNUSED(counter);
    emulator->sdm_read_cache_valid = true;
    emulator->sdm_read_cache_file_number = file->number;
    emulator->sdm_read_cache_len = file->data_len;
    success = true;

cleanup:
    if(pending_scratch_len != 0) dfc_secure_wipe(emulator->pending_chain, pending_scratch_len);
    dfc_secure_wipe(picc_clear, sizeof(picc_clear));
    dfc_secure_wipe(picc_encrypted, sizeof(picc_encrypted));
    dfc_secure_wipe(session_mac_key, sizeof(session_mac_key));
    dfc_secure_wipe(full_mac, sizeof(full_mac));
    dfc_secure_wipe(wire_mac, sizeof(wire_mac));
    dfc_secure_wipe(session_encryption_key, sizeof(session_encryption_key));
    dfc_secure_wipe(counter_block, sizeof(counter_block));
    dfc_secure_wipe(picc_iv, sizeof(picc_iv));
    dfc_secure_wipe(zero_iv, sizeof(zero_iv));
    dfc_secure_wipe(file_iv, sizeof(file_iv));
    return success;
}

bool dfc_emulator_render_sdm_read(DfcEmulator* emulator, DfcFile* file) {
    if(!emulator || !file) return false;
    _Static_assert(
        DFC_EMULATOR_CHAIN_BUFFER_SIZE >= DFC_SDM_READ_CACHE_SIZE * 2,
        "SDM rollback requires two cache-sized regions");
    if(emulator->command_chain_active ||
       emulator->pending_chain_len > emulator->pending_chain_offset) {
        return false;
    }
    uint8_t* saved_cache = emulator->pending_chain + DFC_SDM_READ_CACHE_SIZE;
    memcpy(saved_cache, emulator->sdm_read_cache, sizeof(emulator->sdm_read_cache));
    uint32_t saved_counter = file->sdm_read_counter;
    bool saved_valid = emulator->sdm_read_cache_valid;
    uint8_t saved_file_number = emulator->sdm_read_cache_file_number;
    size_t saved_len = emulator->sdm_read_cache_len;
    bool success = render_sdm_read_in_place(emulator, file);
    if(!success) {
        memcpy(emulator->sdm_read_cache, saved_cache, sizeof(emulator->sdm_read_cache));
        file->sdm_read_counter = saved_counter;
        emulator->sdm_read_cache_valid = saved_valid;
        emulator->sdm_read_cache_file_number = saved_file_number;
        emulator->sdm_read_cache_len = saved_len;
    }
    dfc_secure_wipe(saved_cache, sizeof(emulator->sdm_read_cache));
    return success;
}
#endif

static void handle_read_data(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    DfcByteBuf* tx_buffer,
    Dfc* dfc) {
    DFC_UNUSED(apdu_len);
    uint8_t file_no = apdu[1];
    DfcFile* file = dfc_credential_find_file_in_app(
        emulator->credential, emulator->selected_app_index, file_no);
    if(!file) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
        return;
    }
    if(!file_allows_read(file, emulator)) {
        dfc_bytebuf_append_byte(tx_buffer, file_access_refusal_status(file, false));
        return;
    }

    uint32_t offset = read_uint24_le(apdu + 2);
    uint32_t requested_len = read_uint24_le(apdu + 5);
    if(offset > file->data_len ||
       (requested_len != 0 && (size_t)offset + (size_t)requested_len > file->data_len)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        return;
    }

    size_t available = file->data_len - offset;
    size_t read_len = requested_len == 0 ? available : (size_t)requested_len;

    const uint8_t* file_bytes = dfc_file_data_const(emulator->credential, file);
#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
    // Backup reads keep showing the committed image until CommitTransaction.
    if(file->type == DFC_FILE_TYPE_BACKUP_DATA && emulator->transaction_snapshot_active &&
       emulator->transaction_snapshot_app_index == emulator->selected_app_index &&
       file->data_offset != DFC_FILE_POOL_NONE &&
       file->data_offset <= emulator->transaction_snapshot_pool_length &&
       file->data_len <= emulator->transaction_snapshot_pool_length - file->data_offset) {
        file_bytes = emulator->transaction_snapshot_pool + file->data_offset;
    }
#endif
#if DFC_ENABLE_SDM
    if(file->sdm_enabled && !dfc_emulator_native_authentication_active(emulator) &&
       !emulator->ev2_session_active) {
        if(!emulator->sdm_read_cache_valid && file->sdm_has_counter_limit &&
           file->sdm_read_counter >= file->sdm_counter_limit) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
            return;
        }
        if(!dfc_emulator_render_sdm_read(emulator, file)) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
            return;
        }
        file_bytes = emulator->sdm_read_cache;
    }
#endif
    if(read_len > 0 && !file_bytes) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
        return;
    }

    uint8_t comm = dfc_emulator_file_effective_comm_settings(
        emulator, file, DfcFileAccessRead, file->comm_settings);
    emit_payload_with_chaining_comm(
        emulator,
        tx_buffer,
        DFC_CMD_READ_DATA,
        read_len ? file_bytes + offset : NULL,
        read_len,
        1,
        comm,
        requested_len == 0);

    if(dfc && read_len > 0) {
        dfc_port_notify(dfc, DfcEventFileRequested);
    }
}

#if DFC_ENABLE_SDM
static void handle_get_file_counters(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer) {
    if(buffer_len != 2) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }
    DfcFile* file = dfc_credential_find_file_in_app(
        emulator->credential, emulator->selected_app_index, buffer[1]);
    if(!file || !file->sdm_enabled) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
    const uint8_t encoded_counter[] = {
        (uint8_t)file->sdm_read_counter,
        (uint8_t)(file->sdm_read_counter >> 8),
        (uint8_t)(file->sdm_read_counter >> 16),
        0,
        0,
    };
    dfc_bytebuf_append_bytes(tx_buffer, encoded_counter, sizeof(encoded_counter));
    emulator->sdm_read_cache_valid = false;
}
#endif

static void handle_write_data(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    DfcByteBuf* tx_buffer) {
    uint8_t file_no = apdu[1];
    DfcFile* file = dfc_credential_find_file_in_app(
        emulator->credential, emulator->selected_app_index, file_no);
    if(!file) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
        return;
    }
    if(!file_allows_write(file, emulator)) {
        dfc_bytebuf_append_byte(tx_buffer, file_access_refusal_status(file, true));
        return;
    }
    uint8_t comm = dfc_emulator_file_effective_comm_settings(
        emulator, file, DfcFileAccessWrite, file->comm_settings);
    if(apdu_len > DFC_EMULATOR_CHAIN_BUFFER_SIZE ||
       (comm == DFC_COMM_ENCIPHERED && apdu_len - 8 > DFC_SM_MAX_CRYPTO_SIZE)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        return;
    }

    uint32_t offset = read_uint24_le(apdu + 2);
    uint32_t declared_len = read_uint24_le(apdu + 5);
    if(offset > file->data_len || (size_t)offset + (size_t)declared_len > file->data_len) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        return;
    }

    const uint8_t* wrapped = apdu + 8;
    size_t wrapped_len = apdu_len - 8;

    const uint8_t* clear = wrapped;
    size_t out_len = wrapped_len;
    size_t scratch_len = 0;
    if(dfc_emulator_native_authentication_active(emulator)) {
        bool ev1_sm =
            dfc_secure_messaging_applies_ev1(emulator->secure_messaging, DFC_CMD_WRITE_DATA);
        if(ev1_sm && comm == DFC_COMM_MAC &&
           dfc_secure_messaging_ev1_transmits_command_mac(DFC_CMD_WRITE_DATA)) {
            // Option b: MACt covers Cmd||FileNo||Offset||Len||Data (whole body after Cmd).
            size_t clear_body = dfc_secure_messaging_verify_ev1_transmitted_command_mac_full(
                emulator->secure_messaging, apdu, apdu_len);
            if(clear_body == SIZE_MAX || clear_body < 7) {
                dfc_emulator_reset_session(emulator);
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
                return;
            }
            out_len = clear_body - 7;
            clear = wrapped;
        } else if(ev1_sm && comm == DFC_COMM_ENCIPHERED) {
            if(wrapped_len > sizeof(emulator->pending_chain)) {
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
                return;
            }
            uint8_t* target = emulator->pending_chain;
            out_len = dfc_secure_messaging_verify_command(
                emulator->secure_messaging,
                DFC_COMM_ENCIPHERED,
                apdu,
                8,
                wrapped,
                wrapped_len,
                target,
                sizeof(emulator->pending_chain));
            clear = target;
            scratch_len = wrapped_len;
            if(out_len == 0 && wrapped_len > 0) {
                dfc_secure_wipe(target, scratch_len);
                dfc_emulator_reset_session(emulator);
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
                return;
            }
            // IV left as last CT block for response MACt(RC).
        } else if(ev1_sm) {
            // Plain (or free-access Full demoted to plain): CMAC updates IV only.
            if(!dfc_secure_messaging_update_ev1_command_full(
                   emulator->secure_messaging, apdu, apdu_len)) {
                dfc_emulator_reset_session(emulator);
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
                return;
            }
        } else {
            // D40 file comm modes.
            if(comm != DFC_COMM_PLAIN) {
                if(wrapped_len > sizeof(emulator->pending_chain)) {
                    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
                    return;
                }
                uint8_t* target = emulator->pending_chain;
                out_len = dfc_secure_messaging_verify_command(
                    emulator->secure_messaging,
                    comm,
                    apdu,
                    8,
                    wrapped,
                    wrapped_len,
                    target,
                    sizeof(emulator->pending_chain));
                clear = target;
                scratch_len = wrapped_len;
            }
            if(out_len == 0 && wrapped_len > 0 && comm != DFC_COMM_PLAIN) {
                dfc_secure_wipe(emulator->pending_chain, scratch_len);
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
                return;
            }
        }
    }

    if(out_len != declared_len) {
        dfc_secure_wipe(emulator->pending_chain, scratch_len);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        return;
    }
    uint8_t* file_bytes = dfc_file_data(emulator->credential, file);
#if DFC_ENABLE_BACKUP_FILES
    if(file->type == DFC_FILE_TYPE_BACKUP_DATA && !transaction_snapshot_begin(emulator)) {
        dfc_secure_wipe(emulator->pending_chain, scratch_len);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
#endif
    if(out_len > 0) {
        if(!file_bytes) {
            dfc_secure_wipe(emulator->pending_chain, scratch_len);
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
            return;
        }
    }
    if(file->type == DFC_FILE_TYPE_STANDARD_DATA &&
       !dfc_emulator_transaction_snapshot_mirror_write(
           emulator, (size_t)(file - emulator->credential->files), offset, clear, out_len)) {
        dfc_secure_wipe(emulator->pending_chain, scratch_len);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        return;
    }
    if(out_len > 0) {
        memcpy(file_bytes + offset, clear, out_len);
    }
    if(file->type == DFC_FILE_TYPE_BACKUP_DATA) file->transaction_pending = true;
    emulator->data_written = true;
    dfc_credential_mark_dirty(emulator->credential);

    dfc_secure_wipe(emulator->pending_chain, scratch_len);
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
}

#if DFC_ENABLE_RECORD_FILES
static void handle_write_record(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    DfcByteBuf* tx_buffer) {
    if(apdu_len > DFC_EMULATOR_CHAIN_BUFFER_SIZE) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }
    DfcFile* file = dfc_credential_find_file_in_app(
        emulator->credential, emulator->selected_app_index, apdu[1]);
    if(!file ||
       (file->type != DFC_FILE_TYPE_LINEAR_RECORD && file->type != DFC_FILE_TYPE_CYCLIC_RECORD)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
        return;
    }
    if(!file_allows_write(file, emulator)) {
        dfc_bytebuf_append_byte(tx_buffer, file_access_refusal_status(file, true));
        return;
    }

    uint32_t offset = read_uint24_le(apdu + 2);
    uint32_t write_len = read_uint24_le(apdu + 5);
    uint8_t comm = dfc_emulator_file_effective_comm_settings(
        emulator, file, DfcFileAccessWrite, file->comm_settings);
    uint8_t* record_data = emulator->pending_chain;
    size_t clear_len = unwrap_write_payload(
        emulator, apdu, apdu_len, 7, comm, record_data, sizeof(emulator->pending_chain));
    if(clear_len == SIZE_MAX) {
        dfc_emulator_reset_session(emulator);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        return;
    }
    if(clear_len != write_len || offset + write_len > file->record_size) {
        dfc_secure_wipe(record_data, clear_len);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        return;
    }
    // A cyclic file keeps one record in reserve, so it holds one fewer than its
    // declared size, measured against a genuine EV1.
    size_t cyclic_capacity = file->max_records > 0 ? (size_t)file->max_records - 1 : 0;

    uint8_t* data = dfc_file_data(emulator->credential, file);
    if(!data) {
        dfc_secure_wipe(record_data, clear_len);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
        return;
    }
    if(!transaction_snapshot_begin(emulator)) {
        dfc_secure_wipe(record_data, clear_len);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
    uint8_t operation = transaction_record_operation(emulator, file);
    if(operation == RecordTransactionClear || operation == RecordTransactionUpdate) {
        dfc_secure_wipe(record_data, clear_len);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }

    size_t record_index = 0;
    if(operation == RecordTransactionWrite) {
        size_t index = transaction_file_index(emulator, file);
        record_index = emulator->transaction_record_numbers[index];
    } else {
        // A linear file with no room left refuses the first write in a
        // transaction. Further writes target the record that call created.
        if(file->record_count >= file->max_records && file->type == DFC_FILE_TYPE_LINEAR_RECORD) {
            dfc_secure_wipe(record_data, clear_len);
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
            return;
        }
        if(file->type == DFC_FILE_TYPE_CYCLIC_RECORD && cyclic_capacity == 0) {
            dfc_secure_wipe(record_data, clear_len);
            transaction_set_record_operation(emulator, file, RecordTransactionWrite, 0);
            file->transaction_pending = true;
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
            return;
        }

        record_index = file->record_count;
        if(file->type == DFC_FILE_TYPE_CYCLIC_RECORD && file->record_count >= cyclic_capacity) {
            size_t retained_len = (cyclic_capacity - 1) * (size_t)file->record_size;
            if(retained_len > 0) {
                memmove(data, data + file->record_size, retained_len);
            }
            record_index = cyclic_capacity - 1;
            file->record_count = (uint32_t)cyclic_capacity;
        } else {
            file->record_count++;
        }
        memset(data + record_index * file->record_size, 0, file->record_size);
        transaction_set_record_operation(
            emulator, file, RecordTransactionWrite, (uint32_t)record_index);
    }
    if(write_len > 0) {
        memcpy(data + record_index * file->record_size + offset, record_data, write_len);
    }
    dfc_secure_wipe(record_data, clear_len);
    file->transaction_pending = true;
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
}

static void
    handle_read_records(DfcEmulator* emulator, const uint8_t* apdu, DfcByteBuf* tx_buffer) {
    DfcFile* file = dfc_credential_find_file_in_app(
        emulator->credential, emulator->selected_app_index, apdu[1]);
    if(!file ||
       (file->type != DFC_FILE_TYPE_LINEAR_RECORD && file->type != DFC_FILE_TYPE_CYCLIC_RECORD)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
        return;
    }
    if(!file_allows_read(file, emulator)) {
        dfc_bytebuf_append_byte(tx_buffer, file_access_refusal_status(file, false));
        return;
    }

    uint32_t record_count = file->record_count;
    const uint8_t* data = dfc_file_data_const(emulator->credential, file);
#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
    if(emulator->transaction_snapshot_active &&
       emulator->transaction_snapshot_app_index == emulator->selected_app_index) {
        size_t index = transaction_file_index(emulator, file);
        record_count = emulator->transaction_snapshot_record_counts[index];
        if(file->data_offset != DFC_FILE_POOL_NONE &&
           file->data_offset <= emulator->transaction_snapshot_pool_length) {
            data = emulator->transaction_snapshot_pool + file->data_offset;
        }
    }
#endif

    uint32_t first_record = read_uint24_le(apdu + 2);
    uint32_t requested_records = read_uint24_le(apdu + 5);
    if(record_count == 0 || first_record >= record_count) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        return;
    }
    size_t available = record_count - first_record;
    size_t count = requested_records == 0 ? available : requested_records;
    if(count > available || file->record_size == 0 ||
       count > DFC_MAX_FILE_DATA / file->record_size) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        return;
    }
    if(!data) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
        return;
    }
    // The requested records occupy one contiguous range in stored oldest-first
    // order, even though record number zero names the newest one.
    size_t payload_len = count * file->record_size;
    uint8_t comm = dfc_emulator_file_effective_comm_settings(
        emulator, file, DfcFileAccessRead, file->comm_settings);
    size_t stored_index = record_count - first_record - count;
    emit_payload_with_chaining_comm(
        emulator,
        tx_buffer,
        apdu[0],
        data + stored_index * file->record_size,
        payload_len,
        1,
        comm,
        requested_records == 0);
}

static void handle_update_record(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    DfcByteBuf* tx_buffer) {
    if(apdu_len > DFC_EMULATOR_CHAIN_BUFFER_SIZE) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }
    DfcFile* file = dfc_credential_find_file_in_app(
        emulator->credential, emulator->selected_app_index, apdu[1]);
    if(!file ||
       (file->type != DFC_FILE_TYPE_LINEAR_RECORD && file->type != DFC_FILE_TYPE_CYCLIC_RECORD)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
        return;
    }
    if(!file_allows_read_write(file, emulator)) {
        dfc_bytebuf_append_byte(tx_buffer, file_access_refusal_status(file, true));
        return;
    }
    uint32_t record_number = read_uint24_le(apdu + 2);
    uint32_t offset = read_uint24_le(apdu + 5);
    uint32_t write_length = read_uint24_le(apdu + 8);
    if(record_number >= file->record_count || offset >= file->record_size || write_length == 0 ||
       offset + write_length > file->record_size) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        return;
    }
    uint8_t comm = dfc_emulator_file_effective_comm_settings(
        emulator, file, DfcFileAccessReadWrite, file->comm_settings);
    uint8_t* update_data = emulator->pending_chain;
    size_t clear_len = unwrap_write_payload(
        emulator,
        apdu,
        apdu_len,
        DFC_UPDATE_RECORD_HEADER_SIZE - 1,
        comm,
        update_data,
        sizeof(emulator->pending_chain));
    if(clear_len == SIZE_MAX) {
        dfc_emulator_reset_session(emulator);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        return;
    }
    if(clear_len != write_length) {
        dfc_secure_wipe(update_data, clear_len);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }
    uint8_t* data = dfc_file_data(emulator->credential, file);
    if(!data || !transaction_snapshot_begin(emulator)) {
        dfc_secure_wipe(update_data, clear_len);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OUT_OF_EEPROM);
        return;
    }
    if(file->type == DFC_FILE_TYPE_LINEAR_RECORD && file->record_count >= file->max_records) {
        dfc_secure_wipe(update_data, clear_len);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        return;
    }
    uint8_t operation = transaction_record_operation(emulator, file);
    if(operation == RecordTransactionWrite || operation == RecordTransactionClear ||
       (operation == RecordTransactionUpdate &&
        emulator->transaction_record_numbers[transaction_file_index(emulator, file)] !=
            record_number)) {
        dfc_secure_wipe(update_data, clear_len);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
    size_t stored_index = file->record_count - record_number - 1;
    memcpy(data + stored_index * file->record_size + offset, update_data, write_length);
    dfc_secure_wipe(update_data, clear_len);
    transaction_set_record_operation(emulator, file, RecordTransactionUpdate, record_number);
    file->transaction_pending = true;
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
}

static void handle_clear_record_file(
    DfcEmulator* emulator,
    const uint8_t* apdu,
    size_t apdu_len,
    DfcByteBuf* tx_buffer) {
    if(apdu_len != 2) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }
    DfcFile* file = dfc_credential_find_file_in_app(
        emulator->credential, emulator->selected_app_index, apdu[1]);
    if(!file ||
       (file->type != DFC_FILE_TYPE_LINEAR_RECORD && file->type != DFC_FILE_TYPE_CYCLIC_RECORD)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
        return;
    }
    if(!file_allows_read_write(file, emulator)) {
        dfc_bytebuf_append_byte(tx_buffer, file_access_refusal_status(file, true));
        return;
    }
    if(!transaction_snapshot_begin(emulator)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OUT_OF_EEPROM);
        return;
    }
    if(transaction_record_operation(emulator, file) != RecordTransactionNone) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
    file->record_count = 0;
    transaction_set_record_operation(emulator, file, RecordTransactionClear, 0);
    file->transaction_pending = true;
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OK);
}
#endif

static void
    apply_ev1_response_secure_messaging(DfcEmulator* emulator, uint8_t cmd, DfcByteBuf* tx_buffer) {
    if(!dfc_emulator_native_authentication_active(emulator) ||
       !dfc_secure_messaging_applies_ev1(emulator->secure_messaging, cmd))
        return;
    // Already secured as one response before being split into frames.
    if(emulator->response_secured) return;

    size_t tx_len = dfc_bytebuf_get_size_bytes(tx_buffer);
    const uint8_t* tx_data = dfc_bytebuf_get_data(tx_buffer);
    size_t offset = 0;
    if(tx_len > 1 && tx_data[0] != DFC_STATUS_OK && tx_data[0] != DFC_CMD_ADDITIONAL_FRAME &&
       tx_data[0] != DFC_STATUS_FILE_NOT_FOUND && tx_data[0] != DFC_STATUS_APPLICATION_NOT_FOUND &&
       tx_data[0] != DFC_STATUS_PARAMETER_ERROR && tx_data[0] != DFC_STATUS_PERMISSION_DENIED &&
       tx_data[0] != DFC_STATUS_AUTHENTICATION_ERR && (tx_data[0] & 0xC0) == 0x00) {
        offset = 1;
        if(tx_data[0] & ISO14443_4A_CID_MASK) offset++;
        if(tx_data[0] & ISO14443_4A_NAD_MASK) offset++;
    }
    if(tx_len <= offset) return;

    uint8_t status = tx_data[offset];
    size_t payload_len = tx_len - offset - 1;
    if(status == DFC_STATUS_SPECIAL_SUCCESS ||
       (status == DFC_CMD_ADDITIONAL_FRAME && payload_len == 0))
        return;
    if(status != DFC_STATUS_OK && status != DFC_CMD_ADDITIONAL_FRAME) {
        dfc_emulator_reset_session(emulator);
        return;
    }

    if(payload_len > DFC_WORKER_MAX_BUFFER_SIZE - (offset + 1) - DFC_WIRE_MAC_LENGTH) {
        dfc_emulator_reset_session(emulator);
        dfc_bytebuf_reset(tx_buffer);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        return;
    }
    uint8_t mac[DFC_WIRE_MAC_LENGTH];
    if(!dfc_secure_messaging_generate_ev1_response_mac(
           emulator->secure_messaging, status, tx_data + offset + 1, payload_len, mac)) {
        dfc_secure_wipe(mac, sizeof(mac));
        dfc_emulator_reset_session(emulator);
        dfc_bytebuf_reset(tx_buffer);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
        return;
    }

    dfc_bytebuf_append_bytes(tx_buffer, mac, sizeof(mac));
    emulator->response_secured = true;
    dfc_secure_wipe(mac, sizeof(mac));
}

const char* dfc_desfire_command_name(uint8_t cmd, const DfcEmulator* emulator) {
#if DFC_ENABLE_RECORD_FILES
    cmd = dfc_record_command_base(cmd);
#endif
    switch(cmd) {
    case DFC_CMD_CHANGE_KEY_SETTINGS:
        return "ChangeKeySettings";
    case DFC_CMD_GET_VERSION:
        return "GetVersion";
    case DFC_CMD_GET_CARD_UID:
        return "GetCardUid";
    case DFC_CMD_SELECT_APPLICATION:
        return "SelectApplication";
    case DFC_CMD_GET_KEY_SETTINGS:
        return "GetKeySettings";
    case DFC_CMD_GET_KEY_VERSION:
        return "GetKeyVersion";
#if DFC_ENABLE_KEY_SETS
    case DFC_CMD_INITIALIZE_KEY_SET:
        return "InitializeKeySet";
    case DFC_CMD_FINALIZE_KEY_SET:
        return "FinalizeKeySet";
    case DFC_CMD_ROLL_KEY_SET:
        return "RollKeySet";
#endif
    case DFC_CMD_GET_APPLICATION_IDS:
        return "GetApplicationIds";
    case DFC_CMD_GET_DF_NAMES:
        return "GetDfNames";
    case DFC_CMD_FREE_MEM:
        return "FreeMem";
    case DFC_CMD_CREATE_APPLICATION:
        return "CreateApplication";
    case DFC_CMD_DELETE_APPLICATION:
        return "DeleteApplication";
    case DFC_CMD_FORMAT_PICC:
        return "FormatPicc";
    case DFC_CMD_GET_ISO_FILE_IDS:
        return "GetIsoFileIds";
    case DFC_CMD_GET_FILE_IDS:
        return "GetFileIds";
    case DFC_CMD_GET_FILE_SETTINGS:
        return "GetFileSettings";
    case DFC_CMD_CHANGE_FILE_SETTINGS:
        return "ChangeFileSettings";
    case DFC_CMD_CREATE_STD_DATA_FILE:
        return "CreateStdDataFile";
#if DFC_ENABLE_BACKUP_FILES
    case DFC_CMD_CREATE_BACKUP_DATA_FILE:
        return "CreateBackupDataFile";
#endif
    case DFC_CMD_CREATE_VALUE_FILE:
        return "CreateValueFile";
#if DFC_ENABLE_RECORD_FILES
    case DFC_CMD_CREATE_LINEAR_RECORD_FILE:
        return "CreateLinearRecordFile";
    case DFC_CMD_CREATE_CYCLIC_RECORD_FILE:
        return "CreateCyclicRecordFile";
    case DFC_CMD_WRITE_RECORD:
        return "WriteRecord";
    case DFC_CMD_READ_RECORDS:
        return "ReadRecords";
    case DFC_CMD_UPDATE_RECORD:
    case DFC_CMD_UPDATE_RECORD_ISO:
        return "UpdateRecord";
    case DFC_CMD_CLEAR_RECORD_FILE:
        return "ClearRecordFile";
#endif
    case DFC_CMD_DELETE_FILE:
        return "DeleteFile";
    case DFC_CMD_CHANGE_KEY:
        return "ChangeKey";
#if DFC_ENABLE_KEY_SETS
    case DFC_CMD_CHANGE_KEY_EV2:
        return "ChangeKeyEv2";
#endif
#if DFC_ENABLE_DELEGATED_APPLICATIONS
    case DFC_CMD_CREATE_DELEGATED_APPLICATION:
        return "CreateDelegatedApplication";
    case DFC_CMD_GET_DELEGATED_INFO:
        return "GetDelegatedInfo";
#endif
    case DFC_CMD_GET_VALUE:
        return "GetValue";
    case DFC_CMD_CREDIT:
        return "Credit";
    case DFC_CMD_LIMITED_CREDIT:
        return "LimitedCredit";
    case DFC_CMD_DEBIT:
        return "Debit";
    case DFC_CMD_COMMIT_TRANSACTION:
        return "CommitTransaction";
    case DFC_CMD_ABORT_TRANSACTION:
        return "AbortTransaction";
    case DFC_CMD_AUTHENTICATE_LEGACY:
        return "AuthenticateLegacy";
    case DFC_CMD_AUTHENTICATE_ISO:
        return "AuthenticateIso";
    case DFC_CMD_AUTHENTICATE_AES:
        return "AuthenticateAes";
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    case DFC_CMD_SET_CONFIGURATION:
        return "SetConfiguration";
    case DFC_CMD_AUTHENTICATE_EV2_FIRST:
        return "AuthenticateEv2First";
    case DFC_CMD_AUTHENTICATE_EV2_NON_FIRST:
        return "AuthenticateEv2NonFirst";
#endif
    case DFC_CMD_ADDITIONAL_FRAME:
        return emulator->awaiting_step2 ? "AuthenticateAdditionalFrame" :
                                          "GetVersionAdditionalFrame";
    case DFC_CMD_READ_DATA:
        return "ReadData";
    case DFC_CMD_WRITE_DATA:
        return "WriteData";
#if DFC_ENABLE_PROXIMITY_CHECK
    case DFC_CMD_PREPARE_PROXIMITY_CHECK:
        return "PrepareProximityCheck";
    case DFC_CMD_PROXIMITY_CHECK:
        return "ProximityCheck";
    case DFC_CMD_VERIFY_PROXIMITY_CHECK:
        return "VerifyProximityCheck";
#endif
#if DFC_ENABLE_STATIC_SIGNATURE
    case DFC_CMD_READ_SIGNATURE:
        return "ReadSignature";
#endif
    default:
        return "Unknown";
    }
}

const char* dfc_iso_dep_control_frame_name(uint8_t pcb) {
    if((pcb & 0xC0) == 0x80) {
        return (pcb & 0x10) ? "RBlockNak" : "RBlockAck";
    }

    if((pcb & 0xEF) == 0xC2) {
        return "Deselect";
    }

    if((pcb & 0xF0) == 0xF0) {
        return "WaitTimeExtension";
    }

    if((pcb & 0xC0) == 0xC0) {
        return "SBlock";
    }

    return "EmptyIBlock";
}

static size_t chained_write_header_len(uint8_t cmd) {
    switch(cmd) {
    case DFC_CMD_WRITE_DATA:
    case DFC_CMD_WRITE_RECORD:
        return 7;
    case DFC_CMD_UPDATE_RECORD:
        return 10;
    default:
        return 0;
    }
}

// Total logical native command length after all AF frames have been joined.
// SIZE_MAX means that the first frame does not yet contain enough header.
static size_t chained_write_expected_len(
    DfcEmulator* emulator,
    uint8_t cmd,
    const uint8_t* buffer,
    size_t buffer_len) {
    size_t header_len = chained_write_header_len(cmd);
    if(header_len == 0 || buffer_len < header_len + 1) return SIZE_MAX;
    size_t length_offset = cmd == DFC_CMD_UPDATE_RECORD ? 8 : 5;
    size_t clear_len = read_uint24_le(buffer + length_offset);
    if(clear_len > DFC_EMULATOR_CHAIN_BUFFER_SIZE - header_len - 1) return 0;

    DfcFile* file = NULL;
    if(emulator->selected_application == DfcEmulatorSelectedApplicationApp) {
        file = dfc_credential_find_file_in_app(
            emulator->credential, emulator->selected_app_index, buffer[1]);
    }
    // The command handler can reject this from the first frame without asking
    // the reader to send data for a file that does not exist.
    if(!file) return buffer_len;
    DfcFileAccess access = cmd == DFC_CMD_UPDATE_RECORD ? DfcFileAccessReadWrite :
                                                          DfcFileAccessWrite;
    uint8_t comm =
        dfc_emulator_file_effective_comm_settings(emulator, file, access, file->comm_settings);
    size_t wire_len;

#if DFC_ENABLE_EV2_SECURE_MESSAGING
    if(emulator->ev2_session_active && comm != DFC_COMM_PLAIN) {
        wire_len = dfc_secure_messaging_command_payload_length(NULL, true, comm, clear_len);
    } else
#endif
        if(dfc_emulator_native_authentication_active(emulator)) {
        wire_len = dfc_secure_messaging_command_payload_length(
            emulator->secure_messaging, false, comm, clear_len);
    } else
        wire_len = clear_len;
    if(wire_len == SIZE_MAX) return 0;
    if(wire_len > DFC_EMULATOR_CHAIN_BUFFER_SIZE - header_len - 1) return 0;
    return 1 + header_len + wire_len;
}

static bool begin_or_reject_command_chain(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer) {
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    if(emulator->ev2_session_active && buffer_len < DFC_EV1_MAX_FRAME_PAYLOAD + 1) return false;
#endif
    size_t expected = chained_write_expected_len(emulator, buffer[0], buffer, buffer_len);
    if(expected == SIZE_MAX) return false;
    if(expected == 0 || buffer_len > DFC_EV1_MAX_FRAME_PAYLOAD + 1 || buffer_len > expected) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return true;
    }
    if(buffer_len == expected) return false;
    emulator->command_chain = dfc_platform_alloc(expected, DfcAllocEmulator);
    if(!emulator->command_chain) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_OUT_OF_EEPROM);
        return true;
    }
    memcpy(emulator->command_chain, buffer, buffer_len);
    emulator->command_chain_active = true;
    emulator->command_chain_len = buffer_len;
    emulator->command_chain_expected = expected;
    dfc_bytebuf_append_byte(tx_buffer, DFC_CMD_ADDITIONAL_FRAME);
    return true;
}

static bool update_ev1_command_if_active(
    DfcEmulator* emulator,
    uint8_t cmd,
    const uint8_t* data,
    size_t data_len) {
    if(dfc_emulator_native_authentication_active(emulator) &&
       dfc_secure_messaging_applies_ev1(emulator->secure_messaging, cmd)) {
        return dfc_secure_messaging_update_ev1_command(
            emulator->secure_messaging, cmd, data, data_len);
    }
    return true;
}

#if DFC_ENABLE_PROXIMITY_CHECK || DFC_ENABLE_EV2_SECURE_MESSAGING
static bool prepare_ev1_command_update(
    DfcEmulator* emulator,
    uint8_t cmd,
    const uint8_t* data,
    size_t data_len,
    uint8_t candidate_iv[DFC_SM_MAX_CIPHER_BLOCK_SIZE],
    bool* has_candidate) {
    *has_candidate = false;
    if(!dfc_emulator_native_authentication_active(emulator) ||
       !dfc_secure_messaging_applies_ev1(emulator->secure_messaging, cmd)) {
        return true;
    }
    uint8_t original_iv[DFC_SM_MAX_CIPHER_BLOCK_SIZE];
    memcpy(original_iv, emulator->secure_messaging->iv, sizeof(original_iv));
    if(!dfc_secure_messaging_update_ev1_command(emulator->secure_messaging, cmd, data, data_len)) {
        dfc_secure_wipe(original_iv, sizeof(original_iv));
        return false;
    }
    memcpy(candidate_iv, emulator->secure_messaging->iv, sizeof(original_iv));
    memcpy(emulator->secure_messaging->iv, original_iv, sizeof(original_iv));
    dfc_secure_wipe(original_iv, sizeof(original_iv));
    *has_candidate = true;
    return true;
}

static void commit_ev1_command_update(
    DfcEmulator* emulator,
    const uint8_t candidate_iv[DFC_SM_MAX_CIPHER_BLOCK_SIZE],
    bool has_candidate) {
    if(has_candidate && dfc_emulator_native_authentication_active(emulator)) {
        memcpy(
            emulator->secure_messaging->iv, candidate_iv, sizeof(emulator->secure_messaging->iv));
    }
}
#endif

static void finalize_native_command(
    DfcEmulator* emulator,
    bool preserve_transaction_on_failure,
    const DfcByteBuf* tx_buffer) {
    size_t response_len = dfc_bytebuf_get_size_bytes(tx_buffer);
    if(response_len == 0) return;
    uint8_t status = dfc_bytebuf_get_data(tx_buffer)[0];
    if(status == DFC_STATUS_OK || status == DFC_CMD_ADDITIONAL_FRAME ||
       status == DFC_STATUS_SPECIAL_SUCCESS)
        return;
    if(!preserve_transaction_on_failure) dfc_emulator_abort_transaction(emulator);
    if(emulator->auth_cipher != DFC_CMD_AUTHENTICATE_LEGACY)
        dfc_emulator_clear_active_authentication(emulator);
}

static bool dispatch_native_command(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer,
    void* context) {
    Dfc* dfc = context;
    if(buffer_len < 1) return false;
    uint8_t cmd = buffer[0];
    emulator->response_secured = false;
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    emulator->ev2_response_plain = false;
#endif
    DFC_LOG_T(TAG, "DESFire command %s", dfc_desfire_command_name(cmd, emulator));

    if(emulator->command_chain_active) {
        if(cmd != DFC_CMD_ADDITIONAL_FRAME) {
            dfc_emulator_discard_command_chain(emulator);
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_COMMAND_ABORTED);
            return true;
        }
        size_t continuation_len = buffer_len - 1;
        size_t remaining = emulator->command_chain_expected - emulator->command_chain_len;
        if(continuation_len == 0 || continuation_len > DFC_EV1_MAX_FRAME_PAYLOAD ||
           continuation_len > remaining) {
            dfc_emulator_discard_command_chain(emulator);
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return true;
        }
        memcpy(
            emulator->command_chain + emulator->command_chain_len, buffer + 1, continuation_len);
        emulator->command_chain_len += continuation_len;
        if(emulator->command_chain_len < emulator->command_chain_expected) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_CMD_ADDITIONAL_FRAME);
            return true;
        }
        size_t logical_len = emulator->command_chain_len;
        emulator->command_chain_active = false;
        emulator->command_chain_expected = SIZE_MAX;
        bool handled = dispatch_native_command(
            emulator, emulator->command_chain, logical_len, tx_buffer, context);
        if(handled)
            apply_ev1_response_secure_messaging(emulator, emulator->command_chain[0], tx_buffer);
        dfc_emulator_discard_command_chain(emulator);
        return handled;
    }

    if(cmd != DFC_CMD_ADDITIONAL_FRAME && dfc_emulator_abort_pending_native_work(emulator)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_COMMAND_ABORTED);
        return true;
    }

    if(emulator->command_chain_expected != SIZE_MAX && chained_write_header_len(cmd) != 0 &&
       begin_or_reject_command_chain(emulator, buffer, buffer_len, tx_buffer)) {
        return true;
    }

    // Handlers that own EV1 command IV updates themselves:
    // ChangeKey and ChangeFileSettings (Full cryptograms), plus WriteData /
    // Credit / Debit / LimitedCredit (MAC-on-wire or Full decrypt).
    bool defer_ev1_cmd_cmac = cmd == DFC_CMD_CHANGE_KEY || cmd == DFC_CMD_CHANGE_KEY_SETTINGS ||
                              cmd == DFC_CMD_CHANGE_FILE_SETTINGS ||
                              dfc_secure_messaging_ev1_transmits_command_mac(cmd);
#if DFC_ENABLE_PROXIMITY_CHECK
    defer_ev1_cmd_cmac = defer_ev1_cmd_cmac || cmd == DFC_CMD_PREPARE_PROXIMITY_CHECK;
#endif
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    defer_ev1_cmd_cmac = defer_ev1_cmd_cmac || cmd == DFC_CMD_AUTHENTICATE_EV2_FIRST ||
                         cmd == DFC_CMD_AUTHENTICATE_EV2_NON_FIRST;
#endif
    if(!defer_ev1_cmd_cmac) {
        if(!update_ev1_command_if_active(emulator, cmd, buffer + 1, buffer_len - 1)) {
            dfc_emulator_reset_session(emulator);
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
            return true;
        }
    }

#if DFC_ENABLE_RECORD_FILES
    cmd = dfc_record_command_base(cmd);
#endif
    switch(cmd) {
#if DFC_ENABLE_PROXIMITY_CHECK
    case DFC_CMD_PREPARE_PROXIMITY_CHECK: {
        uint8_t prepare_candidate_iv[DFC_SM_MAX_CIPHER_BLOCK_SIZE];
        bool prepare_has_candidate = false;
        if(!prepare_ev1_command_update(
               emulator,
               cmd,
               buffer + 1,
               buffer_len - 1,
               prepare_candidate_iv,
               &prepare_has_candidate)) {
            dfc_emulator_reset_session(emulator);
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
            return true;
        }
        if(buffer_len != 1) {
            commit_ev1_command_update(emulator, prepare_candidate_iv, prepare_has_candidate);
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return true;
        }
        if(handle_prepare_proximity_check(emulator, tx_buffer)) {
            commit_ev1_command_update(emulator, prepare_candidate_iv, prepare_has_candidate);
        }
        dfc_secure_wipe(prepare_candidate_iv, sizeof(prepare_candidate_iv));
        return true;
    }
    case DFC_CMD_PROXIMITY_CHECK:
        handle_proximity_check(emulator, buffer, buffer_len, tx_buffer);
        return true;
    case DFC_CMD_VERIFY_PROXIMITY_CHECK:
        handle_verify_proximity_check(emulator, buffer, buffer_len, tx_buffer);
        return true;
#endif
#if DFC_ENABLE_STATIC_SIGNATURE
    case DFC_CMD_READ_SIGNATURE:
        handle_read_signature(emulator, buffer, buffer_len, tx_buffer);
        return true;
#endif
    case DFC_CMD_CHANGE_KEY_SETTINGS:
        handle_change_key_settings(emulator, buffer, buffer_len, tx_buffer);
        return true;
    case DFC_CMD_GET_VERSION:
        if(buffer_len != 1) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return true;
        }
        handle_get_version(emulator, tx_buffer);
        return true;
    case DFC_CMD_GET_CARD_UID:
        if(buffer_len != 1) {
            // EV1 and EV2 terminal errors retire their chained state before
            // the plain error is emitted. Legacy sessions keep their old rule.
            bool retires_session = dfc_emulator_native_authentication_active(emulator) &&
                                   emulator->secure_messaging->cipher !=
                                       DFC_CMD_AUTHENTICATE_LEGACY;
#if DFC_ENABLE_EV2_SECURE_MESSAGING
            retires_session = retires_session || emulator->ev2_session_active;
#endif
            if(retires_session) dfc_emulator_reset_session(emulator);
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return true;
        }
        handle_get_card_uid(emulator, tx_buffer);
        return true;
    case DFC_CMD_SELECT_APPLICATION:
        if(buffer_len < 4) return false;
        handle_select_application(emulator, buffer, tx_buffer, dfc);
        return true;
    case DFC_CMD_GET_KEY_SETTINGS:
        handle_get_key_settings(emulator, tx_buffer);
        return true;
    case DFC_CMD_GET_KEY_VERSION:
        if(buffer_len < 2) return false;
        handle_get_key_version(emulator, buffer, buffer_len, tx_buffer);
        return true;
#if DFC_ENABLE_KEY_SETS
    case DFC_CMD_INITIALIZE_KEY_SET:
        handle_initialize_key_set(emulator, buffer, buffer_len, tx_buffer);
        return true;
    case DFC_CMD_FINALIZE_KEY_SET:
        handle_finalize_key_set(emulator, buffer, buffer_len, tx_buffer);
        return true;
    case DFC_CMD_ROLL_KEY_SET:
        handle_roll_key_set(emulator, buffer, buffer_len, tx_buffer);
        return true;
    case DFC_CMD_CHANGE_KEY_EV2:
        handle_change_key_ev2(emulator, buffer, buffer_len, tx_buffer);
        return true;
#endif
#if DFC_ENABLE_DELEGATED_APPLICATIONS
    case DFC_CMD_CREATE_DELEGATED_APPLICATION:
        handle_create_delegated_application(emulator, buffer, buffer_len, tx_buffer);
        return true;
    case DFC_CMD_GET_DELEGATED_INFO:
        handle_get_delegated_info(emulator, buffer, buffer_len, tx_buffer);
        return true;
#endif
    case DFC_CMD_GET_APPLICATION_IDS:
        handle_get_application_ids(emulator, tx_buffer);
        return true;
    case DFC_CMD_GET_DF_NAMES:
        handle_get_df_names(emulator, tx_buffer);
        return true;
    case DFC_CMD_FREE_MEM:
        handle_free_mem(emulator, tx_buffer);
        return true;
    case DFC_CMD_CREATE_APPLICATION:
        if(buffer_len < 6) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return true;
        }
        handle_create_application(emulator, buffer, buffer_len, tx_buffer);
        return true;
    case DFC_CMD_DELETE_APPLICATION:
        if(buffer_len < 4) return false;
        handle_delete_application(emulator, buffer, tx_buffer);
        return true;
    case DFC_CMD_FORMAT_PICC:
        handle_format_picc(emulator, tx_buffer);
        return true;
    case DFC_CMD_GET_ISO_FILE_IDS:
        if(!require_selected_application(emulator, tx_buffer)) return true;
        handle_get_iso_file_ids(emulator, tx_buffer);
        return true;
    case DFC_CMD_GET_FILE_IDS:
        if(!require_selected_application(emulator, tx_buffer)) return true;
        handle_get_file_ids(emulator, tx_buffer);
        return true;
    case DFC_CMD_GET_FILE_SETTINGS:
        if(buffer_len < 2) return false;
        if(!require_selected_application(emulator, tx_buffer)) return true;
        handle_get_file_settings(emulator, buffer, tx_buffer);
        return true;
    case DFC_CMD_CHANGE_FILE_SETTINGS:
        if(buffer_len < 2) return false;
        if(!require_selected_application(emulator, tx_buffer)) return true;
        handle_change_file_settings(emulator, buffer, buffer_len, tx_buffer);
        return true;
    case DFC_CMD_CREATE_STD_DATA_FILE:
        if(buffer_len < 8) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return true;
        }
        if(!require_selected_application(emulator, tx_buffer)) return true;
        handle_create_std_data_file(
            emulator, buffer, buffer_len, DFC_FILE_TYPE_STANDARD_DATA, tx_buffer);
        return true;
#if DFC_ENABLE_BACKUP_FILES
    case DFC_CMD_CREATE_BACKUP_DATA_FILE:
        if(buffer_len < 8) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return true;
        }
        if(!require_selected_application(emulator, tx_buffer)) return true;
        handle_create_std_data_file(
            emulator, buffer, buffer_len, DFC_FILE_TYPE_BACKUP_DATA, tx_buffer);
        return true;
#endif
    case DFC_CMD_CREATE_VALUE_FILE:
        if(buffer_len < 18) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return true;
        }
        if(!require_selected_application(emulator, tx_buffer)) return true;
        handle_create_value_file(emulator, buffer, tx_buffer);
        return true;
#if DFC_ENABLE_RECORD_FILES
    case DFC_CMD_CREATE_LINEAR_RECORD_FILE:
    case DFC_CMD_CREATE_CYCLIC_RECORD_FILE:
        if(!require_selected_application(emulator, tx_buffer)) return true;
        handle_create_record_file(
            emulator,
            buffer,
            buffer_len,
            cmd == DFC_CMD_CREATE_LINEAR_RECORD_FILE ? DFC_FILE_TYPE_LINEAR_RECORD :
                                                       DFC_FILE_TYPE_CYCLIC_RECORD,
            tx_buffer);
        return true;
#endif
    case DFC_CMD_DELETE_FILE:
        if(buffer_len != 2) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return true;
        }
        if(!require_selected_application(emulator, tx_buffer)) return true;
        handle_delete_file(emulator, buffer, tx_buffer);
        return true;
    case DFC_CMD_GET_VALUE:
        if(buffer_len < 2) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return true;
        }
        if(!require_selected_application(emulator, tx_buffer)) return true;
        handle_get_value(emulator, buffer, tx_buffer);
        return true;
    case DFC_CMD_CREDIT:
    case DFC_CMD_LIMITED_CREDIT:
    case DFC_CMD_DEBIT:
        if(buffer_len < 6) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return true;
        }
        if(!require_selected_application(emulator, tx_buffer)) return true;
        handle_value_delta(
            emulator,
            buffer,
            buffer_len,
            tx_buffer,
            cmd,
            cmd == DFC_CMD_DEBIT,
            cmd == DFC_CMD_LIMITED_CREDIT);
        return true;
    case DFC_CMD_COMMIT_TRANSACTION:
        if(!require_selected_application(emulator, tx_buffer)) return true;
        if(buffer_len > 2 ||
           (buffer_len == 2 && buffer[1] != DFC_TRANSACTION_COMMIT_RETURN_MAC_OPTION)) {
            clear_selected_app_pending_values(emulator);
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return true;
        }
        handle_commit_transaction(
            emulator,
            buffer_len == 2 && buffer[1] == DFC_TRANSACTION_COMMIT_RETURN_MAC_OPTION,
            tx_buffer);
        return true;
#if DFC_ENABLE_TRANSACTION_MAC
    case DFC_CMD_CREATE_TRANSACTION_MAC_FILE:
        if(!require_selected_application(emulator, tx_buffer)) return true;
        handle_create_transaction_mac_file(emulator, buffer, buffer_len, tx_buffer);
        return true;
    case DFC_CMD_COMMIT_READER_ID:
        if(!require_selected_application(emulator, tx_buffer)) return true;
        handle_commit_reader_id(emulator, buffer, buffer_len, tx_buffer);
        return true;
    case DFC_CMD_NOTIFY_TRANSACTION_SUCCESS:
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_ILLEGAL_COMMAND_CODE);
        return true;
#endif
    case DFC_CMD_ABORT_TRANSACTION:
        if(!require_selected_application(emulator, tx_buffer)) return true;
        if(buffer_len != 1) {
            clear_selected_app_pending_values(emulator);
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return true;
        }
        handle_abort_transaction(emulator, tx_buffer);
        return true;
    case DFC_CMD_CHANGE_KEY:
        handle_change_key(emulator, buffer, buffer_len, tx_buffer);
        return true;
    case DFC_CMD_AUTHENTICATE_LEGACY:
    case DFC_CMD_AUTHENTICATE_ISO:
    case DFC_CMD_AUTHENTICATE_AES:
        if(buffer_len < 2) return false;
        handle_authenticate_step1(emulator, cmd, buffer, tx_buffer);
        return true;
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    case DFC_CMD_SET_CONFIGURATION:
#if DFC_ENABLE_TRANSACTION_TIMER
        handle_set_configuration(emulator, buffer, buffer_len, tx_buffer);
#else
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_ILLEGAL_COMMAND_CODE);
#endif
        return true;
    case DFC_CMD_AUTHENTICATE_EV2_FIRST:
    case DFC_CMD_AUTHENTICATE_EV2_NON_FIRST: {
        uint8_t auth_candidate_iv[DFC_SM_MAX_CIPHER_BLOCK_SIZE];
        bool auth_has_candidate = false;
        if(!prepare_ev1_command_update(
               emulator, cmd, buffer + 1, buffer_len - 1, auth_candidate_iv, &auth_has_candidate)) {
            dfc_emulator_reset_session(emulator);
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
            return true;
        }
        bool non_first = cmd == DFC_CMD_AUTHENTICATE_EV2_NON_FIRST;
        if(handle_authenticate_ev2_start(emulator, buffer, buffer_len, non_first, tx_buffer)) {
            commit_ev1_command_update(emulator, auth_candidate_iv, auth_has_candidate);
        }
        dfc_secure_wipe(auth_candidate_iv, sizeof(auth_candidate_iv));
        return true;
    }
#endif
    case DFC_CMD_ADDITIONAL_FRAME:
        if(
#if DFC_ENABLE_DELEGATED_APPLICATIONS
            emulator->delegated_creation_pending) {
            handle_create_delegated_application_continuation(
                emulator, buffer, buffer_len, tx_buffer);
        } else if(
#endif
#if DFC_ENABLE_EV2_SECURE_MESSAGING
            emulator->ev2_authentication_pending) {
            handle_authenticate_ev2_continuation(emulator, buffer, buffer_len, tx_buffer);
        } else if(
#endif
            emulator->awaiting_step2) {
            handle_authenticate_step2(emulator, buffer, buffer_len, tx_buffer, dfc);
        } else if(emulator->get_version_frame != 0) {
            if(dfc_emulator_native_authentication_active(emulator)) {
                if(!dfc_secure_messaging_update_ev1_command(
                       emulator->secure_messaging, cmd, buffer + 1, buffer_len - 1)) {
                    clear_pending_chain(emulator);
                    dfc_emulator_reset_session(emulator);
                    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
                    return true;
                }
            }
            if(buffer_len != 1) {
                clear_pending_chain(emulator);
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            } else {
                handle_get_version_continuation(emulator, tx_buffer);
            }
            apply_ev1_response_secure_messaging(emulator, DFC_CMD_GET_VERSION, tx_buffer);
        } else if(emulator->df_names_pending) {
            handle_df_names_continuation(emulator, tx_buffer);
        } else if(emulator->pending_chain_len > emulator->pending_chain_offset) {
            handle_pending_chain_continuation(emulator, tx_buffer);
        } else {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_ILLEGAL_COMMAND_CODE);
        }
        return true;
    case DFC_CMD_READ_DATA:
        if(buffer_len < 8) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return true;
        }
        if(!require_selected_application(emulator, tx_buffer)) return true;
        handle_read_data(emulator, buffer, buffer_len, tx_buffer, dfc);
        return true;
#if DFC_ENABLE_SDM
    case DFC_CMD_GET_FILE_COUNTERS:
        if(!require_selected_application(emulator, tx_buffer)) return true;
        handle_get_file_counters(emulator, buffer, buffer_len, tx_buffer);
        return true;
#endif
    case DFC_CMD_WRITE_DATA:
        if(buffer_len < 8) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return true;
        }
        if(!require_selected_application(emulator, tx_buffer)) return true;
        handle_write_data(emulator, buffer, buffer_len, tx_buffer);
        return true;
#if DFC_ENABLE_RECORD_FILES
    case DFC_CMD_WRITE_RECORD:
        if(buffer_len < 8) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return true;
        }
        if(!require_selected_application(emulator, tx_buffer)) return true;
        handle_write_record(emulator, buffer, buffer_len, tx_buffer);
        return true;
    case DFC_CMD_READ_RECORDS:
        if(buffer_len != 8) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return true;
        }
        if(!require_selected_application(emulator, tx_buffer)) return true;
        handle_read_records(emulator, buffer, tx_buffer);
        return true;
    case DFC_CMD_UPDATE_RECORD:
    case DFC_CMD_UPDATE_RECORD_ISO:
        if(emulator->credential->card.generation == DfcGenerationEv1) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_ILLEGAL_COMMAND_CODE);
            return true;
        }
        if(buffer_len < DFC_UPDATE_RECORD_HEADER_SIZE) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return true;
        }
        if(!require_selected_application(emulator, tx_buffer)) return true;
        handle_update_record(emulator, buffer, buffer_len, tx_buffer);
        return true;
    case DFC_CMD_CLEAR_RECORD_FILE:
        if(!require_selected_application(emulator, tx_buffer)) return true;
        handle_clear_record_file(emulator, buffer, buffer_len, tx_buffer);
        return true;
#endif
    default:
        DFC_LOG_I(TAG, "Unhandled command 0x%02x", cmd);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_ILLEGAL_COMMAND_CODE);
        return true;
    }
}

bool dfc_emulator_handle_command(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer,
    void* context) {
    bool preserve_transaction_on_failure = false;
#if DFC_ENABLE_TRANSACTION_MAC
    if(buffer_len > 0 && buffer[0] == DFC_CMD_CREATE_TRANSACTION_MAC_FILE) {
        preserve_transaction_on_failure = true;
    } else if(
        buffer_len == 2 && buffer[0] == DFC_CMD_DELETE_FILE &&
        emulator->selected_application == DfcEmulatorSelectedApplicationApp) {
        DfcFile* target = dfc_credential_find_file_in_app(
            emulator->credential, emulator->selected_app_index, buffer[1]);
        preserve_transaction_on_failure = target && target->type == DFC_FILE_TYPE_TRANSACTION_MAC;
    }
#endif
    if(!dispatch_native_command(emulator, buffer, buffer_len, tx_buffer, context)) return false;
    apply_ev1_response_secure_messaging(emulator, buffer[0], tx_buffer);
    finalize_native_command(emulator, preserve_transaction_on_failure, tx_buffer);
    return true;
}

bool dfc_emulator_handle_transport_command(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer) {
    // Only this transport consumer accepts a lent ISO response in pending_chain.
    bool iso_read = buffer_len && buffer[0] == DFC_CMD_READ_RECORDS_ISO;
    if(iso_read) emulator->pending_chain_last = DFC_ISO_DEP_RESPONSE_PENDING;
    bool handled = dfc_emulator_handle_command(emulator, buffer, buffer_len, tx_buffer, NULL);
    if(iso_read && emulator->pending_chain_last == DFC_ISO_DEP_RESPONSE_PENDING)
        emulator->pending_chain_last = 0;
    return handled;
}

#endif // DFC_ENABLE_EMULATOR
