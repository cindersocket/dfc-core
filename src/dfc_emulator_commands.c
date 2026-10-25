#include "dfc_emulator_i.h"
#include "dfc_emulator_commands_i.h"
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

void dfc_emulator_command_apply_ev1_response_secure_messaging(
    DfcEmulator* emulator,
    uint8_t cmd,
    DfcByteBuf* tx_buffer);

int32_t dfc_emulator_command_read_int32_le(const uint8_t* data) {
    return (int32_t)((uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) |
                     ((uint32_t)data[3] << 24));
}

void dfc_emulator_command_append_int32_le(DfcByteBuf* tx_buffer, int32_t value) {
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

static bool require_selected_application(DfcEmulator* emulator, DfcByteBuf* tx_buffer) {
    if(emulator->selected_application == DfcEmulatorSelectedApplicationApp) {
        return true;
    }

    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
    return false;
}

bool dfc_emulator_command_is_authenticated_with_key(const DfcEmulator* emulator, uint8_t key_no) {
    return (dfc_emulator_native_authentication_active(emulator) && emulator->auth_key_no == key_no)
#if DFC_ENABLE_EV2_SECURE_MESSAGING
           || (emulator->ev2_session_active && emulator->ev2_authenticated_key_no == key_no)
#endif
        ;
}

bool dfc_emulator_command_is_authenticated_as_master(const DfcEmulator* emulator) {
    return dfc_emulator_command_is_authenticated_with_key(emulator, 0x00);
}

uint8_t dfc_emulator_command_current_key_settings_1(DfcEmulator* emulator) {
    DfcApplication* app = dfc_emulator_current_app(emulator);
    if(app) return app->key_settings_1;
    return emulator->credential->picc_key_settings_1;
}

uint8_t dfc_emulator_command_current_key_settings_2(DfcEmulator* emulator) {
    DfcApplication* app = dfc_emulator_current_app(emulator);
    if(app) return app->key_settings_2;
    return emulator->credential->picc_key_settings_2;
}

// A slot with no key entry carries the factory
// default, every octet zero at the length the key type gives. The default is
// supplied here, where the key is used, so a credential that omits the entry is
// never rewritten to carry it. `factory` is the caller's scratch, used only when
// the credential holds no material for this slot.
const uint8_t* dfc_emulator_command_auth_key(
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
        key_len = dfc_credential_key_length(dfc_emulator_command_current_key_settings_2(emulator));
    }
    if(key_len > factory_cap) key_len = factory_cap;
    *out_key_len = key_len;

    const uint8_t* key = emulator_key(emulator, key_no);
    if(key) return key;
    memset(factory, 0, key_len);
    return factory;
}

#if DFC_ENABLE_SPECIAL_KEY_STATUS
bool dfc_emulator_command_picc_disabled_special_key(DfcEmulator* emulator, uint8_t key_no) {
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
bool dfc_emulator_command_is_available_authentication_key(DfcEmulator* emulator, uint8_t key_no) {
#if DFC_ENABLE_DELEGATED_APPLICATIONS
    if(emulator->selected_application == DfcEmulatorSelectedApplicationPicc &&
       emulator->credential->picc_has_dam_keys && key_no == DFC_DAM_AUTH_KEY_NUMBER)
        return true;
#endif
    return key_no < emulator_num_keys(emulator);
}
#endif

bool dfc_emulator_command_require_directory_access(DfcEmulator* emulator, DfcByteBuf* tx_buffer) {
    if(allows_free_directory_access(dfc_emulator_command_current_key_settings_1(emulator)) ||
       dfc_emulator_command_is_authenticated_as_master(emulator)) {
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
// boundary swaps the two octets on the way in (dfc_emulator_command_access_rights_from_wire) and back
// out (dfc_emulator_command_access_rights_to_wire); nothing between those two points sees wire order.
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

uint8_t dfc_emulator_command_access_change_nibble(uint16_t access_rights) {
    return access_nibble(access_rights, 0);
}

bool dfc_emulator_command_key_references_exist(
    uint32_t references,
    size_t reference_count,
    size_t key_count) {
    while(reference_count-- > 0) {
        uint8_t key = (uint8_t)(references & 0x0F);
        if(key < DFC_ACCESS_FREE && key >= key_count) return false;
        references >>= 4;
    }
    return true;
}

// APDU boundary conversions. `first` is the first access-rights octet on the
// wire, which is the low octet of the logical value.
uint16_t dfc_emulator_command_access_rights_from_wire(uint8_t first, uint8_t second) {
    return (uint16_t)(((uint16_t)second << 8) | first);
}

void dfc_emulator_command_access_rights_to_wire(uint16_t access_rights, uint8_t out[2]) {
    out[0] = (uint8_t)(access_rights & 0xFF);
    out[1] = (uint8_t)(access_rights >> 8);
}

// The nibble that governs `write` when true and `read` when false. The
// read&write nibble is a second, independent path to either and is checked
// alongside it, never in place of it.
static uint8_t access_primary_nibble(uint16_t access_rights, bool write) {
    return write ? access_write_nibble(access_rights) : access_read_nibble(access_rights);
}

bool dfc_emulator_command_access_nibble_allows(uint8_t nibble, const DfcEmulator* emulator) {
    if(nibble == DFC_ACCESS_FREE) return true;
    if(nibble == DFC_ACCESS_DENY) return false;
    return dfc_emulator_command_is_authenticated_with_key(emulator, nibble);
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
void dfc_emulator_command_clear_pending_chain(DfcEmulator* emulator) {
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

bool dfc_emulator_command_has_pending_additional_work(const DfcEmulator* emulator) {
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

void dfc_emulator_command_append_status_payload(
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
static void dfc_emulator_command_emit_payload_with_chaining_comm(
    DfcEmulator* emulator,
    DfcByteBuf* tx_buffer,
    uint8_t cmd,
    const uint8_t* payload,
    size_t payload_len,
    size_t entry,
    uint8_t comm,
    bool length_unknown) {
    bool iso_transport = emulator->pending_chain_last == DFC_ISO_DEP_RESPONSE_PENDING;
    dfc_emulator_command_clear_pending_chain(emulator);

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
        payload_len = comm == DFC_COMM_MAC ?
                          dfc_secure_messaging_generate_d40_response_mac(
                              emulator->secure_messaging,
                              payload,
                              payload_len,
                              emulator->pending_chain,
                              sizeof(emulator->pending_chain)) :
                          dfc_secure_messaging_generate_response_with_length_marker(
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
    }
    if(is_secured) emulator->response_secured = true;

    // The alternate ReadRecords instruction delegates continuation to ISO-DEP.
    // Return its complete logical response so the transport can split I-blocks.
    if(cmd == DFC_CMD_READ_RECORDS_ISO) {
        if(!iso_transport) {
            size_t used = dfc_bytebuf_get_size_bytes(tx_buffer);
            if(used < DFC_BYTEBUF_MAX && payload_len < DFC_BYTEBUF_MAX - used)
                dfc_emulator_command_append_status_payload(
                    tx_buffer, DFC_STATUS_OK, payload, payload_len);
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
        dfc_emulator_command_append_status_payload(tx_buffer, DFC_STATUS_OK, payload, payload_len);
        if(secured_in_pending) dfc_secure_wipe(emulator->pending_chain, pending_used);
        return;
    }

    size_t remaining = payload_len - frame;
    if(secured_in_pending) {
        emulator->pending_chain_len = payload_len;
        emulator->pending_chain_offset = frame;
        dfc_emulator_command_append_status_payload(
            tx_buffer, DFC_CMD_ADDITIONAL_FRAME, payload, frame);
        return;
    }
    if(remaining > sizeof(emulator->pending_chain)) {
        remaining = sizeof(emulator->pending_chain);
    }
    memcpy(emulator->pending_chain, payload + frame, remaining);
    emulator->pending_chain_len = remaining;
    emulator->pending_chain_offset = 0;
    dfc_emulator_command_append_status_payload(
        tx_buffer, DFC_CMD_ADDITIONAL_FRAME, payload, frame);
    return;

crypto_failure:
    dfc_secure_wipe(emulator->pending_chain, pending_used);
    dfc_emulator_command_clear_pending_chain(emulator);
    dfc_emulator_reset_session(emulator);
    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
}

// Most answers are returned plain or under the session default; a file read
// passes its own communication mode through the *_comm form above.
void dfc_emulator_command_emit_payload_with_chaining(
    DfcEmulator* emulator,
    DfcByteBuf* tx_buffer,
    uint8_t cmd,
    const uint8_t* payload,
    size_t payload_len,
    size_t entry) {
    dfc_emulator_command_emit_payload_with_chaining_comm(
        emulator, tx_buffer, cmd, payload, payload_len, entry, DFC_COMM_PLAIN, false);
}

static void handle_pending_chain_continuation(DfcEmulator* emulator, DfcByteBuf* tx_buffer) {
    if(emulator->pending_chain_frame == DFC_ISO_DEP_RESPONSE_PENDING) {
        dfc_emulator_command_clear_pending_chain(emulator);
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_ILLEGAL_COMMAND_CODE);
        return;
    }
    if(emulator->pending_chain_offset >= emulator->pending_chain_len) {
        dfc_emulator_command_clear_pending_chain(emulator);
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
    dfc_emulator_command_append_status_payload(
        tx_buffer, status, emulator->pending_chain + emulator->pending_chain_offset, chunk);
    emulator->pending_chain_offset += chunk;
    if(status == DFC_STATUS_OK) {
        dfc_emulator_command_clear_pending_chain(emulator);
    }
}

// The next GetDFNames record, one application per frame: AID, little-endian
// ISO file ID and DF name, for each application with an ISO file ID.
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

#if DFC_ENABLE_DELEGATED_APPLICATIONS
uint16_t
    dfc_emulator_command_delegated_application_overhead_blocks(uint8_t num_keys, size_t key_length);

#endif

// Unwraps commands that carry a clear header followed by a protected body.
// The caller owns command-IV advancement, so these commands must be deferred
// by the dispatcher. SIZE_MAX means the body failed authentication.
size_t dfc_emulator_command_unwrap_write_payload(
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
    if(comm == DFC_COMM_MAC) {
        size_t data_len = 0;
        return dfc_secure_messaging_verify_d40_command_mac(
                   emulator->secure_messaging, wrapped, wrapped_len, out, out_cap, &data_len) ?
                   data_len :
                   SIZE_MAX;
    }
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

/* Validate the slot before any type-specific allocation or state change. */
/* Publish a fully initialized file, or remove it if snapshotting cannot proceed. */
#if DFC_ENABLE_RECORD_FILES
#endif

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
        size_t wrapped_len = comm == DFC_COMM_MAC ? dfc_secure_messaging_generate_d40_response_mac(
                                                        emulator->secure_messaging,
                                                        value_bytes,
                                                        sizeof(value_bytes),
                                                        wrapped,
                                                        sizeof(wrapped)) :
                                                    dfc_secure_messaging_generate_response(
                                                        emulator->secure_messaging,
                                                        DFC_COMM_ENCIPHERED,
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
            amount = dfc_emulator_command_read_int32_le(body + 1);
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
            amount = dfc_emulator_command_read_int32_le(clear);
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
            amount = dfc_emulator_command_read_int32_le(body + 1);
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
        size_t clear_len = 0;
        bool d40_mac_ok = true;
        if(comm == DFC_COMM_MAC) {
            d40_mac_ok = dfc_secure_messaging_verify_d40_command_mac(
                emulator->secure_messaging,
                body + 1,
                body_len - 1,
                clear,
                sizeof(clear),
                &clear_len);
        } else if(comm == DFC_COMM_ENCIPHERED) {
            clear_len = dfc_secure_messaging_verify_command(
                emulator->secure_messaging,
                DFC_COMM_ENCIPHERED,
                header,
                sizeof(header),
                body + 1,
                body_len - 1,
                clear,
                sizeof(clear));
        } else {
            clear_len = body_len - 1;
        }
        if(!d40_mac_ok || (clear_len < 4 && comm != DFC_COMM_PLAIN)) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
            return;
        }
        if(comm == DFC_COMM_PLAIN) {
            if(body_len < 5) {
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
                return;
            }
            amount = dfc_emulator_command_read_int32_le(body + 1);
        } else {
            amount = dfc_emulator_command_read_int32_le(clear);
        }
    } else {
        if(body_len < 5) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return;
        }
        amount = dfc_emulator_command_read_int32_le(body + 1);
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
    emulator->transaction_snapshot_pool_capacity = length ? length : 1;
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

void dfc_emulator_command_abort_transaction(DfcEmulator* emulator, DfcByteBuf* tx_buffer) {
    bool changed = dfc_emulator_abort_transaction(emulator);
    dfc_bytebuf_append_byte(tx_buffer, changed ? DFC_STATUS_OK : DFC_STATUS_NO_CHANGES);
}

#if DFC_ENABLE_DELEGATED_APPLICATIONS
uint16_t dfc_emulator_command_delegated_application_overhead_blocks(
    uint8_t num_keys,
    size_t key_length) {
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
    uint16_t overhead_blocks =
        dfc_emulator_command_delegated_application_overhead_blocks(num_keys, key_length);
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
    dfc_emulator_command_create_application(
        emulator, create_command, sizeof(create_command), create_response);
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

static DfcSdmRenderStatus render_sdm_read_in_place(DfcEmulator* emulator, DfcFile* file) {
    if(emulator->sdm_read_cache_valid && emulator->sdm_read_cache_file_number == file->number)
        return DfcSdmRenderOk;
    DfcSdmRenderStatus status = DfcSdmRenderFailed;
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
        if(!dfc_random_fill(picc_clear + random_offset, random_padding_len)) {
            status = DfcSdmRenderRandomExhausted;
            goto cleanup;
        }
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
    status = DfcSdmRenderOk;

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
    return status;
}

DfcSdmRenderStatus dfc_emulator_render_sdm_read_status(DfcEmulator* emulator, DfcFile* file) {
    if(!emulator || !file) return DfcSdmRenderFailed;
    _Static_assert(
        DFC_EMULATOR_CHAIN_BUFFER_SIZE >= DFC_SDM_READ_CACHE_SIZE * 2,
        "SDM rollback requires two cache-sized regions");
    if(emulator->command_chain_active ||
       emulator->pending_chain_len > emulator->pending_chain_offset) {
        return DfcSdmRenderFailed;
    }
    uint8_t* saved_cache = emulator->pending_chain + DFC_SDM_READ_CACHE_SIZE;
    memcpy(saved_cache, emulator->sdm_read_cache, sizeof(emulator->sdm_read_cache));
    uint32_t saved_counter = file->sdm_read_counter;
    bool saved_valid = emulator->sdm_read_cache_valid;
    uint8_t saved_file_number = emulator->sdm_read_cache_file_number;
    size_t saved_len = emulator->sdm_read_cache_len;
    DfcSdmRenderStatus status = render_sdm_read_in_place(emulator, file);
    if(status != DfcSdmRenderOk) {
        memcpy(emulator->sdm_read_cache, saved_cache, sizeof(emulator->sdm_read_cache));
        file->sdm_read_counter = saved_counter;
        emulator->sdm_read_cache_valid = saved_valid;
        emulator->sdm_read_cache_file_number = saved_file_number;
        emulator->sdm_read_cache_len = saved_len;
    }
    dfc_secure_wipe(saved_cache, sizeof(emulator->sdm_read_cache));
    return status;
}

bool dfc_emulator_render_sdm_read(DfcEmulator* emulator, DfcFile* file) {
    return dfc_emulator_render_sdm_read_status(emulator, file) == DfcSdmRenderOk;
}
#endif

static bool handle_read_data(
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
        return true;
    }
    if(file->type != DFC_FILE_TYPE_STANDARD_DATA && file->type != DFC_FILE_TYPE_BACKUP_DATA &&
       file->type != DFC_FILE_TYPE_TRANSACTION_MAC) {
        // ReadData cannot reinterpret a value or record file as an octet stream.
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return true;
    }
    if(!file_allows_read(file, emulator)) {
        dfc_bytebuf_append_byte(tx_buffer, file_access_refusal_status(file, false));
        return true;
    }

    uint32_t offset = read_uint24_le(apdu + 2);
    uint32_t requested_len = read_uint24_le(apdu + 5);
    if(offset > file->data_len ||
       (requested_len != 0 && (size_t)offset + (size_t)requested_len > file->data_len)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_BOUNDARY_ERROR);
        return true;
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
    if(file->sdm_enabled) {
        if(!emulator->sdm_read_cache_valid && file->sdm_has_counter_limit &&
           file->sdm_read_counter >= file->sdm_counter_limit) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
            return true;
        }
        DfcSdmRenderStatus render_status = dfc_emulator_render_sdm_read_status(emulator, file);
        if(render_status == DfcSdmRenderRandomExhausted) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_MEMORY_ERROR);
            return true;
        }
        if(render_status != DfcSdmRenderOk) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
            return true;
        }
        file_bytes = emulator->sdm_read_cache;
    }
#endif
    if(read_len > 0 && !file_bytes) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
        return true;
    }

    uint8_t comm = dfc_emulator_file_effective_comm_settings(
        emulator, file, DfcFileAccessRead, file->comm_settings);
    dfc_emulator_command_emit_payload_with_chaining_comm(
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
    return true;
}

#if DFC_ENABLE_SDM
static void handle_get_file_counters(
    DfcEmulator* emulator,
    const uint8_t* buffer,
    size_t buffer_len,
    DfcByteBuf* tx_buffer) {
    bool ev1 = dfc_emulator_native_authentication_active(emulator) &&
               dfc_secure_messaging_applies_ev1(emulator->secure_messaging, buffer[0]);
    if(ev1) {
        size_t clear_len = dfc_secure_messaging_verify_ev1_transmitted_command_mac(
            emulator->secure_messaging, buffer[0], buffer + 1, buffer_len - 1);
        if(clear_len != 1) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
            return;
        }
    } else if(buffer_len != 2) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
        return;
    }
    uint8_t file_selector = buffer[1];
    if((file_selector & 0x60u) != 0) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PARAMETER_ERROR);
        return;
    }
    // The model has no secondary-application selection state, so SAI cannot
    // name a reachable file even when its low five bits are otherwise valid.
    if((file_selector & 0x80u) != 0) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
    DfcFile* file = dfc_credential_find_file_in_app(
        emulator->credential, emulator->selected_app_index, file_selector & 0x1Fu);
    if(!file) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_FILE_NOT_FOUND);
        return;
    }
    if(file->type != DFC_FILE_TYPE_STANDARD_DATA || !file->sdm_enabled) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }

    // SDMCtrRet is the low access-rights nibble. A key reference requires that
    // exact authenticated key; 0xE is free access and 0xF denies the command.
    uint8_t counter_access = (uint8_t)(file->sdm_access_rights & DFC_SDM_ACCESS_MASK);
    if(counter_access == DFC_SDM_DENIED_ACCESS) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_PERMISSION_DENIED);
        return;
    }
    if(counter_access != DFC_SDM_FREE_ACCESS &&
       !dfc_emulator_command_is_authenticated_with_key(emulator, counter_access)) {
        dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_AUTHENTICATION_ERR);
        return;
    }

    const uint8_t encoded_counter[] = {
        (uint8_t)file->sdm_read_counter,
        (uint8_t)(file->sdm_read_counter >> 8),
        (uint8_t)(file->sdm_read_counter >> 16),
        0,
        0,
    };
    bool authenticated = dfc_emulator_native_authentication_active(emulator);
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    authenticated = authenticated || emulator->ev2_session_active;
#endif
    dfc_emulator_command_emit_payload_with_chaining_comm(
        emulator,
        tx_buffer,
        DFC_CMD_GET_FILE_COUNTERS,
        encoded_counter,
        sizeof(encoded_counter),
        1,
        authenticated ? DFC_COMM_ENCIPHERED : DFC_COMM_PLAIN,
        false);
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
                bool d40_mac_ok = true;
                if(comm == DFC_COMM_MAC) {
                    d40_mac_ok = dfc_secure_messaging_verify_d40_command_mac(
                        emulator->secure_messaging,
                        wrapped,
                        wrapped_len,
                        target,
                        sizeof(emulator->pending_chain),
                        &out_len);
                } else {
                    out_len = dfc_secure_messaging_verify_command(
                        emulator->secure_messaging,
                        DFC_COMM_ENCIPHERED,
                        apdu,
                        8,
                        wrapped,
                        wrapped_len,
                        target,
                        sizeof(emulator->pending_chain));
                }
                if(!d40_mac_ok) out_len = SIZE_MAX;
                clear = target;
                scratch_len = wrapped_len;
            }
            if((out_len == 0 && wrapped_len > 0 && comm != DFC_COMM_PLAIN) ||
               out_len == SIZE_MAX) {
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
    size_t clear_len = dfc_emulator_command_unwrap_write_payload(
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
    dfc_emulator_command_emit_payload_with_chaining_comm(
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
    size_t clear_len = dfc_emulator_command_unwrap_write_payload(
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

void dfc_emulator_command_apply_ev1_response_secure_messaging(
    DfcEmulator* emulator,
    uint8_t cmd,
    DfcByteBuf* tx_buffer) {
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
    // GetVersion's first two response bodies remain plain. The three command
    // CMACs advance the IV; only the terminal response body and status are
    // authenticated, and that response CMAC becomes the next command's IV.
    if(cmd == DFC_CMD_GET_VERSION && status == DFC_CMD_ADDITIONAL_FRAME) return;
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
    bool authentication_exchange,
    const DfcByteBuf* tx_buffer) {
    size_t response_len = dfc_bytebuf_get_size_bytes(tx_buffer);
    if(response_len == 0) return;
    uint8_t status = dfc_bytebuf_get_data(tx_buffer)[0];
    if(status == DFC_STATUS_OK || status == DFC_CMD_ADDITIONAL_FRAME ||
       status == DFC_STATUS_SPECIAL_SUCCESS)
        return;
    if(!preserve_transaction_on_failure) dfc_emulator_abort_transaction(emulator);
    // Authentication handlers retire the correct family at every failure
    // stage. The generic policy has a legacy D40 exception, so applying it a
    // second time would make failed D40 authentication retain its session.
    if(authentication_exchange) return;
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
            dfc_emulator_command_apply_ev1_response_secure_messaging(
                emulator, emulator->command_chain[0], tx_buffer);
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
                              cmd == DFC_CMD_SET_CONFIGURATION ||
                              cmd == DFC_CMD_CHANGE_FILE_SETTINGS ||
                              dfc_secure_messaging_ev1_transmits_command_mac(cmd);
#if DFC_ENABLE_PROXIMITY_CHECK
    defer_ev1_cmd_cmac = defer_ev1_cmd_cmac || cmd == DFC_CMD_PREPARE_PROXIMITY_CHECK;
#endif
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    defer_ev1_cmd_cmac = defer_ev1_cmd_cmac || cmd == DFC_CMD_AUTHENTICATE_EV2_FIRST ||
                         cmd == DFC_CMD_AUTHENTICATE_EV2_NON_FIRST;
#endif
#if DFC_ENABLE_SDM
    // SDM ReadData may need randomness. Keep the EV1 IV tentative until the
    // complete response exists, so an exhausted source is retryable.
    defer_ev1_cmd_cmac = defer_ev1_cmd_cmac || cmd == DFC_CMD_READ_DATA;
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
        if(dfc_emulator_command_prepare_proximity_check(emulator, tx_buffer)) {
            commit_ev1_command_update(emulator, prepare_candidate_iv, prepare_has_candidate);
        }
        dfc_secure_wipe(prepare_candidate_iv, sizeof(prepare_candidate_iv));
        return true;
    }
    case DFC_CMD_PROXIMITY_CHECK:
        dfc_emulator_command_proximity_check(emulator, buffer, buffer_len, tx_buffer);
        return true;
    case DFC_CMD_VERIFY_PROXIMITY_CHECK:
        dfc_emulator_command_verify_proximity_check(emulator, buffer, buffer_len, tx_buffer);
        return true;
#endif
#if DFC_ENABLE_STATIC_SIGNATURE
    case DFC_CMD_READ_SIGNATURE:
        dfc_emulator_command_read_signature(emulator, buffer, buffer_len, tx_buffer);
        return true;
#endif
    case DFC_CMD_CHANGE_KEY_SETTINGS:
        dfc_emulator_command_change_key_settings(emulator, buffer, buffer_len, tx_buffer);
        return true;
    case DFC_CMD_GET_VERSION:
        if(buffer_len != 1) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return true;
        }
        dfc_emulator_command_get_version(emulator, tx_buffer);
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
        dfc_emulator_command_select_application(emulator, buffer, tx_buffer, dfc);
        return true;
    case DFC_CMD_GET_KEY_SETTINGS:
        dfc_emulator_command_get_key_settings(emulator, tx_buffer);
        return true;
    case DFC_CMD_GET_KEY_VERSION:
        if(buffer_len < 2) return false;
        dfc_emulator_command_get_key_version(emulator, buffer, buffer_len, tx_buffer);
        return true;
#if DFC_ENABLE_KEY_SETS
    case DFC_CMD_INITIALIZE_KEY_SET:
        dfc_emulator_command_initialize_key_set(emulator, buffer, buffer_len, tx_buffer);
        return true;
    case DFC_CMD_FINALIZE_KEY_SET:
        dfc_emulator_command_finalize_key_set(emulator, buffer, buffer_len, tx_buffer);
        return true;
    case DFC_CMD_ROLL_KEY_SET:
        dfc_emulator_command_roll_key_set(emulator, buffer, buffer_len, tx_buffer);
        return true;
    case DFC_CMD_CHANGE_KEY_EV2:
        dfc_emulator_command_change_key_ev2(emulator, buffer, buffer_len, tx_buffer);
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
        dfc_emulator_command_get_application_ids(emulator, tx_buffer);
        return true;
    case DFC_CMD_GET_DF_NAMES:
        dfc_emulator_command_get_df_names(emulator, tx_buffer);
        return true;
    case DFC_CMD_FREE_MEM:
        dfc_emulator_command_free_mem(emulator, tx_buffer);
        return true;
    case DFC_CMD_CREATE_APPLICATION:
        if(buffer_len < 6) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return true;
        }
        dfc_emulator_command_create_application(emulator, buffer, buffer_len, tx_buffer);
        return true;
    case DFC_CMD_DELETE_APPLICATION:
        if(buffer_len < 4) return false;
        dfc_emulator_command_delete_application(emulator, buffer, tx_buffer);
        return true;
    case DFC_CMD_FORMAT_PICC:
        dfc_emulator_command_format_picc(emulator, buffer_len, tx_buffer);
        return true;
    case DFC_CMD_GET_ISO_FILE_IDS:
        if(!require_selected_application(emulator, tx_buffer)) return true;
        dfc_emulator_command_get_iso_file_ids(emulator, tx_buffer);
        return true;
    case DFC_CMD_GET_FILE_IDS:
        if(!require_selected_application(emulator, tx_buffer)) return true;
        dfc_emulator_command_get_file_ids(emulator, tx_buffer);
        return true;
    case DFC_CMD_GET_FILE_SETTINGS:
        if(buffer_len < 2) return false;
        if(!require_selected_application(emulator, tx_buffer)) return true;
        dfc_emulator_command_get_file_settings(emulator, buffer, tx_buffer);
        return true;
    case DFC_CMD_CHANGE_FILE_SETTINGS:
        if(buffer_len < 2) return false;
        if(!require_selected_application(emulator, tx_buffer)) return true;
        dfc_emulator_command_change_file_settings(emulator, buffer, buffer_len, tx_buffer);
        return true;
    case DFC_CMD_CREATE_STD_DATA_FILE:
        if(buffer_len < 8) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return true;
        }
        if(!require_selected_application(emulator, tx_buffer)) return true;
        dfc_emulator_command_create_std_data_file(
            emulator, buffer, buffer_len, DFC_FILE_TYPE_STANDARD_DATA, tx_buffer);
        return true;
#if DFC_ENABLE_BACKUP_FILES
    case DFC_CMD_CREATE_BACKUP_DATA_FILE:
        if(buffer_len < 8) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return true;
        }
        if(!require_selected_application(emulator, tx_buffer)) return true;
        dfc_emulator_command_create_std_data_file(
            emulator, buffer, buffer_len, DFC_FILE_TYPE_BACKUP_DATA, tx_buffer);
        return true;
#endif
    case DFC_CMD_CREATE_VALUE_FILE:
        if(buffer_len < 18) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return true;
        }
        if(!require_selected_application(emulator, tx_buffer)) return true;
        dfc_emulator_command_create_value_file(emulator, buffer, tx_buffer);
        return true;
#if DFC_ENABLE_RECORD_FILES
    case DFC_CMD_CREATE_LINEAR_RECORD_FILE:
    case DFC_CMD_CREATE_CYCLIC_RECORD_FILE:
        if(!require_selected_application(emulator, tx_buffer)) return true;
        dfc_emulator_command_create_record_file(
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
        dfc_emulator_command_delete_file(emulator, buffer, tx_buffer);
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
        dfc_emulator_command_create_transaction_mac_file(emulator, buffer, buffer_len, tx_buffer);
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
        dfc_emulator_command_abort_transaction(emulator, tx_buffer);
        return true;
    case DFC_CMD_CHANGE_KEY:
        dfc_emulator_command_change_key(emulator, buffer, buffer_len, tx_buffer);
        return true;
    case DFC_CMD_AUTHENTICATE_LEGACY:
    case DFC_CMD_AUTHENTICATE_ISO:
    case DFC_CMD_AUTHENTICATE_AES:
        if(buffer_len < 2) return false;
        dfc_emulator_command_authenticate_step1(emulator, cmd, buffer, tx_buffer);
        return true;
    case DFC_CMD_SET_CONFIGURATION:
        dfc_emulator_command_set_configuration(emulator, buffer, buffer_len, tx_buffer);
        return true;
#if DFC_ENABLE_EV2_SECURE_MESSAGING
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
        if(dfc_emulator_command_authenticate_ev2_start(
               emulator, buffer, buffer_len, non_first, tx_buffer)) {
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
            dfc_emulator_command_authenticate_ev2_continuation(
                emulator, buffer, buffer_len, tx_buffer);
        } else if(
#endif
            emulator->awaiting_step2) {
            dfc_emulator_command_authenticate_step2(emulator, buffer, buffer_len, tx_buffer, dfc);
        } else if(emulator->get_version_frame != 0) {
            if(dfc_emulator_native_authentication_active(emulator)) {
                if(!dfc_secure_messaging_update_ev1_command(
                       emulator->secure_messaging, cmd, buffer + 1, buffer_len - 1)) {
                    dfc_emulator_command_clear_pending_chain(emulator);
                    dfc_emulator_reset_session(emulator);
                    dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
                    return true;
                }
            }
            if(buffer_len != 1) {
                dfc_emulator_command_clear_pending_chain(emulator);
                dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            } else {
                dfc_emulator_command_get_version_continuation(emulator, tx_buffer);
            }
            dfc_emulator_command_apply_ev1_response_secure_messaging(
                emulator, DFC_CMD_GET_VERSION, tx_buffer);
        } else if(emulator->df_names_pending) {
            dfc_emulator_command_df_names_continuation(emulator, tx_buffer);
        } else if(emulator->pending_chain_len > emulator->pending_chain_offset) {
            handle_pending_chain_continuation(emulator, tx_buffer);
        } else {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_ILLEGAL_COMMAND_CODE);
        }
        return true;
    case DFC_CMD_READ_DATA:
#if DFC_ENABLE_SDM
    {
        uint8_t read_original_iv[DFC_SM_MAX_CIPHER_BLOCK_SIZE] = {0};
        uint8_t read_candidate_iv[DFC_SM_MAX_CIPHER_BLOCK_SIZE];
        bool read_has_candidate = false;
        if(dfc_emulator_native_authentication_active(emulator)) {
            memcpy(read_original_iv, emulator->secure_messaging->iv, sizeof(read_original_iv));
        }
        if(!prepare_ev1_command_update(
               emulator, cmd, buffer + 1, buffer_len - 1, read_candidate_iv, &read_has_candidate)) {
            dfc_emulator_reset_session(emulator);
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_INTEGRITY_ERROR);
            return true;
        }
        commit_ev1_command_update(emulator, read_candidate_iv, read_has_candidate);
        if(buffer_len < 8) {
            dfc_secure_wipe(read_original_iv, sizeof(read_original_iv));
            dfc_secure_wipe(read_candidate_iv, sizeof(read_candidate_iv));
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return true;
        }
        if(!require_selected_application(emulator, tx_buffer)) {
            dfc_secure_wipe(read_original_iv, sizeof(read_original_iv));
            dfc_secure_wipe(read_candidate_iv, sizeof(read_candidate_iv));
            return true;
        }
        bool handled = handle_read_data(emulator, buffer, buffer_len, tx_buffer, dfc);
        if(dfc_random_failure_is_retryable() && read_has_candidate &&
           dfc_emulator_native_authentication_active(emulator)) {
            memcpy(emulator->secure_messaging->iv, read_original_iv, sizeof(read_original_iv));
        }
        dfc_secure_wipe(read_original_iv, sizeof(read_original_iv));
        dfc_secure_wipe(read_candidate_iv, sizeof(read_candidate_iv));
        return handled;
    }
#else
        if(buffer_len < 8) {
            dfc_bytebuf_append_byte(tx_buffer, DFC_STATUS_LENGTH_ERROR);
            return true;
        }
        if(!require_selected_application(emulator, tx_buffer)) return true;
        return handle_read_data(emulator, buffer, buffer_len, tx_buffer, dfc);
#endif
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
    bool authentication_exchange = false;
    bool preserve_auth_transaction = false;
    if(buffer_len > 0) {
        uint8_t command = buffer[0];
        authentication_exchange = command == DFC_CMD_AUTHENTICATE_LEGACY ||
                                  command == DFC_CMD_AUTHENTICATE_ISO ||
                                  command == DFC_CMD_AUTHENTICATE_AES;
        preserve_auth_transaction = command == DFC_CMD_AUTHENTICATE_LEGACY;
#if DFC_ENABLE_EV2_SECURE_MESSAGING
        authentication_exchange = authentication_exchange ||
                                  command == DFC_CMD_AUTHENTICATE_EV2_FIRST ||
                                  command == DFC_CMD_AUTHENTICATE_EV2_NON_FIRST;
#endif
        if(command == DFC_CMD_ADDITIONAL_FRAME) {
            authentication_exchange = emulator->awaiting_step2;
            preserve_auth_transaction = emulator->awaiting_step2 &&
                                        emulator->pending_auth_cipher ==
                                            DFC_CMD_AUTHENTICATE_LEGACY;
#if DFC_ENABLE_EV2_SECURE_MESSAGING
            authentication_exchange = authentication_exchange ||
                                      emulator->ev2_authentication_pending;
#endif
        }
    }
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
    preserve_transaction_on_failure = preserve_transaction_on_failure || preserve_auth_transaction;
    if(!dispatch_native_command(emulator, buffer, buffer_len, tx_buffer, context)) return false;
    // A caller-controlled source can be replenished and retried. Its adapter
    // replaces the provisional status, so do not publish failure side effects.
    if(dfc_random_failure_is_retryable()) return true;
    dfc_emulator_command_apply_ev1_response_secure_messaging(emulator, buffer[0], tx_buffer);
    finalize_native_command(
        emulator, preserve_transaction_on_failure, authentication_exchange, tx_buffer);
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
