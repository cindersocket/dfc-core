#include "dfc_emulator_i.h"

#if DFC_ENABLE_EMULATOR

static uint8_t access_nibble(uint16_t access_rights, unsigned shift) {
    return (uint8_t)((access_rights >> shift) & 0x0F);
}

static bool authenticated_with_key(const DfcEmulator* emulator, uint8_t key_no) {
    return (dfc_emulator_native_authentication_active(emulator) && emulator->auth_key_no == key_no)
#if DFC_ENABLE_EV2_SECURE_MESSAGING
           || (emulator->ev2_session_active && emulator->ev2_authenticated_key_no == key_no)
#endif
        ;
}

uint8_t dfc_emulator_file_effective_comm_settings(
    const DfcEmulator* emulator,
    const DfcFile* file,
    DfcFileAccess access,
    uint8_t configured_comm) {
    bool authenticated = dfc_emulator_native_authentication_active(emulator)
#if DFC_ENABLE_EV2_SECURE_MESSAGING
                         || emulator->ev2_session_active
#endif
        ;
    if(!authenticated) return configured_comm;

    uint8_t primary;
    uint8_t alternate = DFC_ACCESS_DENY;
    switch(access) {
    case DfcFileAccessRead:
        primary = access_nibble(file->access_rights, 12);
        alternate = access_nibble(file->access_rights, 4);
        break;
    case DfcFileAccessWrite:
        primary = access_nibble(file->access_rights, 8);
        alternate = access_nibble(file->access_rights, 4);
        break;
    case DfcFileAccessReadWrite:
        primary = access_nibble(file->access_rights, 4);
        break;
    case DfcFileAccessChange:
        primary = access_nibble(file->access_rights, 0);
        break;
    default:
        return configured_comm;
    }

    bool free_access = primary == DFC_ACCESS_FREE || alternate == DFC_ACCESS_FREE;
    bool authenticated_access =
        (primary < DFC_ACCESS_FREE && authenticated_with_key(emulator, primary)) ||
        (alternate < DFC_ACCESS_FREE && authenticated_with_key(emulator, alternate));
    return free_access && !authenticated_access ? DFC_COMM_PLAIN : configured_comm;
}

#endif
