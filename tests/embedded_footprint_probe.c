#include <stdint.h>

#include "dfc_credential.h"
#include "dfc_emulator.h"
#include "dfc_secure_messaging.h"
#include "dfc_virtual_picc.h"

_Static_assert(DFC_BUILD_ROLE == DFC_ROLE_TARGET, "footprint probe requires target role");
_Static_assert(DFC_BUILD_PROFILE == DFC_PROFILE_FULL_EV3, "footprint probe requires full EV3");
_Static_assert(DFC_MAX_APPS == DFC_EV1_MAX_APPLICATIONS, "application capacity changed");
_Static_assert(DFC_MAX_FILES == DFC_EV1_MAX_FILES_PER_APP, "file capacity changed");
_Static_assert(DFC_MAX_KEYS == 14, "key capacity changed");
_Static_assert(DFC_FILE_POOL_SIZE == 8192, "file pool capacity changed");
_Static_assert(DFC_KEY_POOL_SIZE == 4096, "key pool capacity changed");
_Static_assert(DFC_MAX_FILE_DATA == 2048, "maximum file data changed");

#define DFC_SIZE_SYMBOL(name, value) const uint8_t name[(value)] = {0}

DFC_SIZE_SYMBOL(dfc_footprint_DfcApplication, sizeof(DfcApplication));
DFC_SIZE_SYMBOL(dfc_footprint_DfcCredential, sizeof(DfcCredential));
DFC_SIZE_SYMBOL(dfc_footprint_DfcEmulator, sizeof(DfcEmulator));
DFC_SIZE_SYMBOL(dfc_footprint_DfcFile, sizeof(DfcFile));
DFC_SIZE_SYMBOL(dfc_footprint_DfcSecureMessaging, sizeof(DfcSecureMessaging));
DFC_SIZE_SYMBOL(dfc_footprint_DfcVirtualPiccSession, sizeof(DfcVirtualPiccSession));
DFC_SIZE_SYMBOL(dfc_footprint_application_capacity, DFC_MAX_APPS);
DFC_SIZE_SYMBOL(dfc_footprint_file_capacity, DFC_MAX_FILES);
DFC_SIZE_SYMBOL(dfc_footprint_key_capacity, DFC_MAX_KEYS);
DFC_SIZE_SYMBOL(dfc_footprint_file_pool, DFC_FILE_POOL_SIZE);
DFC_SIZE_SYMBOL(dfc_footprint_key_pool, DFC_KEY_POOL_SIZE);
DFC_SIZE_SYMBOL(dfc_footprint_max_file_data, DFC_MAX_FILE_DATA);
