#include "munit/munit.h"

#include "dfc_der.h"
#include "dfc_reader_test_link.h"
#include "dfc_text.h"

static void expect_credential_unchanged(const DfcCredential* before, const DfcCredential* after) {
    munit_assert_memory_equal(sizeof(*before), before, after);
}

static MunitResult test_disabled_round_trips(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    DfcCredential credential;
    dfc_credential_clear(&credential);
    credential.uid_len = DFC_DESFIRE_UID_LEN;
    memcpy(credential.uid, "\x04\x22\x33\x44\x55\x66\x77", credential.uid_len);
    credential.card.generation = DfcGenerationEv3;
    credential.card.storage = 4096;
    credential.card.uid_provenance = DfcUidProvenanceReal;
    credential.picc_key_settings_1 = 0x0F;
    credential.picc_key_settings_2 = DFC_KEY_TYPE_AES | 1;
    munit_assert_true(dfc_credential_keys_resize(&credential, NULL, 1, DFC_AES_KEY_LENGTH));
    const uint8_t aid[] = {0x01, 0x00, 0x00};
    DfcApplication* app = dfc_credential_create_application_desfire_order(
        &credential, aid, 0x0F, DFC_KEY_TYPE_AES | 1);
    munit_assert_not_null(app);
    app->auth_command = DFC_CMD_AUTHENTICATE_AES;
    app->delegated = true;
    app->delegated_quota_limit = 64;
    app->delegated_free_blocks = 60;
    app->delegated_format_disabled = true;

    static uint8_t der[DFC_DER_MAX_SIZE];
    size_t der_len = 0;
    munit_assert_int(dfc_der_encode(&credential, der, sizeof(der), &der_len), ==, DfcDerOk);
    static DfcCredential decoded;
    munit_assert_int(dfc_der_decode(&decoded, der, der_len), ==, DfcDerOk);
    munit_assert_true(decoded.apps[0].delegated_format_disabled);

    static char text[DFC_TEXT_MAX_SIZE];
    size_t text_len = 0;
    munit_assert_int(dfc_text_write(&credential, text, sizeof(text), &text_len), ==, DfcTextOk);
    munit_assert_not_null(strstr(text, "Application 00 Delegated Format Disabled: 1\n"));
    DfcTextError detail = {0};
    munit_assert_int(dfc_text_parse(&decoded, text, text_len, &detail), ==, DfcTextOk);
    munit_assert_true(decoded.apps[0].delegated_format_disabled);
    return MUNIT_OK;
}

static uint8_t send_configuration(Link* link, uint8_t value, uint8_t comm_mode) {
    DfcCommand command;
    DfcReaderExchange exchange;
    munit_assert_int(
        dfc_command_set_configuration(&command, DFC_CONFIGURATION_CARD_OR_APPLICATION, &value, 1),
        ==,
        DfcCommandOk);
    DfcReaderStatus status = link_send(link, &command, comm_mode, &exchange);
    if(status == DfcReaderOk) return DFC_STATUS_OK;
    munit_assert_int(status, ==, DfcReaderCardError);
    return dfc_reader_result_status(&exchange);
}

static void open_authenticated_picc(Link* link, DfcGeneration generation) {
    link_open(link, generation, DfcReaderFramingNative);
    link->credential.picc_key_settings_1 = 0x0F;
    link->credential.picc_key_settings_2 = DFC_KEY_TYPE_AES | 1;
    link->credential.picc_auth_command = DFC_CMD_AUTHENTICATE_AES;
    link->credential.picc_has_auth_commands = true;
    link->credential.picc_auth_commands =
        dfc_credential_default_auth_commands(link->credential.picc_key_settings_2, generation);
    munit_assert_true(dfc_credential_keys_resize(&link->credential, NULL, 1, sizeof(AES_KEY_0)));
    memcpy(dfc_credential_key(&link->credential, NULL, 0), AES_KEY_0, sizeof(AES_KEY_0));
    munit_assert_int(
        authenticate(link, DFC_CMD_AUTHENTICATE_AES, 0, AES_KEY_0, sizeof(AES_KEY_0)),
        ==,
        DfcReaderOk);
}

static void enable_delegated_format_control(Link* link, size_t app_index);

static void check_picc_configuration(
    uint8_t configuration,
    bool random_id,
    bool legacy_random_id,
    bool proximity_mandatory,
    bool authentication_mandatory) {
    Link link;
    open_authenticated_picc(&link, DfcGenerationEv3);
    if((configuration & DFC_CONFIGURATION_PROXIMITY_MANDATORY) != 0) {
        link.credential.picc_has_proximity_key = true;
    }
    if((configuration & DFC_CONFIGURATION_AUTHENTICATION_MANDATORY) != 0) {
        link.credential.virtual_card_configured = true;
    }
    dfc_credential_clear_dirty(&link.credential);

    munit_assert_uint8(
        send_configuration(&link, configuration, DFC_COMM_ENCIPHERED), ==, DFC_STATUS_OK);
    munit_assert_true(link.credential.picc_format_disabled);
    munit_assert_int(link.credential.picc_random_id, ==, random_id);
    munit_assert_int(link.credential.picc_random_id_legacy, ==, legacy_random_id);
    munit_assert_int(link.credential.virtual_card_proximity_mandatory, ==, proximity_mandatory);
    munit_assert_int(
        link.credential.virtual_card_authentication_mandatory, ==, authentication_mandatory);
    munit_assert_true(link.credential.dirty);
    link_close(&link);
}

static MunitResult
    test_picc_configuration_bits_compose(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    check_picc_configuration(0x03, true, false, false, false);
    check_picc_configuration(0x05, false, false, true, false);
    check_picc_configuration(0x09, false, false, false, true);
    check_picc_configuration(0x23, true, true, false, false);
    return MUNIT_OK;
}

static MunitResult
    test_picc_configuration_validation_is_atomic(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    static const uint8_t invalid[] = {0x20, 0x10, 0x40, 0x80};
    for(size_t i = 0; i < sizeof(invalid); i++) {
        Link link;
        open_authenticated_picc(&link, DfcGenerationEv3);
        DfcCredential before = link.credential;
        munit_assert_uint8(
            send_configuration(&link, invalid[i], DFC_COMM_ENCIPHERED),
            ==,
            DFC_STATUS_PARAMETER_ERROR);
        expect_credential_unchanged(&before, &link.credential);
        link_close(&link);
    }
    return MUNIT_OK;
}

static MunitResult test_picc_configuration_requires_supporting_keys(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    static const uint8_t unsupported[] = {
        DFC_CONFIGURATION_PROXIMITY_MANDATORY,
        DFC_CONFIGURATION_AUTHENTICATION_MANDATORY,
    };
    for(size_t i = 0; i < sizeof(unsupported); i++) {
        Link link;
        open_authenticated_picc(&link, DfcGenerationEv3);
        DfcCredential before = link.credential;
        munit_assert_uint8(
            send_configuration(&link, unsupported[i], DFC_COMM_ENCIPHERED),
            ==,
            DFC_STATUS_PERMISSION_DENIED);
        expect_credential_unchanged(&before, &link.credential);
        link_close(&link);
    }
    return MUNIT_OK;
}

static MunitResult
    test_legacy_generation_configuration(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    Link link;
    open_authenticated_picc(&link, DfcGenerationEv1);
    munit_assert_uint8(send_configuration(&link, 0x03, DFC_COMM_ENCIPHERED), ==, DFC_STATUS_OK);
    munit_assert_true(link.credential.picc_format_disabled);
    munit_assert_true(link.credential.picc_random_id);
    munit_assert_false(link.credential.picc_random_id_legacy);
    link_close(&link);

    open_authenticated_picc(&link, DfcGenerationEv1);
    DfcCredential before = link.credential;
    munit_assert_uint8(
        send_configuration(&link, 0x05, DFC_COMM_ENCIPHERED), ==, DFC_STATUS_PARAMETER_ERROR);
    expect_credential_unchanged(&before, &link.credential);
    link_close(&link);
    return MUNIT_OK;
}

static MunitResult test_invalid_application_selection_cannot_configure_picc(
    const MunitParameter params[],
    void* user_data) {
    (void)params;
    (void)user_data;
    Link link;
    open_authenticated_picc(&link, DfcGenerationEv3);
    link.picc->emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    link.picc->emulator->selected_app_index = link.credential.num_apps;
    DfcCredential before = link.credential;
    munit_assert_uint8(
        send_configuration(&link, DFC_CONFIGURATION_DISABLE_FORMAT, DFC_COMM_ENCIPHERED),
        ==,
        DFC_STATUS_PERMISSION_DENIED);
    expect_credential_unchanged(&before, &link.credential);
    link_close(&link);
    return MUNIT_OK;
}

static void format_delegated_and_prove_session(Link* link) {
    DfcCommand command;
    DfcReaderExchange exchange;
    munit_assert_int(dfc_command_format_picc(&command), ==, DfcCommandOk);
    munit_assert_int(link_send(link, &command, DFC_COMM_MAC, &exchange), ==, DfcReaderOk);
    munit_assert_true(dfc_reader_session_is_authenticated(&link->session));

    munit_assert_int(dfc_command_get_key_settings(&command), ==, DfcCommandOk);
    munit_assert_int(link_send(link, &command, DFC_COMM_MAC, &exchange), ==, DfcReaderOk);
    munit_assert_true(dfc_reader_session_is_authenticated(&link->session));
}

static MunitResult
    test_successful_format_preserves_session(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    Link link;
    open_authenticated_picc(&link, DfcGenerationEv3);
    DfcCommand command;
    DfcReaderExchange exchange;
    munit_assert_int(dfc_command_format_picc(&command), ==, DfcCommandOk);
    munit_assert_int(link_send(&link, &command, DFC_COMM_MAC, &exchange), ==, DfcReaderOk);
    munit_assert_false(dfc_reader_session_is_authenticated(&link.session));
    munit_assert_int(link_send(&link, &command, DFC_COMM_MAC, &exchange), ==, DfcReaderCardError);
    munit_assert_uint8(dfc_reader_result_status(&exchange), ==, DFC_STATUS_AUTHENTICATION_ERR);
    link_close(&link);

    link_open(&link, DfcGenerationEv3, DfcReaderFramingNative);
    enable_delegated_format_control(&link, 0);
    select_app(&link, AID_AES);
    munit_assert_false(link.session.selected_application_is_picc);
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 0, AES_KEY_0, sizeof(AES_KEY_0)),
        ==,
        DfcReaderOk);
    munit_assert_false(link.session.selected_application_is_picc);
    format_delegated_and_prove_session(&link);
    link_close(&link);
    return MUNIT_OK;
}

static void enable_delegated_format_control(Link* link, size_t app_index) {
    link->credential.apps[app_index].delegated = true;
    link->credential.apps[app_index].delegated_quota_limit = 64;
    link->credential.apps[app_index].delegated_free_blocks = 60;
}

static void check_legacy_family(
    const uint8_t aid[3],
    size_t app_index,
    uint8_t cipher,
    const uint8_t* key,
    size_t key_len) {
    Link link;
    link_open(&link, DfcGenerationEv3, DfcReaderFramingNative);
    enable_delegated_format_control(&link, app_index);
    select_app(&link, aid);
    munit_assert_int(authenticate(&link, cipher, 0, key, key_len), ==, DfcReaderOk);
    uint8_t status =
        send_configuration(&link, DFC_CONFIGURATION_DISABLE_FORMAT, DFC_COMM_ENCIPHERED);
    munit_assert_true(link.credential.apps[app_index].delegated_format_disabled);
    munit_assert_uint8(status, ==, DFC_STATUS_OK);
    munit_assert_true(link.credential.apps[app_index].delegated_format_disabled);
    munit_assert_true(dfc_reader_session_is_authenticated(&link.session));
    link_close(&link);
}

static MunitResult
    test_supported_authentication_families(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    check_legacy_family(AID_AES, 0, DFC_CMD_AUTHENTICATE_AES, AES_KEY_0, sizeof(AES_KEY_0));
    check_legacy_family(AID_ISO, 1, DFC_CMD_AUTHENTICATE_ISO, TDES_KEY_0, sizeof(TDES_KEY_0));
    check_legacy_family(AID_D40, 3, DFC_CMD_AUTHENTICATE_LEGACY, DES_KEY_0, sizeof(DES_KEY_0));
    return MUNIT_OK;
}

static void
    check_picc_family(uint8_t cipher, const uint8_t* key, size_t key_len, uint8_t key_type) {
    Link link;
    link_open(&link, DfcGenerationEv3, DfcReaderFramingNative);
    link.credential.picc_key_settings_1 = 0x0F;
    link.credential.picc_key_settings_2 = key_type | 1;
    link.credential.picc_auth_command = cipher;
    link.credential.picc_has_auth_commands = true;
    link.credential.picc_auth_commands = dfc_credential_default_auth_commands(
        link.credential.picc_key_settings_2, link.credential.card.generation);
    munit_assert_true(dfc_credential_keys_resize(&link.credential, NULL, 1, key_len));
    memcpy(dfc_credential_key(&link.credential, NULL, 0), key, key_len);

    munit_assert_int(authenticate(&link, cipher, 0, key, key_len), ==, DfcReaderOk);
    munit_assert_uint8(
        send_configuration(&link, DFC_CONFIGURATION_DISABLE_FORMAT, DFC_COMM_ENCIPHERED),
        ==,
        DFC_STATUS_OK);
    munit_assert_true(link.credential.picc_format_disabled);

    DfcCommand format;
    DfcReaderExchange exchange;
    munit_assert_int(dfc_command_format_picc(&format), ==, DfcCommandOk);
    munit_assert_int(link_send(&link, &format, DFC_COMM_MAC, &exchange), ==, DfcReaderCardError);
    munit_assert_uint8(dfc_reader_result_status(&exchange), ==, DFC_STATUS_ILLEGAL_COMMAND_CODE);
    link_close(&link);
}

static MunitResult
    test_picc_supported_authentication_families(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    check_picc_family(DFC_CMD_AUTHENTICATE_AES, AES_KEY_0, sizeof(AES_KEY_0), DFC_KEY_TYPE_AES);
    check_picc_family(
        DFC_CMD_AUTHENTICATE_ISO, TDES_KEY_0, sizeof(TDES_KEY_0), DFC_KEY_TYPE_DES_2K3DES);
    check_picc_family(
        DFC_CMD_AUTHENTICATE_LEGACY, DES_KEY_0, sizeof(DES_KEY_0), DFC_KEY_TYPE_DES_2K3DES);
    return MUNIT_OK;
}

static MunitResult
    test_picc_requires_master_atomically(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    Link link;
    link_open(&link, DfcGenerationEv3, DfcReaderFramingNative);
    link.credential.picc_key_settings_1 = 0x0F;
    link.credential.picc_key_settings_2 = DFC_KEY_TYPE_AES | 2;
    link.credential.picc_auth_command = DFC_CMD_AUTHENTICATE_AES;
    link.credential.picc_has_auth_commands = true;
    link.credential.picc_auth_commands = dfc_credential_default_auth_commands(
        link.credential.picc_key_settings_2, link.credential.card.generation);
    munit_assert_true(dfc_credential_keys_resize(&link.credential, NULL, 2, sizeof(AES_KEY_0)));
    memcpy(dfc_credential_key(&link.credential, NULL, 0), AES_KEY_0, sizeof(AES_KEY_0));
    memcpy(dfc_credential_key(&link.credential, NULL, 1), AES_KEY_1, sizeof(AES_KEY_1));

    DfcCredential before = link.credential;
    munit_assert_uint8(
        send_configuration(&link, DFC_CONFIGURATION_DISABLE_FORMAT, DFC_COMM_ENCIPHERED),
        ==,
        DFC_STATUS_AUTHENTICATION_ERR);
    expect_credential_unchanged(&before, &link.credential);

    uint8_t wrong_key[sizeof(AES_KEY_0)];
    memcpy(wrong_key, AES_KEY_0, sizeof(wrong_key));
    wrong_key[0] ^= 1;
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 0, wrong_key, sizeof(wrong_key)),
        ==,
        DfcReaderCardError);
    expect_credential_unchanged(&before, &link.credential);
    link_close(&link);
    return MUNIT_OK;
}

static MunitResult
    test_corrupt_full_command_is_atomic(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    Link link;
    link_open(&link, DfcGenerationEv3, DfcReaderFramingNative);
    enable_delegated_format_control(&link, 0);
    select_app(&link, AID_AES);
    munit_assert_int(
        authenticate(&link, DFC_CMD_AUTHENTICATE_AES, 0, AES_KEY_0, sizeof(AES_KEY_0)),
        ==,
        DfcReaderOk);
    DfcCredential before = link.credential;

    uint8_t value = DFC_CONFIGURATION_DISABLE_FORMAT;
    DfcCommand command;
    DfcReaderExchange exchange;
    DfcReaderOptions options = {.comm_mode = DFC_COMM_ENCIPHERED};
    munit_assert_int(
        dfc_command_set_configuration(&command, DFC_CONFIGURATION_CARD_OR_APPLICATION, &value, 1),
        ==,
        DfcCommandOk);
    munit_assert_int(
        dfc_reader_exchange_begin(
            &exchange, &link.session, DfcReaderFramingNative, &command, &options),
        ==,
        DfcReaderOk);
    uint8_t request[DFC_COMMAND_MAX_APDU];
    size_t request_len = 0;
    munit_assert_int(
        dfc_reader_step(&exchange, NULL, 0, request, sizeof(request), &request_len),
        ==,
        DfcReaderPending);
    munit_assert_size(request_len, >, 2);
    request[request_len - 1] ^= 0x80;
    uint8_t response[32];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_exchange(
            link.picc, request, request_len, response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    munit_assert_size(response_len, ==, 1);
    munit_assert_uint8(response[0], ==, DFC_STATUS_INTEGRITY_ERROR);
    expect_credential_unchanged(&before, &link.credential);
    link_close(&link);
    return MUNIT_OK;
}

static MunitResult test_authenticated_disable(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    Link link;
    link_open(&link, DfcGenerationEv3, DfcReaderFramingIso7816);
    link.credential.apps[0].delegated = true;
    link.credential.apps[0].delegated_quota_limit = 64;
    link.credential.apps[0].delegated_free_blocks = 60;
    select_app(&link, AID_AES);

    DfcCredential before = link.credential;
    munit_assert_uint8(
        send_configuration(&link, DFC_CONFIGURATION_DISABLE_FORMAT, DFC_COMM_PLAIN),
        ==,
        DFC_STATUS_AUTHENTICATION_ERR);
    expect_credential_unchanged(&before, &link.credential);

    munit_assert_int(authenticate_ev2(&link, true, 1, AES_KEY_1), ==, DfcReaderOk);
    before = link.credential;
    munit_assert_uint8(
        send_configuration(&link, DFC_CONFIGURATION_DISABLE_FORMAT, DFC_COMM_ENCIPHERED),
        ==,
        DFC_STATUS_AUTHENTICATION_ERR);
    expect_credential_unchanged(&before, &link.credential);

    munit_assert_int(authenticate_ev2(&link, true, 0, AES_KEY_0), ==, DfcReaderOk);
    dfc_credential_clear_dirty(&link.credential);
    munit_assert_uint8(
        send_configuration(&link, DFC_CONFIGURATION_DISABLE_FORMAT, DFC_COMM_ENCIPHERED),
        ==,
        DFC_STATUS_OK);
    munit_assert_true(link.credential.apps[0].delegated_format_disabled);
    munit_assert_true(link.credential.dirty);
    munit_assert_true(dfc_reader_session_is_authenticated(&link.session));

    DfcCommand format;
    DfcReaderExchange exchange;
    munit_assert_int(dfc_command_format_picc(&format), ==, DfcCommandOk);
    munit_assert_int(link_send(&link, &format, DFC_COMM_MAC, &exchange), ==, DfcReaderCardError);
    munit_assert_uint8(dfc_reader_result_status(&exchange), ==, DFC_STATUS_PERMISSION_DENIED);
    link_close(&link);
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/disabled-round-trips", test_disabled_round_trips, NULL, NULL, 0, NULL},
    {"/authenticated-disable", test_authenticated_disable, NULL, NULL, 0, NULL},
    {"/supported-authentication-families",
     test_supported_authentication_families,
     NULL,
     NULL,
     0,
     NULL},
    {"/picc-supported-authentication-families",
     test_picc_supported_authentication_families,
     NULL,
     NULL,
     0,
     NULL},
    {"/picc-requires-master-atomically", test_picc_requires_master_atomically, NULL, NULL, 0, NULL},
    {"/picc-configuration-bits-compose", test_picc_configuration_bits_compose, NULL, NULL, 0, NULL},
    {"/picc-configuration-validation-is-atomic",
     test_picc_configuration_validation_is_atomic,
     NULL,
     NULL,
     0,
     NULL},
    {"/picc-configuration-requires-supporting-keys",
     test_picc_configuration_requires_supporting_keys,
     NULL,
     NULL,
     0,
     NULL},
    {"/legacy-generation-configuration", test_legacy_generation_configuration, NULL, NULL, 0, NULL},
    {"/invalid-application-selection-cannot-configure-picc",
     test_invalid_application_selection_cannot_configure_picc,
     NULL,
     NULL,
     0,
     NULL},
    {"/successful-format-preserves-session",
     test_successful_format_preserves_session,
     NULL,
     NULL,
     0,
     NULL},
    {"/corrupt-full-command-is-atomic", test_corrupt_full_command_is_atomic, NULL, NULL, 0, NULL},
    {NULL, NULL, NULL, NULL, 0, NULL},
};

static const MunitSuite suite = {"/dfc_format_configuration", tests, NULL, 1, 0};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
