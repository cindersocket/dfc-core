#include "munit/munit.h"

#include "dfc_credential.h"
#include "dfc_emulator.h"
#include "dfc_port.h"
#include "dfc_port_host.h"

#include <string.h>

typedef struct {
    const void* pointer;
    size_t length;
    bool observed;
    bool zeroed;
} FreedRegion;

typedef struct {
    FreedRegion regions[3];
    size_t count;
} FreeAudit;

static void observe_freed_region(const void* pointer, void* context) {
    FreeAudit* audit = context;
    for(size_t region_index = 0; region_index < audit->count; region_index++) {
        FreedRegion* region = &audit->regions[region_index];
        if(region->pointer != pointer) continue;
        region->observed = true;
        region->zeroed = true;
        const uint8_t* bytes = pointer;
        for(size_t byte_index = 0; byte_index < region->length; byte_index++) {
            if(bytes[byte_index] != 0) region->zeroed = false;
        }
    }
}

static MunitResult
    test_emulator_owned_storage_wiped_before_free(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    DfcCredential credential = {0};
    DfcEmulator* emulator = dfc_emulator_alloc(&credential);
    munit_assert_not_null(emulator);

    const size_t command_length = 37;
    emulator->command_chain = dfc_platform_alloc(command_length, DfcAllocEmulator);
    munit_assert_not_null(emulator->command_chain);
    emulator->command_chain_len = command_length;
    emulator->command_chain_expected = command_length;
    memset(emulator->command_chain, 0xA5, command_length);

#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
    const size_t snapshot_length = 43;
    emulator->transaction_snapshot_pool = dfc_platform_alloc(snapshot_length, DfcAllocEmulator);
    munit_assert_not_null(emulator->transaction_snapshot_pool);
    emulator->transaction_snapshot_pool_length = snapshot_length;
    memset(emulator->transaction_snapshot_pool, 0x5A, snapshot_length);
#else
    const size_t snapshot_length = 0;
#endif

    memset(emulator->rnd_b, 0xC3, sizeof(emulator->rnd_b));
    FreeAudit audit = {
        .regions =
            {
                {emulator->command_chain, command_length, false, false},
#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
                {emulator->transaction_snapshot_pool, snapshot_length, false, false},
#else
                {NULL, snapshot_length, true, true},
#endif
                {emulator, sizeof(*emulator), false, false},
            },
        .count = 3,
    };
    dfc_host_set_free_observer(observe_freed_region, &audit);
    dfc_emulator_free(emulator);
    dfc_host_set_free_observer(NULL, NULL);

    for(size_t index = 0; index < 3; index++) {
        munit_assert_true(audit.regions[index].observed);
        munit_assert_true(audit.regions[index].zeroed);
    }
    return MUNIT_OK;
}

static MunitResult
    test_session_reset_wipes_command_chain(const MunitParameter params[], void* data) {
    (void)params;
    (void)data;

    DfcCredential credential = {0};
    DfcEmulator* emulator = dfc_emulator_alloc(&credential);
    munit_assert_not_null(emulator);
    const size_t command_length = 29;
    emulator->command_chain = dfc_platform_alloc(command_length, DfcAllocEmulator);
    munit_assert_not_null(emulator->command_chain);
    emulator->command_chain_active = true;
    emulator->command_chain_len = command_length;
    emulator->command_chain_expected = command_length;
    memset(emulator->command_chain, 0xA5, command_length);

    FreeAudit audit = {
        .regions = {{emulator->command_chain, command_length, false, false}},
        .count = 1,
    };
    dfc_host_set_free_observer(observe_freed_region, &audit);
    dfc_emulator_reset_session(emulator);
    dfc_host_set_free_observer(NULL, NULL);
    munit_assert_true(audit.regions[0].observed);
    munit_assert_true(audit.regions[0].zeroed);
    munit_assert_null(emulator->command_chain);
    dfc_emulator_free(emulator);
    return MUNIT_OK;
}

static MunitResult test_activation_reset_wipes_retained_and_released_storage(
    const MunitParameter params[],
    void* data) {
    (void)params;
    (void)data;

    DfcCredential credential = {0};
    DfcEmulator* emulator = dfc_emulator_alloc(&credential);
    munit_assert_not_null(emulator);
    const size_t command_length = 31;
    emulator->command_chain = dfc_platform_alloc(command_length, DfcAllocEmulator);
    munit_assert_not_null(emulator->command_chain);
    emulator->command_chain_len = command_length;
    memset(emulator->command_chain, 0xA5, command_length);

#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
    const size_t snapshot_length = 41;
    emulator->transaction_snapshot_pool = dfc_platform_alloc(snapshot_length, DfcAllocEmulator);
    munit_assert_not_null(emulator->transaction_snapshot_pool);
    emulator->transaction_snapshot_pool_length = snapshot_length;
    memset(emulator->transaction_snapshot_pool, 0x5A, snapshot_length);
#endif
    memset(emulator->rnd_b, 0xC3, sizeof(emulator->rnd_b));
    memset(emulator->tx_buffer, 0x3C, sizeof(*emulator->tx_buffer));

    FreeAudit audit = {
        .regions =
            {
                {emulator->command_chain, command_length, false, false},
#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
                {emulator->transaction_snapshot_pool, snapshot_length, false, false},
#endif
            },
#if DFC_ENABLE_TRANSACTIONAL_DATA_FILES
        .count = 2,
#else
        .count = 1,
#endif
    };
    dfc_host_set_free_observer(observe_freed_region, &audit);
    dfc_emulator_reset_activation(emulator);
    dfc_host_set_free_observer(NULL, NULL);
    for(size_t index = 0; index < audit.count; index++) {
        munit_assert_true(audit.regions[index].observed);
        munit_assert_true(audit.regions[index].zeroed);
    }
    munit_assert_memory_equal(
        sizeof(emulator->rnd_b), emulator->rnd_b, ((uint8_t[sizeof(emulator->rnd_b)]){0}));
    munit_assert_memory_equal(
        sizeof(*emulator->tx_buffer),
        emulator->tx_buffer,
        ((uint8_t[sizeof(*emulator->tx_buffer)]){0}));
    dfc_emulator_free(emulator);
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/owned-storage-wiped-before-free",
     test_emulator_owned_storage_wiped_before_free,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/session-reset-wipes-command-chain",
     test_session_reset_wipes_command_chain,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/activation-reset-wipes-storage",
     test_activation_reset_wipes_retained_and_released_storage,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite = {
    "/dfc_teardown",
    tests,
    NULL,
    1,
    MUNIT_SUITE_OPTION_NONE,
};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
