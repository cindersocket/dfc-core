// Property test for the raw ISO-DEP frame path.
//
// Hand-written cases only cover the inputs someone thought of; the retry-buffer
// overflow and the block-number regression both sat outside them. This drives
// the frame entry point with seeded pseudo-random traffic of every block kind,
// frame lengths on both sides of each storage boundary, and response buffers
// from zero bytes up, then checks invariants that must hold after every call:
//
//  * storage ownership: the retry/reassembly length never exceeds the chain
//    buffer, spilled bytes always have a chain buffer of exactly that length,
//    and no inline byte past the length is left behind;
//  * output bounds: an accepted frame never reports more than the capacity;
//  * block numbers: an independent model of the card's single toggling block
//    number agrees with every block the card sends.
//
// Run it under ASan and UBSan (make test SANITIZE=address,undefined), where a
// stray write is a hard failure rather than a silent one.

#include "dfc_virtual_picc_test_helpers.h"
#include "dfc_emulator_i.h"
#include "dfc_iso_dep.h"

#include <string.h>

enum {
    RecordFile = 0x0F,
    Iterations = 6000,
    MaxFrame = 2300,
    ResponseSlack = 4,
};

typedef struct {
    uint64_t state;
} Rng;

static uint32_t next_random(Rng* rng) {
    rng->state ^= rng->state << 13;
    rng->state ^= rng->state >> 7;
    rng->state ^= rng->state << 17;
    return (uint32_t)(rng->state >> 16);
}

static size_t pick_length(Rng* rng) {
    // Both sides of every boundary the staging code has: the inline retry
    // array, one ISO-DEP block, the 255/256 byte short APDU edge, 600, and the
    // size of the command-chain buffer that retry bytes spill into.
    static const size_t boundaries[] = {
        0,
        1,
        2,
        3,
        7,
        8,
        47,
        48,
        49,
        63,
        64,
        100,
        127,
        128,
        129,
        133,
        134,
        135,
        136,
        137,
        200,
        254,
        255,
        256,
        257,
        300,
        599,
        600,
        601,
        1000,
        2000,
        2047,
        2048,
        DFC_EMULATOR_CHAIN_BUFFER_SIZE - 1,
        DFC_EMULATOR_CHAIN_BUFFER_SIZE,
        DFC_EMULATOR_CHAIN_BUFFER_SIZE + 1,
        MaxFrame - 1};
    if(next_random(rng) % 4 == 0) return next_random(rng) % MaxFrame;
    return boundaries[next_random(rng) % (sizeof(boundaries) / sizeof(boundaries[0]))];
}

static size_t pick_capacity(Rng* rng) {
    static const size_t capacities[] = {0, 1, 2, 3, 4, 8, 16, 50, 51, 52, 64, 255, 256, 600, 2048};
    return capacities[next_random(rng) % (sizeof(capacities) / sizeof(capacities[0]))];
}

// A command header that makes the frame look like a command the card accepts
// or at least parses deep enough to reach its storage decisions.
static size_t write_command_prefix(Rng* rng, uint8_t* out) {
    switch(next_random(rng) % 8) {
    case 0: // native WriteData, wrapped
        out[0] = 0x90, out[1] = 0x8D, out[2] = 0, out[3] = 0;
        return 4;
    case 1: // native WriteRecord, wrapped
        out[0] = 0x90, out[1] = 0x8B, out[2] = 0, out[3] = 0;
        return 4;
    case 2: // native ReadData alternate, wrapped
        out[0] = 0x90, out[1] = 0xAD, out[2] = 0, out[3] = 0;
        return 4;
    case 3: // ISO APPEND RECORD
        out[0] = 0x00, out[1] = 0xE2, out[2] = 0, out[3] = 0;
        return 4;
    case 4: // ISO UPDATE BINARY
        out[0] = 0x00, out[1] = 0xD6, out[2] = 0, out[3] = 0;
        return 4;
    case 5: // ISO READ RECORD
        out[0] = 0x00, out[1] = 0xB2, out[2] = 1, out[3] = 4;
        return 4;
    case 6: // native commands without a wrapper
        out[0] = (uint8_t)(next_random(rng) & 0xFF);
        return 1;
    default:
        return 0;
    }
}

typedef struct {
    DfcCredential credential;
    DfcVirtualPiccSession* session;
    // Model of the card's block number, kept independently of the emulator.
    uint8_t card_bn;
    uint8_t last_block[DFC_VIRTUAL_PICC_MAX_BLOCK_SIZE];
    size_t last_block_len;
    bool selected;
    Rng* rng;
    // Full on-air frame size announced by the reader, including header and CRC.
    size_t frame_size;
    // How many new I-blocks the card has sent: lets a chain be read back in full.
    unsigned i_blocks_seen;
    // Complete multi-block answers read back and checked byte for byte.
    unsigned full_chains;
} Fixture;

static void activate(Fixture* fixture) {
    DfcVirtualPiccActivation activation;
    munit_assert_int(
        dfc_virtual_picc_scan_iso14443a(fixture->session, &activation),
        ==,
        DfcVirtualPiccStatusOk);
    // A different frame size announced at every activation (FSDI 0..11; values
    // above 8 are reserved and mean the largest).
    static const unsigned frame_sizes[] = {16, 24, 32, 40, 48, 64, 96, 128, 256};
    unsigned fsdi = next_random(fixture->rng) % 12;
    unsigned frame_size = fsdi < sizeof(frame_sizes) / sizeof(frame_sizes[0]) ? frame_sizes[fsdi] :
                                                                                256;
    fixture->frame_size = frame_size;
    const uint8_t rats[] = {DFC_ISO_DEP_RATS, (uint8_t)(fsdi << 4)};
    uint8_t response[64];
    size_t response_len = 0;
    munit_assert_int(
        dfc_virtual_picc_iso_dep_frame_exchange(
            fixture->session, rats, sizeof(rats), response, sizeof(response), &response_len),
        ==,
        DfcVirtualPiccStatusOk);
    // Work inside the record file's application so ISO reads can reach it.
    fixture->session->emulator->selected_application = DfcEmulatorSelectedApplicationApp;
    fixture->session->emulator->selected_app_index = fixture->credential.files[0].app_index;
    fixture->card_bn = 0;
    // Measured: before it sends anything the card answers a retransmission
    // request as if its last block were an empty I-block numbered 1.
    fixture->last_block[0] = DFC_ISO_DEP_I_BLOCK | DFC_ISO_DEP_SEQUENCE_BIT;
    fixture->last_block_len = 1;
    fixture->selected = true;
}

static void open_fixture(Fixture* fixture, Rng* rng) {
    fixture->rng = rng;
    load_standard_credential(&fixture->credential);
    fixture->credential.card.generation = DfcGenerationEv3;
    DfcFile* file = dfc_credential_find_file_in_app(&fixture->credential, 0, RecordFile);
    munit_assert_not_null(file);
    file->type = DFC_FILE_TYPE_LINEAR_RECORD;
    file->comm_settings = DFC_COMM_PLAIN;
    file->access_rights = 0xEEEE;
    file->state.record.size = 300;
    file->state.record.count = 3;
    file->state.record.max_records = 3;
    file->has_iso_file_id = true;
    file->iso_file_id = 0x1001;
    munit_assert_true(dfc_file_resize(&fixture->credential, file, 900));
    memset(dfc_file_data(&fixture->credential, file), 0x5A, 900);
    fixture->session = dfc_virtual_picc_session_alloc(&fixture->credential);
    munit_assert_not_null(fixture->session);
    activate(fixture);
}

static void assert_storage_invariants(const Fixture* fixture) {
    const DfcVirtualPiccSession* session = fixture->session;
    const DfcEmulator* emulator = session->emulator;
    const size_t inline_size = sizeof(session->pending_command);
    munit_assert_size(session->pending_command_len, <=, DFC_EMULATOR_CHAIN_BUFFER_SIZE);
    if(session->pending_command_len > inline_size) {
        munit_assert_not_null(emulator->command_chain);
        munit_assert_false(emulator->command_chain_active);
        munit_assert_size(emulator->command_chain_len, >=, session->pending_command_len);
    }
    // A command-chain buffer that holds staged bytes must record at least their
    // length, because freeing it wipes exactly command_chain_len bytes (on
    // DESELECT, rescan and so on). A larger recorded length only wipes more.
    if(emulator->command_chain && !emulator->command_chain_active &&
       session->pending_command_len > 0) {
        munit_assert_size(emulator->command_chain_len, >=, session->pending_command_len);
    }
    // Bytes beyond the staged length must have been wiped, not left behind.
    size_t used = session->pending_command_len < inline_size ? session->pending_command_len :
                                                               inline_size;
    for(size_t i = used; i < inline_size; i++)
        munit_assert_uint8(session->pending_command[i], ==, 0);
}

// Applies the card block-number rule to one exchange and checks the reply.
static void check_block_number(
    Fixture* fixture,
    const uint8_t* frame,
    size_t frame_len,
    const uint8_t* response,
    size_t response_len) {
    uint8_t pcb = frame[0];
    uint8_t kind = pcb & DFC_ISO_DEP_BLOCK_MASK;
    uint8_t reply = response[0] & DFC_ISO_DEP_BLOCK_MASK;
    if(kind == 0xC0) {
        // DESELECT ends the activation; the next frame needs a new RATS.
        fixture->selected = false;
        return;
    }
    munit_assert_true(reply == 0x00 || reply == 0x80);
    uint8_t reply_bn = response[0] & DFC_ISO_DEP_SEQUENCE_BIT;
    if(reply == 0x00) {
        // Every I-block respects the frame size announced in RATS, and a block
        // that says more follows is exactly full.
        size_t prefix = 1 + ((response[0] & DFC_ISO_DEP_CID) ? 1 : 0);
        munit_assert_size(response_len, >=, prefix);
        size_t inf_len = response_len - prefix;
        munit_assert_size(response_len + 2, <=, fixture->frame_size);
        size_t max_inf = fixture->frame_size - prefix - 2;
        if(max_inf > 48) max_inf = 48;
        munit_assert_size(inf_len, <=, max_inf);
        if(response[0] & DFC_ISO_DEP_MORE) munit_assert_size(inf_len, ==, max_inf);
    }
    if(kind == 0x00) {
        munit_assert_uint8(reply_bn, ==, fixture->card_bn);
        fixture->card_bn ^= 1;
        if(reply == 0x00) fixture->i_blocks_seen++;
    } else if((pcb & DFC_ISO_DEP_R_NAK) != 0) {
        // R(NAK) never advances the card's number. It is answered by an R(ACK)
        // repeating the current number, or by a retransmission of the last
        // block while a response chain is in flight.
        bool retransmission = response_len == fixture->last_block_len &&
                              memcmp(response, fixture->last_block, response_len) == 0;
        if(!retransmission) munit_assert_uint8(reply, ==, 0x80);
        munit_assert_uint8(reply_bn, ==, (uint8_t)(fixture->card_bn ^ 1));
    } else if(
        response_len == fixture->last_block_len &&
        memcmp(response, fixture->last_block, response_len) == 0) {
        // Retransmission of the last block repeats its number.
        munit_assert_uint8(reply_bn, ==, (uint8_t)(fixture->card_bn ^ 1));
    } else {
        munit_assert_uint8(reply, ==, 0x00);
        munit_assert_uint8(reply_bn, ==, fixture->card_bn);
        fixture->card_bn ^= 1;
        fixture->i_blocks_seen++;
    }
    (void)frame_len;
    // Every block the card transmits is remembered for retransmission.
    if(kind == 0x00 || ((pcb & DFC_ISO_DEP_R_NAK) == 0 &&
                        !(response_len == fixture->last_block_len &&
                          memcmp(response, fixture->last_block, response_len) == 0))) {
        if(response_len <= sizeof(fixture->last_block)) {
            memcpy(fixture->last_block, response, response_len);
            fixture->last_block_len = response_len;
        }
    }
}

static void run_frame(Fixture* fixture, const uint8_t* frame, size_t frame_len, size_t capacity) {
    static uint8_t response[2048 + ResponseSlack];
    // The guard bytes after the capacity expose any write past it.
    memset(response, 0xA5, sizeof(response));
    size_t response_len = (size_t)-1;
    DfcVirtualPiccStatus status = dfc_virtual_picc_iso_dep_frame_exchange(
        fixture->session, frame, frame_len, response, capacity, &response_len);
    for(size_t i = capacity; i < sizeof(response) && i < capacity + ResponseSlack; i++)
        munit_assert_uint8(response[i], ==, 0xA5);
    if(status == DfcVirtualPiccStatusOk) {
        munit_assert_size(response_len, >, 0);
        munit_assert_size(response_len, <=, capacity);
        check_block_number(fixture, frame, frame_len, response, response_len);
    }
    assert_storage_invariants(fixture);
}

// A complete chained ISO APPEND RECORD, sent as an attentive reader would. The
// final fragment executes a command whose bytes live in the chain buffer.
static void run_chained_request(Fixture* fixture, Rng* rng) {
    // Totals include the sizes just below, at and just above what the chain
    // buffer can hold once the 7-byte extended header is counted.
    static const size_t totals[] = {
        40,
        100,
        150,
        200,
        300,
        600,
        DFC_EMULATOR_CHAIN_BUFFER_SIZE - 8,
        DFC_EMULATOR_CHAIN_BUFFER_SIZE - 7,
        DFC_EMULATOR_CHAIN_BUFFER_SIZE - 6};
    size_t total = totals[next_random(rng) % (sizeof(totals) / sizeof(totals[0]))];
    static uint8_t command[DFC_EMULATOR_CHAIN_BUFFER_SIZE + 16];
    command[0] = 0x00, command[1] = 0xE2, command[2] = 0, command[3] = 0;
    command[4] = 0, command[5] = (uint8_t)(total >> 8), command[6] = (uint8_t)total;
    for(size_t i = 0; i < total; i++)
        command[7 + i] = (uint8_t)next_random(rng);
    size_t command_len = 7 + total;
    size_t capacity = (next_random(rng) % 4) ? 256 : pick_capacity(rng);
    static uint8_t frame[64];
    for(size_t offset = 0; offset < command_len && fixture->selected;) {
        size_t chunk = command_len - offset > 48 ? 48 : command_len - offset;
        bool more = offset + chunk < command_len;
        frame[0] = (uint8_t)(DFC_ISO_DEP_I_BLOCK | fixture->session->expected_pcd_sequence |
                             (more ? DFC_ISO_DEP_MORE : 0));
        memcpy(frame + 1, command + offset, chunk);
        run_frame(fixture, frame, chunk + 1, capacity);
        offset += chunk;
    }
}

// Reads a 200-byte record and then acknowledges the answer block by block, the
// way a reader drains a response chain. This is the only path that exercises a
// multi-block response, so it is driven explicitly instead of by chance. The
// file is reset to known contents first, as a linear or a cyclic file, so the
// bytes that come back can be checked: linear record 1 is the OLDEST record and
// cyclic record 1 is the NEWEST, and an index mistake shows up as the wrong fill.
static void run_response_chain(Fixture* fixture, Rng* rng) {
    // Start from a clean activation (and a fresh random frame size) so an earlier
    // answer that was abandoned part-way cannot be mistaken for this one.
    activate(fixture);
    DfcFile* file = &fixture->credential.files[0];
    const bool cyclic = next_random(rng) & 1;
    file->type = cyclic ? DFC_FILE_TYPE_CYCLIC_RECORD : DFC_FILE_TYPE_LINEAR_RECORD;
    // 200 bytes plus the two status bytes fit the 256-byte transmit buffer the
    // frame path answers from, so the whole answer can be sent as a chain.
    file->state.record.size = 200;
    file->state.record.max_records = 4;
    file->state.record.count = 3;
    uint8_t* records = dfc_file_data(&fixture->credential, file);
    for(unsigned k = 0; k < 3; k++)
        memset(records + k * 200, 0x11 * (k + 1), 200);
    const uint8_t expected = cyclic ? 0x33 : 0x11;

    // READ RECORD, record 1, short file identifier 1, P2 = 100b (one record).
    static const uint8_t read_record[] = {0x00, 0xB2, 0x01, 0x0C, 0x00};
    uint8_t frame[1 + sizeof(read_record)];
    frame[0] = (uint8_t)(DFC_ISO_DEP_I_BLOCK | fixture->session->expected_pcd_sequence);
    memcpy(frame + 1, read_record, sizeof(read_record));
    size_t capacity = (next_random(rng) % 4) ? 256 : pick_capacity(rng);

    uint8_t collected[400];
    size_t collected_len = 0;
    bool collecting = true;
    unsigned seen = fixture->i_blocks_seen;
    run_frame(fixture, frame, sizeof(frame), capacity);
    for(unsigned step = 0; step < 24 && fixture->selected; step++) {
        bool new_block = fixture->i_blocks_seen > seen;
        seen = fixture->i_blocks_seen;
        if(new_block && collecting) {
            size_t inf = fixture->last_block_len - 1;
            if(collected_len + inf <= sizeof(collected)) {
                memcpy(collected + collected_len, fixture->last_block + 1, inf);
                collected_len += inf;
            } else {
                collecting = false;
            }
        }
        bool more = fixture->last_block_len > 0 &&
                    (fixture->last_block[0] & DFC_ISO_DEP_BLOCK_MASK) == 0x00 &&
                    (fixture->last_block[0] & DFC_ISO_DEP_MORE) != 0;
        if(!more) break;
        // A number different from the card's last one asks for the next block.
        uint8_t ack = (uint8_t)(DFC_ISO_DEP_R_BLOCK | fixture->card_bn);
        run_frame(fixture, &ack, 1, capacity);
    }
    // When the whole answer was read, it must be that record and a success status.
    if(collecting && capacity >= 51 && collected_len > 2) {
        munit_assert_size(collected_len, ==, 202);
        for(size_t i = 0; i < 200; i++)
            munit_assert_uint8(collected[i], ==, expected);
        munit_assert_uint8(collected[200], ==, 0x90);
        munit_assert_uint8(collected[201], ==, 0x00);
        fixture->full_chains++;
    }
}

// Calls the direct (unframed) API in the middle of framed traffic. Both entry
// points share one staging area and one command-chain buffer, so mixing them is
// where lending and retiring bugs have hidden: a long command arriving while a
// native continuation is pending, or a retry staged over a half-built request.
static void run_direct_command(Fixture* fixture, Rng* rng) {
    static uint8_t command[MaxFrame];
    static uint8_t response[2048 + ResponseSlack];
    size_t length = 0;
    switch(next_random(rng) % 4) {
    case 0: // GetVersion: leaves a native continuation pending
        command[length++] = 0x60;
        break;
    case 1: // a chain-capable command, long enough to borrow the chain buffer
    case 2:
        length = 129 + next_random(rng) % 400;
        memset(command, 0x41, length);
        command[0] = (next_random(rng) & 1) ? 0x8D : 0x8B;
        break;
    default: // anything at all
        length = 1 + next_random(rng) % 300;
        for(size_t i = 0; i < length; i++)
            command[i] = (uint8_t)next_random(rng);
        break;
    }
    size_t capacity = pick_capacity(rng);
    memset(response, 0xA5, sizeof(response));
    size_t response_len = (size_t)-1;
    (void)dfc_virtual_picc_iso_dep_exchange(
        fixture->session, command, length, response, capacity, &response_len);
    for(size_t i = capacity; i < sizeof(response) && i < capacity + ResponseSlack; i++)
        munit_assert_uint8(response[i], ==, 0xA5);
    assert_storage_invariants(fixture);
}

static MunitResult
    test_random_frames_hold_invariants(const MunitParameter params[], void* user_data) {
    (void)params;
    (void)user_data;
    Fixture fixture;
    memset(&fixture, 0, sizeof(fixture));
    Rng rng = {0x9E3779B97F4A7C15ULL};
    open_fixture(&fixture, &rng);

    static uint8_t frame[MaxFrame + 4];
    for(unsigned iteration = 0; iteration < Iterations; iteration++) {
        uint32_t roll = next_random(&rng) % 100;
        if(fixture.selected && roll >= 96) {
            run_chained_request(&fixture, &rng);
            continue;
        }
        if(fixture.selected && roll >= 93) {
            run_response_chain(&fixture, &rng);
            continue;
        }
        if(fixture.selected && roll >= 91) {
            run_direct_command(&fixture, &rng);
            continue;
        }
        if(!fixture.selected || roll < 2) {
            if(roll < 1) munit_assert_int(dfc_virtual_picc_field_off(fixture.session), ==, 0);
            activate(&fixture);
            assert_storage_invariants(&fixture);
            continue;
        }

        size_t frame_len = 0;
        uint8_t bn = (uint8_t)(next_random(&rng) & 1);
        if(roll < 55) {
            // I-block, usually numbered as an attentive reader would number it.
            bn = (next_random(&rng) % 4) ? fixture.session->expected_pcd_sequence : bn;
            frame[frame_len++] = (uint8_t)(DFC_ISO_DEP_I_BLOCK | bn |
                                           ((next_random(&rng) % 3 == 0) ? DFC_ISO_DEP_MORE : 0));
            if(next_random(&rng) % 16 == 0) frame[0] |= DFC_ISO_DEP_CID, frame[frame_len++] = 0;
            size_t payload = pick_length(&rng);
            size_t prefix = write_command_prefix(&rng, frame + frame_len);
            if(prefix > payload) prefix = payload;
            for(size_t i = prefix; i < payload; i++)
                frame[frame_len + i] = (uint8_t)next_random(&rng);
            frame_len += payload;
        } else if(roll < 90) {
            frame[frame_len++] = (uint8_t)(DFC_ISO_DEP_R_BLOCK | bn |
                                           ((next_random(&rng) % 3 == 0) ? DFC_ISO_DEP_R_NAK : 0));
            // An R-block may carry a card identifier too. Its block number must
            // still come from the card's own count, never from the reader's bit.
            if(next_random(&rng) % 4 == 0) frame[0] |= DFC_ISO_DEP_CID, frame[frame_len++] = 0;
        } else if(roll < 95) {
            frame[frame_len++] = (uint8_t)(DFC_ISO_DEP_S_BLOCK | (next_random(&rng) & 0x30));
        } else {
            // A repeat of the previous traffic is the realistic retry shape.
            frame[frame_len++] = (uint8_t)(DFC_ISO_DEP_I_BLOCK | bn);
            size_t payload = pick_length(&rng);
            for(size_t i = 0; i < payload; i++)
                frame[frame_len + i] = (uint8_t)next_random(&rng);
            frame_len += payload;
        }

        run_frame(&fixture, frame, frame_len, pick_capacity(&rng));
    }
    // The generators must actually reach what they exist to test. If response
    // chains stop being delivered (for example the answer no longer fits), this
    // fails instead of the test quietly checking nothing.
    munit_assert_uint(fixture.full_chains, >=, 60);
    munit_assert_int(dfc_virtual_picc_field_off(fixture.session), ==, 0);
    assert_storage_invariants(&fixture);
    dfc_virtual_picc_session_free(fixture.session);
    return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/random-frames-hold-invariants",
     test_random_frames_hold_invariants,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

static const MunitSuite suite =
    {"/dfc_iso_dep_frame_properties", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[]) {
    return munit_suite_main(&suite, NULL, argc, argv);
}
