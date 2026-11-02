// Conformance vector runner for DFC core.
//
// Executes a canonical DESFire vector file against the engine.
//
// Usage: test_dfc_conformance_vectors <vector-file> [<vector-file> ...]
//        test_dfc_conformance_vectors --export-plans <directory> <vector-file> ...
//
// --export-plans also writes one language-neutral replay plan per replayable
// vector (see docs/conformance-vector-format.md, "Replay plans"). The language
// bindings replay those plans instead of parsing vectors themselves.

#include <stdarg.h>
#include "dfc_vector_replay_random.h"
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dfc_credential.h"
#include "dfc_command.h"
#include "dfc_der.h"
#include "dfc_emulator.h"
#include "dfc_virtual_picc.h"
#include "dfc_port_host.h"

enum {
    VectorMaximumLineLength = 4096,
    VectorMaximumByteCount = 1024,
    VectorMaximumInjectedRandomByteCount = 64,
    VectorStatusWordLength = 2,
    VectorNativeStatusPrefix = 0x91,
};

typedef enum {
    VectorWireDialectNative,
    VectorWireDialectNativeApdu,
    VectorWireDialectIsoApdu,
} VectorWireDialect;

typedef struct {
    const char* path;
    int line_no;
    int steps_run;
    bool failed;
} VectorState;

static void fail(VectorState* st, const char* fmt, ...) {
    va_list ap;
    fprintf(stderr, "  %s:%d: ", st->path, st->line_no);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    st->failed = true;
}

typedef enum {
    VectorLineEof,
    VectorLineOk,
    VectorLineTooLong,
} VectorLineResult;

/* Consume a whole physical line so no caller can execute a truncated prefix. */
static VectorLineResult read_vector_line(FILE* file, char* line, size_t capacity) {
    if(!fgets(line, (int)capacity, file)) return VectorLineEof;
    if(strpbrk(line, "\r\n") || strlen(line) < capacity - 1) return VectorLineOk;

    int next = fgetc(file);
    if(next == EOF) return VectorLineOk;
    if(next == '\n') return VectorLineOk;
    if(next == '\r') {
        next = fgetc(file);
        if(next != '\n' && next != EOF) ungetc(next, file);
        return VectorLineOk;
    }
    while(next != '\n' && next != EOF)
        next = fgetc(file);
    return VectorLineTooLong;
}

static bool parse_unsigned(const char* text, int base, uint64_t maximum, uint64_t* value) {
    if(!text || !*text || *text == '+' || *text == '-' || *text == ' ' || *text == '\t')
        return false;
    errno = 0;
    char* end = NULL;
    unsigned long long parsed = strtoull(text, &end, base);
    if(errno == ERANGE || end == text || *end != '\0' || parsed > maximum) return false;
    *value = (uint64_t)parsed;
    return true;
}

// Hex with optional "??" wildcard bytes. Returns byte count, or -1.
// mask[i] is false where the byte is a wildcard.
static int parse_hex(const char* s, uint8_t* out, bool* mask, size_t cap) {
    size_t n = 0;
    while(*s) {
        while(*s == ' ' || *s == '\t')
            s++;
        if(!*s) break;
        if(!s[1]) return -1;
        if(n >= cap) return -1;
        if(s[0] == '?' && s[1] == '?') {
            if(!mask) return -1;
            out[n] = 0;
            mask[n] = false;
            n++;
        } else {
            unsigned high;
            unsigned low;
            if(s[0] >= '0' && s[0] <= '9')
                high = (unsigned)(s[0] - '0');
            else if(s[0] >= 'a' && s[0] <= 'f')
                high = (unsigned)(s[0] - 'a' + 10);
            else if(s[0] >= 'A' && s[0] <= 'F')
                high = (unsigned)(s[0] - 'A' + 10);
            else
                return -1;
            if(s[1] >= '0' && s[1] <= '9')
                low = (unsigned)(s[1] - '0');
            else if(s[1] >= 'a' && s[1] <= 'f')
                low = (unsigned)(s[1] - 'a' + 10);
            else if(s[1] >= 'A' && s[1] <= 'F')
                low = (unsigned)(s[1] - 'A' + 10);
            else
                return -1;
            out[n] = (uint8_t)((high << 4) | low);
            if(mask) mask[n] = true;
            n++;
        }
        s += 2;
    }
    return (int)n;
}

static void hexdump(FILE* f, const uint8_t* b, size_t n) {
    for(size_t i = 0; i < n; i++)
        fprintf(f, "%02X", b[i]);
}

// ------------------------------------------------------------ replay plan ---

// A replay plan is the vector with every header already applied: the initial
// credential in the library's own binary encoding, then explicit steps. It is
// recorded while the vector runs here, so a plan exists only for a vector the C
// engine passed, and its final credential is what the C engine ended with.
typedef struct {
    char* data;
    size_t length;
    size_t capacity;
    bool failed;
} PlanBuffer;

static const char* g_plan_directory;
static PlanBuffer g_plan;
static const char* g_plan_skip;
static int g_plan_written;
static int g_plan_skipped;

static void plan_printf(const char* fmt, ...) {
    if(!g_plan_directory || g_plan.failed) return;
    va_list ap;
    va_start(ap, fmt);
    va_list copy;
    va_copy(copy, ap);
    int needed = vsnprintf(NULL, 0, fmt, copy);
    va_end(copy);
    if(needed < 0) {
        g_plan.failed = true;
        va_end(ap);
        return;
    }
    size_t required = g_plan.length + (size_t)needed + 1;
    if(required > g_plan.capacity) {
        size_t capacity = g_plan.capacity ? g_plan.capacity : 4096;
        while(capacity < required)
            capacity *= 2;
        char* grown = realloc(g_plan.data, capacity);
        if(!grown) {
            g_plan.failed = true;
            va_end(ap);
            return;
        }
        g_plan.data = grown;
        g_plan.capacity = capacity;
    }
    vsnprintf(g_plan.data + g_plan.length, g_plan.capacity - g_plan.length, fmt, ap);
    g_plan.length += (size_t)needed;
    va_end(ap);
}

// Uppercase hex, `??` for a wildcard, and `-` for no bytes.
static void plan_hex(const uint8_t* bytes, const bool* mask, size_t length) {
    if(length == 0) plan_printf("-");
    for(size_t i = 0; i < length; i++) {
        if(mask && !mask[i])
            plan_printf("??");
        else
            plan_printf("%02X", bytes[i]);
    }
}

static void plan_reset(void) {
    free(g_plan.data);
    memset(&g_plan, 0, sizeof(g_plan));
    g_plan_skip = NULL;
}

// "<root>/v6/synthetic/name.vec" becomes "v6-synthetic-name.plan".
static bool plan_file_name(const char* vector_path, char* out, size_t capacity) {
    const char* start = vector_path + strlen(vector_path);
    for(int slashes = 0; start > vector_path; start--) {
        if(start[-1] == '/' && ++slashes == 3) break;
    }
    size_t length = strlen(start);
    if(length > 4 && strcmp(start + length - 4, ".vec") == 0) length -= 4;
    if(length + sizeof(".plan") > capacity) return false;
    for(size_t i = 0; i < length; i++)
        out[i] = start[i] == '/' ? '-' : start[i];
    memcpy(out + length, ".plan", sizeof(".plan"));
    return true;
}

static bool plan_write(const char* vector_path) {
    char name[512];
    char path[1024];
    if(!plan_file_name(vector_path, name, sizeof(name))) return false;
    if(snprintf(path, sizeof(path), "%s/%s", g_plan_directory, name) >= (int)sizeof(path))
        return false;
    FILE* out = fopen(path, "wb");
    if(!out) return false;
    bool ok = !g_plan.failed && fwrite(g_plan.data, 1, g_plan.length, out) == g_plan.length;
    return fclose(out) == 0 && ok;
}

// A tolerance clause: the little-endian integer at `offset` may differ from the
// expected one by at most `delta` (docs/conformance-vector-format.md).
typedef struct {
    size_t offset;
    size_t length;
    uint64_t delta;
} VectorTolerance;

#define VectorMaximumTolerances 4

static uint64_t read_le(const uint8_t* bytes, size_t length) {
    uint64_t value = 0;
    for(size_t i = 0; i < length; i++)
        value |= (uint64_t)bytes[i] << (8 * i);
    return value;
}

// Parse the clauses that follow the expected hex, cutting them off `text`.
// Returns the clause count, or -1 for a malformed clause.
static int parse_tolerances(char* text, VectorTolerance* out, size_t cap) {
    char* clause = strstr(text, "tolerance");
    if(!clause) return 0;
    if(clause == text || (clause[-1] != ' ' && clause[-1] != '\t') ||
       (clause[strlen("tolerance")] != ' ' && clause[strlen("tolerance")] != '\t'))
        return -1;
    *clause = 0;
    int n = 0;
    char* cursor = clause + strlen("tolerance");
    while(cursor && *cursor) {
        while(*cursor == ' ' || *cursor == '\t')
            cursor++;
        if(*cursor == '+' || *cursor == '-') return -1;
        errno = 0;
        char* end = NULL;
        unsigned long long offset = strtoull(cursor, &end, 10);
        if(errno == ERANGE || end == cursor || *end != '+') return -1;
        cursor = end + 1;
        if(*cursor == '+' || *cursor == '-') return -1;
        errno = 0;
        unsigned long long length = strtoull(cursor, &end, 10);
        if(errno == ERANGE || end == cursor || (*end != ' ' && *end != '\t')) return -1;
        cursor = end;
        while(*cursor == ' ' || *cursor == '\t')
            cursor++;
        if(*cursor == '+' || *cursor == '-') return -1;
        errno = 0;
        unsigned long long delta = strtoull(cursor, &end, 10);
        if(errno == ERANGE || end == cursor || offset > SIZE_MAX || length > SIZE_MAX) return -1;
        if(length < 1 || length > 4 || (size_t)n >= cap) return -1;
        out[n].offset = (size_t)offset;
        out[n].length = (size_t)length;
        out[n].delta = (uint64_t)delta;
        n++;
        if(*end != '\0' && *end != ' ' && *end != '\t') return -1;
        cursor = end;
        bool separated = false;
        while(*cursor == ' ' || *cursor == '\t') {
            separated = true;
            cursor++;
        }
        if(!*cursor) break;
        if(!separated) return -1;
        if(strncmp(cursor, "tolerance", strlen("tolerance")) != 0) return -1;
        cursor += strlen("tolerance");
    }
    return n;
}

static bool tolerated(const VectorTolerance* tolerances, int count, size_t index) {
    for(int t = 0; t < count; t++) {
        if(index >= tolerances[t].offset && index - tolerances[t].offset < tolerances[t].length)
            return true;
    }
    return false;
}

static bool compare(
    VectorState* st,
    const uint8_t* got,
    size_t got_len,
    const uint8_t* want,
    const bool* mask,
    size_t want_len,
    const VectorTolerance* tolerances,
    int tolerance_count) {
    bool ok = got_len == want_len;
    for(int t = 0; t < tolerance_count; t++) {
        if(tolerances[t].offset > want_len ||
           tolerances[t].length > want_len - tolerances[t].offset) {
            fail(st, "tolerance clause extends past the response");
            return false;
        }
    }
    if(ok) {
        for(size_t i = 0; i < want_len; i++) {
            if(tolerated(tolerances, tolerance_count, i)) continue;
            if(mask[i] && got[i] != want[i]) {
                ok = false;
                break;
            }
        }
    }
    for(int t = 0; ok && t < tolerance_count; t++) {
        uint64_t expected = read_le(want + tolerances[t].offset, tolerances[t].length);
        uint64_t actual = read_le(got + tolerances[t].offset, tolerances[t].length);
        uint64_t difference = expected > actual ? expected - actual : actual - expected;
        if(difference > tolerances[t].delta) {
            fprintf(
                stderr,
                "  %s:%d: tolerated field at %zu differs by %llu, more than %llu\n",
                st->path,
                st->line_no,
                tolerances[t].offset,
                (unsigned long long)difference,
                (unsigned long long)tolerances[t].delta);
            ok = false;
        }
    }
    if(!ok) {
        fprintf(stderr, "  %s:%d: response mismatch\n", st->path, st->line_no);
        fprintf(stderr, "    expected ");
        for(size_t i = 0; i < want_len; i++) {
            if(mask[i])
                fprintf(stderr, "%02X", want[i]);
            else
                fprintf(stderr, "??");
        }
        fprintf(stderr, "\n    actual   ");
        hexdump(stderr, got, got_len);
        fprintf(stderr, "\n");
        st->failed = true;
    }
    return ok;
}

// ---------------------------------------------------------------- header ----

static bool header_name_in(const char* key, const char* const* names, size_t count) {
    for(size_t i = 0; i < count; i++) {
        if(strcmp(key, names[i]) == 0) return true;
    }
    return false;
}

static bool header_value_valid(const char* key, const char* value) {
    static const char* const hex_headers[] = {
        "uid",
        "picc-hardware-version",
        "picc-software-version",
        "picc-key-settings-1",
        "picc-key-settings-2",
        "picc-key-version",
        "picc-key",
        "picc-auth-commands",
        "picc-ats",
        "picc-sak",
        "picc-atqa",
        "picc-ev2-card-capabilities",
        "picc-proximity-key",
        "picc-proximity-option",
        "picc-proximity-published-response-time",
        "picc-proximity-bitrate",
        "picc-static-signature",
        "picc-dam-auth-key",
        "picc-dam-mac-key",
        "picc-dam-encryption-key",
        "vc-iid",
        "vc-info",
        "vc-capabilities",
        "vc-uid",
        "vc-select-mac-key",
        "vc-select-enc-key",
        "delegated-default-key",
        "new-key",
    };
    static const char* const unsigned_headers[] = {
        "picc-storage",
        "picc-key-len",
        "picc-random-id",
        "picc-format-disabled",
        "vc-auth-mandatory",
        "vc-pc-mandatory",
        "delegated-default-key-version",
        "feature-version",
        "new-key-version",
        "target-key-number",
        "target-key-set",
        "target-key-set-version",
    };
    if(header_name_in(key, hex_headers, sizeof(hex_headers) / sizeof(hex_headers[0]))) {
        uint8_t bytes[VectorMaximumByteCount];
        return parse_hex(value, bytes, NULL, sizeof(bytes)) >= 0;
    }
    if(header_name_in(
           key, unsigned_headers, sizeof(unsigned_headers) / sizeof(unsigned_headers[0]))) {
        uint64_t parsed = 0;
        return parse_unsigned(value, 10, UINT32_MAX, &parsed);
    }
    return true;
}

static void apply_header(DfcCredential* c, const char* key, const char* value) {
    uint8_t buf[VectorMaximumByteCount];
    int n;
    if(strcmp(key, "uid") == 0) {
        n = parse_hex(value, buf, NULL, sizeof(buf));
        if(n > 0) {
            c->uid_len = (size_t)n;
            memcpy(c->uid, buf, (size_t)n);
        }
    } else if(strcmp(key, "picc-generation") == 0) {
        if(strcmp(value, "EV1") == 0) c->card.generation = DfcGenerationEv1;
        if(strcmp(value, "EV2") == 0) c->card.generation = DfcGenerationEv2;
        if(strcmp(value, "EV3") == 0) c->card.generation = DfcGenerationEv3;
    } else if(strcmp(key, "picc-storage") == 0) {
        c->card.storage = (uint32_t)strtoul(value, NULL, 10);
    } else if(strcmp(key, "picc-hardware-version") == 0) {
        n = parse_hex(value, buf, NULL, sizeof(buf));
        if(n == (int)sizeof(c->card.hardware_version)) {
            memcpy(c->card.hardware_version, buf, sizeof(c->card.hardware_version));
            c->card.has_hardware_version = true;
        }
    } else if(strcmp(key, "picc-software-version") == 0) {
        n = parse_hex(value, buf, NULL, sizeof(buf));
        if(n == (int)sizeof(c->card.software_version)) {
            memcpy(c->card.software_version, buf, sizeof(c->card.software_version));
            c->card.has_software_version = true;
        }
    } else if(strcmp(key, "picc-key-settings-1") == 0) {
        c->picc_key_settings_1 = (uint8_t)strtol(value, NULL, 16);
    } else if(strcmp(key, "picc-key-settings-2") == 0) {
        c->picc_key_settings_2 = (uint8_t)strtol(value, NULL, 16);
    } else if(strcmp(key, "picc-key-version") == 0) {
        c->picc_key_versions[0] = (uint8_t)strtol(value, NULL, 16);
    } else if(strcmp(key, "picc-key-len") == 0) {
        // Resize rather than assign: the pool slice is sized from the key length.
        size_t len = (size_t)strtol(value, NULL, 10);
        dfc_credential_keys_resize(c, NULL, c->picc_num_keys ? c->picc_num_keys : 1, len);
    } else if(strcmp(key, "picc-key") == 0) {
        n = parse_hex(value, buf, NULL, sizeof(buf));
        uint8_t* dst = dfc_credential_key(c, NULL, 0);
        size_t room = dfc_credential_stored_key_length(c->picc_key_len);
        if(n > 0 && dst && (size_t)n <= room) memcpy(dst, buf, (size_t)n);
    } else if(strcmp(key, "picc-auth-mode") == 0) {
        uint8_t cmd = 0;
        if(dfc_authentication_mode_from_string(value, &cmd)) c->picc_auth_command = cmd;
    } else if(strcmp(key, "picc-auth-commands") == 0) {
        c->picc_auth_commands = (uint8_t)strtoul(value, NULL, 16);
        c->picc_has_auth_commands = true;
    } else if(strcmp(key, "picc-random-id") == 0) {
        c->picc_random_id = strtol(value, NULL, 10) != 0;
    } else if(strcmp(key, "picc-format-disabled") == 0) {
        c->picc_format_disabled = strtol(value, NULL, 10) != 0;
    } else if(strcmp(key, "picc-ats") == 0) {
        n = parse_hex(value, buf, NULL, sizeof(buf));
        if(n > 0 && (size_t)n <= sizeof(c->picc_ats)) {
            memcpy(c->picc_ats, buf, (size_t)n);
            c->picc_ats_len = (size_t)n;
        }
    } else if(strcmp(key, "picc-sak") == 0) {
        if(parse_hex(value, buf, NULL, sizeof(buf)) == 1) {
            c->picc_sak = buf[0];
            c->picc_has_sak = true;
        }
    } else if(strcmp(key, "picc-atqa") == 0) {
        if(parse_hex(value, buf, NULL, sizeof(buf)) == 2) {
            memcpy(c->picc_atqa, buf, 2);
            c->picc_has_atqa = true;
        }
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    } else if(strcmp(key, "picc-ev2-card-capabilities") == 0) {
        if(parse_hex(value, buf, NULL, sizeof(buf)) == DFC_EV2_CAPABILITY_LENGTH) {
            memcpy(c->picc_ev2_capabilities, buf, DFC_EV2_CAPABILITY_LENGTH);
            c->picc_has_ev2_capabilities = true;
        }
#endif
#if DFC_ENABLE_PROXIMITY_CHECK
    } else if(strcmp(key, "picc-proximity-key") == 0) {
        n = parse_hex(value, buf, NULL, sizeof(buf));
        if(n == DFC_AES_KEY_LENGTH) {
            memcpy(c->picc_proximity_key, buf, DFC_AES_KEY_LENGTH);
            c->picc_has_proximity_key = true;
        }
    } else if(strcmp(key, "picc-proximity-option") == 0) {
        if(parse_hex(value, buf, NULL, sizeof(buf)) == 1) c->picc_proximity_option = buf[0];
    } else if(strcmp(key, "picc-proximity-published-response-time") == 0) {
        if(parse_hex(value, buf, NULL, sizeof(buf)) == DFC_PROXIMITY_PUBLISHED_TIME_LENGTH) {
            c->picc_proximity_published_response_time =
                (uint16_t)(((uint16_t)buf[0] << 8) | buf[1]);
        }
    } else if(strcmp(key, "picc-proximity-bitrate") == 0) {
        if(parse_hex(value, buf, NULL, sizeof(buf)) == 1) {
            c->picc_proximity_bitrate = buf[0];
            c->picc_has_proximity_bitrate = true;
        }
#endif
#if DFC_ENABLE_STATIC_SIGNATURE
    } else if(strcmp(key, "picc-static-signature") == 0) {
        n = parse_hex(value, buf, NULL, sizeof(buf));
        if(n == DFC_STATIC_SIGNATURE_LENGTH) {
            memcpy(c->picc_static_signature, buf, DFC_STATIC_SIGNATURE_LENGTH);
            c->picc_has_static_signature = true;
        }
#endif
#if DFC_ENABLE_DELEGATED_APPLICATIONS
    } else if(strcmp(key, "picc-dam-auth-key") == 0) {
        n = parse_hex(value, buf, NULL, sizeof(buf));
        if(n == DFC_AES_KEY_LENGTH) {
            memcpy(c->picc_dam_auth_key, buf, DFC_AES_KEY_LENGTH);
            c->picc_has_dam_keys = true;
        }
    } else if(strcmp(key, "picc-dam-mac-key") == 0) {
        n = parse_hex(value, buf, NULL, sizeof(buf));
        if(n == DFC_AES_KEY_LENGTH) {
            memcpy(c->picc_dam_mac_key, buf, DFC_AES_KEY_LENGTH);
            c->picc_has_dam_keys = true;
        }
    } else if(strcmp(key, "picc-dam-encryption-key") == 0) {
        n = parse_hex(value, buf, NULL, sizeof(buf));
        if(n == DFC_AES_KEY_LENGTH) {
            memcpy(c->picc_dam_encryption_key, buf, DFC_AES_KEY_LENGTH);
            c->picc_has_dam_keys = true;
        }
#endif
#if DFC_ENABLE_VIRTUAL_CARD
    } else if(strcmp(key, "vc-iid") == 0) {
        n = parse_hex(value, buf, NULL, sizeof(buf));
        if(n > 0 && (size_t)n <= sizeof(c->virtual_card_installation_id)) {
            memcpy(c->virtual_card_installation_id, buf, (size_t)n);
            c->virtual_card_installation_id_len = (size_t)n;
            c->virtual_card_configured = true;
        }
    } else if(strcmp(key, "vc-info") == 0) {
        if(parse_hex(value, buf, NULL, sizeof(buf)) == 1) c->virtual_card_information = buf[0];
    } else if(strcmp(key, "vc-capabilities") == 0) {
        if(parse_hex(value, buf, NULL, sizeof(buf)) == DFC_VIRTUAL_CARD_CAPABILITY_LENGTH)
            memcpy(c->virtual_card_capabilities, buf, DFC_VIRTUAL_CARD_CAPABILITY_LENGTH);
    } else if(strcmp(key, "vc-uid") == 0) {
        n = parse_hex(value, buf, NULL, sizeof(buf));
        if(n > 0 && (size_t)n <= sizeof(c->virtual_card_uid)) {
            memcpy(c->virtual_card_uid, buf, (size_t)n);
            c->virtual_card_uid_len = (size_t)n;
        }
    } else if(strcmp(key, "vc-select-mac-key") == 0) {
        if(parse_hex(value, buf, NULL, sizeof(buf)) == DFC_AES_KEY_LENGTH)
            memcpy(c->virtual_card_select_mac_key, buf, DFC_AES_KEY_LENGTH);
    } else if(strcmp(key, "vc-select-enc-key") == 0) {
        if(parse_hex(value, buf, NULL, sizeof(buf)) == DFC_AES_KEY_LENGTH)
            memcpy(c->virtual_card_select_encryption_key, buf, DFC_AES_KEY_LENGTH);
    } else if(strcmp(key, "vc-auth-mandatory") == 0) {
        c->virtual_card_authentication_mandatory = strtoul(value, NULL, 10) != 0;
    } else if(strcmp(key, "vc-pc-mandatory") == 0) {
        c->virtual_card_proximity_mandatory = strtoul(value, NULL, 10) != 0;
#endif
    }
    // name:, description: and any unknown key are informational.
}

// ---------------------------------------------------------------- requires --

// Whether this build implements one feature the corpus can name.
//
// A vector states the features it exercises. A reduced build skips a vector it
// could not satisfy, rather than reporting a failure for a feature it was
// never meant to carry. A full build implements everything and skips nothing.
static bool feature_supported(const char* name, size_t len) {
    static const struct {
        const char* name;
        bool built;
    } table[] = {
        {"ev1", true},
        {"ev2", DFC_ENABLE_GENERATION_EV2},
        {"ev3", DFC_ENABLE_GENERATION_EV3},
        {"auth-d40", DFC_ENABLE_AUTH_D40},
        {"auth-iso", DFC_ENABLE_AUTH_ISO},
        {"auth-aes", DFC_ENABLE_AUTH_AES},
        {"ev2-secure-messaging", DFC_ENABLE_EV2_SECURE_MESSAGING},
        {"iso7816-auth", DFC_ENABLE_ISO7816_AUTH},
        {"special-key-status", DFC_ENABLE_SPECIAL_KEY_STATUS},
        {"key-sets", DFC_ENABLE_KEY_SETS},
        {"delegated-applications", DFC_ENABLE_DELEGATED_APPLICATIONS},
        {"transaction-mac", DFC_ENABLE_TRANSACTION_MAC},
        {"transaction-timer", DFC_ENABLE_TRANSACTION_TIMER},
        {"virtual-card", DFC_ENABLE_VIRTUAL_CARD},
        {"sdm", DFC_ENABLE_SDM},
        {"proximity-check", DFC_ENABLE_PROXIMITY_CHECK},
        {"static-signature", DFC_ENABLE_STATIC_SIGNATURE},
        {"backup-files", DFC_ENABLE_BACKUP_FILES},
        {"record-files", DFC_ENABLE_RECORD_FILES},
    };
    for(size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        if(strlen(table[i].name) == len && strncmp(table[i].name, name, len) == 0) {
            return table[i].built;
        }
    }
    // An unknown feature name is not a reason to skip: a vector naming one
    // must run, so the corpus and the runner cannot drift apart silently.
    return true;
}

// True when this build implements every feature the comma separated list names.
static bool requires_satisfied(const char* list) {
    const char* cursor = list;
    while(*cursor) {
        while(*cursor == ' ' || *cursor == ',')
            cursor++;
        const char* start = cursor;
        while(*cursor && *cursor != ',' && *cursor != ' ')
            cursor++;
        if(cursor > start && !feature_supported(start, (size_t)(cursor - start))) return false;
    }
    return true;
}

// ----------------------------------------------------------------- asserts --

// Match "prefix[N].field" and yield N plus the field name.
static bool
    split_indexed(const char* path, const char* prefix, size_t* index, const char** field) {
    size_t plen = strlen(prefix);
    if(strncmp(path, prefix, plen) != 0 || path[plen] != '[') return false;
    const char* digits = path + plen + 1;
    if(!*digits || *digits == '+' || *digits == '-') return false;
    errno = 0;
    char* end = NULL;
    unsigned long long n = strtoull(digits, &end, 10);
    if(errno == ERANGE || end == digits || *end != ']' || end[1] != '.' || n > SIZE_MAX)
        return false;
    *index = (size_t)n;
    *field = end + 2;
    return true;
}

static bool split_index_leaf(const char* text, const char* prefix, size_t* index) {
    size_t prefix_length = strlen(prefix);
    if(strncmp(text, prefix, prefix_length) != 0 || text[prefix_length] != '[') return false;
    const char* digits = text + prefix_length + 1;
    if(!*digits || *digits == '+' || *digits == '-') return false;
    errno = 0;
    char* end = NULL;
    unsigned long long parsed = strtoull(digits, &end, 10);
    if(errno == ERANGE || end == digits || strcmp(end, "]") != 0 || parsed > SIZE_MAX)
        return false;
    *index = (size_t)parsed;
    return true;
}

static bool cmp_bytes(
    VectorState* st,
    const char* path,
    const uint8_t* actual,
    size_t actual_len,
    const char* want) {
    uint8_t exp[VectorMaximumByteCount];
    int exp_len = parse_hex(want, exp, NULL, sizeof(exp));
    if(exp_len < 0) {
        fail(st, "assert %s: expected value is not hex", path);
        return false;
    }
    if((size_t)exp_len != actual_len || memcmp(actual, exp, actual_len) != 0) {
        fprintf(stderr, "  %s:%d: assert %s\n", st->path, st->line_no, path);
        fprintf(stderr, "    expected ");
        hexdump(stderr, exp, (size_t)exp_len);
        fprintf(stderr, "\n    actual   ");
        hexdump(stderr, actual, actual_len);
        fprintf(stderr, "\n");
        st->failed = true;
        return false;
    }
    return true;
}

static bool cmp_num(VectorState* st, const char* path, unsigned long actual, const char* want) {
    uint64_t parsed = 0;
    if(!parse_unsigned(want, 0, ULONG_MAX, &parsed)) {
        fail(st, "assert %s: expected value is not an unsigned integer", path);
        return false;
    }
    unsigned long expect = (unsigned long)parsed;
    if(actual != expect) {
        fail(st, "assert %s: expected %lu, got %lu", path, expect, actual);
        return false;
    }
    return true;
}

static bool
    set_model_path(VectorState* st, DfcCredential* c, const char* path, const char* value_text) {
    uint64_t parsed = 0;
    if(!parse_unsigned(value_text, 0, UINT32_MAX, &parsed)) {
        fail(st, "set-model %s: invalid value", path);
        return false;
    }
    unsigned long value = (unsigned long)parsed;
    size_t i;
#if DFC_ENABLE_KEY_SETS
    size_t k;
#endif
    const char* field;
    if(split_indexed(path, "apps", &i, &field) && i < c->num_apps) {
        DfcApplication* app = &c->apps[i];
        if(strcmp(field, "key_len") == 0)
            app->key_len = (size_t)value;
        else if(strcmp(field, "key_settings_2") == 0)
            app->key_settings_2 = (uint8_t)value;
        else if(strcmp(field, "has_auth_commands") == 0)
            app->has_auth_commands = value != 0;
        else if(strcmp(field, "has_preferred_auth_command") == 0)
            app->has_preferred_auth_command = value != 0;
#if DFC_ENABLE_KEY_SETS
        else if(strcmp(field, "key_storage_len") == 0)
            app->key_storage_len = (size_t)value;
        else if(strcmp(field, "max_key_size") == 0)
            app->max_key_size = (uint8_t)value;
        else if(split_index_leaf(field, "key_set_types", &k) && k < app->num_key_sets) {
            uint8_t* type = dfc_credential_key_set_type(c, app, k);
            if(!type) return false;
            *type = (uint8_t)value;
        } else if(split_index_leaf(field, "key_set_versions", &k) && k < app->num_key_sets) {
            uint8_t* version = dfc_credential_key_set_version(c, app, k);
            if(!version) return false;
            *version = (uint8_t)value;
        } else if(split_index_leaf(field, "key_set_initialized", &k) && k < app->num_key_sets) {
            if(!dfc_credential_key_set_set_initialized(c, app, k, value != 0)) return false;
        }
#endif
        else {
            fail(st, "unsupported set-model path '%s'", path);
            return false;
        }
        return true;
    }
    if(split_indexed(path, "files", &i, &field) && i < c->num_files) {
#if DFC_ENABLE_SDM
        DfcFile* file = &c->files[i];
        if(strcmp(field, "sdm_enabled") == 0)
            dfc_file_sdm_flag_set(file, DfcSdmFlagEnabled, value != 0);
        else if(strcmp(field, "sdm_has_encrypted_file_offset") == 0)
            dfc_file_sdm_flag_set(file, DfcSdmFlagEncryptedFile, value != 0);
        else if(strcmp(field, "sdm_encrypted_file_offset") == 0)
            file->state.data.sdm.encrypted_file_offset = (uint32_t)value;
        else if(strcmp(field, "sdm_encrypted_file_length") == 0)
            file->state.data.sdm.encrypted_file_length = (uint32_t)value;
        else {
#else
        {
#endif
            fail(st, "unsupported set-model path '%s'", path);
            return false;
        }
        return true;
    }
    fail(st, "unsupported set-model path '%s'", path);
    return false;
}

static bool assert_path(
    VectorState* st,
    DfcCredential* c,
    DfcVirtualPiccSession* session,
    const DfcVirtualPiccActivation* activation,
    bool have_activation,
    const char* path,
    const char* want) {
    size_t i, k;
    const char* field;

    // What anticollision actually presented for the most recent scan, which is
    // where the PICC configuration takes effect rather than in stored state.
    if(strncmp(path, "activation.", 11) == 0) {
        if(!have_activation) {
            fail(st, "assert %s: no activation, the vector has not scanned", path);
            return false;
        }
        const char* f = path + 11;
        if(strcmp(f, "uid") == 0)
            return cmp_bytes(st, path, activation->uid, activation->uid_len, want);
        if(strcmp(f, "uid_len") == 0)
            return cmp_num(st, path, (unsigned long)activation->uid_len, want);
        if(strcmp(f, "sak") == 0) return cmp_num(st, path, activation->sak, want);
        if(strcmp(f, "atqa") == 0)
            return cmp_bytes(st, path, activation->atqa, activation->atqa_len, want);
        if(strcmp(f, "ats") == 0)
            return cmp_bytes(st, path, activation->ats, activation->ats_len, want);
        fail(st, "unsupported assert path '%s'", path);
        return false;
    }

    if(strcmp(path, "credential.dirty") == 0) return cmp_num(st, path, c->dirty ? 1u : 0u, want);
    if(strcmp(path, "credential.num_apps") == 0)
        return cmp_num(st, path, (unsigned long)c->num_apps, want);
    if(strcmp(path, "credential.num_files") == 0)
        return cmp_num(st, path, (unsigned long)c->num_files, want);
    if(strcmp(path, "credential.uid") == 0) return cmp_bytes(st, path, c->uid, c->uid_len, want);
    if(strcmp(path, "credential.model_status") == 0) {
        DfcModelStatus status = dfc_credential_validate_model(c);
        const char* actual = status == DfcModelOk ? "ok" : "malformed";
        if(strcmp(actual, want) != 0) {
            fail(st, "assert %s: expected %s, got %s", path, want, actual);
            return false;
        }
        return true;
    }

    if(strcmp(path, "emulator.selected_application") == 0) {
        if(!session || !session->emulator) {
            fail(st, "assert %s: no session", path);
            return false;
        }
        return cmp_num(st, path, (unsigned long)session->emulator->selected_application, want);
    }
#if DFC_ENABLE_VIRTUAL_CARD
    if(strcmp(path, "emulator.virtual_card_selected") == 0) {
        if(!session || !session->emulator) {
            fail(st, "assert %s: no session", path);
            return false;
        }
        return cmp_num(st, path, session->emulator->virtual_card_selected ? 1u : 0u, want);
    }
#endif
    if(strcmp(path, "emulator.secure_messaging") == 0) {
        // Wiped storage can remain allocated after authentication ends.
        if(!session || !session->emulator) {
            fail(st, "assert %s: no session", path);
            return false;
        }
        if(strcmp(want, "null") != 0 && strcmp(want, "present") != 0) {
            fail(st, "assert %s: expected null or present", path);
            return false;
        }
        bool active = session->emulator->secure_messaging != NULL &&
                      session->emulator->secure_messaging->cipher != 0;
#if DFC_ENABLE_EV2_SECURE_MESSAGING
        active = active || session->emulator->ev2_session_active;
#endif
        bool is_null = !active;
        bool want_null = strcmp(want, "null") == 0;
        if(is_null != want_null) {
            fail(st, "assert %s: expected %s", path, want_null ? "null" : "present");
            return false;
        }
        return true;
    }
#if DFC_ENABLE_EV2_SECURE_MESSAGING
    if(strncmp(path, "session.", 8) == 0 &&
       (!session || !session->emulator || !session->emulator->ev2_session_active)) {
        fail(st, "assert %s: no EV2 session", path);
        return false;
    }
    if(strcmp(path, "session.transaction_identifier") == 0) {
        return cmp_bytes(
            st,
            path,
            session->emulator->ev2_transaction_identifier,
            DFC_EV2_TRANSACTION_IDENTIFIER_LENGTH,
            want);
    }
    if(strcmp(path, "session.command_counter") == 0) {
        uint8_t counter[DFC_EV2_COUNTER_LENGTH] = {
            (uint8_t)session->emulator->ev2_command_counter,
            (uint8_t)(session->emulator->ev2_command_counter >> 8),
        };
        return cmp_bytes(st, path, counter, sizeof(counter), want);
    }
    if(strcmp(path, "session.encryption_key") == 0)
        return cmp_bytes(
            st, path, session->emulator->ev2_session_encryption_key, DFC_AES_KEY_LENGTH, want);
    if(strcmp(path, "session.mac_key") == 0)
        return cmp_bytes(
            st, path, session->emulator->ev2_session_mac_key, DFC_AES_KEY_LENGTH, want);
#endif

    if(split_indexed(path, "apps", &i, &field)) {
        if(i >= c->num_apps) {
            fail(st, "assert %s: only %zu applications", path, c->num_apps);
            return false;
        }
        DfcApplication* a = &c->apps[i];
        // Most significant byte first, the one AID order the format uses.
        // CreateApplication carries the reverse of this on the wire.
        if(strcmp(field, "aid") == 0) return cmp_bytes(st, path, a->aid, 3, want);
        if(strcmp(field, "key_settings_1") == 0) return cmp_num(st, path, a->key_settings_1, want);
        if(strcmp(field, "key_settings_2") == 0) return cmp_num(st, path, a->key_settings_2, want);
        if(strcmp(field, "auth_command") == 0) return cmp_num(st, path, a->auth_command, want);
        if(strcmp(field, "num_keys") == 0)
            return cmp_num(st, path, (unsigned long)a->num_keys, want);
        if(strcmp(field, "key_len") == 0)
            return cmp_num(st, path, (unsigned long)a->key_len, want);
        if(strcmp(field, "has_iso_file_id") == 0)
            return cmp_num(st, path, a->has_iso_file_id ? 1u : 0u, want);
        if(strcmp(field, "iso_file_id") == 0) return cmp_num(st, path, a->iso_file_id, want);
        if(strcmp(field, "iso_aid_len") == 0)
            return cmp_num(st, path, (unsigned long)a->iso_aid_len, want);
        if(split_index_leaf(field, "keys", &k)) {
            if(k >= a->num_keys) {
                fail(st, "assert %s: only %zu keys", path, a->num_keys);
                return false;
            }
            const uint8_t* key = dfc_credential_key_const(c, a, k);
            if(!key) {
                fail(st, "assert %s: no key material", path);
                return false;
            }
            return cmp_bytes(st, path, key, a->key_len, want);
        }
        if(split_index_leaf(field, "key_versions", &k)) {
            if(k >= a->num_keys) {
                fail(st, "assert %s: only %zu keys", path, a->num_keys);
                return false;
            }
            return cmp_num(st, path, a->key_versions[k], want);
        }
#if DFC_ENABLE_KEY_SETS
        if(split_index_leaf(field, "key_set_types", &k) && k < a->num_key_sets) {
            const uint8_t* type = dfc_credential_key_set_type_const(c, a, k);
            if(!type) return false;
            return cmp_num(st, path, *type, want);
        }
#endif
    }

    if(split_indexed(path, "files", &i, &field)) {
        if(i >= c->num_files) {
            fail(st, "assert %s: only %zu files", path, c->num_files);
            return false;
        }
        DfcFile* fl = &c->files[i];
        if(strcmp(field, "app_index") == 0)
            return cmp_num(st, path, (unsigned long)fl->app_index, want);
        if(strcmp(field, "number") == 0) return cmp_num(st, path, fl->number, want);
        if(strcmp(field, "type") == 0) return cmp_num(st, path, fl->type, want);
        if(strcmp(field, "comm_settings") == 0) return cmp_num(st, path, fl->comm_settings, want);
        if(strcmp(field, "access_rights") == 0) return cmp_num(st, path, fl->access_rights, want);
        if(strcmp(field, "has_iso_file_id") == 0)
            return cmp_num(st, path, fl->has_iso_file_id ? 1u : 0u, want);
        if(strcmp(field, "iso_file_id") == 0) return cmp_num(st, path, fl->iso_file_id, want);
        if(strcmp(field, "data_len") == 0)
            return cmp_num(st, path, (unsigned long)fl->data_len, want);
        if(strcmp(field, "record_count") == 0) {
            if(fl->type != DFC_FILE_TYPE_LINEAR_RECORD &&
               fl->type != DFC_FILE_TYPE_CYCLIC_RECORD) {
                fail(st, "assert %s: file is not a record file", path);
                return false;
            }
            return cmp_num(st, path, (unsigned long)fl->state.record.count, want);
        }
        if(strcmp(field, "data") == 0) {
            const uint8_t* d = dfc_file_data_const(c, fl);
            if(!d && fl->data_len > 0) {
                fail(st, "assert %s: file data unreadable", path);
                return false;
            }
            return cmp_bytes(st, path, d ? d : (const uint8_t*)"", fl->data_len, want);
        }
    }

    fail(st, "unsupported assert path '%s'", path);
    return false;
}

// -------------------------------------------------------------------- run ---

// Reads feature requirements and replayability before running a vector.
// Returns 1 to run, 0 to skip, and -1 for malformed input.
static int vector_is_runnable(const char* path) {
    FILE* f = fopen(path, "r");
    if(!f) return true;
    char line[VectorMaximumLineLength];
    bool runnable = true;
    VectorLineResult line_result;
    while((line_result = read_vector_line(f, line, sizeof(line))) == VectorLineOk) {
        char* cursor = line;
        while(*cursor == ' ' || *cursor == '\t')
            cursor++;
        if(*cursor == '#' || *cursor == '\n' || *cursor == '\r') continue;
        if(strncmp(cursor, "replayable:", 11) == 0) {
            if(strstr(cursor + 11, "false") != NULL) runnable = false;
            continue;
        }
        if(strncmp(cursor, "requires:", 9) != 0) {
            // Headers precede the steps; the first step ends the header block.
            if(strchr(cursor, ':') == NULL) break;
            continue;
        }
        char* value = cursor + 9;
        while(*value == ' ')
            value++;
        char* end = value + strlen(value);
        while(end > value && (end[-1] == '\n' || end[-1] == '\r' || end[-1] == ' '))
            end--;
        *end = '\0';
        runnable = runnable && requires_satisfied(value);
    }
    fclose(f);
    if(line_result == VectorLineTooLong) {
        fprintf(stderr, "  %s: line exceeds %d bytes\n", path, VectorMaximumLineLength - 1);
        return -1;
    }
    return runnable ? 1 : 0;
}

static void use_empty_random_script(void) {
    static const uint8_t empty_script;
    dfc_host_clear_random_buffer();
    dfc_host_set_random_buffer(&empty_script, 0);
}

static bool vector_uses_scripted_random(FILE* f, bool* scripted) {
    char line[VectorMaximumLineLength];
    *scripted = false;
    VectorLineResult line_result;
    while((line_result = read_vector_line(f, line, sizeof(line))) == VectorLineOk) {
        char* cursor = line;
        while(*cursor == ' ' || *cursor == '\t')
            cursor++;
        char* end = strpbrk(cursor, "\r\n");
        if(end) *end = '\0';
        if(strcmp(cursor, "random-source finite") == 0 ||
           (strncmp(cursor, "inject-random", strlen("inject-random")) == 0 &&
            (cursor[strlen("inject-random")] == ' ' || cursor[strlen("inject-random")] == '\t'))) {
            *scripted = true;
            break;
        }
    }
    rewind(f);
    return line_result != VectorLineTooLong;
}

static void plan_credential_hex(const DfcCredential* credential) {
    size_t length = 0;
    uint8_t* encoded = NULL;
    if(dfc_der_encoded_size(credential, &length) == DfcDerOk && length > 0 &&
       (encoded = malloc(length)) != NULL &&
       dfc_der_encode(credential, encoded, length, &length) == DfcDerOk) {
        plan_hex(encoded, NULL, length);
    } else {
        g_plan.failed = true;
    }
    free(encoded);
}

static void plan_begin(const char* path, bool finite_random, const DfcCredential* credential) {
    char name[512];
    if(!plan_file_name(path, name, sizeof(name))) {
        g_plan.failed = true;
        return;
    }
    name[strlen(name) - strlen(".plan")] = '\0';
    plan_printf(
        "plan 1\nsource %s\nrandom %s\ncredential ", name, finite_random ? "finite" : "os");
    plan_credential_hex(credential);
    plan_printf("\n");
}

// Vectors whose expected answers depend on a capacity the C runner is built with.
// The shipped libraries the bindings load use the host profile's larger tables, so
// the plan records a counted skip instead of an expectation they cannot meet.
static const struct {
    const char* basename;
    const char* reason;
} g_capacity_bound_vectors[] = {
    {"vecb-ev1-create-file-full-pool.vec",
     "answer depends on the runner's DFC_MAX_FILES file table; shipped libraries use "
     "DFC_HOST_MAX_FILES"},
};

static void plan_note_capacity_bound(const char* path) {
    const char* base = strrchr(path, '/');
    base = base ? base + 1 : path;
    for(size_t i = 0; i < sizeof(g_capacity_bound_vectors) / sizeof(g_capacity_bound_vectors[0]);
        i++) {
        if(strcmp(base, g_capacity_bound_vectors[i].basename) == 0 && !g_plan_skip)
            g_plan_skip = g_capacity_bound_vectors[i].reason;
    }
}

// Returns false when a plan was due but could not be written.
static bool
    plan_finish(const char* path, bool started, bool failed, const DfcCredential* credential) {
    if(!g_plan_directory || failed || !started) return true;
    plan_note_capacity_bound(path);
    if(g_plan_skip) {
        char name[512];
        const char* reason = g_plan_skip;
        plan_reset();
        if(!plan_file_name(path, name, sizeof(name))) return false;
        name[strlen(name) - strlen(".plan")] = '\0';
        plan_printf("plan 1\nsource %s\nskip %s\n", name, reason);
        g_plan_skipped++;
    } else {
        plan_printf("final ");
        plan_credential_hex(credential);
        plan_printf("\n");
    }
    if(!plan_write(path)) {
        fprintf(stderr, "  %s: cannot write the replay plan\n", path);
        return false;
    }
    g_plan_written++;
    return true;
}

static bool run_vector(const char* path) {
    plan_reset();
    bool plan_started = false;
    dfc_host_clear_random_buffer();
    FILE* f = fopen(path, "r");
    if(!f) {
        fprintf(stderr, "  cannot open %s\n", path);
        return false;
    }

    bool finite_random_source = false;
    if(!vector_uses_scripted_random(f, &finite_random_source)) {
        fprintf(stderr, "  %s: line exceeds %d bytes\n", path, VectorMaximumLineLength - 1);
        fclose(f);
        return false;
    }
    if(finite_random_source) use_empty_random_script();

    VectorState st = {.path = path, .line_no = 0, .steps_run = 0, .failed = false};
    DfcCredential credential;
    dfc_credential_clear(&credential);
    DfcVirtualPiccSession* session = NULL;
    DfcVirtualPiccActivation activation;
    bool have_activation = false;
    memset(&activation, 0, sizeof(activation));
    bool in_header = true;
    char line[VectorMaximumLineLength];

    VectorLineResult line_result;
    while((line_result = read_vector_line(f, line, sizeof(line))) == VectorLineOk) {
        st.line_no++;
        char* p = line;
        while(*p == ' ' || *p == '\t')
            p++;
        char* nl = strpbrk(p, "\r\n");
        if(nl) *nl = 0;
        if(*p == 0 || *p == '#') continue;

        // Header lines are "key: value" and must precede the first step.
        char* colon = strchr(p, ':');
        char* space = strpbrk(p, " \t");
        if(in_header && colon && (!space || colon < space)) {
            *colon = 0;
            char* v = colon + 1;
            while(*v == ' ' || *v == '\t')
                v++;
            if(!header_value_valid(p, v)) {
                fail(&st, "invalid header value for '%s'", p);
                break;
            }
            apply_header(&credential, p, v);
            continue;
        }
        in_header = false;
        if(!plan_started) {
            plan_started = true;
            plan_begin(path, finite_random_source, &credential);
        }

        char* verb = strtok(p, " \t");
        if(!verb) continue;
        st.steps_run++;

        if(strcmp(verb, "scan") == 0) {
            if(strtok(NULL, " \t")) {
                fail(&st, "scan takes no arguments");
                break;
            }
            if(!session) session = dfc_virtual_picc_session_alloc(&credential);
            if(dfc_virtual_picc_scan_iso14443a(session, &activation) != DfcVirtualPiccStatusOk) {
                fail(&st, "scan refused: credential not detectable");
                break;
            }
            have_activation = true;
            plan_printf("step scan\n");
            continue;
        }
        if(strcmp(verb, "field-off") == 0) {
            if(strtok(NULL, " \t")) {
                fail(&st, "field-off takes no arguments");
                break;
            }
            if(session) dfc_virtual_picc_field_off(session);
            have_activation = false;
            plan_printf("step field-off\n");
            continue;
        }
        if(strcmp(verb, "clear-dirty") == 0) {
            if(strtok(NULL, " \t")) {
                fail(&st, "clear-dirty takes no arguments");
                break;
            }
            dfc_credential_clear_dirty(&credential);
            plan_printf("step clear-dirty\n");
            continue;
        }
        if(strcmp(verb, "random-source") == 0) {
            char* mode = strtok(NULL, " \t");
            char* extra = strtok(NULL, " \t");
            if(!mode || strcmp(mode, "finite") != 0 || extra) {
                fail(&st, "random-source must be 'finite'");
                break;
            }
            use_empty_random_script();
            finite_random_source = true;
            plan_printf("step random-clear\n");
            continue;
        }
        if(strcmp(verb, "set-model") == 0) {
            char* model_path = strtok(NULL, " \t");
            char* eq = strtok(NULL, " \t");
            char* value = strtok(NULL, " \t");
            char* extra = strtok(NULL, " \t");
            if(!model_path || !eq || strcmp(eq, "=") != 0 || !value || extra) {
                fail(&st, "set-model syntax: set-model <path> = <value>");
                break;
            }
            if(!set_model_path(&st, &credential, model_path, value)) break;
            g_plan_skip = "set-model edits the credential model in place and no binding can";
            continue;
        }
        if(strcmp(verb, "roll-model-key-set") == 0) {
#if DFC_ENABLE_KEY_SETS
            char* app_text = strtok(NULL, " \t");
            char* set_text = strtok(NULL, " \t");
            char* extra = strtok(NULL, " \t");
            uint64_t app_index = 0;
            uint64_t key_set = 0;
            if(!parse_unsigned(app_text, 0, SIZE_MAX, &app_index) ||
               !parse_unsigned(set_text, 0, SIZE_MAX, &key_set) || extra ||
               app_index >= credential.num_apps ||
               !dfc_credential_roll_key_set(
                   &credential, &credential.apps[(size_t)app_index], (size_t)key_set)) {
                fail(&st, "roll-model-key-set needs valid application and key-set indexes");
                break;
            }
            g_plan_skip =
                "roll-model-key-set edits the credential model in place and no binding can";
#else
            fail(&st, "roll-model-key-set requires key-set support");
            break;
#endif
            continue;
        }
        if(strcmp(verb, "inject-random") == 0) {
            char* hex = strtok(NULL, "");
            while(hex && (*hex == ' ' || *hex == '\t'))
                hex++;
            uint8_t buf[VectorMaximumInjectedRandomByteCount];
            int n = hex ? parse_hex(hex, buf, NULL, sizeof(buf)) : -1;
            if(n <= 0) {
                fail(&st, "inject-random needs hex bytes");
                break;
            }
            size_t remaining_before = dfc_host_random_remaining();
            dfc_host_set_random_buffer(buf, (size_t)n);
            if(dfc_host_random_remaining() != remaining_before + (size_t)n) {
                fail(&st, "inject-random exceeds the host replay queue");
                break;
            }
            plan_printf("step random-inject ");
            plan_hex(buf, NULL, (size_t)n);
            plan_printf("\n");
            continue;
        }
        if(strcmp(verb, "advance-time") == 0) {
            char* milliseconds_text = strtok(NULL, " \t");
            char* extra = strtok(NULL, " \t");
            uint64_t milliseconds = 0;
            if(!parse_unsigned(milliseconds_text, 10, UINT32_MAX, &milliseconds) || extra) {
                fail(&st, "advance-time needs milliseconds");
                break;
            }
            if(!session) session = dfc_virtual_picc_session_alloc(&credential);
            dfc_emulator_advance_time(session->emulator, (uint32_t)milliseconds);
            plan_printf("step advance-time %llu\n", (unsigned long long)milliseconds);
            continue;
        }
        if(strcmp(verb, "assert") == 0) {
            char* apath = strtok(NULL, " \t");
            char* eq = strtok(NULL, " \t");
            char* val = strtok(NULL, " \t");
            char* extra = strtok(NULL, " \t");
            if(!apath || !eq || strcmp(eq, "=") != 0 || !val || extra) {
                fail(&st, "assert syntax: assert <path> = <value>");
                break;
            }
            assert_path(&st, &credential, session, &activation, have_activation, apath, val);
            plan_printf("step assert %s %s\n", apath, val);
            continue;
        }

        if(strcmp(verb, "expect-error") == 0) {
            char* error_class = strtok(NULL, " \t");
            char* operation = strtok(NULL, " \t");
            bool random_error = error_class && strcmp(error_class, "random-source") == 0;
            bool protocol_error = error_class && strcmp(error_class, "protocol-error") == 0;
            if(!operation || (!random_error && !protocol_error) ||
               (random_error && !finite_random_source)) {
                fail(&st, "unsupported expect-error class or missing finite random source");
                break;
            }

            if(!session) session = dfc_virtual_picc_session_alloc(&credential);
            size_t remaining_before = dfc_host_random_remaining();
            DfcVirtualPiccStatus rc = DfcVirtualPiccStatusOk;
            replay_random_clear_failure();
            size_t got_len = 0;
            uint8_t got[VectorMaximumByteCount];

            if(strcmp(operation, "scan") == 0) {
                if(protocol_error) {
                    fail(&st, "protocol-error only supports frame-exchange");
                    break;
                }
                if(strtok(NULL, " \t")) {
                    fail(&st, "expected-error scan takes no arguments");
                    break;
                }
                plan_printf("step error random-source scan\n");
                rc = dfc_virtual_picc_scan_iso14443a(session, &activation);
                if(rc != DfcVirtualPiccStatusOk) have_activation = false;
            } else {
                if(!have_activation) {
                    fail(&st, "expected-error exchange requires an explicit scan first");
                    break;
                }
                bool frame = strcmp(operation, "frame-exchange") == 0;
                bool exchange = strcmp(operation, "exchange") == 0;
                if(protocol_error && !frame) {
                    fail(&st, "protocol-error only supports frame-exchange");
                    break;
                }
                VectorWireDialect dialect = VectorWireDialectNativeApdu;
                char* command_hex = strtok(NULL, " \t");
                if(exchange && command_hex) {
                    if(strcmp(command_hex, "native") == 0) {
                        dialect = VectorWireDialectNative;
                    } else if(strcmp(command_hex, "native-apdu") == 0) {
                        dialect = VectorWireDialectNativeApdu;
                    } else if(strcmp(command_hex, "iso-apdu") == 0) {
                        dialect = VectorWireDialectIsoApdu;
                    } else {
                        fail(&st, "expected-error exchange requires a wire dialect");
                        break;
                    }
                    command_hex = strtok(NULL, " \t");
                }
                char* extra = strtok(NULL, " \t");
                uint8_t command[VectorMaximumByteCount];
                int command_len =
                    command_hex ? parse_hex(command_hex, command, NULL, sizeof(command)) : -1;
                if((!exchange && !frame) || command_len <= 0 || extra) {
                    fail(&st, "malformed expected-error operation");
                    break;
                }
                (void)dialect;
                plan_printf("step error %s %s ", error_class, frame ? "frame" : "exchange");
                plan_hex(command, NULL, (size_t)command_len);
                plan_printf("\n");
                rc = frame ?
                         dfc_virtual_picc_iso_dep_frame_exchange(
                             session, command, (size_t)command_len, got, sizeof(got), &got_len) :
                         dfc_virtual_picc_iso_dep_exchange(
                             session, command, (size_t)command_len, got, sizeof(got), &got_len);
            }
            size_t remaining_after = dfc_host_random_remaining();
            if(protocol_error) {
                if(rc != DfcVirtualPiccStatusProtocolError || got_len != 0) {
                    fail(
                        &st, "protocol error mismatch (status=%d response=%zu)", (int)rc, got_len);
                    break;
                }
            } else if(
                !replay_random_failed() || rc != DfcVirtualPiccStatusProtocolError ||
                got_len != 0 || remaining_after != remaining_before) {
                fail(
                    &st,
                    "random-source failure was not atomic "
                    "(status=%d response=%zu random=%zu->%zu)",
                    (int)rc,
                    got_len,
                    remaining_before,
                    remaining_after);
                break;
            }
            continue;
        }

        bool is_status = strcmp(verb, "status") == 0;
        bool is_exchange = strcmp(verb, "exchange") == 0;
        bool is_frame = strcmp(verb, "frame-exchange") == 0;
        bool is_select_application = strcmp(verb, "select-application") == 0;
        if(!is_status && !is_exchange && !is_frame && !is_select_application) {
            fail(&st, "unknown step '%s'", verb);
            break;
        }

        VectorWireDialect dialect = VectorWireDialectNativeApdu;
        char* dialect_or_command = strtok(NULL, " \t");
        char* cmd_hex = dialect_or_command;
        if(is_exchange && dialect_or_command) {
            if(strcmp(dialect_or_command, "native") == 0) {
                dialect = VectorWireDialectNative;
                cmd_hex = strtok(NULL, " \t");
            } else if(strcmp(dialect_or_command, "native-apdu") == 0) {
                dialect = VectorWireDialectNativeApdu;
                cmd_hex = strtok(NULL, " \t");
            } else if(strcmp(dialect_or_command, "iso-apdu") == 0) {
                dialect = VectorWireDialectIsoApdu;
                cmd_hex = strtok(NULL, " \t");
            }
        }
        char* arrow = strtok(NULL, " \t");
        char* exp_hex = strtok(NULL, "");
        if(!cmd_hex || !arrow || strcmp(arrow, "=>") != 0 || !exp_hex) {
            fail(&st, "syntax: %s <apdu> => <expected>", verb);
            break;
        }
        while(*exp_hex == ' ' || *exp_hex == '\t')
            exp_hex++;
        VectorTolerance tolerances[VectorMaximumTolerances];
        int tolerance_count = parse_tolerances(exp_hex, tolerances, VectorMaximumTolerances);
        if(tolerance_count < 0 || (is_status && tolerance_count > 0)) {
            fail(&st, "malformed tolerance clause");
            break;
        }

        uint8_t cmd[VectorMaximumByteCount];
        int cmd_len;
        if(is_select_application) {
            uint8_t aid[DFC_COMMAND_AID_LENGTH];
            if(parse_hex(cmd_hex, aid, NULL, sizeof(aid)) != DFC_COMMAND_AID_LENGTH) {
                fail(&st, "select-application needs one three-byte model AID");
                break;
            }
            DfcCommand command;
            size_t encoded_length = 0;
            if(dfc_command_select_application(&command, aid, NULL) != DfcCommandOk ||
               dfc_command_to_apdu(&command, cmd, sizeof(cmd), &encoded_length) != DfcCommandOk) {
                fail(&st, "select-application command encoding failed");
                break;
            }
            cmd_len = (int)encoded_length;
        } else {
            cmd_len = parse_hex(cmd_hex, cmd, NULL, sizeof(cmd));
            if(cmd_len <= 0) {
                fail(&st, "bad command hex");
                break;
            }
        }

        uint8_t want[VectorMaximumByteCount];
        bool mask[VectorMaximumByteCount];
        int want_len;
        if(is_status) {
            uint8_t sw[1];
            if(parse_hex(exp_hex, sw, NULL, 1) != 1) {
                fail(&st, "status expects a single status byte");
                break;
            }
            want[0] = VectorNativeStatusPrefix;
            want[1] = sw[0];
            mask[0] = mask[1] = true;
            want_len = VectorStatusWordLength;
        } else {
            want_len = parse_hex(exp_hex, want, mask, sizeof(want));
            if(want_len < 0) {
                fail(&st, "bad expected hex");
                break;
            }
            bool bad_tolerance = false;
            for(int t = 0; t < tolerance_count; t++) {
                if(tolerances[t].offset > (size_t)want_len ||
                   tolerances[t].length > (size_t)want_len - tolerances[t].offset)
                    bad_tolerance = true;
                for(size_t i = tolerances[t].offset;
                    !bad_tolerance && i - tolerances[t].offset < tolerances[t].length;
                    i++) {
                    if(!mask[i]) bad_tolerance = true;
                    for(int u = t + 1; u < tolerance_count; u++) {
                        if(i >= tolerances[u].offset &&
                           i - tolerances[u].offset < tolerances[u].length)
                            bad_tolerance = true;
                    }
                }
            }
            if(bad_tolerance) {
                fail(&st, "tolerance clause overlaps a wildcard, another clause, or the end");
                break;
            }
        }

        if(!session) session = dfc_virtual_picc_session_alloc(&credential);
        if(!have_activation) {
            if(dfc_virtual_picc_scan_iso14443a(session, &activation) != DfcVirtualPiccStatusOk) {
                fail(&st, "exchange activation refused");
                break;
            }
            have_activation = true;
            plan_printf("step scan\n");
        }
        plan_printf("step %s ", is_frame ? "frame" : "exchange");
        plan_hex(cmd, NULL, (size_t)cmd_len);
        plan_printf(" ");
        plan_hex(want, mask, (size_t)want_len);
        for(int t = 0; t < tolerance_count; t++) {
            plan_printf(
                " tol=%zu+%zu:%llu",
                tolerances[t].offset,
                tolerances[t].length,
                (unsigned long long)tolerances[t].delta);
        }
        plan_printf("\n");
        uint8_t got[VectorMaximumByteCount];
        size_t got_len = 0;
        DfcVirtualPiccStatus rc =
            is_frame ? dfc_virtual_picc_iso_dep_frame_exchange(
                           session, cmd, (size_t)cmd_len, got, sizeof(got), &got_len) :
                       dfc_virtual_picc_iso_dep_exchange(
                           session, cmd, (size_t)cmd_len, got, sizeof(got), &got_len);
        (void)dialect;
        if(rc != DfcVirtualPiccStatusOk) {
            fail(&st, "transport error %d", (int)rc);
            break;
        }
        if(!compare(&st, got, got_len, want, mask, (size_t)want_len, tolerances, tolerance_count))
            break;
    }

    if(line_result == VectorLineTooLong)
        fail(&st, "line exceeds %d bytes", VectorMaximumLineLength - 1);

    if(!plan_finish(path, plan_started, st.failed, &credential)) st.failed = true;
    plan_reset();
    if(session) dfc_virtual_picc_session_free(session);
    dfc_host_clear_random_buffer();
    fclose(f);

    printf("  %-52s %s (%d steps)\n", path, st.failed ? "FAIL" : "ok", st.steps_run);
    return !st.failed;
}

static bool compile_vector(const char* path, const char* output_path) {
    FILE* input = fopen(path, "r");
    if(!input) return false;
    DfcCredential credential;
    dfc_credential_clear(&credential);
    char line[VectorMaximumLineLength];
    VectorLineResult line_result;
    while((line_result = read_vector_line(input, line, sizeof(line))) == VectorLineOk) {
        char* p = line;
        while(*p == ' ' || *p == '\t')
            p++;
        char* nl = strpbrk(p, "\r\n");
        if(nl) *nl = 0;
        if(*p == 0 || *p == '#') continue;
        char* colon = strchr(p, ':');
        char* space = strpbrk(p, " \t");
        if(!colon || (space && space < colon)) break;
        *colon = 0;
        char* value = colon + 1;
        while(*value == ' ' || *value == '\t')
            value++;
        if(!header_value_valid(p, value)) {
            fclose(input);
            return false;
        }
        apply_header(&credential, p, value);
    }
    fclose(input);
    if(line_result == VectorLineTooLong) return false;

    size_t encoded_length = 0;
    if(dfc_der_encoded_size(&credential, &encoded_length) != DfcDerOk) {
        return false;
    }
    uint8_t* encoded = malloc(encoded_length);
    if(!encoded ||
       dfc_der_encode(&credential, encoded, encoded_length, &encoded_length) != DfcDerOk) {
        free(encoded);
        return false;
    }
    FILE* output = fopen(output_path, "wb");
    if(!output) {
        free(encoded);
        return false;
    }
    bool ok = fwrite(encoded, 1, encoded_length, output) == encoded_length;
    free(encoded);
    return fclose(output) == 0 && ok;
}

int main(int argc, char** argv) {
    if(argc == 4 && strcmp(argv[1], "--compile-dfcb") == 0) {
        return compile_vector(argv[2], argv[3]) ? 0 : 1;
    }
    int first_vector = 1;
    if(argc >= 3 && strcmp(argv[1], "--export-plans") == 0) {
        g_plan_directory = argv[2];
        first_vector = 3;
    }
    if(argc <= first_vector) {
        fprintf(stderr, "usage: %s [--export-plans <directory>] <vector-file> [...]\n", argv[0]);
        return 2;
    }
    int failed = 0;
    int skipped = 0;
    printf("conformance vectors:\n");
    for(int i = first_vector; i < argc; i++) {
        int runnable = vector_is_runnable(argv[i]);
        if(runnable < 0) {
            failed++;
            continue;
        }
        if(runnable == 0) {
            skipped++;
            continue;
        }
        if(!run_vector(argv[i])) failed++;
    }
    if(g_plan_directory)
        printf("%d replay plans written (%d are skip-only)\n", g_plan_written, g_plan_skipped);
    int total = argc - first_vector;
    int ran = total - skipped;
    if(skipped > 0) {
        printf(
            "%d of %d vectors passed, %d skipped (nonreplayable or unavailable in this build)\n",
            ran - failed,
            ran,
            skipped);
    } else {
        printf("%d of %d vectors passed\n", ran - failed, ran);
    }
    return failed == 0 ? 0 : 1;
}
