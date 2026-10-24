/* Keep the production host queue, but observe the actual failed draw so an
 * unrelated protocol error cannot satisfy an expected random-source failure. */
#define dfc_random_fill dfc_host_random_fill
#include "dfc_port_host.c"
#undef dfc_random_fill

#include "dfc_vector_replay_random.h"

static bool random_failed;

void replay_random_clear_failure(void) {
    random_failed = false;
}

bool replay_random_failed(void) {
    return random_failed;
}

bool dfc_random_fill(uint8_t* buffer, size_t length) {
    bool success = dfc_host_random_fill(buffer, length);
    if(!success) random_failed = true;
    return success;
}
