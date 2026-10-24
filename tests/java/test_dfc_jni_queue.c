#include <limits.h>
#include <stddef.h>

#include "dfc_jni_queue.h"

#define CHECK(condition)                  \
    do {                                  \
        if(!(condition)) return __LINE__; \
    } while(0)

int main(void) {
    size_t total = 99;
    CHECK(dfc_jni_replay_queue_length(0, 0, &total));
    CHECK(total == 0);

    CHECK(dfc_jni_replay_queue_length((size_t)INT_MAX - 1, 1, &total));
    CHECK(total == (size_t)INT_MAX);

    total = 99;
    CHECK(!dfc_jni_replay_queue_length((size_t)INT_MAX, 1, &total));
    CHECK(total == 99);
    CHECK(!dfc_jni_replay_queue_length((size_t)INT_MAX + 1, 0, &total));
    CHECK(total == 99);
    CHECK(!dfc_jni_replay_queue_length(0, 0, NULL));
}
