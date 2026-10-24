#ifndef DFC_JNI_QUEUE_H
#define DFC_JNI_QUEUE_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>

static inline bool dfc_jni_replay_queue_length(size_t remaining, size_t appended, size_t* total) {
    if(total == NULL || remaining > (size_t)INT_MAX || appended > (size_t)INT_MAX - remaining)
        return false;
    *total = remaining + appended;
    return true;
}

#endif
