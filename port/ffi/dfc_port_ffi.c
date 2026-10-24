/* Platform implementation for the shared library that foreign runtimes load.
 *
 * Randomness comes from the virtual PICC the current call is serving: each FFI
 * entry point that can reach the engine installs its handle's source for the
 * duration of the call, on the calling thread only, so handles used from
 * different threads never draw from one another's source. With no source
 * installed the operating system's generator answers.
 */
#include "dfc_port.h"
#include "dfc_port_ffi.h"

#include <stdlib.h>
#include <string.h>
#include <limits.h>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#elif defined(__APPLE__)
#include <stdlib.h>
#elif defined(__ANDROID__)
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#else
#include <errno.h>
#include <sys/random.h>
#include <sys/types.h>
#endif

#if defined(_MSC_VER)
#define DFC_THREAD_LOCAL __declspec(thread)
#else
#define DFC_THREAD_LOCAL _Thread_local
#endif

static DFC_THREAD_LOCAL DfcFfiRandomCallback current_random;
static DFC_THREAD_LOCAL void* current_context;
static DFC_THREAD_LOCAL bool random_failed;

void dfc_ffi_port_set_random(DfcFfiRandomCallback random, void* context) {
    current_random = random;
    current_context = context;
    random_failed = false;
}

bool dfc_ffi_port_random_failed(void) {
    return random_failed;
}

void dfc_ffi_port_system_random(uint8_t* buf, size_t len) {
#if defined(_WIN32)
    size_t filled = 0;
    while(filled < len) {
        size_t remaining = len - filled;
        ULONG count = (ULONG)(remaining > ULONG_MAX ? ULONG_MAX : remaining);
        NTSTATUS status =
            BCryptGenRandom(NULL, buf + filled, count, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if(status != 0) abort();
        filled += count;
    }
#elif defined(__APPLE__)
    arc4random_buf(buf, len);
#elif defined(__ANDROID__)
    int fd;
    do {
        fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    } while(fd < 0 && errno == EINTR);
    if(fd < 0) abort();
    size_t filled = 0;
    while(filled < len) {
        ssize_t n = read(fd, buf + filled, len - filled);
        if(n > 0) {
            filled += (size_t)n;
            continue;
        }
        if(n < 0 && errno == EINTR) continue;
        close(fd);
        abort();
    }
    close(fd);
#else
    size_t filled = 0;
    while(filled < len) {
        ssize_t n = getrandom(buf + filled, len - filled, 0);
        if(n == 0) abort();
        if(n < 0) {
            if(errno == EINTR) continue;
            // No source at all is not survivable: a predictable challenge would
            // break every authentication.
            abort();
        }
        filled += (size_t)n;
    }
#endif
}

bool dfc_random_fill(uint8_t* buf, size_t len) {
    if(len == 0) return true;
    if(current_random) {
        if(current_random(current_context, buf, len) != DFC_FFI_OK) {
            memset(buf, 0, len);
            random_failed = true;
            return false;
        }
        return true;
    }
    dfc_ffi_port_system_random(buf, len);
    return true;
}

void* dfc_platform_alloc(size_t size, DfcAllocTag tag) {
    DFC_UNUSED(tag);
    return calloc(1, size);
}

void dfc_platform_free(void* ptr) {
    free(ptr);
}

void dfc_port_notify(void* context, DfcEvent event) {
    DFC_UNUSED(context);
    DFC_UNUSED(event);
}
