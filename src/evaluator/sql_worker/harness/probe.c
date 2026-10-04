/* ISOLATED DIAGNOSTIC ONLY: current glibc native request counters, NOT an
 * allocator/backing/live-peak/kernel verifier. No source payload is observed.
 * Uses documented-current-glibc __libc_* symbols; loader/internal hidden calls
 * and direct syscalls can bypass ELF symbol interposition. Counts are therefore
 * observations, never an upper bound or evidence of zero native TLS. */
#define _GNU_SOURCE
#include <stdatomic.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void *__libc_memalign(size_t, size_t);
extern void __libc_free(void *);
static _Atomic int enabled;
static _Atomic uint64_t calls[7];
static _Atomic uint64_t requested;
static _Atomic uint64_t request_slots;
static _Atomic uint64_t request_bytes[16];
struct counts { uint64_t calls[7]; uint64_t requested_bytes; uint64_t requests[16]; };
static void record(unsigned kind, size_t bytes) {
    if (atomic_load_explicit(&enabled, memory_order_relaxed)) {
        atomic_fetch_add_explicit(&calls[kind], 1, memory_order_relaxed);
        if (kind != 6) {
            atomic_fetch_add_explicit(&requested, bytes, memory_order_relaxed);
            uint64_t slot = atomic_fetch_add_explicit(&request_slots, 1, memory_order_relaxed);
            if (slot < 16) atomic_store_explicit(&request_bytes[slot], bytes, memory_order_relaxed);
        }
    }
}
void flower_worker_probe_begin(void) {
    atomic_store(&enabled, 0);
    for (unsigned i = 0; i < 7; ++i) atomic_store(&calls[i], 0);
    atomic_store(&requested, 0);
    atomic_store(&request_slots, 0);
    for (unsigned i = 0; i < 16; ++i) atomic_store(&request_bytes[i], 0);
    atomic_store(&enabled, 1);
}
void flower_worker_probe_read(struct counts *result) {
    for (unsigned i = 0; i < 7; ++i) result->calls[i] = atomic_load(&calls[i]);
    result->requested_bytes = atomic_load(&requested);
    for (unsigned i = 0; i < 16; ++i) result->requests[i] = atomic_load(&request_bytes[i]);
}
void flower_worker_probe_end(void) { atomic_store(&enabled, 0); }
void *malloc(size_t bytes) { record(0, bytes); return __libc_malloc(bytes); }
void *calloc(size_t n, size_t bytes) {
    size_t total;
    if (__builtin_mul_overflow(n, bytes, &total)) total = SIZE_MAX;
    record(1, total); return __libc_calloc(n, bytes);
}
void *realloc(void *old, size_t bytes) { record(2, bytes); return __libc_realloc(old, bytes); }
void free(void *old) { record(6, 0); __libc_free(old); }
void *memalign(size_t align, size_t bytes) { record(3, bytes); return __libc_memalign(align, bytes); }
void *aligned_alloc(size_t align, size_t bytes) { record(4, bytes); return __libc_memalign(align, bytes); }
int posix_memalign(void **result, size_t align, size_t bytes) {
    record(5, bytes);
    if (align < sizeof(void *) || (align & (align - 1))) return EINVAL;
    void *ptr = __libc_memalign(align, bytes);
    if (!ptr) return ENOMEM;
    *result = ptr; return 0;
}

/* Fault injection applies ONLY to isolated lab children. It simulates explicit
 * native error returns, never a real physical/kernel capacity certificate. */
static _Atomic unsigned fault_mode;
static _Atomic(void *) create_fn;
static _Atomic(void *) join_fn;
static _Atomic(void *) getattr_fn;
static void *resolve(_Atomic(void *) *slot, const char *name) {
    void *value = atomic_load(slot);
    if (!value) { value = dlsym(RTLD_NEXT, name); atomic_store(slot, value); }
    return value;
}
void flower_worker_probe_fault(unsigned mode) {
    (void)resolve(&create_fn, "pthread_create");
    (void)resolve(&join_fn, "pthread_join");
    (void)resolve(&getattr_fn, "pthread_getattr_np");
    atomic_store(&fault_mode, mode);
}
int pthread_create(pthread_t *restrict thread, const pthread_attr_t *restrict attr,
                   void *(*entry)(void *), void *restrict argument) {
    if (atomic_load(&fault_mode) == 1) return EAGAIN;
    int (*real)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *) = resolve(&create_fn, "pthread_create");
    return real(thread, attr, entry, argument);
}
int pthread_join(pthread_t thread, void **result) {
    if (atomic_load(&fault_mode) == 3) return EINVAL;
    int (*real)(pthread_t, void **) = resolve(&join_fn, "pthread_join");
    return real(thread, result);
}
int pthread_getattr_np(pthread_t thread, pthread_attr_t *attr) {
    int (*real)(pthread_t, pthread_attr_t *) = resolve(&getattr_fn, "pthread_getattr_np");
    int rc = real(thread, attr);
    if (rc == 0 && atomic_load(&fault_mode) == 2) {
        void *address = NULL; size_t bytes = 0;
        rc = pthread_attr_getstack(attr, &address, &bytes);
        if (rc == 0) rc = pthread_attr_setstack(attr, (char *)address + 4096, bytes - 4096);
    }
    return rc;
}
int munmap(void *address, size_t bytes) {
    unsigned mode = atomic_load(&fault_mode);
    if (mode == 4 || mode == 6) { errno = EBUSY; return -1; }
    return (int)syscall(SYS_munmap, address, bytes);
}
int mprotect(void *address, size_t bytes, int protection) {
    unsigned mode = atomic_load(&fault_mode);
    if (mode == 5 || mode == 6) { errno = EACCES; return -1; }
    return (int)syscall(SYS_mprotect, address, bytes, protection);
}
