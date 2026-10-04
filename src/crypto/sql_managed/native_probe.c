/* Independent Linux/glibc evidence only, never linked into production.
 * Interpose native allocation APIs without dlsym recursion or heap scratch.
 * Every counter is const C TLS. Rust GlobalAlloc is observed independently.
 */
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void *__libc_memalign(size_t, size_t);
extern void *__libc_valloc(size_t);
extern void *__libc_pvalloc(size_t);
extern void __libc_free(void *);
static _Thread_local size_t allocations;
static _Thread_local int active;
void sql_managed_native_probe_start(void) { allocations = 0; active = 1; }
size_t sql_managed_native_probe_stop(void) { active = 0; return allocations; }
void *malloc(size_t n) { if (active) ++allocations; return __libc_malloc(n); }
void *calloc(size_t n, size_t m) { if (active) ++allocations; return __libc_calloc(n, m); }
void *realloc(void *p, size_t n) { if (active) ++allocations; return __libc_realloc(p, n); }
void *reallocarray(void *p, size_t n, size_t m) {
    if (active) ++allocations;
    if (m && n > SIZE_MAX / m) { errno = ENOMEM; return NULL; }
    return __libc_realloc(p, n * m);
}
void *memalign(size_t a, size_t n) { if (active) ++allocations; return __libc_memalign(a, n); }
void *aligned_alloc(size_t a, size_t n) { if (active) ++allocations; return __libc_memalign(a, n); }
int posix_memalign(void **p, size_t a, size_t n) {
    if (active) ++allocations;
    if (a < sizeof(void *) || (a & (a - 1))) return EINVAL;
    void *v = __libc_memalign(a, n);
    if (!v) return ENOMEM;
    *p = v;
    return 0;
}
void *valloc(size_t n) { if (active) ++allocations; return __libc_valloc(n); }
void *pvalloc(size_t n) { if (active) ++allocations; return __libc_pvalloc(n); }
void free(void *p) { __libc_free(p); }
/* Volatile indirect calls keep an optimizing Rust/LLVM caller from treating
 * these positive-control allocations as movable/elidable malloc builtins. */
int sql_managed_native_probe_positive_control(void) {
    void *(*volatile allocate)(size_t) = malloc;
    void *(*volatile allocate_zero)(size_t, size_t) = calloc;
    void *(*volatile resize)(void *, size_t) = realloc;
    void *(*volatile aligned)(size_t, size_t) = aligned_alloc;
    int (*volatile posix)(void **, size_t, size_t) = posix_memalign;
    void *a = allocate(33);
    void *b = allocate_zero(2, 17);
    void *c = resize(a, 65);
    void *d = aligned(64, 128);
    void *e = NULL;
    int status = posix(&e, 64, 129);
    int success = b && c && d && e && status == 0;
    free(b); free(c); free(d); free(e);
    return success;
}
