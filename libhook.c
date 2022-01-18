#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <stdlib.h>
static unsigned char buffer[100][100];
static void *(*real_malloc)(size_t) = NULL;
static void (*real_free)(void *) = NULL;
static void *(*real_realloc)(void *, size_t) = NULL;
static void *(*real_memalign)(size_t blocksize, size_t bytes) = NULL;
static void *(*real_calloc)(size_t nmemb, size_t size) = NULL;
static void *(*real_valloc)(size_t size) = NULL;
static int (*real_posix_memalign)(void **memptr, size_t alignment,
                                  size_t size);
static void *(*real_reallocarray)(void *, size_t, size_t) = NULL;
static int (*temp_posix_memalign)(void **memptr, size_t alignment,
                                  size_t size);
static void *(*real_mmap)(void *addr, size_t len, int prot, int flags, int fd, off_t offset) = NULL;
static int (*real_munmap)(void *addr, size_t len) = NULL;
static void *(*real_sbrk)(intptr_t increment) = NULL;

__thread unsigned int entered = 0;
int start_call()
{
    return __sync_fetch_and_add(&entered, 1);
}
void end_call()
{
    __sync_fetch_and_sub(&entered, 1);
}
void __attribute__((constructor)) hookfns()
{
    start_call();
    real_posix_memalign = NULL;
    temp_posix_memalign = dlsym(RTLD_NEXT, "posix_memalign");

    if (!temp_posix_memalign)
    {
        fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
        exit(1);
    }
    real_posix_memalign = temp_posix_memalign;
    end_call();
}
static void mtrace_init(void)
{
    real_free = dlsym(RTLD_NEXT, "free");
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    real_calloc = dlsym(RTLD_NEXT, "calloc");
    real_valloc = dlsym(RTLD_NEXT, "valloc");
    real_memalign = dlsym(RTLD_NEXT, "memalign");
    real_reallocarray = dlsym(RTLD_NEXT, "reallocarray");
    real_mmap = dlsym(RTLD_NEXT, "mmap");
    real_munmap = dlsym(RTLD_NEXT, "munmap");
    real_sbrk = dlsym(RTLD_NEXT, "sbrk");
    if (NULL == real_malloc ||
        NULL == real_free ||
        NULL == real_realloc ||
        NULL == real_calloc ||
        NULL == real_reallocarray ||
        NULL == real_valloc ||
        NULL == real_memalign ||
        NULL == real_mmap ||
        NULL == real_munmap ||
        NULL == real_sbrk)
    {
        fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
    }
}
void *malloc(size_t size)
{
    struct timeval time;
    int id = syscall(SYS_gettid);
    if (real_malloc == NULL)
    {
        mtrace_init();
    }
    void *ptr = real_malloc(size);
    gettimeofday(&time, NULL);
    fprintf(stderr, "%ld.%06ld [%d] LIBHOOK_LOG malloc[%zu] = %p\n", time.tv_sec, time.tv_usec, id, size, ptr);
    return ptr;
}
void free(void *ptr)
{
    if (buffer <= ptr && ptr < buffer + sizeof(buffer))
        return;
    struct timeval time;
    int id = syscall(SYS_gettid);
    if (real_free == NULL)
    {
        mtrace_init();
    }
    real_free(ptr);
    gettimeofday(&time, NULL);
    fprintf(stderr, "%ld.%06ld [%d] LIBHOOK_LOG free[%p]\n", time.tv_sec, time.tv_usec, id, ptr);
}
void *realloc(void *ptr, size_t size)
{
    struct timeval time;
    int id = syscall(SYS_gettid);
    if (real_realloc == NULL)
    {
        mtrace_init();
    }
    void *result = real_realloc(ptr, size);
    gettimeofday(&time, NULL);
    fprintf(stderr, "%ld.%06ld [%d] LIBHOOK_LOG realloc[%p, %zu] = %p\n", time.tv_sec, time.tv_usec, id, ptr, size, result);
    return result;
}
void *calloc(size_t nmemb, size_t size)
{   
    struct timeval time;
    int id = syscall(SYS_gettid);
    static int index = 0;
    if (real_calloc == NULL)
    {
        index++;
        // fprintf(stderr, "%ld.%06ld [%d] calloc[%zu, %zu] return buffer %p\n", id, nmemb, size, buffer[index]);
        // fprintf(stderr, "index: %d\n", index);
        return buffer[index];
    }
    void *p = real_calloc(nmemb, size);
    gettimeofday(&time, NULL);
    fprintf(stderr, "%ld.%06ld [%d] LIBHOOK_LOG calloc[%zu, %zu] = %p\n", time.tv_sec, time.tv_usec, id, nmemb, size, p);
    return p;
}
void *valloc(size_t size)
{
    struct timeval time;
    int id = syscall(SYS_gettid);
    if (real_valloc == NULL)
    {
        mtrace_init();
    }
    void *ptr = real_valloc(size);
    gettimeofday(&time, NULL);
    fprintf(stderr, "%ld.%06ld [%d] LIBHOOK_LOG valloc[%zu] = %p\n", time.tv_sec, time.tv_usec, id, size, ptr);
    return ptr;
}
void *memalign(size_t blocksize, size_t bytes)
{
    struct timeval time;
    int id = syscall(SYS_gettid);
    if (real_memalign == NULL)
    {
        mtrace_init();
    }
    void *ptr = real_memalign(blocksize, bytes);
    gettimeofday(&time, NULL);
    fprintf(stderr, "%ld.%06ld [%d] LIBHOOK_LOG memalign[%zu, %zu] = %p\n", time.tv_sec,
            time.tv_usec, id, blocksize, bytes, ptr);
    return ptr;
}
void *reallocarray(void *ptr, size_t nmemb, size_t size)
{
    struct timeval time;
    int id = syscall(SYS_gettid);
    if (real_reallocarray == NULL)
    {
        mtrace_init();
    }
    void *result = real_reallocarray(ptr, nmemb, size);
    gettimeofday(&time, NULL);
    fprintf(stderr, "%ld.%06ld [%d] LIBHOOK_LOG reallocarray[%p, %zu, %zu] = %p\n", time.tv_sec, time.tv_usec, id, ptr, nmemb, size, result);
    return result;
}
int posix_memalign(void **memptr, size_t alignment, size_t size)
{
    struct timeval time;
    int id = syscall(SYS_gettid);
    if (real_posix_memalign == NULL)
    {
        mtrace_init();
    }
    int result = real_posix_memalign(memptr, alignment, size);
    gettimeofday(&time, NULL);
    if (result == 0) {
        fprintf(stderr, "%ld.%06ld [%d] LIBHOOK_LOG posix_memalign[%p, %zu, %zu] = 0, %p\n", time.tv_sec, time.tv_usec, id, memptr, alignment, size, memptr);
    }
    else {
        fprintf(stderr, "%ld.%06ld [%d] LIBHOOK_LOG posix_memalign[%p, %zu, %zu] = %d, NULL\n", time.tv_sec, time.tv_usec, id, memptr, alignment, size, result);
    }
    return result;
}
void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) 
{
    struct timeval time;
    int id = syscall(SYS_gettid);
    if (real_mmap == NULL)
    {
        mtrace_init();
    }
    void *result = real_mmap(addr, len, prot, flags, fd, offset);
    gettimeofday(&time, NULL);
    fprintf(stderr, "%ld.%06ld [%d] LIBHOOK_LOG mmap[%p, %zu, %d, %d, %d, %ld] = %p\n", time.tv_sec, time.tv_usec, id, addr, len, prot, flags, fd, offset, result);
    return result;
}
int munmap(void *addr, size_t len)
{
    struct timeval time;
    int id = syscall(SYS_gettid);
    if (real_munmap == NULL)
    {
        mtrace_init();
    }
    int result = real_munmap(addr, len);
    gettimeofday(&time, NULL);
    fprintf(stderr, "%ld.%06ld [%d] LIBHOOK_LOG munmap[%p, %zu] = %d\n", time.tv_sec, time.tv_usec, id, addr, len, result);
    return result;
}
void *sbrk(intptr_t increment)
{
    struct timeval time;
    int id = syscall(SYS_gettid);
    if (real_sbrk == NULL)
    {
        mtrace_init();
    }
    void *result = real_sbrk(increment);
    gettimeofday(&time, NULL);
    fprintf(stderr, "%ld.%06ld [%d] LIBHOOK_LOG sbrk[%ld] = %p\n", time.tv_sec, time.tv_usec, id, increment, result);
    return result;   
}
