#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// AFL-style forkserver fds
#define FORKSRV_FD 198
#define FORKSRV_FD_OUT 199

#define INIT_HOOK(fn) \
    do { if (!real_##fn) real_##fn = (typeof(real_##fn))dlsym(RTLD_NEXT, #fn); } while (0)
#define CHECK_HOOK(fn) do { if (!(real_##fn)) { _exit(127); } } while(0)

static ssize_t (*real_write)(int fd, const void *buf, size_t count) = NULL;
static int (*real_open)(const char *pathname, int flags, ...) = NULL;
static int (*real_openat)(int dirfd, const char *pathname, int flags, ...) = NULL;
static void *(*real_mmap)(void *addr, size_t length, int prot, int flags, int fd, off_t offset) = NULL;
static void *(*real_malloc)(size_t size) = NULL;
static void (*real_free)(void *ptr) = NULL;
static void *(*real_calloc)(size_t nmemb, size_t size) = NULL;
static void *(*real_realloc)(void *ptr, size_t size) = NULL;
static ssize_t (*real_read)(int, void *, size_t) = NULL;
static int (*real_close)(int) = NULL;
static void *(*real_memcpy)(void *, const void *, size_t) = NULL;
static void *(*real_memset)(void *, int, size_t) = NULL;
static char *(*real_strdup)(const char *) = NULL;
static char *(*real_getenv)(const char *) = NULL;
static char *(*real_strcpy)(char *, const char *) = NULL;
static char *(*real_strncpy)(char *, const char *, size_t) = NULL;
static int (*real_sprintf)(char *, const char *, ...) = NULL;
static int (*real_snprintf)(char *, size_t, const char *, ...) = NULL;

// Shared memory for stdin replacement: layout [4 bytes len][payload...]
static uint8_t *shm_base = NULL;
static size_t shm_size = 0;
static size_t shm_off = 0;

// Coverage bitmap shared memory (no recompile): we mark call sites of interposed libc calls
static uint8_t *cov_base = NULL;
static size_t cov_size = 0;

static void init_hooks(void) {
    INIT_HOOK(write);
    INIT_HOOK(open);
    INIT_HOOK(openat);
    INIT_HOOK(mmap);
    INIT_HOOK(malloc);
    INIT_HOOK(free);
    INIT_HOOK(calloc);
    INIT_HOOK(realloc);
    INIT_HOOK(read);
    INIT_HOOK(close);
    INIT_HOOK(memcpy);
    INIT_HOOK(memset);
    INIT_HOOK(strdup);
    INIT_HOOK(getenv);
    INIT_HOOK(strcpy);
    INIT_HOOK(strncpy);
    INIT_HOOK(sprintf);
    INIT_HOOK(snprintf);

    CHECK_HOOK(write);
    CHECK_HOOK(open);
    CHECK_HOOK(openat);
    CHECK_HOOK(mmap);
    CHECK_HOOK(malloc);
    CHECK_HOOK(free);
    CHECK_HOOK(calloc);
    CHECK_HOOK(realloc);
    CHECK_HOOK(read);
    CHECK_HOOK(close);
    CHECK_HOOK(memcpy);
    CHECK_HOOK(memset);
    CHECK_HOOK(strdup);
    CHECK_HOOK(getenv);
    CHECK_HOOK(strcpy);
    CHECK_HOOK(strncpy);
    CHECK_HOOK(sprintf);
    CHECK_HOOK(snprintf);
}

static void init_shm(void) {
    if (shm_base) return;
    const char *name = getenv("FUZZER_SHM_NAME");
    const char *size_env = getenv("FUZZER_SHM_SIZE");
    if (!name) return;
    size_t sz = size_env ? (size_t)strtoull(size_env, NULL, 10) : (1<<20);
    int fd = shm_open(name, O_RDONLY, 0600);
    if (fd < 0) return;
    void *p = mmap(NULL, sz, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (p == MAP_FAILED) return;
    shm_base = (uint8_t*)p;
    shm_size = sz;
}

// Minimal robust write
static void write_u32(int fd, uint32_t val) {
    uint8_t b[4];
    b[0] = (uint8_t)(val & 0xFF);
    b[1] = (uint8_t)((val >> 8) & 0xFF);
    b[2] = (uint8_t)((val >> 16) & 0xFF);
    b[3] = (uint8_t)((val >> 24) & 0xFF);
    ssize_t off = 0;
    while (off < 4) {
        ssize_t r = write(fd, b + off, 4 - off);
        if (r <= 0) return;
        off += r;
    }
}

static int try_forkserver(void) {
    // Verify fds exist
    if (fcntl(FORKSRV_FD, F_GETFL) == -1 || fcntl(FORKSRV_FD_OUT, F_GETFL) == -1) {
        return -1;
    }
    // Handshake: write 4 bytes to signal ready
    write_u32(FORKSRV_FD_OUT, 0);

    while (1) {
        uint32_t ctl;
        ssize_t r = read(FORKSRV_FD, &ctl, 4);
        if (r != 4) _exit(0);

        // Create an in-memory file descriptor with the input data
        // memfd_create creates a file in RAM with no size limits
        int memfd = -1;
        if (shm_base && shm_size >= 4) {
            uint32_t total = (uint32_t)shm_base[0] | ((uint32_t)shm_base[1] << 8) 
                           | ((uint32_t)shm_base[2] << 16) | ((uint32_t)shm_base[3] << 24);
            if (total + 4 > shm_size) {
                total = (uint32_t)(shm_size > 4 ? shm_size - 4 : 0);
            }
            
            // Create anonymous file in memory
            memfd = memfd_create("fuzz_input", 0);
            if (memfd >= 0) {
                // Write all data to it (no pipe buffer limit!)
                ssize_t written = 0;
                while (written < total) {
                    ssize_t w = write(memfd, shm_base + 4 + written, total - written);
                    if (w <= 0) break;
                    written += w;
                }
                // Rewind to beginning for reading
                lseek(memfd, 0, SEEK_SET);
            }
        }

        pid_t pid = fork();
        if (pid < 0) {
            if (memfd >= 0) close(memfd);
            _exit(1);
        }
        
        if (pid == 0) {
            // CHILD: redirect stdin to memfd
            if (memfd >= 0) {
                dup2(memfd, 0);  // stdin = memfd
                close(memfd);
            }
            close(FORKSRV_FD);
            close(FORKSRV_FD_OUT);
            return 0; // return to program with stdin from memfd
        }
        
        // PARENT: close memfd and wait for child
        if (memfd >= 0) close(memfd);
        write_u32(FORKSRV_FD_OUT, (uint32_t)pid);
        int status = 0;
        if (waitpid(pid, &status, 0) < 0) status = 0xFFFF;
        write_u32(FORKSRV_FD_OUT, (uint32_t)status);
    }
}

// Initialize coverage shared memory used by cov_mark_pc()
static void init_cov(void) {
    if (cov_base) return;
    const char *name = getenv("FUZZER_COV_NAME");
    const char *size_env = getenv("FUZZER_COV_SIZE");
    if (!name) return;
    size_t sz = size_env ? (size_t)strtoull(size_env, NULL, 10) : (1<<16);
    int fd = shm_open(name, O_RDWR, 0600);
    if (fd < 0) return;
    void *p = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (p == MAP_FAILED) return;
    cov_base = (uint8_t*)p;
    cov_size = sz;
}

__attribute__((constructor)) static void fuzzer_init(void) {
    init_hooks();
    init_shm();
    init_cov();
    // Start forkserver only if fds are present; otherwise proceed normally
    if (fcntl(FORKSRV_FD, F_GETFL) != -1 && fcntl(FORKSRV_FD_OUT, F_GETFL) != -1) {
        int r = try_forkserver();
        if (r != 0) {
            // Should not reach
        }
    }
}


// coverage marking function
static inline void cov_mark_pc(void *pc) {
    if (!cov_base || cov_size == 0) return;
    size_t idx = ((uintptr_t)pc >> 4) % cov_size;
    cov_base[idx]++;
}

ssize_t write(int fd, const void *buf, size_t count) {
    cov_mark_pc(__builtin_return_address(0));
    return real_write(fd, buf, count);
}

int open(const char *pathname, int flags, ...) {
    cov_mark_pc(__builtin_return_address(0));
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
    }
    return real_open(pathname, flags, mode);
}

int openat(int dirfd, const char *pathname, int flags, ...) {
    cov_mark_pc(__builtin_return_address(0));
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
    }
    return real_openat(dirfd, pathname, flags, mode);
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    cov_mark_pc(__builtin_return_address(0));
    return real_mmap(addr, length, prot, flags, fd, offset);
}

void *malloc(size_t size) {
    cov_mark_pc(__builtin_return_address(0));
    return real_malloc(size);
}

void free(void *ptr) {
    cov_mark_pc(__builtin_return_address(0));
    real_free(ptr);
}

void *calloc(size_t nmemb, size_t size) {
    cov_mark_pc(__builtin_return_address(0));
    return real_calloc(nmemb, size);
}

void *realloc(void *ptr, size_t size) {
    cov_mark_pc(__builtin_return_address(0));
    return real_realloc(ptr, size);
}

ssize_t read(int fd, void *buf, size_t count) {
    cov_mark_pc(__builtin_return_address(0));
    return real_read(fd, buf, count);
}

int close(int fd) {
    cov_mark_pc(__builtin_return_address(0));
    return real_close(fd);
}

void *memcpy(void *dest, const void *src, size_t n) {
    cov_mark_pc(__builtin_return_address(0));
    return real_memcpy(dest, src, n);
}

void *memset(void *s, int c, size_t n) {
    cov_mark_pc(__builtin_return_address(0));
    return real_memset(s, c, n);
}

char *strdup(const char *s) {
    cov_mark_pc(__builtin_return_address(0));
    return real_strdup(s);
}

char *getenv(const char *name) {
    cov_mark_pc(__builtin_return_address(0));
    return real_getenv(name);
}

char *strcpy(char *dest, const char *src) {
    cov_mark_pc(__builtin_return_address(0));
    return real_strcpy(dest, src);
}

char *strncpy(char *dest, const char *src, size_t n) {
    cov_mark_pc(__builtin_return_address(0));
    return real_strncpy(dest, src, n);
}

int sprintf(char *str, const char *format, ...) {
    cov_mark_pc(__builtin_return_address(0));
    va_list args;
    va_start(args, format);
    int res = real_sprintf(str, format, args);
    va_end(args);
    return res;
}

int snprintf(char *str, size_t size, const char *format, ...) {
    cov_mark_pc(__builtin_return_address(0));
    va_list args;
    va_start(args, format);
    int res = real_snprintf(str, size, format, args);
    va_end(args);
    return res;
}