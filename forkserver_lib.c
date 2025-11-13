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

static ssize_t (*real_read)(int fd, void *buf, size_t count) = NULL;
static ssize_t (*real_write)(int fd, const void *buf, size_t count) = NULL;
static int (*real_open)(const char *pathname, int flags, ...) = NULL;
static int (*real_openat)(int dirfd, const char *pathname, int flags, ...) = NULL;
static void *(*real_mmap)(void *addr, size_t length, int prot, int flags, int fd, off_t offset) = NULL;
static void *(*real_malloc)(size_t size) = NULL;
static void (*real_free)(void *ptr) = NULL;
static void *(*real_calloc)(size_t nmemb, size_t size) = NULL;
static void *(*real_realloc)(void *ptr, size_t size) = NULL;

// Shared memory for stdin replacement: layout [4 bytes len][payload...]
static uint8_t *shm_base = NULL;
static size_t shm_size = 0;
static size_t shm_off = 0;

// Coverage bitmap shared memory (no recompile): we mark call sites of interposed libc calls
static uint8_t *cov_base = NULL;
static size_t cov_size = 0;

static void init_real_read(void) {
    if (!real_read) {
        real_read = (ssize_t (*)(int, void*, size_t))dlsym(RTLD_NEXT, "read");
        if (!real_read) {
            _exit(127);
        }
    }
    if (!real_write) real_write = (ssize_t (*)(int, const void*, size_t))dlsym(RTLD_NEXT, "write");
    if (!real_open) real_open = (int (*)(const char*, int, ...))dlsym(RTLD_NEXT, "open");
    if (!real_openat) real_openat = (int (*)(int, const char*, int, ...))dlsym(RTLD_NEXT, "openat");
    if (!real_mmap) real_mmap = (void *(*)(void*, size_t, int, int, int, off_t))dlsym(RTLD_NEXT, "mmap");
    if (!real_malloc) real_malloc = (void *(*)(size_t))dlsym(RTLD_NEXT, "malloc");
    if (!real_free) real_free = (void (*)(void*))dlsym(RTLD_NEXT, "free");
    if (!real_calloc) real_calloc = (void *(*)(size_t, size_t))dlsym(RTLD_NEXT, "calloc");
    if (!real_realloc) real_realloc = (void *(*)(void*, size_t))dlsym(RTLD_NEXT, "realloc");
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

        pid_t pid = fork();
        if (pid < 0) _exit(1);
        if (pid == 0) {
            // child branch: reset stdin offset and close fds
            shm_off = 0;
            close(FORKSRV_FD);
            close(FORKSRV_FD_OUT);
            return 0; // return to program
        }
        // parent (forkserver) branch
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
    init_real_read();
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

ssize_t read(int fd, void *buf, size_t count) {
    init_real_read();
    if (fd != 0 || !shm_base || shm_size < 4) {
        return real_read(fd, buf, count);
    }
    // First 4 bytes little-endian length
    uint32_t total = (uint32_t)shm_base[0] | ((uint32_t)shm_base[1] << 8) | ((uint32_t)shm_base[2] << 16) | ((uint32_t)shm_base[3] << 24);
    if (total + 4 > shm_size) {
        total = (uint32_t)(shm_size > 4 ? shm_size - 4 : 0);
    }
    if (shm_off >= total) {
        return 0; // EOF
    }
    size_t avail = total - shm_off;
    size_t to_copy = avail < count ? avail : count;
    memcpy(buf, shm_base + 4 + shm_off, to_copy);
    shm_off += to_copy;
    return (ssize_t)to_copy;
}

static inline void cov_mark_pc(void *pc) {
    if (!cov_base || cov_size == 0) return;
    size_t idx = ((uintptr_t)pc >> 4) % cov_size;
    cov_base[idx]++;
}

ssize_t write(int fd, const void *buf, size_t count) {
    init_real_read();
    cov_mark_pc(__builtin_return_address(0));
    return real_write(fd, buf, count);
}

int open(const char *pathname, int flags, ...) {
    init_real_read();
    cov_mark_pc(__builtin_return_address(0));
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
    }
    return real_open(pathname, flags, mode);
}

int openat(int dirfd, const char *pathname, int flags, ...) {
    init_real_read();
    cov_mark_pc(__builtin_return_address(0));
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap);
    }
    return real_openat(dirfd, pathname, flags, mode);
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    init_real_read();
    cov_mark_pc(__builtin_return_address(0));
    return real_mmap(addr, length, prot, flags, fd, offset);
}

void *malloc(size_t size) {
    init_real_read();
    cov_mark_pc(__builtin_return_address(0));
    return real_malloc(size);
}

void free(void *ptr) {
    init_real_read();
    cov_mark_pc(__builtin_return_address(0));
    real_free(ptr);
}

void *calloc(size_t nmemb, size_t size) {
    init_real_read();
    cov_mark_pc(__builtin_return_address(0));
    return real_calloc(nmemb, size);
}

void *realloc(void *ptr, size_t size) {
    init_real_read();
    cov_mark_pc(__builtin_return_address(0));
    return real_realloc(ptr, size);
}
