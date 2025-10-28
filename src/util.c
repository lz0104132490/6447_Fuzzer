#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <magic.h>
#include "util.h"

static unsigned int rand_state = 1;

void *xmalloc(size_t size) {
    void *ptr = malloc(size);
    if (!ptr) {
        perror("malloc");
        exit(1);
    }
    return ptr;
}

void *xrealloc(void *ptr, size_t size) {
    void *new_ptr = realloc(ptr, size);
    if (!new_ptr && size > 0) {
        perror("realloc");
        exit(1);
    }
    return new_ptr;
}

char *xstrdup(const char *s) {
    char *dup = strdup(s);
    if (!dup) {
        perror("strdup");
        exit(1);
    }
    return dup;
}

int xopen(const char *path, int flags) {
    int fd = open(path, flags, 0644);
    if (fd < 0) {
        perror("open");
        exit(1);
    }
    return fd;
}

ssize_t xread(int fd, void *buf, size_t count) {
    ssize_t ret = read(fd, buf, count);
    if (ret < 0) {
        perror("read");
        exit(1);
    }
    return ret;
}

ssize_t xwrite(int fd, const void *buf, size_t count) {
    ssize_t ret = write(fd, buf, count);
    if (ret < 0) {
        perror("write");
        exit(1);
    }
    return ret;
}

pid_t xfork(void) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(1);
    }
    return pid;
}

char *read_file(const char *path, size_t *size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return NULL;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return NULL;
    }

    char *data = xmalloc(st.st_size + 1);
    ssize_t n = read(fd, data, st.st_size);
    if (n < 0) {
        perror("read");
        free(data);
        close(fd);
        return NULL;
    }

    data[n] = '\0';
    *size = n;
    close(fd);
    return data;
}

void write_file(const char *path, const char *data, size_t size) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        return;
    }

    ssize_t n = write(fd, data, size);
    if (n < 0) {
        perror("write");
    }

    close(fd);
}

void rand_init(unsigned int seed) {
    rand_state = seed;
}

unsigned int rand_next(void) {
    rand_state = rand_state * 1103515245 + 12345;
    return (rand_state / 65536) % 32768;
}

int rand_range(int min, int max) {
    if (min >= max)
        return min;
    return min + (rand_next() % (max - min + 1));
}

int memfd_create_buf(const char *data, size_t size) {
    int fd = memfd_create("fuzz", MFD_CLOEXEC);
    if (fd < 0) {
        perror("memfd_create");
        return -1;
    }

    ssize_t n = write(fd, data, size);
    if (n < 0 || (size_t)n != size) {
        perror("write memfd");
        close(fd);
        return -1;
    }

    lseek(fd, 0, SEEK_SET);
    return fd;
}

char *memfd_path(int fd, char *buf, size_t len) {
    snprintf(buf, len, "/proc/self/fd/%d", fd);
    return buf;
}

const char *detect_type(const char *data, size_t size) {
    static magic_t magic = NULL;
    
    if (!magic) {
        magic = magic_open(MAGIC_MIME_TYPE);
        if (!magic) {
            fprintf(stderr, "magic_open failed\n");
            return "application/octet-stream";
        }
        if (magic_load(magic, NULL) != 0) {
            fprintf(stderr, "magic_load: %s\n", magic_error(magic));
            magic_close(magic);
            magic = NULL;
            return "application/octet-stream";
        }
    }

    const char *type = magic_buffer(magic, data, size);
    return type ? type : "application/octet-stream";
}
