#include "safe_wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

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