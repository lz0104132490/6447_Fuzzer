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
#include <sys/time.h>
#include <magic.h>
#include <elf.h>
#include "util.h"
#include "safe_wrapper.h"

static unsigned int rand_state = 1;

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

unsigned char get_elf_class(const char *binary) {
    int fd = open(binary, O_RDONLY);
    if (fd < 0) {
        perror("open binary");
        exit(1);
    }

    unsigned char e_ident[EI_NIDENT];
    ssize_t n = read(fd, e_ident, EI_NIDENT);
    close(fd);

    if (n != EI_NIDENT) {
        fprintf(stderr, "Failed to read ELF header\n");
        exit(1);
    }

    if (memcmp(e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not an ELF file\n");
        exit(1);
    }

    return e_ident[EI_CLASS];
}

char **arr_join(char **arr1, char **arr2) {
    size_t len1 = 0, len2 = 0;
    
    if (arr1) {
        while (arr1[len1]) len1++;
    }
    if (arr2) {
        while (arr2[len2]) len2++;
    }

    char **result = xmalloc((len1 + len2 + 1) * sizeof(char *));
    size_t i = 0;

    if (arr1) {
        for (size_t j = 0; j < len1; j++) {
            result[i++] = arr1[j];
        }
    }
    if (arr2) {
        for (size_t j = 0; j < len2; j++) {
            result[i++] = arr2[j];
        }
    }
    result[i] = NULL;

    return result;
}

/* Initialize timeout tracker */
void timeout_init(struct timeout_tracker *tracker, int timeout_seconds) {
    if (!tracker) {
        return;
    }
    
    gettimeofday(&tracker->start_time, NULL);
    tracker->timeout_seconds = (timeout_seconds > 0) ? timeout_seconds : 60;
}

/* Check if timeout has been reached */
bool timeout_check(const struct timeout_tracker *tracker) {
    if (!tracker) {
        return false;
    }
    
    struct timeval current_time;
    gettimeofday(&current_time, NULL);
    
    double elapsed = (current_time.tv_sec - tracker->start_time.tv_sec) + 
                    (current_time.tv_usec - tracker->start_time.tv_usec) / 1000000.0;
    
    return elapsed >= tracker->timeout_seconds;
}

/* Get elapsed time in seconds */
double timeout_elapsed(const struct timeout_tracker *tracker) {
    if (!tracker) {
        return 0.0;
    }
    
    struct timeval current_time;
    gettimeofday(&current_time, NULL);
    
    return (current_time.tv_sec - tracker->start_time.tv_sec) + 
           (current_time.tv_usec - tracker->start_time.tv_usec) / 1000000.0;
}
