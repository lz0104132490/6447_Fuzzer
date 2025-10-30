#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/time.h>
#include "types.h"

/* Random number generation */
void rand_init(unsigned int seed);
unsigned int rand_next(void);
int rand_range(int min, int max);

/* Memory file descriptor operations */
int memfd_create_buf(const char *data, size_t sz);
char *memfd_path(int fd, char *buf, size_t len);

/* ELF detection */
unsigned char get_elf_class(const char *binary);

/* Array utilities */
char **arr_join(char **arr1, char **arr2);

/* Timeout tracking for fuzzing */
struct timeout_tracker {
    struct timeval start_time;
    int timeout_seconds;
};

/* Initialize timeout tracker with timeout in seconds */
void timeout_init(struct timeout_tracker *tracker, int timeout_seconds);

/* Check if timeout has been reached, returns true if timeout exceeded */
bool timeout_check(const struct timeout_tracker *tracker);

/* Get elapsed time in seconds since timeout_init was called */
double timeout_elapsed(const struct timeout_tracker *tracker);

/* Check if target crashed and save crash input */
void check_crash(struct state *s, int wstatus, int iteration);

#endif /* UTIL_H */
