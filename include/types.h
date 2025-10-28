#ifndef TYPES_H
#define TYPES_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Fork server file descriptors */
#define CMD_FD 198
#define INFO_FD 199

/* Fork server commands */
#define CMD_RUN 'R'
#define CMD_QUIT 'Q'
#define CMD_TEST 'T'

/* Fuzzer state */
struct state {
    const char *binary;
    const char *input_file;
    const char **envp;
    int max_iters;
    int timeout;
};

/* Mutation result */
struct mutation {
    char *data;
    size_t size;
    bool success;
};

#endif
