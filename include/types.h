#ifndef TYPES_H
#define TYPES_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>

/* Fork server file descriptors */
#define CMD_FD 198
#define INFO_FD 199
#define MEMFD_FD 200

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
    int memfd;  /* Memory file descriptor for payload communication */
    void *mem;  /* Memory-mapped input file */
    struct stat stat;  /* File statistics */
};

/* Mutation result */
struct mutation {
    char *data;
    size_t size;
    bool success;
};

enum file_type_t {
    file_type_plain,
    file_type_csv,
    file_type_json,
    file_type_xml,
    file_type_jpeg,
    file_type_elf,
    file_type_pdf,
};

#endif /* TYPES_H */
