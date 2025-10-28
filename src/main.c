#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "types.h"
#include "json_fuzz.h"

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -b <binary>    Target binary to fuzz\n");
    fprintf(stderr, "  -i <input>     Input file (JSON)\n");
    fprintf(stderr, "  -n <count>     Number of iterations (default: 1000)\n");
    fprintf(stderr, "  -t <timeout>   Timeout in seconds (default: 5)\n");
    fprintf(stderr, "  -h             Show this help\n");
    exit(1);
}

int main(int argc, char **argv, char **envp) {
    struct state s = {
        .binary = NULL,
        .input_file = NULL,
        .envp = (const char **)envp,
        .max_iters = 1000,
        .timeout = 5
    };

    int opt;
    while ((opt = getopt(argc, argv, "b:i:n:t:h")) != -1) {
        switch (opt) {
        case 'b':
            s.binary = optarg;
            break;
        case 'i':
            s.input_file = optarg;
            break;
        case 'n':
            s.max_iters = atoi(optarg);
            break;
        case 't':
            s.timeout = atoi(optarg);
            break;
        case 'h':
        default:
            usage(argv[0]);
        }
    }

    if (!s.binary || !s.input_file) {
        fprintf(stderr, "Error: -b and -i are required\n");
        usage(argv[0]);
    }

    return fuzz_json(&s);
}
