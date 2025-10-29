#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <getopt.h>
#include "types.h"
#include "json_fuzz.h"
#include "format_detection.h"
#include "fs.h"
#include "safe_wrapper.h"

static void (*fuzz_handles[])(struct state *) = {
    // [file_type_csv] = fuzz_handle_csv,
    [file_type_json] = fuzz_handle_json,
    // [file_type_plain] = fuzz_handle_plaintext,
    // [file_type_xml] = fuzz_handle_xml,
    // [file_type_jpeg] = fuzz_handle_jpeg,
    // [file_type_elf] = fuzz_handle_elf,
    // [file_type_pdf] = fuzz_handle_pdf,
};

static void usage(const char *progname) {
    fprintf(stderr, "Usage: %s -b <binary> -i <input_file> [-n <max_iters>] [-t <timeout>]\n", progname);
    fprintf(stderr, "  -b <binary>      Target binary to fuzz\n");
    fprintf(stderr, "  -i <input_file>   Input file to fuzz\n");
    fprintf(stderr, "  -n <max_iters>   Maximum fuzzing iterations (default: 1000)\n");
    fprintf(stderr, "  -t <timeout>     Fuzzing timeout in seconds (default: 60)\n");
    fprintf(stderr, "  -h               Show this help message\n");
    exit(1);
}

/* Initialize state by memory-mapping input file */
static int init_state(struct state *s) {
    int fd = open(s->input_file, O_RDONLY);
    if (fd < 0) {
        perror("open input_file");
        return -1;
    }

    /* Get file statistics */
    if (fstat(fd, &s->stat) < 0) {
        perror("fstat input_file");
        close(fd);
        return -1;
    }

    /* Memory-map the input file */
    s->mem = mmap(NULL, s->stat.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);

    if (s->mem == MAP_FAILED) {
        perror("mmap input_file");
        return -1;
    }

    return 0;
}

/* Global state for cleanup */
static struct state *global_state = NULL;

void exit_fuzzer(void) {
    /* Cleanup memory-mapped file */
    if (global_state && global_state->mem && global_state->mem != MAP_FAILED) {
        munmap(global_state->mem, global_state->stat.st_size);
    }
    
    /* Cleanup fork server */
    fs_cleanup();
    
    exit(0);
}

int main(int argc, char **argv, char **envp) {
  struct state s = {.binary = NULL,
                    .input_file = NULL,
                    .envp = (const char **)envp,
                    .max_iters = 1000,
                    .timeout = 60,  /* Default 60 seconds fuzzing timeout */
                    .memfd = -1,
                    .mem = NULL};
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

    /* Initialize state: memory-map input file */
    if (init_state(&s) < 0) {
        fprintf(stderr, "[!] Failed to initialize state\n");
        return 1;
    }
    
    /* Store state for cleanup */
    global_state = &s;

    /* Initialize format detection */
    if (format_detection_init() != 0) {
        fprintf(stderr, "[!] Failed to initialize format detection\n");
        munmap(s.mem, s.stat.st_size);
        return 1;
    }

    /* Detect file type from memory-mapped data */
    enum file_type_t file_type = detect_file_type((const char *)s.mem, s.stat.st_size);

    /* Initialize fork server */
    fs_init(&s);

    /* Run appropriate fuzzer handler */
    fuzz_handles[file_type](&s);

    /* Cleanup will be handled by exit_fuzzer() */
    exit_fuzzer();
}
