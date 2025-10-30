#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

static const char *basename_from_path(const char *path) {
    if (!path) return "unknown";
    const char *slash = strrchr(path, '/');
    return slash ? (slash + 1) : path;
}

void save_bad(const char *prog, const char *data, size_t sz, int iter, int signal) {
    char fname[512];
    const char *base = basename_from_path(prog);
    
    /* Try to save to /fuzzer_outputs if it exists, otherwise current directory */
    const char *output_dir = "/fuzzer_outputs";
    snprintf(fname, sizeof(fname), "%s/bad_%s.txt", output_dir, base);
    
    FILE *f = fopen(fname, "a");
    if (!f) {
        /* Fallback to current directory if /fuzzer_outputs doesn't exist */
        snprintf(fname, sizeof(fname), "bad_%s.txt", base);
        f = fopen(fname, "a");
        if (!f) {
            perror("fopen");
            return;
        }
    }
    
    /* Get signal name for better readability */
    const char *sig_name = "UNKNOWN";
    switch (signal) {
        case 11: sig_name = "SIGSEGV"; break;  /* Segmentation fault */
        case 6:  sig_name = "SIGABRT"; break;  /* Abort signal */
        case 4:  sig_name = "SIGILL"; break;   /* Illegal instruction */
        case 8:  sig_name = "SIGFPE"; break;   /* Floating point exception */
        case 7:  sig_name = "SIGBUS"; break;   /* Bus error */
    }
    
    fprintf(f, "=== Iteration %d ===\n", iter);
    fprintf(f, "Signal: %d (%s)\n", signal, sig_name);
    fprintf(f, "\n--- crash input ---\n");
    fwrite(data, 1, sz, f);
    fprintf(f, "\n--- end input ---\n\n");
    fclose(f);
    
    printf("[!] Crash saved to %s (iteration %d, signal: %s)\n", fname, iter, sig_name);
}

void save_hang(const char *prog, const char *data, size_t sz, int iter) {
    char fname[512];
    const char *base = basename_from_path(prog);
    
    /* Try to save to /fuzzer_outputs if it exists, otherwise current directory */
    const char *output_dir = "/fuzzer_outputs";
    snprintf(fname, sizeof(fname), "%s/hang_%s.txt", output_dir, base);
    
    FILE *f = fopen(fname, "a");
    if (!f) {
        /* Fallback to current directory if /fuzzer_outputs doesn't exist */
        snprintf(fname, sizeof(fname), "hang_%s.txt", base);
        f = fopen(fname, "a");
        if (!f) {
            perror("fopen");
            return;
        }
    }
    
    fprintf(f, "=== Iteration %d (TIMEOUT) ===\n", iter);
    fwrite(data, 1, sz, f);
    fprintf(f, "\n\n");
    fclose(f);
    
    printf("[!] Hang saved to %s (iteration %d)\n", fname, iter);
}