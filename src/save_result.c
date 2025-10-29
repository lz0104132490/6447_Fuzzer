#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

void save_bad(const char *prog, const char *data, size_t sz, int iter) {
    char fname[256];
    snprintf(fname, sizeof(fname), "bad_%s.txt", prog);
    
    FILE *f = fopen(fname, "a");
    if (!f) {
        perror("fopen");
        return;
    }
    
    fprintf(f, "=== Iteration %d ===\n", iter);
    fwrite(data, 1, sz, f);
    fprintf(f, "\n\n");
    fclose(f);
    
    printf("[!] Crash saved to %s (iteration %d)\n", fname, iter);
}

void save_hang(const char *prog, const char *data, size_t sz, int iter) {
    char fname[256];
    snprintf(fname, sizeof(fname), "hang_%s.txt", prog);
    
    FILE *f = fopen(fname, "a");
    if (!f) {
        perror("fopen");
        return;
    }
    
    fprintf(f, "=== Iteration %d (TIMEOUT) ===\n", iter);
    fwrite(data, 1, sz, f);
    fprintf(f, "\n\n");
    fclose(f);
    
    printf("[!] Hang saved to %s (iteration %d)\n", fname, iter);
}