#include <stdio.h>
#include "types.h"

void fuzz_handle_xml(struct state *s) {
    (void)s;
    fprintf(stderr, "[i] XML handler not implemented. Skipping.\n");
}

void fuzz_handle_csv(struct state *s) {
    (void)s;
    fprintf(stderr, "[i] CSV handler not implemented. Skipping.\n");
}

void fuzz_handle_jpeg(struct state *s) {
    (void)s;
    fprintf(stderr, "[i] JPEG handler not implemented. Skipping.\n");
}

void fuzz_handle_elf(struct state *s) {
    (void)s;
    fprintf(stderr, "[i] ELF handler not implemented. Skipping.\n");
}

void fuzz_handle_pdf(struct state *s) {
    (void)s;
    fprintf(stderr, "[i] PDF handler not implemented. Skipping.\n");
}

void fuzz_handle_plaintext(struct state *s) {
    (void)s;
    fprintf(stderr, "[i] Plaintext handler not implemented. Skipping.\n");
}


