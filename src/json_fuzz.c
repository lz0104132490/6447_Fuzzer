#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
#include "json_fuzz.h"
#include "mutate.h"
#include "fs.h"
#include "util.h"

static void save_bad(const char *prog, const char *data, size_t sz, int iter) {
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

static const char *progname(const char *path) {
    const char *name = strrchr(path, '/');
    return name ? name + 1 : path;
}

int fuzz_json(struct state *s) {
    size_t orig_sz;
    char *orig = read_file(s->input_file, &orig_sz);
    if (!orig) {
        fprintf(stderr, "Failed to read input file: %s\n", s->input_file);
        return 1;
    }

    const char *ftype = detect_ftype(orig, orig_sz);
    printf("[*] Starting fuzzer\n");
    printf("[*] Target: %s\n", s->binary);
    printf("[*] Input: %s (%zu bytes)\n", s->input_file, orig_sz);
    printf("[*] Detected type: %s\n", ftype);
    printf("[*] Max iterations: %d\n", s->max_iters);

    rand_init(time(NULL));
    
    /* Initialize fork server */
    fs_init(s);

    int crashes = 0;
    int hangs = 0;
    const char *prog = progname(s->binary);

    for (int i = 0; i < s->max_iters; i++) {
        /* Select mutation based on file type */
        enum mut_type mtype = pick_mut(ftype);
        
        /* Apply mutation */
        struct mutation m = mutate(orig, orig_sz, mtype);
        if (!m.success) {
            mutation_free(&m);
            continue;
        }

        /* Create memfd with mutated data */
        int mfd = memfd_create_buf(m.data, m.size);
        if (mfd < 0) {
            mutation_free(&m);
            continue;
        }

        char path[64];
        memfd_path(mfd, path, sizeof(path));

        /* Run target */
        int wstatus = fs_run(path);
        close(mfd);

        /* Check for crash */
        if (WIFSIGNALED(wstatus)) {
            int sig = WTERMSIG(wstatus);
            printf("[!] CRASH: signal %d at iteration %d\n", sig, i);
            save_bad(prog, m.data, m.size, i);
            crashes++;
        } else if (WIFEXITED(wstatus)) {
            int exitcode = WEXITSTATUS(wstatus);
            if (exitcode != 0) {
                /* Non-zero exit might indicate error */
            }
        }

        mutation_free(&m);

        /* Progress */
        if ((i + 1) % 100 == 0) {
            printf("[*] Progress: %d/%d (crashes: %d, hangs: %d)\n", 
                   i + 1, s->max_iters, crashes, hangs);
        }
    }

    fs_cleanup();
    magic_cleanup();
    free(orig);

    printf("\n[*] Fuzzing complete\n");
    printf("[*] Total iterations: %d\n", s->max_iters);
    printf("[*] Crashes found: %d\n", crashes);
    printf("[*] Hangs found: %d\n", hangs);

    return 0;
}
