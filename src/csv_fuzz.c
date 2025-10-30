#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>

#include "csv_fuzz.h"
#include "mutate.h"
#include "util.h"
#include "fs.h"
#include "safe_wrapper.h"
#include "save_result.h"
#include <sys/wait.h>


/* Forward declarations */
static void fuzz_buffer_overflow(struct state *s);
static void fuzz_bad_nums(struct state *s);
static void fuzz_csv_injection(struct state *s);
static void fuzz_special_chars(struct state *s);
static void fuzz_empty_cells(struct state *s);
static void fuzz_bit_flip(struct state *s);
static void fuzz_add_rows(struct state *s);
static void fuzz_add_columns(struct state *s);
static void fuzz_mutations(struct state *s);
static void csv_revert(void);

/* Array of single-run strategies */
static void (*fuzz_payloads_single[])(struct state *) = {
    fuzz_buffer_overflow,
    fuzz_bad_nums,
    fuzz_csv_injection,
    fuzz_special_chars,
    fuzz_empty_cells,
};
#define SINGLE_PAYLOADS_COUNT (sizeof(fuzz_payloads_single) / sizeof(fuzz_payloads_single[0]))

/* Array of repeating strategies */
static void (*fuzz_payloads_repeat[])(struct state *) = {
    fuzz_bit_flip,
    fuzz_add_rows,
    fuzz_add_columns,
    fuzz_mutations,
};
#define REPEAT_PAYLOADS_COUNT (sizeof(fuzz_payloads_repeat) / sizeof(fuzz_payloads_repeat[0]))

/* Represents a single CSV cell/value */
struct csv_value {
    char *val;           /* Current value */
    char *orig_val;      /* Original value for restoration */
    size_t len;          /* Current length */
    size_t orig_len;     /* Original length */
    bool added;          /* Flag if this was artificially added */
    struct csv_value *next;
    struct csv_value *prev;
};

/* Represents a CSV row */
struct csv_row {
    char *row_text;      /* Full row as text */
    char *orig_row_text; /* Original row text */
    size_t nvals;        /* Number of values in this row */
    size_t orig_nvals;   /* Original number of values */
    bool added;          /* Flag if this row was artificially added */
    struct csv_value *vals;  /* Linked list of values */
    struct csv_row *next;
    struct csv_row *prev;
};

/* Global CSV corpus */
static struct {
    size_t nrows;
    size_t orig_nrows;
    struct csv_row *rows;
} csv_corpus = {0};

/* Global iteration counter for crash reporting */
static int g_iteration = 0;

/* ============================================================================
 * CONSTANTS AND TEST VALUES
 * ============================================================================ */

/* Large buffer for overflow testing */
#define BIG_SIZE 800
static const char BIG[BIG_SIZE + 1] = 
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/* CSV injection payloads (formula injection) */
static const char *csv_injection_payloads[] = {
    "=1+1",
    "=A1+A2",
    "=SUM(A1:A10)",
    "=cmd|' /C calc'!'A1'",
    "=HYPERLINK(\"http://evil.com\", \"click\")",
    "@SUM(1+1)",
    "+1+1",
    "-1+1",
    "=1+1+cmd|' /C calc'!'A1'",
};
#define CSV_INJECTION_COUNT (sizeof(csv_injection_payloads) / sizeof(csv_injection_payloads[0]))

/* Boundary integer values */
static const int64_t bad_nums[] = {
    -128, -1, 0, 1, 16, 32, 64, 100, 127,
    -32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767,
    -2147483648LL, -100663046, -32769, 32768, 65535, 65536,
    100663045, 2147483647LL, 2147483648LL, -2147483649LL
};
#define BAD_NUMS_COUNT (sizeof(bad_nums) / sizeof(bad_nums[0]))

/* Boundary float values */
static const double bad_floats[] = {
    0.0, -0.0, 0.33333333333333, M_PI, 0.1, 0.1000000,
    -1.0, 1.0, INFINITY, -INFINITY, NAN, 1e308, -1e308
};
#define BAD_FLOATS_COUNT (sizeof(bad_floats) / sizeof(bad_floats[0]))

/* Special characters that may break parsing */
static const char *special_chars[] = {
    "\"", "\"\"", "\\", "\n", "\r", "\r\n", "\t",
    ",", ",,", ",,,", "\"\"\"", "\\\"", "\",\"",
    "\"\\n\"", "\"\\r\\n\"", "\",\",\",\"", 
};
#define SPECIAL_CHARS_COUNT (sizeof(special_chars) / sizeof(special_chars[0]))

/* Check if target crashed and save crash input */

/* Simple CSV line parser (handles quoted fields) */
static char **parse_csv_line(const char *line) {
    if (!line) return NULL;
    
    /* Allocate space for values (max 256 columns) */
    char **result = xmalloc(sizeof(char *) * 257);
    int count = 0;
    
    const char *p = line;
    char buffer[4096];
    int buf_idx = 0;
    bool in_quotes = false;
    
    while (*p && count < 256) {
        if (*p == '"') {
            if (in_quotes && *(p + 1) == '"') {
                /* Escaped quote */
                buffer[buf_idx++] = '"';
                p += 2;
            } else {
                in_quotes = !in_quotes;
                p++;
            }
        } else if (*p == ',' && !in_quotes) {
            /* End of field */
            buffer[buf_idx] = '\0';
            result[count++] = xstrdup(buffer);
            buf_idx = 0;
            p++;
        } else if ((*p == '\n' || *p == '\r') && !in_quotes) {
            /* End of line */
            break;
        } else {
            buffer[buf_idx++] = *p++;
            if (buf_idx >= 4095) break; /* Prevent overflow */
        }
    }
    
    /* Add last field */
    buffer[buf_idx] = '\0';
    result[count++] = xstrdup(buffer);
    result[count] = NULL;
    
    return result;
}

/* Free parsed CSV line */
static void free_csv_line(char **parsed) {
    if (!parsed) return;
    for (int i = 0; parsed[i]; i++) {
        free(parsed[i]);
    }
    free(parsed);
}

/* Count array length */
static size_t arr_length(char **arr) {
    size_t count = 0;
    if (!arr) return 0;
    while (arr[count]) count++;
    return count;
}

/* Split input on newlines */
static char **split_lines(const char *data, size_t size) {
    /* Allocate space for lines (max 10000 lines) */
    char **lines = xmalloc(sizeof(char *) * 10001);
    int count = 0;
    
    const char *start = data;
    const char *p = data;
    const char *end = data + size;
    
    while (p < end && count < 10000) {
        if (*p == '\n') {
            /* Found newline */
            size_t len = p - start;
            char *line = xmalloc(len + 1);
            memcpy(line, start, len);
            line[len] = '\0';
            
            /* Remove \r if present */
            if (len > 0 && line[len - 1] == '\r') {
                line[len - 1] = '\0';
            }
            
            lines[count++] = line;
            start = p + 1;
        }
        p++;
    }
    
    /* Add last line if not empty */
    if (start < end) {
        size_t len = end - start;
        char *line = xmalloc(len + 1);
        memcpy(line, start, len);
        line[len] = '\0';
        lines[count++] = line;
    }
    
    lines[count] = NULL;
    return lines;
}

/* Dump CSV to memfd and return size */
static size_t csv_dump(struct state *s) {
    /* Reset memfd */
    if (ftruncate(s->memfd, 0) < 0) {
        perror("ftruncate");
        return 0;
    }
    if (lseek(s->memfd, 0, SEEK_SET) < 0) {
        perror("lseek");
        return 0;
    }
    
    size_t total = 0;
    struct csv_row *row = csv_corpus.rows;
    
    while (row) {
        struct csv_value *val = row->vals;
        bool first = true;
        
        while (val) {
            if (!first) {
                write(s->memfd, ",", 1);
                total++;
            }
            first = false;
            
            if (val->len > 0) {
                ssize_t n = write(s->memfd, val->val, val->len);
                if (n > 0) total += n;
            }
            
            val = val->next;
        }
        
        write(s->memfd, "\n", 1);
        total++;
        row = row->next;
    }
    
    return total;
}

/* Revert CSV corpus to original state */
static void csv_revert(void) {
    struct csv_row *row = csv_corpus.rows;
    struct csv_row *prev_row = NULL;
    
    while (row) {
        if (row->added) {
            /* Remove this row */
            struct csv_row *next = row->next;
            if (row->row_text) free(row->row_text);
            if (row->orig_row_text) free(row->orig_row_text);
            
            /* Free values */
            struct csv_value *val = row->vals;
            while (val) {
                struct csv_value *next_val = val->next;
                if (val->val) free(val->val);
                if (val->orig_val) free(val->orig_val);
                free(val);
                val = next_val;
            }
            
            if (prev_row) {
                prev_row->next = next;
            } else {
                csv_corpus.rows = next;
            }
            
            free(row);
            row = next;
        } else {
            /* Revert values */
            row->nvals = row->orig_nvals;
            struct csv_value *val = row->vals;
            struct csv_value *prev_val = NULL;
            
            while (val) {
                if (val->added) {
                    /* Remove this value */
                    struct csv_value *next_val = val->next;
                    if (val->val) free(val->val);
                    if (val->orig_val) free(val->orig_val);
                    
                    if (prev_val) {
                        prev_val->next = next_val;
                    } else {
                        row->vals = next_val;
                    }
                    
                    free(val);
                    val = next_val;
                } else {
                    /* Revert value */
                    if (val->val && val->val != val->orig_val) {
                        free(val->val);
                    }
                    val->val = xstrdup(val->orig_val);
                    val->len = val->orig_len;
                    prev_val = val;
                    val = val->next;
                }
            }
            
            prev_row = row;
            row = row->next;
        }
    }
    
    csv_corpus.nrows = csv_corpus.orig_nrows;
}

/* ============================================================================
 * FUZZING STRATEGIES - SINGLE RUN (Deterministic)
 * ============================================================================ */

/* Test buffer overflow by replacing cells with large strings */
static void fuzz_buffer_overflow(struct state *s) {
    printf("[*] Running buffer overflow fuzzing...\n");
    
    struct csv_row *row = csv_corpus.rows;
    while (row) {
        struct csv_value *val = row->vals;
        while (val) {
            /* Save original */
            char *old_val = val->val;
            size_t old_len = val->len;
            
            /* Replace with large buffer */
            val->val = (char *)BIG;
            val->len = BIG_SIZE;
            
            csv_dump(s);
            int wstatus = deploy();
            check_crash(s, wstatus, g_iteration++);
            
            /* Restore */
            val->val = old_val;
            val->len = old_len;
            
            val = val->next;
        }
        row = row->next;
    }

    csv_revert();
}

/* Test with boundary integer and float values */
static void fuzz_bad_nums(struct state *s) {
    printf("[*] Running bad numbers fuzzing...\n");
    
    struct csv_row *row = csv_corpus.rows;
    while (row) {
        struct csv_value *val = row->vals;
        while (val) {
            char *old_val = val->val;
            size_t old_len = val->len;
            
            /* Try bad integers */
            for (size_t i = 0; i < BAD_NUMS_COUNT; i++) {
                char buf[64];
                snprintf(buf, sizeof(buf), "%lld", (long long)bad_nums[i]);
                val->val = buf;
                val->len = strlen(buf);
                csv_dump(s);
                int wstatus = deploy();
                check_crash(s, wstatus, g_iteration++);
            }
            
            /* Try bad floats */
            for (size_t i = 0; i < BAD_FLOATS_COUNT; i++) {
                char buf[64];
                if (isnan(bad_floats[i])) {
                    strcpy(buf, "NaN");
                } else if (isinf(bad_floats[i])) {
                    strcpy(buf, bad_floats[i] > 0 ? "Infinity" : "-Infinity");
                } else {
                    snprintf(buf, sizeof(buf), "%.15g", bad_floats[i]);
                }
                val->val = buf;
                val->len = strlen(buf);
                csv_dump(s);
                int wstatus = deploy();
                check_crash(s, wstatus, g_iteration++);
            }
            
            /* Restore */
            val->val = old_val;
            val->len = old_len;
            
            val = val->next;
        }
        row = row->next;
    }
}

/* Test CSV injection attacks */
static void fuzz_csv_injection(struct state *s) {
    printf("[*] Running CSV injection fuzzing...\n");
    
    struct csv_row *row = csv_corpus.rows;
    while (row) {
        struct csv_value *val = row->vals;
        while (val) {
            char *old_val = val->val;
            size_t old_len = val->len;
            
            /* Try injection payloads */
            for (size_t i = 0; i < CSV_INJECTION_COUNT; i++) {
                val->val = (char *)csv_injection_payloads[i];
                val->len = strlen(csv_injection_payloads[i]);
                csv_dump(s);
                int wstatus = deploy();
                check_crash(s, wstatus, g_iteration++);
            }
            
            /* Restore */
            val->val = old_val;
            val->len = old_len;
            
            val = val->next;
        }
        row = row->next;
    }
}

/* Test with special characters */
static void fuzz_special_chars(struct state *s) {
    printf("[*] Running special characters fuzzing...\n");
    
    struct csv_row *row = csv_corpus.rows;
    while (row) {
        struct csv_value *val = row->vals;
        while (val) {
            char *old_val = val->val;
            size_t old_len = val->len;
            
            /* Try special characters */
            for (size_t i = 0; i < SPECIAL_CHARS_COUNT; i++) {
                val->val = (char *)special_chars[i];
                val->len = strlen(special_chars[i]);
                csv_dump(s);
                int wstatus = deploy();
                check_crash(s, wstatus, g_iteration++);
            }
            
            /* Restore */
            val->val = old_val;
            val->len = old_len;
            
            val = val->next;
        }
        row = row->next;
    }
}

/* Test with empty cells */
static void fuzz_empty_cells(struct state *s) {
    printf("[*] Running empty cells fuzzing...\n");
    
    struct csv_row *row = csv_corpus.rows;
    while (row) {
        struct csv_value *val = row->vals;
        while (val) {
            char *old_val = val->val;
            size_t old_len = val->len;
            
            /* Empty value */
            val->val = "";
            val->len = 0;
            csv_dump(s);
            int wstatus = deploy();
            check_crash(s, wstatus, g_iteration++);
            
            /* Restore */
            val->val = old_val;
            val->len = old_len;
            
            val = val->next;
        }
        row = row->next;
    }

    csv_revert();
}

/* ============================================================================
 * FUZZING STRATEGIES - REPEATING (Randomized)
 * ============================================================================ */

/* Bit flip near CSV structure characters */
static void fuzz_bit_flip(struct state *s) {
    size_t len = csv_dump(s);
    if (len == 0) return;
    
    /* Read back serialized CSV */
    char *buf = xmalloc(len);
    lseek(s->memfd, 0, SEEK_SET);
    if (read(s->memfd, buf, len) != (ssize_t)len) {
        free(buf);
        return;
    }
    
    /* Find structure characters and flip nearby bits */
    for (size_t i = 0; i < len; i++) {
        char ch = buf[i];
        
        if (ch == ',' || ch == '\n' || ch == '"' || ch == '\\' || ch == '\r') {
            /* Flip bits near structure character */
            size_t offset = i + rand_range(0, 5);
            if (offset >= len) offset = len - 1;
            
            unsigned char shift = rand_range(1, 7);
            char mutated = buf[offset] << shift;
            
            /* Write mutated byte */
            lseek(s->memfd, offset, SEEK_SET);
            write(s->memfd, &mutated, 1);
            ftruncate(s->memfd, len);
            
            int wstatus = deploy();
            check_crash(s, wstatus, g_iteration++);
            
            /* Restore */
            lseek(s->memfd, offset, SEEK_SET);
            write(s->memfd, &buf[offset], 1);
        }
    }
    
    free(buf);
}

/* Add extra rows */
static void fuzz_add_rows(struct state *s) {
    /* Find last row */
    struct csv_row *last = csv_corpus.rows;
    while (last && last->next) {
        last = last->next;
    }
    
    if (!last) return;
    
    /* Add a duplicate row */
    struct csv_row *new_row = xmalloc(sizeof(struct csv_row));
    new_row->row_text = xstrdup(last->row_text);
    new_row->orig_row_text = NULL;
    new_row->nvals = last->nvals;
    new_row->orig_nvals = 0;
    new_row->added = true;
    new_row->next = NULL;
    new_row->prev = last;
    
    /* Copy values */
    new_row->vals = NULL;
    struct csv_value *src = last->vals;
    struct csv_value *prev_val = NULL;
    
    while (src) {
        struct csv_value *new_val = xmalloc(sizeof(struct csv_value));
        new_val->val = xstrdup(src->val);
        new_val->orig_val = NULL;
        new_val->len = src->len;
        new_val->orig_len = 0;
        new_val->added = true;
        new_val->next = NULL;
        new_val->prev = prev_val;
        
        if (prev_val) {
            prev_val->next = new_val;
        } else {
            new_row->vals = new_val;
        }
        
        prev_val = new_val;
        src = src->next;
    }
    
    last->next = new_row;
    csv_corpus.nrows++;
    
    csv_dump(s);
    int wstatus = deploy();
    check_crash(s, wstatus, g_iteration++);
}

/* Add extra columns */
static void fuzz_add_columns(struct state *s) {
    /* Get row 0 (header row) */
    struct csv_row *header_row = csv_corpus.rows;
    if (!header_row) return;
    
    /* Pick a random value from row 0 to use as template */
    struct csv_value *header_val = header_row->vals;
    if (!header_val) return;
    
    /* Count header values and pick one randomly */
    size_t header_count = 0;
    struct csv_value *hv = header_val;
    while (hv) {
        header_count++;
        hv = hv->next;
    }
    
    if (header_count == 0) return;
    
    size_t pick_index = rand() % header_count;
    hv = header_val;
    for (size_t i = 0; i < pick_index && hv; i++) {
        hv = hv->next;
    }
    
    if (!hv) return;
    
    /* Now add this column to all rows */
    struct csv_row *row = csv_corpus.rows;
    
    while (row) {
        /* Find last value */
        struct csv_value *last = row->vals;
        while (last && last->next) {
            last = last->next;
        }
        
        if (last) {
            /* Add new column using value from row 0 */
            struct csv_value *new_val = xmalloc(sizeof(struct csv_value));
            new_val->val = xstrdup(hv->val);
            new_val->orig_val = NULL;
            new_val->len = hv->len;
            new_val->orig_len = 0;
            new_val->added = true;
            new_val->next = NULL;
            new_val->prev = last;
            
            last->next = new_val;
            row->nvals++;
        }
        
        row = row->next;
    }
    
    csv_dump(s);
    int wstatus = deploy();
    check_crash(s, wstatus, g_iteration++);
}

/* Generic mutations using mutate.c */
static void fuzz_mutations(struct state *s) {
    size_t len = csv_dump(s);
    if (len == 0) return;
    
    /* Read current state */
    char *buf = xmalloc(len);
    lseek(s->memfd, 0, SEEK_SET);
    if (read(s->memfd, buf, len) != (ssize_t)len) {
        free(buf);
        return;
    }
    
    /* Apply random mutation */
    enum mut_type mtype = pick_mut("csv");
    struct mutation mut = mutate(buf, len, mtype);
    
    if (mut.success && mut.data) {
        /* Write mutated data */
        ftruncate(s->memfd, 0);
        lseek(s->memfd, 0, SEEK_SET);
        write(s->memfd, mut.data, mut.size);
        
        int wstatus = deploy();
        check_crash(s, wstatus, g_iteration++);
        
        free(mut.data);
    }
    
    free(buf);
}

/* ============================================================================
 * MAIN FUZZING LOOP
 * ============================================================================ */


/* Main fuzzing orchestrator */
static void fuzz(struct state *s) {
    printf("[*] Starting CSV fuzzing...\n");
    
    /* Initialize timeout tracking */
    struct timeout_tracker timeout;
    timeout_init(&timeout, s->timeout);
    
    /* Run deterministic strategies once */
    printf("[*] Running %zu deterministic strategies...\n", SINGLE_PAYLOADS_COUNT);
    for (size_t i = 0; i < SINGLE_PAYLOADS_COUNT; i++) {
        fuzz_payloads_single[i](s);
    }
    
    /* Run randomized strategies */
    printf("[*] Starting randomized fuzzing loop (max_iters=%d, timeout=%ds)...\n",
           s->max_iters, s->timeout);
    
    for (int iteration = 0; iteration < s->max_iters; iteration++) {
        /* Check timeout */
        if (timeout_check(&timeout)) {
            printf("[*] Timeout reached after %d iterations\n", iteration);
            break;
        }
        
        /* Pick random strategy */
        int idx = rand_range(0, REPEAT_PAYLOADS_COUNT - 1);
        fuzz_payloads_repeat[idx](s);
        
        /* Progress reporting */
        if ((iteration + 1) % 1000 == 0) {
            printf("[*] Completed %d/%d iterations (%.1fs elapsed)\n",
                   iteration + 1, s->max_iters, timeout_elapsed(&timeout));
        }
    }
    
    printf("[*] Fuzzing completed: %d iterations in %.1f seconds\n",
           s->max_iters, timeout_elapsed(&timeout));
}

/* Main entry point for CSV fuzzing */
void fuzz_handle_csv(struct state *s) {
    printf("[*] Initializing CSV fuzzer...\n");
    
    /* Parse CSV input */
    const char *input = (const char *)s->mem;
    size_t input_size = (size_t)s->stat.st_size;
    
    /* Split into lines */
    char **lines = split_lines(input, input_size);
    if (!lines || !lines[0]) {
        fprintf(stderr, "[!] Failed to parse CSV input\n");
        return;
    }
    
    /* Count lines */
    size_t nlines = arr_length(lines);
    csv_corpus.nrows = nlines;
    csv_corpus.orig_nrows = nlines;
    
    printf("[+] Parsed %zu CSV rows\n", nlines);
    
    /* Build row structures */
    csv_corpus.rows = NULL;
    struct csv_row *prev_row = NULL;
    
    for (size_t i = 0; i < nlines; i++) {
        struct csv_row *row = xmalloc(sizeof(struct csv_row));
        row->row_text = lines[i];
        row->orig_row_text = xstrdup(lines[i]);
        row->added = false;
        row->next = NULL;
        row->prev = prev_row;
        
        /* Parse values */
        char **vals = parse_csv_line(lines[i]);
        row->nvals = arr_length(vals);
        row->orig_nvals = row->nvals;
        
        /* Build value list */
        row->vals = NULL;
        struct csv_value *prev_val = NULL;
        
        for (size_t j = 0; vals[j]; j++) {
            struct csv_value *val = xmalloc(sizeof(struct csv_value));
            val->val = vals[j];
            val->orig_val = xstrdup(vals[j]);
            val->len = strlen(vals[j]);
            val->orig_len = val->len;
            val->added = false;
            val->next = NULL;
            val->prev = prev_val;
            
            if (prev_val) {
                prev_val->next = val;
            } else {
                row->vals = val;
            }
            
            prev_val = val;
        }
        
        free(vals);  /* Don't free individual strings, they're now owned by csv_value */
        
        if (prev_row) {
            prev_row->next = row;
        } else {
            csv_corpus.rows = row;
        }
        
        prev_row = row;
    }
    
    free(lines);  /* Don't free individual lines, they're now owned by csv_row */
    
    printf("[+] CSV parsed successfully\n");
    
    /* Start fuzzing */
    fuzz(s);
    
    /* Cleanup */
    struct csv_row *row = csv_corpus.rows;
    while (row) {
        struct csv_row *next_row = row->next;
        
        struct csv_value *val = row->vals;
        while (val) {
            struct csv_value *next_val = val->next;
            if (val->val) free(val->val);
            if (val->orig_val) free(val->orig_val);
            free(val);
            val = next_val;
        }
        
        if (row->row_text) free(row->row_text);
        if (row->orig_row_text) free(row->orig_row_text);
        free(row);
        row = next_row;
    }
}

