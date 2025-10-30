#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <math.h>

#include "json_fuzz.h"
#include "mutate.h"
#include "util.h"
#include "save_result.h"
#include "fs.h"
#include "safe_wrapper.h"
#include "../libs/json_parser/CJSON.h"

/* Helper functions */
static void fuzz(struct state *s);
static void fuzz_loop(struct state *s);

/* Single-run fuzzing strategies (deterministic) */
static void fuzz_buffer_overflow(struct state *s);
static void fuzz_bad_nums(struct state *s);
static void fuzz_fmt_str(struct state *s);
static void fuzz_empty(struct state *s);
static void fuzz_extra_entries(struct state *s);
static void fuzz_extra_objects(struct state *s);
static void fuzz_append_objects(struct state *s);

/* Repeating fuzzing strategies (randomized) */
static void fuzz_bit_shift(struct state *s);
static void fuzz_mutations(struct state *s);

/* Utility functions */
static size_t json_dump(struct state *s, cJSON *root);
static void traverse_json(cJSON *root, void (*entry_handler)(struct state *, cJSON *), 
                          void (*value_handler)(struct state *, cJSON *), struct state *s);

/* Array of single-run strategies (deterministic, run once) */
static void (*fuzz_payloads_single[])(struct state *) = {
    fuzz_extra_objects,
    fuzz_buffer_overflow,
    fuzz_bad_nums,
    fuzz_fmt_str,
    fuzz_empty,
    fuzz_extra_entries,
    fuzz_append_objects,
};
#define SINGLE_PAYLOADS_COUNT (sizeof(fuzz_payloads_single) / sizeof(fuzz_payloads_single[0]))

/* Array of repeating strategies (randomized, run in infinite loop) */
static void (*fuzz_payloads_repeat[])(struct state *) = {
    fuzz_bit_shift,
    fuzz_mutations,
};
#define REPEAT_PAYLOADS_COUNT (sizeof(fuzz_payloads_repeat) / sizeof(fuzz_payloads_repeat[0]))

/* Global JSON corpus */
static cJSON *json_corpus = NULL;

/* Global iteration counter for crash reporting */
static int g_iteration = 0;

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

/* Format strings for testing */
static const char *fmt_strings[] = {
    "%1$s", "%2$s", "%3$s", "%4$s", "%5$s", 
    "%6$s", "%7$s", "%8$s", "%9$s",
    "%s%s%s%s%s", "%n%n%n%n%n"
};
#define FMT_STRINGS_COUNT (sizeof(fmt_strings) / sizeof(fmt_strings[0]))

/* Boundary values for integer testing */
static const int64_t bad_nums[] = {
    -128, -1, 0, 1, 16, 32, 64, 100, 127,
    -32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767,
    -2147483648LL, -100663046, -32769, 32768, 65535, 65536,
    100663045, 2147483647, 1337
};
#define BAD_NUMS_COUNT (sizeof(bad_nums) / sizeof(bad_nums[0]))

/* Boundary values for floating point testing */
static const double bad_nums_floats[] = {
    0.0, -0.0, 0.33333333333333, M_PI, 0.1, 0.1000000,
    -1.0, 1.0, INFINITY, -INFINITY, NAN
};
#define BAD_NUMS_FLOATS_COUNT (sizeof(bad_nums_floats) / sizeof(bad_nums_floats[0]))

/* Traverse JSON tree and call handlers for object entries and all values */
static void traverse_json(cJSON *root, 
                          void (*entry_handler)(struct state *, cJSON *), 
                          void (*value_handler)(struct state *, cJSON *),
                          struct state *s) {
    if (!root) return;
    
    /* Call value handler on current node */
    if (value_handler) {
        value_handler(s, root);
    }
    
    /* Recurse into objects and arrays */
    if (cJSON_IsObject(root)) {
        cJSON *child = root->child;
        while (child) {
            /* Call entry handler for object entries */
            if (entry_handler) {
                entry_handler(s, child);
            }
            /* Recursively traverse child */
            traverse_json(child, entry_handler, value_handler, s);
            child = child->next;
        }
    } else if (cJSON_IsArray(root)) {
        cJSON *child = root->child;
        while (child) {
            /* Recursively traverse array elements */
            traverse_json(child, entry_handler, value_handler, s);
            child = child->next;
        }
    }
}

/* Dump JSON to memfd and return the size written */
static size_t json_dump(struct state *s, cJSON *root) {
    char *json_str = cJSON_PrintUnformatted(root);
    if (!json_str) {
        fprintf(stderr, "[!] Failed to serialize JSON\n");
        return 0;
    }
    
    size_t len = strlen(json_str);
    
    /* Truncate and reset memfd */
    if (ftruncate(s->memfd, 0) < 0) {
        perror("ftruncate");
        free(json_str);
        return 0;
    }
    if (lseek(s->memfd, 0, SEEK_SET) < 0) {
        perror("lseek");
        free(json_str);
        return 0;
    }
    
    /* Write to memfd */
    ssize_t n = write(s->memfd, json_str, len);
    if (n < 0 || (size_t)n != len) {
        perror("write memfd");
        free(json_str);
        return 0;
    }
    
    free(json_str);
    return len;
}

/* ============================================================================
 * FUZZING STRATEGIES - SINGLE RUN (Deterministic)
 * ============================================================================ */

/* Test buffer overflow by replacing keys with large strings */
static void fuzz_buffer_overflow(struct state *s) {
    void handler(struct state *st, cJSON *item) {
        /* Save original key */
        char *old_key = item->string;
        
        /* Replace with large buffer */
        item->string = (char *)BIG;
        json_dump(st, json_corpus);
        int wstatus = deploy();
        check_crash(st, wstatus, g_iteration++);
        
        /* Restore original */
        item->string = old_key;
    }
    
    traverse_json(json_corpus, handler, NULL, s);
}

/* Test with boundary integer and float values */
static void fuzz_bad_nums(struct state *s) {
    void handler(struct state *st, cJSON *item) {
        if (cJSON_IsNumber(item)) {
            double old_value = item->valuedouble;
            
            /* Try all bad integer values */
            for (size_t i = 0; i < BAD_NUMS_COUNT; i++) {
                item->valuedouble = (double)bad_nums[i];
                item->valueint = (int)bad_nums[i];
                json_dump(st, json_corpus);
                int wstatus = deploy();
                check_crash(st, wstatus, g_iteration++);
            }
            
            /* Try all bad float values */
            for (size_t i = 0; i < BAD_NUMS_FLOATS_COUNT; i++) {
                item->valuedouble = bad_nums_floats[i];
                item->valueint = (int)bad_nums_floats[i];
                json_dump(st, json_corpus);
                int wstatus = deploy();
                check_crash(st, wstatus, g_iteration++);
            }
            
            /* Restore original */
            item->valuedouble = old_value;
            item->valueint = (int)old_value;
        }
    }
    
    traverse_json(json_corpus, NULL, handler, s);
}

/* Test with format strings in keys and string values */
static void fuzz_fmt_str(struct state *s) {
    /* Handler for string values */
    void value_handler(struct state *st, cJSON *item) {
        if (cJSON_IsString(item)) {
            char *old_value = item->valuestring;
            
            for (size_t i = 0; i < FMT_STRINGS_COUNT; i++) {
                item->valuestring = (char *)fmt_strings[i];
                json_dump(st, json_corpus);
                int wstatus = deploy();
                check_crash(st, wstatus, g_iteration++);
            }
            
            item->valuestring = old_value;
        }
    }
    
    /* Handler for object entries (keys) */
    void entry_handler(struct state *st, cJSON *item) {
        char *old_key = item->string;
        
        for (size_t i = 0; i < FMT_STRINGS_COUNT; i++) {
            item->string = (char *)fmt_strings[i];
            json_dump(st, json_corpus);
            int wstatus = deploy();
            check_crash(st, wstatus, g_iteration++);
        }
        
        item->string = old_key;
    }
    
    traverse_json(json_corpus, entry_handler, value_handler, s);
}

/* Test with empty/null keys and values */
static void fuzz_empty(struct state *s) {
    void handler(struct state *st, cJSON *item) {
        char *old_key = item->string;
        
        /* Empty key name */
        item->string = "";
        json_dump(st, json_corpus);
        int wstatus = deploy();
        check_crash(st, wstatus, g_iteration++);
        
        /* Restore */
        item->string = old_key;
    }
    
    traverse_json(json_corpus, handler, NULL, s);
}

/* Add many extra entries to objects */
static void fuzz_extra_entries(struct state *s) {
    if (!cJSON_IsObject(json_corpus)) return;
    
    /* Clone original to restore later */
    cJSON *original = cJSON_Duplicate(json_corpus, 1);
    
    /* Add 100 extra entries */
    for (int i = 0; i < 100; i++) {
        cJSON_AddStringToObject(json_corpus, "extra", "extra_value");
    }
    
    json_dump(s, json_corpus);
    int wstatus = deploy();
    check_crash(s, wstatus, g_iteration++);
    
    /* Restore original */
    cJSON_Delete(json_corpus);
    json_corpus = original;
}

/* Wrap JSON in array with many copies */
static void fuzz_extra_objects(struct state *s) {
    char *json_str = cJSON_PrintUnformatted(json_corpus);
    if (!json_str) return;
    
    /* Calculate size needed: "[" + (json + ", ") * 100 + json + "]" */
    size_t json_len = strlen(json_str);
    size_t total_len = 1 + (json_len + 2) * 100 + json_len + 1;
    char *final = xmalloc(total_len + 1);
    
    strcpy(final, "[");
    for (int i = 0; i < 100; i++) {
        strcat(final, json_str);
        strcat(final, ", ");
    }
    strcat(final, json_str);
    strcat(final, "]");
    
    /* Write to memfd */
    ftruncate(s->memfd, 0);
    lseek(s->memfd, 0, SEEK_SET);
    write(s->memfd, final, strlen(final));
    
    int wstatus = deploy();
    check_crash(s, wstatus, g_iteration++);
    
    free(json_str);
    free(final);
}

/* Append many copies of JSON (invalid JSON) */
static void fuzz_append_objects(struct state *s) {
    char *json_str = cJSON_PrintUnformatted(json_corpus);
    if (!json_str) return;
    
    size_t json_len = strlen(json_str);
    size_t total_len = (json_len + 1) * 101;  /* 100 copies + newlines + original */
    char *final = xmalloc(total_len + 1);
    
    final[0] = '\0';
    for (int i = 0; i < 100; i++) {
        strcat(final, json_str);
        strcat(final, "\n");
    }
    strcat(final, json_str);
    
    /* Write to memfd */
    ftruncate(s->memfd, 0);
    lseek(s->memfd, 0, SEEK_SET);
    write(s->memfd, final, strlen(final));
    
    int wstatus = deploy();
    check_crash(s, wstatus, g_iteration++);
    
    free(json_str);
    free(final);
}

/* ============================================================================
 * FUZZING STRATEGIES - REPEATING (Randomized)
 * ============================================================================ */

/* Bit shift bytes near JSON structure characters */
static void fuzz_bit_shift(struct state *s) {
    size_t len = json_dump(s, json_corpus);
    if (len == 0) return;
    
    /* Read back the serialized JSON */
    char *buf = xmalloc(len);
    lseek(s->memfd, 0, SEEK_SET);
    if (read(s->memfd, buf, len) != (ssize_t)len) {
        free(buf);
        return;
    }
    
    /* Find structure characters and fuzz nearby bytes */
    for (size_t i = 0; i < len; i++) {
        char ch = buf[i];
        
        /* Check if this is a JSON structure character */
        if (ch == '\\' || ch == '\n' || ch == '"' || ch == ',' || 
            ch == '/' || ch == ':' || ch == '[' || ch == ']' ||
            ch == '{' || ch == '}') {
            
            /* Fuzz some neighboring bytes */
            size_t offset = i + rand_range(1, 10);
            if (offset >= len) offset = len - 1;
            
            /* Bit shift */
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

/* Generic mutation strategies using mutate.c */
static void fuzz_mutations(struct state *s) {
    size_t len = json_dump(s, json_corpus);
    if (len == 0) return;
    
    /* Read current state */
    char *buf = xmalloc(len);
    lseek(s->memfd, 0, SEEK_SET);
    if (read(s->memfd, buf, len) != (ssize_t)len) {
        free(buf);
        return;
    }
    
    /* Apply random mutation */
    enum mut_type mtype = pick_mut("json");
    struct mutation mut = mutate(buf, len, mtype);
    
    if (mut.success && mut.data) {
        /* Write mutated data to memfd */
        ftruncate(s->memfd, 0);
        lseek(s->memfd, 0, SEEK_SET);
        write(s->memfd, mut.data, mut.size);
        
        int wstatus = deploy();
        check_crash(s, wstatus, g_iteration++);
        
        free(mut.data);
    }
    
    free(buf);
}

/* Main fuzzing orchestrator */
static void fuzz(struct state *s) {
    printf("[*] Starting JSON fuzzing...\n");
    
    /* Initialize timeout tracking */
    struct timeout_tracker timeout;
    timeout_init(&timeout, s->timeout);
    
    /* Run all deterministic strategies once */
    printf("[*] Running %zu deterministic strategies...\n", SINGLE_PAYLOADS_COUNT);
    for (size_t i = 0; i < SINGLE_PAYLOADS_COUNT; i++) {
        fuzz_payloads_single[i](s);
    }
    
    /* Run randomized strategies with iteration/timeout limits */
    printf("[*] Starting randomized fuzzing loop (max_iters=%d, timeout=%ds)...\n", 
           s->max_iters, s->timeout);
    
    for (int iteration = 0; iteration < s->max_iters; iteration++) {
        /* Check timeout */
        if (timeout_check(&timeout)) {
            printf("[*] Timeout reached after %d iterations\n", iteration);
            break;
        }
        
        /* Pick a random strategy */
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

/* Main entry point for JSON fuzzing */
void fuzz_handle_json(struct state *s) {
    printf("[*] Initializing JSON fuzzer...\n");
    
    /* Parse and validate original input once */
    size_t input_sz = (size_t)s->stat.st_size;
    const char *original_input = (const char *)s->mem;
    
    /* Parse JSON corpus once */
    json_corpus = cJSON_ParseWithLength(original_input, input_sz);
    if (json_corpus == NULL) {
        fprintf(stderr, "[!] Invalid JSON in input file\n");
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "[!] Parse error before: %s\n", error_ptr);
        }
        return;
    }
    
    printf("[+] JSON parsed successfully\n");
    printf("[*] Input size: %zu bytes\n", input_sz);
    
    /* Start fuzzing */
    fuzz(s);
    
    /* Cleanup (never reached in infinite loop, but good practice) */
    if (json_corpus) {
        cJSON_Delete(json_corpus);
        json_corpus = NULL;
    }
}

