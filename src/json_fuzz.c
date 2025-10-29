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

#include "json_fuzz.h"
#include "mutate.h"
#include "util.h"
#include "save_result.h"
#include "fs.h"
#include "safe_wrapper.h"
#include "../libs/json_parser/CJSON.h"

static struct state *json_state = NULL;

/* JSON-aware mutation: parse, tweak a random element, serialize back */
static struct mutation json_mutate(const char *data, size_t sz) {
    struct mutation m = {0};
    if (!data || sz == 0) {
        return m;
    }

    /* Parse with explicit length to allow embedded NULs safely */
    cJSON *root = cJSON_ParseWithLength((const char *)data, sz);
    if (root == NULL) {
        return m;
    }

    /* If object/array, try mutating a child; else wrap into object */
    cJSON *target = root;
    if (cJSON_IsObject(root) || cJSON_IsArray(root)) {
        if (root->child) {
            /* Walk to a random child depth 1 */
            int count = 0;
            for (cJSON *e = root->child; e; e = e->next) count++;
            if (count > 0) {
                int idx = rand_range(0, count - 1);
                cJSON *e = root->child;
                while (idx-- && e) e = e->next;
                if (e) target = e;
            }
        }
    }

    /* Apply a small mutation based on type */
    if (cJSON_IsNumber(target)) {
        double v = cJSON_GetNumberValue(target);
        int delta = rand_range(-5, 5);
        cJSON_SetNumberValue(target, v + (double)delta);
    } else if (cJSON_IsString(target)) {
        char *s = cJSON_GetStringValue(target);
        if (s && s[0] != '\0') {
            size_t len = strlen(s);
            size_t pos = rand_range(0, (int)len - 1);
            s[pos] ^= 0x01; /* minimal perturbation */
            cJSON_SetValuestring(target, s);
        } else if (target->type & cJSON_String) {
            cJSON_SetValuestring(target, "");
        }
    } else if (cJSON_IsBool(target)) {
        cJSON_SetBoolValue(target, !cJSON_IsTrue(target));
    } else if (cJSON_IsObject(root)) {
        /* Add a small random field */
        cJSON *val = cJSON_CreateNumber(rand_range(-10, 10));
        cJSON_AddItemToObject(root, "_f", val);
    } else if (cJSON_IsArray(root)) {
        cJSON *val = cJSON_CreateString("x");
        cJSON_AddItemToArray(root, val);
    } else {
        /* Fallback: wrap in object */
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddItemToObject(obj, "value", cJSON_Duplicate(root, 1));
        cJSON_Delete(root);
        root = obj;
    }

    char *printed = cJSON_PrintUnformatted(root);
    if (printed) {
        m.data = printed; /* allocated via cJSON_malloc/malloc */
        m.size = strlen(printed);
        m.success = true;
    }

    cJSON_Delete(root);
    return m;
}

/* JSON parsing/validation using cJSON */
static bool json_parse(const char *data, size_t sz) {
    if (!data || sz == 0) {
        return false;
    }
    const char *endptr = NULL;
    cJSON *root = cJSON_ParseWithLengthOpts((const char *)data, sz, &endptr, 0);
    if (!root) {
        return false;
    }
    cJSON_Delete(root);
    return true;
}

static void fuzz_loop(struct state *s) {
    /* s->mem contains the original valid input (read-only reference) */
    /* We'll mutate copies and write to s->memfd to feed the target */
    
    size_t input_sz = (size_t)s->stat.st_size;
    const char *original_input = (const char *)s->mem;
    
    /* Start with a copy of the original input for mutation */
    char *current = xmalloc(input_sz);
    memcpy(current, original_input, input_sz);
    size_t current_sz = input_sz;

    /* Initialize timeout tracking */
    struct timeout_tracker timeout;
    timeout_init(&timeout, s->timeout);

    for (int i = 0; i < s->max_iters; i++) {
        /* Check if timeout has been reached */
        if (timeout_check(&timeout)) {
            printf("[*] Fuzzing timeout (%d seconds) reached after %d iterations\n", 
                   timeout.timeout_seconds, i);
            break;
        }
        struct mutation mut = {0};
        
        /* Use JSON-aware mutation part of the time; otherwise generic engine */
        if ((rand_next() % 3) == 0) {
            mut = json_mutate(current, current_sz);
            if (!mut.success) {
                enum mut_type mtype = pick_mut("json");
                mut = mutate(current, current_sz, mtype);
            }
        } else {
            enum mut_type mtype = pick_mut("json");
            mut = mutate(current, current_sz, mtype);
        }
        
        if (!mut.success) {
            continue;
        }

        /* Write mutated payload to memfd (this feeds the target binary) */
        if (ftruncate(s->memfd, 0) < 0) {
            perror("ftruncate memfd");
            continue;
        }
        
        /* Reset memfd position before writing */
        if (lseek(s->memfd, 0, SEEK_SET) < 0) {
            perror("lseek memfd");
            continue;
        }
        
        ssize_t n = write(s->memfd, mut.data, mut.size);
        if (n < 0 || (size_t)n != mut.size) {
            perror("write memfd");
            continue;
        }
        
        /* Send CMD_RUN command to fork server */
        int cmd_fd = fs_get_cmd_fd();
        char cmd = CMD_RUN;
        xwrite(cmd_fd, &cmd, sizeof(cmd));
        
        /* Receive feedback from fork server */
        int wstatus = deploy();

        if (WIFSIGNALED(wstatus) && WTERMSIG(wstatus) == SIGSEGV) {
            save_bad(s->binary, mut.data, mut.size, i);
        }

        /* Update current for next iteration */
        free(current);
        current = mut.data;
        current_sz = mut.size;
        mut.data = NULL;
    }

    if (current) {
        free(current);
    }
}

void fuzz_handle_json(struct state *s) {
    json_state = s;

    /* Validate original input is valid JSON */
    size_t input_sz = (size_t)s->stat.st_size;
    const char *original_input = (const char *)s->mem;

    if (!json_parse(original_input, input_sz)) {
        fprintf(stderr, "[!] Invalid JSON in input file\n");
        return;
    }

    /* Start fuzzing: original input in s->mem, mutated data written to s->memfd */
    fuzz_loop(s);
}

