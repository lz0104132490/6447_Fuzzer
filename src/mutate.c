#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mutate.h"
#include "util.h"

static struct mutation bit_flip(const char *data, size_t sz) {
    struct mutation m = {0};
    if (sz == 0) return m;

    m.data = xmalloc(sz);
    memcpy(m.data, data, sz);
    m.size = sz;

    /* Flip random bit */
    size_t pos = rand_range(0, sz - 1);
    int bit = rand_range(0, 7);
    m.data[pos] ^= (1 << bit);
    m.success = true;

    return m;
}

static struct mutation byte_flip(const char *data, size_t sz) {
    struct mutation m = {0};
    if (sz == 0) return m;

    m.data = xmalloc(sz);
    memcpy(m.data, data, sz);
    m.size = sz;

    /* Flip random byte */
    size_t pos = rand_range(0, sz - 1);
    m.data[pos] ^= 0xFF;
    m.success = true;

    return m;
}

static struct mutation byte_insert(const char *data, size_t sz) {
    struct mutation m = {0};

    m.size = sz + 1;
    m.data = xmalloc(m.size);

    size_t pos = rand_range(0, sz);
    char byte = rand_range(0, 255);

    memcpy(m.data, data, pos);
    m.data[pos] = byte;
    memcpy(m.data + pos + 1, data + pos, sz - pos);
    m.success = true;

    return m;
}

static struct mutation byte_delete(const char *data, size_t sz) {
    struct mutation m = {0};
    if (sz == 0) return m;

    m.size = sz - 1;
    m.data = xmalloc(m.size);

    size_t pos = rand_range(0, sz - 1);

    memcpy(m.data, data, pos);
    memcpy(m.data + pos, data + pos + 1, sz - pos - 1);
    m.success = true;

    return m;
}

static struct mutation seq_repeat(const char *data, size_t sz) {
    struct mutation m = {0};
    if (sz == 0) return m;

    size_t seq_len = rand_range(1, sz < 16 ? sz : 16);
    size_t pos = rand_range(0, sz - seq_len);
    int repeat = rand_range(2, 8);

    m.size = sz + seq_len * (repeat - 1);
    m.data = xmalloc(m.size);

    memcpy(m.data, data, pos);
    for (int i = 0; i < repeat; i++) {
        memcpy(m.data + pos + seq_len * i, data + pos, seq_len);
    }
    memcpy(m.data + pos + seq_len * repeat, data + pos + seq_len, 
           sz - pos - seq_len);
    m.success = true;

    return m;
}

static struct mutation seq_delete(const char *data, size_t sz) {
    struct mutation m = {0};
    if (sz == 0) return m;

    size_t seq_len = rand_range(1, sz < 16 ? sz : 16);
    if (seq_len > sz) seq_len = sz;
    size_t pos = rand_range(0, sz - seq_len);

    m.size = sz - seq_len;
    m.data = xmalloc(m.size);

    memcpy(m.data, data, pos);
    memcpy(m.data + pos, data + pos + seq_len, sz - pos - seq_len);
    m.success = true;

    return m;
}

static struct mutation num_mutate(const char *data, size_t sz) {
    struct mutation m = {0};
    if (sz < 4) return m;

    m.data = xmalloc(sz);
    memcpy(m.data, data, sz);
    m.size = sz;

    /* Find and mutate a number-like sequence */
    for (size_t i = 0; i < sz - 1; i++) {
        if (data[i] >= '0' && data[i] <= '9') {
            /* Found digit, mutate it */
            int choice = rand_range(0, 3);
            switch (choice) {
            case 0: /* Increment */
                if (m.data[i] < '9') m.data[i]++;
                else m.data[i] = '0';
                break;
            case 1: /* Decrement */
                if (m.data[i] > '0') m.data[i]--;
                else m.data[i] = '9';
                break;
            case 2: /* Replace with 0 */
                m.data[i] = '0';
                break;
            case 3: /* Replace with max */
                m.data[i] = '9';
                break;
            }
            m.success = true;
            break;
        }
    }

    return m;
}

struct mutation mutate(const char *data, size_t sz, enum mut_type type) {
    switch (type) {
    case MUT_BIT_FLIP:
        return bit_flip(data, sz);
    case MUT_BYTE_FLIP:
        return byte_flip(data, sz);
    case MUT_BYTE_INSERT:
        return byte_insert(data, sz);
    case MUT_BYTE_DELETE:
        return byte_delete(data, sz);
    case MUT_SEQ_REPEAT:
        return seq_repeat(data, sz);
    case MUT_SEQ_DELETE:
        return seq_delete(data, sz);
    case MUT_NUM_MUTATE:
        return num_mutate(data, sz);
    default:
        return (struct mutation){0};
    }
}

enum mut_type pick_mut(const char *ftype) {
    /* JSON/text files: prefer number and structural mutations */
    if (strstr(ftype, "json") || strstr(ftype, "text")) {
        int r = rand_range(0, 99);
        if (r < 30) return MUT_NUM_MUTATE;
        if (r < 50) return MUT_BYTE_INSERT;
        if (r < 70) return MUT_BYTE_DELETE;
        if (r < 85) return MUT_SEQ_REPEAT;
        return rand_range(0, MUT_MAX - 1);
    }
    
    /* Binary files: prefer bit/byte flips */
    if (strstr(ftype, "application")) {
        int r = rand_range(0, 99);
        if (r < 40) return MUT_BIT_FLIP;
        if (r < 70) return MUT_BYTE_FLIP;
        return rand_range(0, MUT_MAX - 1);
    }
    
    /* Default: random mutation */
    return rand_range(0, MUT_MAX - 1);
}

void mutation_free(struct mutation *m) {
    if (m && m->data) {
        free(m->data);
        m->data = NULL;
        m->size = 0;
        m->success = false;
    }
}
