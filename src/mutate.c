#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mutate.h"
#include "util.h"
#include "safe_wrapper.h"

/* Adaptive mutation engine state inspired by mutation_strategy.md
 * - Weighted selection by score × priority
 * - Scores learn: +2 on success, -1 on failure (clamped)
 * - Format-aware boosts: text/json favor numbers and sequences; binary favors bit/byte flips
 */

static double g_scores[MUT_MAX] = {
    [MUT_BIT_FLIP] = 6.0,
    [MUT_BYTE_FLIP] = 6.0,
    [MUT_BYTE_INSERT] = 5.0,
    [MUT_BYTE_DELETE] = 5.0,
    [MUT_SEQ_REPEAT] = 5.0,
    [MUT_SEQ_DELETE] = 5.0,
    [MUT_NUM_MUTATE] = 6.0,
};

static const double g_base_priority[MUT_MAX] = {
    [MUT_BIT_FLIP] = 1.0,
    [MUT_BYTE_FLIP] = 1.0,
    [MUT_BYTE_INSERT] = 0.9,
    [MUT_BYTE_DELETE] = 0.9,
    [MUT_SEQ_REPEAT] = 0.8,
    [MUT_SEQ_DELETE] = 0.8,
    [MUT_NUM_MUTATE] = 1.1,
};

static enum mut_type g_last_pick = MUT_BIT_FLIP;
static char g_last_ftype[16] = {0}; /* "json", "text", "application", etc. */

static int is_textish(const char *ftype) {
    if (!ftype) return 0;
    return strstr(ftype, "json") || strstr(ftype, "text") || strstr(ftype, "xml") || strstr(ftype, "csv");
}

static int is_structured_binary(const char *ftype) {
    if (!ftype) return 0;
    return strstr(ftype, "jpeg") || strstr(ftype, "jpg") || strstr(ftype, "elf") || strstr(ftype, "pdf");
}

static void adjust_scores(enum mut_type t, int success, const char *ftype) {
    if (t < 0 || t >= MUT_MAX) return;
    /* Learn by success/failure */
    if (success) {
        g_scores[t] += 2.0;
    } else {
        g_scores[t] -= 1.0;
    }
    if (g_scores[t] < 1.0) g_scores[t] = 1.0;
    if (g_scores[t] > 10.0) g_scores[t] = 10.0;

    /* Mild cross-adjustment by context to encourage exploration */
    int text = is_textish(ftype);
    if (text) {
        /* Favor structure/number ops in text */
        g_scores[MUT_NUM_MUTATE] += 0.2;
        g_scores[MUT_SEQ_REPEAT] += 0.1;
        g_scores[MUT_SEQ_DELETE] += 0.1;
    } else if (is_structured_binary(ftype)) {
        /* Balanced adjustments for structured binaries (JPEG/ELF/PDF) */
        g_scores[MUT_BYTE_INSERT] += 0.15;
        g_scores[MUT_BYTE_DELETE] += 0.15;
        g_scores[MUT_SEQ_REPEAT] += 0.1;
        g_scores[MUT_SEQ_DELETE] += 0.1;
        g_scores[MUT_BIT_FLIP] += 0.05;
        g_scores[MUT_BYTE_FLIP] += 0.05;
    } else {
        /* Generic fallback */
        g_scores[MUT_BYTE_INSERT] += 0.1;
        g_scores[MUT_BYTE_DELETE] += 0.1;
    }

    /* Clamp all */
    for (int i = 0; i < MUT_MAX; i++) {
        if (g_scores[i] < 1.0) g_scores[i] = 1.0;
        if (g_scores[i] > 10.0) g_scores[i] = 10.0;
    }
}

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
    struct mutation out = {0};
    switch (type) {
    case MUT_BIT_FLIP:
        out = bit_flip(data, sz);
        break;
    case MUT_BYTE_FLIP:
        out = byte_flip(data, sz);
        break;
    case MUT_BYTE_INSERT:
        out = byte_insert(data, sz);
        break;
    case MUT_BYTE_DELETE:
        out = byte_delete(data, sz);
        break;
    case MUT_SEQ_REPEAT:
        out = seq_repeat(data, sz);
        break;
    case MUT_SEQ_DELETE:
        out = seq_delete(data, sz);
        break;
    case MUT_NUM_MUTATE:
        out = num_mutate(data, sz);
        break;
    default:
        out = (struct mutation){0};
        break;
    }

    /* Learning update based on result and last context */
    adjust_scores(type, out.success ? 1 : 0, g_last_ftype[0] ? g_last_ftype : NULL);
    return out;
}

enum mut_type pick_mut(const char *ftype) {
    /* Cache context */
    if (ftype) {
        size_t n = strlen(ftype);
        if (n >= sizeof(g_last_ftype)) n = sizeof(g_last_ftype) - 1;
        memcpy(g_last_ftype, ftype, n);
        g_last_ftype[n] = '\0';
    } else {
        g_last_ftype[0] = '\0';
    }

    /* Format-aware priority multipliers */
    double fmt_boost[MUT_MAX];
    for (int i = 0; i < MUT_MAX; i++) fmt_boost[i] = 1.0;
    if (is_textish(ftype)) {
        fmt_boost[MUT_NUM_MUTATE] = 1.6;
        fmt_boost[MUT_SEQ_REPEAT] = 1.3;
        fmt_boost[MUT_SEQ_DELETE] = 1.2;
        fmt_boost[MUT_BYTE_INSERT] = 1.1;
        fmt_boost[MUT_BYTE_DELETE] = 1.0;
        fmt_boost[MUT_BIT_FLIP] = 0.8;
        fmt_boost[MUT_BYTE_FLIP] = 0.9;
    } else if (is_structured_binary(ftype)) {
        /* Balanced, avoid heavy reliance on raw bit/byte flips */
        fmt_boost[MUT_BIT_FLIP] = 1.05;
        fmt_boost[MUT_BYTE_FLIP] = 1.05;
        fmt_boost[MUT_BYTE_INSERT] = 1.2;
        fmt_boost[MUT_BYTE_DELETE] = 1.2;
        fmt_boost[MUT_SEQ_REPEAT] = 1.15;
        fmt_boost[MUT_SEQ_DELETE] = 1.1;
        fmt_boost[MUT_NUM_MUTATE] = 0.8;
    } else {
        /* Generic text-like defaults since we don't fuzz arbitrary binary */
        fmt_boost[MUT_BIT_FLIP] = 0.9;
        fmt_boost[MUT_BYTE_FLIP] = 0.95;
        fmt_boost[MUT_BYTE_INSERT] = 1.1;
        fmt_boost[MUT_BYTE_DELETE] = 1.1;
        fmt_boost[MUT_SEQ_REPEAT] = 1.1;
        fmt_boost[MUT_SEQ_DELETE] = 1.05;
        fmt_boost[MUT_NUM_MUTATE] = 1.0;
    }

    /* Compute roulette wheel weights */
    double weights[MUT_MAX];
    double total = 0.0;
    for (int i = 0; i < MUT_MAX; i++) {
        double w = g_scores[i] * g_base_priority[i] * fmt_boost[i];
        if (w < 0.1) w = 0.1;
        weights[i] = w;
        total += w;
    }

    /* Pick proportionally */
    int r = rand_range(0, 1000000);
    double target = (total * r) / 1000000.0;
    double acc = 0.0;
    enum mut_type pick = MUT_BIT_FLIP;
    for (int i = 0; i < MUT_MAX; i++) {
        acc += weights[i];
        if (acc >= target) { pick = (enum mut_type)i; break; }
    }

    g_last_pick = pick;
    return pick;
}

void mutation_free(struct mutation *m) {
    if (m && m->data) {
        free(m->data);
        m->data = NULL;
        m->size = 0;
        m->success = false;
    }
}
