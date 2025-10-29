#ifndef MUTATE_H
#define MUTATE_H

#include "types.h"

/* Mutation strategies */
enum mut_type {
    MUT_BIT_FLIP,
    MUT_BYTE_FLIP,
    MUT_BYTE_INSERT,
    MUT_BYTE_DELETE,
    MUT_SEQ_REPEAT,
    MUT_SEQ_DELETE,
    MUT_NUM_MUTATE,
    MUT_MAX
};

/* Apply mutation to data */
struct mutation mutate(const char *data, size_t sz, enum mut_type type);

/* Select mutation based on file type */
enum mut_type pick_mut(const char *ftype);

/* Free mutation result */
void mutation_free(struct mutation *m);

#endif /* MUTATE_H */
