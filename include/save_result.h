#ifndef SAVE_RESULT_H
#define SAVE_RESULT_H

#include <stdio.h>
#include <stddef.h>

void save_bad(const char *prog, const char *data, size_t sz, int iter, int signal);
void save_hang(const char *prog, const char *data, size_t sz, int iter);

#endif /* SAVE_RESULT_H */
