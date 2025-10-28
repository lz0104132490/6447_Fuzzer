#ifndef FS_H
#define FS_H

#include "types.h"

/* Initialize fork server */
void fs_init(struct state *s);

/* Run testcase using fork server */
int fs_run(const char *input_file);

/* Cleanup fork server */
void fs_cleanup(void);

#endif
