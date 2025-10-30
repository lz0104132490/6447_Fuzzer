#ifndef FS_H
#define FS_H

#include "types.h"

/* Timeout status code */
#define TIMEOUT_STATUS 0x7FFFFFFF

/* Initialize fork server */
void fs_init(struct state *s);

/* Run testcase using fork server */
int fs_run(const char *input_file);

/* Execute target with current memfd payload and return exit status */
int deploy(void);

/* Cleanup fork server */
void fs_cleanup(void);

/* Get file descriptors for fork server communication */
int fs_get_cmd_fd(void);
int fs_get_info_fd(void);

/* Check if fork server is enabled */
bool fs_is_enabled(void);

#endif /* FS_H */
