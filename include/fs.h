#ifndef FS_H
#define FS_H

#include "types.h"

/* Timeout status code */
#define TIMEOUT_STATUS 0x7FFFFFFF

/* Initialize fork server */
void fs_init(struct state *s);

/* Run testcase using fork server */
int fs_run(const char *input_file);

/* Receive feedback from fork server (caller must write CMD_RUN, payload_len, payload first) */
int deploy(void);

/* Cleanup fork server */
void fs_cleanup(void);

/* Get file descriptors for fork server communication */
int fs_get_cmd_fd(void);
int fs_get_info_fd(void);

#endif /* FS_H */
