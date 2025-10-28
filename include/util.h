#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <sys/types.h>

/* Memory allocation wrappers */
void *xmalloc(size_t sz);
void *xrealloc(void *ptr, size_t sz);
char *xstrdup(const char *s);

/* File I/O wrappers */
int xopen(const char *path, int flags);
ssize_t xread(int fd, void *buf, size_t cnt);
ssize_t xwrite(int fd, const void *buf, size_t cnt);
pid_t xfork(void);

/* File operations */
char *read_file(const char *path, size_t *sz);
void write_file(const char *path, const char *data, size_t sz);

/* Random number generation */
void rand_init(unsigned int seed);
unsigned int rand_next(void);
int rand_range(int min, int max);

/* Memory file descriptor operations */
int memfd_create_buf(const char *data, size_t sz);
char *memfd_path(int fd, char *buf, size_t len);

/* File type detection with libmagic */
const char *detect_ftype(const char *data, size_t sz);
void magic_cleanup(void);

#endif
