#ifndef SAFE_WRAPPER_H
#define SAFE_WRAPPER_H

#include <stddef.h>
#include <sys/types.h>

/* Memory allocation wrappers */
void *xmalloc(size_t size);
void *xrealloc(void *ptr, size_t size);
char *xstrdup(const char *s);

/* File I/O wrappers */
int xopen(const char *path, int flags);
ssize_t xread(int fd, void *buf, size_t count);
ssize_t xwrite(int fd, const void *buf, size_t count);
pid_t xfork(void);
char *read_file(const char *path, size_t *size);
void write_file(const char *path, const char *data, size_t size);

#endif /* SAFE_WRAPPER_H */