#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include "fs.h"
#include "util.h"

static const char *bin_path = NULL;

void fs_init(struct state *s) {
    bin_path = s->binary;
    printf("[+] Fuzzer initialized (fork-based, memfd)\n");
}

int fs_run(const char *memfd_path) {
    pid_t pid = xfork();
    
    if (pid == 0) {
        /* Child: execute target with memfd input */
        int fd = open(memfd_path, O_RDONLY);
        if (fd >= 0) {
            dup2(fd, STDIN_FILENO);
            close(fd);
        }
        
        /* Redirect stdout/stderr to /dev/null for isolation */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        
        /* Execute target with clean environment */
        char *argv[] = { (char *)bin_path, NULL };
        char *envp[] = { NULL };
        execve(bin_path, argv, envp);
        _exit(127);
    }
    
    /* Parent: wait for child */
    int wstatus;
    waitpid(pid, &wstatus, 0);
    return wstatus;
}

void fs_cleanup(void) {
    /* No cleanup needed for fork-based approach */
}
