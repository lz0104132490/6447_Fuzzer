#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <string.h>
#include <assert.h>
#include <sys/syscall.h>

#define CMD_FD 198
#define INFO_FD 199
#define MEMFD_FD 200

static int run(void);
static void run_test(void);

__attribute__((constructor))
void shared(void) {
    char cmd;
    int ret;

    while (1) {
        ret = read(CMD_FD, &cmd, sizeof(cmd));
        assert(ret == sizeof(cmd));

        switch (cmd) {
        case 'R': /* Run */
            if (run() == 0)
                return; /* Child returns to main */
            break;

        case 'Q': /* Quit */
            exit(0);

        case 'T': /* Test */
            run_test();
            break;

        default:
            fprintf(stderr, "Unknown command: '%c' (%#hhx)\n", cmd, cmd);
            exit(1);
        }
    }
}
static int run(void) {
    int ret, wstatus;

    /* Use memfd passed from fuzzer (available at MEMFD_FD) */
    /* Fuzzer writes payload directly to memfd, we just need to redirect stdin */
    
    /* Reset memfd: truncate to 0 (payload size should already be written by fuzzer) */
    /* But we need to seek to beginning for reading */
    ret = lseek(MEMFD_FD, 0, SEEK_SET);
    assert(ret == 0);

    /* Replace stdin with memfd */
    ret = dup2(MEMFD_FD, STDIN_FILENO);
    assert(ret >= 0);

    /* Fork */
    pid_t pid = fork();
    assert(pid >= 0);

    if (pid == 0) {
        /* Child: return to target main() */
        return 0;
    }

    /* Parent: send child PID to fuzzer immediately for timeout tracking */
    ret = write(INFO_FD, &pid, sizeof(pid));
    assert(ret == sizeof(pid));

    /* Parent: wait for child */
    ret = waitpid(pid, &wstatus, 0);
    assert(ret >= 0);

    /* Reset parent stdin to /dev/null (don't close MEMFD_FD, reuse it) */
    int devnull = open("/dev/null", O_RDONLY);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        close(devnull);
    }

    /* Send status back to fuzzer */
    ret = write(INFO_FD, &wstatus, sizeof(wstatus));
    assert(ret == sizeof(wstatus));

    return 1;
}

static void run_test(void) {
    char buf[3] = {0};
    int ret;

    ret = read(CMD_FD, buf, 3);
    assert(ret == 3);

    ret = write(INFO_FD, "ACK", 3);
    assert(ret == 3);
}

