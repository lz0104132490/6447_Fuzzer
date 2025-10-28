#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>

#define CMD_FD 198
#define INFO_FD 199

static int run(void) {
    int ret, wstatus;

    /* Reset stdin */
    ret = lseek(0, 0, SEEK_SET);
    assert(ret >= 0);

    /* Fork */
    ret = fork();
    assert(ret >= 0);

    if (ret == 0)
        return 0; /* Child continues execution */

    /* Parent waits for child */
    ret = waitpid(ret, &wstatus, 0);
    assert(ret >= 0);

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
