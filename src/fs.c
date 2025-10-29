#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <errno.h>
#include <elf.h>
#include "types.h"
#include "fs.h"
#include "util.h"
#include "safe_wrapper.h"

/* Global state */
static struct state *system_state = NULL;
static int cmd_fd = -1;  /* Fuzzer writes commands here */
static int info_fd = -1; /* Fuzzer reads info here */
static pid_t fs_pid = -1;
static bool use_forkserver = true;

/* Timeout constants */
#define TIMEOUT_SEC 60

/* Forward declarations */
static void spawn_target(struct state *s, int payload_fd) __attribute__((noreturn));
static int backup_deploy(const char *input_path);
static int fs_test(void);
static void child_pipes_init(int cmd_pipe[2], int info_pipe[2], int memfd);
static void parent_pipes_init(int cmd_pipe[2], int info_pipe[2]);
static void set_target_output(void);
static ssize_t read_n(int fd, void *buf, size_t n);
static ssize_t write_n(int fd, const void *buf, size_t n);

/* Initialize pipes and memfd for child (fork server) */
static void child_pipes_init(int cmd_pipe[2], int info_pipe[2], int memfd) {
    /* Child reads commands from cmd_pipe[0] -> CMD_FD (198) */
    /* Child writes info to info_pipe[1] -> INFO_FD (199) */
    /* Child uses memfd -> MEMFD_FD (200) */
    close(cmd_pipe[1]);
    close(info_pipe[0]);
    
    if (dup2(cmd_pipe[0], CMD_FD) < 0) {
        perror("dup2 CMD_FD");
        exit(1);
    }
    if (dup2(info_pipe[1], INFO_FD) < 0) {
        perror("dup2 INFO_FD");
        exit(1);
    }
    if (dup2(memfd, MEMFD_FD) < 0) {
        perror("dup2 MEMFD_FD");
        exit(1);
    }
    
    close(cmd_pipe[0]);
    close(info_pipe[1]);
    close(memfd);  /* Close original, using dup'd one */
}

/* Initialize pipes for parent (fuzzer) */
static void parent_pipes_init(int cmd_pipe[2], int info_pipe[2]) {
    /* Parent writes commands to cmd_pipe[1] */
    /* Parent reads info from info_pipe[0] */
    close(cmd_pipe[0]);
    close(info_pipe[1]);
    
    cmd_fd = cmd_pipe[1];
    info_fd = info_pipe[0];
}

/* Redirect target output to /dev/null */
static void set_target_output(void) {
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        close(devnull);
    }
}

/* Spawn target with LD_PRELOAD */
static void spawn_target(struct state *s, int payload_fd) {
    unsigned char elf_class = get_elf_class(s->binary);
    
    char *const argv[] = {
        (char *)s->binary,
        NULL
    };
    
    /* Build environment with LD_PRELOAD */
    const char *new_env[3] = {NULL};
    
    if (elf_class == ELFCLASS64) {
        /* Load our custom 64bit library */
        new_env[0] = "LD_PRELOAD=./shared.so";
    } else {
        fprintf(stderr, "Only 64-bit binaries are supported\n");
        exit(1);
    }
    
    /* Solve all symbols (i.e. the GOT) before loading fork server */
    new_env[1] = "LD_BIND_NOW=1";
    new_env[2] = NULL;
    
    /* Overwrite standard input with payload fd */
    if (dup2(payload_fd, STDIN_FILENO) < 0) {
        perror("dup2 stdin");
        exit(1);
    }
    close(payload_fd);
    
    /* Merge environments */
    char **full_env = arr_join((char **)s->envp, (char **)new_env);
    
    execve(s->binary, argv, full_env);
    perror("execve");
    exit(1);
}

/* Test fork server connection */
static int fs_test(void) {
    ssize_t ret;
    char buf[4] = {0};
    
    /* Send test command */
    char cmd = CMD_TEST;
    ret = write(cmd_fd, &cmd, sizeof(cmd));
    if (ret != sizeof(cmd))
        return -1;
    
    /* Read ACK */
    ret = read(info_fd, buf, 3);
    if (ret != 3)
        return -1;
    
    if (strcmp(buf, "ACK") != 0)
        return -1;
    
    return 0;
}

/* Fallback: backup deploy (fork + execve) */
static int backup_deploy(const char *input_path) {
    pid_t pid = xfork();
    
    if (pid == 0) {
        /* Child: execute target with input */
        int fd = open(input_path, O_RDONLY);
        if (fd >= 0) {
            dup2(fd, STDIN_FILENO);
            close(fd);
        }
        
        /* Redirect stdout/stderr to /dev/null */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        
        /* Execute target */
        char *argv[] = { (char *)system_state->binary, NULL };
        char *envp[] = { NULL };
        execve(system_state->binary, argv, envp);
        _exit(127);
    }
    
    /* Parent: wait for child */
    int wstatus;
    waitpid(pid, &wstatus, 0);
    return wstatus;
}

/* Initialize fork server */
void fs_init(struct state *s) {
    int cmd_pipe[2] = {0};
    int info_pipe[2] = {0};
    
    /* Save state for later use */
    system_state = s;
    
    /* Create persistent memfd for payload communication */
    s->memfd = memfd_create("fuzz_payload", 0);
    if (s->memfd < 0) {
        perror("memfd_create");
        exit(1);
    }
    
    /* Create pipes */
    if (pipe(cmd_pipe) < 0) {
        perror("pipe cmd");
        exit(1);
    }
    if (pipe(info_pipe) < 0) {
        perror("pipe info");
        exit(1);
    }
    
    /* Fork to create fork server process */
    pid_t pid = xfork();
    
    if (pid == 0) {
        /* Child: setup pipes, memfd, and spawn target */
        child_pipes_init(cmd_pipe, info_pipe, s->memfd);
        set_target_output();
        
        /* Open initial input file for stdin */
        int input_fd = open(s->input_file, O_RDONLY);
        if (input_fd < 0) {
            perror("open input_file");
            exit(1);
        }
        
        spawn_target(s, input_fd);
        /* Never returns */
    }
    
    /* Parent: setup pipes and test fork server */
    fs_pid = pid;
    parent_pipes_init(cmd_pipe, info_pipe);
    
    /* Test fork server connection */
    if (fs_test() < 0) {
        fprintf(stderr, "[!] Fork server test failed, using fallback mode\n");
        use_forkserver = false;
        /* Kill the fork server process */
        kill(fs_pid, SIGKILL);
        waitpid(fs_pid, NULL, 0);
    } else {
        printf("[+] Fork server initialized successfully\n");
    }
}

/* Receive feedback from fork server after it has been told to run */
/* Caller must write CMD_RUN, payload_len, and payload before calling this */
int deploy(void)
{
	int wstatus;
	pid_t pid;

	/* Read PID and status from fork server */
	xread(info_fd, &pid, sizeof(pid));
	xread(info_fd, &wstatus, sizeof(wstatus));

	return wstatus;
}
/* Get file descriptors for fork server communication */
int fs_get_cmd_fd(void) {
    return cmd_fd;
}

int fs_get_info_fd(void) {
    return info_fd;
}

/* Cleanup fork server */
void fs_cleanup(void) {
    if (use_forkserver && cmd_fd >= 0) {
        /* Send QUIT command */
        char cmd = CMD_QUIT;
        write(cmd_fd, &cmd, sizeof(cmd));
        
        /* Wait for fork server to exit */
        if (fs_pid > 0) {
            waitpid(fs_pid, NULL, 0);
        }
        
        close(cmd_fd);
        close(info_fd);
    }
    
    /* Close memfd */
    if (system_state && system_state->memfd >= 0) {
        close(system_state->memfd);
        system_state->memfd = -1;
    }
}
