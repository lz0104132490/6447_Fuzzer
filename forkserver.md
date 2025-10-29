Reviewing the fork server implementation and summarizing:


[5 tools called]

## Conclusion: Fork Server Implementation

### Overview
Uses a fork server (similar to AFL) to speed up testcase execution. It reduces overhead by loading the target binary once and reusing it via forking.

---

### Architecture

#### Components:

1. Shared library (`shared.so`):
   - Built as a shared library with a constructor function
   - Injected into target via `LD_PRELOAD`
   - Contains the fork server loop

2. Communication channels:
   - File descriptors `198` (CMD_FD): fuzzer → fork server
   - File descriptors `199` (INFO_FD): fork server → fuzzer
   - Uses pipes created during initialization

3. Two deployment modes:
   - Fork server mode (preferred): persistent server process
   - Boring deploy (fallback): `fork()` + `execve()` per testcase

---

### How it works

#### Initialization (`fs_init()`):
```30:56:fuzz/src/fs.c
void
fs_init(struct state *s)
{
	int cmd_pipe[2] = {0}; /* Fuzzer reads this pipe */
	int info_pipe[2] = {0}; /* Fuzzer writes this pipe */

	/* saved for later use */
	system_state = s;

	spipe(cmd_pipe);
	spipe(info_pipe);

	pid_t pid = sfork();

	switch (pid) {
	case 0: /* child */
		child_pipes_init(cmd_pipe, info_pipe);
		set_target_output();
		spawn_target(s);

	default: /* parent */
		parent_pipes_init(cmd_pipe, info_pipe);
		if (fs_test() < 0)
			deploy_hook = &boring_deploy;
		break;
	}
}
```

- Creates pipe pairs for communication
- Forks to create fork server process
- Child: spawns target with `LD_PRELOAD` to load shared library
- Parent: initializes pipes and tests fork server connection

#### Fork Server Loop (in shared library):
```17:48:fuzz/shared/shared.c
__attribute__ ((constructor))
void
shared(void)
{
	char cmd;
	int ret;

	while (1) {

		ret = read(CMD_FD, &cmd, sizeof(cmd));
		assert(ret == sizeof(cmd));

		switch (cmd) {
		case 'R': /* run */
			if (run() == 0)
				return; /* Child proc returns */
			break;

		case 'Q': /* quit */
			exit(0);

		case 'T': /* test */
			run_test();
			break;

		default:
			fprintf(stderr, "Unkown command: `%c` (%#hhx)", cmd, cmd);
			exit(1);
		}

	}
}
```

Runs as a constructor function before `main()`, implementing a command loop:
- `'R'`: Fork and run testcase
- `'Q'`: Quit
- `'T'`: Test connection

#### Per-Testcase Execution (`run()`):
```65:89:fuzz/shared/shared.c
static
int
run(void)
{
	int ret, wstatus;

	/* Reset stdin */
	ret = lseek(0, 0, SEEK_SET);
	assert(ret >= 0);

	/* put the "fork" in "fork server" */
	ret = fork();
	assert(ret >= 0);

	if (ret == 0)
		return 0; /* child */

	ret = waitpid(ret, &wstatus, 0);
	assert(ret >= 0);

	ret = write(INFO_FD, &wstatus, sizeof(wstatus));
	assert(ret == sizeof(wstatus));

	return 1;
}
```

For each testcase:
1. Resets stdin position (`lseek(0, 0, SEEK_SET)`)
2. Forks (child continues execution; parent waits)
3. Parent waits and sends exit status back to fuzzer

---

### Performance benefits

- ~2x speedup (per comments)
- Avoids `execve()` overhead (linker, symbol resolution, library loading)
- Uses `LD_BIND_NOW` to resolve symbols once upfront
- Binary loaded once and reused via forking

---

### Design features

1. Architecture detection:
```203:244:fuzz/src/fs.c
/* Where the child process starts, will start the target process */
NORETURN
static
void
spawn_target(struct state *s)
{
	unsigned char elf_class = get_elf_class(s);

	char *const argv[] = {
		(char *) s->binary,
		NULL
	};

	const char *new_env[] = {0};

	if (elf_class == ELFCLASS64) {
		/* Load our custom 64bit library */
		new_env[0] = "LD_PRELOAD=./shared.so";
	} else {
		panic("Only 64-bit binaries are supported");
	}

	/* Solve all symbols (i.e. the GOT) before loading fork server */
	new_env[1] = "LD_BIND_NOW=1";

	/* Overwrite standard input with our input file */
	int fd = sopen(s->payload_fname, O_RDONLY);
	sdup2(fd, 0);
	sclose(fd);

	sexecve(
		s->binary,
		argv,
		(void *) arr_join(
			(void *) s->envp,
			(void *) new_env
		) /* Data types are hard :( */
	);

}
```
- Detects 64-bit binaries via ELF header
- Loads shared library for 64-bit targets only

2. Fallback mechanism:
```148:171:fuzz/src/fs.c
static
int
fs_test (void)
{
	ssize_t ret;
	char buf[4] = {0};

	ret = write(CMD_FD, CMD_TEST, sizeof(CMD_TEST)-1);
	if (ret < 0)
		return -1;

	ret = write(CMD_FD, "SYN", 3);
	if (ret < 0)
		return -1;

	ret = read(INFO_FD, &buf, 3);
	if (ret < 0)
		return -1;

	if (strcmp(buf, "ACK") != 0)
		return -1;

	return 0;
}
```
- Tests fork server with SYN/ACK
- Falls back to `boring_deploy()` if fork server fails (e.g., static binaries)
- Ensures compatibility with static binaries

3. Clean process isolation:
- Each testcase runs in a fresh forked process
- Process memory resets automatically
- Only stdin position needs manual reset

---

### Limitations

- Requires dynamic linking: doesn't work with statically linked binaries (falls back)
- Dependent on `LD_PRELOAD` availability
- Slightly more complex than simple `fork()` + `execve()`

---

### Summary

The fork server:
- Loads the target binary once and reuses it via forking
- Communicates via pipes (FDs 198/199)
- Achieves ~2x speedup by avoiding `execve()` overhead
- Falls back gracefully when fork server isn't available
- Supports 64-bit binaries only
- Provides clean process isolation per testcase

Matches the pattern used by AFL and similar fuzzers, providing a significant performance improvement for fuzzing dynamic binaries.