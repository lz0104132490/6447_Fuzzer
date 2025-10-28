# Fuzzer

A mutation-based fuzzer with fork server optimization and in-memory execution.

## Architecture

```
include/        - Header files (public interfaces)
src/            - Implementation files
  ├── main.c    - Main fuzzer driver
  ├── fs.c      - Fork server management
  ├── mutate.c  - Mutation strategies
  ├── json_fuzz.c - JSON-specific fuzzing
  └── util.c    - Utility functions
shared/         - Fork server shared library
  └── shared.c  - Injected via LD_PRELOAD
```

## Features

- **In-Memory Execution**: Uses memfd (no disk I/O) - Linux only
- **File Type Detection**: libmagic auto-detects input type
- **Fork Server**: ~2x speedup by avoiding execve() overhead
- **Multiple Mutations**: Bit flip, byte operations, sequence manipulation, number mutation
- **Crash Detection**: Automatically saves crashing inputs to `bad_{progname}.txt`
- **Architecture Support**: Detects and handles 32-bit and 64-bit binaries

## Build

**Requirements**: libmagic-dev (Debian/Ubuntu) or file-devel (RHEL/Fedora)

```bash
sudo apt install libmagic-dev  # Debian/Ubuntu
make
```

This builds:
- `fuzzer` - Main fuzzer binary
- `shared64.so` - 64-bit fork server library
- `shared32.so` - 32-bit fork server library (optional: `make shared32`)

## Usage

```bash
./fuzzer -b <target_binary> -i <input.json> -n <iterations>
```

Options:
- `-b <binary>` - Target binary to fuzz (required)
- `-i <input>` - Input JSON file (required)
- `-n <count>` - Number of iterations (default: 1000)
- `-t <timeout>` - Timeout in seconds (default: 5)

## Example

```bash
# Create sample JSON
echo '{"name":"test","value":123}' > sample.json

# Fuzz a JSON parser
./fuzzer -b /path/to/json_parser -i sample.json -n 10000
```

## Output

Crashing inputs are saved to `bad_{progname}.txt` with iteration numbers.

## Mutation Strategies

1. **Bit Flip** - Flip random bits
2. **Byte Flip** - Flip entire bytes
3. **Byte Insert** - Insert random bytes
4. **Byte Delete** - Delete random bytes
5. **Sequence Repeat** - Repeat byte sequences
6. **Sequence Delete** - Delete byte sequences
7. **Number Mutate** - Mutate numeric values

## Implementation Details

### In-Memory Execution
- Uses `memfd_create()` to create anonymous file descriptors
- Mutated inputs passed via `/proc/self/fd/<n>` paths
- No disk I/O during fuzzing (only crash saves)
- Stateless - each run gets fresh memory

### Fork Server
- Loads target binary once and reuses via forking
- Communicates via pipes (FDs 198/199)
- Supports both 32-bit and 64-bit binaries
- Falls back to direct execution if fork server fails
- Provides clean process isolation per testcase

### File Type Detection
- Uses libmagic to detect MIME types
- Auto-selects appropriate mutation strategy
- Supports JSON, XML, CSV, plaintext, binary
