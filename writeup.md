# Fuzzer Design and Functionality

## Overview
This project implements a **black-box coverage-guided fuzzer** that automatically discovers memory corruption vulnerabilities in Linux binaries. Given a target binary and valid sample input, the fuzzer detects the input format, applies format-aware mutations, and executes the target repeatedly to trigger crashes, invalid memory writes, heap corruption, and other security flaws within a 60-second time budget per binary.

## Architecture

### Format Detection Layer
The fuzzer employs a **dual-strategy detection system** combining libmagic MIME-type analysis with custom heuristics. It identifies seven input formats: CSV, JSON, XML, plaintext, JPEG, ELF, and PDF. For ambiguous cases (e.g., CSV files misidentified as plain text), heuristic validators analyze structural patterns—comma distribution, line consistency, and delimiter ratios—to ensure accurate classification.

### AFL-Inspired Fork Server
Performance optimization centers on an **AFL-style persistent fork server** with `LD_PRELOAD` injection. The parent fuzzer spawns a single fork server process that loads the target binary once. For each test case, the fork server forks a child from this pre-initialized state, eliminating repeated `execve()` overhead. Communication occurs through dedicated file descriptors (CMD_FD, INFO_FD) for command dispatch and status reporting. The implementation gracefully degrades to direct fork/exec if fork server initialization fails.

### Zero-Disk I/O Design
All mutated inputs exist purely in memory using Linux `memfd_create()` anonymous file descriptors. Payloads written to memfd appear as valid file paths via `/proc/self/fd/<n>`, allowing targets to read from stdin without any filesystem I/O. This approach eliminates disk bottlenecks, reduces wear on SSDs, and enables sustained high-throughput execution (1000+ execs/sec).

### Format-Specific Fuzzing Engines

**CSV Handler**: Parses input into a linked-list structure (rows → cells), enabling deep structural mutations. Strategies include buffer overflow injection (800-byte strings), boundary integer/float testing (INT_MIN/MAX, infinity, NaN), CSV formula injection (`=cmd|calc`, `=SUM()`), special character insertion (quotes, commas, newlines), empty cell injection, row/column duplication, and generic byte-level mutations.

**JSON Handler**: Leverages cJSON for parsing and manipulation. Strategies include key/value buffer overflows, boundary numeric testing, format string injection (`%s%s%n`), empty key/null value testing, structural expansion (adding 100+ duplicate entries), array wrapping (creating large nested arrays), bit-shifting near structural characters (`{}[]:"`), and adaptive mutations.

### Two-Phase Fuzzing Strategy
Each format handler executes in two phases:

1. **Deterministic Phase**: Runs predefined strategies once (buffer overflows, boundary values, injection attacks, structural manipulations)
2. **Randomized Phase**: Applies weighted mutations in a loop until hitting iteration limits (default 1000) or timeout (60 seconds)

This hybrid approach ensures comprehensive coverage of known vulnerability patterns while exploring novel crash paths through adaptive randomization.

### Crash Detection & Persistence
The harness monitors child processes for abnormal termination (SIGSEGV, SIGBUS, SIGABRT) while filtering intentional aborts. Crash-inducing inputs are saved to `fuzzer_outputs/bad_<binary>.txt` with iteration numbers. Statistics tracking logs total executions, unique crashes, and mutation effectiveness in real-time.

## Implementation Highlights
The codebase demonstrates clean separation of concerns: format detection (`format_detection.c`), mutation logic (`mutate.c`), fork server management (`fs.c`), format handlers (`csv_fuzz.c`, `json_fuzz.c`), and safe wrappers (`safe_wrapper.c`). Memory safety abstractions prevent fuzzer self-crashes. The system uses `mmap()` for efficient original input access and `memfd` for mutated payload delivery.



