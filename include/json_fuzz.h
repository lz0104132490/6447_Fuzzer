#ifndef JSON_FUZZ_H
#define JSON_FUZZ_H

#include "types.h"

/**
 * Main JSON fuzzing handler
 * 
 * This function performs fuzzing of JSON input using the fork server.
 * It validates the input JSON, then runs a fuzzing loop that:
 * - Mutates the original input (stored in s->mem)
 * - Writes mutated payloads to s->memfd for the target binary
 * - Executes the target via the fork server
 * - Detects crashes (SIGSEGV) and saves them
 * 
 * The function respects both iteration limits (s->max_iters) and
 * timeout limits (s->timeout, default 60 seconds).
 * 
 * @param s Pointer to fuzzer state containing binary, input data, and configuration
 * 
 * Requirements:
 * - s->mem must be a valid memory-mapped input file
 * - s->memfd must be a valid file descriptor for payload communication
 * - Fork server must be initialized via fs_init()
 */
void fuzz_handle_json(struct state *s);

#endif /* JSON_FUZZ_H */
