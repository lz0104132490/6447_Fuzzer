#ifndef CSV_FUZZ_H
#define CSV_FUZZ_H

#include "types.h"

/**
 * Main CSV fuzzing handler
 * 
 * This function performs fuzzing of CSV input using the fork server.
 * It parses the CSV structure, then runs a fuzzing loop that:
 * - Mutates CSV rows and values (cells)
 * - Writes mutated payloads to s->memfd for the target binary
 * - Executes the target via the fork server
 * - Detects crashes (SIGSEGV) and saves them
 * 
 * The function respects both iteration limits (s->max_iters) and
 * timeout limits (s->timeout).
 * 
 * CSV-specific mutations include:
 * - Buffer overflow attacks on cells
 * - Bad number injection
 * - CSV injection (formula injection)
 * - Bit flipping near structure characters (,  \n  ")
 * - Adding/removing rows and columns
 * - Empty cell fuzzing
 * 
 * @param s Pointer to fuzzer state containing binary, input data, and configuration
 * 
 * Requirements:
 * - s->mem must be a valid memory-mapped input file containing CSV data
 * - s->memfd must be a valid file descriptor for payload communication
 * - Fork server must be initialized via fs_init()
 */
void fuzz_handle_csv(struct state *s);

#endif /* CSV_FUZZ_H */

