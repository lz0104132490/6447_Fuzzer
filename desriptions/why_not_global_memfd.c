// WHY NOT MAKE MEMFD GLOBAL?

// Option 1: Global memfd (BAD)
static int global_memfd = -1;

void forkserver_loop() {
    // Problem 1: Each fuzzing iteration has DIFFERENT input data!
    // Input 1: "A,B,C\n"
    // Input 2: "header,must,stay,intact\nX,Y,Z\n" (different size!)
    
    // You'd have to:
    global_memfd = memfd_create(...);  // Create once
    
    // Then each iteration:
    ftruncate(global_memfd, 0);        // Truncate to 0
    write(global_memfd, new_data, new_size);  // Write new data
    lseek(global_memfd, 0, SEEK_SET);  // Rewind
    
    // Problem 2: File descriptor state is shared!
    fork();
    // Child reads from memfd, advances file position
    // Parent's memfd position is now undefined!
    
    // Problem 3: Race conditions
    // If you reuse it, you might overwrite while child is still reading
}

// Option 2: Create per-iteration (CORRECT)
void forkserver_loop() {
    while (1) {
        // Each iteration gets fresh memfd
        int memfd = memfd_create("fuzz_input", 0);
        write(memfd, current_input, size);
        lseek(memfd, 0, SEEK_SET);
        
        pid_t pid = fork();
        if (pid == 0) {
            // Child gets its own copy of the memfd FD
            dup2(memfd, 0);
            close(memfd);
            exec_program();  // Reads from stdin
        }
        
        // Parent closes its copy
        close(memfd);  // Kernel frees memory when all FDs closed
        waitpid(pid);
        
        // Next iteration: new memfd with new data
    }
}

// PERFORMANCE: Is creating memfd every time slow?
// NO! memfd_create() is very fast:
// - Just allocates a struct in kernel
// - No disk I/O
// - Faster than malloc/free in userspace
// - Modern Linux creates ~1 million memfd/second

