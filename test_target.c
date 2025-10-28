#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Simple vulnerable JSON parser for testing */
int main(void) {
    char buf[64];
    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    /* Read input */
    while ((read = getline(&line, &len, stdin)) != -1) {
        /* Vulnerable: no bounds checking */
        if (strstr(line, "CRASH")) {
            /* Trigger crash on specific input */
            char *p = NULL;
            *p = 'X'; /* Null pointer dereference */
        }
        
        if (strlen(line) > 100) {
            /* Buffer overflow */
            strcpy(buf, line);
        }
    }

    free(line);
    return 0;
}
