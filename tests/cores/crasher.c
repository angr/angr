/*
 * Simple test program that segfaults at a known location.
 * Used to generate core dumps for testing angr's core_state().
 *
 * Compile: gcc -g -O0 -no-pie -o crasher crasher.c
 *
 * It sets several registers/variables to known values before crashing,
 * so we can verify they're recovered correctly from the core dump.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Global with a known value, so we can verify .data is accessible */
int global_marker = 0xDEAD;

/* Function that will crash - separate function so we can verify RIP/call stack */
void do_crash(int *ptr) {
    /* At this point:
     * - rdi should hold ptr (NULL)
     * - global_marker should be 0xBEEF (we changed it)
     * - The stack should have our local variables
     */
    *ptr = 42;  /* SIGSEGV here */
}

int main(int argc, char **argv) {
    int local_var = 0x12345678;
    char buf[64];

    /* Fill buffer with a known pattern so we can find it on the stack */
    memset(buf, 'A', sizeof(buf));
    buf[63] = '\0';

    /* Update global to a known value */
    global_marker = 0xBEEF;

    /* Print address info for test verification */
    printf("crasher: global_marker at %p = 0x%x\n", &global_marker, global_marker);
    printf("crasher: local_var at %p = 0x%x\n", &local_var, local_var);
    printf("crasher: do_crash at %p\n", (void *)do_crash);
    printf("crasher: main at %p\n", (void *)main);
    fflush(stdout);

    /* Crash with a NULL pointer dereference */
    do_crash(NULL);

    return 0;
}
