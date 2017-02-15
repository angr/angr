#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

// gcc ctype_b_loc.c -o ../bin/ctype_b_loc.run

int main(int argc, char *argv[]) {
    const unsigned short int ** b_loc = __ctype_b_loc();

    for(int i = -128; i < 256; i++) {
        printf("%d->0x%x\n", i, (*b_loc)[i]);
    }

    return 0;
}
