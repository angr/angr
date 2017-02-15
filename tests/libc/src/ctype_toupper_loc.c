#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

// gcc ctype_toupper_loc.c -o ../bin/ctype_toupper_loc.run

int main(int argc, char *argv[]) {
    const int ** upper_loc = __ctype_toupper_loc();

    for(int i = -128; i < 256; i++) {
        printf("%d->0x%x\n", i, (*upper_loc)[i]);
    }

    return 0;
}
