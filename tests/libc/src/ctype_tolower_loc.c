#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

// gcc ctype_tolower_loc.c -o ../bin/ctype_tolower_loc.run

int main(int argc, char *argv[]) {
    const int ** lower_loc = __ctype_tolower_loc();

    for(int i = -128; i < 256; i++) {
        printf("%d->0x%x\n", i, (*lower_loc)[i]);
    }

    return 0;
}
