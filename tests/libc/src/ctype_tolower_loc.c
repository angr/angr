#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    const int ** lower_loc = __ctype_tolower_loc();

    for(int i = -128; i < 256; i++) {
        if (i == -1)
            // Special case where it normally outputs 0xffffffff
            // but this won't pass our testing because we want to try
            // to lessen the amoutn of space allocated by only
            // using 1-byte values
            printf("-1->0xff\n");
        else
            printf("%d->0x%x\n", i, (*lower_loc)[i]);
    }

    return 0;
}
