#include <stdio.h>

int loop()
{
    int i, j = 0;
    for(i = 0; i < 10; ++i)
    {
        j += i;
    }
    printf("j = %d\n", j);
    for(j = 0; j < 10; ++j)
    {
        i += j * 2;
    }
    printf("i = %d\n", i);
}

int main()
{
    printf("CFG Test #1\n");
    loop();
}
