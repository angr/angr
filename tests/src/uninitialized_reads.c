#include <stdio.h>

void initialized_read()
{
    int a = 0;
    printf("%d\n", a);
    a = 1;
    printf("%d\n", a);
}

void uninitialized_read()
{
    int a;
    printf("%d\n", a);
    a += 10;
    printf("%d\n", a);
}

int main()
{
    initialized_read();
    uninitialized_read();
}
