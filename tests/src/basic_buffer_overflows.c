#include <stdio.h>

void overflow_1()
{
    char buf[20];
    int i;
    for(i = 0; i < 40; ++i)
    {
        buf[i] = (char)(i * 20);
    }
}

void overflow_2()
{
    char buf_1[100];
    char buf_2[80];
    int i;
    for(i = 0; i < 120; ++i)
    {
        buf_1[i + 2] = 'a';
    }
    for(i = 0; i < 80; i += 2)
    {
        buf_2[i] = 'b';
    }
}

void overflow_3()
{
    char buf[100];
    int i;
    for(i = 200; i > 100; ++i)
    {
        buf[i] = (char)(i + 4);
    }
}

int main()
{
    overflow_1();
    overflow_2();
    overflow_3();
}
