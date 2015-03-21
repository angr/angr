#include <stdio.h>

char g_buf[1024];

void calc_sum(int* n, int upper)
{
    int sum;
    int i;

    sum = 0;

    for(i = 0; i < upper; ++i)
    {
        sum += i;
    }

    *n = sum;
}

void gen_random(char* buf, int n)
{
    int i;
    for (i = 0; i < n; ++i)
    {
        buf[i] = (unsigned char)(rand() % 0x100);
    }
}

void buf_cpy(char* dst, char* src, int n)
{
    int i;

    for (i = 0; i < n; ++i)
    {
        dst[i] = src[i];
    }
}

int main()
{
    int n;
    int upper;
    char src_buf[1024];
    char dst_buf[1024];
    
    printf("Please input sum: ");
    scanf("%d", &upper);
    calc_sum(&n, upper);

    gen_random(src_buf, sizeof(src_buf));
    /* Copy to local buffer */
    buf_cpy(dst_buf, src_buf, sizeof(dst_buf));
    /* Copy to global buffer */
    buf_cpy(g_buf, src_buf, sizeof(g_buf));

    return 0;
}
