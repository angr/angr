#include <stdio.h>

/*
 * Normal functions.
 * i.e. all arguments are used.
 */
int arg1(int a1)
{
    printf("%d\n", a1);
    return a1;
}

int arg2(int a1, int a2)
{
    printf("%d\n", a1 + a2);
    return a2;
}

int arg3(int a1, int a2, int a3)
{
    printf("%d\n", a1 + a2 + a3);
    return a3;
}

int arg4(int a1, int a2, int a3, int a4)
{
    printf("%d\n", a1 + a2 + a3 + a4);
    return a4;
}

int arg5(int a1, int a2, int a3, int a4, int a5)
{
    printf("%d\n", a1 + a2 + a3 + a4 + a5);
    return a5;
}

int arg6(int a1, int a2, int a3, int a4, int a5, int a6)
{
    printf("%d\n", a1 + a2 + a3 + a4 + a5 + a6);
    return a6;
}

int arg7(int a1, int a2, int a3, int a4, int a5, int a6, int a7)
{
    printf("%d\n", a1 + a2 + a3 + a4 + a5 + a6 + a7);
    return a7;
}

int arg8(int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8)
{
    printf("%d\n", a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8);
    return a8;
}

int arg9(int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8, int a9)
{
    printf("%d\n", a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8 + a9);
    return a9;
}

/*
 * Not all parameters are used.
 */
int params_unused(int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8, int a9)
{
    printf("%d\n", a1 + a2 + a9);
    return a1;
}

/*
 * Directly passes arguments to the callee
 * In some cases this function might be optimized and no reference of those 
 * arguments can be found in this function.
 */
int argument_pass_through(int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8, int a9)
{
    arg3(a1, a2, a3);
    arg9(a1, a2, a3, a4, a5, a6, a7, a8, a9);

    return a1;
}

int main(int argc, char** argv)
{
    int a;
    scanf("%d", &a);
    arg1(a);
    arg2(a, a);
    arg3(a, a, a);
    arg4(a, a, a, a);
    arg5(a, a, a, a, a);
    arg6(a, a, a, a, a, a);
    arg7(a, a, a, a, a, a, a);
    arg8(a, a, a, a, a, a, a, a);
    arg9(a, a, a, a, a, a, a, a, a);
    params_unused(a, a, a, a, a, a, a, a, a);
    argument_pass_through(a, a, a, a, a, a, a, a, a);
}
