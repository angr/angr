#include <stdio.h>
#include <stdlib.h>

int main()
{
	unsigned int num = 0;

	read(0, &num, 4);

	if (num > 10)
	{
		puts(">10");
		if (num < 20)
		{
			puts("<20");
		}
		else
		{
			puts(">=20");
		}

		if (num % 2)
		{
			puts("odd");
		}
		else
		{
			puts("even");
		}
	}
	else
	{
		puts("<=10");
	}
}
