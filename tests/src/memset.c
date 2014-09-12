#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
	char asdf[50];
	asdf[0] = 'A';
	asdf[1] = 'B';
	asdf[2] = 'C';
	asdf[3] = 'D';
	asdf[49] = '\0';

	void (*fuckfuck)() = memset;

	fuckfuck(asdf, asdf[1], 49);
	puts(asdf);
}
