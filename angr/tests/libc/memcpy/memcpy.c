#include <string.h>

int main(void)
{
	char str[] = "let's test memcpy!"; // 18 + 1

	char buf[19];

	memcpy(buf, str, 19);

	void (*dumbassgcc)() = memcpy;

	dumbassgcc(buf,str,19);

	puts(buf);

	return 0;
}
